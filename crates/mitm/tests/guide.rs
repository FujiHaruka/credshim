mod common;

use std::sync::Arc;

use common::{Downstream, client_for, raw_exchange, read_head};
use credshim_core::{InjectSpec, Injector, Limits, RuleSet, RuleSpec, Secrets};
use credshim_mitm::{
    CertificateAuthority, Details, Guide, Intercept, Proxy, ProxyConfig, TestingHooks, Topic,
    Upstream,
};
use credshim_testkit::{
    LogCapture, MockUpstream, TestCa, capture_logs, fake_secret, install_crypto_provider,
};
use secrecy::SecretString;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

const API: &str = "api.openai.com";
const DUMMY: &str = "sk-credshim-openai-guide-0123456789abcdef";
const DETAILS: &str = "credshim tail --id";

struct Setup {
    proxy: Proxy,
    dev_ca: Arc<CertificateAuthority>,
    secret: String,
    _mock: MockUpstream,
    _dir: tempfile::TempDir,
}

impl Setup {
    async fn new(guide: Guide, limits: Limits) -> Self {
        install_crypto_provider();
        let upstream_ca = TestCa::new();
        let mock = MockUpstream::https(upstream_ca.issue(&[API])).start().await;
        let dir = tempfile::tempdir().unwrap();
        let dev_ca = Arc::new(CertificateAuthority::init(dir.path()).unwrap());
        let upstream = Upstream::with_testing_hooks(TestingHooks {
            extra_trust_anchors: vec![upstream_ca.cert_der()],
            resolve_overrides: [(API.to_string(), mock.addr())].into_iter().collect(),
        })
        .unwrap();
        let rules = RuleSet::new(vec![RuleSpec {
            name: "openai".into(),
            host: API.into(),
            port: None,
            path_prefix: None,
            allow_methods: Some(vec!["GET".into(), "HEAD".into()]),
            allow_paths: Some(vec!["/echo".into()]),
            limits,
            base_url_prefix: None,
            env: None,
            secret: "openai".into(),
            dummy: DUMMY.into(),
            inject: InjectSpec {
                header: Some("authorization".into()),
                ..InjectSpec::default()
            },
        }])
        .unwrap();
        let secret = fake_secret("guide");
        let mut secrets = Secrets::new();
        secrets.insert("openai", SecretString::from(secret.clone()));
        let mut config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
        config.intercept = Some(Intercept::new(dev_ca.clone(), [API]));
        config.injector = Arc::new(Injector::new(rules, secrets).unwrap());
        config.guide = guide;
        let proxy = Proxy::bind(config, upstream).await.unwrap();
        Self {
            proxy,
            dev_ca,
            secret,
            _mock: mock,
            _dir: dir,
        }
    }

    async fn call(&self, method: reqwest::Method, path: &str) -> reqwest::Response {
        client_for(
            self.proxy.local_addr(),
            self.dev_ca.cert_der().as_ref(),
            Downstream::Http1,
        )
        .request(method, format!("https://{API}{path}"))
        .bearer_auth(DUMMY)
        .send()
        .await
        .unwrap()
    }
}

fn with_details() -> Guide {
    Guide::new(Details::Command(DETAILS.into()))
}

fn request_id(response: &reqwest::Response) -> String {
    response.headers()["credshim-request-id"]
        .to_str()
        .unwrap()
        .to_string()
}

fn audit_line(logs: &LogCapture, id: &str) -> String {
    logs.contents()
        .lines()
        .find(|line| {
            line.contains(credshim_mitm::AUDIT_TARGET) && line.contains(&format!("id=\"{id}\""))
        })
        .unwrap_or_else(|| panic!("no audit line with id {id}"))
        .to_string()
}

#[tokio::test]
async fn a_refusal_says_why_names_its_audit_entry_and_points_to_the_docs() {
    let logs = capture_logs();
    let setup = Setup::new(with_details(), Limits::default()).await;

    let response = setup.call(reqwest::Method::POST, "/v1/files").await;

    assert_eq!(response.status(), 403);
    assert_eq!(response.headers()["credshim-error"], "not_allowed");
    assert_eq!(
        response.headers()["content-type"],
        "text/plain; charset=utf-8"
    );
    let id = request_id(&response);
    let body = response.text().await.unwrap();
    assert_eq!(
        body,
        format!(
            "credshim: POST /v1/files is outside the allow_methods or allow_paths of rule \"openai\"\n\
             details: {DETAILS} {id}\n\
             docs: credshim docs troubleshooting#not_allowed\n"
        )
    );
    let line = audit_line(&logs, &id);
    assert!(line.contains(r#"decision="not_allowed""#), "{line}");
    assert!(
        line.contains(r#"detail="POST /v1/files is outside the allow_methods"#),
        "{line}"
    );
    assert!(!body.contains(&setup.secret));
    logs.assert_absent(&[&setup.secret]);
}

#[tokio::test]
async fn a_relayed_response_carries_the_id_of_its_audit_entry() {
    let logs = capture_logs();
    let setup = Setup::new(with_details(), Limits::default()).await;

    let response = setup.call(reqwest::Method::GET, "/echo").await;

    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key("credshim-error"));
    let line = audit_line(&logs, &request_id(&response));
    assert!(line.contains(r#"decision="inject""#), "{line}");
    assert!(!line.contains("detail="), "{line}");
}

#[tokio::test]
async fn a_limited_request_says_which_rule_is_over_its_limits() {
    let setup = Setup::new(
        with_details(),
        Limits {
            per_minute: Some(1),
            ..Limits::default()
        },
    )
    .await;
    assert_eq!(
        setup.call(reqwest::Method::GET, "/echo").await.status(),
        200
    );

    let response = setup.call(reqwest::Method::GET, "/echo").await;

    assert_eq!(response.status(), 429);
    assert_eq!(response.headers()["credshim-error"], "limited");
    let body = response.text().await.unwrap();
    assert!(
        body.starts_with("credshim: rule \"openai\" is over its limits\n"),
        "{body}"
    );
    assert!(
        body.ends_with("docs: credshim docs troubleshooting#limited\n"),
        "{body}"
    );
}

#[tokio::test]
async fn a_refused_head_request_keeps_its_body_empty() {
    let setup = Setup::new(with_details(), Limits::default()).await;

    let response = setup.call(reqwest::Method::HEAD, "/v1/files").await;

    assert_eq!(response.status(), 403);
    assert_eq!(response.headers()["credshim-error"], "not_allowed");
    assert!(response.bytes().await.unwrap().is_empty());
}

#[tokio::test]
async fn without_an_audit_log_the_refusal_says_where_the_reason_went() {
    let setup = Setup::new(Guide::default(), Limits::default()).await;

    let response = setup.call(reqwest::Method::POST, "/v1/files").await;

    let body = response.text().await.unwrap();
    assert!(
        body.contains(
            "details: no audit log is configured, so only the proxy's own log has the reason (credshim docs configuration#audit-log-and-status)"
        ),
        "{body}"
    );
}

#[tokio::test]
async fn a_dummy_over_plain_http_is_refused_with_the_reason() {
    install_crypto_provider();
    let logs = capture_logs();
    let rules = RuleSet::new(vec![RuleSpec {
        name: "openai".into(),
        host: API.into(),
        port: None,
        path_prefix: None,
        allow_methods: None,
        allow_paths: None,
        limits: Limits::default(),
        base_url_prefix: None,
        env: None,
        secret: "openai".into(),
        dummy: DUMMY.into(),
        inject: InjectSpec {
            header: Some("authorization".into()),
            ..InjectSpec::default()
        },
    }])
    .unwrap();
    let mut secrets = Secrets::new();
    secrets.insert("openai", SecretString::from(fake_secret("plain")));
    let dir = tempfile::tempdir().unwrap();
    let dev_ca = Arc::new(CertificateAuthority::init(dir.path()).unwrap());
    let mut config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
    config.intercept = Some(Intercept::new(dev_ca, [API]));
    config.injector = Arc::new(Injector::new(rules, secrets).unwrap());
    config.guide = with_details();
    let proxy = Proxy::bind(config, Upstream::new().unwrap()).await.unwrap();

    let response = raw_exchange(
        proxy.local_addr(),
        &format!(
            "GET http://{API}/v1/models HTTP/1.1\r\nHost: {API}\r\nAuthorization: Bearer {DUMMY}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert!(response.contains("credshim-error: deny\r\n"), "{response}");
    assert!(
        response.contains(
            "credshim: the dummy of rule \"openai\" was sent over plain HTTP; use https://\n"
        ),
        "{response}"
    );
    let id = response
        .lines()
        .find_map(|line| line.strip_prefix("credshim-request-id: "))
        .unwrap();
    assert!(response.contains(&format!("details: {DETAILS} {id}\n")));
    assert!(audit_line(&logs, id).contains(r#"decision="deny""#));
}

#[tokio::test]
async fn an_unreachable_tunnel_target_is_502_with_the_connect_error() {
    install_crypto_provider();
    let mut config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
    config.guide = with_details();
    let proxy = Proxy::bind(config, Upstream::new().unwrap()).await.unwrap();
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = closed.local_addr().unwrap();
    drop(closed);

    let mut tcp = TcpStream::connect(proxy.local_addr()).await.unwrap();
    tcp.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = read_head(&mut tcp).await;

    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    assert!(head.contains("credshim-error: upstream\r\n"), "{head}");
    assert!(head.contains("credshim-request-id: "), "{head}");
}

#[test]
fn every_topic_has_a_distinct_anchor() {
    let anchors: std::collections::BTreeSet<_> = Topic::ALL.iter().map(|t| t.anchor()).collect();
    assert_eq!(anchors.len(), Topic::ALL.len());
}
