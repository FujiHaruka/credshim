mod common;

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use common::{
    COMBOS, Downstream, client_for, connect, exchange, h2_over_proxy, raw_exchange, tls_over,
    upstream_version,
};
use credshim_core::{InjectSpec, Injector, RuleSet, RuleSpec, Secrets};
use credshim_mitm::{
    BindError, CertificateAuthority, Intercept, Proxy, ProxyConfig, TestingHooks, Upstream,
};
use credshim_testkit::{
    Alpn, Echo, MockUpstream, TestCa, capture_logs, fake_secret, install_crypto_provider,
};
use http_body_util::{BodyExt, Full};
use rustls::RootCertStore;
use secrecy::SecretString;

const OPENAI: &str = "api.openai.com";
const ANTHROPIC: &str = "api.anthropic.com";
const GEMINI: &str = "generativelanguage.googleapis.com";
const BASIC: &str = "basic.example.test";
const HOSTS: [&str; 4] = [OPENAI, ANTHROPIC, GEMINI, BASIC];

const OPENAI_DUMMY: &str = "sk-credshim-openai-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const ANTHROPIC_DUMMY: &str = "sk-ant-credshim-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const GEMINI_DUMMY: &str = "credshim-gemini-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
const BASIC_DUMMY: &str = "credshim-basic-DDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";

struct Fixture {
    proxy: Proxy,
    dev_ca: Arc<CertificateAuthority>,
    mock: MockUpstream,
    secrets: HashMap<&'static str, String>,
    downstream: Downstream,
    _dir: tempfile::TempDir,
}

fn rule(name: &str, host: &str, dummy: &str, inject: InjectSpec) -> RuleSpec {
    RuleSpec {
        name: name.to_string(),
        host: host.to_string(),
        port: None,
        path_prefix: None,
        secret: name.to_string(),
        dummy: dummy.to_string(),
        inject,
    }
}

fn header(name: &str) -> InjectSpec {
    InjectSpec {
        header: Some(name.to_string()),
        ..InjectSpec::default()
    }
}

impl Fixture {
    async fn new() -> Self {
        Self::with(Downstream::Http1, Alpn::Both).await
    }

    async fn with(downstream: Downstream, alpn: Alpn) -> Self {
        install_crypto_provider();
        let upstream_ca = TestCa::new();
        let mock = MockUpstream::https(upstream_ca.issue(&HOSTS))
            .alpn(alpn)
            .start()
            .await;
        let dir = tempfile::tempdir().unwrap();
        let dev_ca = Arc::new(CertificateAuthority::init(dir.path()).unwrap());
        let upstream = Upstream::with_testing_hooks(TestingHooks {
            extra_trust_anchors: vec![upstream_ca.cert_der()],
            resolve_overrides: HOSTS
                .iter()
                .map(|host| (host.to_string(), mock.addr()))
                .collect(),
        })
        .unwrap();

        let rules = RuleSet::new(vec![
            rule("openai", OPENAI, OPENAI_DUMMY, header("authorization")),
            rule("anthropic", ANTHROPIC, ANTHROPIC_DUMMY, header("x-api-key")),
            rule(
                "gemini",
                GEMINI,
                GEMINI_DUMMY,
                InjectSpec {
                    header: Some("x-goog-api-key".into()),
                    query: Some("key".into()),
                    basic: false,
                },
            ),
            rule(
                "basic",
                BASIC,
                BASIC_DUMMY,
                InjectSpec {
                    basic: true,
                    ..InjectSpec::default()
                },
            ),
        ])
        .unwrap();
        let secret_values: HashMap<&'static str, String> =
            ["openai", "anthropic", "gemini", "basic"]
                .into_iter()
                .map(|name| (name, fake_secret(name)))
                .collect();
        let mut secrets = Secrets::new();
        for (name, value) in &secret_values {
            secrets.insert(*name, SecretString::from(value.as_str()));
        }
        let injector = Arc::new(Injector::new(rules, secrets).unwrap());

        let mut config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
        config.intercept = Some(Intercept::new(dev_ca.clone(), injector.rules().hosts()));
        config.injector = injector;
        let proxy = Proxy::bind(config, upstream).await.unwrap();
        Self {
            proxy,
            dev_ca,
            mock,
            secrets: secret_values,
            downstream,
            _dir: dir,
        }
    }

    fn client(&self) -> reqwest::Client {
        client_for(
            self.proxy.local_addr(),
            self.dev_ca.cert_der().as_ref(),
            self.downstream,
        )
    }

    fn secret(&self, name: &str) -> &str {
        &self.secrets[name]
    }

    fn dev_roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.dev_ca.cert_der().clone()).unwrap();
        roots
    }

    async fn raw_tls(&self, host: &str, request: &str) -> String {
        let (tcp, head) = connect(self.proxy.local_addr(), &format!("{host}:443")).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        let mut tls = tls_over(tcp, self.dev_roots(), host, true).await.unwrap();
        exchange(&mut tls, request).await
    }

    async fn raw_h2(&self, request: http::Request<Full<Bytes>>) -> (http::StatusCode, Bytes) {
        let mut sender = h2_over_proxy(
            self.proxy.local_addr(),
            &format!("{}:443", request.uri().host().unwrap()),
            self.dev_roots(),
        )
        .await;
        let response = sender.send_request(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, body)
    }
}

fn body_of(response: &str) -> String {
    common::http1_body(response)
}

#[tokio::test]
async fn openai_bearer_dummy_reaches_the_upstream_as_the_real_secret() {
    for (downstream, alpn) in COMBOS {
        let fixture = Fixture::with(downstream, alpn).await;

        let response = fixture
            .client()
            .post(format!("https://{OPENAI}/v1/responses"))
            .bearer_auth(OPENAI_DUMMY)
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(response.version(), downstream.version());
        let echo: Echo = response.json().await.unwrap();

        assert_eq!(echo.version, upstream_version(alpn), "{downstream:?}");
        assert_eq!(echo.authority.as_deref(), Some(OPENAI));
        assert_eq!(
            echo.header("authorization"),
            Some(format!("Bearer {}", fixture.secret("openai")).as_str())
        );
        assert_eq!(echo.body, "{}");
    }
}

#[tokio::test]
async fn dummy_sent_to_another_intercepted_host_is_403_and_nothing_reaches_upstream() {
    for (downstream, alpn) in COMBOS {
        let fixture = Fixture::with(downstream, alpn).await;

        let response = fixture
            .client()
            .post(format!("https://{ANTHROPIC}/v1/messages"))
            .header("x-api-key", OPENAI_DUMMY)
            .body("{}")
            .send()
            .await
            .unwrap();

        assert_eq!(response.version(), downstream.version());
        assert_eq!(response.status(), 403);
        assert_eq!(fixture.mock.request_count(), 0);
    }
}

#[tokio::test]
async fn dummy_over_plain_http_is_403_and_nothing_reaches_upstream() {
    install_crypto_provider();
    let fixture = Fixture::new().await;
    let plain = MockUpstream::http().start().await;

    let response = raw_exchange(
        fixture.proxy.local_addr(),
        &format!(
            "GET {} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {OPENAI_DUMMY}\r\nConnection: close\r\n\r\n",
            plain.url("127.0.0.1", "/v1/models")
        ),
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert_eq!(plain.request_count(), 0);
}

#[tokio::test]
async fn basic_auth_and_query_parameters_are_injected() {
    for (downstream, alpn) in COMBOS {
        let fixture = Fixture::with(downstream, alpn).await;
        assert_basic_and_query_injected(&fixture).await;
    }
}

async fn assert_basic_and_query_injected(fixture: &Fixture) {
    let client = fixture.client();

    let echo: Echo = client
        .get(format!("https://{BASIC}/token"))
        .basic_auth("client-id", Some(BASIC_DUMMY))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let expected = STANDARD.encode(format!("client-id:{}", fixture.secret("basic")));
    assert_eq!(
        echo.header("authorization"),
        Some(format!("Basic {expected}").as_str())
    );

    let echo: Echo = client
        .get(format!(
            "https://{GEMINI}/v1beta/models?alt=sse&key={GEMINI_DUMMY}"
        ))
        .header("x-goog-api-key", GEMINI_DUMMY)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        echo.query.as_deref(),
        Some(format!("alt=sse&key={}", fixture.secret("gemini")).as_str())
    );
    assert_eq!(
        echo.header("x-goog-api-key"),
        Some(fixture.secret("gemini"))
    );
}

fn expected_unchanged_headers() -> std::collections::BTreeMap<String, Vec<String>> {
    [
        ("accept-encoding", vec!["identity"]),
        ("authorization", vec!["Bearer sk-someone-else"]),
        ("x-custom", vec!["a  b", "second"]),
    ]
    .into_iter()
    .map(|(name, values)| {
        (
            name.to_string(),
            values.into_iter().map(String::from).collect(),
        )
    })
    .collect()
}

fn assert_unchanged(echo: Echo, alpn: Alpn) {
    let mut echo = echo;
    assert_eq!(echo.version, upstream_version(alpn));
    assert_eq!(echo.query.as_deref(), Some("a=%41+b&&key=sk-other"));
    assert_eq!(echo.authority.as_deref(), Some(OPENAI));
    let host = echo.headers.remove("host");
    match alpn {
        Alpn::H1Only => assert_eq!(host, Some(vec![OPENAI.to_string()])),
        _ => assert_eq!(host, None),
    }
    assert_eq!(echo.headers, expected_unchanged_headers());
}

#[tokio::test]
async fn request_without_dummies_is_forwarded_unchanged() {
    for alpn in [Alpn::H1Only, Alpn::H2Only] {
        let fixture = Fixture::with(Downstream::Http1, alpn).await;
        let response = fixture
            .raw_tls(
                OPENAI,
                &format!(
                    "GET /v1/models?a=%41+b&&key=sk-other HTTP/1.1\r\nHost: {OPENAI}\r\nAuthorization: Bearer sk-someone-else\r\nX-Custom: a  b\r\nX-Custom: second\r\nConnection: close\r\n\r\n"
                ),
            )
            .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert_unchanged(serde_json::from_str(&body_of(&response)).unwrap(), alpn);

        let fixture = Fixture::with(Downstream::Http2, alpn).await;
        let request =
            http::Request::get(format!("https://{OPENAI}/v1/models?a=%41+b&&key=sk-other"))
                .header("authorization", "Bearer sk-someone-else")
                .header("x-custom", "a  b")
                .header("x-custom", "second")
                .body(Full::new(Bytes::new()))
                .unwrap();
        let (status, body) = fixture.raw_h2(request).await;
        assert_eq!(status, 200);
        assert_unchanged(serde_json::from_slice(&body).unwrap(), alpn);
    }
}

#[tokio::test]
async fn secrets_and_dummies_never_reach_the_logs_and_requests_are_audited() {
    for (downstream, alpn) in COMBOS {
        assert_logs_clean_and_audited(downstream, alpn).await;
    }
}

async fn assert_logs_clean_and_audited(downstream: Downstream, alpn: Alpn) {
    let logs = capture_logs();
    let fixture = Fixture::with(downstream, alpn).await;
    let client = fixture.client();

    client
        .get(format!("https://{GEMINI}/v1/models?key={GEMINI_DUMMY}"))
        .send()
        .await
        .unwrap();
    client
        .post(format!(
            "https://{ANTHROPIC}/v1/messages?key={OPENAI_DUMMY}"
        ))
        .bearer_auth(OPENAI_DUMMY)
        .send()
        .await
        .unwrap();

    let contents = logs.contents();
    let audit: Vec<&str> = contents
        .lines()
        .filter(|line| line.contains(credshim_mitm::AUDIT_TARGET))
        .collect();
    for expected in [
        r#"host="generativelanguage.googleapis.com" port=443 method=GET path="/v1/models" rules=gemini decision="inject" status=200"#,
        r#"host="api.anthropic.com" port=443 method=POST path="/v1/messages" rules=openai decision="deny" status=403"#,
    ] {
        assert!(
            audit.iter().any(|line| line.ends_with(expected)),
            "{expected} not in {audit:#?}"
        );
    }
    let mut needles: Vec<&str> = fixture.secrets.values().map(String::as_str).collect();
    needles.extend([OPENAI_DUMMY, GEMINI_DUMMY]);
    logs.assert_absent(&needles);
}

#[tokio::test]
async fn rule_hosts_must_be_intercepted() {
    install_crypto_provider();
    let rules = RuleSet::new(vec![rule(
        "openai",
        OPENAI,
        OPENAI_DUMMY,
        header("authorization"),
    )])
    .unwrap();
    let mut secrets = Secrets::new();
    secrets.insert("openai", SecretString::from("x"));
    let mut config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
    config.injector = Arc::new(Injector::new(rules, secrets).unwrap());

    let err = Proxy::bind(config, Upstream::new().unwrap())
        .await
        .err()
        .unwrap();

    assert!(matches!(err, BindError::RuleHostNotIntercepted(host) if host == OPENAI));
}
