mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use common::{assert_sse_unbuffered, http1_body, raw_exchange};
use credshim_core::{BaseUrls, InjectSpec, Injector, RuleSet, RuleSpec, Secrets};
use credshim_mitm::{BindError, Proxy, ProxyConfig, TestingHooks, Upstream};
use credshim_testkit::{
    Echo, MockUpstream, TestCa, capture_logs, fake_secret, install_crypto_provider,
};
use secrecy::SecretString;

const API: &str = "api.example.test";
const OTHER: &str = "other.example.test";
const DUMMY: &str = "credshim-base-url-dummy-0123456789abcdef";
const OTHER_DUMMY: &str = "credshim-other-dummy-0123456789abcdef";

fn spec(name: &str, host: &str, dummy: &str, prefix: Option<&str>) -> RuleSpec {
    RuleSpec {
        name: name.into(),
        host: host.into(),
        port: None,
        path_prefix: None,
        allow_methods: None,
        allow_paths: None,
        limits: Default::default(),
        base_url_prefix: prefix.map(Into::into),
        env: None,
        secret: name.into(),
        dummy: dummy.into(),
        inject: InjectSpec {
            header: Some("authorization".into()),
            ..InjectSpec::default()
        },
    }
}

struct Setup {
    proxy: Proxy,
    mock: MockUpstream,
    secret: String,
}

impl Setup {
    async fn new() -> Self {
        install_crypto_provider();
        let upstream_ca = TestCa::new();
        let mock = MockUpstream::https(upstream_ca.issue(&[API])).start().await;
        let upstream = Upstream::with_testing_hooks(TestingHooks {
            extra_trust_anchors: vec![upstream_ca.cert_der()],
            resolve_overrides: [(API.to_string(), mock.addr())].into_iter().collect(),
        })
        .unwrap();
        let specs = vec![
            spec("api", API, DUMMY, Some("/api")),
            spec("other", OTHER, OTHER_DUMMY, None),
        ];
        let base_urls = BaseUrls::from_specs(&specs).unwrap();
        let secret = fake_secret("base-url");
        let mut secrets = Secrets::new();
        secrets.insert("api", SecretString::from(secret.as_str()));
        secrets.insert("other", SecretString::from(fake_secret("other").as_str()));
        let injector = Injector::new(RuleSet::new(specs).unwrap(), secrets).unwrap();
        let mut config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
        config.intercept = Some(credshim_mitm::Intercept::new(
            Arc::new(
                credshim_mitm::CertificateAuthority::init(tempfile::tempdir().unwrap().path())
                    .unwrap(),
            ),
            [API, OTHER],
        ));
        config.injector = Arc::new(injector);
        config.base_url_listen = Some("127.0.0.1:0".parse().unwrap());
        config.base_urls = base_urls;
        let proxy = Proxy::bind(config, upstream).await.unwrap();
        Self {
            proxy,
            mock,
            secret,
        }
    }

    fn base(&self) -> SocketAddr {
        self.proxy.base_url_addr().unwrap()
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.base())
    }

    async fn raw(&self, request: &str) -> String {
        raw_exchange(self.base(), request).await
    }
}

#[tokio::test]
async fn prefix_maps_to_the_rule_host_and_the_real_secret_is_injected() {
    let logs = capture_logs();
    let setup = Setup::new().await;

    let response = reqwest::Client::new()
        .post(setup.url("/api/v1/things?limit=2"))
        .bearer_auth(DUMMY)
        .body("payload")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let echo: Echo = response.json().await.unwrap();
    assert_eq!(echo.path, "/v1/things");
    assert_eq!(echo.query.as_deref(), Some("limit=2"));
    assert_eq!(echo.body, "payload");
    assert_eq!(
        echo.header("authorization"),
        Some(format!("Bearer {}", setup.secret).as_str())
    );
    assert_eq!(echo.header("host").or(echo.authority.as_deref()), Some(API));
    let contents = logs.contents();
    assert!(
        contents
            .lines()
            .any(|line| line.contains(r#"ingress="base_url""#)
                && line.contains(r#"decision="inject""#)),
        "{contents}"
    );
    logs.assert_absent(&[&setup.secret]);
}

#[tokio::test]
async fn responses_are_scrubbed_and_streams_stay_unbuffered() {
    let setup = Setup::new().await;
    let client = reqwest::Client::new();

    let response = client
        .post(setup.url(&format!("/api/reflect?chunk=5&header={}", setup.secret)))
        .body(format!("echo {} back", setup.secret))
        .send()
        .await
        .unwrap();

    assert_eq!(response.headers()["x-reflected"], DUMMY);
    assert_eq!(response.text().await.unwrap(), format!("echo {DUMMY} back"));
    assert_sse_unbuffered(&client, setup.url("/api/sse")).await;
}

#[tokio::test]
async fn a_dummy_bound_to_another_host_is_refused() {
    let setup = Setup::new().await;

    let response = reqwest::Client::new()
        .get(setup.url("/api/v1/models"))
        .bearer_auth(OTHER_DUMMY)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 403);
    assert_eq!(setup.mock.request_count(), 0);
}

#[tokio::test]
async fn requests_naming_a_foreign_host_are_refused() {
    let setup = Setup::new().await;

    for host in ["evil.example.test", "api.example.test", "127.0.0.1.nip.io"] {
        let response = setup
            .raw(&format!(
                "GET /api/v1/models HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {DUMMY}\r\nConnection: close\r\n\r\n"
            ))
            .await;
        assert!(response.starts_with("HTTP/1.1 421"), "{host}: {response}");
    }
    let response = setup
        .raw(&format!(
            "GET /api/v1/models HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
            setup.base().port()
        ))
        .await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert_eq!(setup.mock.request_count(), 1);
}

#[tokio::test]
async fn paths_outside_a_prefix_and_proxy_forms_are_refused() {
    let setup = Setup::new().await;
    let host = format!("Host: {}", setup.base());

    for (request, code) in [
        (
            format!("GET /api/../other/v1 HTTP/1.1\r\n{host}\r\n"),
            "404",
        ),
        (format!("GET /api/%2e%2e/x HTTP/1.1\r\n{host}\r\n"), "404"),
        (format!("GET /apix/v1 HTTP/1.1\r\n{host}\r\n"), "404"),
        (format!("GET /v1/models HTTP/1.1\r\n{host}\r\n"), "404"),
        (
            format!("GET https://{API}/v1/models HTTP/1.1\r\n{host}\r\n"),
            "400",
        ),
        (
            format!("CONNECT {API}:443 HTTP/1.1\r\nHost: {API}:443\r\n"),
            "405",
        ),
    ] {
        let response = setup
            .raw(&format!(
                "{request}Authorization: Bearer {DUMMY}\r\nConnection: close\r\n\r\n"
            ))
            .await;
        assert!(
            response.starts_with(&format!("HTTP/1.1 {code}")),
            "{request}: {response}"
        );
    }
    assert_eq!(setup.mock.request_count(), 0);
}

#[tokio::test]
async fn requests_without_a_dummy_pass_through_unchanged() {
    let setup = Setup::new().await;

    let response = setup
        .raw(&format!(
            "GET /api/v1/models HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer caller-own-key\r\nConnection: close\r\n\r\n",
            setup.base()
        ))
        .await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let echo: Echo = serde_json::from_str(&http1_body(&response)).unwrap();
    assert_eq!(echo.header("authorization"), Some("Bearer caller-own-key"));
}

#[tokio::test]
async fn base_url_listener_follows_the_same_bind_rules() {
    install_crypto_provider();
    let routes = BaseUrls::from_specs(&[spec("api", API, DUMMY, Some("/api"))]).unwrap();

    let mut config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
    config.base_urls = routes.clone();
    let err = Proxy::bind(config, Upstream::new().unwrap())
        .await
        .err()
        .unwrap();
    assert!(matches!(err, BindError::BaseUrlWithoutListener), "{err}");

    for addr in ["0.0.0.0:0", "192.0.2.1:0"] {
        let mut config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
        config.base_url_listen = Some(addr.parse().unwrap());
        config.base_urls = routes.clone();
        let err = Proxy::bind(config, Upstream::new().unwrap())
            .await
            .err()
            .unwrap();
        assert!(
            matches!(err, BindError::Unspecified(_) | BindError::NotLoopback(_)),
            "{addr}: {err}"
        );
    }
}
