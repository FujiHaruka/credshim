mod common;

use std::sync::Arc;

use common::{Downstream, client_for};
use credshim_core::{InjectSpec, Injector, Limits, RuleSet, RuleSpec, Secrets};
use credshim_mitm::{CertificateAuthority, Intercept, Proxy, ProxyConfig, TestingHooks, Upstream};
use credshim_testkit::{MockUpstream, TestCa, capture_logs, fake_secret, install_crypto_provider};
use secrecy::SecretString;

const API: &str = "api.openai.com";
const DUMMY: &str = "sk-credshim-openai-policy-0123456789abcdef";

struct Setup {
    proxy: Proxy,
    dev_ca: Arc<CertificateAuthority>,
    mock: MockUpstream,
    _dir: tempfile::TempDir,
}

impl Setup {
    async fn new(
        allow_methods: Option<&[&str]>,
        allow_paths: Option<&[&str]>,
        limits: Limits,
    ) -> Self {
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
        let strings = |list: &[&str]| list.iter().map(|item| item.to_string()).collect();
        let rules = RuleSet::new(vec![RuleSpec {
            name: "openai".into(),
            host: API.into(),
            port: None,
            path_prefix: None,
            allow_methods: allow_methods.map(strings),
            allow_paths: allow_paths.map(strings),
            limits,
            secret: "openai".into(),
            dummy: DUMMY.into(),
            inject: InjectSpec {
                header: Some("authorization".into()),
                ..InjectSpec::default()
            },
        }])
        .unwrap();
        let mut secrets = Secrets::new();
        secrets.insert("openai", SecretString::from(fake_secret("policy")));
        let mut config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
        config.intercept = Some(Intercept::new(dev_ca.clone(), [API]));
        config.injector = Arc::new(Injector::new(rules, secrets).unwrap());
        let proxy = Proxy::bind(config, upstream).await.unwrap();
        Self {
            proxy,
            dev_ca,
            mock,
            _dir: dir,
        }
    }

    fn client(&self) -> reqwest::Client {
        client_for(
            self.proxy.local_addr(),
            self.dev_ca.cert_der().as_ref(),
            Downstream::Http1,
        )
    }

    async fn call(&self, method: reqwest::Method, path: &str) -> reqwest::Response {
        self.client()
            .request(method, format!("https://{API}{path}"))
            .bearer_auth(DUMMY)
            .send()
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn paths_and_methods_outside_the_allow_list_are_403_and_never_reach_upstream() {
    let logs = capture_logs();
    let setup = Setup::new(
        Some(&["POST"]),
        Some(&["/v1/chat/completions"]),
        Limits::default(),
    )
    .await;

    let allowed = setup
        .call(reqwest::Method::POST, "/v1/chat/completions/x")
        .await;
    assert_eq!(allowed.status(), 200);
    assert_eq!(setup.mock.request_count(), 1);

    for (method, path) in [
        (reqwest::Method::GET, "/v1/organization/api_keys"),
        (reqwest::Method::POST, "/v1/organization/api_keys"),
        (reqwest::Method::DELETE, "/v1/chat/completions/x"),
    ] {
        let response = setup.call(method, path).await;
        assert_eq!(response.status(), 403, "{path}");
    }
    assert_eq!(setup.mock.request_count(), 1);
    assert!(logs.contents().lines().any(|line| {
        line.contains(credshim_mitm::AUDIT_TARGET)
            && line.ends_with(r#"rules=openai decision="not_allowed" status=403"#)
    }));
}

#[tokio::test]
async fn requests_over_the_rate_limit_are_429_and_never_reach_upstream() {
    let logs = capture_logs();
    let setup = Setup::new(
        None,
        None,
        Limits {
            per_minute: Some(2),
            ..Limits::default()
        },
    )
    .await;

    for _ in 0..2 {
        assert_eq!(
            setup.call(reqwest::Method::GET, "/echo").await.status(),
            200
        );
    }
    assert_eq!(
        setup.call(reqwest::Method::GET, "/echo").await.status(),
        429
    );
    assert_eq!(setup.mock.request_count(), 2);
    assert!(logs.contents().lines().any(|line| {
        line.contains(credshim_mitm::AUDIT_TARGET)
            && line.ends_with(r#"rules=openai decision="limited" status=429"#)
    }));
}

#[tokio::test]
async fn daily_limit_caps_total_requests() {
    let setup = Setup::new(
        None,
        None,
        Limits {
            per_day: Some(1),
            ..Limits::default()
        },
    )
    .await;

    assert_eq!(
        setup.call(reqwest::Method::GET, "/echo").await.status(),
        200
    );
    assert_eq!(
        setup.call(reqwest::Method::GET, "/echo").await.status(),
        429
    );
}

#[tokio::test]
async fn concurrency_limit_holds_for_the_whole_streamed_response() {
    let setup = Setup::new(
        None,
        None,
        Limits {
            concurrent: Some(1),
            ..Limits::default()
        },
    )
    .await;

    let stream = setup
        .call(reqwest::Method::GET, "/sse?count=3&interval_ms=300")
        .await;
    assert_eq!(stream.status(), 200);
    assert_eq!(
        setup.call(reqwest::Method::GET, "/echo").await.status(),
        429
    );

    stream.bytes().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        setup.call(reqwest::Method::GET, "/echo").await.status(),
        200
    );
}

#[tokio::test]
async fn requests_without_the_dummy_bypass_limits_because_no_credential_is_used() {
    let setup = Setup::new(
        None,
        Some(&["/v1/chat/completions"]),
        Limits {
            per_minute: Some(1),
            ..Limits::default()
        },
    )
    .await;

    for _ in 0..3 {
        let response = setup
            .client()
            .get(format!("https://{API}/v1/organization"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }
}
