mod common;

use std::sync::Arc;

use common::{COMBOS, Downstream, assert_sse_unbuffered, client_for};
use credshim_core::{InjectSpec, Injector, RuleSet, RuleSpec, Secrets};
use credshim_mitm::{CertificateAuthority, Intercept, Proxy, ProxyConfig, TestingHooks, Upstream};
use credshim_testkit::{
    Alpn, MockUpstream, TestCa, capture_logs, fake_secret, install_crypto_provider,
};
use secrecy::SecretString;

const API: &str = "api.example.test";
const DUMMY: &str = "credshim-scrub-dummy-0123456789abcdef";

struct Setup {
    proxy: Proxy,
    dev_ca: Arc<CertificateAuthority>,
    mock: MockUpstream,
    secret: String,
    downstream: Downstream,
    _dir: tempfile::TempDir,
}

impl Setup {
    async fn new(downstream: Downstream, alpn: Alpn, scrub: bool) -> Self {
        install_crypto_provider();
        let upstream_ca = TestCa::new();
        let mock = MockUpstream::https(upstream_ca.issue(&[API]))
            .alpn(alpn)
            .start()
            .await;
        let dir = tempfile::tempdir().unwrap();
        let dev_ca = Arc::new(CertificateAuthority::init(dir.path()).unwrap());
        let upstream = Upstream::with_testing_hooks(TestingHooks {
            extra_trust_anchors: vec![upstream_ca.cert_der()],
            resolve_overrides: [(API.to_string(), mock.addr())].into_iter().collect(),
        })
        .unwrap();
        let rules = RuleSet::new(vec![RuleSpec {
            name: "api".into(),
            host: API.into(),
            port: None,
            path_prefix: None,
            allow_methods: None,
            allow_paths: None,
            limits: Default::default(),
            secret: "api".into(),
            dummy: DUMMY.into(),
            inject: InjectSpec {
                header: Some("authorization".into()),
                ..InjectSpec::default()
            },
        }])
        .unwrap();
        let secret = fake_secret("scrub");
        let mut secrets = Secrets::new();
        secrets.insert("api", SecretString::from(secret.as_str()));
        let injector = Arc::new(Injector::new(rules, secrets).unwrap());
        let mut config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
        config.intercept = Some(Intercept::new(dev_ca.clone(), [API]));
        config.injector = injector;
        config.scrub = scrub;
        let proxy = Proxy::bind(config, upstream).await.unwrap();
        Self {
            proxy,
            dev_ca,
            mock,
            secret,
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

    async fn reflect(&self, query: &str, body: String) -> reqwest::Response {
        self.client()
            .post(self.mock.url(API, &format!("/reflect?{query}")))
            .body(body)
            .send()
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn echoed_secret_never_reaches_the_client_even_across_chunk_boundaries() {
    let logs = capture_logs();
    for (downstream, alpn) in COMBOS {
        let setup = Setup::new(downstream, alpn, true).await;
        let secret = setup.secret.clone();
        let body = format!(
            "start {secret} middle {secret}{secret} end {}",
            &secret[..10]
        );
        let expected = format!("start {DUMMY} middle {DUMMY}{DUMMY} end {}", &secret[..10]);
        for chunk in [
            1,
            2,
            7,
            secret.len() - 1,
            secret.len(),
            secret.len() + 3,
            body.len(),
        ] {
            let response = setup
                .reflect(&format!("chunk={chunk}&header={secret}"), body.clone())
                .await;
            assert_eq!(response.status(), 200);
            assert_eq!(response.headers()["x-reflected"], DUMMY);
            assert!(response.headers().get("content-length").is_none());
            let text = response.text().await.unwrap();
            assert_eq!(
                text, expected,
                "chunk size {chunk} over {downstream:?}/{alpn:?}"
            );
        }
        logs.assert_absent(&[&secret]);
    }
}

#[tokio::test]
async fn responses_without_secrets_are_byte_identical() {
    let setup = Setup::new(Downstream::Http1, Alpn::Both, true).await;
    let body = "plain body with FAKE-SECRET- prefix only".to_string();

    let text = setup
        .reflect("chunk=3", body.clone())
        .await
        .text()
        .await
        .unwrap();

    assert_eq!(text, body);
}

#[tokio::test]
async fn sse_stays_unbuffered_and_large_bodies_intact_with_scrubbing() {
    for (downstream, alpn) in COMBOS {
        let setup = Setup::new(downstream, alpn, true).await;
        let client = setup.client();
        assert_sse_unbuffered(&client, setup.mock.url(API, "/sse")).await;
        common::assert_large_bodies_intact(&client, &setup.mock, API).await;
    }
}

#[tokio::test]
async fn encoded_responses_are_refused_rather_than_passed_unscrubbed() {
    let setup = Setup::new(Downstream::Http1, Alpn::Both, true).await;

    let response = setup
        .reflect("encoding=gzip", format!("compressed? {}", setup.secret))
        .await;

    assert_eq!(response.status(), 502);
    let text = response.text().await.unwrap();
    assert!(!text.contains(&setup.secret));
}

#[tokio::test]
async fn upstream_is_asked_for_an_identity_encoded_response() {
    let setup = Setup::new(Downstream::Http1, Alpn::Both, true).await;

    setup
        .client()
        .get(setup.mock.url(API, "/echo"))
        .header("accept-encoding", "gzip, br")
        .send()
        .await
        .unwrap();

    let request = setup.mock.requests().pop().unwrap();
    assert_eq!(request.headers["accept-encoding"], "identity");
}

#[tokio::test]
async fn scrubbing_can_be_turned_off() {
    let setup = Setup::new(Downstream::Http1, Alpn::Both, false).await;

    let text = setup
        .reflect("chunk=5", format!("echo {}", setup.secret))
        .await
        .text()
        .await
        .unwrap();

    assert_eq!(text, format!("echo {}", setup.secret));
}

#[tokio::test]
async fn upstream_reason_phrase_never_reaches_the_client() {
    for scrub in [true, false] {
        let setup = Setup::new(Downstream::Http1, Alpn::H1Only, scrub).await;
        let (tcp, head) = common::connect(setup.proxy.local_addr(), &format!("{API}:443")).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(setup.dev_ca.cert_der().clone()).unwrap();
        let mut tls = common::tls_over(tcp, roots, API, true).await.unwrap();
        let response = common::exchange(
            &mut tls,
            &format!(
                "POST /reflect?reason={} HTTP/1.1\r\nHost: {API}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                setup.secret
            ),
        )
        .await;
        let status_line = response.lines().next().unwrap();
        assert!(status_line.starts_with("HTTP/1.1 400"), "{status_line}");
        assert!(!response.contains(&setup.secret), "{status_line}");
    }
}
