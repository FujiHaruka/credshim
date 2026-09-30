mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use common::{
    assert_large_bodies_intact, assert_sse_unbuffered, client_via, connect, eventually, exchange,
    tls_over,
};
use credshim_mitm::{CertificateAuthority, Intercept, Proxy, ProxyConfig, TestingHooks, Upstream};
use credshim_testkit::{
    Echo, LeafCert, LeafOptions, MockUpstream, TestCa, capture_logs, fake_secret,
    install_crypto_provider,
};
use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

const API: &str = "api.example.test";
const OTHER: &str = "other.example.test";

struct Setup {
    proxy: Proxy,
    dev_ca: Arc<CertificateAuthority>,
    mock: MockUpstream,
    _dir: tempfile::TempDir,
}

impl Setup {
    async fn with_leaf(leaf: LeafCert, upstream_ca: &TestCa) -> Self {
        Self::build(leaf, Some(upstream_ca)).await
    }

    async fn new() -> Self {
        install_crypto_provider();
        let upstream_ca = TestCa::new();
        Self::with_leaf(upstream_ca.issue(&[API]), &upstream_ca).await
    }

    async fn build(leaf: LeafCert, trusted: Option<&TestCa>) -> Self {
        install_crypto_provider();
        let mock = MockUpstream::https(leaf).start().await;
        let dir = tempfile::tempdir().unwrap();
        let dev_ca = Arc::new(CertificateAuthority::init(dir.path()).unwrap());
        let upstream = Upstream::with_testing_hooks(TestingHooks {
            extra_trust_anchors: trusted.map(|ca| ca.cert_der()).into_iter().collect(),
            resolve_overrides: HashMap::from([
                (API.to_string(), mock.addr()),
                (OTHER.to_string(), mock.addr()),
            ]),
        })
        .unwrap();
        let mut config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
        config.intercept = Some(Intercept::new(dev_ca.clone(), [API]));
        let proxy = Proxy::bind(config, upstream).await.unwrap();
        Self {
            proxy,
            dev_ca,
            mock,
            _dir: dir,
        }
    }

    fn addr(&self) -> SocketAddr {
        self.proxy.local_addr()
    }

    fn target(&self, host: &str) -> String {
        format!("{host}:{}", self.mock.port())
    }

    fn dev_roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.dev_ca.cert_der().clone()).unwrap();
        roots
    }

    fn client(&self) -> reqwest::Client {
        client_via(self.addr(), Some(self.dev_ca.cert_der().as_ref()))
    }

    fn url(&self, path: &str) -> String {
        self.mock.url(API, path)
    }
}

#[derive(Debug)]
struct AcceptAnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

async fn tls_skipping_verification(
    tcp: TcpStream,
    sni: &str,
) -> std::io::Result<TlsStream<TcpStream>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate(provider)))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
        .connect(sni.to_string().try_into().unwrap(), tcp)
        .await
}

async fn assert_connect_502(setup: &Setup) {
    let (_tcp, head) = connect(setup.addr(), &setup.target(API)).await;
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    assert_eq!(setup.mock.request_count(), 0);
}

#[tokio::test]
async fn intercepted_host_is_served_a_dev_ca_leaf_for_that_name_only() {
    let setup = Setup::new().await;

    let (tcp, head) = connect(setup.addr(), &setup.target(API)).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let mut tls = tls_over(tcp, setup.dev_roots(), API, true).await.unwrap();
    let response = exchange(
        &mut tls,
        &format!(
            "GET /mitm?x=1 HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            setup.target(API)
        ),
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let echo: Echo = serde_json::from_str(&response[response.find("\r\n\r\n").unwrap() + 4..])
        .unwrap_or_else(|_| panic!("{response}"));
    assert_eq!(echo.path, "/mitm");
    assert_eq!(echo.query.as_deref(), Some("x=1"));
    assert_eq!(echo.authority.as_deref(), Some(setup.target(API).as_str()));
    assert_eq!(setup.mock.request_count(), 1);
}

#[tokio::test]
async fn dev_ca_leaf_is_cached_and_valid_for_the_connect_host_only() {
    let setup = Setup::new().await;
    let config = setup.dev_ca.server_config(API).unwrap();
    let again = setup.dev_ca.server_config(&API.to_uppercase()).unwrap();
    assert!(Arc::ptr_eq(&config, &again));

    let (tcp, _) = connect(setup.addr(), &setup.target(API)).await;
    let tls = tls_over(tcp, setup.dev_roots(), API, true).await.unwrap();
    let leaf = tls.get_ref().1.peer_certificates().unwrap()[0].clone();
    let verifier = WebPkiServerVerifier::builder(Arc::new(setup.dev_roots()))
        .build()
        .unwrap();
    let verify = |name: &str| {
        verifier.verify_server_cert(
            &leaf,
            &[],
            &ServerName::try_from(name.to_string()).unwrap(),
            &[],
            UnixTime::now(),
        )
    };

    assert!(verify(API).is_ok());
    assert!(verify(OTHER).is_err());
}

#[tokio::test]
async fn non_intercepted_host_is_tunnelled_with_the_upstreams_own_certificate() {
    install_crypto_provider();
    let upstream_ca = TestCa::new();
    let leaf = upstream_ca.issue(&[API, OTHER]);
    let setup = Setup::with_leaf(leaf.clone(), &upstream_ca).await;

    let (tcp, head) = connect(setup.addr(), &setup.target(OTHER)).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let tls = tls_over(tcp, upstream_ca.root_store(), OTHER, true)
        .await
        .unwrap();

    assert_eq!(
        tls.get_ref().1.peer_certificates().unwrap()[0],
        leaf.cert_der
    );
}

#[tokio::test]
async fn expired_upstream_certificate_is_502_before_connect_succeeds() {
    install_crypto_provider();
    let upstream_ca = TestCa::new();
    let setup = Setup::with_leaf(
        upstream_ca.issue_with(LeafOptions::expired(&[API])),
        &upstream_ca,
    )
    .await;

    assert_connect_502(&setup).await;
}

#[tokio::test]
async fn upstream_certificate_for_another_name_is_502() {
    install_crypto_provider();
    let upstream_ca = TestCa::new();
    let setup = Setup::with_leaf(upstream_ca.issue(&[OTHER]), &upstream_ca).await;

    assert_connect_502(&setup).await;
}

#[tokio::test]
async fn upstream_certificate_from_an_unknown_ca_is_502() {
    install_crypto_provider();
    let upstream_ca = TestCa::new();
    let setup = Setup::build(upstream_ca.issue(&[API]), None).await;

    assert_connect_502(&setup).await;
}

#[tokio::test]
async fn sni_for_another_host_is_rejected_and_audited() {
    let logs = capture_logs();
    let setup = Setup::new().await;

    let (tcp, head) = connect(setup.addr(), &setup.target(API)).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let result = tls_skipping_verification(tcp, OTHER).await;

    assert!(result.is_err());
    assert_eq!(setup.mock.request_count(), 0);
    let expected = format!(
        r#"ingress="connect" scheme="https" host="{API}" port={} method=CONNECT path="" rules= decision="rejected" status=200"#,
        setup.mock.port()
    );
    eventually("the rejected session to be audited", || {
        std::future::ready(
            logs.contents().lines().any(|line| {
                line.contains(credshim_mitm::AUDIT_TARGET) && line.ends_with(&expected)
            }),
        )
    })
    .await;
}

#[tokio::test]
async fn missing_sni_is_rejected() {
    let setup = Setup::new().await;

    let (tcp, _) = connect(setup.addr(), &setup.target(API)).await;
    let result = tls_over(tcp, setup.dev_roots(), API, false).await;

    assert!(result.is_err());
    assert_eq!(setup.mock.request_count(), 0);
}

#[tokio::test]
async fn inner_requests_naming_another_authority_are_rejected() {
    let setup = Setup::new().await;
    let api = setup.target(API);
    let cases = [
        format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            setup.target(OTHER)
        ),
        format!("GET / HTTP/1.1\r\nHost: {API}\r\nConnection: close\r\n\r\n"),
        "GET / HTTP/1.1\r\nConnection: close\r\n\r\n".to_string(),
        format!(
            "GET https://{}/ HTTP/1.1\r\nHost: {api}\r\nConnection: close\r\n\r\n",
            setup.target(OTHER)
        ),
    ];

    for request in cases {
        let (tcp, _) = connect(setup.addr(), &api).await;
        let mut tls = tls_over(tcp, setup.dev_roots(), API, true).await.unwrap();
        let response = exchange(&mut tls, &request).await;
        assert!(
            response.starts_with("HTTP/1.1 421") || response.starts_with("HTTP/1.1 400"),
            "{request:?} -> {response}"
        );
    }
    assert_eq!(setup.mock.request_count(), 0);
}

#[tokio::test]
async fn inner_host_comparison_ignores_case() {
    let setup = Setup::new().await;
    let (tcp, _) = connect(setup.addr(), &setup.target(API)).await;
    let mut tls = tls_over(tcp, setup.dev_roots(), API, true).await.unwrap();

    let response = exchange(
        &mut tls,
        &format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            setup.target(&API.to_uppercase())
        ),
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}

#[tokio::test]
async fn reqwest_through_mitm_reuses_and_survives_multiple_requests() {
    let setup = Setup::new().await;
    let client = setup.client();

    for i in 0..3 {
        let echo: Echo = client
            .get(setup.url(&format!("/n/{i}")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(echo.path, format!("/n/{i}"));
    }
    assert_eq!(setup.mock.request_count(), 3);
}

#[tokio::test]
async fn sse_events_are_not_buffered_through_mitm() {
    let setup = Setup::new().await;

    assert_sse_unbuffered(&setup.client(), setup.url("/sse")).await;
}

#[tokio::test]
async fn large_bodies_are_byte_identical_through_mitm() {
    let setup = Setup::new().await;

    assert_large_bodies_intact(&setup.client(), &setup.mock, API).await;
}

#[tokio::test]
async fn intercepted_request_values_never_reach_the_logs() {
    let logs = capture_logs();
    let setup = Setup::new().await;
    let header_secret = fake_secret("mitm-header");
    let query_secret = fake_secret("mitm-query");

    setup
        .client()
        .get(setup.url(&format!("/v1/x?key={query_secret}")))
        .bearer_auth(&header_secret)
        .send()
        .await
        .unwrap();

    logs.assert_absent(&[&header_secret, &query_secret]);
}
