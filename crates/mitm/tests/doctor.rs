mod common;

use std::sync::Arc;

use common::{connect, exchange, h2_over_proxy, http1_body, raw_exchange, tls_over};
use credshim_mitm::{CertificateAuthority, DOCTOR_HOST, Proxy, ProxyConfig, Upstream};
use credshim_testkit::{TestCa, install_crypto_provider};
use http_body_util::BodyExt;
use rustls::RootCertStore;

struct Setup {
    proxy: Proxy,
    ca: Arc<CertificateAuthority>,
    _dir: tempfile::TempDir,
}

impl Setup {
    async fn new(with_ca: bool) -> Self {
        install_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let ca = Arc::new(CertificateAuthority::init(dir.path()).unwrap());
        let mut config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
        config.doctor_ca = with_ca.then(|| ca.clone());
        let proxy = Proxy::bind(config, Upstream::new().unwrap()).await.unwrap();
        Self {
            proxy,
            ca,
            _dir: dir,
        }
    }

    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca.cert_der().clone()).unwrap();
        roots
    }
}

fn report(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap()
}

#[tokio::test]
async fn doctor_host_is_answered_by_the_proxy_over_http1_and_h2() {
    let setup = Setup::new(true).await;
    let target = format!("{DOCTOR_HOST}:443");

    let (tcp, head) = connect(setup.proxy.local_addr(), &target).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let mut tls = tls_over(tcp, setup.roots(), DOCTOR_HOST, true)
        .await
        .unwrap();
    let response = exchange(
        &mut tls,
        &format!("GET / HTTP/1.1\r\nHost: {DOCTOR_HOST}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    let body = report(&http1_body(&response));
    assert_eq!(body["via_proxy"], true);
    assert_eq!(body["ca_trusted"], true);
    assert_eq!(body["protocol"], "http/1.1");

    let mut h2 = h2_over_proxy(setup.proxy.local_addr(), &target, setup.roots()).await;
    let response = h2
        .send_request(
            http::Request::get(format!("https://{DOCTOR_HOST}/"))
                .body(Default::default())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        report(std::str::from_utf8(&bytes).unwrap())["protocol"],
        "h2"
    );
}

#[tokio::test]
async fn a_client_that_does_not_trust_the_ca_fails_the_handshake() {
    let setup = Setup::new(true).await;
    let mut other = RootCertStore::empty();
    other.add(TestCa::new().cert_der()).unwrap();

    let (tcp, _) = connect(setup.proxy.local_addr(), &format!("{DOCTOR_HOST}:443")).await;

    assert!(tls_over(tcp, other, DOCTOR_HOST, true).await.is_err());
}

#[tokio::test]
async fn plain_http_doctor_reports_no_tls() {
    let setup = Setup::new(true).await;

    let response = raw_exchange(
        setup.proxy.local_addr(),
        &format!(
            "GET http://{DOCTOR_HOST}/ HTTP/1.1\r\nHost: {DOCTOR_HOST}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;

    let body = report(&http1_body(&response));
    assert_eq!(body["via_proxy"], true);
    assert_eq!(body["tls"], false);
}

#[tokio::test]
async fn doctor_without_a_ca_refuses_the_tunnel() {
    let setup = Setup::new(false).await;

    let (_, head) = connect(setup.proxy.local_addr(), &format!("{DOCTOR_HOST}:443")).await;

    assert!(head.starts_with("HTTP/1.1 503"), "{head}");
}
