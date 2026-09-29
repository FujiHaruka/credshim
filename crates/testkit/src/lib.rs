pub mod ca;
pub mod logs;
pub mod pattern;
pub mod upstream;

pub use ca::{LeafCert, LeafOptions, TestCa};
pub use logs::{LogCapture, capture_logs, fake_secret};
pub use upstream::{Alpn, Echo, MockUpstream, RecordedRequest, SseTick, UploadSummary};

pub fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

pub fn client_trusting(ca: &TestCa) -> reqwest::ClientBuilder {
    let root =
        reqwest::Certificate::from_der(ca.cert_der().as_ref()).expect("test CA as reqwest cert");
    reqwest::Client::builder().tls_certs_only([root]).no_proxy()
}
