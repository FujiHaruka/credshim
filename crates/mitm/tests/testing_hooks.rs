use std::collections::HashMap;

use credshim_mitm::{TestingHooks, Upstream};
use credshim_testkit::{MockUpstream, TestCa, install_crypto_provider};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn get_root(upstream: &Upstream, host: &str) -> anyhow::Result<String> {
    let mut tls = upstream.connect_tls(host, 443, &[b"http/1.1"]).await?;
    tls.write_all(
        format!("GET /hooked HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await?;
    let mut response = String::new();
    tls.read_to_string(&mut response).await?;
    Ok(response)
}

#[tokio::test]
async fn hooks_redirect_a_public_name_to_a_mock_trusted_by_the_test_ca() {
    install_crypto_provider();
    let ca = TestCa::new();
    let mock = MockUpstream::https(ca.issue(&["api.openai.com"]))
        .start()
        .await;
    let upstream = Upstream::with_testing_hooks(TestingHooks {
        extra_trust_anchors: vec![ca.cert_der()],
        resolve_overrides: HashMap::from([("api.openai.com".to_string(), mock.addr())]),
    })
    .unwrap();

    let response = get_root(&upstream, "api.openai.com").await.unwrap();

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("\"path\":\"/hooked\""));
    assert_eq!(mock.request_count(), 1);
}

#[tokio::test]
async fn without_extra_anchor_the_platform_verifier_rejects_the_test_ca() {
    install_crypto_provider();
    let ca = TestCa::new();
    let mock = MockUpstream::https(ca.issue(&["api.openai.com"]))
        .start()
        .await;
    let upstream = Upstream::with_testing_hooks(TestingHooks {
        extra_trust_anchors: vec![],
        resolve_overrides: HashMap::from([("api.openai.com".to_string(), mock.addr())]),
    })
    .unwrap();

    let err = get_root(&upstream, "api.openai.com").await.unwrap_err();

    assert!(err.to_string().contains("TLS verification"), "{err}");
    assert_eq!(mock.request_count(), 0);
}
