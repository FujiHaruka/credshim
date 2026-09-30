#![no_main]

use std::sync::LazyLock;

use bytes::Bytes;
use credshim_oauth::{ClientSecretSpec, OAuth, Provider, ProviderSpec, Vault};
use http_body_util::Full;
use libfuzzer_sys::fuzz_target;
use secrecy::SecretString;

static OAUTH: LazyLock<OAuth> = LazyLock::new(|| {
    let spec = ProviderSpec {
        name: "fuzz".into(),
        token_endpoint: "https://oauth.example.test/token".into(),
        revoke_endpoint: Some("https://oauth.example.test/revoke".into()),
        client_id: Some("client".into()),
        client_secret: Some(ClientSecretSpec {
            secret: "client-secret".into(),
            dummy: "credshim-fuzz-client-secret-000000".into(),
        }),
        client_auth: Default::default(),
        resource_hosts: vec!["api.example.test".into()],
        id_token: Default::default(),
    };
    let provider = Provider::new(spec, Some(SecretString::from("REAL-CLIENT-SECRET"))).unwrap();
    OAuth::new(vec![provider], Vault::in_memory()).unwrap()
});

fuzz_target!(|data: &[u8]| {
    let (selector, body) = data.split_first().unwrap_or((&0, &[]));
    let content_type = match selector % 4 {
        0 => "application/json",
        1 => "application/x-www-form-urlencoded",
        2 => "text/plain",
        _ => "application/json; charset=utf-8",
    };
    let status = if selector & 0x80 == 0 { 200 } else { 400 };
    let path = if selector & 0x40 == 0 {
        "/token"
    } else {
        "/revoke"
    };
    let (parts, ()) = http::Request::post(format!("https://oauth.example.test{path}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(())
        .unwrap()
        .into_parts();
    let Some(exchange) = OAUTH.exchange("oauth.example.test", 443, &parts) else {
        return;
    };
    let request = Full::new(Bytes::from_static(
        b"grant_type=authorization_code&code=x&client_id=client&client_secret=credshim-fuzz-client-secret-000000",
    ));
    let response_body = Bytes::copy_from_slice(body);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let result = runtime.block_on(exchange.run(parts, request, |_req| async move {
        Ok::<_, std::convert::Infallible>(
            http::Response::builder()
                .status(status)
                .header("content-type", content_type)
                .body(Full::new(response_body))
                .unwrap(),
        )
    }));
    if let Ok(response) = result {
        assert_eq!(
            response.headers()["content-length"],
            response.body().len().to_string().as_str()
        );
    }
});
