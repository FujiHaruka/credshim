use std::convert::Infallible;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use credshim_core::TokenResolver;
use credshim_oauth::{
    ClientSecretSpec, EXPIRY_GRACE, ExchangeError, OAuth, Provider, ProviderError, ProviderSpec,
    TokenKind, Vault, VaultError,
};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use secrecy::SecretString;

const CLIENT_DUMMY: &str = "credshim-client-secret-0123456789abcdef";
const REAL_SECRET: &str = "real-client-secret";

fn spec(name: &str, host: &str) -> ProviderSpec {
    ProviderSpec {
        name: name.to_string(),
        token_endpoint: format!("https://{host}/token"),
        revoke_endpoint: Some(format!("https://{host}/revoke")),
        client_id: Some("client-a".to_string()),
        client_secret: Some(ClientSecretSpec {
            secret: format!("{name}-secret"),
            dummy: format!("{CLIENT_DUMMY}-{name}"),
        }),
        client_auth: Default::default(),
        resource_hosts: vec![format!("api.{host}")],
        id_token: Default::default(),
    }
}

fn provider(name: &str, host: &str) -> Provider {
    Provider::new(spec(name, host), Some(SecretString::from(REAL_SECRET))).unwrap()
}

fn oauth() -> OAuth {
    OAuth::new(
        vec![
            provider("a", "a.example.test"),
            provider("b", "b.example.test"),
        ],
        Vault::in_memory(),
    )
    .unwrap()
}

fn parts(path: &str, content_type: &str) -> http::request::Parts {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", content_type)
        .body(())
        .unwrap()
        .into_parts()
        .0
}

type Sent = Arc<Mutex<Option<Request<Bytes>>>>;

async fn run(
    oauth: &OAuth,
    host: &str,
    path: &str,
    body: &str,
    response: Response<Full<Bytes>>,
) -> (Result<Response<Bytes>, ExchangeError>, Sent) {
    let parts = parts(path, "application/x-www-form-urlencoded");
    let exchange = oauth.exchange(host, 443, &parts).expect("endpoint");
    let sent: Sent = Arc::default();
    let record = sent.clone();
    let result = exchange
        .run(
            parts,
            Full::new(Bytes::from(body.to_string())),
            |req| async move {
                *record.lock().unwrap() = Some(req);
                Ok::<_, Infallible>(response)
            },
        )
        .await;
    (result, sent)
}

fn json(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

fn sent_body(sent: &Sent) -> String {
    let guard = sent.lock().unwrap();
    String::from_utf8(guard.as_ref().expect("sent").body().to_vec()).unwrap()
}

const CLIENT_CREDENTIALS: &str = "grant_type=client_credentials&client_id=client-a";

#[tokio::test]
async fn successful_responses_that_cannot_be_rewritten_are_withheld() {
    let oauth = oauth();
    let gzip = Response::builder()
        .header("content-type", "application/json")
        .header("content-encoding", "gzip")
        .body(Full::new(Bytes::from_static(
            b"{\"access_token\":\"real\"}",
        )))
        .unwrap();
    for response in [
        json(StatusCode::OK, "<xml>real-token</xml>"),
        json(StatusCode::OK, "{\"token\":\"real\"}"),
        json(StatusCode::OK, "[\"real\"]"),
        gzip,
    ] {
        let (result, _) = run(
            &oauth,
            "a.example.test",
            "/token",
            CLIENT_CREDENTIALS,
            response,
        )
        .await;
        let err = result.unwrap_err();
        assert!(matches!(err, ExchangeError::Unreadable), "{err}");
        assert_eq!(err.status(), StatusCode::BAD_GATEWAY);
    }
    assert!(oauth.vault().is_empty());
}

#[tokio::test]
async fn error_responses_pass_through_unchanged() {
    let oauth = oauth();
    let body = "{\"error\":\"invalid_grant\"}";

    let (result, _) = run(
        &oauth,
        "a.example.test",
        "/token",
        CLIENT_CREDENTIALS,
        json(StatusCode::BAD_REQUEST, body),
    )
    .await;

    let response = result.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.body(), body);
}

#[tokio::test]
async fn oversized_responses_are_withheld() {
    let oauth = oauth().with_max_body(64);
    let big = format!("{{\"access_token\":\"{}\"}}", "x".repeat(128));

    let (result, _) = run(
        &oauth,
        "a.example.test",
        "/token",
        CLIENT_CREDENTIALS,
        json(StatusCode::OK, &big),
    )
    .await;

    assert!(matches!(result, Err(ExchangeError::ResponseTooLarge(64))));
}

#[tokio::test]
async fn requests_for_another_client_or_provider_never_leave_the_proxy() {
    let oauth = oauth();
    let foreign = oauth.vault().issue(
        "b",
        TokenKind::Refresh,
        &SecretString::from("real-b-refresh"),
        None,
    );
    let cases = [
        (
            format!(
                "grant_type=client_credentials&client_id=client-z&client_secret={CLIENT_DUMMY}-a"
            ),
            "ClientMismatch",
        ),
        (
            format!("grant_type=refresh_token&refresh_token={foreign}"),
            "ForeignToken",
        ),
        ("not a form body".to_string(), "MalformedRequest"),
    ];
    for (body, expected) in cases {
        let (result, sent) = run(
            &oauth,
            "a.example.test",
            "/token",
            &body,
            json(StatusCode::OK, "{}"),
        )
        .await;
        let err = result.unwrap_err();
        assert!(format!("{err:?}").starts_with(expected), "{err:?}");
        assert!(sent.lock().unwrap().is_none());
    }
}

#[tokio::test]
async fn post_client_secret_and_refresh_token_are_swapped_in_the_body() {
    let oauth = oauth();
    let refresh = oauth.vault().issue(
        "a",
        TokenKind::Refresh,
        &SecretString::from("real-a-refresh"),
        None,
    );
    let body = format!(
        "grant_type=refresh_token&refresh_token={refresh}&client_id=client-a&client_secret={CLIENT_DUMMY}-a"
    );

    let (result, sent) = run(
        &oauth,
        "a.example.test",
        "/token",
        &body,
        json(
            StatusCode::OK,
            "{\"access_token\":\"real-a-access\",\"expires_in\":\"60\",\"refresh_token\":\"real-a-refresh\"}",
        ),
    )
    .await;

    assert_eq!(
        sent_body(&sent),
        format!(
            "grant_type=refresh_token&refresh_token=real-a-refresh&client_id=client-a&client_secret={REAL_SECRET}"
        )
    );
    let reply: serde_json::Value = serde_json::from_slice(result.unwrap().body()).unwrap();
    assert_eq!(reply["refresh_token"], refresh.as_str());
    assert_eq!(reply["expires_in"], "60");
    let access = reply["access_token"].as_str().unwrap();
    assert!(access.starts_with("csh_at_"));
    assert!(oauth.resolve(access).is_some());

    oauth
        .purge(SystemTime::now() + Duration::from_secs(60) + EXPIRY_GRACE + Duration::from_secs(5));
    assert!(oauth.vault().get(access).is_none());
    assert!(oauth.vault().get(&refresh).is_some());
}

#[tokio::test]
async fn failed_refreshes_are_not_replayed_to_retries() {
    let oauth = oauth();
    let refresh = oauth.vault().issue(
        "a",
        TokenKind::Refresh,
        &SecretString::from("real-a-refresh"),
        None,
    );
    let body = format!("grant_type=refresh_token&refresh_token={refresh}");

    let (first, _) = run(
        &oauth,
        "a.example.test",
        "/token",
        &body,
        json(StatusCode::SERVICE_UNAVAILABLE, "{\"error\":\"unavailable\"}"),
    )
    .await;
    assert_eq!(first.unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);

    let (retry, sent) = run(
        &oauth,
        "a.example.test",
        "/token",
        &body,
        json(StatusCode::OK, "{\"access_token\":\"real-a-access\"}"),
    )
    .await;
    assert!(sent.lock().unwrap().is_some());
    assert_eq!(retry.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn requests_without_dummies_are_forwarded_byte_for_byte() {
    let oauth = oauth();
    let body = "grant_type=client_credentials&client_id=client-a&scope=a+b%20c";

    let (_, sent) = run(
        &oauth,
        "a.example.test",
        "/token",
        body,
        json(StatusCode::BAD_REQUEST, "{}"),
    )
    .await;

    assert_eq!(sent_body(&sent), body);
    let guard = sent.lock().unwrap();
    let headers = guard.as_ref().unwrap().headers();
    assert_eq!(headers["accept-encoding"], "identity");
    assert_eq!(headers["content-length"], body.len().to_string());
}

#[test]
fn issued_tokens_resolve_to_rules_bound_by_kind() {
    let oauth = oauth();
    let access = oauth.vault().issue(
        "a",
        TokenKind::Access,
        &SecretString::from("real-a-access"),
        None,
    );

    let rule = oauth.resolve(&access).unwrap();
    assert_eq!(rule.name(), "oauth.a.access");
    let hosts: Vec<&str> = rule.hosts().collect();
    assert_eq!(hosts, ["api.a.example.test", "a.example.test"]);
    assert!(oauth.resolve("csh_at_unknown").is_none());
}

#[test]
fn vault_persists_encrypted_and_needs_its_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested/vault.age");
    let key = Vault::generate_key();
    let vault = Vault::open(path.clone(), &key).unwrap();
    let dummy = vault.issue(
        "a",
        TokenKind::Refresh,
        &SecretString::from("real-persisted-refresh"),
        None,
    );

    let stored = std::fs::read(&path).unwrap();
    assert!(!String::from_utf8_lossy(&stored).contains("real-persisted-refresh"));
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let reopened = Vault::open(path.clone(), &key).unwrap();
    assert_eq!(reopened.get(&dummy).unwrap().kind, TokenKind::Refresh);
    assert!(matches!(
        Vault::open(path.clone(), &Vault::generate_key()),
        Err(VaultError::Corrupt { .. })
    ));
    assert!(matches!(
        Vault::open(path, &SecretString::from("not a key")),
        Err(VaultError::InvalidKey)
    ));
}

#[test]
fn invalid_provider_configs_are_rejected() {
    let secret = || Some(SecretString::from(REAL_SECRET));
    let with = |edit: fn(&mut ProviderSpec)| {
        let mut spec = spec("a", "a.example.test");
        edit(&mut spec);
        Provider::new(spec, secret()).unwrap_err()
    };

    assert!(matches!(
        with(|s| s.name = "a b".into()),
        ProviderError::InvalidName(_)
    ));
    for url in [
        "http://a.example.test/token",
        "https://a.example.test/token?x=1",
        "https://a.example.test",
        "not a url",
    ] {
        let mut spec = spec("a", "a.example.test");
        spec.token_endpoint = url.to_string();
        assert!(
            matches!(
                Provider::new(spec, secret()),
                Err(ProviderError::InvalidEndpoint { .. })
            ),
            "{url}"
        );
    }
    assert!(matches!(
        with(|s| s.revoke_endpoint = Some("https://a.example.test/token".into())),
        ProviderError::SameEndpoints { .. }
    ));
    assert!(matches!(
        with(|s| s.resource_hosts = vec!["*.example.test".into()]),
        ProviderError::InvalidBinding { .. }
    ));
    assert!(matches!(
        Provider::new(spec("a", "a.example.test"), None),
        Err(ProviderError::MissingClientSecret { .. })
    ));
    assert!(matches!(
        OAuth::new(
            vec![
                provider("a", "a.example.test"),
                provider("b", "a.example.test")
            ],
            Vault::in_memory()
        ),
        Err(ProviderError::SharedEndpoint(..))
    ));
}

#[test]
fn provider_specs_parse_from_toml() {
    #[derive(serde::Deserialize)]
    struct File {
        oauth: Vec<ProviderSpec>,
    }
    let file: File = toml::from_str(
        r#"
        [[oauth]]
        name = "google"
        token_endpoint = "https://oauth2.googleapis.com/token"
        revoke_endpoint = "https://oauth2.googleapis.com/revoke"
        client_id = "client-id"
        client_secret = { secret = "google-client-secret", dummy = "credshim-google-secret-0123456789abcdef" }
        client_auth = "client_secret_basic"
        resource_hosts = ["www.googleapis.com", "gmail.googleapis.com"]
        id_token = "passthrough"
        "#,
    )
    .unwrap();
    let spec = file.oauth.into_iter().next().unwrap();
    assert_eq!(spec.client_secret_name(), Some("google-client-secret"));

    let oauth = OAuth::new(
        vec![Provider::new(spec, Some(SecretString::from(REAL_SECRET))).unwrap()],
        Vault::in_memory(),
    )
    .unwrap();
    let rules = oauth.client_secret_rules().unwrap();
    assert_eq!(rules[0].name(), "oauth.google");
    let mut hosts: Vec<&str> = oauth.hosts().collect();
    hosts.dedup();
    assert_eq!(
        hosts,
        [
            "oauth2.googleapis.com",
            "www.googleapis.com",
            "gmail.googleapis.com"
        ]
    );
}

#[tokio::test]
async fn endpoint_variants_the_upstream_may_route_alike_are_still_exchanged() {
    let oauth = oauth();
    for path in [
        "/token/",
        "/TOKEN",
        "/token.json",
        "/token;x",
        "/%74oken",
        "/token/extra",
    ] {
        let (result, _) = run(
            &oauth,
            "a.example.test",
            path,
            CLIENT_CREDENTIALS,
            json(StatusCode::OK, "{\"access_token\":\"real-variant\"}"),
        )
        .await;
        let body = result.unwrap().into_body();
        assert!(
            !String::from_utf8_lossy(&body).contains("real-variant"),
            "{path}"
        );
    }
    let parts = parts("/tokeninfo", "application/json");
    assert!(oauth.exchange("a.example.test", 443, &parts).is_none());
}

#[tokio::test]
async fn nested_tokens_are_swapped_too() {
    let oauth = oauth();
    let body = r#"{"ok":true,"access_token":"real-bot","authed_user":{"access_token":"real-user","refresh_token":"real-user-refresh","expires_in":18446744073709551615},"expires_in":1e300}"#;

    let (result, _) = run(
        &oauth,
        "a.example.test",
        "/token",
        CLIENT_CREDENTIALS,
        json(StatusCode::OK, body),
    )
    .await;

    let reply = String::from_utf8(result.unwrap().into_body().to_vec()).unwrap();
    assert!(!reply.contains("real-"), "{reply}");
    let reply: serde_json::Value = serde_json::from_str(&reply).unwrap();
    assert!(
        reply["authed_user"]["refresh_token"]
            .as_str()
            .unwrap()
            .starts_with("csh_rt_")
    );
    assert_eq!(oauth.vault().len(), 3);
}

#[tokio::test]
async fn successful_error_responses_without_tokens_pass_through() {
    let oauth = oauth();
    for (content_type, body) in [
        ("application/json", "{\"error\":\"bad_verification_code\"}"),
        (
            "application/x-www-form-urlencoded",
            "error=incorrect_client_credentials&error_description=x",
        ),
    ] {
        let response = Response::builder()
            .header("content-type", content_type)
            .body(Full::new(Bytes::from(body)))
            .unwrap();
        let (result, _) = run(
            &oauth,
            "a.example.test",
            "/token",
            CLIENT_CREDENTIALS,
            response,
        )
        .await;
        assert_eq!(result.unwrap().body(), body);
    }
}

#[tokio::test]
async fn every_revoked_query_token_is_forgotten() {
    let oauth = oauth();
    let a = oauth
        .vault()
        .issue("a", TokenKind::Access, &SecretString::from("real-1"), None);
    let b = oauth
        .vault()
        .issue("a", TokenKind::Access, &SecretString::from("real-2"), None);

    let (result, _) = run(
        &oauth,
        "a.example.test",
        &format!("/revoke?token=junk&token={a}&token={b}"),
        "",
        json(StatusCode::OK, ""),
    )
    .await;

    assert_eq!(result.unwrap().status(), StatusCode::OK);
    assert!(oauth.vault().is_empty());
}
