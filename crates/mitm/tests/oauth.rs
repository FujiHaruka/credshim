mod common;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{Downstream, client_for};
use credshim_core::{Injector, RuleSet, Secrets};
use credshim_mitm::{CertificateAuthority, Intercept, Proxy, ProxyConfig, TestingHooks, Upstream};
use credshim_oauth::{ClientAuth, ClientSecretSpec, OAuth, Provider, ProviderSpec, Vault};
use credshim_testkit::oauth::{
    ClientAuthMethod, MOCK_CLIENT_ID, MOCK_ID_TOKEN, MOCK_SCOPE, TokenFormat, pkce_challenge,
};
use credshim_testkit::{
    MockOAuth, MockOAuthConfig, TestCa, capture_logs, fake_secret, install_crypto_provider,
};
use secrecy::SecretString;

const AUTH_HOST: &str = "oauth.example.test";
const API_HOST: &str = "api.example.test";
const CLIENT_DUMMY: &str = "credshim-oauth-client-secret-0123456789";
const REDIRECT: &str = "http://localhost:8080/callback";
const VERIFIER: &str = "test-code-verifier-0123456789-0123456789-0123456789";

struct Options {
    mock: MockOAuthConfig,
    vault: Option<(PathBuf, SecretString)>,
    replay_window: Duration,
    max_body: usize,
    downstream: Downstream,
}

impl Options {
    fn new(auth: ClientAuthMethod, format: TokenFormat) -> Self {
        let mut mock = MockOAuthConfig::new(fake_secret("oauth-client"));
        mock.client_auth = auth;
        mock.format = format;
        Self {
            mock,
            vault: None,
            replay_window: Duration::from_secs(30),
            max_body: 64 * 1024,
            downstream: Downstream::Http1,
        }
    }
}

struct Fixture {
    proxy: Proxy,
    oauth: Arc<OAuth>,
    mock: Arc<MockOAuth>,
    dev_ca: Arc<CertificateAuthority>,
    upstream: Upstream,
    options: Options,
    _dir: tempfile::TempDir,
}

#[derive(Debug)]
struct Tokens {
    raw: String,
    fields: HashMap<String, String>,
}

impl Tokens {
    fn get(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    fn access(&self) -> &str {
        self.get("access_token").expect("access_token")
    }

    fn refresh(&self) -> &str {
        self.get("refresh_token").expect("refresh_token")
    }
}

fn provider(options: &Options) -> Provider {
    let spec = ProviderSpec {
        name: "example".to_string(),
        token_endpoint: format!("https://{AUTH_HOST}/token"),
        revoke_endpoint: Some(format!("https://{AUTH_HOST}/revoke")),
        client_id: Some(MOCK_CLIENT_ID.to_string()),
        client_secret: Some(ClientSecretSpec {
            secret: "oauth-client".to_string(),
            dummy: CLIENT_DUMMY.to_string(),
        }),
        client_auth: match options.mock.client_auth {
            ClientAuthMethod::Post => ClientAuth::ClientSecretPost,
            ClientAuthMethod::Basic => ClientAuth::ClientSecretBasic,
        },
        resource_hosts: vec![API_HOST.to_string()],
        id_token: Default::default(),
    };
    Provider::new(
        spec,
        Some(SecretString::from(options.mock.client_secret.as_str())),
    )
    .unwrap()
}

async fn start_proxy(
    options: &Options,
    dev_ca: Arc<CertificateAuthority>,
    upstream: Upstream,
) -> (Proxy, Arc<OAuth>) {
    let vault = match &options.vault {
        Some((path, key)) => Vault::open(path.clone(), key).unwrap(),
        None => Vault::in_memory(),
    };
    let oauth = Arc::new(
        OAuth::new(vec![provider(options)], vault)
            .unwrap()
            .with_replay_window(options.replay_window)
            .with_max_body(options.max_body),
    );
    let rules = RuleSet::from_rules(oauth.client_secret_rules().unwrap()).unwrap();
    let injector = Injector::new(rules, Secrets::new())
        .unwrap()
        .with_tokens(oauth.clone());
    let mut config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
    config.intercept = Some(Intercept::new(
        dev_ca,
        injector.rules().hosts().chain(oauth.hosts()),
    ));
    config.injector = Arc::new(injector);
    config.oauth = Some(oauth.clone());
    (Proxy::bind(config, upstream).await.unwrap(), oauth)
}

impl Fixture {
    async fn new(options: Options) -> Self {
        install_crypto_provider();
        let upstream_ca = TestCa::new();
        let mock = Arc::new(
            MockOAuth::start(
                upstream_ca.issue(&[AUTH_HOST, API_HOST]),
                options.mock.clone(),
            )
            .await,
        );
        let dir = tempfile::tempdir().unwrap();
        let dev_ca = Arc::new(CertificateAuthority::init(&dir.path().join("ca")).unwrap());
        let upstream = Upstream::with_testing_hooks(TestingHooks {
            extra_trust_anchors: vec![upstream_ca.cert_der()],
            resolve_overrides: [AUTH_HOST, API_HOST]
                .iter()
                .map(|host| (host.to_string(), mock.addr()))
                .collect(),
        })
        .unwrap();
        let (proxy, oauth) = start_proxy(&options, dev_ca.clone(), upstream.clone()).await;
        Self {
            proxy,
            oauth,
            mock,
            dev_ca,
            upstream,
            options,
            _dir: dir,
        }
    }

    async fn restart(&mut self) {
        let (proxy, oauth) =
            start_proxy(&self.options, self.dev_ca.clone(), self.upstream.clone()).await;
        self.proxy = proxy;
        self.oauth = oauth;
    }

    fn client(&self) -> reqwest::Client {
        client_for(
            self.proxy.local_addr(),
            self.dev_ca.cert_der().as_ref(),
            self.options.downstream,
        )
    }

    fn token_request(&self, mut form: Vec<(&str, String)>) -> reqwest::RequestBuilder {
        let request = self.client().post(format!("https://{AUTH_HOST}/token"));
        match self.options.mock.client_auth {
            ClientAuthMethod::Post => {
                form.push(("client_id", MOCK_CLIENT_ID.to_string()));
                form.push(("client_secret", CLIENT_DUMMY.to_string()));
                request.form(&form)
            }
            ClientAuthMethod::Basic => request
                .header(
                    "authorization",
                    format!(
                        "Basic {}",
                        STANDARD.encode(format!("{MOCK_CLIENT_ID}:{CLIENT_DUMMY}"))
                    ),
                )
                .form(&form),
        }
    }

    async fn authorization_code(&self) -> String {
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{}", self.proxy.local_addr())).unwrap())
            .tls_certs_only([
                reqwest::Certificate::from_der(self.dev_ca.cert_der().as_ref()).unwrap(),
            ])
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let response = client
            .get(format!("https://{AUTH_HOST}/authorize"))
            .query(&[
                ("response_type", "code"),
                ("client_id", MOCK_CLIENT_ID),
                ("redirect_uri", REDIRECT),
                ("state", "xyz"),
                ("code_challenge", &pkce_challenge(VERIFIER)),
                ("code_challenge_method", "S256"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 303);
        let location = response.headers()["location"].to_str().unwrap().to_string();
        let query = location.split_once('?').unwrap().1;
        form_urlencoded::parse(query.as_bytes())
            .find(|(name, _)| name == "code")
            .map(|(_, code)| code.into_owned())
            .unwrap()
    }

    async fn exchange_code(&self) -> Tokens {
        let code = self.authorization_code().await;
        let response = self
            .token_request(vec![
                ("grant_type", "authorization_code".to_string()),
                ("code", code),
                ("redirect_uri", REDIRECT.to_string()),
                ("code_verifier", VERIFIER.to_string()),
            ])
            .send()
            .await
            .unwrap();
        tokens(response).await
    }

    async fn refresh(&self, refresh: &str) -> reqwest::Response {
        self.token_request(vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh.to_string()),
        ])
        .send()
        .await
        .unwrap()
    }

    async fn call_api(&self, host: &str, access: &str) -> reqwest::StatusCode {
        self.client()
            .get(format!("https://{host}/api/me"))
            .bearer_auth(access)
            .send()
            .await
            .unwrap()
            .status()
    }

    fn reals(&self) -> Vec<String> {
        let mut reals = self.mock.issued();
        reals.push(self.options.mock.client_secret.clone());
        reals
    }

    fn assert_app_sees_only_dummies(&self, tokens: &Tokens) {
        for real in self.reals() {
            assert!(!tokens.raw.contains(&real), "a real token reached the app");
        }
        assert!(tokens.access().starts_with("csh_at_"), "{tokens:?}");
        if let Some(refresh) = tokens.get("refresh_token") {
            assert!(refresh.starts_with("csh_rt_"), "{tokens:?}");
        }
    }
}

async fn tokens(response: reqwest::Response) -> Tokens {
    assert_eq!(response.status(), 200);
    let content_type = response.headers()["content-type"]
        .to_str()
        .unwrap()
        .to_string();
    let length: usize = response.headers()["content-length"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let raw = response.text().await.unwrap();
    assert_eq!(length, raw.len());
    let fields = if content_type.starts_with("application/json") {
        serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&raw)
            .unwrap()
            .into_iter()
            .map(|(name, value)| match value {
                serde_json::Value::String(text) => (name, text),
                other => (name, other.to_string()),
            })
            .collect()
    } else {
        form_urlencoded::parse(raw.as_bytes())
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect()
    };
    Tokens { raw, fields }
}

#[tokio::test]
async fn code_exchange_hands_the_app_dummies_and_the_api_real_tokens() {
    let logs = capture_logs();
    for (auth, format) in [
        (ClientAuthMethod::Post, TokenFormat::Json),
        (ClientAuthMethod::Basic, TokenFormat::Form),
    ] {
        let f = Fixture::new(Options::new(auth, format)).await;

        let tokens = f.exchange_code().await;

        f.assert_app_sees_only_dummies(&tokens);
        assert_eq!(tokens.get("id_token"), Some(MOCK_ID_TOKEN));
        assert_eq!(tokens.get("scope"), Some(MOCK_SCOPE));
        assert_eq!(tokens.get("token_type"), Some("Bearer"));
        assert_eq!(tokens.get("expires_in"), Some("3600"));

        assert_eq!(f.call_api(API_HOST, tokens.access()).await, 200);
        let real_access = f.mock.issued()[0].clone();
        assert_eq!(f.mock.bearers(), [real_access]);

        let sent = &f.mock.requests()[0];
        assert!(!sent.body.contains(CLIENT_DUMMY));
        assert_eq!(sent.headers["accept-encoding"], "identity");
        match auth {
            ClientAuthMethod::Post => {
                assert!(sent.body.contains(&f.options.mock.client_secret));
            }
            ClientAuthMethod::Basic => {
                let expected =
                    STANDARD.encode(format!("{MOCK_CLIENT_ID}:{}", f.options.mock.client_secret));
                assert_eq!(sent.headers["authorization"], format!("Basic {expected}"));
            }
        }
        let reals = f.reals();
        logs.assert_absent(&reals.iter().map(String::as_str).collect::<Vec<_>>());
    }
}

#[tokio::test]
async fn client_credentials_grant_gets_a_dummy_access_token() {
    let f = Fixture::new(Options::new(ClientAuthMethod::Post, TokenFormat::Json)).await;

    let response = f
        .token_request(vec![("grant_type", "client_credentials".to_string())])
        .send()
        .await
        .unwrap();
    let tokens = tokens(response).await;

    f.assert_app_sees_only_dummies(&tokens);
    assert_eq!(tokens.get("refresh_token"), None);
    assert_eq!(f.call_api(API_HOST, tokens.access()).await, 200);
}

#[tokio::test]
async fn rotated_refresh_tokens_get_new_dummies_and_the_old_one_is_retired() {
    let mut options = Options::new(ClientAuthMethod::Post, TokenFormat::Json);
    options.replay_window = Duration::ZERO;
    let f = Fixture::new(options).await;
    let first = f.exchange_code().await;

    let second = tokens(f.refresh(first.refresh()).await).await;

    f.assert_app_sees_only_dummies(&second);
    assert_ne!(second.refresh(), first.refresh());
    assert_ne!(second.access(), first.access());
    assert_eq!(f.call_api(API_HOST, second.access()).await, 200);
    assert!(f.oauth.vault().get(first.refresh()).is_none());

    let stale = f.refresh(first.refresh()).await;
    assert_eq!(stale.status(), 400);
    let last = f.mock.requests().pop().unwrap();
    assert!(last.body.contains(first.refresh()));

    let third = tokens(f.refresh(second.refresh()).await).await;
    f.assert_app_sees_only_dummies(&third);
    assert_eq!(f.mock.refreshes(), 3);
}

#[tokio::test]
async fn unrotated_refresh_tokens_keep_their_dummy() {
    let mut options = Options::new(ClientAuthMethod::Basic, TokenFormat::Form);
    options.mock.rotate_refresh = false;
    options.replay_window = Duration::ZERO;
    let f = Fixture::new(options).await;
    let first = f.exchange_code().await;

    for _ in 0..2 {
        let next = tokens(f.refresh(first.refresh()).await).await;
        f.assert_app_sees_only_dummies(&next);
        assert_eq!(next.get("refresh_token"), None);
        assert_eq!(f.call_api(API_HOST, next.access()).await, 200);
    }
    assert!(f.oauth.vault().get(first.refresh()).is_some());
    assert_eq!(f.mock.refreshes(), 2);
}

#[tokio::test]
async fn concurrent_refreshes_share_one_upstream_exchange() {
    let mut options = Options::new(ClientAuthMethod::Post, TokenFormat::Json);
    options.mock.refresh_delay = Duration::from_millis(300);
    let f = Fixture::new(options).await;
    let first = f.exchange_code().await;

    let (a, b) = tokio::join!(f.refresh(first.refresh()), f.refresh(first.refresh()));
    let (a, b) = (tokens(a).await, tokens(b).await);

    assert_eq!(f.mock.refreshes(), 1);
    assert_eq!(a.raw, b.raw);
    f.assert_app_sees_only_dummies(&a);
    assert_eq!(f.call_api(API_HOST, a.access()).await, 200);
}

#[tokio::test]
async fn refresh_works_after_the_proxy_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let mut options = Options::new(ClientAuthMethod::Post, TokenFormat::Json);
    options.vault = Some((dir.path().join("vault.age"), Vault::generate_key()));
    let mut f = Fixture::new(options).await;
    let first = f.exchange_code().await;

    f.restart().await;
    let second = tokens(f.refresh(first.refresh()).await).await;

    f.assert_app_sees_only_dummies(&second);
    assert_eq!(f.call_api(API_HOST, second.access()).await, 200);
    assert_eq!(f.call_api(API_HOST, first.access()).await, 200);
    let stored = std::fs::read(dir.path().join("vault.age")).unwrap();
    for real in f.reals() {
        assert!(!String::from_utf8_lossy(&stored).contains(&real));
    }
}

#[tokio::test]
async fn access_dummy_sent_outside_resource_hosts_is_refused() {
    let f = Fixture::new(Options::new(ClientAuthMethod::Post, TokenFormat::Json)).await;
    let tokens = f.exchange_code().await;

    assert_eq!(f.call_api(AUTH_HOST, tokens.access()).await, 403);
    assert!(f.mock.bearers().is_empty());

    let plain = f
        .client()
        .get("http://127.0.0.1:9/api/me")
        .bearer_auth(tokens.access())
        .send()
        .await
        .unwrap();
    assert_eq!(plain.status(), 403);

    let refresh_as_bearer = f.call_api(API_HOST, tokens.refresh()).await;
    assert_eq!(refresh_as_bearer, 403);
}

#[tokio::test]
async fn revocation_swaps_the_token_and_forgets_it() {
    let f = Fixture::new(Options::new(ClientAuthMethod::Post, TokenFormat::Json)).await;
    let tokens = f.exchange_code().await;
    let real_refresh = f.mock.issued()[1].clone();

    let response = f
        .client()
        .post(format!("https://{AUTH_HOST}/revoke"))
        .form(&[("token", tokens.refresh())])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(!f.mock.is_active(&real_refresh));
    assert!(f.oauth.vault().get(tokens.refresh()).is_none());

    let real_access = f.mock.issued()[0].clone();
    let response = f
        .client()
        .post(format!("https://{AUTH_HOST}/revoke"))
        .query(&[("token", tokens.access())])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(!f.mock.is_active(&real_access));
    assert!(f.oauth.vault().get(tokens.access()).is_none());
}

#[tokio::test]
async fn oversized_token_requests_are_refused_before_reaching_upstream() {
    let mut options = Options::new(ClientAuthMethod::Post, TokenFormat::Json);
    options.max_body = 1024;
    let f = Fixture::new(options).await;

    let response = f
        .token_request(vec![
            ("grant_type", "client_credentials".to_string()),
            ("padding", "x".repeat(4096)),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 413);
    assert!(f.mock.requests().is_empty());
}

#[tokio::test]
async fn client_secret_dummy_is_refused_away_from_the_token_endpoint() {
    let f = Fixture::new(Options::new(ClientAuthMethod::Basic, TokenFormat::Json)).await;
    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!("{MOCK_CLIENT_ID}:{CLIENT_DUMMY}"))
    );

    let response = f
        .client()
        .get(format!("https://{API_HOST}/api/me"))
        .header("authorization", basic)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 403);
    assert!(f.mock.bearers().is_empty());
}

#[tokio::test]
async fn token_exchange_and_api_calls_work_over_http2() {
    let mut options = Options::new(ClientAuthMethod::Basic, TokenFormat::Json);
    options.downstream = Downstream::Http2;
    let f = Fixture::new(options).await;

    let first = f.exchange_code().await;
    f.assert_app_sees_only_dummies(&first);
    let refreshed = tokens(f.refresh(first.refresh()).await).await;

    f.assert_app_sees_only_dummies(&refreshed);
    assert_eq!(f.call_api(API_HOST, refreshed.access()).await, 200);
}
