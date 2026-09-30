use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use http_body_util::BodyExt;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::aws::{AwsKeys, Keyring, KeyringEntry};
use crate::ca::LeafCert;

const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const REFRESH_TOKEN_GRANT: &str = "refresh_token";

#[derive(Clone, Debug)]
pub struct MockSsoConfig {
    pub access_token_lifetime: Duration,
    pub role_lifetime: Duration,
    pub issue_refresh_tokens: bool,
    pub interval_secs: u64,
    pub device_expires_in_secs: u64,
}

impl Default for MockSsoConfig {
    fn default() -> Self {
        Self {
            access_token_lifetime: Duration::from_secs(8 * 3600),
            role_lifetime: Duration::from_secs(3600),
            issue_refresh_tokens: true,
            interval_secs: 1,
            device_expires_in_secs: 600,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SsoCounts {
    pub registrations: usize,
    pub device_tokens: usize,
    pub refreshes: usize,
    pub role_credentials: usize,
    pub logouts: usize,
}

struct Device {
    user_code: String,
    approved: bool,
    refreshable: bool,
}

struct AccessToken {
    expires_at: SystemTime,
    revoked: bool,
}

#[derive(Default)]
struct SsoState {
    clients: HashMap<String, (String, bool)>,
    devices: HashMap<String, Device>,
    access_tokens: HashMap<String, AccessToken>,
    refresh_tokens: HashMap<String, String>,
    start_urls: Vec<String>,
    secrets: Vec<String>,
    counts: SsoCounts,
}

struct Shared {
    keyring: Keyring,
    config: Mutex<MockSsoConfig>,
    state: Mutex<SsoState>,
}

pub struct MockSso {
    addr: SocketAddr,
    shared: Arc<Shared>,
    accept_loop: JoinHandle<()>,
}

impl Drop for MockSso {
    fn drop(&mut self) {
        self.accept_loop.abort();
    }
}

impl MockSso {
    pub async fn start(leaf: LeafCert, keyring: Keyring, config: MockSsoConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
        let addr = listener.local_addr().unwrap();
        let shared = Arc::new(Shared {
            keyring,
            config: Mutex::new(config),
            state: Mutex::default(),
        });
        let router = Router::new().fallback(handle).with_state(shared.clone());
        let acceptor = TlsAcceptor::from(leaf.server_config(&[b"http/1.1"]));
        let accept_loop = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    continue;
                };
                let router = router.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        let _ = auto::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(tls), TowerToHyperService::new(router))
                            .await;
                    }
                });
            }
        });
        Self {
            addr,
            shared,
            accept_loop,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn configure(&self, change: impl FnOnce(&mut MockSsoConfig)) {
        change(&mut self.shared.config.lock().unwrap());
    }

    pub fn approve(&self, user_code: &str) {
        for device in self.shared.state.lock().unwrap().devices.values_mut() {
            if device.user_code == user_code {
                device.approved = true;
            }
        }
    }

    pub fn expire_access_tokens(&self) {
        for token in self.shared.state.lock().unwrap().access_tokens.values_mut() {
            token.expires_at = SystemTime::UNIX_EPOCH;
        }
    }

    pub fn revoke_refresh_tokens(&self) {
        self.shared.state.lock().unwrap().refresh_tokens.clear();
    }

    pub fn counts(&self) -> SsoCounts {
        self.shared.state.lock().unwrap().counts
    }

    pub fn start_urls(&self) -> Vec<String> {
        self.shared.state.lock().unwrap().start_urls.clone()
    }

    pub fn issued_secrets(&self) -> Vec<String> {
        self.shared.state.lock().unwrap().secrets.clone()
    }
}

fn random(prefix: &str) -> String {
    let mut raw = [0u8; 24];
    getrandom::fill(&mut raw).unwrap();
    format!("{prefix}{}", hex::encode(raw))
}

fn oidc_error(code: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [("content-type", "application/json")],
        json!({ "error": code, "error_description": code }).to_string(),
    )
        .into_response()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            ("content-type", "application/json"),
            ("x-amzn-errortype", "UnauthorizedException"),
        ],
        json!({ "message": "Session token not found or invalid" }).to_string(),
    )
        .into_response()
}

fn ok(body: Value) -> Response {
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn unix(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn handle(State(shared): State<Arc<Shared>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let host = parts
        .headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default()
        .to_string();
    let Ok(body) = body.collect().await.map(|collected| collected.to_bytes()) else {
        return oidc_error("invalid_request");
    };
    if host.starts_with("oidc.") && parts.method == Method::POST {
        let Ok(input) = serde_json::from_slice::<Value>(&body) else {
            return oidc_error("invalid_request");
        };
        return match parts.uri.path() {
            "/client/register" => register(&shared, &input),
            "/device_authorization" => device_authorization(&shared, &host, &input),
            "/token" => token(&shared, &input),
            _ => oidc_error("invalid_request"),
        };
    }
    if host.starts_with("portal.sso.") {
        let bearer = parts
            .headers
            .get("x-amz-sso_bearer_token")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        return match (parts.method.clone(), parts.uri.path()) {
            (Method::GET, "/federation/credentials") => {
                role_credentials(&shared, &bearer, parts.uri.query().unwrap_or_default())
            }
            (Method::POST, "/logout") => logout(&shared, &bearer),
            _ => (StatusCode::NOT_FOUND, Bytes::new()).into_response(),
        };
    }
    (StatusCode::NOT_FOUND, Bytes::new()).into_response()
}

fn register(shared: &Shared, input: &Value) -> Response {
    if input["clientType"] != "public" || input["clientName"].as_str().is_none() {
        return oidc_error("invalid_client_metadata");
    }
    let refreshable = input["grantTypes"]
        .as_array()
        .is_some_and(|grants| grants.iter().any(|grant| grant == REFRESH_TOKEN_GRANT));
    let id = random("client-");
    let secret = random("client-secret-");
    let mut state = shared.state.lock().unwrap();
    state.counts.registrations += 1;
    state.secrets.push(secret.clone());
    state
        .clients
        .insert(id.clone(), (secret.clone(), refreshable));
    ok(json!({
        "clientId": id,
        "clientSecret": secret,
        "clientIdIssuedAt": unix(SystemTime::now()),
        "clientSecretExpiresAt": unix(SystemTime::now() + Duration::from_secs(90 * 86400)),
    }))
}

fn client_ok(state: &SsoState, input: &Value) -> Option<bool> {
    let id = input["clientId"].as_str()?;
    let (secret, refreshable) = state.clients.get(id)?;
    (input["clientSecret"].as_str() == Some(secret.as_str())).then_some(*refreshable)
}

fn device_authorization(shared: &Shared, host: &str, input: &Value) -> Response {
    let config = shared.config.lock().unwrap().clone();
    let mut state = shared.state.lock().unwrap();
    let Some(refreshable) = client_ok(&state, input) else {
        return oidc_error("invalid_client");
    };
    let Some(start_url) = input["startUrl"].as_str() else {
        return oidc_error("invalid_request");
    };
    state.start_urls.push(start_url.to_string());
    let device_code = random("device-");
    let user_code = random("")
        .chars()
        .take(8)
        .collect::<String>()
        .to_uppercase();
    state.secrets.push(device_code.clone());
    state.devices.insert(
        device_code.clone(),
        Device {
            user_code: user_code.clone(),
            approved: false,
            refreshable,
        },
    );
    let region = host.trim_start_matches("oidc.");
    ok(json!({
        "deviceCode": device_code,
        "userCode": user_code,
        "verificationUri": format!("https://device.sso.{region}"),
        "verificationUriComplete": format!("https://device.sso.{region}?user_code={user_code}"),
        "expiresIn": config.device_expires_in_secs,
        "interval": config.interval_secs,
    }))
}

fn token(shared: &Shared, input: &Value) -> Response {
    let config = shared.config.lock().unwrap().clone();
    let mut state = shared.state.lock().unwrap();
    let Some(client_refreshable) = client_ok(&state, input) else {
        return oidc_error("invalid_client");
    };
    let refreshable = match input["grantType"].as_str() {
        Some(DEVICE_CODE_GRANT) => {
            let code = input["deviceCode"].as_str().unwrap_or_default();
            match state.devices.get(code) {
                None => return oidc_error("invalid_grant"),
                Some(device) if !device.approved => return oidc_error("authorization_pending"),
                Some(device) => {
                    let refreshable = device.refreshable;
                    state.devices.remove(code);
                    state.counts.device_tokens += 1;
                    refreshable
                }
            }
        }
        Some(REFRESH_TOKEN_GRANT) => {
            let presented = input["refreshToken"].as_str().unwrap_or_default();
            let owner = input["clientId"].as_str().unwrap_or_default();
            if state.refresh_tokens.get(presented).map(String::as_str) != Some(owner) {
                return oidc_error("invalid_grant");
            }
            state.refresh_tokens.remove(presented);
            state.counts.refreshes += 1;
            client_refreshable
        }
        _ => return oidc_error("unsupported_grant_type"),
    };
    let access = random("sso-access-");
    state.secrets.push(access.clone());
    state.access_tokens.insert(
        access.clone(),
        AccessToken {
            expires_at: SystemTime::now() + config.access_token_lifetime,
            revoked: false,
        },
    );
    let mut body = json!({
        "accessToken": access,
        "tokenType": "Bearer",
        "expiresIn": config.access_token_lifetime.as_secs(),
    });
    if refreshable && config.issue_refresh_tokens {
        let refresh = random("sso-refresh-");
        state.secrets.push(refresh.clone());
        state.refresh_tokens.insert(
            refresh.clone(),
            input["clientId"].as_str().unwrap_or_default().to_string(),
        );
        body["refreshToken"] = json!(refresh);
    }
    ok(body)
}

fn bearer_ok(state: &SsoState, bearer: &str) -> bool {
    state
        .access_tokens
        .get(bearer)
        .is_some_and(|token| !token.revoked && token.expires_at > SystemTime::now())
}

fn role_credentials(shared: &Shared, bearer: &str, query: &str) -> Response {
    let lifetime = shared.config.lock().unwrap().role_lifetime;
    let mut state = shared.state.lock().unwrap();
    if !bearer_ok(&state, bearer) {
        return unauthorized();
    }
    let params: HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    if params.get("account_id").is_none_or(|id| id.len() != 12) || !params.contains_key("role_name")
    {
        return (StatusCode::BAD_REQUEST, Bytes::new()).into_response();
    }
    state.counts.role_credentials += 1;
    let keys = AwsKeys {
        access_key_id: format!("ASIA{}", random("").to_uppercase().get(..16).unwrap()),
        secret_access_key: random("role-secret-"),
    };
    let session_token = random("role-session-token-");
    let expires_at = SystemTime::now() + lifetime;
    state.secrets.extend([
        keys.access_key_id.clone(),
        keys.secret_access_key.clone(),
        session_token.clone(),
    ]);
    shared.keyring.add(KeyringEntry {
        keys: keys.clone(),
        session_token: Some(session_token.clone()),
        expires_at: Some(expires_at),
    });
    let expiration_ms = expires_at
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    ok(json!({
        "roleCredentials": {
            "accessKeyId": keys.access_key_id,
            "secretAccessKey": keys.secret_access_key,
            "sessionToken": session_token,
            "expiration": expiration_ms,
        }
    }))
}

fn logout(shared: &Shared, bearer: &str) -> Response {
    let mut state = shared.state.lock().unwrap();
    if !bearer_ok(&state, bearer) {
        return unauthorized();
    }
    state.counts.logouts += 1;
    if let Some(token) = state.access_tokens.get_mut(bearer) {
        token.revoked = true;
    }
    state.refresh_tokens.clear();
    (StatusCode::OK, Bytes::new()).into_response()
}
