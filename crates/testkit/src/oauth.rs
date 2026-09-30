use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Json, Redirect, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::ca::LeafCert;

pub const MOCK_CLIENT_ID: &str = "credshim-test-client";
pub const MOCK_SCOPE: &str = "profile email";
pub const MOCK_ID_TOKEN: &str = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJtb2NrIn0.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientAuthMethod {
    Post,
    Basic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenFormat {
    Json,
    Form,
}

#[derive(Clone, Debug)]
pub struct MockOAuthConfig {
    pub client_secret: String,
    pub client_auth: ClientAuthMethod,
    pub format: TokenFormat,
    pub rotate_refresh: bool,
    pub expires_in: u64,
    pub refresh_delay: Duration,
}

impl MockOAuthConfig {
    pub fn new(client_secret: impl Into<String>) -> Self {
        Self {
            client_secret: client_secret.into(),
            client_auth: ClientAuthMethod::Post,
            format: TokenFormat::Json,
            rotate_refresh: true,
            expires_in: 3600,
            refresh_delay: Duration::ZERO,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TokenRequest {
    pub path: String,
    pub query: Option<String>,
    pub headers: HeaderMap,
    pub body: String,
}

#[derive(Default)]
struct Tokens {
    codes: HashMap<String, String>,
    access: HashSet<String>,
    refresh: HashSet<String>,
    issued: Vec<String>,
}

struct Shared {
    config: MockOAuthConfig,
    tokens: Mutex<Tokens>,
    requests: Mutex<Vec<TokenRequest>>,
    refreshes: AtomicUsize,
    bearers: Mutex<Vec<String>>,
}

pub struct MockOAuth {
    addr: SocketAddr,
    shared: Arc<Shared>,
    accept_loop: JoinHandle<()>,
}

impl Drop for MockOAuth {
    fn drop(&mut self) {
        self.accept_loop.abort();
    }
}

impl MockOAuth {
    pub async fn start(leaf: LeafCert, config: MockOAuthConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
        let addr = listener.local_addr().unwrap();
        let shared = Arc::new(Shared {
            config,
            tokens: Mutex::default(),
            requests: Mutex::default(),
            refreshes: AtomicUsize::new(0),
            bearers: Mutex::default(),
        });
        let router = Router::new()
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .route("/revoke", post(revoke))
            .route("/api/me", get(me))
            .with_state(shared.clone());
        let acceptor = TlsAcceptor::from(leaf.server_config(&[b"h2", b"http/1.1"]));
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

    pub fn issued(&self) -> Vec<String> {
        self.shared.tokens.lock().unwrap().issued.clone()
    }

    pub fn is_active(&self, token: &str) -> bool {
        let tokens = self.shared.tokens.lock().unwrap();
        tokens.access.contains(token) || tokens.refresh.contains(token)
    }

    pub fn requests(&self) -> Vec<TokenRequest> {
        self.shared.requests.lock().unwrap().clone()
    }

    pub fn refreshes(&self) -> usize {
        self.shared.refreshes.load(Ordering::SeqCst)
    }

    pub fn bearers(&self) -> Vec<String> {
        self.shared.bearers.lock().unwrap().clone()
    }
}

pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn random(label: &str) -> String {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).expect("random bytes");
    format!("{label}-{}", hex::encode(raw))
}

async fn authorize(
    State(shared): State<Arc<Shared>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let valid = params.get("response_type").map(String::as_str) == Some("code")
        && params.get("client_id").map(String::as_str) == Some(MOCK_CLIENT_ID)
        && params.get("code_challenge_method").map(String::as_str) == Some("S256");
    let (Some(redirect), Some(challenge), true) = (
        params.get("redirect_uri"),
        params.get("code_challenge"),
        valid,
    ) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let code = random("code");
    shared
        .tokens
        .lock()
        .unwrap()
        .codes
        .insert(code.clone(), challenge.clone());
    let state = params.get("state").cloned().unwrap_or_default();
    let location = format!(
        "{redirect}?{}",
        form_urlencoded::Serializer::new(String::new())
            .append_pair("code", &code)
            .append_pair("state", &state)
            .finish()
    );
    Redirect::to(&location).into_response()
}

fn record(
    shared: &Shared,
    uri: &Uri,
    headers: &HeaderMap,
    body: &Bytes,
) -> HashMap<String, String> {
    shared.requests.lock().unwrap().push(TokenRequest {
        path: uri.path().to_string(),
        query: uri.query().map(str::to_string),
        headers: headers.clone(),
        body: String::from_utf8_lossy(body).into_owned(),
    });
    form_urlencoded::parse(body)
        .chain(form_urlencoded::parse(
            uri.query().unwrap_or_default().as_bytes(),
        ))
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

fn client_authenticated(
    shared: &Shared,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> bool {
    let expected = format!("{MOCK_CLIENT_ID}:{}", shared.config.client_secret);
    match shared.config.client_auth {
        ClientAuthMethod::Post => {
            form.get("client_id").map(String::as_str) == Some(MOCK_CLIENT_ID)
                && form.get("client_secret") == Some(&shared.config.client_secret)
        }
        ClientAuthMethod::Basic => headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Basic "))
            .and_then(|encoded| STANDARD.decode(encoded).ok())
            .is_some_and(|decoded| decoded == expected.as_bytes()),
    }
}

fn error(status: StatusCode, code: &str) -> Response {
    (status, Json(serde_json::json!({ "error": code }))).into_response()
}

async fn token(
    State(shared): State<Arc<Shared>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let form = record(&shared, &uri, &headers, &body);
    if !client_authenticated(&shared, &headers, &form) {
        return error(StatusCode::UNAUTHORIZED, "invalid_client");
    }
    let grant = form.get("grant_type").map(String::as_str);
    let issue_refresh = match grant {
        Some("authorization_code") => {
            let challenge = form
                .get("code")
                .and_then(|code| shared.tokens.lock().unwrap().codes.remove(code));
            let verified = challenge.is_some_and(|challenge| {
                form.get("code_verifier")
                    .is_some_and(|verifier| pkce_challenge(verifier) == challenge)
            });
            if !verified {
                return error(StatusCode::BAD_REQUEST, "invalid_grant");
            }
            true
        }
        Some("refresh_token") => {
            shared.refreshes.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(shared.config.refresh_delay).await;
            let mut tokens = shared.tokens.lock().unwrap();
            let Some(presented) = form
                .get("refresh_token")
                .filter(|t| tokens.refresh.contains(*t))
            else {
                return error(StatusCode::BAD_REQUEST, "invalid_grant");
            };
            if shared.config.rotate_refresh {
                tokens.refresh.remove(presented);
            }
            shared.config.rotate_refresh
        }
        Some("client_credentials") => false,
        _ => return error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
    };
    let mut tokens = shared.tokens.lock().unwrap();
    let access = random("real-at");
    tokens.access.insert(access.clone());
    tokens.issued.push(access.clone());
    let refresh = issue_refresh.then(|| {
        let refresh = random("real-rt");
        tokens.refresh.insert(refresh.clone());
        tokens.issued.push(refresh.clone());
        refresh
    });
    drop(tokens);
    let id_token = (grant == Some("authorization_code")).then_some(MOCK_ID_TOKEN);
    let expires_in = shared.config.expires_in;
    match shared.config.format {
        TokenFormat::Json => {
            let mut body = serde_json::json!({
                "access_token": access,
                "token_type": "Bearer",
                "expires_in": expires_in,
                "scope": MOCK_SCOPE,
            });
            if let Some(refresh) = refresh {
                body["refresh_token"] = refresh.into();
            }
            if let Some(id_token) = id_token {
                body["id_token"] = id_token.into();
            }
            ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
        }
        TokenFormat::Form => {
            let mut form = form_urlencoded::Serializer::new(String::new());
            form.append_pair("access_token", &access)
                .append_pair("token_type", "Bearer")
                .append_pair("expires_in", &expires_in.to_string())
                .append_pair("scope", MOCK_SCOPE);
            if let Some(refresh) = &refresh {
                form.append_pair("refresh_token", refresh);
            }
            if let Some(id_token) = id_token {
                form.append_pair("id_token", id_token);
            }
            (
                [
                    (header::CONTENT_TYPE, "application/x-www-form-urlencoded"),
                    (header::CACHE_CONTROL, "no-store"),
                ],
                form.finish(),
            )
                .into_response()
        }
    }
}

async fn revoke(
    State(shared): State<Arc<Shared>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let form = record(&shared, &uri, &headers, &body);
    let Some(token) = form.get("token") else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let mut tokens = shared.tokens.lock().unwrap();
    tokens.access.remove(token);
    tokens.refresh.remove(token);
    StatusCode::OK.into_response()
}

async fn me(State(shared): State<Arc<Shared>>, headers: HeaderMap) -> Response {
    let Some(bearer) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    shared.bearers.lock().unwrap().push(bearer.to_string());
    if shared.tokens.lock().unwrap().access.contains(bearer) {
        Json(serde_json::json!({ "sub": "mock-user" })).into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}
