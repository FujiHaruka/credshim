use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use credshim_core::ScrubSource;
use credshim_secrets::{SecretStore, StoreError};
use http::StatusCode;
use secrecy::SecretString;

use super::SsoSession;
use super::api::{Api, RoleCredentials, Token, Transport};
use super::stored::StoredLogin;
use crate::resign::{AwsCredentials, SCRUBBED_SECRET};
use crate::rule::SsoRole;

const SCRUBBED_TOKEN: &str = "credshim-scrubbed-aws-sso-token";
const KEPT_GENERATIONS: usize = 2;
const REFRESH_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct SsoOptions {
    pub refresh_before: Duration,
    pub store_recheck: Duration,
}

impl Default for SsoOptions {
    fn default() -> Self {
        Self {
            refresh_before: Duration::from_secs(10 * 60),
            store_recheck: Duration::from_secs(1),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("AWS SSO session {0:?} needs a login; run `credshim aws sso login {0}`")]
    LoginRequired(String),
    #[error(
        "IAM Identity Center refused role credentials for AWS SSO session {session:?} ({status})"
    )]
    Refused { session: String, status: StatusCode },
    #[error("could not reach IAM Identity Center for AWS SSO session {session:?}: {reason}")]
    Unavailable { session: String, reason: String },
    #[error("IAM Identity Center returned role credentials credshim cannot use")]
    Unusable,
    #[error("no credentials are loaded for aws rule {0:?}")]
    NotLoaded(String),
}

struct SessionState {
    session: SsoSession,
    login: tokio::sync::Mutex<LoginState>,
}

#[derive(Default)]
struct LoginState {
    current: Option<StoredLogin>,
    serial: u64,
    loaded_at: Option<Instant>,
    refresh_after: Option<Instant>,
    warned_read_only: bool,
}

impl LoginState {
    fn replace(&mut self, login: StoredLogin) {
        self.current = Some(login);
        self.serial += 1;
        self.refresh_after = None;
    }

    fn usable(&self, now: SystemTime) -> Option<(SecretString, u64)> {
        self.current
            .as_ref()
            .filter(|current| current.token.expires_at > now)
            .map(|current| (current.token.access_token.clone(), self.serial))
    }
}

struct RoleSlot {
    role: SsoRole,
    dummy: String,
    cached: tokio::sync::Mutex<Option<CachedRole>>,
}

struct CachedRole {
    credentials: Arc<AwsCredentials>,
    expiration: SystemTime,
}

pub struct SsoProvider {
    sessions: HashMap<String, SessionState>,
    roles: HashMap<String, RoleSlot>,
    store: Arc<dyn SecretStore>,
    transport: Arc<dyn Transport>,
    options: SsoOptions,
    generation: AtomicU64,
    scrub: Mutex<BTreeMap<String, VecDeque<Vec<(SecretString, String)>>>>,
}

impl std::fmt::Debug for SsoProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsoProvider")
            .field("sessions", &self.sessions.keys().collect::<Vec<_>>())
            .field("roles", &self.roles.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl SsoProvider {
    pub fn new(
        sessions: Vec<SsoSession>,
        roles: impl IntoIterator<Item = (String, SsoRole, String)>,
        store: Arc<dyn SecretStore>,
        transport: Arc<dyn Transport>,
        options: SsoOptions,
    ) -> Self {
        let provider = Self {
            sessions: sessions
                .into_iter()
                .map(|session| {
                    (
                        session.name().to_string(),
                        SessionState {
                            session,
                            login: tokio::sync::Mutex::default(),
                        },
                    )
                })
                .collect(),
            roles: roles
                .into_iter()
                .map(|(rule, role, dummy)| {
                    (
                        rule,
                        RoleSlot {
                            role,
                            dummy,
                            cached: tokio::sync::Mutex::default(),
                        },
                    )
                })
                .collect(),
            store,
            transport,
            options,
            generation: AtomicU64::new(0),
            scrub: Mutex::default(),
        };
        for state in provider.sessions.values() {
            let mut login = state
                .login
                .try_lock()
                .expect("nothing else holds a session before the provider is shared");
            provider.load(
                state,
                &mut login,
                provider.store.get(&state.session.secret_name()),
            );
            if login.current.is_none() {
                tracing::info!(
                    session = state.session.name(),
                    "AWS SSO session is not logged in; run `credshim aws sso login {}`",
                    state.session.name()
                );
            }
        }
        provider
    }

    pub async fn credentials(&self, rule: &str) -> Result<Arc<AwsCredentials>, CredentialError> {
        let slot = self
            .roles
            .get(rule)
            .ok_or_else(|| CredentialError::NotLoaded(rule.to_string()))?;
        let session = slot.role.session.as_str();
        let (token, serial) = self.access_token(session).await?;
        let mut cached = slot.cached.lock().await;
        if let Some(cached) = cached.as_ref()
            && cached.expiration > SystemTime::now() + self.options.refresh_before
        {
            return Ok(cached.credentials.clone());
        }
        let fetched = match self.fetch(session, &token, &slot.role).await {
            Err(CredentialError::LoginRequired(_)) => {
                self.invalidate(session, serial).await;
                let (token, retried) = self.access_token(session).await?;
                if retried == serial {
                    return Err(CredentialError::LoginRequired(session.to_string()));
                }
                self.fetch(session, &token, &slot.role).await
            }
            other => other,
        };
        let fresh = match fetched {
            Ok(fresh) => fresh,
            Err(err @ CredentialError::Unavailable { .. }) => {
                return match cached.as_ref() {
                    Some(cached) if cached.expiration > SystemTime::now() => {
                        tracing::warn!(%rule, error = %err, "keeping AWS role credentials that are about to expire");
                        Ok(cached.credentials.clone())
                    }
                    _ => Err(err),
                };
            }
            Err(err) => return Err(err),
        };
        let expiration = fresh.expiration;
        self.record(
            format!("role:{rule}"),
            vec![
                (fresh.access_key_id.clone(), slot.dummy.clone()),
                (fresh.secret_access_key.clone(), SCRUBBED_SECRET.to_string()),
                (fresh.session_token.clone(), SCRUBBED_SECRET.to_string()),
            ],
        );
        let credentials = Arc::new(
            AwsCredentials::new(
                fresh.access_key_id,
                fresh.secret_access_key,
                Some(fresh.session_token),
            )
            .map_err(|_| CredentialError::Unusable)?,
        );
        *cached = Some(CachedRole {
            credentials: credentials.clone(),
            expiration,
        });
        tracing::info!(%rule, "fetched AWS role credentials from IAM Identity Center");
        Ok(credentials)
    }

    async fn fetch(
        &self,
        session: &str,
        token: &SecretString,
        role: &SsoRole,
    ) -> Result<RoleCredentials, CredentialError> {
        let state = self.session(session)?;
        let api = Api {
            transport: self.transport.as_ref(),
            session: &state.session,
        };
        api.get_role_credentials(token, role)
            .await
            .map_err(|err| match err.status() {
                Some(StatusCode::UNAUTHORIZED) => {
                    CredentialError::LoginRequired(session.to_string())
                }
                Some(status)
                    if status.is_client_error() && status != StatusCode::TOO_MANY_REQUESTS =>
                {
                    CredentialError::Refused {
                        session: session.to_string(),
                        status,
                    }
                }
                _ => CredentialError::Unavailable {
                    session: session.to_string(),
                    reason: err.to_string(),
                },
            })
    }

    fn session(&self, name: &str) -> Result<&SessionState, CredentialError> {
        self.sessions
            .get(name)
            .ok_or_else(|| CredentialError::LoginRequired(name.to_string()))
    }

    async fn access_token(&self, name: &str) -> Result<(SecretString, u64), CredentialError> {
        let state = self.session(name)?;
        let mut login = state.login.lock().await;
        if login.current.is_none() {
            self.reload(state, &mut login).await;
        }
        for _ in 0..3 {
            let Some(current) = login.current.as_ref() else {
                break;
            };
            let now = SystemTime::now();
            if current.token.expires_at > now + self.options.refresh_before {
                return Ok((current.token.access_token.clone(), login.serial));
            }
            let backing_off = login
                .refresh_after
                .is_some_and(|after| Instant::now() < after);
            if !(backing_off && current.token.expires_at > now) {
                match self.refresh(state, current).await {
                    Some(refreshed) => {
                        self.persist(state, &mut login, refreshed).await;
                        continue;
                    }
                    None => login.refresh_after = Some(Instant::now() + REFRESH_BACKOFF),
                }
            }
            if let Some(usable) = login.usable(now) {
                return Ok(usable);
            }
            if !self.reload(state, &mut login).await {
                break;
            }
        }
        login
            .usable(SystemTime::now())
            .ok_or_else(|| CredentialError::LoginRequired(name.to_string()))
    }

    async fn invalidate(&self, name: &str, serial: u64) {
        let Ok(state) = self.session(name) else {
            return;
        };
        let mut login = state.login.lock().await;
        if login.serial == serial
            && let Some(current) = login.current.as_mut()
        {
            current.token.expires_at = SystemTime::UNIX_EPOCH;
        }
    }

    async fn refresh(&self, state: &SessionState, current: &StoredLogin) -> Option<StoredLogin> {
        let refresh_token = current.token.refresh_token.as_ref()?;
        if current.client.expires_at <= SystemTime::now() {
            return None;
        }
        let api = Api {
            transport: self.transport.as_ref(),
            session: &state.session,
        };
        match api.refresh(&current.client, refresh_token).await {
            Ok(token) => Some(StoredLogin {
                login_id: current.login_id.clone(),
                client: current.client.clone(),
                token: Token {
                    refresh_token: token
                        .refresh_token
                        .or_else(|| current.token.refresh_token.clone()),
                    ..token
                },
            }),
            Err(err) => {
                tracing::warn!(session = state.session.name(), error = %err, "could not refresh the AWS SSO token");
                None
            }
        }
    }

    async fn persist(&self, state: &SessionState, login: &mut LoginState, refreshed: StoredLogin) {
        self.record_login(&state.session, &refreshed);
        let name = state.session.secret_name();
        let stored = self.blocking_get(&name).await;
        if let Ok(Some(secret)) = &stored
            && let Ok(other) = StoredLogin::from_secret(secret, &state.session)
            && other.login_id != refreshed.login_id
        {
            self.record_login(&state.session, &other);
            login.replace(other);
            return;
        }
        let secret = refreshed.to_secret(&state.session);
        let store = self.store.clone();
        let written = tokio::task::spawn_blocking(move || store.set(&name, secret))
            .await
            .unwrap_or_else(|_| Err(StoreError::ReadOnly("panicked")));
        match written {
            Ok(()) => {}
            Err(StoreError::ReadOnly(_)) if login.warned_read_only => {}
            Err(StoreError::ReadOnly(backend)) => {
                login.warned_read_only = true;
                tracing::warn!(
                    session = state.session.name(),
                    backend,
                    "the secret store is read-only, so the refreshed AWS SSO token lives only in memory"
                );
            }
            Err(err) => {
                tracing::warn!(session = state.session.name(), error = %err, "could not save the refreshed AWS SSO token")
            }
        }
        login.replace(refreshed);
    }

    async fn reload(&self, state: &SessionState, login: &mut LoginState) -> bool {
        if login
            .loaded_at
            .is_some_and(|at| at.elapsed() < self.options.store_recheck)
        {
            return false;
        }
        let before = login.serial;
        let got = self.blocking_get(&state.session.secret_name()).await;
        self.load(state, login, got);
        login.current.is_some() && login.serial != before
    }

    fn load(
        &self,
        state: &SessionState,
        login: &mut LoginState,
        got: Result<Option<SecretString>, StoreError>,
    ) {
        login.loaded_at = Some(Instant::now());
        let stored = match got {
            Ok(Some(secret)) => StoredLogin::from_secret(&secret, &state.session)
                .map_err(|err| {
                    tracing::warn!(session = state.session.name(), error = %err, "ignoring the stored AWS SSO login");
                })
                .ok(),
            Ok(None) => None,
            Err(err) => {
                tracing::warn!(session = state.session.name(), error = %err, "could not read the stored AWS SSO login");
                return;
            }
        };
        match stored {
            Some(stored)
                if login
                    .current
                    .as_ref()
                    .is_none_or(|current| current.login_id != stored.login_id) =>
            {
                self.record_login(&state.session, &stored);
                login.replace(stored);
            }
            Some(_) => {}
            None => login.current = None,
        }
    }

    async fn blocking_get(&self, name: &str) -> Result<Option<SecretString>, StoreError> {
        let store = self.store.clone();
        let name = name.to_string();
        tokio::task::spawn_blocking(move || store.get(&name))
            .await
            .unwrap_or(Ok(None))
    }

    fn record_login(&self, session: &SsoSession, login: &StoredLogin) {
        self.record(
            format!("session:{}", session.name()),
            login
                .secrets()
                .into_iter()
                .map(|secret| (secret, SCRUBBED_TOKEN.to_string()))
                .collect(),
        );
    }

    fn record(&self, key: String, pairs: Vec<(SecretString, String)>) {
        let mut scrub = self
            .scrub
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let kept = scrub.entry(key).or_default();
        kept.push_back(pairs);
        while kept.len() > KEPT_GENERATIONS {
            kept.pop_front();
        }
        self.generation.fetch_add(1, Ordering::AcqRel);
    }
}

impl ScrubSource for SsoProvider {
    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn pairs(&self) -> Vec<(SecretString, String)> {
        self.scrub
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .flatten()
            .flatten()
            .cloned()
            .collect()
    }
}
