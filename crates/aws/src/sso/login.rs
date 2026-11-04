use std::time::{Duration, Instant, SystemTime};

use credshim_secrets::{SecretStore, StoreError};

use super::SsoSession;
use super::api::{Api, ApiError, Client, Pkce, Token, Transport};
use super::callback::{Callback, Outcome};
use super::stored::StoredLogin;

const MIN_POLL_INTERVAL: Duration = Duration::from_secs(1);
const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);
const BROWSER_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Browser { timeout: Duration },
    DeviceCode,
}

impl Flow {
    pub fn browser() -> Self {
        Flow::Browser {
            timeout: BROWSER_TIMEOUT,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prompt {
    pub url: String,
    pub user_code: Option<String>,
    pub expires_in: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error("could not reach IAM Identity Center: {0}")]
    Unreachable(String),
    #[error("IAM Identity Center refused the login ({0})")]
    Refused(String),
    #[error("the login was not approved before it expired")]
    TimedOut,
    #[error("the login was not allowed in the browser ({0})")]
    Denied(String),
    #[error("could not listen on 127.0.0.1 for the browser to come back: {0}")]
    Callback(String),
    #[error("could not save the SSO login: {0}")]
    Store(#[from] StoreError),
}

impl From<ApiError> for LoginError {
    fn from(err: ApiError) -> Self {
        match err {
            ApiError::Transport(err) => LoginError::Unreachable(err.to_string()),
            other => LoginError::Refused(other.to_string()),
        }
    }
}

pub async fn login(
    session: &SsoSession,
    transport: &dyn Transport,
    store: &dyn SecretStore,
    flow: Flow,
    show: impl FnOnce(&Prompt),
) -> Result<(), LoginError> {
    let api = Api { transport, session };
    let (client, token) = match flow {
        Flow::Browser { timeout } => browser(&api, timeout, show).await?,
        Flow::DeviceCode => device(&api, show).await?,
    };
    let stored = StoredLogin::new(client, token);
    store.set(&session.secret_name(), stored.to_secret(session))?;
    Ok(())
}

async fn browser(
    api: &Api<'_>,
    timeout: Duration,
    show: impl FnOnce(&Prompt),
) -> Result<(Client, Token), LoginError> {
    let callback = Callback::bind()
        .await
        .map_err(|err| LoginError::Callback(err.to_string()))?;
    let redirect_uri = callback.redirect_uri();
    let client = api.register_browser_client().await?;
    let pkce = Pkce::generate();
    show(&Prompt {
        url: api.authorization_url(&client, &pkce, &redirect_uri),
        user_code: None,
        expires_in: timeout,
    });
    let code = match tokio::time::timeout(timeout, callback.wait(&pkce.state)).await {
        Err(_) => return Err(LoginError::TimedOut),
        Ok(Outcome::Denied(reason)) => return Err(LoginError::Denied(reason)),
        Ok(Outcome::Code(code)) => code,
    };
    let token = api
        .create_token_from_code(&client, &code, &pkce, &redirect_uri)
        .await?;
    Ok((client, token))
}

async fn device(api: &Api<'_>, show: impl FnOnce(&Prompt)) -> Result<(Client, Token), LoginError> {
    let client = api.register_device_client().await?;
    let authorization = api.start_device_authorization(&client).await?;
    show(&Prompt {
        url: authorization
            .verification_uri_complete
            .clone()
            .unwrap_or_else(|| authorization.verification_uri.clone()),
        user_code: Some(authorization.user_code.clone()),
        expires_in: authorization.expires_in,
    });
    let deadline = Instant::now() + authorization.expires_in;
    let mut interval = authorization.interval.max(MIN_POLL_INTERVAL);
    loop {
        if Instant::now() + interval > deadline {
            return Err(LoginError::TimedOut);
        }
        tokio::time::sleep(interval).await;
        match api
            .create_token_from_device(&client, &authorization.device_code)
            .await
        {
            Ok(token) => return Ok((client, token)),
            Err(err) => match err.code() {
                Some("authorization_pending") => {}
                Some("slow_down") => interval += SLOW_DOWN_STEP,
                Some("expired_token") => return Err(LoginError::TimedOut),
                _ => return Err(err.into()),
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LogoutOutcome {
    NotLoggedIn,
    Revoked,
    RemovedWithoutRevoking(String),
}

#[derive(Debug, thiserror::Error)]
pub enum LogoutError {
    #[error("could not remove the SSO login: {0}")]
    Store(#[from] StoreError),
}

pub async fn logout(
    session: &SsoSession,
    transport: &dyn Transport,
    store: &dyn SecretStore,
) -> Result<LogoutOutcome, LogoutError> {
    let name = session.secret_name();
    let Some(secret) = store.get(&name)? else {
        return Ok(LogoutOutcome::NotLoggedIn);
    };
    let revoked = match StoredLogin::from_secret(&secret, session) {
        Ok(stored) => {
            let api = Api { transport, session };
            let access_token = match &stored.token.refresh_token {
                Some(refresh_token)
                    if stored.token.expires_at <= SystemTime::now()
                        && stored.client.expires_at > SystemTime::now() =>
                {
                    api.refresh(&stored.client, refresh_token)
                        .await
                        .map_or(stored.token.access_token.clone(), |token| {
                            token.access_token
                        })
                }
                _ => stored.token.access_token.clone(),
            };
            api.logout(&access_token)
                .await
                .map_err(|err| err.to_string())
        }
        Err(err) => Err(err.to_string()),
    };
    store.remove(&name)?;
    Ok(match revoked {
        Ok(()) => LogoutOutcome::Revoked,
        Err(reason) => LogoutOutcome::RemovedWithoutRevoking(reason),
    })
}
