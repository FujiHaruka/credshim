use std::time::{Duration, Instant};

use credshim_secrets::{SecretStore, StoreError};

use super::SsoSession;
use super::api::{Api, ApiError, Transport};
use super::stored::StoredLogin;

const MIN_POLL_INTERVAL: Duration = Duration::from_secs(1);
const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prompt {
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub user_code: String,
    pub expires_in: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error("could not reach IAM Identity Center: {0}")]
    Unreachable(String),
    #[error("IAM Identity Center refused the login ({0})")]
    Refused(String),
    #[error("the device authorization was not approved before it expired")]
    TimedOut,
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
    show: impl FnOnce(&Prompt),
) -> Result<(), LoginError> {
    let api = Api { transport, session };
    let client = api.register_client().await?;
    let authorization = api.start_device_authorization(&client).await?;
    show(&Prompt {
        verification_uri: authorization.verification_uri.clone(),
        verification_uri_complete: authorization.verification_uri_complete.clone(),
        user_code: authorization.user_code.clone(),
        expires_in: authorization.expires_in,
    });
    let deadline = Instant::now() + authorization.expires_in;
    let mut interval = authorization.interval.max(MIN_POLL_INTERVAL);
    let token = loop {
        if Instant::now() + interval > deadline {
            return Err(LoginError::TimedOut);
        }
        tokio::time::sleep(interval).await;
        match api
            .create_token_from_device(&client, &authorization.device_code)
            .await
        {
            Ok(token) => break token,
            Err(err) => match err.code() {
                Some("authorization_pending") => {}
                Some("slow_down") => interval += SLOW_DOWN_STEP,
                Some("expired_token") => return Err(LoginError::TimedOut),
                _ => return Err(err.into()),
            },
        }
    };
    let stored = StoredLogin::new(client, token);
    store.set(&session.secret_name(), stored.to_secret(session))?;
    Ok(())
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
        Ok(stored) => Api { transport, session }
            .logout(&stored.token.access_token)
            .await
            .or_else(|err| match err.status() {
                Some(http::StatusCode::UNAUTHORIZED) => Ok(()),
                _ => Err(err.to_string()),
            }),
        Err(err) => Err(err.to_string()),
    };
    store.remove(&name)?;
    Ok(match revoked {
        Ok(()) => LogoutOutcome::Revoked,
        Err(reason) => LogoutOutcome::RemovedWithoutRevoking(reason),
    })
}
