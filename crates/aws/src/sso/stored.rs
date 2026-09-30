use std::time::{Duration, SystemTime};

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::SsoSession;
use super::api::{Client, Token};

const VERSION: u32 = 1;

pub(crate) struct StoredLogin {
    pub login_id: String,
    pub client: Client,
    pub token: Token,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StoredError {
    #[error("the stored AWS SSO login is not in a format this credshim understands")]
    Malformed,
    #[error("the stored AWS SSO login was made for another start_url or region")]
    OtherSession,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Blob {
    version: u32,
    login_id: String,
    start_url: String,
    region: String,
    client_id: String,
    client_secret: String,
    client_expires_at: u64,
    access_token: String,
    expires_at: u64,
    refresh_token: Option<String>,
}

impl Drop for Blob {
    fn drop(&mut self) {
        self.client_secret.zeroize();
        self.access_token.zeroize();
        if let Some(token) = &mut self.refresh_token {
            token.zeroize();
        }
    }
}

impl StoredLogin {
    pub fn new(client: Client, token: Token) -> Self {
        Self {
            login_id: credshim_core::dummy::generate("login-"),
            client,
            token,
        }
    }

    pub fn to_secret(&self, session: &SsoSession) -> SecretString {
        let blob = Blob {
            version: VERSION,
            login_id: self.login_id.clone(),
            start_url: session.start_url().to_string(),
            region: session.region().to_string(),
            client_id: self.client.id.clone(),
            client_secret: self.client.secret.expose_secret().to_string(),
            client_expires_at: unix_seconds(self.client.expires_at),
            access_token: self.token.access_token.expose_secret().to_string(),
            expires_at: unix_seconds(self.token.expires_at),
            refresh_token: self
                .token
                .refresh_token
                .as_ref()
                .map(|token| token.expose_secret().to_string()),
        };
        let json =
            Zeroizing::new(serde_json::to_string(&blob).expect("a stored login always serializes"));
        SecretString::from(json.as_str())
    }

    pub fn from_secret(secret: &SecretString, session: &SsoSession) -> Result<Self, StoredError> {
        let blob: Blob =
            serde_json::from_str(secret.expose_secret()).map_err(|_| StoredError::Malformed)?;
        if blob.version != VERSION {
            return Err(StoredError::Malformed);
        }
        if blob.start_url != session.start_url() || blob.region != session.region() {
            return Err(StoredError::OtherSession);
        }
        Ok(Self {
            login_id: blob.login_id.clone(),
            client: Client {
                id: blob.client_id.clone(),
                secret: SecretString::from(blob.client_secret.as_str()),
                expires_at: from_unix_seconds(blob.client_expires_at),
            },
            token: Token {
                access_token: SecretString::from(blob.access_token.as_str()),
                expires_at: from_unix_seconds(blob.expires_at),
                refresh_token: blob.refresh_token.as_deref().map(SecretString::from),
            },
        })
    }

    pub fn secrets(&self) -> Vec<SecretString> {
        let mut secrets = vec![self.client.secret.clone(), self.token.access_token.clone()];
        secrets.extend(self.token.refresh_token.clone());
        secrets
    }
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn from_unix_seconds(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}
