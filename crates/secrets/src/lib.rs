mod age_file;
mod command;
mod keychain;

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use secrecy::SecretString;
use serde::Deserialize;

pub use age_file::AgeFileStore;
pub use command::CommandStore;
pub use keychain::{Keychain, KeychainStore};

pub const DEFAULT_KEYCHAIN_SERVICE: &str = "credshim";
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretInfo {
    pub name: String,
    pub updated_at: SystemTime,
}

pub trait SecretStore: Send + Sync {
    fn get(&self, name: &str) -> Result<Option<SecretString>, StoreError>;
    fn set(&self, name: &str, value: SecretString) -> Result<(), StoreError>;
    fn list(&self) -> Result<Vec<SecretInfo>, StoreError>;
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("secret name {0:?} must be non-empty and use only letters, digits, '.', '_' or '-'")]
    InvalidName(String),
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path}: {reason}")]
    Corrupt { path: PathBuf, reason: String },
    #[error("keychain: {0}")]
    Keychain(String),
    #[error("the keychain backend is not available on this platform")]
    KeychainUnsupported,
    #[error("the {0} backend is read-only; manage secrets in the external tool")]
    ReadOnly(&'static str),
    #[error("the {0} backend cannot list secrets")]
    ListUnsupported(&'static str),
    #[error("secret command for {name:?} failed: {reason}")]
    Command { name: String, reason: String },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "backend", rename_all = "kebab-case", deny_unknown_fields)]
pub enum BackendConfig {
    Keychain {
        service: Option<String>,
    },
    AgeFile {
        path: PathBuf,
        identity: Option<PathBuf>,
    },
    Command {
        command: Vec<String>,
        timeout_secs: Option<u64>,
    },
}

impl BackendConfig {
    pub fn open(&self) -> Result<Box<dyn SecretStore>, StoreError> {
        Ok(match self {
            BackendConfig::Keychain { service } => Box::new(KeychainStore::new(
                keychain::os_keychain(service.as_deref().unwrap_or(DEFAULT_KEYCHAIN_SERVICE))?,
            )),
            BackendConfig::AgeFile { path, identity } => {
                Box::new(AgeFileStore::new(path.clone(), identity.clone()))
            }
            BackendConfig::Command {
                command,
                timeout_secs,
            } => Box::new(CommandStore::new(
                command.clone(),
                timeout_secs.map_or(DEFAULT_COMMAND_TIMEOUT, Duration::from_secs),
            )?),
        })
    }
}

pub fn check_name(name: &str) -> Result<(), StoreError> {
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(StoreError::InvalidName(name.to_string()))
    }
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn from_unix_seconds(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}
