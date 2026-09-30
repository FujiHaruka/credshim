use std::collections::BTreeMap;
use std::time::SystemTime;

use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::{SecretInfo, SecretStore, StoreError, check_name, from_unix_seconds, unix_seconds};

const INDEX_ACCOUNT: &str = "index";
const SECRET_ACCOUNT_PREFIX: &str = "secret:";

pub trait Keychain: Send + Sync {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>, StoreError>;
    fn set(&self, account: &str, value: &str) -> Result<(), StoreError>;
    fn delete(&self, account: &str) -> Result<bool, StoreError>;
}

pub struct KeychainStore<K> {
    keychain: K,
}

impl<K: Keychain> KeychainStore<K> {
    pub fn new(keychain: K) -> Self {
        Self { keychain }
    }

    fn index(&self) -> Result<BTreeMap<String, u64>, StoreError> {
        match self.keychain.get(INDEX_ACCOUNT)? {
            Some(json) => serde_json::from_str(&json)
                .map_err(|err| StoreError::Keychain(format!("index entry is corrupt: {err}"))),
            None => Ok(BTreeMap::new()),
        }
    }

    fn save_index(&self, index: &BTreeMap<String, u64>) -> Result<(), StoreError> {
        let json =
            serde_json::to_string(index).map_err(|err| StoreError::Keychain(err.to_string()))?;
        self.keychain.set(INDEX_ACCOUNT, &json)
    }
}

impl<K: Keychain> SecretStore for KeychainStore<K> {
    fn get(&self, name: &str) -> Result<Option<SecretString>, StoreError> {
        check_name(name)?;
        Ok(self
            .keychain
            .get(&format!("{SECRET_ACCOUNT_PREFIX}{name}"))?
            .map(|value| SecretString::from(value.as_str())))
    }

    fn set(&self, name: &str, value: SecretString) -> Result<(), StoreError> {
        check_name(name)?;
        let mut index = self.index()?;
        self.keychain.set(
            &format!("{SECRET_ACCOUNT_PREFIX}{name}"),
            value.expose_secret(),
        )?;
        index.insert(name.to_string(), unix_seconds(SystemTime::now()));
        self.save_index(&index)
    }

    fn remove(&self, name: &str) -> Result<bool, StoreError> {
        check_name(name)?;
        let mut index = self.index()?;
        let removed = self
            .keychain
            .delete(&format!("{SECRET_ACCOUNT_PREFIX}{name}"))?;
        if index.remove(name).is_some() {
            self.save_index(&index)?;
        }
        Ok(removed)
    }

    fn list(&self) -> Result<Vec<SecretInfo>, StoreError> {
        Ok(self
            .index()?
            .into_iter()
            .map(|(name, updated_at)| SecretInfo {
                name,
                updated_at: from_unix_seconds(updated_at),
            })
            .collect())
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn os_keychain(service: &str) -> Result<OsKeychain, StoreError> {
    Ok(OsKeychain {
        service: service.to_string(),
    })
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn os_keychain(_service: &str) -> Result<OsKeychain, StoreError> {
    Err(StoreError::KeychainUnsupported)
}

pub(crate) struct OsKeychain {
    #[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
    service: String,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
impl Keychain for OsKeychain {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>, StoreError> {
        let entry = keyring::Entry::new(&self.service, account).map_err(keychain_error)?;
        match entry.get_password() {
            Ok(value) => Ok(Some(Zeroizing::new(value))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(keychain_error(err)),
        }
    }

    fn set(&self, account: &str, value: &str) -> Result<(), StoreError> {
        keyring::Entry::new(&self.service, account)
            .and_then(|entry| entry.set_password(value))
            .map_err(keychain_error)
    }

    fn delete(&self, account: &str) -> Result<bool, StoreError> {
        let entry = keyring::Entry::new(&self.service, account).map_err(keychain_error)?;
        match entry.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(err) => Err(keychain_error(err)),
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
impl Keychain for OsKeychain {
    fn get(&self, _account: &str) -> Result<Option<Zeroizing<String>>, StoreError> {
        Err(StoreError::KeychainUnsupported)
    }

    fn set(&self, _account: &str, _value: &str) -> Result<(), StoreError> {
        Err(StoreError::KeychainUnsupported)
    }

    fn delete(&self, _account: &str) -> Result<bool, StoreError> {
        Err(StoreError::KeychainUnsupported)
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn keychain_error(err: keyring::Error) -> StoreError {
    let reason = match err {
        keyring::Error::NoStorageAccess(_) => "access to the keychain was denied".to_string(),
        keyring::Error::PlatformFailure(_) => "the platform keychain failed".to_string(),
        keyring::Error::BadEncoding(_) => "an entry is not valid UTF-8".to_string(),
        other => other.to_string(),
    };
    StoreError::Keychain(reason)
}
