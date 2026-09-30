use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use credshim_core::dummy::{self, ACCESS_TOKEN_PREFIX, REFRESH_TOKEN_PREFIX};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub const EXPIRY_GRACE: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenKind {
    Access,
    Refresh,
}

impl TokenKind {
    fn prefix(self) -> &'static str {
        match self {
            TokenKind::Access => ACCESS_TOKEN_PREFIX,
            TokenKind::Refresh => REFRESH_TOKEN_PREFIX,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Issued {
    pub real: SecretString,
    pub provider: String,
    pub kind: TokenKind,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    real: String,
    provider: String,
    kind: TokenKind,
    expires_at: Option<u64>,
    created_at: u64,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.real.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Contents {
    tokens: BTreeMap<String, Entry>,
}

#[derive(Serialize)]
struct ContentsRef<'a> {
    tokens: &'a BTreeMap<String, Entry>,
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path}: {reason}")]
    Corrupt { path: PathBuf, reason: String },
    #[error("the token vault key is not a valid age X25519 identity")]
    InvalidKey,
}

struct VaultFile {
    path: PathBuf,
    identity: age::x25519::Identity,
    written: Mutex<u64>,
}

pub struct Vault {
    tokens: Mutex<BTreeMap<String, Entry>>,
    file: Option<VaultFile>,
    generation: AtomicU64,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("tokens", &self.lock().len())
            .field("path", &self.file.as_ref().map(|file| &file.path))
            .finish()
    }
}

impl Vault {
    pub fn in_memory() -> Self {
        Self {
            tokens: Mutex::default(),
            file: None,
            generation: AtomicU64::new(0),
        }
    }

    pub fn generate_key() -> SecretString {
        SecretString::from(
            age::x25519::Identity::generate()
                .to_string()
                .expose_secret()
                .to_string(),
        )
    }

    pub fn open(path: PathBuf, key: &SecretString) -> Result<Self, VaultError> {
        let identity: age::x25519::Identity = key
            .expose_secret()
            .trim()
            .parse()
            .map_err(|_| VaultError::InvalidKey)?;
        let tokens = match fs::read(&path) {
            Ok(ciphertext) => {
                let plaintext = Zeroizing::new(
                    age::decrypt(&identity, &ciphertext).map_err(|err| corrupt(&path, err))?,
                );
                let contents: Contents = serde_json::from_slice(&plaintext)
                    .map_err(|_| corrupt(&path, "malformed contents"))?;
                contents.tokens
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(source) => return Err(VaultError::Io { path, source }),
        };
        Ok(Self {
            tokens: Mutex::new(tokens),
            file: Some(VaultFile {
                path,
                identity,
                written: Mutex::new(0),
            }),
            generation: AtomicU64::new(0),
        })
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn issued(&self) -> Vec<(String, SecretString)> {
        self.lock()
            .iter()
            .map(|(dummy, entry)| (dummy.clone(), SecretString::from(entry.real.as_str())))
            .collect()
    }

    pub fn issue(
        &self,
        provider: &str,
        kind: TokenKind,
        real: &SecretString,
        expires_at: Option<SystemTime>,
    ) -> String {
        let dummy = dummy::generate(kind.prefix());
        let mut tokens = self.lock();
        tokens.insert(
            dummy.clone(),
            Entry {
                real: real.expose_secret().to_string(),
                provider: provider.to_string(),
                kind,
                expires_at: expires_at.map(unix_seconds),
                created_at: unix_seconds(SystemTime::now()),
            },
        );
        self.persist(tokens);
        dummy
    }

    pub fn get(&self, dummy: &str) -> Option<Issued> {
        self.lock().get(dummy).map(|entry| Issued {
            real: SecretString::from(entry.real.as_str()),
            provider: entry.provider.clone(),
            kind: entry.kind,
        })
    }

    pub fn remove(&self, dummy: &str) -> bool {
        let mut tokens = self.lock();
        let removed = tokens.remove(dummy).is_some();
        if removed {
            self.persist(tokens);
        }
        removed
    }

    pub fn purge_expired(&self, now: SystemTime) -> usize {
        let cutoff = unix_seconds(now).saturating_sub(EXPIRY_GRACE.as_secs());
        let mut tokens = self.lock();
        let before = tokens.len();
        tokens.retain(|_, entry| entry.expires_at.is_none_or(|at| at > cutoff));
        let purged = before - tokens.len();
        if purged > 0 {
            self.persist(tokens);
        }
        purged
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, Entry>> {
        self.tokens
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn persist(&self, tokens: MutexGuard<'_, BTreeMap<String, Entry>>) {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        let Some(file) = &self.file else {
            return;
        };
        let snapshot = file.serialize(&tokens);
        drop(tokens);
        let mut written = file
            .written
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *written > generation {
            return;
        }
        match snapshot.and_then(|plaintext| file.write(&plaintext)) {
            Ok(()) => *written = generation,
            Err(err) => tracing::error!(error = %err, "could not save the OAuth token vault"),
        }
    }
}

impl VaultFile {
    fn serialize(
        &self,
        tokens: &BTreeMap<String, Entry>,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        serde_json::to_vec(&ContentsRef { tokens })
            .map(Zeroizing::new)
            .map_err(|_| corrupt(&self.path, "could not serialize"))
    }

    fn write(&self, plaintext: &[u8]) -> Result<(), VaultError> {
        let ciphertext = age::encrypt(&self.identity.to_public(), plaintext)
            .map_err(|err| corrupt(&self.path, err))?;
        let dir = match self.path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir,
            _ => Path::new("."),
        };
        if !dir.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|source| io(dir, source))?;
        }
        let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(|source| io(dir, source))?;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| io(tmp.path(), source))?;
        tmp.write_all(&ciphertext)
            .and_then(|()| tmp.as_file().sync_all())
            .map_err(|source| io(&self.path, source))?;
        tmp.persist(&self.path)
            .map_err(|err| io(&self.path, err.error))?;
        Ok(())
    }
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn io(path: &Path, source: std::io::Error) -> VaultError {
    VaultError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn corrupt(path: &Path, reason: impl ToString) -> VaultError {
    VaultError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    }
}
