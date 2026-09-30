use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{SecretInfo, SecretStore, StoreError, check_name, from_unix_seconds, unix_seconds};

pub struct AgeFileStore {
    path: PathBuf,
    identity: PathBuf,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Vault {
    secrets: BTreeMap<String, Entry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    value: String,
    updated_at: u64,
}

impl Drop for Vault {
    fn drop(&mut self) {
        for entry in self.secrets.values_mut() {
            entry.value.zeroize();
        }
    }
}

impl AgeFileStore {
    pub fn new(path: PathBuf, identity: Option<PathBuf>) -> Self {
        let identity = identity.unwrap_or_else(|| path.with_extension("key"));
        Self { path, identity }
    }

    pub fn identity_path(&self) -> &Path {
        &self.identity
    }

    fn load(&self) -> Result<Vault, StoreError> {
        let ciphertext = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vault::default()),
            Err(source) => return Err(io(&self.path, source)),
        };
        let identity = self.read_identity()?;
        let plaintext = Zeroizing::new(
            age::decrypt(&identity, &ciphertext).map_err(|err| corrupt(&self.path, err))?,
        );
        serde_json::from_slice(&plaintext).map_err(|err| {
            corrupt(
                &self.path,
                format!(
                    "malformed contents at line {} column {}",
                    err.line(),
                    err.column()
                ),
            )
        })
    }

    fn save(&self, vault: &Vault, identity: &age::x25519::Identity) -> Result<(), StoreError> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(vault).map_err(|_| corrupt(&self.path, "could not serialize"))?,
        );
        let ciphertext = age::encrypt(&identity.to_public(), &plaintext)
            .map_err(|err| corrupt(&self.path, err))?;
        let dir = parent(&self.path);
        ensure_private_dir(dir)?;
        let mut file = tempfile::NamedTempFile::new_in(dir).map_err(|source| io(dir, source))?;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| io(file.path(), source))?;
        file.write_all(&ciphertext)
            .and_then(|()| file.as_file().sync_all())
            .map_err(|source| io(&self.path, source))?;
        file.persist(&self.path)
            .map_err(|err| io(&self.path, err.error))?;
        Ok(())
    }

    fn lock(&self) -> Result<fs::File, StoreError> {
        let path = self.path.with_extension("lock");
        ensure_private_dir(parent(&path))?;
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(|source| io(&path, source))?;
        file.lock().map_err(|source| io(&path, source))?;
        Ok(file)
    }

    fn read_identity(&self) -> Result<age::x25519::Identity, StoreError> {
        let text = Zeroizing::new(
            fs::read_to_string(&self.identity).map_err(|source| io(&self.identity, source))?,
        );
        text.lines()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with('#'))
            .and_then(|line| line.parse().ok())
            .ok_or_else(|| corrupt(&self.identity, "no age X25519 identity found"))
    }

    fn identity_or_create(&self) -> Result<age::x25519::Identity, StoreError> {
        if self.identity.exists() {
            return self.read_identity();
        }
        if self.path.exists() {
            return Err(corrupt(
                &self.identity,
                "identity file is missing but the secret file exists",
            ));
        }
        let identity = age::x25519::Identity::generate();
        let dir = parent(&self.identity);
        ensure_private_dir(dir)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.identity)
            .map_err(|source| io(&self.identity, source))?;
        let encoded = identity.to_string();
        writeln!(file, "{}", encoded.expose_secret())
            .and_then(|()| file.sync_all())
            .map_err(|source| io(&self.identity, source))?;
        Ok(identity)
    }
}

impl SecretStore for AgeFileStore {
    fn get(&self, name: &str) -> Result<Option<SecretString>, StoreError> {
        check_name(name)?;
        let vault = self.load()?;
        Ok(vault
            .secrets
            .get(name)
            .map(|entry| SecretString::from(entry.value.as_str())))
    }

    fn set(&self, name: &str, value: SecretString) -> Result<(), StoreError> {
        check_name(name)?;
        let _lock = self.lock()?;
        let identity = self.identity_or_create()?;
        let mut vault = self.load()?;
        vault.secrets.insert(
            name.to_string(),
            Entry {
                value: value.expose_secret().to_string(),
                updated_at: unix_seconds(SystemTime::now()),
            },
        );
        self.save(&vault, &identity)
    }

    fn remove(&self, name: &str) -> Result<bool, StoreError> {
        check_name(name)?;
        let _lock = self.lock()?;
        let mut vault = self.load()?;
        if vault.secrets.remove(name).is_none() {
            return Ok(false);
        }
        self.save(&vault, &self.read_identity()?)?;
        Ok(true)
    }

    fn list(&self) -> Result<Vec<SecretInfo>, StoreError> {
        Ok(self
            .load()?
            .secrets
            .iter()
            .map(|(name, entry)| SecretInfo {
                name: name.clone(),
                updated_at: from_unix_seconds(entry.updated_at),
            })
            .collect())
    }
}

fn parent(path: &Path) -> &Path {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

fn ensure_private_dir(dir: &Path) -> Result<(), StoreError> {
    if dir.exists() {
        return Ok(());
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|source| io(dir, source))
}

fn io(path: &Path, source: std::io::Error) -> StoreError {
    StoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn corrupt(path: &Path, reason: impl ToString) -> StoreError {
    StoreError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    }
}
