use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use credshim_core::RuleSpec;
use credshim_oauth::ProviderSpec;
use credshim_secrets::BackendConfig;
use serde::Deserialize;

pub const DEFAULT_LISTEN: &str = "127.0.0.1:8787";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub listen: ListenConfig,
    #[serde(default)]
    pub ca: CaConfig,
    pub secrets: Option<BackendConfig>,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default, rename = "rule")]
    pub rules: Vec<RuleSpec>,
    #[serde(default, rename = "oauth")]
    pub oauth: Vec<ProviderSpec>,
    #[serde(default)]
    pub vault: VaultConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    pub path: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    pub max_token_body_bytes: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenConfig {
    pub addr: Option<SocketAddr>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaConfig {
    pub dir: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    pub path: Option<PathBuf>,
}

pub struct Loaded {
    pub config: Config,
    pub source: Option<PathBuf>,
}

pub fn load(explicit: Option<&Path>) -> anyhow::Result<Loaded> {
    let (path, required) = match explicit {
        Some(path) => (path.to_path_buf(), true),
        None => (config_dir()?.join("config.toml"), false),
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound && !required => {
            return Ok(Loaded {
                config: Config::default(),
                source: None,
            });
        }
        Err(err) => return Err(err).with_context(|| format!("could not read {}", path.display())),
    };
    let config =
        toml::from_str(&text).with_context(|| format!("invalid config {}", path.display()))?;
    Ok(Loaded {
        config,
        source: Some(path),
    })
}

impl Config {
    pub fn listen(&self) -> SocketAddr {
        self.listen.addr.unwrap_or_else(|| {
            DEFAULT_LISTEN
                .parse()
                .expect("valid default listen address")
        })
    }

    pub fn ca_dir(&self) -> anyhow::Result<PathBuf> {
        match &self.ca.dir {
            Some(dir) => Ok(dir.clone()),
            None => default_ca_dir(),
        }
    }

    pub fn vault_path(&self) -> anyhow::Result<PathBuf> {
        match &self.vault.path {
            Some(path) => Ok(path.clone()),
            None => Ok(config_dir()?.join("oauth-vault.age")),
        }
    }

    pub fn secrets(&self) -> anyhow::Result<BackendConfig> {
        match &self.secrets {
            Some(backend) => Ok(backend.clone()),
            None => default_backend(),
        }
    }
}

pub fn config_dir() -> anyhow::Result<PathBuf> {
    let config_home = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".config"),
    };
    Ok(config_home.join("credshim"))
}

pub fn default_ca_dir() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join("ca"))
}

#[cfg(target_os = "macos")]
fn default_backend() -> anyhow::Result<BackendConfig> {
    Ok(BackendConfig::Keychain { service: None })
}

#[cfg(not(target_os = "macos"))]
fn default_backend() -> anyhow::Result<BackendConfig> {
    Ok(BackendConfig::AgeFile {
        path: config_dir()?.join("secrets.age"),
        identity: None,
    })
}
