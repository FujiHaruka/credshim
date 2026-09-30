use std::collections::BTreeMap;
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
    #[serde(default)]
    pub scrub: ScrubConfig,
    #[serde(default)]
    pub status: StatusConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusConfig {
    pub socket: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScrubConfig {
    pub enabled: Option<bool>,
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
    pub base_url_addr: Option<SocketAddr>,
    #[serde(default)]
    pub allow_non_loopback: bool,
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
    let config: Config =
        toml::from_str(&text).with_context(|| format!("invalid config {}", path.display()))?;
    config
        .check_env_names()
        .with_context(|| format!("invalid config {}", path.display()))?;
    Ok(Loaded {
        config,
        source: Some(path),
    })
}

impl Config {
    fn check_env_names(&self) -> anyhow::Result<()> {
        let mut owners = BTreeMap::new();
        for rule in &self.rules {
            if let Some(name) = &rule.env {
                anyhow::ensure!(
                    is_env_name(name),
                    "rule {:?}: env {name:?} must be an environment variable name (A-Z, 0-9, '_', not starting with a digit)",
                    rule.name
                );
                anyhow::ensure!(
                    ends_like_a_credential(name),
                    "rule {:?}: env {name:?} must end in one of {} so it cannot override proxy, CA or shell variables",
                    rule.name,
                    CREDENTIAL_SUFFIXES.join(", ")
                );
                if let Some(first) = owners.insert(name.as_str(), rule.name.as_str()) {
                    anyhow::bail!(
                        "rules {first:?} and {:?} both set env {name:?}; each variable can hold only one dummy",
                        rule.name
                    );
                }
            }
        }
        Ok(())
    }

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

const CREDENTIAL_SUFFIXES: [&str; 4] = ["_KEY", "_TOKEN", "_SECRET", "_PASSWORD"];

fn ends_like_a_credential(name: &str) -> bool {
    CREDENTIAL_SUFFIXES
        .iter()
        .any(|suffix| name.len() > suffix.len() && name.ends_with(suffix))
}

fn is_env_name(name: &str) -> bool {
    name.bytes().next().is_some_and(|b| !b.is_ascii_digit())
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}
