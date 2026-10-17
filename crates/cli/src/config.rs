use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::Context;
use credshim_aws::{AwsKeySpec, AwsRule, AwsSsoRoleSpec, SsoSession, SsoSessionSpec};
use credshim_core::{BaseUrls, Rule, RuleSet, RuleSpec};
use credshim_oauth::{Provider, ProviderSpec};
use credshim_secrets::BackendConfig;
use credshim_ssh::{SshKeySpec, SshRule};
use secrecy::SecretString;
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
    #[serde(default)]
    pub ssh: SshConfig,
    #[serde(default, rename = "ssh_key")]
    pub ssh_keys: Vec<SshKeySpec>,
    #[serde(default)]
    pub aws: AwsConfig,
    #[serde(default, rename = "aws_key")]
    pub aws_keys: Vec<AwsKeySpec>,
    #[serde(default, rename = "aws_sso_session")]
    pub aws_sso_sessions: Vec<SsoSessionSpec>,
    #[serde(default, rename = "aws_sso_role")]
    pub aws_sso_roles: Vec<AwsSsoRoleSpec>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsConfig {
    pub max_body_bytes: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshConfig {
    pub socket: Option<PathBuf>,
    pub client_uids: Option<Vec<u32>>,
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
    pub table: toml::Table,
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
                table: toml::Table::new(),
                source: None,
            });
        }
        Err(err) => return Err(err).with_context(|| format!("could not read {}", path.display())),
    };
    let invalid = |problem: Problem| problem.into_error(&path);
    let (config, table) = parse(&text).map_err(invalid)?;
    if let Some(problem) = config.basic_problems().into_iter().next() {
        return Err(invalid(problem));
    }
    Ok(Loaded {
        config,
        table,
        source: Some(path),
    })
}

pub fn read(path: &Path) -> anyhow::Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("could not read {}", path.display()))
}

pub fn parse(text: &str) -> Result<(Config, toml::Table), Problem> {
    let problem = |err: toml::de::Error| Problem {
        topic: section_topic(section_at(text, err.span())),
        error: err.into(),
    };
    let config: Config = toml::from_str(text).map_err(problem)?;
    let table: toml::Table = toml::from_str(text).map_err(problem)?;
    Ok((config, table))
}

fn section_at(text: &str, span: Option<std::ops::Range<usize>>) -> &str {
    let end = span.map_or(0, |span| span.start);
    text.get(..end)
        .unwrap_or(text)
        .lines()
        .rev()
        .find_map(|line| line.trim_start().strip_prefix('['))
        .and_then(|header| {
            header
                .trim_start_matches('[')
                .split([']', '.'])
                .next()
                .map(str::trim)
        })
        .unwrap_or_default()
}

pub const CONFIG_TOPIC: &str = "configuration";
const RULES_TOPIC: &str = "configuration#writing-rules";
const BASE_URL_TOPIC: &str = "configuration#base-url-mode";
const OAUTH_TOPIC: &str = "configuration#oauth";
const SSH_TOPIC: &str = "ssh#configuration";
const AWS_KEY_TOPIC: &str = "aws#static-access-keys";
const AWS_SSO_TOPIC: &str = "aws#aws-iam-identity-center-sso";

pub const SECTION_TOPICS: &[(&str, &str)] = &[
    ("rule", RULES_TOPIC),
    ("scrub", RULES_TOPIC),
    ("listen", BASE_URL_TOPIC),
    ("ca", "install#2-install-admin-session"),
    ("secrets", "configuration#secret-stores"),
    ("audit", "configuration#audit-log-and-status"),
    ("status", "configuration#audit-log-and-status"),
    ("oauth", OAUTH_TOPIC),
    ("vault", OAUTH_TOPIC),
    ("limits", OAUTH_TOPIC),
    ("ssh", SSH_TOPIC),
    ("ssh_key", SSH_TOPIC),
    ("aws", AWS_KEY_TOPIC),
    ("aws_key", AWS_KEY_TOPIC),
    ("aws_sso_session", AWS_SSO_TOPIC),
    ("aws_sso_role", AWS_SSO_TOPIC),
];

fn section_topic(section: &str) -> &'static str {
    SECTION_TOPICS
        .iter()
        .find(|(name, _)| *name == section)
        .map_or(CONFIG_TOPIC, |(_, topic)| topic)
}

#[derive(Debug)]
pub struct Invalid {
    pub path: PathBuf,
    pub topic: &'static str,
}

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid config {}", self.path.display())
    }
}

#[derive(Debug)]
pub struct Problem {
    pub topic: &'static str,
    pub error: anyhow::Error,
}

impl Problem {
    pub fn into_error(self, path: &Path) -> anyhow::Error {
        self.error.context(Invalid {
            path: path.to_path_buf(),
            topic: self.topic,
        })
    }
}

fn note<E: Into<anyhow::Error>>(
    problems: &mut Vec<Problem>,
    topic: &'static str,
    result: Result<(), E>,
) {
    if let Err(error) = result {
        problems.push(Problem {
            topic,
            error: error.into(),
        });
    }
}

impl Config {
    pub fn problems(&self) -> Vec<Problem> {
        let mut problems = self.basic_problems();
        let mut rules = Vec::new();
        for spec in &self.rules {
            match Rule::from_spec(spec.clone()) {
                Ok(rule) => rules.push(rule),
                Err(err) => note(&mut problems, RULES_TOPIC, Err(err)),
            }
        }
        if rules.len() == self.rules.len() {
            note(
                &mut problems,
                RULES_TOPIC,
                RuleSet::from_rules(rules).map(drop),
            );
        }
        note(
            &mut problems,
            BASE_URL_TOPIC,
            BaseUrls::from_specs(&self.rules).map(drop),
        );
        for spec in &self.oauth {
            let placeholder = spec
                .client_secret_name()
                .map(|_| SecretString::from(String::new()));
            note(
                &mut problems,
                OAUTH_TOPIC,
                Provider::new(spec.clone(), placeholder).map(drop),
            );
        }
        problems
    }

    fn basic_problems(&self) -> Vec<Problem> {
        let mut problems = Vec::new();
        note(&mut problems, RULES_TOPIC, self.check_env_names());
        note(
            &mut problems,
            SSH_TOPIC,
            SshRule::from_specs(&self.ssh_keys).map(drop),
        );
        note(
            &mut problems,
            SSH_TOPIC,
            if self
                .ssh
                .client_uids
                .as_ref()
                .is_some_and(|uids| uids.is_empty())
            {
                Err(anyhow::anyhow!(
                    "[ssh] client_uids must list at least one uid"
                ))
            } else {
                Ok(())
            },
        );
        note(&mut problems, AWS_KEY_TOPIC, self.check_aws_keys());
        problems
    }

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

    pub fn aws_rules(&self) -> anyhow::Result<(Vec<SsoSession>, Vec<AwsRule>)> {
        let sessions = SsoSession::from_specs(&self.aws_sso_sessions)?;
        let rules = AwsRule::from_config(&self.aws_keys, &self.aws_sso_roles, &sessions)?;
        Ok((sessions, rules))
    }

    pub fn has_aws(&self) -> bool {
        !self.aws_keys.is_empty() || !self.aws_sso_roles.is_empty()
    }

    fn check_aws_keys(&self) -> anyhow::Result<()> {
        let (_, aws) = self.aws_rules()?;
        for key in &aws {
            if let Some(rule) = self
                .rules
                .iter()
                .find(|rule| credshim_aws::rule::overlaps(&rule.dummy, key.dummy()))
            {
                anyhow::bail!(
                    "aws_key {:?} and rule {:?} have dummies where one contains the other",
                    key.name(),
                    rule.name
                );
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

    pub fn ssh_socket(&self) -> anyhow::Result<PathBuf> {
        match &self.ssh.socket {
            Some(path) => Ok(path.clone()),
            None => Ok(config_dir()?.join("ssh-agent.sock")),
        }
    }

    pub fn secrets(&self) -> anyhow::Result<BackendConfig> {
        match &self.secrets {
            Some(backend) => Ok(backend.clone()),
            None => default_backend(),
        }
    }
}

const SERVICE_STATE_DIR: &str = "/var/lib/credshim";

pub fn config_dir() -> anyhow::Result<PathBuf> {
    let service = Path::new(SERVICE_STATE_DIR);
    if is_own_directory(service) {
        return Ok(service.to_path_buf());
    }
    let config_home = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".config"),
    };
    Ok(config_home.join("credshim"))
}

fn is_own_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .is_ok_and(|meta| meta.is_dir() && meta.uid() == rustix::process::geteuid().as_raw())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_parse_error_points_to_the_docs_of_its_section() {
        let topic = |text: &str| parse(text).unwrap_err().topic;
        assert_eq!(
            topic("[secrets]\nbackend = \"file\"\n"),
            "configuration#secret-stores"
        );
        assert_eq!(
            topic("[ca]\ndir = \"x\"\n\n[[aws_sso_role]]\nnmae = \"x\"\n"),
            "aws#aws-iam-identity-center-sso"
        );
        assert_eq!(topic("[[rule]\n"), "configuration#writing-rules");
        assert_eq!(topic("listne = 1\n"), CONFIG_TOPIC);
    }

    #[test]
    fn only_a_real_directory_owned_by_this_user_is_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, "").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();

        assert!(is_own_directory(dir.path()));
        assert!(!is_own_directory(&file));
        assert!(!is_own_directory(&link));
        assert!(!is_own_directory(&dir.path().join("missing")));
        if !rustix::process::geteuid().is_root() {
            assert!(!is_own_directory(Path::new("/usr")));
        }
    }
}
