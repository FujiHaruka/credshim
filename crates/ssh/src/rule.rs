use std::collections::HashSet;
use std::str::FromStr;

use serde::Deserialize;
use ssh_key::{Fingerprint, HashAlg};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshKeySpec {
    pub name: String,
    pub secret: String,
    pub host_keys: Vec<String>,
    pub users: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct SshRule {
    name: String,
    secret: String,
    host_keys: Vec<Fingerprint>,
    users: Vec<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SshRuleError {
    #[error("ssh_key name {0:?} must be non-empty and use only letters, digits, '.', '_' or '-'")]
    InvalidName(String),
    #[error("ssh_key {0:?} is defined more than once")]
    DuplicateName(String),
    #[error(
        "ssh_key {rule:?}: secret name {secret:?} must use only letters, digits, '.', '_' or '-'"
    )]
    InvalidSecretName { rule: String, secret: String },
    #[error("ssh_key {first:?} and {second:?} use the same secret {secret:?}")]
    SharedSecret {
        first: String,
        second: String,
        secret: String,
    },
    #[error("ssh_key {0:?}: host_keys must list at least one fingerprint")]
    NoHostKeys(String),
    #[error(
        "ssh_key {rule:?}: host key {value:?} must be a SHA256 fingerprint like \"SHA256:...\""
    )]
    InvalidHostKey { rule: String, value: String },
    #[error("ssh_key {0:?}: users must list at least one user name")]
    NoUsers(String),
    #[error(
        "ssh_key {rule:?}: user {user:?} must be non-empty and use only letters, digits, '.', '_' or '-'"
    )]
    InvalidUser { rule: String, user: String },
}

impl SshRule {
    pub fn from_spec(spec: SshKeySpec) -> Result<Self, SshRuleError> {
        if !is_plain_name(&spec.name) {
            return Err(SshRuleError::InvalidName(spec.name));
        }
        if !is_plain_name(&spec.secret) {
            return Err(SshRuleError::InvalidSecretName {
                rule: spec.name,
                secret: spec.secret,
            });
        }
        if spec.host_keys.is_empty() {
            return Err(SshRuleError::NoHostKeys(spec.name));
        }
        let mut host_keys = Vec::with_capacity(spec.host_keys.len());
        for value in &spec.host_keys {
            let Some(fingerprint) = parse_fingerprint(value) else {
                return Err(SshRuleError::InvalidHostKey {
                    rule: spec.name,
                    value: value.clone(),
                });
            };
            host_keys.push(fingerprint);
        }
        if spec.users.is_empty() {
            return Err(SshRuleError::NoUsers(spec.name));
        }
        if let Some(user) = spec.users.iter().find(|user| !is_plain_name(user)) {
            return Err(SshRuleError::InvalidUser {
                user: user.clone(),
                rule: spec.name,
            });
        }
        Ok(Self {
            name: spec.name,
            secret: spec.secret,
            host_keys,
            users: spec.users,
        })
    }

    pub fn from_specs(specs: &[SshKeySpec]) -> Result<Vec<Self>, SshRuleError> {
        let rules = specs
            .iter()
            .cloned()
            .map(Self::from_spec)
            .collect::<Result<Vec<_>, _>>()?;
        let mut names = HashSet::new();
        for rule in &rules {
            if !names.insert(rule.name.as_str()) {
                return Err(SshRuleError::DuplicateName(rule.name.clone()));
            }
        }
        for (i, first) in rules.iter().enumerate() {
            if let Some(second) = rules[i + 1..].iter().find(|r| r.secret == first.secret) {
                return Err(SshRuleError::SharedSecret {
                    first: first.name.clone(),
                    second: second.name.clone(),
                    secret: first.secret.clone(),
                });
            }
        }
        Ok(rules)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn secret_name(&self) -> &str {
        &self.secret
    }

    pub fn binds_host_key(&self, fingerprint: &Fingerprint) -> bool {
        self.host_keys.contains(fingerprint)
    }

    pub fn allows_user(&self, user: &str) -> bool {
        self.users.iter().any(|allowed| allowed == user)
    }
}

fn parse_fingerprint(value: &str) -> Option<Fingerprint> {
    Fingerprint::from_str(value)
        .ok()
        .filter(|fingerprint| fingerprint.algorithm() == HashAlg::Sha256)
}

fn is_plain_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
