use std::collections::{BTreeSet, HashSet};

use credshim_core::dummy::ISSUED_PREFIXES;
use credshim_core::rule::{MAX_DUMMY_LEN, MIN_DUMMY_LEN, is_identifier, is_valid_dummy};
use serde::Deserialize;

use crate::auth::Scope;
use crate::hosts::CUSTOMER_HOSTED_SERVICES;
use crate::sso::{SsoSession, SsoSessionError};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsKeySpec {
    pub name: String,
    pub dummy_access_key_id: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub services: Option<Vec<String>>,
    pub regions: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsSsoRoleSpec {
    pub name: String,
    pub dummy_access_key_id: String,
    pub session: String,
    pub account_id: String,
    pub role_name: String,
    pub services: Option<Vec<String>>,
    pub regions: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Static {
        access_key_id: String,
        secret_access_key: String,
    },
    Sso(SsoRole),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SsoRole {
    pub session: String,
    pub account_id: String,
    pub role_name: String,
}

#[derive(Clone, Debug)]
pub struct AwsRule {
    name: String,
    dummy: String,
    source: Source,
    services: Option<BTreeSet<String>>,
    regions: Option<BTreeSet<String>>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AwsRuleError {
    #[error("aws_key name {0:?} must be non-empty and use only letters, digits, '.', '_' or '-'")]
    InvalidName(String),
    #[error("aws_key {0:?} is defined more than once")]
    DuplicateName(String),
    #[error(
        "aws_key {rule:?}: secret name {secret:?} must use only letters, digits, '.', '_' or '-'"
    )]
    InvalidSecretName { rule: String, secret: String },
    #[error(
        "aws_key {0:?}: dummy_access_key_id must be {MIN_DUMMY_LEN}..={MAX_DUMMY_LEN} characters of A-Z, a-z, 0-9, '-', '.', '_' or '~'"
    )]
    InvalidDummy(String),
    #[error(
        "aws_key {0:?}: dummy_access_key_id must not contain the prefixes reserved for issued OAuth tokens"
    )]
    ReservedDummy(String),
    #[error("aws_key {0:?} and {1:?} have dummies where one contains the other")]
    OverlappingDummies(String, String),
    #[error(
        "aws_key {rule:?}: {field} must list at least one lowercase name of letters, digits or '-'"
    )]
    InvalidFilter { rule: String, field: &'static str },
    #[error("aws_sso_role {rule:?}: no aws_sso_session is named {session:?}")]
    UnknownSession { rule: String, session: String },
    #[error("aws_sso_role {0:?}: account_id must be 12 digits")]
    InvalidAccount(String),
    #[error(
        "aws_sso_role {0:?}: role_name must be 1..=64 characters of letters, digits or '+=,.@_-'"
    )]
    InvalidRoleName(String),
    #[error(transparent)]
    Session(#[from] SsoSessionError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeRefusal {
    Service,
    Region,
}

impl AwsRule {
    pub fn from_specs(specs: &[AwsKeySpec]) -> Result<Vec<Self>, AwsRuleError> {
        Self::from_config(specs, &[], &[])
    }

    pub fn from_config(
        keys: &[AwsKeySpec],
        roles: &[AwsSsoRoleSpec],
        sessions: &[SsoSession],
    ) -> Result<Vec<Self>, AwsRuleError> {
        let rules = keys
            .iter()
            .map(Self::from_spec)
            .chain(roles.iter().map(|spec| Self::from_role(spec, sessions)))
            .collect::<Result<Vec<_>, _>>()?;
        let mut names = HashSet::new();
        for rule in &rules {
            if !names.insert(rule.name.as_str()) {
                return Err(AwsRuleError::DuplicateName(rule.name.clone()));
            }
        }
        for (i, a) in rules.iter().enumerate() {
            if let Some(b) = rules[i + 1..].iter().find(|b| overlaps(&a.dummy, &b.dummy)) {
                return Err(AwsRuleError::OverlappingDummies(
                    a.name.clone(),
                    b.name.clone(),
                ));
            }
        }
        Ok(rules)
    }

    fn from_spec(spec: &AwsKeySpec) -> Result<Self, AwsRuleError> {
        let name = spec.name.clone();
        if !is_identifier(&name) {
            return Err(AwsRuleError::InvalidName(name));
        }
        for secret in [&spec.access_key_id, &spec.secret_access_key] {
            if !is_identifier(secret) {
                return Err(AwsRuleError::InvalidSecretName {
                    rule: name,
                    secret: secret.clone(),
                });
            }
        }
        Self::build(
            name,
            &spec.dummy_access_key_id,
            Source::Static {
                access_key_id: spec.access_key_id.clone(),
                secret_access_key: spec.secret_access_key.clone(),
            },
            spec.services.as_deref(),
            spec.regions.as_deref(),
        )
    }

    fn from_role(spec: &AwsSsoRoleSpec, sessions: &[SsoSession]) -> Result<Self, AwsRuleError> {
        let name = spec.name.clone();
        if !is_identifier(&name) {
            return Err(AwsRuleError::InvalidName(name));
        }
        if !sessions
            .iter()
            .any(|session| session.name() == spec.session)
        {
            return Err(AwsRuleError::UnknownSession {
                rule: name,
                session: spec.session.clone(),
            });
        }
        if spec.account_id.len() != 12 || !spec.account_id.bytes().all(|b| b.is_ascii_digit()) {
            return Err(AwsRuleError::InvalidAccount(name));
        }
        let role_name_valid = (1..=64).contains(&spec.role_name.len())
            && spec
                .role_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-".contains(&b));
        if !role_name_valid {
            return Err(AwsRuleError::InvalidRoleName(name));
        }
        Self::build(
            name,
            &spec.dummy_access_key_id,
            Source::Sso(SsoRole {
                session: spec.session.clone(),
                account_id: spec.account_id.clone(),
                role_name: spec.role_name.clone(),
            }),
            spec.services.as_deref(),
            spec.regions.as_deref(),
        )
    }

    fn build(
        name: String,
        dummy: &str,
        source: Source,
        services: Option<&[String]>,
        regions: Option<&[String]>,
    ) -> Result<Self, AwsRuleError> {
        if !is_valid_dummy(dummy) {
            return Err(AwsRuleError::InvalidDummy(name));
        }
        if ISSUED_PREFIXES.iter().any(|prefix| dummy.contains(prefix)) {
            return Err(AwsRuleError::ReservedDummy(name));
        }
        let services = filter(&name, "services", services)?;
        let regions = filter(&name, "regions", regions)?;
        Ok(Self {
            name,
            dummy: dummy.to_string(),
            source,
            services,
            regions,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn dummy(&self) -> &str {
        &self.dummy
    }

    pub fn source(&self) -> &Source {
        &self.source
    }

    pub fn refuses(&self, scope: &Scope) -> Option<ScopeRefusal> {
        let listed = self
            .services
            .as_ref()
            .map(|allowed| allowed.contains(&scope.service));
        let customer_hosted = CUSTOMER_HOSTED_SERVICES.contains(&scope.service.as_str());
        if listed == Some(false) || (customer_hosted && listed.is_none()) {
            return Some(ScopeRefusal::Service);
        }
        if self
            .regions
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&scope.region))
        {
            return Some(ScopeRefusal::Region);
        }
        None
    }
}

pub fn overlaps(a: &str, b: &str) -> bool {
    a.contains(b) || b.contains(a)
}

fn filter(
    rule: &str,
    field: &'static str,
    values: Option<&[String]>,
) -> Result<Option<BTreeSet<String>>, AwsRuleError> {
    let Some(values) = values else {
        return Ok(None);
    };
    let valid = !values.is_empty()
        && values.iter().all(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    if !valid {
        return Err(AwsRuleError::InvalidFilter {
            rule: rule.to_string(),
            field,
        });
    }
    Ok(Some(values.iter().cloned().collect()))
}
