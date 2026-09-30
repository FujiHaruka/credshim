use std::collections::HashSet;

use http::HeaderName;
use http::header;
use secrecy::SecretString;
use serde::Deserialize;

use crate::dummy;

pub const DEFAULT_PORT: u16 = 443;
pub const MIN_DUMMY_LEN: usize = 24;
pub const MAX_DUMMY_LEN: usize = 256;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub name: String,
    pub host: String,
    pub port: Option<u16>,
    pub path_prefix: Option<String>,
    pub secret: String,
    pub dummy: String,
    pub inject: InjectSpec,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InjectSpec {
    pub header: Option<String>,
    pub query: Option<String>,
    #[serde(default)]
    pub basic: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Location {
    Header(HeaderName),
    BasicAuth,
    Query(String),
}

#[derive(Clone, Debug)]
pub struct Binding {
    host: String,
    port: u16,
    path_prefix: Option<String>,
    locations: Vec<Location>,
}

#[derive(Clone, Debug)]
pub enum SecretRef {
    Named(String),
    Inline(SecretString),
}

#[derive(Clone, Debug)]
pub struct Rule {
    name: String,
    dummy: String,
    secret: SecretRef,
    bindings: Vec<Binding>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BindingError {
    #[error("host {0:?} must be a plain lowercase DNS name without port")]
    InvalidHost(String),
    #[error("port must not be 0")]
    InvalidPort,
    #[error(
        "path_prefix {0:?} must start with '/' and contain no dot segments, '%', '?', '#' or '\\'"
    )]
    InvalidPathPrefix(String),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RuleError {
    #[error("rule name {0:?} must be non-empty and use only letters, digits, '.', '_' or '-'")]
    InvalidName(String),
    #[error("rule {0:?} is defined more than once")]
    DuplicateName(String),
    #[error("rule {rule:?}: host {host:?} must be a plain lowercase DNS name without port")]
    InvalidHost { rule: String, host: String },
    #[error("rule {0:?}: port must not be 0")]
    InvalidPort(String),
    #[error(
        "rule {rule:?}: path_prefix {prefix:?} must start with '/' and contain no dot segments, '%', '?', '#' or '\\'"
    )]
    InvalidPathPrefix { rule: String, prefix: String },
    #[error("rule {rule:?}: secret name {secret:?} must use only letters, digits, '.', '_' or '-'")]
    InvalidSecretName { rule: String, secret: String },
    #[error(
        "rule {0:?}: dummy must be {MIN_DUMMY_LEN}..={MAX_DUMMY_LEN} characters of A-Z, a-z, 0-9, '-', '.', '_' or '~'"
    )]
    InvalidDummy(String),
    #[error("rule {0:?}: dummy must not contain the prefixes reserved for issued OAuth tokens")]
    ReservedDummy(String),
    #[error("rules {0:?} and {1:?} have dummies where one contains the other")]
    OverlappingDummies(String, String),
    #[error("rule {0:?}: inject must name at least one of header, basic or query")]
    NoLocation(String),
    #[error("rule {rule:?}: header {header:?} cannot carry a credential")]
    InvalidHeader { rule: String, header: String },
    #[error("rule {0:?}: query parameter name must be non-empty")]
    InvalidQueryParam(String),
    #[error("rule {0:?}: must be bound to at least one destination")]
    Unbound(String),
}

impl Binding {
    pub fn new(
        host: &str,
        port: u16,
        path_prefix: Option<String>,
        locations: Vec<Location>,
    ) -> Result<Self, BindingError> {
        let host = host.to_ascii_lowercase();
        if !is_dns_name(&host) {
            return Err(BindingError::InvalidHost(host));
        }
        if port == 0 {
            return Err(BindingError::InvalidPort);
        }
        if let Some(prefix) = &path_prefix
            && !is_clean_path_prefix(prefix)
        {
            return Err(BindingError::InvalidPathPrefix(prefix.clone()));
        }
        Ok(Self {
            host,
            port,
            path_prefix,
            locations,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn locations(&self) -> &[Location] {
        &self.locations
    }

    pub(crate) fn applies_to(&self, host: &str, port: u16, path: &str) -> bool {
        self.host.eq_ignore_ascii_case(host)
            && self.port == port
            && self
                .path_prefix
                .as_deref()
                .is_none_or(|prefix| path_is_under(path, prefix))
    }
}

impl Rule {
    pub fn new(
        name: String,
        dummy: String,
        secret: SecretRef,
        bindings: Vec<Binding>,
    ) -> Result<Self, RuleError> {
        if !is_identifier(&name) {
            return Err(RuleError::InvalidName(name));
        }
        if let SecretRef::Named(secret) = &secret
            && !is_identifier(secret)
        {
            return Err(RuleError::InvalidSecretName {
                rule: name,
                secret: secret.clone(),
            });
        }
        if !is_valid_dummy(&dummy) {
            return Err(RuleError::InvalidDummy(name));
        }
        if dummy::ISSUED_PREFIXES
            .iter()
            .any(|prefix| dummy.contains(prefix))
        {
            return Err(RuleError::ReservedDummy(name));
        }
        if bindings.is_empty() {
            return Err(RuleError::Unbound(name));
        }
        Ok(Self {
            name,
            dummy,
            secret,
            bindings,
        })
    }

    pub fn issued(
        name: String,
        dummy: String,
        secret: SecretString,
        bindings: Vec<Binding>,
    ) -> Self {
        Self {
            name,
            dummy,
            secret: SecretRef::Inline(secret),
            bindings,
        }
    }

    pub fn from_spec(spec: RuleSpec) -> Result<Self, RuleError> {
        let RuleSpec {
            name,
            host,
            port,
            path_prefix,
            secret,
            dummy,
            inject,
        } = spec;
        if !is_identifier(&name) {
            return Err(RuleError::InvalidName(name));
        }
        let locations = locations(&name, inject)?;
        let binding = Binding::new(&host, port.unwrap_or(DEFAULT_PORT), path_prefix, locations)
            .map_err(|err| match err {
                BindingError::InvalidHost(host) => RuleError::InvalidHost {
                    rule: name.clone(),
                    host,
                },
                BindingError::InvalidPort => RuleError::InvalidPort(name.clone()),
                BindingError::InvalidPathPrefix(prefix) => RuleError::InvalidPathPrefix {
                    rule: name.clone(),
                    prefix,
                },
            })?;
        Self::new(name, dummy, SecretRef::Named(secret), vec![binding])
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn dummy(&self) -> &str {
        &self.dummy
    }

    pub fn secret(&self) -> &SecretRef {
        &self.secret
    }

    pub fn secret_name(&self) -> Option<&str> {
        match &self.secret {
            SecretRef::Named(name) => Some(name),
            SecretRef::Inline(_) => None,
        }
    }

    pub fn bindings(&self) -> &[Binding] {
        &self.bindings
    }

    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.bindings.iter().map(Binding::host)
    }
}

pub(crate) fn validate(rules: Vec<Rule>) -> Result<Vec<Rule>, RuleError> {
    let mut names = HashSet::new();
    for rule in &rules {
        if !names.insert(rule.name.as_str()) {
            return Err(RuleError::DuplicateName(rule.name.clone()));
        }
    }
    for (i, a) in rules.iter().enumerate() {
        for b in &rules[i + 1..] {
            if a.dummy.contains(&b.dummy) || b.dummy.contains(&a.dummy) {
                return Err(RuleError::OverlappingDummies(
                    a.name.clone(),
                    b.name.clone(),
                ));
            }
        }
    }
    Ok(rules)
}

fn locations(rule: &str, inject: InjectSpec) -> Result<Vec<Location>, RuleError> {
    let mut locations = Vec::new();
    if let Some(name) = inject.header {
        let header = HeaderName::from_bytes(name.as_bytes())
            .ok()
            .filter(|header| !is_forbidden_header(header))
            .ok_or_else(|| RuleError::InvalidHeader {
                rule: rule.to_string(),
                header: name,
            })?;
        locations.push(Location::Header(header));
    }
    if inject.basic {
        locations.push(Location::BasicAuth);
    }
    if let Some(param) = inject.query {
        if param.is_empty() {
            return Err(RuleError::InvalidQueryParam(rule.to_string()));
        }
        locations.push(Location::Query(param));
    }
    if locations.is_empty() {
        return Err(RuleError::NoLocation(rule.to_string()));
    }
    Ok(locations)
}

fn is_forbidden_header(header: &HeaderName) -> bool {
    [
        header::HOST,
        header::CONTENT_LENGTH,
        header::TRANSFER_ENCODING,
        header::CONNECTION,
        header::UPGRADE,
        header::TE,
        header::TRAILER,
        header::PROXY_AUTHORIZATION,
    ]
    .contains(header)
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn is_dns_name(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

pub(crate) fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn is_valid_dummy(dummy: &str) -> bool {
    (MIN_DUMMY_LEN..=MAX_DUMMY_LEN).contains(&dummy.len()) && dummy.bytes().all(is_unreserved)
}

fn is_clean_path_prefix(prefix: &str) -> bool {
    prefix.starts_with('/') && !prefix.contains(['%', '?', '#', '\\']) && !has_dot_segment(prefix)
}

fn has_dot_segment(path: &str) -> bool {
    path.split('/')
        .any(|segment| segment == "." || segment == "..")
}

fn has_encoded_separator(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    ["%2e", "%2f", "%5c"]
        .iter()
        .any(|encoded| lower.contains(encoded))
}

fn path_is_under(path: &str, prefix: &str) -> bool {
    if path.contains('\\') || has_dot_segment(path) || has_encoded_separator(path) {
        return false;
    }
    match path.strip_prefix(prefix) {
        Some(rest) => prefix.ends_with('/') || rest.is_empty() || rest.starts_with('/'),
        None => false,
    }
}
