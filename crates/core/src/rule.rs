use std::collections::HashSet;

use http::HeaderName;
use http::header;
use serde::Deserialize;

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
pub struct Target {
    host: String,
    port: u16,
    path_prefix: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Rule {
    name: String,
    target: Target,
    secret: String,
    dummy: String,
    locations: Vec<Location>,
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
    #[error("rules {0:?} and {1:?} have dummies where one contains the other")]
    OverlappingDummies(String, String),
    #[error("rule {0:?}: inject must name at least one of header, basic or query")]
    NoLocation(String),
    #[error("rule {rule:?}: header {header:?} cannot carry a credential")]
    InvalidHeader { rule: String, header: String },
    #[error("rule {0:?}: query parameter name must be non-empty")]
    InvalidQueryParam(String),
}

impl Rule {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn host(&self) -> &str {
        &self.target.host
    }

    pub fn port(&self) -> u16 {
        self.target.port
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub fn dummy(&self) -> &str {
        &self.dummy
    }

    pub fn locations(&self) -> &[Location] {
        &self.locations
    }

    pub(crate) fn applies_to(&self, host: &str, port: u16, path: &str) -> bool {
        self.target.host.eq_ignore_ascii_case(host)
            && self.target.port == port
            && self
                .target
                .path_prefix
                .as_deref()
                .is_none_or(|prefix| path_is_under(path, prefix))
    }
}

pub(crate) fn validate(specs: Vec<RuleSpec>) -> Result<Vec<Rule>, RuleError> {
    let mut names = HashSet::new();
    let mut rules = Vec::with_capacity(specs.len());
    for spec in specs {
        let rule = validate_one(spec)?;
        if !names.insert(rule.name.clone()) {
            return Err(RuleError::DuplicateName(rule.name));
        }
        rules.push(rule);
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

fn validate_one(spec: RuleSpec) -> Result<Rule, RuleError> {
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
    let host = host.to_ascii_lowercase();
    if !is_dns_name(&host) {
        return Err(RuleError::InvalidHost { rule: name, host });
    }
    let port = port.unwrap_or(DEFAULT_PORT);
    if port == 0 {
        return Err(RuleError::InvalidPort(name));
    }
    if let Some(prefix) = &path_prefix
        && !is_clean_path_prefix(prefix)
    {
        return Err(RuleError::InvalidPathPrefix {
            rule: name,
            prefix: prefix.clone(),
        });
    }
    if !is_identifier(&secret) {
        return Err(RuleError::InvalidSecretName { rule: name, secret });
    }
    if !is_valid_dummy(&dummy) {
        return Err(RuleError::InvalidDummy(name));
    }
    let locations = locations(&name, inject)?;
    Ok(Rule {
        name,
        target: Target {
            host,
            port,
            path_prefix,
        },
        secret,
        dummy,
        locations,
    })
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
