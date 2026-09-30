use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use http::header::{AUTHORIZATION, HeaderName, HeaderValue};
use http::request::Parts;
use http::uri::PathAndQuery;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_encode};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::policy::{Limiter, Permit};
use crate::rule::{Location, Rule, SecretRef};
use crate::rules::{self, Decision, Destination, Edit, RuleSet};
use crate::scan;
use crate::scrub::Scrubber;

const QUERY_VALUE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

#[derive(Default)]
pub struct Secrets(HashMap<String, SecretString>);

impl Secrets {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, name: impl Into<String>, value: SecretString) {
        self.0.insert(name.into(), value);
    }

    fn get(&self, name: &str) -> Option<&SecretString> {
        self.0.get(name)
    }
}

impl fmt::Debug for Secrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.0.keys()).finish()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InjectorError {
    #[error("rule {rule:?} needs secret {secret:?}, which is not in the secret store")]
    MissingSecret { rule: String, secret: String },
    #[error("secret {secret:?} is empty")]
    EmptySecret { secret: String },
    #[error(
        "secret {secret:?} cannot be placed in an HTTP header: it contains control characters or surrounding whitespace"
    )]
    NotHeaderSafe { secret: String },
}

#[derive(Debug, thiserror::Error)]
#[error("could not rewrite the request for rule {rule:?}")]
pub struct InjectError {
    pub rule: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Injected(Vec<String>),
    Denied(String),
    NotAllowed(String),
}

pub trait TokenResolver: Send + Sync + fmt::Debug {
    fn resolve(&self, dummy: &str) -> Option<Rule>;

    fn generation(&self) -> u64 {
        0
    }

    fn issued(&self) -> Vec<(String, SecretString)> {
        Vec::new()
    }
}

#[derive(Debug, Default)]
pub struct Injector {
    rules: RuleSet,
    secrets: Secrets,
    tokens: Option<Arc<dyn TokenResolver>>,
    scrubber: Mutex<Option<(u64, Arc<Scrubber>)>>,
    limiter: Limiter,
}

impl Injector {
    pub fn new(rules: RuleSet, secrets: Secrets) -> Result<Self, InjectorError> {
        for rule in rules.rules() {
            let Some(name) = rule.secret_name() else {
                continue;
            };
            let secret = secrets
                .get(name)
                .ok_or_else(|| InjectorError::MissingSecret {
                    rule: rule.name().to_string(),
                    secret: name.to_string(),
                })?;
            check_secret(rule, name, secret)?;
        }
        Ok(Self {
            rules,
            secrets,
            tokens: None,
            scrubber: Mutex::default(),
            limiter: Limiter::default(),
        })
    }

    pub fn with_tokens(mut self, tokens: Arc<dyn TokenResolver>) -> Self {
        self.tokens = Some(tokens);
        self
    }

    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    pub fn unscrubbable_rules(&self) -> Vec<&str> {
        self.rules
            .rules()
            .iter()
            .filter(|rule| {
                let secret = match rule.secret() {
                    SecretRef::Named(name) => self.secrets.get(name),
                    SecretRef::Inline(secret) => Some(secret),
                };
                secret.is_some_and(|secret| {
                    secret.expose_secret().len() < crate::scrub::MIN_SCRUB_LEN
                })
            })
            .map(Rule::name)
            .collect()
    }

    pub fn admit(&self, applied: &[String]) -> Result<Permit, String> {
        let limits = applied.iter().filter_map(|name| {
            let rule = self.rules.rules().iter().find(|rule| rule.name() == name)?;
            Some((rule.name(), rule.policy().limits()))
        });
        self.limiter.admit(
            limits,
            std::time::Instant::now(),
            std::time::SystemTime::now(),
        )
    }

    pub fn scrubber(&self) -> Arc<Scrubber> {
        let generation = self.tokens.as_ref().map_or(0, |tokens| tokens.generation());
        let mut cached = self
            .scrubber
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((built, scrubber)) = cached.as_ref()
            && *built == generation
        {
            return scrubber.clone();
        }
        let issued = self
            .tokens
            .as_ref()
            .map(|tokens| tokens.issued())
            .unwrap_or_default();
        let statics = self.rules.rules().iter().filter_map(|rule| {
            let secret = match rule.secret() {
                SecretRef::Named(name) => self.secrets.get(name)?,
                SecretRef::Inline(secret) => secret,
            };
            Some((secret, rule.dummy()))
        });
        let scrubber = Arc::new(Scrubber::new(
            statics.chain(issued.iter().map(|(dummy, real)| (real, dummy.as_str()))),
        ));
        *cached = Some((generation, scrubber.clone()));
        scrubber
    }

    pub fn first_dummy_in(&self, parts: &Parts) -> Option<String> {
        let issued = self.issued_in(parts);
        rules::first_dummy_in(self.rules.rules().iter().chain(&issued), parts)
            .map(|rule| rule.name().to_string())
    }

    fn issued_in(&self, parts: &Parts) -> Vec<Rule> {
        let Some(tokens) = &self.tokens else {
            return Vec::new();
        };
        scan::issued_tokens(parts)
            .iter()
            .filter_map(|dummy| tokens.resolve(dummy))
            .collect()
    }

    pub fn apply(&self, dest: Destination<'_>, parts: &mut Parts) -> Result<Verdict, InjectError> {
        let issued = self.issued_in(parts);
        match rules::decide(self.rules.rules().iter().chain(&issued), dest, parts) {
            Decision::Pass => Ok(Verdict::Pass),
            Decision::Deny(rule) => Ok(Verdict::Denied(rule.name().to_string())),
            Decision::NotAllowed(rule) => Ok(Verdict::NotAllowed(rule.name().to_string())),
            Decision::Inject(edits) => {
                let mut applied: Vec<String> = Vec::new();
                for edit in edits {
                    self.substitute(edit, parts).ok_or_else(|| InjectError {
                        rule: edit.rule().name().to_string(),
                    })?;
                    let name = edit.rule().name();
                    if !applied.iter().any(|seen| seen == name) {
                        applied.push(name.to_string());
                    }
                }
                Ok(Verdict::Injected(applied))
            }
        }
    }

    fn substitute(&self, edit: Edit<'_>, parts: &mut Parts) -> Option<()> {
        let rule = edit.rule();
        let secret = match rule.secret() {
            SecretRef::Named(name) => self.secrets.get(name)?,
            SecretRef::Inline(secret) => secret,
        }
        .expose_secret()
        .as_bytes();
        let dummy = rule.dummy().as_bytes();
        match edit.location() {
            Location::Header(name) => replace_in_header(parts, name, dummy, secret),
            Location::BasicAuth => replace_in_basic(parts, dummy, secret),
            Location::Query(param) => replace_in_query(parts, param, rule.dummy(), secret),
        }
    }
}

fn check_secret(rule: &Rule, name: &str, secret: &SecretString) -> Result<(), InjectorError> {
    let value = secret.expose_secret();
    if value.is_empty() {
        return Err(InjectorError::EmptySecret {
            secret: name.to_string(),
        });
    }
    let needs_header_safe = rule
        .bindings()
        .iter()
        .flat_map(|binding| binding.locations())
        .any(|location| matches!(location, Location::Header(_)));
    let header_safe = value.trim() == value && HeaderValue::from_str(value).is_ok();
    if needs_header_safe && !header_safe {
        return Err(InjectorError::NotHeaderSafe {
            secret: name.to_string(),
        });
    }
    Ok(())
}

fn replace_in_header(
    parts: &mut Parts,
    name: &HeaderName,
    dummy: &[u8],
    secret: &[u8],
) -> Option<()> {
    let values: Vec<HeaderValue> = parts.headers.get_all(name).iter().cloned().collect();
    parts.headers.remove(name);
    for value in values {
        let value = if scan::contains(value.as_bytes(), dummy) {
            let replaced = replace_all(value.as_bytes(), dummy, secret);
            sensitive(HeaderValue::from_bytes(&replaced).ok()?)
        } else {
            value
        };
        parts.headers.append(name.clone(), value);
    }
    Some(())
}

fn replace_in_basic(parts: &mut Parts, dummy: &[u8], secret: &[u8]) -> Option<()> {
    let values: Vec<HeaderValue> = parts
        .headers
        .get_all(AUTHORIZATION)
        .iter()
        .cloned()
        .collect();
    parts.headers.remove(AUTHORIZATION);
    for value in values {
        let value = match scan::decode_basic(&value).map(Zeroizing::new) {
            Some(decoded) if scan::contains(&decoded, dummy) => {
                let replaced = replace_all(&decoded, dummy, secret);
                let encoded = Zeroizing::new(format!("Basic {}", STANDARD.encode(&*replaced)));
                sensitive(HeaderValue::from_str(&encoded).ok()?)
            }
            _ => value,
        };
        parts.headers.append(AUTHORIZATION, value);
    }
    Some(())
}

fn replace_in_query(parts: &mut Parts, param: &str, dummy: &str, secret: &[u8]) -> Option<()> {
    let query = parts.uri.query()?;
    let encoded_secret = Zeroizing::new(percent_encode(secret, QUERY_VALUE).to_string());
    let rewritten: Zeroizing<Vec<String>> = Zeroizing::new(
        scan::query_pairs(query)
            .zip(query.split('&'))
            .map(|((name, value), raw)| {
                if scan::decode(name) != param.as_bytes() {
                    return raw.to_string();
                }
                if value.contains(dummy) {
                    return format!("{name}={}", value.replace(dummy, &encoded_secret));
                }
                let decoded = Zeroizing::new(scan::decode(value));
                if !scan::contains(&decoded, dummy.as_bytes()) {
                    return raw.to_string();
                }
                let replaced = replace_all(&decoded, dummy.as_bytes(), secret);
                let reencoded = percent_encode(&replaced, QUERY_VALUE);
                format!("{name}={reencoded}")
            })
            .collect(),
    );
    let rewritten = Zeroizing::new(rewritten.join("&"));
    let path_and_query =
        PathAndQuery::try_from(format!("{}?{}", parts.uri.path(), rewritten.as_str())).ok()?;
    let mut uri = std::mem::take(&mut parts.uri).into_parts();
    uri.path_and_query = Some(path_and_query);
    parts.uri = http::Uri::from_parts(uri).ok()?;
    Some(())
}

fn replace_all(haystack: &[u8], needle: &[u8], with: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(haystack.len() + with.len()));
    let mut rest = haystack;
    while let Some(at) = rest
        .windows(needle.len())
        .position(|window| window == needle)
    {
        out.extend_from_slice(&rest[..at]);
        out.extend_from_slice(with);
        rest = &rest[at + needle.len()..];
    }
    out.extend_from_slice(rest);
    out
}

fn sensitive(mut value: HeaderValue) -> HeaderValue {
    value.set_sensitive(true);
    value
}
