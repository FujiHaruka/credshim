use std::collections::BTreeSet;

use base64::Engine;
use base64::alphabet::STANDARD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use http::HeaderName;
use http::header::{AUTHORIZATION, HeaderValue};
use http::request::Parts;
use percent_encoding::percent_decode_str;

use crate::dummy;
use crate::rule::Location;

const LENIENT_BASE64: GeneralPurpose = GeneralPurpose::new(
    &STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Hit {
    Header(HeaderName),
    BasicAuth,
    EncodedHeader,
    Query(Vec<u8>),
    Uri,
}

impl Hit {
    pub(crate) fn is_at(&self, location: &Location) -> bool {
        match (self, location) {
            (Hit::Header(found), Location::Header(wanted)) => found == wanted,
            (Hit::BasicAuth, Location::BasicAuth) => true,
            (Hit::Query(found), Location::Query(wanted)) => found == wanted.as_bytes(),
            _ => false,
        }
    }
}

pub(crate) fn hits(dummy: &str, parts: &Parts) -> Vec<Hit> {
    let needle = dummy.as_bytes();
    let mut hits = Vec::new();
    for (name, value) in &parts.headers {
        if contains(value.as_bytes(), needle) {
            hits.push(Hit::Header(name.clone()));
        }
        if let Some(decoded) = decode_basic(value)
            && contains(&decoded, needle)
        {
            hits.push(if name == AUTHORIZATION {
                Hit::BasicAuth
            } else {
                Hit::EncodedHeader
            });
        }
    }
    let path = parts.uri.path();
    if contains(path.as_bytes(), needle) || contains(&decode(path), needle) {
        hits.push(Hit::Uri);
    }
    if let Some(query) = parts.uri.query() {
        for (name, value) in query_pairs(query) {
            if contains(&decode(value), needle) {
                hits.push(Hit::Query(decode(name)));
            }
            if contains(&decode(name), needle) {
                hits.push(Hit::Uri);
            }
        }
    }
    hits
}

pub fn appears_in(dummy: &str, parts: &Parts) -> bool {
    !hits(dummy, parts).is_empty()
}

pub(crate) fn issued_tokens(parts: &Parts) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut collect = |haystack: &[u8]| {
        found.extend(dummy::find_issued(haystack).map(str::to_string));
    };
    for value in parts.headers.values() {
        collect(value.as_bytes());
        if let Some(decoded) = decode_basic(value) {
            collect(&decoded);
        }
    }
    let path = parts.uri.path();
    collect(path.as_bytes());
    collect(&decode(path));
    if let Some(query) = parts.uri.query() {
        collect(query.as_bytes());
        for (name, value) in query_pairs(query) {
            collect(&decode(name));
            collect(&decode(value));
        }
    }
    found
}

pub(crate) fn query_pairs(query: &str) -> impl Iterator<Item = (&str, &str)> {
    query
        .split('&')
        .map(|pair| pair.split_once('=').unwrap_or((pair, "")))
}

pub(crate) fn decode(raw: &str) -> Vec<u8> {
    percent_decode_str(raw).collect()
}

pub fn decode_basic(value: &HeaderValue) -> Option<Vec<u8>> {
    let value = value.to_str().ok()?;
    let (scheme, credentials) = value.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    LENIENT_BASE64.decode(credentials.trim()).ok()
}

pub(crate) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
