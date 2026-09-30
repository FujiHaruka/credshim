use http::request::Parts;
use http::{HeaderName, Method};
use percent_encoding::percent_decode_str;

use crate::credential_operations::CREDENTIAL_OPERATIONS;
use crate::hosts;

const X_AMZ_TARGET: HeaderName = HeaderName::from_static("x-amz-target");
const MAX_NAME_LEN: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth {
    None,
    SigV4,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CredentialOperation {
    pub signing_name: &'static str,
    pub endpoint_prefix: &'static str,
    pub name: &'static str,
    pub method: &'static str,
    pub request_uri: &'static str,
    pub auth: Auth,
}

impl CredentialOperation {
    pub fn qualified(&self) -> String {
        format!("{}:{}", self.signing_name, self.name)
    }

    fn serves(&self, scope_service: Option<&str>, host: &str) -> bool {
        let signing_name = scope_service.map(|service| match service {
            "s3express" => "s3",
            other => other,
        });
        signing_name == Some(self.signing_name) || hosts::has_prefix(host, self.endpoint_prefix)
    }

    fn matches(&self, request: &Request<'_>) -> bool {
        let named = request
            .names
            .iter()
            .any(|name| name.eq_ignore_ascii_case(self.name));
        named || (self.request_uri != "/" && self.matches_route(request))
    }

    fn matches_route(&self, request: &Request<'_>) -> bool {
        if !request.method.as_str().eq_ignore_ascii_case(self.method) {
            return false;
        }
        let (path, query) = self
            .request_uri
            .split_once('?')
            .unwrap_or((self.request_uri, ""));
        let query_matches = query
            .split('&')
            .filter(|required| !required.is_empty())
            .all(|required| {
                let (key, value) = match required.split_once('=') {
                    Some((key, value)) => (key, Some(value)),
                    None => (required, None),
                };
                request
                    .query
                    .iter()
                    .any(|(k, v)| k == key && value.is_none_or(|value| v == value))
            });
        let path_matches = path_matches(path, &request.segments)
            || path
                .strip_prefix("/{Bucket}")
                .is_some_and(|rest| path_matches(rest, &request.segments));
        query_matches && path_matches
    }
}

struct Request<'a> {
    method: &'a Method,
    segments: Vec<String>,
    query: Vec<(String, String)>,
    names: &'a [String],
}

pub fn names(parts: &Parts, body: Option<&[u8]>) -> Vec<String> {
    let mut names = Vec::new();
    let query = parts.uri.query().unwrap_or_default().as_bytes();
    for source in [Some(query), body].into_iter().flatten() {
        names.extend(
            form_urlencoded::parse(source)
                .filter(|(key, _)| key.eq_ignore_ascii_case("action"))
                .map(|(_, value)| value.into_owned()),
        );
    }
    names.extend(
        parts
            .headers
            .get_all(X_AMZ_TARGET)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .map(|target| {
                let target = target.trim();
                target.rsplit('.').next().unwrap_or(target).to_string()
            }),
    );
    let segments = segments(parts.uri.path());
    if let [service, _, operation, op] = segments.as_slice()
        && service == "service"
        && operation == "operation"
    {
        names.push(op.clone());
    }
    names
}

pub fn label(names: &[String]) -> Option<&str> {
    names
        .iter()
        .find(|name| {
            !name.is_empty()
                && name.len() <= MAX_NAME_LEN
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        })
        .map(String::as_str)
}

pub fn credential_operation(
    scope_service: Option<&str>,
    host: &str,
    parts: &Parts,
    names: &[String],
) -> Option<&'static CredentialOperation> {
    let request = Request {
        method: &parts.method,
        segments: segments(parts.uri.path()),
        query: form_urlencoded::parse(parts.uri.query().unwrap_or_default().as_bytes())
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect(),
        names,
    };
    CREDENTIAL_OPERATIONS
        .iter()
        .find(|op| op.serves(scope_service, host) && op.matches(&request))
}

pub fn unsigned_operation_hosts() -> impl Iterator<Item = &'static str> {
    CREDENTIAL_OPERATIONS
        .iter()
        .filter(|op| op.auth == Auth::None)
        .map(|op| op.endpoint_prefix)
}

fn segments(path: &str) -> Vec<String> {
    let mut resolved: Vec<String> = Vec::new();
    for segment in path.split('/') {
        let segment = percent_decode_str(segment).decode_utf8_lossy().into_owned();
        match segment.as_str() {
            "" | "." => {}
            ".." => {
                resolved.pop();
            }
            _ => resolved.push(segment),
        }
    }
    resolved
}

fn path_matches(template: &str, segments: &[String]) -> bool {
    let mut rest = segments;
    for part in template.split('/').filter(|part| !part.is_empty()) {
        if part.starts_with('{') && part.ends_with("+}") {
            return !rest.is_empty();
        }
        let Some((segment, tail)) = rest.split_first() else {
            return false;
        };
        let is_label = part.starts_with('{') && part.ends_with('}');
        if !is_label && !segment.eq_ignore_ascii_case(part) {
            return false;
        }
        rest = tail;
    }
    rest.is_empty()
}
