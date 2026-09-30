use http::request::Parts;
use http::{HeaderName, Method};
use percent_encoding::percent_decode_str;

use crate::auth::Scope;
use crate::credential_operations::CREDENTIAL_OPERATIONS;
use crate::hosts;
use crate::rest_operations::REST_OPERATIONS;

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
        scope_service.map(signing_name) == Some(self.signing_name)
            || hosts::has_prefix(host, self.endpoint_prefix)
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
            .all(|required| request.has_query(required));
        let path_matches = path_matches(path, &request.segments)
            || path
                .strip_prefix("/{Bucket}")
                .is_some_and(|rest| path_matches(rest, &request.segments));
        query_matches && path_matches
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct RestOperation {
    pub signing_name: &'static str,
    pub endpoint_prefix: &'static str,
    pub name: &'static str,
    pub method: &'static str,
    pub path: &'static str,
    pub query: &'static [&'static str],
    pub headers: &'static [&'static str],
}

impl RestOperation {
    fn served_by(&self, host: &str, s3_host: Option<S3Host>) -> bool {
        if self.endpoint_prefix == S3_PREFIX {
            s3_host.is_some()
        } else {
            hosts::has_prefix(host, self.endpoint_prefix)
        }
    }

    fn matches(&self, request: &Request<'_>, s3_host: Option<S3Host>) -> bool {
        let path = if self.endpoint_prefix == S3_PREFIX && s3_host == Some(S3Host::BucketInHost) {
            match self.path.strip_prefix("/{Bucket}") {
                Some(rest) => rest,
                None => return false,
            }
        } else {
            self.path
        };
        request.method.as_str().eq_ignore_ascii_case(self.method)
            && self
                .query
                .iter()
                .all(|required| request.has_query(required))
            && self
                .headers
                .iter()
                .all(|name| request.headers.contains_key(*name))
            && path_matches(path, &request.segments)
    }

    fn specificity(&self) -> (usize, usize) {
        let literals = self
            .path
            .split('/')
            .filter(|part| !part.is_empty() && !part.starts_with('{'))
            .count();
        (self.query.len() + self.headers.len(), literals)
    }
}

const S3_PREFIX: &str = "s3";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum S3Host {
    BucketInHost,
    BucketInPath,
}

fn s3_host(host: &str, region: &str) -> Option<S3Host> {
    let host = host.to_ascii_lowercase();
    let rest = host.strip_suffix(&format!(".{}", hosts::AWS_DOMAIN))?;
    let legacy = format!("s3-{region}");
    let labels: Vec<&str> = rest.split('.').collect();
    let index = labels.iter().position(|label| {
        [
            "s3",
            "s3-fips",
            "s3-accesspoint",
            "s3-accesspoint-fips",
            "s3-external-1",
            legacy.as_str(),
        ]
        .contains(label)
    })?;
    Some(if index == 0 {
        S3Host::BucketInPath
    } else {
        S3Host::BucketInHost
    })
}

struct Request<'a> {
    method: &'a Method,
    headers: &'a http::HeaderMap,
    segments: Vec<String>,
    query: Vec<(String, String)>,
    names: &'a [String],
}

impl<'a> Request<'a> {
    fn new(parts: &'a Parts, names: &'a [String]) -> Self {
        Self {
            method: &parts.method,
            headers: &parts.headers,
            segments: segments(parts.uri.path()),
            query: form_urlencoded::parse(parts.uri.query().unwrap_or_default().as_bytes())
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect(),
            names,
        }
    }

    fn has_query(&self, required: &str) -> bool {
        let (key, value) = match required.split_once('=') {
            Some((key, value)) => (key, Some(value)),
            None => (required, None),
        };
        self.query
            .iter()
            .any(|(k, v)| k == key && value.is_none_or(|value| v == value))
    }
}

pub fn signing_name(scope_service: &str) -> &str {
    match scope_service {
        "s3express" => "s3",
        other => other,
    }
}

pub fn identify(scope: &Scope, host: &str, parts: &Parts, names: &[String]) -> Vec<String> {
    let service = signing_name(&scope.service);
    let request = Request::new(parts, names);
    let s3_host = s3_host(host, &scope.region);
    let start = REST_OPERATIONS.partition_point(|op| op.signing_name < service);
    let matched: Vec<&RestOperation> = REST_OPERATIONS[start..]
        .iter()
        .take_while(|op| op.signing_name == service)
        .filter(|op| op.served_by(host, s3_host) && op.matches(&request, s3_host))
        .collect();
    let best = matched.iter().map(|op| op.specificity()).max();
    let mut found: Vec<String> = Vec::new();
    let most_specific = matched
        .iter()
        .filter(|op| Some(op.specificity()) == best)
        .map(|op| op.name.to_string());
    for name in names.iter().cloned().chain(most_specific) {
        if !found.iter().any(|seen| seen.eq_ignore_ascii_case(&name)) {
            found.push(name);
        }
    }
    found
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
    let request = Request::new(parts, names);
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
