use http::HeaderName;
use http::request::Parts;

use crate::auth::{Scope, SigV4Auth};
use crate::hosts::{self, BlockedHost};
use crate::operation;
use crate::rule::{AwsRule, ScopeRefusal};

pub const X_AMZ_CONTENT_SHA256: HeaderName = HeaderName::from_static("x-amz-content-sha256");
pub const S3: &str = "s3";
const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
const STREAMING_UNSIGNED_PAYLOAD_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    Buffered,
    Precomputed(String),
    Unsigned,
    StreamingUnsignedTrailer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    BlockedHost(BlockedHost),
    NotBound,
    UnsupportedLocation,
    BadAuthorization,
    ServiceNotAllowed,
    RegionNotAllowed,
    CredentialOperation,
    UnsignedCredentialOperation,
    SignedChunks,
    BadPayloadHash,
    BodyTooLarge,
    EncodedBody,
    EndpointMismatch,
    BufferBusy,
    SsoLoginRequired,
    SsoRefused,
    SsoUnavailable,
}

impl Reason {
    pub fn name(self) -> &'static str {
        match self {
            Reason::BlockedHost(host) => host.name(),
            Reason::NotBound => "not_bound",
            Reason::UnsupportedLocation => "unsupported_location",
            Reason::BadAuthorization => "bad_authorization",
            Reason::ServiceNotAllowed => "service_not_allowed",
            Reason::RegionNotAllowed => "region_not_allowed",
            Reason::CredentialOperation => "credential_operation",
            Reason::UnsignedCredentialOperation => "unsigned_credential_operation",
            Reason::SignedChunks => "signed_chunks",
            Reason::BadPayloadHash => "bad_payload_hash",
            Reason::BodyTooLarge => "body_too_large",
            Reason::EncodedBody => "encoded_body",
            Reason::EndpointMismatch => "endpoint_mismatch",
            Reason::BufferBusy => "buffer_busy",
            Reason::SsoLoginRequired => "sso_login_required",
            Reason::SsoRefused => "sso_refused",
            Reason::SsoUnavailable => "sso_unavailable",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Labels {
    pub scope: Option<Scope>,
    pub operation: Option<String>,
}

#[derive(Debug)]
pub enum Decision<'r> {
    Pass(Labels),
    Resign(Resign<'r>),
    Deny(Denial<'r>),
}

#[derive(Debug)]
pub struct Resign<'r> {
    pub rule: &'r AwsRule,
    pub auth: SigV4Auth,
    pub payload: Payload,
    pub labels: Labels,
}

#[derive(Debug)]
pub struct Denial<'r> {
    pub rule: Option<&'r AwsRule>,
    pub reason: Reason,
    pub labels: Labels,
}

pub fn needs_body(rules: &[AwsRule], host: &str, parts: &Parts) -> bool {
    if !hosts::is_aws_host(host) {
        return false;
    }
    if operation::unsigned_operation_hosts().any(|prefix| hosts::has_prefix(host, prefix)) {
        return true;
    }
    rules
        .iter()
        .any(|rule| credshim_core::appears_in(rule.dummy(), parts))
        && !matches!(
            SigV4Auth::from_headers(&parts.headers),
            Ok(Some(auth)) if auth.scope.service == S3
        )
}

pub fn decide<'r>(
    rules: &'r [AwsRule],
    host: &str,
    parts: &Parts,
    body: Option<&[u8]>,
) -> Decision<'r> {
    let deny = |rule, reason, labels| {
        Decision::Deny(Denial {
            rule,
            reason,
            labels,
        })
    };
    if let Some(blocked) = hosts::blocked(host) {
        return deny(None, Reason::BlockedHost(blocked), Labels::default());
    }
    let rule = rules
        .iter()
        .find(|rule| credshim_core::appears_in(rule.dummy(), parts));
    if !hosts::is_aws_host(host) {
        return match rule {
            Some(rule) => deny(Some(rule), Reason::NotBound, Labels::default()),
            None => Decision::Pass(Labels::default()),
        };
    }
    let auth = SigV4Auth::from_headers(&parts.headers);
    let encoded = parts
        .headers
        .get_all(http::header::CONTENT_ENCODING)
        .iter()
        .any(|value| !value.as_bytes().eq_ignore_ascii_case(b"identity"));
    if body.is_some() && encoded {
        return deny(rule, Reason::EncodedBody, Labels::default());
    }
    let names = operation::names(parts, body);
    let labels = Labels {
        scope: auth
            .as_ref()
            .ok()
            .and_then(Option::as_ref)
            .map(|auth| auth.scope.clone()),
        operation: operation::label(&names).map(str::to_string),
    };
    let scope_service = labels.scope.as_ref().map(|scope| scope.service.as_str());
    if let Some(op) = operation::credential_operation(scope_service, host, parts, &names) {
        let labels = Labels {
            operation: Some(op.name.to_string()),
            ..labels.clone()
        };
        if op.auth == operation::Auth::None {
            return deny(rule, Reason::UnsignedCredentialOperation, labels);
        }
        if let Some(rule) = rule {
            return deny(Some(rule), Reason::CredentialOperation, labels);
        }
    }
    let Some(rule) = rule else {
        return Decision::Pass(labels);
    };
    let auth = match auth {
        Ok(Some(auth)) if auth.access_key_id == rule.dummy() => auth,
        Ok(_) => return deny(Some(rule), Reason::UnsupportedLocation, labels),
        Err(_) => return deny(Some(rule), Reason::BadAuthorization, labels),
    };
    match rule.refuses(&auth.scope) {
        Some(ScopeRefusal::Service) => return deny(Some(rule), Reason::ServiceNotAllowed, labels),
        Some(ScopeRefusal::Region) => return deny(Some(rule), Reason::RegionNotAllowed, labels),
        None => {}
    }
    if !hosts::is_endpoint_of(host, &auth.scope.service, &auth.scope.region) {
        return deny(Some(rule), Reason::EndpointMismatch, labels);
    }
    let payload = if auth.scope.service == S3 {
        match s3_payload(parts) {
            Ok(payload) => payload,
            Err(reason) => return deny(Some(rule), reason, labels),
        }
    } else {
        Payload::Buffered
    };
    Decision::Resign(Resign {
        rule,
        auth,
        payload,
        labels,
    })
}

fn s3_payload(parts: &Parts) -> Result<Payload, Reason> {
    let mut values = parts.headers.get_all(X_AMZ_CONTENT_SHA256).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err(Reason::BadPayloadHash);
    };
    let value = value.to_str().map_err(|_| Reason::BadPayloadHash)?;
    match value {
        UNSIGNED_PAYLOAD => Ok(Payload::Unsigned),
        STREAMING_UNSIGNED_PAYLOAD_TRAILER => Ok(Payload::StreamingUnsignedTrailer),
        hash if hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
        {
            Ok(Payload::Precomputed(hash.to_string()))
        }
        other if other.starts_with("STREAMING-") => Err(Reason::SignedChunks),
        _ => Err(Reason::BadPayloadHash),
    }
}
