use std::time::SystemTime;

use http::HeaderMap;
use http::header::AUTHORIZATION;
use time::PrimitiveDateTime;
use time::macros::format_description;

pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";
pub const X_AMZ_DATE: &str = "x-amz-date";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    pub date: String,
    pub region: String,
    pub service: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigV4Auth {
    pub access_key_id: String,
    pub scope: Scope,
    pub signed_headers: Vec<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("request carries more than one Authorization header")]
    Repeated,
    #[error("Authorization header is not AWS4-HMAC-SHA256")]
    NotSigV4,
    #[error("Authorization header is malformed")]
    Malformed,
    #[error("X-Amz-Date is missing or malformed")]
    BadDate,
    #[error("X-Amz-Date does not fall on the credential scope's date")]
    DateMismatch,
}

impl SigV4Auth {
    pub fn from_headers(headers: &HeaderMap) -> Result<Option<Self>, AuthError> {
        let mut values = headers.get_all(AUTHORIZATION).iter();
        let Some(value) = values.next() else {
            return Ok(None);
        };
        if values.next().is_some() {
            return Err(AuthError::Repeated);
        }
        let value = value.to_str().map_err(|_| AuthError::Malformed)?;
        let Some(rest) = value.strip_prefix(ALGORITHM) else {
            return Err(AuthError::NotSigV4);
        };
        if !rest.starts_with(' ') {
            return Err(AuthError::NotSigV4);
        }
        Self::parse_fields(rest).map(Some)
    }

    fn parse_fields(fields: &str) -> Result<Self, AuthError> {
        let mut credential = None;
        let mut signed_headers = None;
        let mut signature = None;
        for field in fields.split(',') {
            let (name, value) = field.trim().split_once('=').ok_or(AuthError::Malformed)?;
            let slot = match name {
                "Credential" => &mut credential,
                "SignedHeaders" => &mut signed_headers,
                "Signature" => &mut signature,
                _ => return Err(AuthError::Malformed),
            };
            if slot.replace(value).is_some() {
                return Err(AuthError::Malformed);
            }
        }
        let (credential, signed_headers) = match (credential, signed_headers, signature) {
            (Some(credential), Some(signed_headers), Some(_)) => (credential, signed_headers),
            _ => return Err(AuthError::Malformed),
        };
        let mut parts = credential.split('/');
        let (
            Some(access_key_id),
            Some(date),
            Some(region),
            Some(service),
            Some("aws4_request"),
            None,
        ) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        )
        else {
            return Err(AuthError::Malformed);
        };
        let is_date = date.len() == 8 && date.bytes().all(|b| b.is_ascii_digit());
        if access_key_id.is_empty() || !is_date || !is_label(region) || !is_label(service) {
            return Err(AuthError::Malformed);
        }
        let signed_headers: Vec<String> = signed_headers.split(';').map(str::to_string).collect();
        let well_formed = signed_headers.iter().all(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        });
        if !well_formed {
            return Err(AuthError::Malformed);
        }
        Ok(Self {
            access_key_id: access_key_id.to_string(),
            scope: Scope {
                date: date.to_string(),
                region: region.to_string(),
                service: service.to_string(),
            },
            signed_headers,
        })
    }

    pub fn signing_time(&self, headers: &HeaderMap) -> Result<SystemTime, AuthError> {
        let mut values = headers.get_all(X_AMZ_DATE).iter();
        let (Some(value), None) = (values.next(), values.next()) else {
            return Err(AuthError::BadDate);
        };
        let value = value.to_str().map_err(|_| AuthError::BadDate)?;
        let parsed = PrimitiveDateTime::parse(
            value,
            format_description!("[year][month][day]T[hour][minute][second]Z"),
        )
        .map_err(|_| AuthError::BadDate)?;
        if !value.starts_with(&self.scope.date) {
            return Err(AuthError::DateMismatch);
        }
        Ok(parsed.assume_utc().into())
    }
}

fn is_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
