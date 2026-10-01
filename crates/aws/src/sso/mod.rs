mod api;
mod login;
mod provider;
mod stored;

use std::collections::HashSet;

use credshim_core::rule::is_identifier;
use serde::Deserialize;

pub use api::{BoxFuture, RoleCredentials, Transport, TransportError};
pub use login::{LoginError, LogoutError, LogoutOutcome, Prompt, login, logout};
pub use provider::{CredentialError, SsoOptions, SsoProvider};
pub use stored::StoredError;

pub const SECRET_PREFIX: &str = "credshim-aws-sso-";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsoSessionSpec {
    pub name: String,
    pub start_url: String,
    pub region: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsoSession {
    name: String,
    start_url: String,
    region: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SsoSessionError {
    #[error(
        "aws_sso_session name {0:?} must be non-empty and use only letters, digits, '.', '_' or '-'"
    )]
    InvalidName(String),
    #[error("aws_sso_session {0:?} is defined more than once")]
    DuplicateName(String),
    #[error("aws_sso_session {0:?}: start_url must be an https:// URL")]
    InvalidStartUrl(String),
    #[error("aws_sso_session {0:?}: region must be a lowercase region name such as us-east-1")]
    InvalidRegion(String),
}

impl SsoSession {
    pub fn from_specs(specs: &[SsoSessionSpec]) -> Result<Vec<Self>, SsoSessionError> {
        let mut names = HashSet::new();
        specs
            .iter()
            .map(|spec| {
                let session = Self::from_spec(spec)?;
                if !names.insert(session.name.clone()) {
                    return Err(SsoSessionError::DuplicateName(session.name));
                }
                Ok(session)
            })
            .collect()
    }

    fn from_spec(spec: &SsoSessionSpec) -> Result<Self, SsoSessionError> {
        let name = spec.name.clone();
        if !is_identifier(&name) {
            return Err(SsoSessionError::InvalidName(name));
        }
        let https = spec
            .start_url
            .parse::<http::Uri>()
            .is_ok_and(|uri| uri.scheme_str() == Some("https") && uri.host().is_some());
        if !https {
            return Err(SsoSessionError::InvalidStartUrl(name));
        }
        let region_valid = !spec.region.is_empty()
            && spec
                .region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !region_valid {
            return Err(SsoSessionError::InvalidRegion(name));
        }
        Ok(Self {
            name,
            start_url: spec.start_url.clone(),
            region: spec.region.clone(),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn start_url(&self) -> &str {
        &self.start_url
    }

    pub fn region(&self) -> &str {
        &self.region
    }

    pub fn secret_name(&self) -> String {
        format!("{SECRET_PREFIX}{}", self.name)
    }

    pub fn oidc_host(&self) -> String {
        format!("oidc.{}.amazonaws.com", self.region)
    }

    pub fn portal_host(&self) -> String {
        format!("portal.sso.{}.amazonaws.com", self.region)
    }
}
