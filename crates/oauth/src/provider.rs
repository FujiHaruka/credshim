use std::collections::HashSet;

use credshim_core::{Binding, BindingError, DEFAULT_PORT, Location, Rule, RuleError, SecretRef};
use http::Uri;
use http::header::AUTHORIZATION;
use percent_encoding::percent_decode_str;
use secrecy::SecretString;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSpec {
    pub name: String,
    pub token_endpoint: String,
    pub revoke_endpoint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<ClientSecretSpec>,
    #[serde(default)]
    pub client_auth: ClientAuth,
    #[serde(default)]
    pub resource_hosts: Vec<String>,
    #[serde(default)]
    pub id_token: IdToken,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSecretSpec {
    pub secret: String,
    pub dummy: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuth {
    #[default]
    ClientSecretPost,
    ClientSecretBasic,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdToken {
    #[default]
    Passthrough,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProviderError {
    #[error(
        "oauth provider name {0:?} must be non-empty and use only letters, digits, '.', '_' or '-'"
    )]
    InvalidName(String),
    #[error("oauth provider {0:?} is defined more than once")]
    DuplicateName(String),
    #[error(
        "oauth provider {provider:?}: {field} {url:?} must be an https URL with a path and no query"
    )]
    InvalidEndpoint {
        provider: String,
        field: &'static str,
        url: String,
    },
    #[error("oauth provider {provider:?}: {source}")]
    InvalidBinding {
        provider: String,
        source: BindingError,
    },
    #[error("oauth provider {provider:?}: the token and revoke endpoints must differ")]
    SameEndpoints { provider: String },
    #[error("oauth providers {0:?} and {1:?} share an endpoint")]
    SharedEndpoint(String, String),
    #[error("oauth provider {provider:?}: client_secret {secret:?} is not in the secret store")]
    MissingClientSecret { provider: String, secret: String },
    #[error(transparent)]
    Rule(#[from] RuleError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Endpoint {
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Endpoint {
    fn parse(provider: &str, field: &'static str, url: &str) -> Result<Self, ProviderError> {
        let invalid = || ProviderError::InvalidEndpoint {
            provider: provider.to_string(),
            field,
            url: url.to_string(),
        };
        let uri: Uri = url.parse().map_err(|_| invalid())?;
        if uri.scheme_str() != Some("https") || uri.query().is_some() || uri.path() == "/" {
            return Err(invalid());
        }
        let authority = uri.authority().ok_or_else(invalid)?;
        let endpoint = Self {
            host: authority.host().to_ascii_lowercase(),
            port: authority.port_u16().unwrap_or(DEFAULT_PORT),
            path: uri.path().to_string(),
        };
        endpoint.binding(provider, Vec::new())?;
        Ok(endpoint)
    }

    pub(crate) fn binding(
        &self,
        provider: &str,
        locations: Vec<Location>,
    ) -> Result<Binding, ProviderError> {
        Binding::new(&self.host, self.port, Some(self.path.clone()), locations).map_err(|source| {
            ProviderError::InvalidBinding {
                provider: provider.to_string(),
                source,
            }
        })
    }

    pub(crate) fn covers(&self, host: &str, port: u16, path: &str) -> bool {
        if !self.host.eq_ignore_ascii_case(host) || self.port != port {
            return false;
        }
        let path = percent_decode_str(path).decode_utf8_lossy().to_lowercase();
        let own = self.path.to_lowercase();
        path.strip_prefix(own.trim_end_matches('/'))
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(['/', '.', ';']))
    }
}

pub(crate) struct ClientSecret {
    pub dummy: String,
    pub real: SecretString,
}

pub struct Provider {
    pub(crate) name: String,
    pub(crate) token: Endpoint,
    pub(crate) revoke: Option<Endpoint>,
    pub(crate) client_id: Option<String>,
    pub(crate) client_secret: Option<ClientSecret>,
    pub(crate) client_auth: ClientAuth,
    pub(crate) access_bindings: Vec<Binding>,
    pub(crate) refresh_bindings: Vec<Binding>,
    resource_hosts: Vec<String>,
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provider")
            .field("name", &self.name)
            .field("token", &self.token)
            .field("revoke", &self.revoke)
            .field("resource_hosts", &self.resource_hosts)
            .finish_non_exhaustive()
    }
}

impl ProviderSpec {
    pub fn client_secret_name(&self) -> Option<&str> {
        self.client_secret.as_ref().map(|spec| spec.secret.as_str())
    }
}

impl Provider {
    pub fn new(
        spec: ProviderSpec,
        client_secret: Option<SecretString>,
    ) -> Result<Self, ProviderError> {
        let name = spec.name;
        let valid_name = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !valid_name {
            return Err(ProviderError::InvalidName(name));
        }
        let token = Endpoint::parse(&name, "token_endpoint", &spec.token_endpoint)?;
        let revoke = spec
            .revoke_endpoint
            .as_deref()
            .map(|url| Endpoint::parse(&name, "revoke_endpoint", url))
            .transpose()?;
        if revoke.as_ref() == Some(&token) {
            return Err(ProviderError::SameEndpoints { provider: name });
        }
        let client_secret = match (spec.client_secret, client_secret) {
            (Some(spec), Some(real)) => Some(ClientSecret {
                dummy: spec.dummy,
                real,
            }),
            (Some(spec), None) => {
                return Err(ProviderError::MissingClientSecret {
                    provider: name,
                    secret: spec.secret,
                });
            }
            (None, _) => None,
        };
        let revoke_binding = |locations| {
            revoke
                .as_ref()
                .map(|endpoint| endpoint.binding(&name, locations))
                .transpose()
        };
        let mut access_bindings = spec
            .resource_hosts
            .iter()
            .map(|host| {
                Binding::new(
                    host,
                    DEFAULT_PORT,
                    None,
                    vec![Location::Header(AUTHORIZATION)],
                )
                .map_err(|source| ProviderError::InvalidBinding {
                    provider: name.clone(),
                    source,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        access_bindings.extend(revoke_binding(vec![Location::Query("token".into())])?);
        let mut refresh_bindings = vec![token.binding(&name, Vec::new())?];
        refresh_bindings.extend(revoke_binding(vec![Location::Query("token".into())])?);
        Ok(Self {
            token,
            revoke,
            client_id: spec.client_id,
            client_secret,
            client_auth: spec.client_auth,
            access_bindings,
            refresh_bindings,
            resource_hosts: spec
                .resource_hosts
                .iter()
                .map(|host| host.to_ascii_lowercase())
                .collect(),
            name,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn endpoints(&self) -> impl Iterator<Item = &Endpoint> {
        std::iter::once(&self.token).chain(&self.revoke)
    }

    pub(crate) fn hosts(&self) -> impl Iterator<Item = &str> {
        self.endpoints()
            .map(|endpoint| endpoint.host.as_str())
            .chain(self.resource_hosts.iter().map(String::as_str))
    }

    pub(crate) fn client_secret_rule(&self) -> Result<Option<Rule>, ProviderError> {
        let Some(secret) = &self.client_secret else {
            return Ok(None);
        };
        let locations = match self.client_auth {
            ClientAuth::ClientSecretBasic => vec![Location::BasicAuth],
            ClientAuth::ClientSecretPost => Vec::new(),
        };
        let bindings = self
            .endpoints()
            .map(|endpoint| endpoint.binding(&self.name, locations.clone()))
            .collect::<Result<_, _>>()?;
        Ok(Some(Rule::new(
            format!("oauth.{}", self.name),
            secret.dummy.clone(),
            SecretRef::Inline(secret.real.clone()),
            bindings,
        )?))
    }
}

pub(crate) fn check_unique(providers: &[Provider]) -> Result<(), ProviderError> {
    let mut names = HashSet::new();
    for provider in providers {
        if !names.insert(provider.name.as_str()) {
            return Err(ProviderError::DuplicateName(provider.name.clone()));
        }
    }
    for (i, a) in providers.iter().enumerate() {
        for b in &providers[i + 1..] {
            if a.endpoints().any(|x| b.endpoints().any(|y| x == y)) {
                return Err(ProviderError::SharedEndpoint(
                    a.name.clone(),
                    b.name.clone(),
                ));
            }
        }
    }
    Ok(())
}
