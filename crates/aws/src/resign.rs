use std::collections::HashMap;
use std::fmt;

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{
    PercentEncodingMode, SignableBody, SignableRequest, SigningSettings, UriPathNormalizationMode,
    sign,
};
use aws_sigv4::sign::v4;
use http::header::{AUTHORIZATION, HeaderName, HeaderValue};
use http::request::Parts;
use secrecy::{ExposeSecret, SecretString};
use tracing::subscriber::NoSubscriber;

use crate::auth::{AuthError, X_AMZ_DATE};
use crate::policy::{Payload, Resign, S3};

pub const X_AMZ_SECURITY_TOKEN: HeaderName = HeaderName::from_static("x-amz-security-token");
const SCRUBBED_SECRET: &str = "credshim-scrubbed-aws-secret-access-key";

pub struct AwsCredentials {
    access_key_id: SecretString,
    secret_access_key: SecretString,
    session_token: Option<SecretString>,
}

impl AwsCredentials {
    pub fn new(
        access_key_id: SecretString,
        secret_access_key: SecretString,
        session_token: Option<SecretString>,
    ) -> Self {
        Self {
            access_key_id,
            secret_access_key,
            session_token,
        }
    }
}

#[derive(Default)]
pub struct Signer {
    keys: HashMap<String, (String, AwsCredentials)>,
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.keys.keys()).finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ResignError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error("no credentials are loaded for aws_key {0:?}")]
    MissingCredentials(String),
    #[error("a signed header value is not visible ASCII")]
    HeaderValue,
    #[error("the request could not be re-signed")]
    Signing,
}

impl Signer {
    pub fn insert(&mut self, rule: &str, dummy: &str, credentials: AwsCredentials) {
        self.keys
            .insert(rule.to_string(), (dummy.to_string(), credentials));
    }

    pub fn scrub_pairs(&self) -> Vec<(SecretString, String)> {
        let mut pairs = Vec::new();
        for (dummy, credentials) in self.keys.values() {
            pairs.push((credentials.access_key_id.clone(), dummy.clone()));
            pairs.push((
                credentials.secret_access_key.clone(),
                SCRUBBED_SECRET.to_string(),
            ));
            if let Some(token) = &credentials.session_token {
                pairs.push((token.clone(), SCRUBBED_SECRET.to_string()));
            }
        }
        pairs
    }

    pub fn resign(
        &self,
        plan: &Resign<'_>,
        parts: &mut Parts,
        authority: &str,
        body: &[u8],
    ) -> Result<(), ResignError> {
        let (_, credentials) = self
            .keys
            .get(plan.rule.name())
            .ok_or_else(|| ResignError::MissingCredentials(plan.rule.name().to_string()))?;
        let time = plan.auth.signing_time(&parts.headers)?;
        let signed: Vec<(String, String)> = plan
            .auth
            .signed_headers
            .iter()
            .filter(|name| {
                !matches!(
                    name.as_str(),
                    "host" | X_AMZ_DATE | "authorization" | "x-amz-security-token"
                )
            })
            .flat_map(|name| {
                parts
                    .headers
                    .get_all(name.as_str())
                    .iter()
                    .map(move |value| (name, value))
            })
            .map(|(name, value)| {
                value
                    .to_str()
                    .map(|value| (name.clone(), value.to_string()))
                    .map_err(|_| ResignError::HeaderValue)
            })
            .collect::<Result<_, _>>()?;
        let path = parts
            .uri
            .path_and_query()
            .map_or("/", |path_and_query| path_and_query.as_str());
        let signable_body = match &plan.payload {
            Payload::Buffered => SignableBody::Bytes(body),
            Payload::Precomputed(hash) => SignableBody::Precomputed(hash.clone()),
            Payload::Unsigned => SignableBody::UnsignedPayload,
            Payload::StreamingUnsignedTrailer => SignableBody::StreamingUnsignedPayloadTrailer,
        };
        let request = SignableRequest::new(
            parts.method.as_str(),
            format!("https://{authority}{path}"),
            signed
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
            signable_body,
        )
        .map_err(|_| ResignError::Signing)?;
        let mut settings = SigningSettings::default();
        settings.excluded_headers = None;
        if plan.auth.scope.service == S3 {
            settings.percent_encoding_mode = PercentEncodingMode::Single;
            settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
        }
        let identity = Credentials::new(
            credentials.access_key_id.expose_secret(),
            credentials.secret_access_key.expose_secret(),
            credentials
                .session_token
                .as_ref()
                .map(|token| token.expose_secret().to_string()),
            None,
            "credshim",
        )
        .into();
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(&plan.auth.scope.region)
            .name(&plan.auth.scope.service)
            .time(time)
            .settings(settings)
            .build()
            .map_err(|_| ResignError::Signing)?
            .into();
        let signed =
            tracing::subscriber::with_default(NoSubscriber::default(), || sign(request, &params));
        let (instructions, _) = signed.map_err(|_| ResignError::Signing)?.into_parts();
        parts.headers.remove(AUTHORIZATION);
        parts.headers.remove(X_AMZ_SECURITY_TOKEN);
        let (headers, _) = instructions.into_parts();
        for header in headers {
            let mut value =
                HeaderValue::from_str(header.value()).map_err(|_| ResignError::Signing)?;
            value.set_sensitive(true);
            parts
                .headers
                .insert(HeaderName::from_static(header.name()), value);
        }
        Ok(())
    }
}
