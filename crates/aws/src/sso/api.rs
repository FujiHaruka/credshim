use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use super::SsoSession;
use crate::rule::SsoRole;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Transport: Send + Sync {
    fn send(
        &self,
        request: Request<Bytes>,
    ) -> BoxFuture<'_, Result<Response<Bytes>, TransportError>>;
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TransportError(pub String);

const BEARER_HEADER: &str = "x-amz-sso_bearer_token";
const CLIENT_NAME: &str = "credshim";
const SCOPE: &str = "sso:account:access";
const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const REFRESH_TOKEN_GRANT: &str = "refresh_token";

#[derive(Clone)]
pub(crate) struct Client {
    pub id: String,
    pub secret: SecretString,
    pub expires_at: SystemTime,
}

pub(crate) struct Token {
    pub access_token: SecretString,
    pub expires_at: SystemTime,
    pub refresh_token: Option<SecretString>,
}

pub(crate) struct DeviceAuthorization {
    pub device_code: SecretString,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: Duration,
    pub interval: Duration,
}

pub struct RoleCredentials {
    pub access_key_id: SecretString,
    pub secret_access_key: SecretString,
    pub session_token: SecretString,
    pub expiration: SystemTime,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ApiError {
    #[error("{0}")]
    Transport(#[from] TransportError),
    #[error("IAM Identity Center answered {status} ({code})")]
    Service { status: StatusCode, code: String },
    #[error("IAM Identity Center sent a response credshim could not read")]
    Malformed,
}

impl ApiError {
    pub fn code(&self) -> Option<&str> {
        match self {
            ApiError::Service { code, .. } => Some(code),
            _ => None,
        }
    }

    pub fn status(&self) -> Option<StatusCode> {
        match self {
            ApiError::Service { status, .. } => Some(*status),
            _ => None,
        }
    }
}

pub(crate) struct Api<'a> {
    pub transport: &'a dyn Transport,
    pub session: &'a SsoSession,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterClientResponse {
    client_id: String,
    client_secret: SecretString,
    client_secret_expires_at: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartDeviceAuthorizationResponse {
    device_code: SecretString,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateTokenResponse {
    access_token: SecretString,
    expires_in: u64,
    refresh_token: Option<SecretString>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetRoleCredentialsResponse {
    role_credentials: RoleCredentialsBody,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoleCredentialsBody {
    access_key_id: SecretString,
    secret_access_key: SecretString,
    session_token: SecretString,
    expiration: u64,
}

#[derive(Deserialize)]
struct OidcError {
    error: Option<String>,
}

impl Api<'_> {
    pub async fn register_client(&self) -> Result<Client, ApiError> {
        let body = serde_json::json!({
            "clientName": CLIENT_NAME,
            "clientType": "public",
            "scopes": [SCOPE],
            "grantTypes": [DEVICE_CODE_GRANT, REFRESH_TOKEN_GRANT],
        });
        let response: RegisterClientResponse = self.oidc("/client/register", &body).await?;
        Ok(Client {
            id: response.client_id,
            secret: response.client_secret,
            expires_at: SystemTime::UNIX_EPOCH
                + Duration::from_secs(response.client_secret_expires_at),
        })
    }

    pub async fn start_device_authorization(
        &self,
        client: &Client,
    ) -> Result<DeviceAuthorization, ApiError> {
        let body = serde_json::json!({
            "clientId": client.id,
            "clientSecret": client.secret.expose_secret(),
            "startUrl": self.session.start_url(),
        });
        let response: StartDeviceAuthorizationResponse =
            self.oidc("/device_authorization", &body).await?;
        Ok(DeviceAuthorization {
            device_code: response.device_code,
            user_code: response.user_code,
            verification_uri: response.verification_uri,
            verification_uri_complete: response.verification_uri_complete,
            expires_in: Duration::from_secs(response.expires_in),
            interval: Duration::from_secs(response.interval.unwrap_or(5)),
        })
    }

    pub async fn create_token_from_device(
        &self,
        client: &Client,
        device_code: &SecretString,
    ) -> Result<Token, ApiError> {
        let body = serde_json::json!({
            "clientId": client.id,
            "clientSecret": client.secret.expose_secret(),
            "grantType": DEVICE_CODE_GRANT,
            "deviceCode": device_code.expose_secret(),
        });
        self.create_token(&body).await
    }

    pub async fn refresh(
        &self,
        client: &Client,
        refresh_token: &SecretString,
    ) -> Result<Token, ApiError> {
        let body = serde_json::json!({
            "clientId": client.id,
            "clientSecret": client.secret.expose_secret(),
            "grantType": REFRESH_TOKEN_GRANT,
            "refreshToken": refresh_token.expose_secret(),
        });
        self.create_token(&body).await
    }

    async fn create_token(&self, body: &serde_json::Value) -> Result<Token, ApiError> {
        let response: CreateTokenResponse = self.oidc("/token", body).await?;
        Ok(Token {
            access_token: response.access_token,
            expires_at: SystemTime::now() + Duration::from_secs(response.expires_in),
            refresh_token: response.refresh_token,
        })
    }

    pub async fn get_role_credentials(
        &self,
        access_token: &SecretString,
        role: &SsoRole,
    ) -> Result<RoleCredentials, ApiError> {
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("account_id", &role.account_id)
            .append_pair("role_name", &role.role_name)
            .finish();
        let request = self.portal_request(
            Method::GET,
            &format!("/federation/credentials?{query}"),
            access_token,
        )?;
        let response = self.transport.send(request).await?;
        let body: GetRoleCredentialsResponse = parse(response)?;
        let credentials = body.role_credentials;
        Ok(RoleCredentials {
            access_key_id: credentials.access_key_id,
            secret_access_key: credentials.secret_access_key,
            session_token: credentials.session_token,
            expiration: SystemTime::UNIX_EPOCH + Duration::from_millis(credentials.expiration),
        })
    }

    pub async fn logout(&self, access_token: &SecretString) -> Result<(), ApiError> {
        let request = self.portal_request(Method::POST, "/logout", access_token)?;
        let response = self.transport.send(request).await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(service_error(&response))
        }
    }

    fn portal_request(
        &self,
        method: Method,
        path: &str,
        access_token: &SecretString,
    ) -> Result<Request<Bytes>, ApiError> {
        let mut token = http::HeaderValue::from_str(access_token.expose_secret())
            .map_err(|_| ApiError::Malformed)?;
        token.set_sensitive(true);
        Request::builder()
            .method(method)
            .uri(format!("https://{}{path}", self.session.portal_host()))
            .header(header::HOST, self.session.portal_host())
            .header(BEARER_HEADER, token)
            .header(header::CONTENT_LENGTH, 0)
            .body(Bytes::new())
            .map_err(|_| ApiError::Malformed)
    }

    async fn oidc<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T, ApiError> {
        let host = self.session.oidc_host();
        let body =
            zeroize::Zeroizing::new(serde_json::to_vec(body).map_err(|_| ApiError::Malformed)?);
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("https://{host}{path}"))
            .header(header::HOST, host)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Bytes::copy_from_slice(&body))
            .map_err(|_| ApiError::Malformed)?;
        parse(self.transport.send(request).await?)
    }
}

fn parse<T: for<'de> Deserialize<'de>>(response: Response<Bytes>) -> Result<T, ApiError> {
    if !response.status().is_success() {
        return Err(service_error(&response));
    }
    serde_json::from_slice(response.body()).map_err(|_| ApiError::Malformed)
}

fn service_error(response: &Response<Bytes>) -> ApiError {
    let code = serde_json::from_slice::<OidcError>(response.body())
        .ok()
        .and_then(|error| error.error)
        .or_else(|| {
            response
                .headers()
                .get("x-amzn-errortype")
                .and_then(|value| value.to_str().ok())
                .map(|value| value.split(':').next().unwrap_or(value).to_string())
        })
        .filter(|code| {
            code.len() <= 64
                && code
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
        })
        .unwrap_or_else(|| "unknown".to_string());
    ApiError::Service {
        status: response.status(),
        code,
    }
}
