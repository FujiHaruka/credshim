use std::fmt::Display;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderValue};
use http::request::Parts;
use http::{Request, Response, StatusCode};
use http_body::Body;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Map, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::OAuth;
use crate::provider::{ClientAuth, Provider};
use crate::vault::TokenKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointKind {
    Token,
    Revoke,
}

#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    #[error("token endpoint request body exceeds {0} bytes")]
    RequestTooLarge(usize),
    #[error("could not read the token endpoint request body")]
    RequestBody,
    #[error("token endpoint request body is neither form-encoded nor a JSON object")]
    MalformedRequest,
    #[error("request names a client_id that does not belong to this provider")]
    ClientMismatch,
    #[error("request carries a token issued for a different provider")]
    ForeignToken,
    #[error("upstream token endpoint request failed: {0}")]
    Upstream(String),
    #[error("token endpoint response exceeds {0} bytes")]
    ResponseTooLarge(usize),
    #[error("could not read the token endpoint response body")]
    ResponseBody,
    #[error("token endpoint response is not a form or JSON token response the proxy can rewrite")]
    Unreadable,
}

impl ExchangeError {
    pub fn status(&self) -> StatusCode {
        match self {
            ExchangeError::RequestTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            ExchangeError::RequestBody | ExchangeError::MalformedRequest => StatusCode::BAD_REQUEST,
            ExchangeError::ClientMismatch | ExchangeError::ForeignToken => StatusCode::FORBIDDEN,
            ExchangeError::Upstream(_)
            | ExchangeError::ResponseTooLarge(_)
            | ExchangeError::ResponseBody
            | ExchangeError::Unreadable => StatusCode::BAD_GATEWAY,
        }
    }
}

#[derive(Clone)]
pub(crate) struct Replay {
    at: Instant,
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Replay {
    pub(crate) fn is_fresh(&self, window: Duration) -> bool {
        self.at.elapsed() < window
    }

    fn response(&self) -> Response<Bytes> {
        let mut response = Response::new(self.body.clone());
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers.clone();
        response
    }
}

pub struct Exchange<'a> {
    oauth: &'a OAuth,
    provider: &'a Provider,
    kind: EndpointKind,
    basic_client_id: Option<String>,
    query_tokens: Vec<String>,
}

impl<'a> Exchange<'a> {
    pub(crate) fn new(
        oauth: &'a OAuth,
        provider: &'a Provider,
        kind: EndpointKind,
        parts: &Parts,
    ) -> Self {
        Self {
            oauth,
            provider,
            kind,
            basic_client_id: basic_client_id(&parts.headers),
            query_tokens: query_tokens(parts),
        }
    }

    pub fn provider(&self) -> &str {
        self.provider.name()
    }

    pub fn kind(&self) -> EndpointKind {
        self.kind
    }

    pub async fn run<B, F, Fut, RB, E>(
        self,
        parts: Parts,
        body: B,
        send: F,
    ) -> Result<Response<Bytes>, ExchangeError>
    where
        B: Body<Data = Bytes>,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        F: FnOnce(Request<Bytes>) -> Fut,
        Fut: Future<Output = Result<Response<RB>, E>>,
        RB: Body<Data = Bytes>,
        RB::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        E: Display,
    {
        let max = self.oauth.max_body;
        let raw = Limited::new(body, max)
            .collect()
            .await
            .map_err(|err| {
                if err.is::<LengthLimitError>() {
                    ExchangeError::RequestTooLarge(max)
                } else {
                    ExchangeError::RequestBody
                }
            })?
            .to_bytes();
        let doc = if raw.is_empty() {
            Document::empty()
        } else {
            Document::parse(parts.headers.get(header::CONTENT_TYPE), &raw)
                .ok_or(ExchangeError::MalformedRequest)?
        };
        self.check_client_id(&doc)?;
        let refresh_dummy = match self.kind {
            EndpointKind::Token if doc.get("grant_type") == Some("refresh_token") => {
                doc.get("refresh_token").map(str::to_string)
            }
            _ => None,
        };
        let Some(dummy) = refresh_dummy else {
            return self.exchange(parts, raw, doc, None, send).await;
        };
        let gate = self.oauth.gate(&dummy);
        let mut slot = gate.lock().await;
        if let Some(replay) = slot
            .as_ref()
            .filter(|replay| replay.is_fresh(self.oauth.replay_window))
        {
            tracing::debug!(
                provider = self.provider.name(),
                "replaying a concurrent refresh result"
            );
            return Ok(replay.response());
        }
        let response = self.exchange(parts, raw, doc, Some(dummy), send).await?;
        if !response.status().is_success() {
            return Ok(response);
        }
        *slot = Some(Replay {
            at: Instant::now(),
            status: response.status(),
            headers: response.headers().clone(),
            body: response.body().clone(),
        });
        Ok(response)
    }

    async fn exchange<F, Fut, RB, E>(
        &self,
        mut parts: Parts,
        raw: Bytes,
        mut doc: Document,
        refresh_dummy: Option<String>,
        send: F,
    ) -> Result<Response<Bytes>, ExchangeError>
    where
        F: FnOnce(Request<Bytes>) -> Fut,
        Fut: Future<Output = Result<Response<RB>, E>>,
        RB: Body<Data = Bytes>,
        RB::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        E: Display,
    {
        self.substitute_client_secret(&mut doc);
        let sent_refresh = match &refresh_dummy {
            Some(dummy) => {
                self.substitute(&mut doc, "refresh_token", dummy, Some(TokenKind::Refresh))?
            }
            None => None,
        };
        let mut revoked = Vec::new();
        if self.kind == EndpointKind::Revoke {
            revoked.clone_from(&self.query_tokens);
            if let Some(dummy) = doc.get("token").map(str::to_string)
                && self.substitute(&mut doc, "token", &dummy, None)?.is_some()
            {
                revoked.push(dummy);
            }
        }
        let body = if doc.touched {
            Bytes::from(doc.to_bytes().to_vec())
        } else {
            raw
        };
        parts.headers.remove(header::TRANSFER_ENCODING);
        parts.headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        parts
            .headers
            .insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
        let response = send(Request::from_parts(parts, body))
            .await
            .map_err(|err| ExchangeError::Upstream(err.to_string()))?;
        let (mut head, body) = response.into_parts();
        let max = self.oauth.max_body;
        let body = Limited::new(body, max)
            .collect()
            .await
            .map_err(|err| {
                if err.is::<LengthLimitError>() {
                    ExchangeError::ResponseTooLarge(max)
                } else {
                    ExchangeError::ResponseBody
                }
            })?
            .to_bytes();
        let body = if !head.status.is_success() {
            body
        } else {
            match self.kind {
                EndpointKind::Token => {
                    self.rewrite_tokens(&head.headers, &body, refresh_dummy.zip(sent_refresh))?
                }
                EndpointKind::Revoke => {
                    for dummy in &revoked {
                        self.oauth.vault.remove(dummy);
                    }
                    body
                }
            }
        };
        head.headers.remove(header::TRANSFER_ENCODING);
        head.headers
            .insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
        Ok(Response::from_parts(head, body))
    }

    fn check_client_id(&self, doc: &Document) -> Result<(), ExchangeError> {
        let Some(expected) = &self.provider.client_id else {
            return Ok(());
        };
        let presented = [doc.get("client_id"), self.basic_client_id.as_deref()];
        if presented.into_iter().flatten().any(|id| id != expected) {
            return Err(ExchangeError::ClientMismatch);
        }
        Ok(())
    }

    fn substitute_client_secret(&self, doc: &mut Document) {
        let Some(secret) = &self.provider.client_secret else {
            return;
        };
        if self.provider.client_auth == ClientAuth::ClientSecretPost
            && doc.get("client_secret") == Some(secret.dummy.as_str())
        {
            doc.set("client_secret", secret.real.expose_secret());
        }
    }

    fn substitute(
        &self,
        doc: &mut Document,
        field: &str,
        dummy: &str,
        kind: Option<TokenKind>,
    ) -> Result<Option<SecretString>, ExchangeError> {
        let Some(issued) = self.oauth.vault.get(dummy) else {
            return Ok(None);
        };
        if issued.provider != self.provider.name() {
            return Err(ExchangeError::ForeignToken);
        }
        if kind.is_some_and(|kind| kind != issued.kind) {
            return Ok(None);
        }
        doc.set(field, issued.real.expose_secret());
        Ok(Some(issued.real))
    }

    fn rewrite_tokens(
        &self,
        headers: &HeaderMap,
        body: &[u8],
        sent_refresh: Option<(String, SecretString)>,
    ) -> Result<Bytes, ExchangeError> {
        let identity = headers
            .get(header::CONTENT_ENCODING)
            .is_none_or(|value| value.as_bytes().eq_ignore_ascii_case(b"identity"));
        if !identity {
            return Err(ExchangeError::Unreadable);
        }
        let mut doc = Document::parse(headers.get(header::CONTENT_TYPE), body)
            .ok_or(ExchangeError::Unreadable)?;
        if !doc.has_access_token() {
            return if doc.get("error").is_some() && !doc.has_token() {
                Ok(Bytes::copy_from_slice(body))
            } else {
                Err(ExchangeError::Unreadable)
            };
        }
        let vault = &self.oauth.vault;
        let provider = self.provider.name();
        let (mut kept, mut rotated) = (false, false);
        doc.rewrite_tokens(&mut |kind, real, expires_in| {
            let real = SecretString::from(real);
            match (kind, &sent_refresh) {
                (TokenKind::Refresh, Some((dummy, sent)))
                    if sent.expose_secret() == real.expose_secret() =>
                {
                    kept = true;
                    dummy.clone()
                }
                (TokenKind::Refresh, _) => {
                    rotated = true;
                    vault.issue(provider, kind, &real, None)
                }
                (TokenKind::Access, _) => {
                    let expires_at = expires_in.and_then(|seconds| {
                        SystemTime::now().checked_add(Duration::from_secs(seconds))
                    });
                    vault.issue(provider, kind, &real, expires_at)
                }
            }
        });
        if let Some((old, _)) = &sent_refresh
            && rotated
            && !kept
        {
            vault.remove(old);
        }
        Ok(Bytes::from(doc.to_bytes().to_vec()))
    }
}

fn basic_client_id(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, credentials) = value.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = Zeroizing::new(STANDARD.decode(credentials.trim()).ok()?);
    let user = decoded.split(|b| *b == b':').next()?;
    let user: String = form_urlencoded::parse(&[b"x=", user].concat())
        .next()
        .map(|(_, value)| value.into_owned())?;
    Some(user)
}

fn query_tokens(parts: &Parts) -> Vec<String> {
    let query = parts.uri.query().unwrap_or_default();
    form_urlencoded::parse(query.as_bytes())
        .filter(|(name, _)| name == "token")
        .map(|(_, value)| value.into_owned())
        .collect()
}

const TOKEN_FIELDS: [(&str, TokenKind); 2] = [
    ("access_token", TokenKind::Access),
    ("refresh_token", TokenKind::Refresh),
];

type Swap<'a> = dyn FnMut(TokenKind, &str, Option<u64>) -> String + 'a;

fn has_json_token(value: &Value, fields: &[&str]) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            (fields.contains(&key.as_str()) && value.is_string()) || has_json_token(value, fields)
        }),
        Value::Array(items) => items.iter().any(|item| has_json_token(item, fields)),
        _ => false,
    }
}

fn rewrite_json(map: &mut Map<String, Value>, swap: &mut Swap<'_>) {
    let expires_in = map.get("expires_in").and_then(json_seconds);
    for (field, kind) in TOKEN_FIELDS {
        if let Some(Value::String(real)) = map.get_mut(field) {
            let dummy = swap(kind, real, expires_in);
            real.zeroize();
            *real = dummy;
        }
    }
    for value in map.values_mut() {
        rewrite_json_value(value, swap);
    }
}

fn rewrite_json_value(value: &mut Value, swap: &mut Swap<'_>) {
    match value {
        Value::Object(map) => rewrite_json(map, swap),
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| rewrite_json_value(item, swap)),
        _ => {}
    }
}

fn json_seconds(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .or_else(|| number.as_f64().filter(|n| *n >= 0.0).map(|n| n as u64)),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

enum Format {
    Form(Vec<(String, String)>),
    Json(Map<String, Value>),
}

struct Document {
    format: Format,
    touched: bool,
}

impl Document {
    fn empty() -> Self {
        Self {
            format: Format::Form(Vec::new()),
            touched: false,
        }
    }

    fn parse(content_type: Option<&HeaderValue>, body: &[u8]) -> Option<Self> {
        let media = content_type
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase()
            });
        let json = match media.as_deref() {
            Some("application/x-www-form-urlencoded") => false,
            Some(media) if media == "application/json" || media.ends_with("+json") => true,
            _ => body.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{'),
        };
        let format = if json {
            match serde_json::from_slice(body).ok()? {
                Value::Object(map) => Format::Json(map),
                _ => return None,
            }
        } else {
            let text = std::str::from_utf8(body).ok()?.trim_ascii();
            if !text.contains('=') || text.contains(char::is_whitespace) {
                return None;
            }
            Format::Form(
                form_urlencoded::parse(text.as_bytes())
                    .map(|(name, value)| (name.into_owned(), value.into_owned()))
                    .collect(),
            )
        };
        Some(Self {
            format,
            touched: false,
        })
    }

    fn get(&self, key: &str) -> Option<&str> {
        match &self.format {
            Format::Form(pairs) => pairs
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.as_str()),
            Format::Json(map) => map.get(key)?.as_str(),
        }
    }

    fn set(&mut self, key: &str, value: &str) {
        self.touched = true;
        match &mut self.format {
            Format::Form(pairs) => {
                for (name, old) in pairs.iter_mut() {
                    if name == key {
                        old.zeroize();
                        *old = value.to_string();
                    }
                }
            }
            Format::Json(map) => {
                if let Some(Value::String(old)) = map.get_mut(key) {
                    old.zeroize();
                }
                map.insert(key.to_string(), Value::String(value.to_string()));
            }
        }
    }

    fn has_access_token(&self) -> bool {
        self.has_any(&["access_token"])
    }

    fn has_token(&self) -> bool {
        self.has_any(&TOKEN_FIELDS.map(|(field, _)| field))
    }

    fn has_any(&self, fields: &[&str]) -> bool {
        match &self.format {
            Format::Form(pairs) => pairs
                .iter()
                .any(|(name, _)| fields.contains(&name.as_str())),
            Format::Json(map) => map.iter().any(|(key, value)| {
                (fields.contains(&key.as_str()) && value.is_string())
                    || has_json_token(value, fields)
            }),
        }
    }

    fn rewrite_tokens(&mut self, swap: &mut Swap<'_>) {
        self.touched = true;
        match &mut self.format {
            Format::Form(pairs) => {
                let expires_in = pairs
                    .iter()
                    .find(|(name, _)| name == "expires_in")
                    .and_then(|(_, value)| value.trim().parse().ok());
                for (name, value) in pairs.iter_mut() {
                    if let Some((_, kind)) = TOKEN_FIELDS.iter().find(|(field, _)| field == name) {
                        let dummy = swap(*kind, value, expires_in);
                        value.zeroize();
                        *value = dummy;
                    }
                }
            }
            Format::Json(map) => rewrite_json(map, swap),
        }
    }

    fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(match &self.format {
            Format::Form(pairs) => form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs)
                .finish()
                .into_bytes(),
            Format::Json(map) => serde_json::to_vec(map).unwrap_or_default(),
        })
    }
}

impl Drop for Document {
    fn drop(&mut self) {
        match &mut self.format {
            Format::Form(pairs) => {
                for (_, value) in pairs.iter_mut() {
                    value.zeroize();
                }
            }
            Format::Json(map) => map.values_mut().for_each(zeroize_value),
        }
    }
}

fn zeroize_value(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(zeroize_value),
        Value::Object(map) => map.values_mut().for_each(zeroize_value),
        _ => {}
    }
}

pub(crate) type Gate = Arc<tokio::sync::Mutex<Option<Replay>>>;
