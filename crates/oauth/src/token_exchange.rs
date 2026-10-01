use std::fmt::Display;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

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
    #[error("request path reaches an OAuth endpoint only after normalization")]
    DisguisedPath,
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
            ExchangeError::RequestBody
            | ExchangeError::MalformedRequest
            | ExchangeError::DisguisedPath => StatusCode::BAD_REQUEST,
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
    refresh_held: String,
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Replay {
    pub(crate) fn is_fresh(&self, window: Duration) -> bool {
        self.at.elapsed() < window
    }

    fn is_live(&self, oauth: &OAuth) -> bool {
        self.is_fresh(oauth.replay_window) && oauth.vault.get(&self.refresh_held).is_some()
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
    disguised: bool,
    basic_users: Vec<Zeroizing<String>>,
    query_client_ids: Vec<String>,
    query_tokens: Vec<String>,
}

impl<'a> Exchange<'a> {
    pub(crate) fn new(
        oauth: &'a OAuth,
        provider: &'a Provider,
        kind: EndpointKind,
        parts: &Parts,
        disguised: bool,
    ) -> Self {
        Self {
            oauth,
            provider,
            kind,
            disguised,
            basic_users: basic_users(&parts.headers),
            query_client_ids: query_values(parts, "client_id"),
            query_tokens: query_values(parts, "token"),
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
        if self.disguised {
            return Err(ExchangeError::DisguisedPath);
        }
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
            return Ok(self.exchange(parts, raw, doc, None, send).await?.0);
        };
        let issued_here = self.oauth.vault.get(&dummy).is_some_and(|issued| {
            issued.kind == TokenKind::Refresh && issued.provider == self.provider.name()
        });
        let Some(gate) = self.oauth.gate(self.provider.name(), &dummy, issued_here) else {
            return Ok(self.exchange(parts, raw, doc, Some(dummy), send).await?.0);
        };
        let mut slot = gate.lock().await;
        if let Some(replay) = slot.as_ref().filter(|replay| replay.is_live(self.oauth)) {
            tracing::debug!(
                provider = self.provider.name(),
                "replaying a concurrent refresh result"
            );
            return Ok(replay.response());
        }
        let (response, rotated_to) = self
            .exchange(parts, raw, doc, Some(dummy.clone()), send)
            .await?;
        if !response.status().is_success() {
            return Ok(response);
        }
        *slot = Some(Replay {
            at: Instant::now(),
            refresh_held: rotated_to.unwrap_or(dummy),
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
    ) -> Result<(Response<Bytes>, Option<String>), ExchangeError>
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
            revoked = self.own_query_tokens()?;
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
        let (body, rotated_to) = if !head.status.is_success() {
            (body, None)
        } else {
            match self.kind {
                EndpointKind::Token => {
                    self.rewrite_tokens(&head.headers, &body, refresh_dummy.zip(sent_refresh))?
                }
                EndpointKind::Revoke => {
                    for dummy in &revoked {
                        self.oauth.vault.remove(dummy);
                    }
                    (body, None)
                }
            }
        };
        head.headers.remove(header::TRANSFER_ENCODING);
        head.headers
            .insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
        Ok((Response::from_parts(head, body), rotated_to))
    }

    fn own_query_tokens(&self) -> Result<Vec<String>, ExchangeError> {
        let mut own = Vec::new();
        for dummy in &self.query_tokens {
            match self.oauth.vault.get(dummy) {
                Some(issued) if issued.provider != self.provider.name() => {
                    return Err(ExchangeError::ForeignToken);
                }
                Some(_) => own.push(dummy.clone()),
                None => {}
            }
        }
        Ok(own)
    }

    fn check_client_id(&self, doc: &Document) -> Result<(), ExchangeError> {
        let secret_dummy = self.provider.client_secret.as_ref().map(|s| &s.dummy);
        if secret_dummy
            .is_some_and(|dummy| self.basic_users.iter().any(|u| u.contains(dummy.as_str())))
        {
            return Err(ExchangeError::ClientMismatch);
        }
        let Some(expected) = &self.provider.client_id else {
            return Ok(());
        };
        let mut presented = doc
            .all("client_id")
            .into_iter()
            .chain(self.basic_users.iter().map(|user| Some(user.as_str())))
            .chain(self.query_client_ids.iter().map(|id| Some(id.as_str())));
        if presented.any(|id| id != Some(expected.as_str())) {
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
    ) -> Result<(Bytes, Option<String>), ExchangeError> {
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
                Ok((Bytes::copy_from_slice(body), None))
            } else {
                Err(ExchangeError::Unreadable)
            };
        }
        let vault = &self.oauth.vault;
        let provider = self.provider.name();
        let (mut kept, mut rotated) = (false, None);
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
                    let dummy = vault.issue(provider, kind, &real, None);
                    rotated = Some(dummy.clone());
                    dummy
                }
                (TokenKind::Access, _) => {
                    let expires_at = expires_in.and_then(|seconds| {
                        SystemTime::now().checked_add(Duration::from_secs(seconds))
                    });
                    vault.issue(provider, kind, &real, expires_at)
                }
            }
        });
        let rotated_to = match &sent_refresh {
            Some((old, _)) if rotated.is_some() && !kept => {
                vault.remove(old);
                rotated
            }
            _ => None,
        };
        Ok((Bytes::from(doc.to_bytes().to_vec()), rotated_to))
    }
}

fn basic_users(headers: &HeaderMap) -> Vec<Zeroizing<String>> {
    headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .filter_map(credshim_core::decode_basic)
        .map(|decoded| {
            let decoded = Zeroizing::new(decoded);
            let user = decoded.split(|b| *b == b':').next().unwrap_or_default();
            let encoded = Zeroizing::new([b"x=", user].concat());
            Zeroizing::new(
                form_urlencoded::parse(&encoded)
                    .next()
                    .map(|(_, value)| value.into_owned())
                    .unwrap_or_default(),
            )
        })
        .collect()
}

fn query_values(parts: &Parts, key: &str) -> Vec<String> {
    let query = parts.uri.query().unwrap_or_default();
    form_urlencoded::parse(query.as_bytes())
        .filter(|(name, _)| name == key)
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

struct UniqueKeys(Map<String, Value>);

impl<'de> serde::Deserialize<'de> for UniqueKeys {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueKeys;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object without repeated keys")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut access: A,
            ) -> Result<UniqueKeys, A::Error> {
                let mut map = Map::new();
                while let Some((key, value)) = access.next_entry::<String, Value>()? {
                    if let Some(mut earlier) = map.insert(key, value) {
                        zeroize_value(&mut earlier);
                        map.values_mut().for_each(zeroize_value);
                        return Err(serde::de::Error::custom("repeated key"));
                    }
                }
                Ok(UniqueKeys(map))
            }
        }

        deserializer.deserialize_map(Visitor)
    }
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
            Format::Json(serde_json::from_slice::<UniqueKeys>(body).ok()?.0)
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

    fn all(&self, key: &str) -> Vec<Option<&str>> {
        match &self.format {
            Format::Form(pairs) => pairs
                .iter()
                .filter(|(name, _)| name == key)
                .map(|(_, value)| Some(value.as_str()))
                .collect(),
            Format::Json(map) => map.get(key).map(Value::as_str).into_iter().collect(),
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
