use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use http::header::{self, HeaderValue};
use http::uri::{Authority, PathAndQuery};
use http::{Method, Request, Response, StatusCode, Uri, Version};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::upgrade::OnUpgrade;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio_rustls::LazyConfigAcceptor;

use credshim_core::{Destination, InjectError, Injector, Verdict};
use credshim_oauth::{Exchange, OAuth};

use crate::audit::{self, Outcome};
use crate::ca::CertificateAuthority;
use crate::proxy::{ProxyBody, status, strip_hop_by_hop};
use crate::scrub::{self, ScrubBody};
use crate::upstream::{ALPN_H2, ConnectError, TargetConnector, Upstream};

const HTTPS_PORT: u16 = 443;

#[derive(Clone)]
pub struct Intercept {
    ca: Arc<CertificateAuthority>,
    hosts: HashSet<String>,
}

impl std::fmt::Debug for Intercept {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Intercept")
            .field("hosts", &self.hosts)
            .finish_non_exhaustive()
    }
}

impl Intercept {
    pub fn new<I, S>(ca: Arc<CertificateAuthority>, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            ca,
            hosts: hosts
                .into_iter()
                .map(|host| host.as_ref().to_ascii_lowercase())
                .collect(),
        }
    }

    pub(crate) fn ca(&self) -> Arc<CertificateAuthority> {
        self.ca.clone()
    }

    pub(crate) fn covers(&self, host: &str) -> bool {
        self.hosts.contains(&host.to_ascii_lowercase())
    }
}

#[derive(Debug)]
pub struct VerifiedTarget {
    host: String,
    port: u16,
}

impl VerifiedTarget {
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == HTTPS_PORT {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    fn destination(&self) -> Destination<'_> {
        Destination {
            host: &self.host,
            port: self.port,
        }
    }

    fn matches(&self, authority: &Authority) -> bool {
        let host = authority.host();
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        host.eq_ignore_ascii_case(&self.host)
            && authority.port_u16().unwrap_or(HTTPS_PORT) == self.port
    }
}

#[derive(Debug, thiserror::Error)]
enum SendError {
    #[error("request URI could not be rebuilt for the upstream")]
    BadUri,
    #[error(transparent)]
    Client(#[from] hyper_util::client::legacy::Error),
}

fn full(body: bytes::Bytes) -> ProxyBody {
    Full::new(body).map_err(|never| match never {}).boxed()
}

#[derive(Debug, thiserror::Error)]
enum UpgradeError {
    #[error(transparent)]
    Connect(#[from] ConnectError),
    #[error("upstream HTTP/1.1 exchange failed: {0}")]
    Http(#[from] hyper::Error),
}

fn inject(
    target: &VerifiedTarget,
    injector: &Injector,
    parts: &mut http::request::Parts,
) -> Result<Verdict, InjectError> {
    injector.apply(target.destination(), parts)
}

#[derive(Clone)]
pub(crate) struct Services {
    pub(crate) injector: Arc<Injector>,
    pub(crate) oauth: Option<Arc<OAuth>>,
    pub(crate) scrub: bool,
}

pub(crate) struct Session {
    target: VerifiedTarget,
    injector: Arc<Injector>,
    oauth: Option<Arc<OAuth>>,
    scrub: bool,
    connector: TargetConnector,
    client: Client<TargetConnector, ProxyBody>,
}

impl Session {
    pub(crate) async fn open(
        upstream: Upstream,
        services: Services,
        host: String,
        port: u16,
        connect_timeout: Duration,
        idle_timeout: Duration,
    ) -> Result<Self, ConnectError> {
        let connector = TargetConnector::open(upstream, &host, port, connect_timeout).await?;
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(idle_timeout)
            .build(connector.clone());
        Ok(Self {
            target: VerifiedTarget { host, port },
            injector: services.injector,
            oauth: services.oauth,
            scrub: services.scrub,
            connector,
            client,
        })
    }

    pub(crate) fn serve(
        self,
        on_upgrade: OnUpgrade,
        ca: Arc<CertificateAuthority>,
        handshake_timeout: Duration,
    ) {
        tokio::spawn(async move {
            let host = self.target.host.clone();
            let port = self.target.port;
            match tokio::time::timeout(handshake_timeout, self.accept(on_upgrade, &ca)).await {
                Ok(Ok(())) => {}
                Ok(Err(reason)) => tracing::warn!(%host, port, %reason, "MITM session rejected"),
                Err(_) => tracing::warn!(%host, port, "downstream TLS handshake timed out"),
            }
        });
    }

    async fn accept(self, on_upgrade: OnUpgrade, ca: &CertificateAuthority) -> Result<(), String> {
        let upgraded = on_upgrade.await.map_err(|e| e.to_string())?;
        let start =
            LazyConfigAcceptor::new(rustls::server::Acceptor::default(), TokioIo::new(upgraded))
                .await
                .map_err(|e| format!("downstream TLS failed: {e}"))?;
        let sni_matches = start
            .client_hello()
            .server_name()
            .is_some_and(|sni| sni.eq_ignore_ascii_case(&self.target.host));
        if !sni_matches {
            return Err("TLS SNI does not match the CONNECT host".to_string());
        }
        let config = ca
            .server_config(&self.target.host)
            .map_err(|e| e.to_string())?;
        let tls = start
            .into_stream(config)
            .await
            .map_err(|e| format!("downstream TLS failed: {e}"))?;
        let h2 = tls.get_ref().1.alpn_protocol() == Some(ALPN_H2);
        tracing::debug!(
            host = %self.target.host,
            port = self.target.port,
            protocol = if h2 { "h2" } else { "http/1.1" },
            "MITM session established"
        );
        tokio::spawn(self.serve_connection(TokioIo::new(tls), h2));
        Ok(())
    }

    async fn serve_connection<S>(self, io: TokioIo<S>, h2: bool)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let session = Arc::new(self);
        let host = session.target.host.clone();
        let service = service_fn(move |req| {
            let session = session.clone();
            async move { Ok::<_, Infallible>(session.handle(req).await) }
        });
        let result = if h2 {
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .timer(TokioTimer::new())
                .serve_connection(io, service)
                .await
        } else {
            hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .serve_connection(io, service)
                .with_upgrades()
                .await
        };
        if let Err(err) = result {
            tracing::debug!(%host, error = %err, "MITM connection ended with error");
        }
    }

    async fn handle(&self, req: Request<Incoming>) -> Response<ProxyBody> {
        let (parts, body) = req.into_parts();
        let method = parts.method.clone();
        let path = parts.uri.path().to_string();
        let (outcome, response) = self.relay(parts, body).await;
        let entry = audit::Entry {
            scheme: "https",
            host: &self.target.host,
            port: self.target.port,
            method: &method,
            path: &path,
        };
        audit::record(&entry, &outcome, response.status());
        response
    }

    async fn relay(
        &self,
        mut parts: http::request::Parts,
        body: Incoming,
    ) -> (Outcome, Response<ProxyBody>) {
        let target = &self.target;
        if !self.addressed_to_target(&parts) {
            tracing::warn!(
                host = %target.host,
                port = target.port,
                method = %parts.method,
                "request inside CONNECT tunnel names a different host"
            );
            return (
                Outcome::Misdirected,
                status(StatusCode::MISDIRECTED_REQUEST),
            );
        }
        tracing::debug!(
            method = %parts.method,
            host = %target.host,
            port = target.port,
            path = parts.uri.path(),
            "intercepted request"
        );
        let exchange = self
            .oauth
            .as_deref()
            .and_then(|oauth| oauth.exchange(&target.host, target.port, &parts));
        let outcome = match inject(target, &self.injector, &mut parts) {
            Ok(Verdict::Pass) => Outcome::Pass,
            Ok(Verdict::Injected(rules)) => Outcome::Injected(rules),
            Ok(Verdict::Denied(rule)) => {
                tracing::warn!(
                    %rule,
                    host = %target.host,
                    port = target.port,
                    "dummy credential sent to a destination its rule is not bound to"
                );
                return (Outcome::Denied(rule), status(StatusCode::FORBIDDEN));
            }
            Err(err) => {
                tracing::error!(rule = %err.rule, "credential injection failed");
                return (
                    Outcome::Failed(err.rule),
                    status(StatusCode::INTERNAL_SERVER_ERROR),
                );
            }
        };
        if let Some(exchange) = exchange {
            return self.exchange(exchange, parts, body).await;
        }
        if self.scrub {
            parts.headers.insert(
                header::ACCEPT_ENCODING,
                HeaderValue::from_static("identity"),
            );
        }
        let method = parts.method.clone();
        let response = match websocket_upgrade(&parts) {
            Some(protocol) => self.upgrade(parts, body, protocol).await,
            None => self.forward(parts, body).await,
        };
        (outcome, self.scrubbed(&method, response))
    }

    fn scrubbed(&self, method: &Method, response: Response<ProxyBody>) -> Response<ProxyBody> {
        if !self.scrub {
            return response;
        }
        let scrubber = self.injector.scrubber();
        if scrubber.is_empty() {
            return response;
        }
        let (mut parts, body) = response.into_parts();
        let has_body = scrub::may_have_body(method, parts.status);
        if has_body && scrub::is_encoded(&parts.headers) {
            tracing::warn!(
                host = %self.target.host,
                port = self.target.port,
                "upstream sent an encoded response that cannot be scrubbed"
            );
            return status(StatusCode::BAD_GATEWAY);
        }
        if scrubber.scrub_headers(&mut parts.headers) > 0 {
            tracing::warn!(host = %self.target.host, "scrubbed secret values from response headers");
        }
        if !has_body {
            return Response::from_parts(parts, body);
        }
        parts.headers.remove(header::CONTENT_LENGTH);
        let body = ScrubBody::new(body, &scrubber, self.target.host.clone());
        Response::from_parts(parts, body.boxed())
    }

    fn scrubbed_full(
        &self,
        mut parts: http::response::Parts,
        body: bytes::Bytes,
    ) -> Response<ProxyBody> {
        if !self.scrub {
            return Response::from_parts(parts, full(body));
        }
        let scrubber = self.injector.scrubber();
        if scrub::is_encoded(&parts.headers) && !scrubber.is_empty() {
            tracing::warn!(
                host = %self.target.host,
                port = self.target.port,
                "upstream sent an encoded response that cannot be scrubbed"
            );
            return status(StatusCode::BAD_GATEWAY);
        }
        let mut replaced = scrubber.scrub_headers(&mut parts.headers);
        let body = match scrubber.scrub(&body) {
            Some(clean) => {
                replaced += 1;
                bytes::Bytes::from(clean)
            }
            None => body,
        };
        if replaced > 0 {
            tracing::warn!(host = %self.target.host, "scrubbed secret values from an OAuth endpoint response");
        }
        parts
            .headers
            .insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
        Response::from_parts(parts, full(body))
    }

    async fn forward(&self, parts: http::request::Parts, body: Incoming) -> Response<ProxyBody> {
        let target = &self.target;
        match self.send(parts, body.boxed()).await {
            Ok(res) => {
                let (mut parts, body) = res.into_parts();
                strip_hop_by_hop_keeping_trailers(&mut parts.headers);
                parts.version = Version::HTTP_11;
                Response::from_parts(parts, body.boxed())
            }
            Err(SendError::BadUri) => status(StatusCode::BAD_REQUEST),
            Err(err) => {
                tracing::warn!(host = %target.host, port = target.port, error = %err, "intercepted request failed");
                status(StatusCode::BAD_GATEWAY)
            }
        }
    }

    async fn send(
        &self,
        mut parts: http::request::Parts,
        body: ProxyBody,
    ) -> Result<Response<Incoming>, SendError> {
        strip_hop_by_hop_keeping_trailers(&mut parts.headers);
        parts.headers.remove(header::HOST);
        if parts.version == Version::HTTP_2 {
            join_cookies(&mut parts.headers);
        }
        parts.uri = absolute_uri(&self.target, &parts.uri).map_err(|_| SendError::BadUri)?;
        parts.version = Version::HTTP_11;
        Ok(self
            .client
            .request(Request::from_parts(parts, body))
            .await?)
    }

    async fn exchange(
        &self,
        exchange: Exchange<'_>,
        parts: http::request::Parts,
        body: Incoming,
    ) -> (Outcome, Response<ProxyBody>) {
        let rule = format!("oauth.{}", exchange.provider());
        let result = exchange
            .run(parts, body, |req| async move {
                let (parts, body) = req.into_parts();
                self.send(parts, full(body)).await
            })
            .await;
        match result {
            Ok(res) => {
                let (mut parts, body) = res.into_parts();
                strip_hop_by_hop(&mut parts.headers);
                parts.version = Version::HTTP_11;
                (Outcome::Exchanged(rule), self.scrubbed_full(parts, body))
            }
            Err(err) => {
                tracing::warn!(
                    %rule,
                    host = %self.target.host,
                    port = self.target.port,
                    error = %err,
                    "OAuth endpoint exchange failed"
                );
                let code = err.status();
                let outcome = if code == StatusCode::FORBIDDEN {
                    Outcome::Denied(rule)
                } else {
                    Outcome::Failed(rule)
                };
                (outcome, status(code))
            }
        }
    }

    async fn upgrade(
        &self,
        mut parts: http::request::Parts,
        body: Incoming,
        protocol: HeaderValue,
    ) -> Response<ProxyBody> {
        let target = &self.target;
        let downstream = parts.extensions.remove::<OnUpgrade>();
        strip_hop_by_hop(&mut parts.headers);
        parts
            .headers
            .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        parts.headers.insert(header::UPGRADE, protocol);
        let Ok(host) = HeaderValue::from_str(&target.authority()) else {
            return status(StatusCode::BAD_REQUEST);
        };
        parts.headers.insert(header::HOST, host);
        parts.uri = origin_form(&parts.uri);
        let req = Request::from_parts(parts, body.boxed());
        let mut res = match self.send_upgrade(req).await {
            Ok(res) => res,
            Err(err) => {
                tracing::warn!(host = %target.host, port = target.port, error = %err, "upgrade request failed");
                return status(StatusCode::BAD_GATEWAY);
            }
        };
        if res.status() != StatusCode::SWITCHING_PROTOCOLS {
            let (mut parts, body) = res.into_parts();
            strip_hop_by_hop(&mut parts.headers);
            return Response::from_parts(parts, body.boxed());
        }
        let Some(downstream) = downstream else {
            return status(StatusCode::BAD_GATEWAY);
        };
        let upstream = hyper::upgrade::on(&mut res);
        let host = target.host.clone();
        tokio::spawn(async move {
            match tokio::try_join!(downstream, upstream) {
                Ok((downstream, upstream)) => {
                    let mut downstream = TokioIo::new(downstream);
                    let mut upstream = TokioIo::new(upstream);
                    if let Err(err) =
                        tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await
                    {
                        tracing::debug!(%host, error = %err, "upgraded connection closed with error");
                    }
                }
                Err(err) => tracing::debug!(%host, error = %err, "connection upgrade failed"),
            }
        });
        let (parts, body) = res.into_parts();
        Response::from_parts(parts, body.boxed())
    }

    async fn send_upgrade(
        &self,
        req: Request<ProxyBody>,
    ) -> Result<Response<Incoming>, UpgradeError> {
        let tls = self.connector.connect_http1().await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
        let host = self.target.host.clone();
        tokio::spawn(async move {
            if let Err(err) = connection.with_upgrades().await {
                tracing::debug!(%host, error = %err, "upstream upgrade connection ended with error");
            }
        });
        Ok(sender.send_request(req).await?)
    }

    fn addressed_to_target(&self, parts: &http::request::Parts) -> bool {
        let uri_authority = parts.uri.authority();
        let uri_ok = uri_authority.is_none_or(|authority| self.target.matches(authority));
        let host_ok = match parts.headers.get(header::HOST) {
            Some(value) => value
                .to_str()
                .ok()
                .and_then(|value| value.parse::<Authority>().ok())
                .is_some_and(|authority| self.target.matches(&authority)),
            None => parts.version == Version::HTTP_2 && uri_authority.is_some(),
        };
        uri_ok && host_ok
    }
}

fn strip_hop_by_hop_keeping_trailers(headers: &mut http::HeaderMap) {
    let wants_trailers = headers
        .get(header::TE)
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"trailers"));
    let declared: Vec<HeaderValue> = headers.get_all(header::TRAILER).iter().cloned().collect();
    strip_hop_by_hop(headers);
    if wants_trailers {
        headers.insert(header::TE, HeaderValue::from_static("trailers"));
    }
    for value in declared {
        headers.append(header::TRAILER, value);
    }
}

fn websocket_upgrade(parts: &http::request::Parts) -> Option<HeaderValue> {
    if parts.version != Version::HTTP_11 {
        return None;
    }
    let connection_upgrade = parts
        .headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
    let protocol = parts.headers.get(header::UPGRADE)?;
    let websocket = protocol.as_bytes().eq_ignore_ascii_case(b"websocket");
    (connection_upgrade && websocket).then(|| protocol.clone())
}

fn join_cookies(headers: &mut http::HeaderMap) {
    let cookies: Vec<&HeaderValue> = headers.get_all(header::COOKIE).iter().collect();
    if cookies.len() < 2 {
        return;
    }
    let sensitive = cookies.iter().any(|value| value.is_sensitive());
    let joined = cookies
        .iter()
        .map(|value| value.as_bytes())
        .collect::<Vec<_>>()
        .join(&b"; "[..]);
    if let Ok(mut value) = HeaderValue::from_bytes(&joined) {
        value.set_sensitive(sensitive);
        headers.insert(header::COOKIE, value);
    }
}

fn absolute_uri(target: &VerifiedTarget, uri: &Uri) -> Result<Uri, http::Error> {
    let path = uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));
    Uri::builder()
        .scheme("https")
        .authority(target.authority())
        .path_and_query(path)
        .build()
}

fn origin_form(uri: &Uri) -> Uri {
    let path = uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));
    Uri::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joined_cookie_stays_sensitive_when_any_crumb_was() {
        let mut headers = http::HeaderMap::new();
        let mut secret = HeaderValue::from_static("token=abc");
        secret.set_sensitive(true);
        headers.append(header::COOKIE, HeaderValue::from_static("a=1"));
        headers.append(header::COOKIE, secret);

        join_cookies(&mut headers);

        let joined = headers.get(header::COOKIE).unwrap();
        assert_eq!(joined, "a=1; token=abc");
        assert!(joined.is_sensitive());
        assert_eq!(headers.get_all(header::COOKIE).iter().count(), 1);
    }
}
