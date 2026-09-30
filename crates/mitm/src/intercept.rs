use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use http::header::{self, HeaderValue};
use http::uri::{Authority, PathAndQuery};
use http::{Request, Response, StatusCode, Uri};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::service::service_fn;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::sync::Mutex;
use tokio_rustls::LazyConfigAcceptor;

use crate::ca::CertificateAuthority;
use crate::proxy::{ProxyBody, status, strip_hop_by_hop};
use crate::upstream::{ConnectError, Upstream};

const HTTPS_PORT: u16 = 443;
const ALPN_HTTP1: &[u8] = b"http/1.1";

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

    fn host_header(&self) -> String {
        if self.port == HTTPS_PORT {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    fn matches(&self, authority: &Authority) -> bool {
        authority.host().eq_ignore_ascii_case(&self.host)
            && authority.port_u16().unwrap_or(HTTPS_PORT) == self.port
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SessionError {
    #[error("timed out connecting to upstream")]
    Timeout,
    #[error(transparent)]
    Connect(#[from] ConnectError),
    #[error("upstream HTTP handshake failed: {0}")]
    Handshake(#[from] hyper::Error),
}

pub(crate) struct Session {
    target: VerifiedTarget,
    upstream: Upstream,
    connect_timeout: Duration,
    sender: Mutex<SendRequest<ProxyBody>>,
}

impl Session {
    pub(crate) async fn open(
        upstream: Upstream,
        host: String,
        port: u16,
        connect_timeout: Duration,
    ) -> Result<Self, SessionError> {
        let sender = connect(&upstream, &host, port, connect_timeout).await?;
        Ok(Self {
            target: VerifiedTarget { host, port },
            upstream,
            connect_timeout,
            sender: Mutex::new(sender),
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
        tokio::spawn(self.serve_http1(TokioIo::new(tls)));
        Ok(())
    }

    async fn serve_http1<S>(self, io: TokioIo<S>)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let session = Arc::new(self);
        let host = session.target.host.clone();
        let service = service_fn(move |req| {
            let session = session.clone();
            async move { Ok::<_, Infallible>(session.handle(req).await) }
        });
        if let Err(err) = hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .serve_connection(io, service)
            .await
        {
            tracing::debug!(%host, error = %err, "MITM connection ended with error");
        }
    }

    async fn handle(&self, req: Request<Incoming>) -> Response<ProxyBody> {
        let (mut parts, body) = req.into_parts();
        let target = &self.target;
        if !self.addressed_to_target(&parts.uri, &parts.headers) {
            tracing::warn!(
                host = %target.host,
                port = target.port,
                method = %parts.method,
                "request inside CONNECT tunnel names a different host"
            );
            return status(StatusCode::MISDIRECTED_REQUEST);
        }
        tracing::debug!(
            method = %parts.method,
            host = %target.host,
            port = target.port,
            path = parts.uri.path(),
            "intercepted request"
        );
        strip_hop_by_hop(&mut parts.headers);
        let Ok(host_header) = HeaderValue::from_str(&target.host_header()) else {
            return status(StatusCode::BAD_REQUEST);
        };
        parts.headers.insert(header::HOST, host_header);
        parts.uri = origin_form(&parts.uri);
        parts.version = http::Version::HTTP_11;
        let req = Request::from_parts(parts, body.boxed());

        match self.send(req).await {
            Ok(res) => {
                let (mut parts, body) = res.into_parts();
                strip_hop_by_hop(&mut parts.headers);
                Response::from_parts(parts, body.boxed())
            }
            Err(err) => {
                tracing::warn!(host = %target.host, port = target.port, error = %err, "intercepted request failed");
                status(StatusCode::BAD_GATEWAY)
            }
        }
    }

    fn addressed_to_target(&self, uri: &Uri, headers: &http::HeaderMap) -> bool {
        let uri_ok = uri
            .authority()
            .is_none_or(|authority| self.target.matches(authority));
        let host_ok = headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<Authority>().ok())
            .is_some_and(|authority| self.target.matches(&authority));
        uri_ok && host_ok
    }

    async fn send(&self, req: Request<ProxyBody>) -> Result<Response<Incoming>, SessionError> {
        let mut sender = self.sender.lock().await;
        if sender.ready().await.is_err() {
            *sender = connect(
                &self.upstream,
                &self.target.host,
                self.target.port,
                self.connect_timeout,
            )
            .await?;
        }
        Ok(sender.send_request(req).await?)
    }
}

async fn connect(
    upstream: &Upstream,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<SendRequest<ProxyBody>, SessionError> {
    let tls = tokio::time::timeout(timeout, upstream.connect_tls(host, port, &[ALPN_HTTP1]))
        .await
        .map_err(|_| SessionError::Timeout)??;
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    let host = host.to_string();
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            tracing::debug!(%host, port, error = %err, "upstream connection ended with error");
        }
    });
    Ok(sender)
}

fn origin_form(uri: &Uri) -> Uri {
    let path = uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));
    Uri::from(path)
}
