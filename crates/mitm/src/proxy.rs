use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName};
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use credshim_core::Injector;

use crate::audit::{self, Outcome};
use crate::intercept::{Intercept, Session};
use crate::upstream::{ConnectError, Upstream};

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub header_read_timeout: Duration,
    pub intercept: Option<Intercept>,
    pub injector: Arc<Injector>,
}

impl ProxyConfig {
    pub fn new(listen: SocketAddr) -> Self {
        Self {
            listen,
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(90),
            header_read_timeout: Duration::from_secs(30),
            intercept: None,
            injector: Arc::new(Injector::default()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BindError {
    #[error("refusing to listen on non-loopback address {0}")]
    NotLoopback(SocketAddr),
    #[error("rule host {0} is not in the intercept list, so its rule could never apply")]
    RuleHostNotIntercepted(String),
    #[error("could not listen on {addr}: {source}")]
    Io { addr: SocketAddr, source: io::Error },
}

pub struct Proxy {
    addr: SocketAddr,
    accept_loop: JoinHandle<()>,
}

impl Proxy {
    pub async fn bind(config: ProxyConfig, upstream: Upstream) -> Result<Self, BindError> {
        if !config.listen.ip().is_loopback() {
            return Err(BindError::NotLoopback(config.listen));
        }
        if let Some(host) = config
            .injector
            .rules()
            .hosts()
            .find(|host| !config.intercept.as_ref().is_some_and(|i| i.covers(host)))
        {
            return Err(BindError::RuleHostNotIntercepted(host.to_string()));
        }
        let listener = TcpListener::bind(config.listen)
            .await
            .map_err(|source| BindError::Io {
                addr: config.listen,
                source,
            })?;
        let addr = listener.local_addr().map_err(|source| BindError::Io {
            addr: config.listen,
            source,
        })?;
        let handler = Arc::new(Handler::new(&config, upstream));
        let accept_loop = tokio::spawn(accept_loop(listener, handler, config));
        tracing::info!(%addr, "proxy listening");
        Ok(Self { addr, accept_loop })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub async fn wait(mut self) {
        let _ = (&mut self.accept_loop).await;
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.accept_loop.abort();
    }
}

async fn accept_loop(listener: TcpListener, handler: Arc<Handler>, config: ProxyConfig) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(error = %err, "accept failed");
                continue;
            }
        };
        let handler = handler.clone();
        let header_read_timeout = config.header_read_timeout;
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let handler = handler.clone();
                async move { Ok::<_, Infallible>(handler.handle(req).await) }
            });
            let result = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(header_read_timeout)
                .serve_connection(TokioIo::new(tcp), service)
                .with_upgrades()
                .await;
            if let Err(err) = result {
                tracing::debug!(%peer, error = %err, "downstream connection ended with error");
            }
        });
    }
}

struct Handler {
    upstream: Upstream,
    client: Client<Connector, ProxyBody>,
    connect_timeout: Duration,
    idle_timeout: Duration,
    handshake_timeout: Duration,
    intercept: Option<Intercept>,
    injector: Arc<Injector>,
}

impl Handler {
    fn new(config: &ProxyConfig, upstream: Upstream) -> Self {
        let connector = Connector {
            upstream: upstream.clone(),
            timeout: config.connect_timeout,
        };
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(config.idle_timeout)
            .build(connector);
        Self {
            upstream,
            client,
            connect_timeout: config.connect_timeout,
            idle_timeout: config.idle_timeout,
            handshake_timeout: config.header_read_timeout,
            intercept: config.intercept.clone(),
            injector: config.injector.clone(),
        }
    }

    async fn handle(&self, req: Request<Incoming>) -> Response<ProxyBody> {
        if req.method() == Method::CONNECT {
            self.tunnel(req).await
        } else {
            self.forward(req).await
        }
    }

    async fn tunnel(&self, mut req: Request<Incoming>) -> Response<ProxyBody> {
        let Some((host, port)) = connect_target(req.uri()) else {
            tracing::warn!("CONNECT without a host:port authority");
            return status(StatusCode::BAD_REQUEST);
        };
        tracing::debug!(%host, port, "CONNECT");
        if let Some(intercept) = self.intercept.as_ref().filter(|i| i.covers(&host)) {
            return self.intercept(req, intercept, host, port).await;
        }
        let upstream = match self.connect_with_timeout(&host, port).await {
            Ok(tcp) => tcp,
            Err(err) => {
                tracing::warn!(%host, port, error = %err, "CONNECT upstream failed");
                return status(StatusCode::BAD_GATEWAY);
            }
        };
        let on_upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            let mut upstream = upstream;
            match on_upgrade.await {
                Ok(upgraded) => {
                    let mut downstream = TokioIo::new(upgraded);
                    if let Err(err) =
                        tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await
                    {
                        tracing::debug!(%host, port, error = %err, "tunnel closed with error");
                    }
                }
                Err(err) => tracing::debug!(%host, port, error = %err, "CONNECT upgrade failed"),
            }
        });
        Response::new(empty())
    }

    async fn intercept(
        &self,
        mut req: Request<Incoming>,
        intercept: &Intercept,
        host: String,
        port: u16,
    ) -> Response<ProxyBody> {
        let session = match Session::open(
            self.upstream.clone(),
            self.injector.clone(),
            host.clone(),
            port,
            self.connect_timeout,
            self.idle_timeout,
        )
        .await
        {
            Ok(session) => session,
            Err(err) => {
                tracing::warn!(%host, port, error = %err, "intercepted upstream failed");
                return status(StatusCode::BAD_GATEWAY);
            }
        };
        session.serve(
            hyper::upgrade::on(&mut req),
            intercept.ca(),
            self.handshake_timeout,
        );
        Response::new(empty())
    }

    async fn connect_with_timeout(&self, host: &str, port: u16) -> Result<TcpStream, TunnelError> {
        tokio::time::timeout(self.connect_timeout, self.upstream.connect_tcp(host, port))
            .await
            .map_err(|_| TunnelError::Timeout)?
            .map_err(TunnelError::Connect)
    }

    async fn forward(&self, req: Request<Incoming>) -> Response<ProxyBody> {
        let (mut parts, body) = req.into_parts();
        let Some(authority) = forward_authority(&parts.uri) else {
            tracing::warn!(method = %parts.method, "request is not an absolute http:// URI");
            return status(StatusCode::BAD_REQUEST);
        };
        tracing::debug!(method = %parts.method, %authority, path = parts.uri.path(), "forward");
        let method = parts.method.clone();
        let path = parts.uri.path().to_string();
        let entry = audit::Entry {
            scheme: "http",
            host: authority.host(),
            port: authority.port_u16().unwrap_or(80),
            method: &method,
            path: &path,
        };
        if let Some(rule) = self.injector.rules().first_dummy_in(&parts) {
            tracing::warn!(
                rule = rule.name(),
                %authority,
                "dummy credential sent over plain HTTP; refusing to forward"
            );
            audit::record(
                &entry,
                &Outcome::Denied(rule.name().to_string()),
                StatusCode::FORBIDDEN,
            );
            return status(StatusCode::FORBIDDEN);
        }
        strip_hop_by_hop(&mut parts.headers);
        match http::HeaderValue::from_str(authority.as_str()) {
            Ok(host) => {
                parts.headers.insert(header::HOST, host);
            }
            Err(_) => return status(StatusCode::BAD_REQUEST),
        }
        parts.version = http::Version::HTTP_11;
        let req = Request::from_parts(parts, body.boxed());
        let response = match self.client.request(req).await {
            Ok(res) => {
                let (mut parts, body) = res.into_parts();
                strip_hop_by_hop(&mut parts.headers);
                Response::from_parts(parts, body.boxed())
            }
            Err(err) => {
                tracing::warn!(%authority, error = %err, "upstream request failed");
                status(StatusCode::BAD_GATEWAY)
            }
        };
        audit::record(&entry, &Outcome::Pass, response.status());
        response
    }
}

#[derive(Debug, thiserror::Error)]
enum TunnelError {
    #[error("timed out connecting to upstream")]
    Timeout,
    #[error(transparent)]
    Connect(#[from] ConnectError),
}

fn connect_target(uri: &Uri) -> Option<(String, u16)> {
    let authority = uri.authority()?;
    let port = authority.port_u16()?;
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    Some((host.to_string(), port))
}

fn forward_authority(uri: &Uri) -> Option<http::uri::Authority> {
    if uri.scheme() != Some(&http::uri::Scheme::HTTP) {
        return None;
    }
    uri.authority().cloned()
}

const HOP_BY_HOP: [HeaderName; 8] = [
    header::CONNECTION,
    HeaderName::from_static("keep-alive"),
    HeaderName::from_static("proxy-connection"),
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
];

pub(crate) fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in listed.iter().chain(HOP_BY_HOP.iter()) {
        headers.remove(name);
    }
}

fn empty() -> ProxyBody {
    Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed()
}

pub(crate) fn status(code: StatusCode) -> Response<ProxyBody> {
    let mut res = Response::new(empty());
    *res.status_mut() = code;
    res
}

#[derive(Clone)]
struct Connector {
    upstream: Upstream,
    timeout: Duration,
}

impl tower_service::Service<Uri> for Connector {
    type Response = TokioIo<TcpStream>;
    type Error = TunnelError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let upstream = self.upstream.clone();
        let timeout = self.timeout;
        Box::pin(async move {
            let host = uri.host().unwrap_or_default().to_string();
            let port = uri.port_u16().unwrap_or(80);
            let tcp = tokio::time::timeout(timeout, upstream.connect_tcp(&host, port))
                .await
                .map_err(|_| TunnelError::Timeout)??;
            let _ = tcp.set_nodelay(true);
            Ok(TokioIo::new(tcp))
        })
    }
}
