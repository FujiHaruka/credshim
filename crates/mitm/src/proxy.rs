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

use credshim_aws::Aws;
use credshim_core::{BaseUrls, Injector};
use credshim_oauth::OAuth;

use crate::audit::{self, AwsLabels, Outcome, Stats};
use crate::base_url::BaseUrlServer;
use crate::ca::CertificateAuthority;
use crate::doctor;
use crate::intercept::{Ingress, Intercept, Services, Session};
use crate::upstream::{ConnectError, Upstream};

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub allow_non_loopback: bool,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub header_read_timeout: Duration,
    pub intercept: Option<Intercept>,
    pub injector: Arc<Injector>,
    pub oauth: Option<Arc<OAuth>>,
    pub aws: Option<Arc<Aws>>,
    pub scrub: bool,
    pub stats: Arc<Stats>,
    pub purge_interval: Duration,
    pub doctor_ca: Option<Arc<CertificateAuthority>>,
    pub base_url_listen: Option<SocketAddr>,
    pub base_urls: BaseUrls,
}

impl ProxyConfig {
    pub fn new(listen: SocketAddr) -> Self {
        Self {
            listen,
            allow_non_loopback: false,
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(90),
            header_read_timeout: Duration::from_secs(30),
            intercept: None,
            injector: Arc::new(Injector::default()),
            oauth: None,
            aws: None,
            scrub: true,
            stats: Arc::default(),
            purge_interval: Duration::from_secs(60),
            doctor_ca: None,
            base_url_listen: None,
            base_urls: BaseUrls::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BindError {
    #[error("refusing to listen on non-loopback address {0}")]
    NotLoopback(SocketAddr),
    #[error("refusing to listen on the unspecified address {0}; name the one interface to bind")]
    Unspecified(SocketAddr),
    #[error("rule host {0} is not in the intercept list, so its rule could never apply")]
    RuleHostNotIntercepted(String),
    #[error("OAuth host {0} is not in the intercept list, so its tokens could never be swapped")]
    OAuthHostNotIntercepted(String),
    #[error("base_url_prefix is set on a rule but [listen] base_url_addr is not")]
    BaseUrlWithoutListener,
    #[error("could not listen on {addr}: {source}")]
    Io { addr: SocketAddr, source: io::Error },
}

pub struct Proxy {
    addr: SocketAddr,
    base_url_addr: Option<SocketAddr>,
    accept_loop: JoinHandle<()>,
    base_url_loop: Option<JoinHandle<()>>,
    purge_loop: Option<JoinHandle<()>>,
}

fn check_listen(addr: SocketAddr, allow_non_loopback: bool) -> Result<(), BindError> {
    if addr.ip().is_unspecified() {
        return Err(BindError::Unspecified(addr));
    }
    if !addr.ip().is_loopback() && !allow_non_loopback {
        return Err(BindError::NotLoopback(addr));
    }
    Ok(())
}

async fn listen(addr: SocketAddr) -> Result<(TcpListener, SocketAddr), BindError> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| BindError::Io { addr, source })?;
    let local = listener
        .local_addr()
        .map_err(|source| BindError::Io { addr, source })?;
    Ok((listener, local))
}

impl Proxy {
    pub async fn bind(config: ProxyConfig, upstream: Upstream) -> Result<Self, BindError> {
        check_listen(config.listen, config.allow_non_loopback)?;
        if let Some(addr) = config.base_url_listen {
            check_listen(addr, config.allow_non_loopback)?;
        } else if !config.base_urls.is_empty() {
            return Err(BindError::BaseUrlWithoutListener);
        }
        if let Some(host) = config
            .injector
            .rules()
            .hosts()
            .find(|host| !config.intercept.as_ref().is_some_and(|i| i.covers(host)))
        {
            return Err(BindError::RuleHostNotIntercepted(host.to_string()));
        }
        if let Some(host) = config
            .oauth
            .iter()
            .flat_map(|oauth| oauth.hosts())
            .find(|host| !config.intercept.as_ref().is_some_and(|i| i.covers(host)))
        {
            return Err(BindError::OAuthHostNotIntercepted(host.to_string()));
        }
        let (listener, addr) = listen(config.listen).await?;
        let base_url = match config.base_url_listen {
            Some(listen_addr) => Some(listen(listen_addr).await?),
            None => None,
        };
        let handler = Arc::new(Handler::new(&config, upstream.clone()));
        let base_url_addr = base_url.as_ref().map(|(_, addr)| *addr);
        let base_url_loop = base_url.map(|(listener, local)| {
            let server = Arc::new(BaseUrlServer::new(
                config.base_urls.clone(),
                local.ip(),
                upstream,
                handler.services.clone(),
                config.connect_timeout,
                config.idle_timeout,
            ));
            tracing::info!(base_url = %local, "base URL listener ready");
            tokio::spawn(server.accept_loop(listener, config.header_read_timeout))
        });
        let purge_loop = config
            .oauth
            .clone()
            .map(|oauth| tokio::spawn(purge_loop(oauth, config.purge_interval)));
        let accept_loop = tokio::spawn(accept_loop(listener, handler, config));
        tracing::info!(%addr, "proxy listening");
        Ok(Self {
            addr,
            base_url_addr,
            accept_loop,
            base_url_loop,
            purge_loop,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn base_url_addr(&self) -> Option<SocketAddr> {
        self.base_url_addr
    }

    pub async fn wait(mut self) {
        let _ = (&mut self.accept_loop).await;
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.accept_loop.abort();
        for task in [&self.base_url_loop, &self.purge_loop]
            .into_iter()
            .flatten()
        {
            task.abort();
        }
    }
}

async fn purge_loop(oauth: Arc<OAuth>, every: Duration) {
    let mut ticks = tokio::time::interval(every);
    loop {
        ticks.tick().await;
        let purged = oauth.purge(std::time::SystemTime::now());
        if purged > 0 {
            tracing::debug!(purged, "removed expired OAuth tokens from the vault");
        }
    }
}

pub(crate) const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

async fn accept_loop(listener: TcpListener, handler: Arc<Handler>, config: ProxyConfig) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(error = %err, "accept failed");
                tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
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
    services: Services,
    doctor_ca: Option<Arc<CertificateAuthority>>,
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
            services: Services {
                injector: config.injector.clone(),
                oauth: config.oauth.clone(),
                aws: config.aws.clone(),
                aws_buffers: crate::intercept::aws_buffer_budget(config.aws.as_deref()),
                scrub: config.scrub,
                stats: config.stats.clone(),
            },
            doctor_ca: config.doctor_ca.clone(),
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
        if doctor::is_doctor_host(&host) {
            let Some(ca) = self.doctor_ca.clone() else {
                tracing::warn!("doctor check needs a CA; create one with `credshim ca init`");
                return status(StatusCode::SERVICE_UNAVAILABLE);
            };
            doctor::serve_tls(hyper::upgrade::on(&mut req), ca, self.handshake_timeout);
            return Response::new(empty());
        }
        if let Some(blocked) = credshim_aws::blocked(&host) {
            tracing::warn!(%host, port, "CONNECT to an AWS sign-in or SSO endpoint refused");
            let labels = AwsLabels::reason(credshim_aws::Reason::BlockedHost(blocked));
            audit::record_connect_labelled(
                "tcp",
                &host,
                port,
                Some(&labels),
                &Outcome::Blocked,
                StatusCode::FORBIDDEN,
                &self.services.stats,
            );
            return status(StatusCode::FORBIDDEN);
        }
        if let Some(intercept) = self.intercept.as_ref().filter(|i| i.covers(&host)) {
            return self.intercept(req, intercept, host, port).await;
        }
        let upstream = match self.connect_with_timeout(&host, port).await {
            Ok(tcp) => tcp,
            Err(err) if err.is_off_limits() => {
                tracing::warn!(%host, port, "CONNECT to a link-local or unspecified address refused");
                self.audit_connect("tcp", &host, port, &Outcome::Blocked, StatusCode::FORBIDDEN);
                return status(StatusCode::FORBIDDEN);
            }
            Err(err) => {
                tracing::warn!(%host, port, error = %err, "CONNECT upstream failed");
                self.audit_connect(
                    "tcp",
                    &host,
                    port,
                    &Outcome::Tunnel,
                    StatusCode::BAD_GATEWAY,
                );
                return status(StatusCode::BAD_GATEWAY);
            }
        };
        self.audit_connect("tcp", &host, port, &Outcome::Tunnel, StatusCode::OK);
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
            self.services.clone(),
            Ingress::Connect,
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
                self.audit_connect(
                    "https",
                    &host,
                    port,
                    &Outcome::Rejected,
                    StatusCode::BAD_GATEWAY,
                );
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

    fn audit_connect(
        &self,
        scheme: &'static str,
        host: &str,
        port: u16,
        outcome: &Outcome,
        status: StatusCode,
    ) {
        audit::record_connect(scheme, host, port, outcome, status, &self.services.stats);
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
        if doctor::is_doctor_host(authority.host()) {
            return doctor::report(false, parts.version);
        }
        let method = parts.method.clone();
        let path = parts.uri.path().to_string();
        let entry = audit::Entry {
            ingress: "forward",
            scheme: "http",
            host: authority.host(),
            port: authority.port_u16().unwrap_or(80),
            method: &method,
            path: &path,
        };
        if let Some(blocked) = credshim_aws::blocked(authority.host()) {
            tracing::warn!(%authority, "request to an AWS sign-in or SSO endpoint refused");
            let labels = AwsLabels::reason(credshim_aws::Reason::BlockedHost(blocked));
            audit::record_labelled(
                &entry,
                Some(&labels),
                &Outcome::Blocked,
                StatusCode::FORBIDDEN,
                &self.services.stats,
            );
            return status(StatusCode::FORBIDDEN);
        }
        let dummy = self.injector.first_dummy_in(&parts).or_else(|| {
            self.services
                .aws
                .as_ref()
                .and_then(|aws| aws.first_dummy_in(&parts))
                .map(str::to_string)
        });
        if let Some(rule) = dummy {
            tracing::warn!(
                %rule,
                %authority,
                "dummy credential sent over plain HTTP; refusing to forward"
            );
            audit::record(
                &entry,
                &Outcome::Denied(rule),
                StatusCode::FORBIDDEN,
                &self.services.stats,
            );
            return status(StatusCode::FORBIDDEN);
        }
        let mut uri = http::uri::Parts::from(std::mem::take(&mut parts.uri));
        uri.authority = Some(authority.clone());
        let Ok(uri) = Uri::from_parts(uri) else {
            return status(StatusCode::BAD_REQUEST);
        };
        parts.uri = uri;
        strip_hop_by_hop(&mut parts.headers);
        match http::HeaderValue::from_str(authority.as_str()) {
            Ok(host) => {
                parts.headers.insert(header::HOST, host);
            }
            Err(_) => return status(StatusCode::BAD_REQUEST),
        }
        parts.version = http::Version::HTTP_11;
        let req = Request::from_parts(parts, body.boxed());
        let (outcome, response) = match self.client.request(req).await {
            Ok(res) => {
                let (mut parts, body) = res.into_parts();
                strip_hop_by_hop(&mut parts.headers);
                (Outcome::Pass, Response::from_parts(parts, body.boxed()))
            }
            Err(err) if TunnelError::off_limits_in(&err) => {
                tracing::warn!(%authority, "request to a link-local or unspecified address refused");
                (Outcome::Blocked, status(StatusCode::FORBIDDEN))
            }
            Err(err) => {
                tracing::warn!(%authority, error = %err, "upstream request failed");
                (Outcome::Pass, status(StatusCode::BAD_GATEWAY))
            }
        };
        audit::record(&entry, &outcome, response.status(), &self.services.stats);
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

impl TunnelError {
    fn is_off_limits(&self) -> bool {
        matches!(self, Self::Connect(ConnectError::OffLimits { .. }))
    }

    fn off_limits_in(err: &(dyn std::error::Error + 'static)) -> bool {
        std::iter::successors(Some(err), |err| err.source())
            .any(|err| err.downcast_ref::<Self>().is_some_and(Self::is_off_limits))
    }
}

fn connect_target(uri: &Uri) -> Option<(String, u16)> {
    let authority = uri.authority()?;
    let port = authority.port_u16()?;
    let host = without_root_dot(bare_host(authority.host()))?;
    Some((host.to_string(), port))
}

fn forward_authority(uri: &Uri) -> Option<http::uri::Authority> {
    if uri.scheme() != Some(&http::uri::Scheme::HTTP) {
        return None;
    }
    let authority = uri.authority()?.as_str();
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, rest)| rest);
    let parsed: http::uri::Authority = host_port.parse().ok()?;
    let host = without_root_dot(parsed.host())?;
    match parsed.port() {
        Some(port) => format!("{host}:{port}").parse().ok(),
        None => host.parse().ok(),
    }
}

fn bare_host(host: &str) -> &str {
    host.trim_start_matches('[').trim_end_matches(']')
}

fn without_root_dot(host: &str) -> Option<&str> {
    Some(host.trim_end_matches('.')).filter(|host| !host.is_empty())
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
            let host = bare_host(uri.host().unwrap_or_default()).to_string();
            let port = uri.port_u16().unwrap_or(80);
            let tcp = tokio::time::timeout(timeout, upstream.connect_tcp(&host, port))
                .await
                .map_err(|_| TunnelError::Timeout)??;
            let _ = tcp.set_nodelay(true);
            Ok(TokioIo::new(tcp))
        })
    }
}
