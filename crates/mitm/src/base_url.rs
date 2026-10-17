use std::collections::HashMap;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::uri::{Authority, PathAndQuery};
use http::{Method, Request, Response, StatusCode, Uri, header};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::OnceCell;

use crate::guide::{Topic, refuse};
use crate::intercept::{Ingress, Session};
use crate::live::Live;
use crate::proxy::{ProxyBody, unreachable};
use crate::upstream::{ConnectError, Upstream};

type SessionCell = Arc<OnceCell<Arc<Session>>>;

pub(crate) struct BaseUrlServer {
    listen_ip: IpAddr,
    upstream: Upstream,
    live: Live,
    connect_timeout: Duration,
    idle_timeout: Duration,
    sessions: Mutex<HashMap<(String, u16), SessionCell>>,
}

impl BaseUrlServer {
    pub(crate) fn new(
        listen_ip: IpAddr,
        upstream: Upstream,
        live: Live,
        connect_timeout: Duration,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            listen_ip,
            upstream,
            live,
            connect_timeout,
            idle_timeout,
            sessions: Mutex::default(),
        }
    }

    pub(crate) async fn accept_loop(
        self: Arc<Self>,
        listener: TcpListener,
        header_read_timeout: Duration,
    ) {
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(conn) => conn,
                Err(err) => {
                    tracing::warn!(error = %err, "base URL accept failed");
                    tokio::time::sleep(crate::proxy::ACCEPT_RETRY_DELAY).await;
                    continue;
                }
            };
            let server = self.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let server = server.clone();
                    async move { Ok::<_, Infallible>(server.handle(req).await) }
                });
                let result = hyper::server::conn::http1::Builder::new()
                    .timer(TokioTimer::new())
                    .header_read_timeout(header_read_timeout)
                    .serve_connection(TokioIo::new(tcp), service)
                    .with_upgrades()
                    .await;
                if let Err(err) = result {
                    tracing::debug!(%peer, error = %err, "base URL connection ended with error");
                }
            });
        }
    }

    async fn handle(&self, req: Request<Incoming>) -> Response<ProxyBody> {
        let (mut parts, body) = req.into_parts();
        if parts.method == Method::CONNECT {
            return self.refuse(
                StatusCode::METHOD_NOT_ALLOWED,
                Topic::Rejected,
                "the base URL listener takes plain requests to a base_url_prefix, not CONNECT"
                    .into(),
            );
        }
        if parts.uri.scheme().is_some() || parts.uri.authority().is_some() {
            tracing::warn!("base URL request is not in origin form");
            return self.refuse(
                StatusCode::BAD_REQUEST,
                Topic::Rejected,
                "the base URL request came in proxy form; make the client connect to the listener directly (add it to NO_PROXY)".into(),
            );
        }
        if !self.addressed_to_listener(&parts.headers) {
            tracing::warn!("base URL request names a host other than the loopback listener");
            return self.refuse(
                StatusCode::MISDIRECTED_REQUEST,
                Topic::Misdirected,
                "the Host of a base URL request must be the listener's own address".into(),
            );
        }
        let routing = self.live.current();
        let Some(route) = routing.base_urls.resolve(parts.uri.path()) else {
            tracing::debug!(path = parts.uri.path(), "no base URL prefix matches");
            let why = format!("no rule's base_url_prefix matches {}", parts.uri.path());
            return self.refuse(StatusCode::NOT_FOUND, Topic::Rejected, why);
        };
        let rebuilt = match parts.uri.query() {
            Some(query) => format!("{}?{query}", route.path),
            None => route.path.to_string(),
        };
        let Ok(path) = PathAndQuery::try_from(rebuilt) else {
            return self.refuse(
                StatusCode::BAD_REQUEST,
                Topic::Rejected,
                "the rewritten path is not a valid request path".into(),
            );
        };
        let (host, port) = (route.host.to_string(), route.port);
        parts.uri = Uri::from(path);
        parts.headers.remove(header::HOST);
        match self.session(host.clone(), port).await {
            Ok(session) => session.respond(parts, body).await,
            Err(err) => self
                .live
                .guide()
                .finish(None, unreachable(&host, port, &err)),
        }
    }

    fn refuse(&self, status: StatusCode, topic: Topic, why: String) -> Response<ProxyBody> {
        self.live.guide().finish(None, refuse(status, topic, why))
    }

    fn addressed_to_listener(&self, headers: &http::HeaderMap) -> bool {
        let Some(authority) = headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<Authority>().ok())
        else {
            return false;
        };
        let host = authority.host();
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        if host.eq_ignore_ascii_case("localhost") {
            return self.listen_ip.is_loopback();
        }
        host.parse::<IpAddr>().is_ok_and(|ip| {
            ip == self.listen_ip || (ip.is_loopback() && self.listen_ip.is_loopback())
        })
    }

    async fn session(&self, host: String, port: u16) -> Result<Arc<Session>, ConnectError> {
        let cell = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry((host.clone(), port))
            .or_default()
            .clone();
        let opened = cell
            .get_or_try_init(|| async {
                Session::open(
                    self.upstream.clone(),
                    self.live.clone(),
                    Ingress::BaseUrl,
                    host.clone(),
                    port,
                    self.connect_timeout,
                    self.idle_timeout,
                )
                .await
                .map(Arc::new)
            })
            .await;
        match opened {
            Ok(session) => Ok(session.clone()),
            Err(err) => {
                tracing::warn!(%host, port, error = %err, "base URL upstream failed");
                Err(err)
            }
        }
    }
}
