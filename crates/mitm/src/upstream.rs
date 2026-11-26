use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use http::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;

use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use rustls_platform_verifier::Verifier;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

#[cfg(feature = "testing")]
pub const TESTING_HOOKS_MARKER: &str = "credshim-testing-hooks-enabled";

#[cfg(feature = "testing")]
#[derive(Clone, Default)]
pub struct TestingHooks {
    pub extra_trust_anchors: Vec<rustls_pki_types::CertificateDer<'static>>,
    pub resolve_overrides: std::collections::HashMap<String, std::net::SocketAddr>,
}

#[derive(Clone)]
pub struct Upstream {
    tls: Arc<ClientConfig>,
    #[cfg(feature = "testing")]
    hooks: TestingHooks,
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("could not connect to upstream {host}:{port}: {source}")]
    Tcp {
        host: String,
        port: u16,
        source: io::Error,
    },
    #[error("upstream {host}:{port} failed TLS verification: {source}")]
    Tls {
        host: String,
        port: u16,
        source: io::Error,
    },
    #[error("invalid upstream server name {0:?}")]
    InvalidName(String),
    #[error("timed out connecting to upstream {host}:{port}")]
    Timeout { host: String, port: u16 },
    #[error(
        "upstream {host}:{port} resolves only to link-local, unspecified or cloud metadata addresses"
    )]
    OffLimits { host: String, port: u16 },
}

const GCP_METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd20, 0xce, 0, 0, 0, 0, 0, 0x254);

fn is_aws_service_v6(v6: Ipv6Addr) -> bool {
    v6.segments()[..2] == [0xfd00, 0xec2]
}

fn is_off_limits(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local() || v4.octets()[0] == 0,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_off_limits(IpAddr::V4(v4)),
            None => {
                v6.is_unspecified()
                    || v6.is_unicast_link_local()
                    || is_aws_service_v6(v6)
                    || v6 == GCP_METADATA_V6
            }
        },
    }
}

const ATTEMPT_STAGGER: Duration = Duration::from_millis(250);

fn interleave_families(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let Some(first) = addrs.first() else {
        return Vec::new();
    };
    let (lead, other): (Vec<SocketAddr>, Vec<SocketAddr>) = addrs
        .iter()
        .copied()
        .partition(|addr| addr.is_ipv6() == first.is_ipv6());
    let mut lead = lead.into_iter();
    let mut other = other.into_iter();
    let mut ordered = Vec::with_capacity(addrs.len());
    loop {
        match (lead.next(), other.next()) {
            (None, None) => return ordered,
            (a, b) => ordered.extend(a.into_iter().chain(b)),
        }
    }
}

async fn race<T, C, F>(addrs: Vec<SocketAddr>, stagger: Duration, connect: C) -> io::Result<T>
where
    T: Send + 'static,
    C: Fn(SocketAddr) -> F,
    F: Future<Output = io::Result<T>> + Send + 'static,
{
    let mut pending = addrs.into_iter();
    let mut attempts = JoinSet::new();
    let mut last_error: Option<io::Error> = None;
    loop {
        if attempts.is_empty() {
            let Some(addr) = pending.next() else {
                return Err(last_error.unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "could not resolve to any address",
                    )
                }));
            };
            attempts.spawn(connect(addr));
        }
        let failure = tokio::select! {
            biased;
            Some(joined) = attempts.join_next() => match joined {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(err)) => Some(err),
                Err(err) => Some(io::Error::other(err)),
            },
            () = tokio::time::sleep(stagger), if !pending.as_slice().is_empty() => None,
        };
        if failure.is_some() {
            last_error = failure;
        }
        if let Some(addr) = pending.next() {
            attempts.spawn(connect(addr));
        }
    }
}

pub async fn connect_first(addrs: &[SocketAddr], stagger: Duration) -> io::Result<TcpStream> {
    race(interleave_families(addrs), stagger, TcpStream::connect).await
}

impl Upstream {
    pub fn new() -> anyhow::Result<Self> {
        let verifier = Verifier::new(crypto_provider())?;
        Ok(Self {
            tls: Arc::new(client_config(verifier)),
            #[cfg(feature = "testing")]
            hooks: TestingHooks::default(),
        })
    }

    #[cfg(feature = "testing")]
    pub fn with_testing_hooks(hooks: TestingHooks) -> anyhow::Result<Self> {
        tracing::warn!(
            marker = TESTING_HOOKS_MARKER,
            "upstream testing hooks are active"
        );
        let verifier =
            Verifier::new_with_extra_roots(hooks.extra_trust_anchors.clone(), crypto_provider())?;
        Ok(Self {
            tls: Arc::new(client_config(verifier)),
            hooks,
        })
    }

    pub async fn connect_tcp(&self, host: &str, port: u16) -> Result<TcpStream, ConnectError> {
        #[cfg(feature = "testing")]
        if let Some(addr) = self.hooks.resolve_overrides.get(host) {
            return TcpStream::connect(addr)
                .await
                .map_err(|source| ConnectError::Tcp {
                    host: host.to_string(),
                    port,
                    source,
                });
        }
        let tcp_error = |source| ConnectError::Tcp {
            host: host.to_string(),
            port,
            source,
        };
        let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(tcp_error)?
            .collect();
        let allowed: Vec<SocketAddr> = resolved
            .iter()
            .copied()
            .filter(|addr| !is_off_limits(addr.ip()))
            .collect();
        if allowed.is_empty() && !resolved.is_empty() {
            return Err(ConnectError::OffLimits {
                host: host.to_string(),
                port,
            });
        }
        connect_first(&allowed, ATTEMPT_STAGGER)
            .await
            .map_err(tcp_error)
    }

    pub async fn connect_tls(
        &self,
        host: &str,
        port: u16,
        alpn: &[&[u8]],
    ) -> Result<TlsStream<TcpStream>, ConnectError> {
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| ConnectError::InvalidName(host.to_string()))?;
        let tcp = self.connect_tcp(host, port).await?;
        let mut config = (*self.tls).clone();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        TlsConnector::from(Arc::new(config))
            .connect(server_name, tcp)
            .await
            .map_err(|source| ConnectError::Tls {
                host: host.to_string(),
                port,
                source,
            })
    }

    pub(crate) async fn connect_tls_within(
        &self,
        host: &str,
        port: u16,
        alpn: &[&[u8]],
        timeout: Duration,
    ) -> Result<TlsStream<TcpStream>, ConnectError> {
        tokio::time::timeout(timeout, self.connect_tls(host, port, alpn))
            .await
            .map_err(|_| ConnectError::Timeout {
                host: host.to_string(),
                port,
            })?
    }
}

fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn client_config(verifier: Verifier) -> ClientConfig {
    ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth()
}

pub(crate) const ALPN_H2: &[u8] = b"h2";
pub(crate) const ALPN_HTTP1: &[u8] = b"http/1.1";

pub(crate) struct UpstreamIo(TokioIo<TlsStream<TcpStream>>);

impl UpstreamIo {
    pub(crate) fn new(tls: TlsStream<TcpStream>) -> Self {
        Self(TokioIo::new(tls))
    }
}

impl Connection for UpstreamIo {
    fn connected(&self) -> Connected {
        let connected = Connected::new();
        if self.0.inner().get_ref().1.alpn_protocol() == Some(ALPN_H2) {
            connected.negotiated_h2()
        } else {
            connected
        }
    }
}

impl hyper::rt::Read for UpstreamIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for UpstreamIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }
}

#[derive(Clone)]
pub(crate) struct TargetConnector {
    upstream: Upstream,
    host: String,
    port: u16,
    timeout: Duration,
    verified: Arc<Mutex<Option<TlsStream<TcpStream>>>>,
}

impl TargetConnector {
    pub(crate) async fn open(
        upstream: Upstream,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<Self, ConnectError> {
        let tls = upstream
            .connect_tls_within(host, port, &[ALPN_H2, ALPN_HTTP1], timeout)
            .await?;
        Ok(Self {
            upstream,
            host: host.to_string(),
            port,
            timeout,
            verified: Arc::new(Mutex::new(Some(tls))),
        })
    }

    pub(crate) async fn connect_http1(&self) -> Result<TlsStream<TcpStream>, ConnectError> {
        self.upstream
            .connect_tls_within(&self.host, self.port, &[ALPN_HTTP1], self.timeout)
            .await
    }
}

impl tower_service::Service<Uri> for TargetConnector {
    type Response = UpstreamIo;
    type Error = ConnectError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Uri) -> Self::Future {
        let verified = self
            .verified
            .lock()
            .expect("connector lock poisoned")
            .take();
        let connector = self.clone();
        Box::pin(async move {
            let tls = match verified {
                Some(tls) => tls,
                None => {
                    connector
                        .upstream
                        .connect_tls_within(
                            &connector.host,
                            connector.port,
                            &[ALPN_H2, ALPN_HTTP1],
                            connector.timeout,
                        )
                        .await?
                }
            };
            Ok(UpstreamIo::new(tls))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn families_alternate_starting_with_the_resolvers_first_choice() {
        let ordered = interleave_families(&[
            addr("[2001:db8::1]:443"),
            addr("[2001:db8::2]:443"),
            addr("192.0.2.1:443"),
            addr("192.0.2.2:443"),
            addr("192.0.2.3:443"),
        ]);

        assert_eq!(
            ordered,
            vec![
                addr("[2001:db8::1]:443"),
                addr("192.0.2.1:443"),
                addr("[2001:db8::2]:443"),
                addr("192.0.2.2:443"),
                addr("192.0.2.3:443"),
            ]
        );
    }

    #[tokio::test]
    async fn a_hanging_first_address_does_not_block_the_next_one() {
        let addrs = vec![addr("[2001:db8::1]:443"), addr("192.0.2.1:443")];

        let winner = tokio::time::timeout(
            Duration::from_secs(5),
            race(addrs, Duration::from_millis(20), |addr| async move {
                if addr.is_ipv6() {
                    std::future::pending::<()>().await;
                }
                Ok::<_, io::Error>(addr)
            }),
        )
        .await
        .expect("the second address is tried while the first hangs")
        .unwrap();

        assert_eq!(winner, addr("192.0.2.1:443"));
    }

    #[tokio::test]
    async fn a_failed_address_moves_on_without_waiting_for_the_stagger() {
        let addrs = vec![addr("192.0.2.1:443"), addr("192.0.2.2:443")];

        let winner = tokio::time::timeout(
            Duration::from_secs(5),
            race(addrs, Duration::from_secs(3600), |addr| async move {
                if addr == "192.0.2.1:443".parse().unwrap() {
                    return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
                }
                Ok(addr)
            }),
        )
        .await
        .expect("the second address is tried as soon as the first fails")
        .unwrap();

        assert_eq!(winner, addr("192.0.2.2:443"));
    }

    #[tokio::test]
    async fn when_every_address_fails_the_last_error_is_returned() {
        let addrs = vec![addr("192.0.2.1:443"), addr("192.0.2.2:443")];

        let err = race(addrs, Duration::from_millis(20), |addr| async move {
            Err::<SocketAddr, _>(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                addr.to_string(),
            ))
        })
        .await
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(err.to_string(), "192.0.2.2:443");
    }

    #[tokio::test]
    async fn no_addresses_is_an_error() {
        let err = race(Vec::new(), Duration::from_millis(20), |addr| async move {
            Ok::<_, io::Error>(addr)
        })
        .await
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
