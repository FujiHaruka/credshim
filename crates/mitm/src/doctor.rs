use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{self, HeaderValue};
use http::{Response, Version};
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio_rustls::TlsAcceptor;

use crate::ca::CertificateAuthority;
use crate::proxy::ProxyBody;
use crate::upstream::ALPN_H2;

pub const DOCTOR_HOST: &str = "credshim.test";

pub(crate) fn is_doctor_host(host: &str) -> bool {
    host.eq_ignore_ascii_case(DOCTOR_HOST)
}

pub(crate) fn report(tls: bool, version: Version) -> Response<ProxyBody> {
    let protocol = if version == Version::HTTP_2 {
        "h2"
    } else {
        "http/1.1"
    };
    let body = format!(
        "{{\"credshim\":\"doctor\",\"via_proxy\":true,\"tls\":{tls},\"ca_trusted\":{tls},\"protocol\":\"{protocol}\"}}\n"
    );
    let mut response = Response::new(Full::new(Bytes::from(body)).map_err(|n| match n {}).boxed());
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

pub(crate) fn serve_tls(
    on_upgrade: OnUpgrade,
    ca: Arc<CertificateAuthority>,
    handshake_timeout: Duration,
) {
    tokio::spawn(async move {
        let accept = async {
            let upgraded = on_upgrade.await.map_err(|e| e.to_string())?;
            let config = ca.server_config(DOCTOR_HOST).map_err(|e| e.to_string())?;
            TlsAcceptor::from(config)
                .accept(TokioIo::new(upgraded))
                .await
                .map_err(|e| e.to_string())
        };
        let tls = match tokio::time::timeout(handshake_timeout, accept).await {
            Ok(Ok(tls)) => tls,
            Ok(Err(reason)) => {
                tracing::info!(%reason, "doctor TLS handshake failed; the client may not trust the CA");
                return;
            }
            Err(_) => {
                tracing::info!("doctor TLS handshake timed out");
                return;
            }
        };
        let h2 = tls.get_ref().1.alpn_protocol() == Some(ALPN_H2);
        let service = service_fn(|req: http::Request<hyper::body::Incoming>| async move {
            Ok::<_, Infallible>(report(true, req.version()))
        });
        let io = TokioIo::new(tls);
        let result = if h2 {
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .timer(TokioTimer::new())
                .serve_connection(io, service)
                .await
        } else {
            hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .serve_connection(io, service)
                .await
        };
        if let Err(err) = result {
            tracing::debug!(error = %err, "doctor connection ended with error");
        }
    });
}

#[derive(Debug)]
pub struct Probe {
    pub protocol: &'static str,
    pub body: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("could not connect to the proxy at {addr}: {source}")]
    Connect {
        addr: std::net::SocketAddr,
        source: std::io::Error,
    },
    #[error("the proxy answered the doctor CONNECT with {0:?}")]
    Refused(String),
    #[error("{0} holds no PEM certificate")]
    NoCertificate(String),
    #[error("TLS with {DOCTOR_HOST} failed ({0}); the proxy is not signing with this CA")]
    Tls(std::io::Error),
    #[error("doctor request failed: {0}")]
    Http(#[from] hyper::Error),
    #[error("timed out talking to the proxy")]
    Timeout,
}

pub async fn probe(
    proxy: std::net::SocketAddr,
    ca_pem: &str,
    ca_label: &str,
    timeout: Duration,
) -> Result<Probe, ProbeError> {
    tokio::time::timeout(timeout, probe_inner(proxy, ca_pem, ca_label))
        .await
        .map_err(|_| ProbeError::Timeout)?
}

async fn probe_inner(
    proxy: std::net::SocketAddr,
    ca_pem: &str,
    ca_label: &str,
) -> Result<Probe, ProbeError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut roots = rustls::RootCertStore::empty();
    for block in pem::parse_many(ca_pem).unwrap_or_default() {
        if block.tag() == "CERTIFICATE" {
            let _ = roots.add(rustls_pki_types::CertificateDer::from(
                block.into_contents(),
            ));
        }
    }
    if roots.is_empty() {
        return Err(ProbeError::NoCertificate(ca_label.to_string()));
    }
    let mut tcp = tokio::net::TcpStream::connect(proxy)
        .await
        .map_err(|source| ProbeError::Connect {
            addr: proxy,
            source,
        })?;
    tcp.write_all(
        format!("CONNECT {DOCTOR_HOST}:443 HTTP/1.1\r\nHost: {DOCTOR_HOST}:443\r\n\r\n").as_bytes(),
    )
    .await
    .map_err(|source| ProbeError::Connect {
        addr: proxy,
        source,
    })?;
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let byte = tcp.read_u8().await.map_err(|source| ProbeError::Connect {
            addr: proxy,
            source,
        })?;
        head.push(byte);
    }
    let status_line = String::from_utf8_lossy(&head)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    if status_line.split_whitespace().nth(1) != Some("200") {
        return Err(ProbeError::Refused(status_line));
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("aws-lc-rs supports the default protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_H2.to_vec(), crate::upstream::ALPN_HTTP1.to_vec()];
    let name = rustls_pki_types::ServerName::try_from(DOCTOR_HOST).expect("valid DNS name");
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .map_err(ProbeError::Tls)?;
    let h2 = tls.get_ref().1.alpn_protocol() == Some(ALPN_H2);
    let io = TokioIo::new(tls);
    let request = |uri: &str| {
        http::Request::get(uri)
            .header(header::HOST, DOCTOR_HOST)
            .body(http_body_util::Empty::<Bytes>::new())
            .expect("static request")
    };
    let response = if h2 {
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await?;
        tokio::spawn(connection);
        let mut req = request(&format!("https://{DOCTOR_HOST}/"));
        req.headers_mut().remove(header::HOST);
        sender.send_request(req).await?
    } else {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(connection);
        sender.send_request(request("/")).await?
    };
    let body = response.into_body().collect().await?.to_bytes();
    Ok(Probe {
        protocol: if h2 { "h2" } else { "http/1.1" },
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}
