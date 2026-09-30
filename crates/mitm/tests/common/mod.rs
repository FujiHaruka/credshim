#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use credshim_testkit::upstream::now_us;
use credshim_testkit::{Alpn, MockUpstream, SseTick, UploadSummary, pattern};
use futures_util::StreamExt;
use http_body_util::Full;
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::RootCertStore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

pub const LARGE: u64 = 24 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Downstream {
    Http1,
    Http2,
}

impl Downstream {
    pub fn version(self) -> reqwest::Version {
        match self {
            Downstream::Http1 => reqwest::Version::HTTP_11,
            Downstream::Http2 => reqwest::Version::HTTP_2,
        }
    }
}

pub const COMBOS: [(Downstream, Alpn); 4] = [
    (Downstream::Http1, Alpn::H1Only),
    (Downstream::Http1, Alpn::H2Only),
    (Downstream::Http2, Alpn::H1Only),
    (Downstream::Http2, Alpn::H2Only),
];

pub fn upstream_version(alpn: Alpn) -> &'static str {
    match alpn {
        Alpn::H1Only => "HTTP/1.1",
        Alpn::H2Only | Alpn::Both => "HTTP/2.0",
    }
}

pub fn client_for(proxy: SocketAddr, root: &[u8], downstream: Downstream) -> reqwest::Client {
    let builder = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{}", proxy)).unwrap())
        .tls_certs_only([reqwest::Certificate::from_der(root).unwrap()]);
    match downstream {
        Downstream::Http1 => builder.http1_only(),
        Downstream::Http2 => builder.http2_prior_knowledge(),
    }
    .build()
    .unwrap()
}

pub async fn h2_over_proxy(
    proxy: SocketAddr,
    target: &str,
    roots: RootCertStore,
) -> SendRequest<Full<Bytes>> {
    let (tcp, head) = connect(proxy, target).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let sni = target.rsplit_once(':').map_or(target, |(host, _)| host);
    let tls = tls_with_alpn(tcp, roots, sni, b"h2").await.unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(connection);
    sender
}

pub fn client_via(proxy: SocketAddr, root: Option<&[u8]>) -> reqwest::Client {
    let mut builder =
        reqwest::Client::builder().proxy(reqwest::Proxy::all(format!("http://{}", proxy)).unwrap());
    if let Some(root) = root {
        let root = reqwest::Certificate::from_der(root).unwrap();
        builder = builder.tls_certs_only([root]);
    }
    builder.build().unwrap()
}

pub async fn raw_exchange(proxy: SocketAddr, request: &str) -> String {
    let mut tcp = TcpStream::connect(proxy).await.unwrap();
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    tcp.read_to_string(&mut response).await.unwrap();
    response
}

pub async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let byte = stream.read_u8().await.unwrap();
        head.push(byte);
    }
    String::from_utf8(head).unwrap()
}

pub async fn assert_sse_unbuffered(client: &reqwest::Client, url: String) {
    let interval_ms = 300;
    let res = client
        .get(format!("{url}?count=5&interval_ms={interval_ms}"))
        .send()
        .await
        .unwrap();
    let mut stream = res.bytes_stream();
    let mut pending = String::new();
    let mut seen = 0;
    while let Some(chunk) = stream.next().await {
        let arrived = now_us();
        pending.push_str(std::str::from_utf8(&chunk.unwrap()).unwrap());
        while let Some(end) = pending.find("\n\n") {
            let event: String = pending.drain(..end + 2).collect();
            let data = event.trim().strip_prefix("data: ").unwrap();
            let tick: SseTick = serde_json::from_str(data).unwrap();
            let latency_ms = (arrived - tick.sent_at_us) / 1000;
            assert!(
                latency_ms < interval_ms / 2,
                "event {} took {latency_ms}ms to arrive",
                tick.seq
            );
            seen += 1;
        }
    }
    assert_eq!(seen, 5);
}

pub async fn assert_large_bodies_intact(client: &reqwest::Client, mock: &MockUpstream, host: &str) {
    let res = client
        .get(mock.url(host, &format!("/bytes/{LARGE}")))
        .send()
        .await
        .unwrap();
    let mut hasher = Sha256::new();
    let mut len = 0u64;
    let mut stream = res.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.unwrap();
        len += chunk.len() as u64;
        hasher.update(&chunk);
    }
    assert_eq!(len, LARGE);
    assert_eq!(hex::encode(hasher.finalize()), pattern::sha256_hex(LARGE));

    let body =
        reqwest::Body::wrap_stream(pattern::chunks(LARGE, 64 * 1024).map(Ok::<_, std::io::Error>));
    let summary: UploadSummary = client
        .post(mock.url(host, "/upload"))
        .body(body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(summary.len, LARGE);
    assert_eq!(summary.sha256, pattern::sha256_hex(LARGE));
}

pub async fn connect(proxy: SocketAddr, target: &str) -> (TcpStream, String) {
    let mut tcp = TcpStream::connect(proxy).await.unwrap();
    tcp.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = read_head(&mut tcp).await;
    (tcp, head)
}

pub async fn tls_over(
    tcp: TcpStream,
    roots: RootCertStore,
    sni: &str,
    send_sni: bool,
) -> std::io::Result<TlsStream<TcpStream>> {
    tls_connect(tcp, roots, sni, send_sni, b"http/1.1").await
}

pub async fn tls_with_alpn(
    tcp: TcpStream,
    roots: RootCertStore,
    sni: &str,
    alpn: &[u8],
) -> std::io::Result<TlsStream<TcpStream>> {
    tls_connect(tcp, roots, sni, true, alpn).await
}

async fn tls_connect(
    tcp: TcpStream,
    roots: RootCertStore,
    sni: &str,
    send_sni: bool,
    alpn: &[u8],
) -> std::io::Result<TlsStream<TcpStream>> {
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    config.enable_sni = send_sni;
    TlsConnector::from(Arc::new(config))
        .connect(sni.to_string().try_into().unwrap(), tcp)
        .await
}

pub async fn exchange(tls: &mut TlsStream<TcpStream>, request: &str) -> String {
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    let _ = tls.read_to_end(&mut response).await;
    String::from_utf8(response).unwrap()
}
