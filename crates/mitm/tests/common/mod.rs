#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use credshim_testkit::upstream::now_us;
use credshim_testkit::{MockUpstream, SseTick, UploadSummary, pattern};
use futures_util::StreamExt;
use rustls::RootCertStore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

pub const LARGE: u64 = 24 * 1024 * 1024;

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
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
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
