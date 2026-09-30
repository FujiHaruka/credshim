use std::net::SocketAddr;
use std::sync::Arc;

use credshim_mitm::{BindError, Proxy, ProxyConfig, Upstream};
use credshim_testkit::upstream::now_us;
use credshim_testkit::{
    Echo, MockUpstream, SseTick, TestCa, UploadSummary, capture_logs, fake_secret,
    install_crypto_provider, pattern,
};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const LARGE: u64 = 24 * 1024 * 1024;

async fn start_proxy() -> Proxy {
    install_crypto_provider();
    let config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
    Proxy::bind(config, Upstream::new().unwrap()).await.unwrap()
}

fn client_via(proxy: &Proxy, ca: Option<&TestCa>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{}", proxy.local_addr())).unwrap());
    if let Some(ca) = ca {
        let root = reqwest::Certificate::from_der(ca.cert_der().as_ref()).unwrap();
        builder = builder.tls_certs_only([root]);
    }
    builder.build().unwrap()
}

async fn https_mock() -> (TestCa, MockUpstream) {
    install_crypto_provider();
    let ca = TestCa::new();
    let mock = MockUpstream::https(ca.issue(&["localhost"])).start().await;
    (ca, mock)
}

async fn raw_exchange(proxy: &Proxy, request: &str) -> String {
    let mut tcp = TcpStream::connect(proxy.local_addr()).await.unwrap();
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    tcp.read_to_string(&mut response).await.unwrap();
    response
}

async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let byte = stream.read_u8().await.unwrap();
        head.push(byte);
    }
    String::from_utf8(head).unwrap()
}

#[tokio::test]
async fn forwards_plain_http_get_and_post() {
    let proxy = start_proxy().await;
    let mock = MockUpstream::http().start().await;
    let client = client_via(&proxy, None);

    let get: Echo = client
        .get(mock.url("127.0.0.1", "/v1/models?limit=2"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let post: Echo = client
        .post(mock.url("127.0.0.1", "/v1/things"))
        .header("content-type", "application/json")
        .body(r#"{"a":1}"#)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(get.method, "GET");
    assert_eq!(get.path, "/v1/models");
    assert_eq!(get.query.as_deref(), Some("limit=2"));
    assert_eq!(post.method, "POST");
    assert_eq!(post.body, r#"{"a":1}"#);
    assert_eq!(post.header("content-type"), Some("application/json"));
    assert_eq!(mock.request_count(), 2);
    assert!(mock.requests().iter().all(|r| r.uri.scheme().is_none()));
}

#[tokio::test]
async fn curl_can_use_the_proxy() {
    let proxy = start_proxy().await;
    let mock = MockUpstream::http().start().await;
    let proxy_url = format!("http://{}", proxy.local_addr());
    let target = mock.url("127.0.0.1", "/curl");

    let output = tokio::process::Command::new("curl")
        .args(["-sS", "-x", &proxy_url, "-d", "posted", &target])
        .output()
        .await
        .expect("curl must be installed");

    assert!(output.status.success(), "{output:?}");
    let echo: Echo = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(echo.method, "POST");
    assert_eq!(echo.path, "/curl");
    assert_eq!(echo.body, "posted");
}

#[tokio::test]
async fn strips_hop_by_hop_headers() {
    let proxy = start_proxy().await;
    let mock = MockUpstream::http().start().await;
    let authority = format!("127.0.0.1:{}", mock.port());

    let response = raw_exchange(
        &proxy,
        &format!(
            "GET http://{authority}/hop HTTP/1.1\r\n\
             Host: {authority}\r\n\
             Connection: close, x-drop-me\r\n\
             X-Drop-Me: 1\r\n\
             X-Keep-Me: 1\r\n\
             Keep-Alive: timeout=5\r\n\
             Proxy-Connection: keep-alive\r\n\
             Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\
             TE: trailers\r\n\
             Trailer: x-t\r\n\
             Upgrade: h2c\r\n\
             \r\n"
        ),
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let body = &response[response.find("\r\n\r\n").unwrap() + 4..];
    let echo: Echo = serde_json::from_str(body).unwrap();
    for dropped in [
        "x-drop-me",
        "keep-alive",
        "proxy-connection",
        "proxy-authorization",
        "te",
        "trailer",
        "upgrade",
    ] {
        assert_eq!(echo.header(dropped), None, "{dropped} reached upstream");
    }
    assert_eq!(echo.header("x-keep-me"), Some("1"));
}

#[tokio::test]
async fn host_header_follows_the_request_target() {
    let proxy = start_proxy().await;
    let mock = MockUpstream::http().start().await;
    let authority = format!("127.0.0.1:{}", mock.port());

    let response = raw_exchange(
        &proxy,
        &format!(
            "GET http://{authority}/h HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;

    let body = &response[response.find("\r\n\r\n").unwrap() + 4..];
    let echo: Echo = serde_json::from_str(body).unwrap();
    assert_eq!(echo.header("host"), Some(authority.as_str()));
}

#[tokio::test]
async fn rejects_origin_form_and_non_http_targets() {
    let proxy = start_proxy().await;

    let origin_form = raw_exchange(
        &proxy,
        "GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    )
    .await;
    let https_target = raw_exchange(
        &proxy,
        "GET https://127.0.0.1/x HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(origin_form.starts_with("HTTP/1.1 400"), "{origin_form}");
    assert!(https_target.starts_with("HTTP/1.1 400"), "{https_target}");
}

#[tokio::test]
async fn connect_tunnel_shows_the_upstreams_own_certificate() {
    let proxy = start_proxy().await;
    let ca = TestCa::new();
    let leaf = ca.issue(&["localhost"]);
    let mock = MockUpstream::https(leaf.clone()).start().await;

    let mut tcp = TcpStream::connect(proxy.local_addr()).await.unwrap();
    let target = format!("localhost:{}", mock.port());
    tcp.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = read_head(&mut tcp).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(ca.root_store())
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .unwrap();
    let peer = tls.get_ref().1.peer_certificates().unwrap()[0].clone();
    assert_eq!(peer, leaf.cert_der);

    tls.write_all(b"GET /tunnelled HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    tls.read_to_string(&mut response).await.unwrap();
    assert!(response.contains("\"path\":\"/tunnelled\""), "{response}");
}

#[tokio::test]
async fn reqwest_reaches_https_mock_through_connect() {
    let proxy = start_proxy().await;
    let (ca, mock) = https_mock().await;
    let client = client_via(&proxy, Some(&ca));

    let echo: Echo = client
        .get(mock.url("localhost", "/via-connect"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(echo.path, "/via-connect");
}

#[tokio::test]
async fn unreachable_upstream_is_502() {
    let proxy = start_proxy().await;
    let closed = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };

    let forwarded = raw_exchange(
        &proxy,
        &format!("GET http://{closed}/x HTTP/1.1\r\nHost: {closed}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    let mut tcp = TcpStream::connect(proxy.local_addr()).await.unwrap();
    tcp.write_all(format!("CONNECT {closed} HTTP/1.1\r\nHost: {closed}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let tunnelled = read_head(&mut tcp).await;

    assert!(forwarded.starts_with("HTTP/1.1 502"), "{forwarded}");
    assert!(tunnelled.starts_with("HTTP/1.1 502"), "{tunnelled}");
}

#[tokio::test]
async fn refuses_non_loopback_listen_address() {
    install_crypto_provider();
    let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();

    let err = Proxy::bind(ProxyConfig::new(addr), Upstream::new().unwrap())
        .await
        .err()
        .unwrap();

    assert!(matches!(err, BindError::NotLoopback(_)), "{err}");
}

async fn assert_sse_unbuffered(client: &reqwest::Client, url: String) {
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

#[tokio::test]
async fn sse_events_are_not_buffered_over_http() {
    let proxy = start_proxy().await;
    let mock = MockUpstream::http().start().await;

    assert_sse_unbuffered(&client_via(&proxy, None), mock.url("127.0.0.1", "/sse")).await;
}

#[tokio::test]
async fn sse_events_are_not_buffered_over_connect() {
    let proxy = start_proxy().await;
    let (ca, mock) = https_mock().await;

    assert_sse_unbuffered(
        &client_via(&proxy, Some(&ca)),
        mock.url("localhost", "/sse"),
    )
    .await;
}

async fn assert_large_bodies_intact(client: &reqwest::Client, mock: &MockUpstream, host: &str) {
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

#[tokio::test]
async fn large_bodies_are_byte_identical_over_http() {
    let proxy = start_proxy().await;
    let mock = MockUpstream::http().start().await;

    assert_large_bodies_intact(&client_via(&proxy, None), &mock, "127.0.0.1").await;
}

#[tokio::test]
async fn large_bodies_are_byte_identical_over_connect() {
    let proxy = start_proxy().await;
    let (ca, mock) = https_mock().await;

    assert_large_bodies_intact(&client_via(&proxy, Some(&ca)), &mock, "localhost").await;
}

#[tokio::test]
async fn request_values_never_reach_the_logs() {
    let logs = capture_logs();
    let proxy = start_proxy().await;
    let mock = MockUpstream::http().start().await;
    let header_secret = fake_secret("header");
    let query_secret = fake_secret("query");
    let client = client_via(&proxy, None);

    client
        .get(mock.url("127.0.0.1", &format!("/v1/x?key={query_secret}")))
        .bearer_auth(&header_secret)
        .send()
        .await
        .unwrap();

    logs.assert_absent(&[&header_secret, &query_secret]);
}
