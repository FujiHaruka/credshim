use std::time::Duration;

use credshim_testkit::{
    Alpn, Echo, LeafOptions, MockUpstream, SseTick, TestCa, UploadSummary, client_trusting,
    install_crypto_provider, pattern,
};
use futures_util::{SinkExt, StreamExt};
use reqwest::Version;
use tokio_tungstenite::tungstenite::Message;

async fn https_mock(alpn: Alpn) -> (TestCa, MockUpstream) {
    install_crypto_provider();
    let ca = TestCa::new();
    let upstream = MockUpstream::https(ca.issue(&["localhost"]))
        .alpn(alpn)
        .start()
        .await;
    (ca, upstream)
}

#[tokio::test]
async fn reqwest_reaches_mock_over_http1() {
    let (ca, upstream) = https_mock(Alpn::Both).await;
    let client = client_trusting(&ca).http1_only().build().unwrap();

    let res = client
        .post(upstream.url("localhost", "/v1/anything?x=1"))
        .header("authorization", "Bearer abc")
        .body("hello")
        .send()
        .await
        .unwrap();

    assert_eq!(res.version(), Version::HTTP_11);
    let echo: Echo = res.json().await.unwrap();
    assert_eq!(echo.method, "POST");
    assert_eq!(echo.path, "/v1/anything");
    assert_eq!(echo.query.as_deref(), Some("x=1"));
    assert_eq!(echo.header("authorization"), Some("Bearer abc"));
    assert_eq!(echo.body, "hello");
    assert_eq!(upstream.request_count(), 1);
}

#[tokio::test]
async fn reqwest_negotiates_h2_via_alpn() {
    let (ca, upstream) = https_mock(Alpn::Both).await;
    let client = client_trusting(&ca).build().unwrap();

    let res = client
        .get(upstream.url("localhost", "/x"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.version(), Version::HTTP_2);
    let echo: Echo = res.json().await.unwrap();
    assert_eq!(echo.version, "HTTP/2.0");
}

#[tokio::test]
async fn h1_only_mock_refuses_to_negotiate_h2() {
    let (ca, upstream) = https_mock(Alpn::H1Only).await;
    let client = client_trusting(&ca).build().unwrap();

    let res = client
        .get(upstream.url("localhost", "/x"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.version(), Version::HTTP_11);
}

#[tokio::test]
async fn untrusted_ca_is_rejected() {
    install_crypto_provider();
    let ca = TestCa::new();
    let other = TestCa::new();
    let upstream = MockUpstream::https(ca.issue(&["localhost"])).start().await;
    let client = client_trusting(&other).build().unwrap();

    let err = client
        .get(upstream.url("localhost", "/"))
        .send()
        .await
        .unwrap_err();

    assert!(err.is_connect(), "{err:?}");
}

#[tokio::test]
async fn expired_leaf_is_rejected() {
    install_crypto_provider();
    let ca = TestCa::new();
    let upstream = MockUpstream::https(ca.issue_with(LeafOptions::expired(&["localhost"])))
        .start()
        .await;
    let client = client_trusting(&ca).build().unwrap();

    assert!(
        client
            .get(upstream.url("localhost", "/"))
            .send()
            .await
            .is_err()
    );
}

#[tokio::test]
async fn sse_ticks_arrive_incrementally() {
    let (ca, upstream) = https_mock(Alpn::Both).await;
    let client = client_trusting(&ca).build().unwrap();

    let res = client
        .get(upstream.url("localhost", "/sse?count=3&interval_ms=50"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.headers()["content-type"], "text/event-stream");
    let body = res.text().await.unwrap();

    let ticks: Vec<SseTick> = body
        .lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .map(|d| serde_json::from_str(d).unwrap())
        .collect();
    assert_eq!(ticks.iter().map(|t| t.seq).collect::<Vec<_>>(), [0, 1, 2]);
    assert!(ticks[2].sent_at_us - ticks[0].sent_at_us >= 100_000);
}

#[tokio::test]
async fn sse_disconnect_is_observed() {
    let (ca, upstream) = https_mock(Alpn::Both).await;
    let client = client_trusting(&ca).http1_only().build().unwrap();

    let mut stream = client
        .get(upstream.url("localhost", "/sse?count=1000&interval_ms=20"))
        .send()
        .await
        .unwrap()
        .bytes_stream();
    stream.next().await.unwrap().unwrap();
    drop(stream);
    drop(client);

    tokio::time::timeout(Duration::from_secs(5), async {
        while upstream.sse_streams_closed() == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("mock never observed the disconnect");
}

#[tokio::test]
async fn large_download_matches_pattern() {
    let (ca, upstream) = https_mock(Alpn::Both).await;
    let client = client_trusting(&ca).build().unwrap();
    let len = 20 * 1024 * 1024;

    let body = client
        .get(upstream.url("localhost", &format!("/bytes/{len}")))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();

    assert_eq!(body.len() as u64, len);
    assert_eq!(pattern::digest_hex(&body), pattern::sha256_hex(len));
}

#[tokio::test]
async fn large_upload_is_hashed_by_mock() {
    let (ca, upstream) = https_mock(Alpn::Both).await;
    let client = client_trusting(&ca).build().unwrap();
    let len = 20 * 1024 * 1024u64;

    let summary: UploadSummary = client
        .post(upstream.url("localhost", "/upload"))
        .body(reqwest::Body::wrap_stream(
            pattern::chunks(len, 64 * 1024).map(Ok::<_, std::io::Error>),
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(summary.len, len);
    assert_eq!(summary.sha256, pattern::sha256_hex(len));
}

#[tokio::test]
async fn websocket_echo_reports_authorization_and_echoes() {
    let upstream = MockUpstream::http().start().await;
    let mut request =
        tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
            upstream.url("127.0.0.1", "/ws").replace("http", "ws"),
        )
        .unwrap();
    request
        .headers_mut()
        .insert("authorization", "Bearer ws-token".parse().unwrap());

    let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    let hello = ws.next().await.unwrap().unwrap();
    assert!(hello.to_text().unwrap().contains("Bearer ws-token"));

    ws.send(Message::text("ping-1")).await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap(), Message::text("ping-1"));
}

#[tokio::test]
async fn trailers_route_sends_trailers_over_h2() {
    let upstream = MockUpstream::http().alpn(Alpn::H2Only).start().await;
    let tcp = tokio::net::TcpStream::connect(upstream.addr())
        .await
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(tcp),
    )
    .await
    .unwrap();
    tokio::spawn(connection);

    let request = http::Request::get(upstream.url("127.0.0.1", "/trailers"))
        .header("te", "trailers")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let collected = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap();

    let trailers = collected.trailers().cloned().expect("trailers missing");
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
    assert_eq!(trailers.get("x-request-te").unwrap(), "trailers");
    assert_eq!(
        collected.to_bytes(),
        credshim_testkit::TRAILER_BODY.as_bytes()
    );
}
