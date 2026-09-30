mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use common::{
    COMBOS, Downstream, assert_large_bodies_intact, assert_sse_unbuffered, client_for, connect,
    exchange, h2_over_proxy, tls_over, tls_with_alpn,
};
use credshim_core::{InjectSpec, Injector, RuleSet, RuleSpec, Secrets};
use credshim_mitm::{CertificateAuthority, Intercept, Proxy, ProxyConfig, TestingHooks, Upstream};
use credshim_testkit::{
    Alpn, Echo, MockUpstream, TRAILER_BODY, TestCa, capture_logs, fake_secret,
    install_crypto_provider,
};
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use rustls::RootCertStore;
use secrecy::SecretString;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

const API: &str = "api.example.test";
const OTHER: &str = "other.example.test";
const DUMMY: &str = "credshim-protocols-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";

struct Setup {
    proxy: Proxy,
    dev_ca: Arc<CertificateAuthority>,
    mock: MockUpstream,
    secret: String,
    downstream: Downstream,
    _dir: tempfile::TempDir,
}

impl Setup {
    async fn new(downstream: Downstream, alpn: Alpn) -> Self {
        install_crypto_provider();
        let upstream_ca = TestCa::new();
        let mock = MockUpstream::https(upstream_ca.issue(&[API, OTHER]))
            .alpn(alpn)
            .start()
            .await;
        let dir = tempfile::tempdir().unwrap();
        let dev_ca = Arc::new(CertificateAuthority::init(dir.path()).unwrap());
        let upstream = Upstream::with_testing_hooks(TestingHooks {
            extra_trust_anchors: vec![upstream_ca.cert_der()],
            resolve_overrides: HashMap::from([
                (API.to_string(), mock.addr()),
                (OTHER.to_string(), mock.addr()),
            ]),
        })
        .unwrap();
        let rules = RuleSet::new(vec![RuleSpec {
            name: "api".into(),
            host: API.into(),
            port: None,
            path_prefix: None,
            allow_methods: None,
            allow_paths: None,
            limits: Default::default(),
            secret: "api".into(),
            dummy: DUMMY.into(),
            inject: InjectSpec {
                header: Some("authorization".into()),
                ..InjectSpec::default()
            },
        }])
        .unwrap();
        let secret = fake_secret("protocols");
        let mut secrets = Secrets::new();
        secrets.insert("api", SecretString::from(secret.as_str()));
        let injector = Arc::new(Injector::new(rules, secrets).unwrap());
        let mut config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
        config.intercept = Some(Intercept::new(dev_ca.clone(), [API]));
        config.injector = injector;
        let proxy = Proxy::bind(config, upstream).await.unwrap();
        Self {
            proxy,
            dev_ca,
            mock,
            secret,
            downstream,
            _dir: dir,
        }
    }

    fn client(&self) -> reqwest::Client {
        client_for(
            self.proxy.local_addr(),
            self.dev_ca.cert_der().as_ref(),
            self.downstream,
        )
    }

    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.dev_ca.cert_der().clone()).unwrap();
        roots
    }

    async fn tls(&self) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
        let (tcp, head) = connect(self.proxy.local_addr(), &format!("{API}:443")).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        tls_over(tcp, self.roots(), API, true).await.unwrap()
    }
}

fn get(url: String) -> http::Request<Full<Bytes>> {
    http::Request::get(url)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    for _ in 0..100 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn sse_is_unbuffered_in_every_protocol_combination() {
    for (downstream, alpn) in COMBOS {
        let setup = Setup::new(downstream, alpn).await;
        assert_sse_unbuffered(&setup.client(), format!("https://{API}/sse")).await;
    }
}

#[tokio::test]
async fn large_bodies_are_intact_in_every_protocol_combination() {
    for (downstream, alpn) in COMBOS {
        let setup = Setup::new(downstream, alpn).await;
        let client = setup.client();
        let res = client
            .get(format!("https://{API}/bytes/1"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.version(), downstream.version());
        assert_large_bodies_intact(&client, &setup.mock, API).await;
    }
}

#[tokio::test]
async fn client_disconnect_mid_sse_closes_the_upstream_stream() {
    for (downstream, alpn) in COMBOS {
        let setup = Setup::new(downstream, alpn).await;
        let client = setup.client();
        let res = client
            .get(format!("https://{API}/sse?count=1000&interval_ms=50"))
            .send()
            .await
            .unwrap();
        let mut stream = res.bytes_stream();
        stream.next().await.unwrap().unwrap();
        assert_eq!(setup.mock.sse_streams_closed(), 0);

        drop(stream);
        drop(client);

        eventually(
            &format!("upstream SSE close with {downstream:?}/{alpn:?}"),
            || setup.mock.sse_streams_closed() == 1,
        )
        .await;
    }
}

#[tokio::test]
async fn slow_downstream_reader_bounds_how_much_is_read_from_upstream() {
    const HUGE: u64 = 4 * 1024 * 1024 * 1024;
    const BOUND: u64 = 64 * 1024 * 1024;
    for (downstream, alpn) in COMBOS {
        let setup = Setup::new(downstream, alpn).await;
        let res = setup
            .client()
            .get(format!("https://{API}/bytes/{HUGE}"))
            .send()
            .await
            .unwrap();
        let mut stream = res.bytes_stream();
        let mut read = 0u64;
        while read < 1024 * 1024 {
            read += stream.next().await.unwrap().unwrap().len() as u64;
        }

        tokio::time::sleep(Duration::from_millis(1000)).await;
        let stalled_at = setup.mock.bytes_produced();
        tokio::time::sleep(Duration::from_millis(500)).await;

        assert!(
            stalled_at < BOUND,
            "{downstream:?}/{alpn:?} read {stalled_at} bytes ahead of a stalled client"
        );
        assert_eq!(setup.mock.bytes_produced(), stalled_at);
        drop(stream);
    }
}

#[tokio::test]
async fn trailers_are_relayed_to_h2_clients() {
    for alpn in [Alpn::H1Only, Alpn::H2Only] {
        let setup = Setup::new(Downstream::Http2, alpn).await;
        let mut sender = h2_over_proxy(
            setup.proxy.local_addr(),
            &format!("{API}:443"),
            setup.roots(),
        )
        .await;
        let mut request = get(format!("https://{API}/trailers"));
        request
            .headers_mut()
            .insert("te", "trailers".parse().unwrap());

        let response = sender.send_request(request).await.unwrap();
        let collected = response.into_body().collect().await.unwrap();
        let trailers = collected.trailers().cloned().expect("trailers missing");

        assert_eq!(trailers.get("grpc-status").unwrap(), "0", "{alpn:?}");
        assert_eq!(trailers.get("x-request-te").unwrap(), "trailers");
        assert_eq!(collected.to_bytes(), TRAILER_BODY.as_bytes());
    }
}

#[tokio::test]
async fn trailers_are_relayed_to_h1_clients_that_accept_them() {
    for alpn in [Alpn::H1Only, Alpn::H2Only] {
        let setup = Setup::new(Downstream::Http1, alpn).await;
        let mut tls = setup.tls().await;

        let response = exchange(
            &mut tls,
            &format!(
                "GET /trailers HTTP/1.1\r\nHost: {API}\r\nTE: trailers\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains(TRAILER_BODY), "{response}");
        assert!(
            response.contains("grpc-status: 0\r\n"),
            "{alpn:?}: {response}"
        );
    }
}

#[tokio::test]
async fn h2_streams_run_concurrently_and_only_the_misdirected_one_is_rejected() {
    for alpn in [Alpn::H1Only, Alpn::H2Only] {
        let setup = Setup::new(Downstream::Http2, alpn).await;
        let sender = h2_over_proxy(
            setup.proxy.local_addr(),
            &format!("{API}:443"),
            setup.roots(),
        )
        .await;

        let slow = {
            let mut sender = sender.clone();
            tokio::spawn(async move {
                let response = sender
                    .send_request(get(format!("https://{API}/sse?count=3&interval_ms=300")))
                    .await
                    .unwrap();
                let status = response.status();
                let body = response.into_body().collect().await.unwrap().to_bytes();
                (status, body)
            })
        };
        eventually("the slow stream to reach upstream", || {
            setup.mock.request_count() == 1
        })
        .await;
        let mut authorized = get(format!("https://{API}/v1/echo"));
        authorized
            .headers_mut()
            .insert("authorization", format!("Bearer {DUMMY}").parse().unwrap());
        let echo = sender.clone().send_request(authorized);
        let misdirected = sender
            .clone()
            .send_request(get(format!("https://{OTHER}/v1/echo")));
        let spoofed_host = {
            let mut request = get(format!("https://{API}/v1/echo"));
            request.headers_mut().insert("host", OTHER.parse().unwrap());
            sender.clone().send_request(request)
        };

        let started = std::time::Instant::now();
        let (echo, misdirected, spoofed_host) = tokio::join!(echo, misdirected, spoofed_host);
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "streams were serialized"
        );
        assert_eq!(misdirected.unwrap().status(), 421);
        assert_eq!(spoofed_host.unwrap().status(), 421);
        let echo: Echo = serde_json::from_slice(
            &echo
                .unwrap()
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes(),
        )
        .unwrap();
        assert_eq!(
            echo.header("authorization"),
            Some(format!("Bearer {}", setup.secret).as_str())
        );
        let (status, body) = slow.await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(String::from_utf8_lossy(&body).matches("data: ").count(), 3);
        assert_eq!(setup.mock.request_count(), 2, "{alpn:?}");
    }
}

async fn open_websocket(
    setup: &Setup,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    tokio_tungstenite::tungstenite::Error,
> {
    let (tcp, head) = connect(setup.proxy.local_addr(), &format!("{API}:443")).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let tls = tls_with_alpn(tcp, setup.roots(), API, b"http/1.1")
        .await
        .unwrap();
    let mut request = format!("wss://{API}/ws").into_client_request().unwrap();
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {DUMMY}").parse().unwrap());
    tokio_tungstenite::client_async(request, tls)
        .await
        .map(|(ws, _)| ws)
}

#[tokio::test]
async fn websocket_echo_works_with_the_credential_injected() {
    let logs = capture_logs();
    let setup = Setup::new(Downstream::Http1, Alpn::Both).await;

    let mut ws = open_websocket(&setup).await.unwrap();

    let hello = ws.next().await.unwrap().unwrap();
    let hello: serde_json::Value = serde_json::from_str(hello.to_text().unwrap()).unwrap();
    assert_eq!(hello["authorization"], format!("Bearer {}", setup.secret));
    for text in ["one", "two"] {
        ws.send(Message::text(text)).await.unwrap();
        assert_eq!(ws.next().await.unwrap().unwrap(), Message::text(text));
    }
    ws.send(Message::binary(vec![0u8, 1, 2])).await.unwrap();
    assert_eq!(
        ws.next().await.unwrap().unwrap(),
        Message::binary(vec![0u8, 1, 2])
    );
    ws.close(None).await.unwrap();
    let contents = logs.contents();
    let proxy_lines: Vec<&str> = contents
        .lines()
        .filter(|line| !line.contains("tungstenite::"))
        .collect();
    assert!(proxy_lines.iter().any(|line| line.contains("status=101")));
    for needle in [setup.secret.as_str(), DUMMY] {
        assert!(!proxy_lines.iter().any(|line| line.contains(needle)));
    }
}

#[tokio::test]
async fn websocket_to_an_h2_only_upstream_is_502() {
    let setup = Setup::new(Downstream::Http1, Alpn::H2Only).await;

    let err = open_websocket(&setup).await.err().unwrap();

    match err {
        tokio_tungstenite::tungstenite::Error::Http(response) => {
            assert_eq!(response.status(), 502)
        }
        other => panic!("unexpected error {other:?}"),
    }
}

#[tokio::test]
async fn non_websocket_upgrades_are_forwarded_as_plain_requests() {
    let setup = Setup::new(Downstream::Http1, Alpn::H1Only).await;
    let mut tls = setup.tls().await;

    let response = exchange(
        &mut tls,
        &format!(
            "GET /h2c HTTP/1.1\r\nHost: {API}\r\nConnection: upgrade, close\r\nUpgrade: h2c\r\nAuthorization: Bearer {DUMMY}\r\n\r\n"
        ),
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let echo: Echo = serde_json::from_str(&common::http1_body(&response)).unwrap();
    assert_eq!(echo.header("upgrade"), None);
    assert_eq!(
        echo.header("authorization"),
        Some(format!("Bearer {}", setup.secret).as_str())
    );
}
