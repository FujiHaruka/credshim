use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri, Version};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{any, get, post};
use futures_util::{Stream, StreamExt};
use http_body_util::StreamBody;
use hyper::body::Frame;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::ca::LeafCert;
use crate::pattern;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alpn {
    Both,
    H1Only,
    H2Only,
}

#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: Method,
    pub uri: Uri,
    pub version: Version,
    pub headers: HeaderMap,
}

#[derive(Default)]
struct Shared {
    requests: Mutex<Vec<RecordedRequest>>,
    sse_streams_closed: AtomicUsize,
    bytes_produced: AtomicU64,
}

pub struct MockUpstreamBuilder {
    tls: Option<LeafCert>,
    alpn: Alpn,
}

pub struct MockUpstream {
    addr: SocketAddr,
    tls: bool,
    shared: Arc<Shared>,
    accept_loop: JoinHandle<()>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(from = "EchoWire", into = "EchoWire")]
pub struct Echo {
    pub method: String,
    pub path: String,
    pub authority: Option<String>,
    pub query: Option<String>,
    pub version: String,
    pub headers: BTreeMap<String, Vec<String>>,
    pub body: String,
    pub body_len: usize,
}

#[derive(Serialize, Deserialize)]
struct EchoWire {
    method: String,
    path: String,
    authority: Option<String>,
    query_hex: Option<String>,
    version: String,
    headers_hex: BTreeMap<String, Vec<String>>,
    body_hex: String,
    body_len: usize,
}

fn unhex(value: &str) -> String {
    String::from_utf8_lossy(&hex::decode(value).expect("echo fields are hex")).into_owned()
}

impl From<Echo> for EchoWire {
    fn from(echo: Echo) -> Self {
        Self {
            method: echo.method,
            path: echo.path,
            authority: echo.authority,
            query_hex: echo.query.map(hex::encode),
            version: echo.version,
            headers_hex: echo
                .headers
                .into_iter()
                .map(|(name, values)| (name, values.into_iter().map(hex::encode).collect()))
                .collect(),
            body_hex: hex::encode(echo.body),
            body_len: echo.body_len,
        }
    }
}

impl From<EchoWire> for Echo {
    fn from(wire: EchoWire) -> Self {
        Self {
            method: wire.method,
            path: wire.path,
            authority: wire.authority,
            query: wire.query_hex.as_deref().map(unhex),
            version: wire.version,
            headers: wire
                .headers_hex
                .into_iter()
                .map(|(name, values)| (name, values.iter().map(|v| unhex(v)).collect()))
                .collect(),
            body: unhex(&wire.body_hex),
            body_len: wire.body_len,
        }
    }
}

impl Echo {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .and_then(|v| v.first())
            .map(String::as_str)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UploadSummary {
    pub len: u64,
    pub sha256: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SseTick {
    pub seq: u64,
    pub sent_at_us: u128,
}

impl MockUpstream {
    pub fn http() -> MockUpstreamBuilder {
        MockUpstreamBuilder {
            tls: None,
            alpn: Alpn::Both,
        }
    }

    pub fn https(leaf: LeafCert) -> MockUpstreamBuilder {
        MockUpstreamBuilder {
            tls: Some(leaf),
            alpn: Alpn::Both,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn url(&self, host: &str, path: &str) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        format!("{scheme}://{host}:{}{path}", self.addr.port())
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.shared.requests.lock().unwrap().clone()
    }

    pub fn request_count(&self) -> usize {
        self.shared.requests.lock().unwrap().len()
    }

    pub fn sse_streams_closed(&self) -> usize {
        self.shared.sse_streams_closed.load(Ordering::SeqCst)
    }

    pub fn bytes_produced(&self) -> u64 {
        self.shared.bytes_produced.load(Ordering::SeqCst)
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        self.accept_loop.abort();
    }
}

impl MockUpstreamBuilder {
    pub fn alpn(mut self, alpn: Alpn) -> Self {
        self.alpn = alpn;
        self
    }

    pub async fn start(self) -> MockUpstream {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
        let addr = listener.local_addr().unwrap();
        let shared = Arc::new(Shared::default());
        let router = router(shared.clone());
        let acceptor = self.tls.as_ref().map(|leaf| {
            let protocols: &[&[u8]] = match self.alpn {
                Alpn::Both => &[b"h2", b"http/1.1"],
                Alpn::H1Only => &[b"http/1.1"],
                Alpn::H2Only => &[b"h2"],
            };
            TlsAcceptor::from(leaf.server_config(protocols))
        });
        let alpn = self.alpn;
        let accept_loop = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    continue;
                };
                let router = router.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match acceptor {
                        Some(acceptor) => {
                            if let Ok(tls) = acceptor.accept(tcp).await {
                                serve(tls, router, alpn).await;
                            }
                        }
                        None => serve(tcp, router, alpn).await,
                    }
                });
            }
        });
        MockUpstream {
            addr,
            tls: self.tls.is_some(),
            shared,
            accept_loop,
        }
    }
}

async fn serve<S>(stream: S, router: Router, alpn: Alpn)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder = match alpn {
        Alpn::Both => builder,
        Alpn::H1Only => builder.http1_only(),
        Alpn::H2Only => builder.http2_only(),
    };
    let _ = builder
        .serve_connection_with_upgrades(TokioIo::new(stream), TowerToHyperService::new(router))
        .await;
}

fn router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/sse", get(sse))
        .route("/bytes/{len}", get(bytes))
        .route("/trailers", any(trailers))
        .route("/upload", post(upload))
        .route("/ws", any(websocket))
        .route("/status/{code}", any(status))
        .route("/reflect", post(reflect))
        .route("/v1/chat/completions", post(chat_completions))
        .fallback(echo)
        .layer(middleware::from_fn_with_state(shared.clone(), record))
        .with_state(shared)
}

async fn record(State(shared): State<Arc<Shared>>, req: Request, next: Next) -> Response {
    shared.requests.lock().unwrap().push(RecordedRequest {
        method: req.method().clone(),
        uri: req.uri().clone(),
        version: req.version(),
        headers: req.headers().clone(),
    });
    next.run(req).await
}

async fn echo(
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
    body: Bytes,
) -> Json<Echo> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in &headers {
        map.entry(name.as_str().to_string())
            .or_default()
            .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
    }
    let authority = uri.authority().map(ToString::to_string).or_else(|| {
        headers
            .get("host")
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
    });
    Json(Echo {
        method: method.to_string(),
        path: uri.path().to_string(),
        authority,
        query: uri.query().map(str::to_string),
        version: format!("{version:?}"),
        headers: map,
        body: String::from_utf8_lossy(&body).into_owned(),
        body_len: body.len(),
    })
}

#[derive(Deserialize)]
struct ReflectParams {
    chunk: Option<usize>,
    interval_ms: Option<u64>,
    header: Option<String>,
    encoding: Option<String>,
}

async fn reflect(Query(params): Query<ReflectParams>, body: Bytes) -> Response {
    let size = params.chunk.unwrap_or(body.len()).max(1);
    let interval = Duration::from_millis(params.interval_ms.unwrap_or(0));
    let chunks: Vec<Bytes> = body.chunks(size).map(Bytes::copy_from_slice).collect();
    let stream = async_stream::stream! {
        for (i, chunk) in chunks.into_iter().enumerate() {
            if i > 0 && !interval.is_zero() {
                tokio::time::sleep(interval).await;
            }
            yield Ok::<_, Infallible>(chunk);
        }
    };
    let mut response = Response::builder()
        .header("content-type", "application/octet-stream")
        .header("content-length", body.len());
    if let Some(value) = params.header {
        response = response.header("x-reflected", value);
    }
    if let Some(encoding) = params.encoding {
        response = response.header("content-encoding", encoding);
    }
    response.body(Body::from_stream(stream)).unwrap()
}

async fn status(Path(code): Path<u16>) -> StatusCode {
    StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST)
}

#[derive(Deserialize)]
struct SseParams {
    count: Option<u64>,
    interval_ms: Option<u64>,
}

struct CloseCounter(Arc<Shared>);

impl Drop for CloseCounter {
    fn drop(&mut self) {
        self.0.sse_streams_closed.fetch_add(1, Ordering::SeqCst);
    }
}

async fn sse(
    State(shared): State<Arc<Shared>>,
    Query(params): Query<SseParams>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let count = params.count.unwrap_or(5);
    let interval = Duration::from_millis(params.interval_ms.unwrap_or(100));
    let stream = async_stream::stream! {
        let _guard = CloseCounter(shared);
        for seq in 0..count {
            if seq > 0 {
                tokio::time::sleep(interval).await;
            }
            let tick = SseTick { seq, sent_at_us: now_us() };
            yield Ok(Event::default().data(serde_json::to_string(&tick).unwrap()));
        }
    };
    Sse::new(stream)
}

pub fn now_us() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros()
}

async fn bytes(State(shared): State<Arc<Shared>>, Path(len): Path<u64>) -> Response {
    let stream = pattern::chunks(len, 64 * 1024).map(move |chunk| {
        shared
            .bytes_produced
            .fetch_add(chunk.len() as u64, Ordering::SeqCst);
        Ok::<_, Infallible>(chunk)
    });
    Response::builder()
        .header("content-type", "application/octet-stream")
        .header("content-length", len)
        .body(Body::from_stream(stream))
        .unwrap()
}

pub const TRAILER_BODY: &str = "trailer body";

async fn trailers(headers: HeaderMap) -> Response {
    let te = headers
        .get("te")
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .unwrap_or_default();
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", "0".parse().unwrap());
    trailers.insert("x-request-te", te.parse().unwrap());
    let frames = futures_util::stream::iter([
        Ok::<_, Infallible>(Frame::data(Bytes::from_static(TRAILER_BODY.as_bytes()))),
        Ok(Frame::trailers(trailers)),
    ]);
    Response::builder()
        .header("trailer", "grpc-status, x-request-te")
        .body(Body::new(StreamBody::new(frames)))
        .unwrap()
}

async fn upload(body: Body) -> Result<Json<UploadSummary>, StatusCode> {
    let mut hasher = Sha256::new();
    let mut len = 0u64;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
        len += chunk.len() as u64;
        hasher.update(&chunk);
    }
    Ok(Json(UploadSummary {
        len,
        sha256: hex::encode(hasher.finalize()),
    }))
}

async fn websocket(ws: WebSocketUpgrade, headers: HeaderMap) -> impl IntoResponse {
    let authorization = headers
        .get("authorization")
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
    ws.on_upgrade(move |socket| echo_socket(socket, authorization))
}

async fn echo_socket(mut socket: WebSocket, authorization: Option<String>) {
    let hello = serde_json::json!({ "authorization": authorization }).to_string();
    if socket.send(Message::Text(hello.into())).await.is_err() {
        return;
    }
    while let Some(Ok(msg)) = socket.recv().await {
        let reply = match msg {
            Message::Text(_) | Message::Binary(_) => msg,
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) => continue,
        };
        if socket.send(reply).await.is_err() {
            break;
        }
    }
}

pub const MOCK_COMPLETION: &str = "hello from mock";

async fn chat_completions(Json(request): Json<serde_json::Value>) -> Response {
    let model = request["model"].as_str().unwrap_or("mock").to_string();
    if request["stream"].as_bool() != Some(true) {
        return Json(serde_json::json!({
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "created": 0,
            "model": model,
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": MOCK_COMPLETION },
                "finish_reason": "stop",
            }],
            "usage": { "prompt_tokens": 1, "completion_tokens": 3, "total_tokens": 4 },
        }))
        .into_response();
    }
    let chunk = |delta: serde_json::Value, finish: Option<&str>| {
        serde_json::json!({
            "id": "chatcmpl-mock",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": model,
            "choices": [{ "index": 0, "delta": delta, "finish_reason": finish }],
        })
        .to_string()
    };
    let mut events = vec![chunk(
        serde_json::json!({ "role": "assistant", "content": "" }),
        None,
    )];
    events.extend(
        MOCK_COMPLETION
            .split_inclusive(' ')
            .map(|piece| chunk(serde_json::json!({ "content": piece }), None)),
    );
    events.push(chunk(serde_json::json!({}), Some("stop")));
    events.push("[DONE]".to_string());
    let stream = async_stream::stream! {
        for data in events {
            yield Ok::<_, Infallible>(Event::default().data(data));
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    Sse::new(stream).into_response()
}
