use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{
    PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
    UriPathNormalizationMode, sign,
};
use aws_sigv4::sign::v4;
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use http_body_util::BodyExt;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::ca::LeafCert;
use crate::pattern;

pub const MOCK_ACCOUNT: &str = "123456789012";
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
pub const STREAMING_UNSIGNED_PAYLOAD_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
const GENERATED_PREFIX: &str = "generated/";

#[derive(Clone, Debug)]
pub struct AwsKeys {
    pub access_key_id: String,
    pub secret_access_key: String,
}

#[derive(Clone, Debug)]
pub struct KeyringEntry {
    pub keys: AwsKeys,
    pub session_token: Option<String>,
    pub expires_at: Option<SystemTime>,
}

#[derive(Clone, Debug, Default)]
pub struct Keyring(Arc<Mutex<Vec<KeyringEntry>>>);

impl Keyring {
    pub fn with(keys: AwsKeys) -> Self {
        let keyring = Self::default();
        keyring.add(KeyringEntry {
            keys,
            session_token: None,
            expires_at: None,
        });
        keyring
    }

    pub fn add(&self, entry: KeyringEntry) {
        self.0.lock().unwrap().push(entry);
    }

    pub fn find(&self, access_key_id: &str) -> Option<KeyringEntry> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .find(|entry| entry.keys.access_key_id == access_key_id)
            .cloned()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ClientPayload<'a> {
    Bytes(&'a [u8]),
    Unsigned,
    StreamingUnsignedTrailer,
}

#[derive(Clone, Debug)]
pub struct AwsRequest {
    pub method: Method,
    pub host: String,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body_len: usize,
    pub verdict: Result<(), String>,
}

pub fn client_sign(
    method: &str,
    url: &str,
    headers: &mut HeaderMap,
    payload: ClientPayload<'_>,
    keys: &AwsKeys,
    region: &str,
    service: &str,
) {
    let s3 = service == "s3";
    let signable_headers: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_str().unwrap().to_string()))
        .collect();
    let body = match payload {
        ClientPayload::Bytes(bytes) => SignableBody::Bytes(bytes),
        ClientPayload::Unsigned => SignableBody::UnsignedPayload,
        ClientPayload::StreamingUnsignedTrailer => SignableBody::StreamingUnsignedPayloadTrailer,
    };
    let request = SignableRequest::new(
        method,
        url,
        signable_headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        body,
    )
    .unwrap();
    let mut settings = SigningSettings::default();
    if s3 {
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        settings.percent_encoding_mode = PercentEncodingMode::Single;
        settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    }
    let identity = Credentials::new(
        &keys.access_key_id,
        &keys.secret_access_key,
        None,
        None,
        "testkit",
    )
    .into();
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name(service)
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .unwrap()
        .into();
    let (instructions, _) = sign(request, &params).unwrap().into_parts();
    for (name, value) in instructions.headers() {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
}

struct ParsedAuth {
    access_key_id: String,
    region: String,
    service: String,
    signed_headers: Vec<String>,
    signature: String,
}

fn parse_authorization(headers: &HeaderMap) -> Result<ParsedAuth, String> {
    let value = headers
        .get("authorization")
        .ok_or("MissingAuthenticationToken")?
        .to_str()
        .map_err(|_| "IncompleteSignature")?;
    let fields = value
        .strip_prefix("AWS4-HMAC-SHA256 ")
        .ok_or("IncompleteSignature")?;
    let mut credential = None;
    let mut signed = None;
    let mut signature = None;
    for field in fields.split(',') {
        match field.trim().split_once('=') {
            Some(("Credential", v)) => credential = Some(v),
            Some(("SignedHeaders", v)) => signed = Some(v),
            Some(("Signature", v)) => signature = Some(v),
            _ => return Err("IncompleteSignature".into()),
        }
    }
    let parts: Vec<&str> = credential
        .ok_or("IncompleteSignature")?
        .split('/')
        .collect();
    let [akid, _date, region, service, "aws4_request"] = parts.as_slice() else {
        return Err("IncompleteSignature".into());
    };
    Ok(ParsedAuth {
        access_key_id: akid.to_string(),
        region: region.to_string(),
        service: service.to_string(),
        signed_headers: signed
            .ok_or("IncompleteSignature")?
            .split(';')
            .map(str::to_string)
            .collect(),
        signature: signature.ok_or("IncompleteSignature")?.to_string(),
    })
}

fn signing_time(headers: &HeaderMap) -> Result<SystemTime, String> {
    let value = headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .ok_or("MissingDate")?;
    let format = time::macros::format_description!("[year][month][day]T[hour][minute][second]Z");
    time::PrimitiveDateTime::parse(value, format)
        .map(|t| t.assume_utc().into())
        .map_err(|_| "MissingDate".into())
}

pub fn verify(
    method: &Method,
    host: &str,
    uri: &Uri,
    headers: &HeaderMap,
    payload_hash: &str,
    keyring: &Keyring,
) -> Result<(), String> {
    let auth = parse_authorization(headers)?;
    let entry = keyring
        .find(&auth.access_key_id)
        .ok_or("InvalidAccessKeyId")?;
    if entry
        .expires_at
        .is_some_and(|expires_at| expires_at <= SystemTime::now())
    {
        return Err("ExpiredToken".into());
    }
    let sent_token = headers
        .get("x-amz-security-token")
        .and_then(|value| value.to_str().ok());
    if sent_token != entry.session_token.as_deref() {
        return Err("InvalidToken".into());
    }
    if entry.session_token.is_some()
        && !auth
            .signed_headers
            .iter()
            .any(|name| name == "x-amz-security-token")
    {
        return Err("SignatureDoesNotMatch: the security token is not signed".into());
    }
    let keys = &entry.keys;
    let expected_service = host_service(host);
    if auth.service != expected_service {
        return Err(format!(
            "SignatureDoesNotMatch: credential scoped to {} but sent to {expected_service}",
            auth.service
        ));
    }
    if let Some(region) = host_region(host)
        && auth.region != region
    {
        return Err(format!(
            "SignatureDoesNotMatch: credential scoped to region {} but sent to {region}",
            auth.region
        ));
    }
    let time = signing_time(headers)?;
    let signed: Vec<(String, String)> =
        auth.signed_headers
            .iter()
            .filter(|name| {
                !matches!(
                    name.as_str(),
                    "host" | "x-amz-date" | "x-amz-security-token"
                )
            })
            .flat_map(|name| {
                headers.get_all(name.as_str()).iter().map(move |value| {
                    (name.clone(), value.to_str().unwrap_or_default().to_string())
                })
            })
            .collect();
    if !auth.signed_headers.iter().any(|name| name == "host") {
        return Err("SignatureDoesNotMatch: host is not signed".into());
    }
    let path = uri.path_and_query().map_or("/", |pq| pq.as_str());
    let request = SignableRequest::new(
        method.as_str(),
        format!("https://{host}{path}"),
        signed.iter().map(|(n, v)| (n.as_str(), v.as_str())),
        SignableBody::Precomputed(payload_hash.to_string()),
    )
    .map_err(|e| e.to_string())?;
    let mut settings = SigningSettings::default();
    settings.excluded_headers = None;
    if auth.service == "s3" {
        settings.percent_encoding_mode = PercentEncodingMode::Single;
        settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    }
    let identity = Credentials::new(
        &keys.access_key_id,
        &keys.secret_access_key,
        entry.session_token.clone(),
        None,
        "testkit",
    )
    .into();
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(&auth.region)
        .name(&auth.service)
        .time(time)
        .settings(settings)
        .build()
        .map_err(|e| e.to_string())?
        .into();
    let signed =
        tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
            sign(request, &params)
        });
    let (_, signature) = signed.map_err(|e| e.to_string())?.into_parts();
    if signature != auth.signature {
        return Err("SignatureDoesNotMatch".into());
    }
    Ok(())
}

pub fn host_service(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').collect();
    if labels.contains(&"s3") {
        "s3".into()
    } else {
        labels.first().copied().unwrap_or_default().to_string()
    }
}

fn host_region(host: &str) -> Option<String> {
    let labels: Vec<&str> = host.strip_suffix(".amazonaws.com")?.split('.').collect();
    let at = labels.iter().position(|label| *label == "s3").unwrap_or(0);
    labels.get(at + 1).map(|region| region.to_string())
}

fn s3_bucket(host: &str) -> Option<String> {
    let (bucket, _) = host.split_once(".s3.")?;
    Some(bucket.to_string())
}

pub fn decode_aws_chunked(raw: &[u8]) -> Result<(Vec<u8>, BTreeMap<String, String>), String> {
    let mut data = Vec::new();
    let mut rest = raw;
    loop {
        let end = find(rest, b"\r\n").ok_or("chunk header is not terminated")?;
        let header = std::str::from_utf8(&rest[..end]).map_err(|_| "chunk header is not UTF-8")?;
        let size_hex = header.split(';').next().unwrap_or_default();
        if header.contains("chunk-signature") {
            return Err("signed chunks are not expected".into());
        }
        let size = usize::from_str_radix(size_hex.trim(), 16).map_err(|_| "bad chunk size")?;
        rest = &rest[end + 2..];
        if size == 0 {
            break;
        }
        if rest.len() < size + 2 || &rest[size..size + 2] != b"\r\n" {
            return Err("chunk is truncated".into());
        }
        data.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
    let mut trailers = BTreeMap::new();
    let text = std::str::from_utf8(rest).map_err(|_| "trailer is not UTF-8")?;
    for line in text.split("\r\n").filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or("bad trailer line")?;
        trailers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    Ok((data, trailers))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

struct Shared {
    keyring: Keyring,
    requests: Mutex<Vec<AwsRequest>>,
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
}

pub struct MockAws {
    addr: SocketAddr,
    shared: Arc<Shared>,
    accept_loop: JoinHandle<()>,
}

impl Drop for MockAws {
    fn drop(&mut self) {
        self.accept_loop.abort();
    }
}

impl MockAws {
    pub async fn start(leaf: LeafCert, keys: AwsKeys) -> Self {
        Self::start_with(leaf, Keyring::with(keys)).await
    }

    pub async fn start_with(leaf: LeafCert, keyring: Keyring) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
        let addr = listener.local_addr().unwrap();
        let shared = Arc::new(Shared {
            keyring,
            requests: Mutex::default(),
            objects: Mutex::default(),
        });
        let router = Router::new().fallback(handle).with_state(shared.clone());
        let acceptor = TlsAcceptor::from(leaf.server_config(&[b"http/1.1"]));
        let accept_loop = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    continue;
                };
                let router = router.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        let _ = auto::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(tls), TowerToHyperService::new(router))
                            .await;
                    }
                });
            }
        });
        Self {
            addr,
            shared,
            accept_loop,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn requests(&self) -> Vec<AwsRequest> {
        self.shared.requests.lock().unwrap().clone()
    }

    pub fn object(&self, bucket: &str, key: &str) -> Option<Vec<u8>> {
        self.shared
            .objects
            .lock()
            .unwrap()
            .get(&format!("{bucket}/{key}"))
            .cloned()
    }

    pub fn put_object(&self, bucket: &str, key: &str, body: Vec<u8>) {
        self.shared
            .objects
            .lock()
            .unwrap()
            .insert(format!("{bucket}/{key}"), body);
    }
}

fn aws_error(status: StatusCode, code: &str) -> Response {
    (
        status,
        [("content-type", "text/xml")],
        format!("<ErrorResponse><Error><Code>{code}</Code></Error></ErrorResponse>"),
    )
        .into_response()
}

async fn handle(State(shared): State<Arc<Shared>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let host = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| parts.uri.host().map(str::to_string))
        .unwrap_or_default();
    let host = host.split(':').next().unwrap_or_default().to_string();
    let raw = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return aws_error(StatusCode::BAD_REQUEST, "IncompleteBody"),
    };
    let checked = payload(&parts.headers, &raw);
    let verdict = match &checked {
        Ok((hash, _)) => verify(
            &parts.method,
            &host,
            &parts.uri,
            &parts.headers,
            hash,
            &shared.keyring,
        ),
        Err(err) => Err(err.clone()),
    };
    shared.requests.lock().unwrap().push(AwsRequest {
        method: parts.method.clone(),
        host: host.clone(),
        uri: parts.uri.clone(),
        headers: parts.headers.clone(),
        body_len: raw.len(),
        verdict: verdict.clone(),
    });
    if let Err(code) = verdict {
        return aws_error(StatusCode::FORBIDDEN, &code);
    }
    let (_, decoded) = checked.expect("verified payload");
    match host_service(&host).as_str() {
        "sts" => sts(&parts.headers, &decoded),
        "dynamodb" => dynamodb(&parts.headers),
        "s3" => s3(&shared, &host, &parts.method, &parts.uri, decoded),
        service => (
            StatusCode::OK,
            [("content-type", "application/json")],
            format!("{{\"service\":\"{service}\"}}"),
        )
            .into_response(),
    }
}

fn payload(headers: &HeaderMap, raw: &Bytes) -> Result<(String, Vec<u8>), String> {
    let actual = hex::encode(Sha256::digest(raw));
    let Some(declared) = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
    else {
        return Ok((actual, raw.to_vec()));
    };
    match declared {
        UNSIGNED_PAYLOAD => Ok((declared.to_string(), raw.to_vec())),
        STREAMING_UNSIGNED_PAYLOAD_TRAILER => {
            let encoding = headers
                .get("content-encoding")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            if !encoding.contains("aws-chunked") {
                return Err("InvalidRequest: aws-chunked content encoding is missing".into());
            }
            let (data, trailers) = decode_aws_chunked(raw)?;
            let expected_len: Option<usize> = headers
                .get("x-amz-decoded-content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok());
            if expected_len != Some(data.len()) {
                return Err("IncompleteBody: decoded length mismatch".into());
            }
            if let Some(trailer) = headers.get("x-amz-trailer").and_then(|v| v.to_str().ok())
                && !trailers.contains_key(&trailer.to_ascii_lowercase())
            {
                return Err("InvalidRequest: declared trailer is missing".into());
            }
            Ok((declared.to_string(), data))
        }
        hash if hash == actual => Ok((actual, raw.to_vec())),
        _ => Err("XAmzContentSHA256Mismatch".into()),
    }
}

fn sts(headers: &HeaderMap, body: &[u8]) -> Response {
    let action = form_urlencoded::parse(body)
        .find(|(key, _)| key == "Action")
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default();
    if action != "GetCallerIdentity" {
        return aws_error(StatusCode::BAD_REQUEST, "InvalidAction");
    }
    let xml = format!(
        "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><GetCallerIdentityResult><Arn>arn:aws:iam::{MOCK_ACCOUNT}:user/credshim</Arn><UserId>{}</UserId><Account>{MOCK_ACCOUNT}</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>credshim</RequestId></ResponseMetadata></GetCallerIdentityResponse>",
        parse_authorization(headers)
            .map(|auth| auth.access_key_id)
            .unwrap_or_default()
    );
    (StatusCode::OK, [("content-type", "text/xml")], xml).into_response()
}

fn dynamodb(headers: &HeaderMap) -> Response {
    let target = headers
        .get("x-amz-target")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if target != "DynamoDB_20120810.ListTables" {
        return aws_error(StatusCode::BAD_REQUEST, "UnknownOperationException");
    }
    (
        StatusCode::OK,
        [("content-type", "application/x-amz-json-1.0")],
        "{\"TableNames\":[\"credshim\"]}",
    )
        .into_response()
}

fn s3(shared: &Shared, host: &str, method: &Method, uri: &Uri, body: Vec<u8>) -> Response {
    let Some(bucket) = s3_bucket(host) else {
        return aws_error(StatusCode::BAD_REQUEST, "InvalidBucketName");
    };
    let key = percent_encoding::percent_decode_str(uri.path().trim_start_matches('/'))
        .decode_utf8_lossy()
        .into_owned();
    let objects = &shared.objects;
    match (method.clone(), key.is_empty()) {
        (Method::GET, true) => {
            let prefix = format!("{bucket}/");
            let contents: String = objects
                .lock()
                .unwrap()
                .iter()
                .filter_map(|(name, data)| {
                    let key = name.strip_prefix(&prefix)?;
                    Some(format!(
                        "<Contents><Key>{key}</Key><LastModified>2026-10-01T00:00:00.000Z</LastModified><ETag>&quot;{}&quot;</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>",
                        etag(data),
                        data.len()
                    ))
                })
                .collect();
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>{bucket}</Name><Prefix></Prefix><KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>{contents}</ListBucketResult>"
            );
            (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
        }
        (Method::PUT, false) => {
            let tag = etag(&body);
            objects
                .lock()
                .unwrap()
                .insert(format!("{bucket}/{key}"), body);
            (StatusCode::OK, [("etag", format!("\"{tag}\""))]).into_response()
        }
        (Method::GET | Method::HEAD, false) => {
            if let Some(len) = key.strip_prefix(GENERATED_PREFIX) {
                let Ok(len) = len.parse::<u64>() else {
                    return aws_error(StatusCode::NOT_FOUND, "NoSuchKey");
                };
                let body = if method == Method::HEAD {
                    Body::empty()
                } else {
                    Body::from_stream(pattern::chunks(len, 64 * 1024).map(Ok::<_, std::io::Error>))
                };
                return Response::builder()
                    .header("content-length", len)
                    .header("etag", "\"generated\"")
                    .header("last-modified", "Thu, 01 Oct 2026 00:00:00 GMT")
                    .body(body)
                    .unwrap();
            }
            let Some(data) = objects
                .lock()
                .unwrap()
                .get(&format!("{bucket}/{key}"))
                .cloned()
            else {
                return aws_error(StatusCode::NOT_FOUND, "NoSuchKey");
            };
            let response = Response::builder()
                .header("content-length", data.len())
                .header("etag", format!("\"{}\"", etag(&data)))
                .header("last-modified", "Thu, 01 Oct 2026 00:00:00 GMT")
                .header("content-type", "binary/octet-stream");
            let body = if method == Method::HEAD {
                Body::empty()
            } else {
                Body::from(data)
            };
            response.body(body).unwrap()
        }
        _ => aws_error(StatusCode::NOT_IMPLEMENTED, "NotImplemented"),
    }
}

fn etag(data: &[u8]) -> String {
    hex::encode(&Sha256::digest(data)[..16])
}
