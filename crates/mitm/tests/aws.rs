mod common;

use std::sync::Arc;

use bytes::Bytes;
use common::{connect, read_head, tls_over};
use credshim_aws::{Aws, AwsCredentials, AwsKeySpec, AwsRule, Signer};
use credshim_core::{InjectSpec, Injector, RuleSet, RuleSpec, Secrets};
use credshim_mitm::{CertificateAuthority, Intercept, Proxy, ProxyConfig, TestingHooks, Upstream};
use credshim_testkit::aws::{UNSIGNED_PAYLOAD, client_sign};
use credshim_testkit::{
    AwsKeys, ClientPayload, MockAws, MockUpstream, TestCa, capture_logs, fake_secret,
    install_crypto_provider, pattern,
};
use futures_util::StreamExt;
use http::{HeaderMap, HeaderValue, StatusCode};
use rustls::RootCertStore;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

const REGION: &str = "ap-northeast-1";
const STS: &str = "sts.ap-northeast-1.amazonaws.com";
const DYNAMODB: &str = "dynamodb.ap-northeast-1.amazonaws.com";
const LAMBDA: &str = "lambda.ap-northeast-1.amazonaws.com";
const BUCKET: &str = "credshim-bucket";
const S3: &str = "credshim-bucket.s3.ap-northeast-1.amazonaws.com";
const IAM: &str = "iam.amazonaws.com";
const COGNITO: &str = "cognito-identity.ap-northeast-1.amazonaws.com";
const OPENAI: &str = "api.openai.com";
const AWS_HOSTS: [&str; 6] = [STS, DYNAMODB, LAMBDA, S3, IAM, COGNITO];

const DUMMY: &str = "CREDSHIMDUMMYAWSACCESSKEY0001";
const OPENAI_DUMMY: &str = "sk-credshim-openai-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const MAX_BODY: usize = 64 * 1024;

struct Fixture {
    proxy: Proxy,
    dev_ca: Arc<CertificateAuthority>,
    mock: MockAws,
    other: MockUpstream,
    real: AwsKeys,
    dummy: AwsKeys,
    _dir: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> Self {
        install_crypto_provider();
        let upstream_ca = TestCa::new();
        let real = AwsKeys {
            access_key_id: format!("AKIA{}", fake_secret("akid")),
            secret_access_key: fake_secret("aws-secret"),
        };
        let dummy = AwsKeys {
            access_key_id: DUMMY.to_string(),
            secret_access_key: "credshim-dummy-secret-not-sent".to_string(),
        };
        let mock = MockAws::start(upstream_ca.issue(&AWS_HOSTS), real.clone()).await;
        let other = MockUpstream::https(upstream_ca.issue(&[OPENAI]))
            .start()
            .await;
        let dir = tempfile::tempdir().unwrap();
        let dev_ca = Arc::new(CertificateAuthority::init(dir.path()).unwrap());
        let mut overrides: std::collections::HashMap<String, std::net::SocketAddr> = AWS_HOSTS
            .iter()
            .map(|host| (host.to_string(), mock.addr()))
            .collect();
        overrides.insert(OPENAI.to_string(), other.addr());
        let upstream = Upstream::with_testing_hooks(TestingHooks {
            extra_trust_anchors: vec![upstream_ca.cert_der()],
            resolve_overrides: overrides,
        })
        .unwrap();

        let rules = AwsRule::from_specs(&[AwsKeySpec {
            name: "aws-dev".into(),
            dummy_access_key_id: DUMMY.into(),
            access_key_id: "aws-dev-akid".into(),
            secret_access_key: "aws-dev-secret".into(),
            services: Some(vec![
                "sts".into(),
                "s3".into(),
                "dynamodb".into(),
                "iam".into(),
            ]),
            regions: None,
        }])
        .unwrap();
        let mut signer = Signer::default();
        signer.insert(
            "aws-dev",
            DUMMY,
            AwsCredentials::new(
                SecretString::from(real.access_key_id.as_str()),
                SecretString::from(real.secret_access_key.as_str()),
                None,
            ),
        );
        let scrub = signer.scrub_pairs();
        let aws = Arc::new(Aws::new(rules, signer).with_max_body(MAX_BODY));

        let core = RuleSet::new(vec![RuleSpec {
            name: "openai".into(),
            host: OPENAI.into(),
            port: None,
            path_prefix: None,
            allow_methods: None,
            allow_paths: None,
            limits: Default::default(),
            base_url_prefix: None,
            env: None,
            secret: "openai".into(),
            dummy: OPENAI_DUMMY.into(),
            inject: InjectSpec {
                header: Some("authorization".into()),
                ..InjectSpec::default()
            },
        }])
        .unwrap();
        let mut secrets = Secrets::new();
        secrets.insert("openai", SecretString::from(fake_secret("openai")));
        let injector = Arc::new(Injector::new(core, secrets).unwrap().also_scrub(scrub));

        let mut config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
        config.intercept = Some(
            Intercept::new(dev_ca.clone(), injector.rules().hosts())
                .with_domains([credshim_aws::AWS_DOMAIN]),
        );
        config.injector = injector;
        config.aws = Some(aws);
        let proxy = Proxy::bind(config, upstream).await.unwrap();
        Self {
            proxy,
            dev_ca,
            mock,
            other,
            real,
            dummy,
            _dir: dir,
        }
    }

    fn client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{}", self.proxy.local_addr())).unwrap())
            .tls_certs_only([
                reqwest::Certificate::from_der(self.dev_ca.cert_der().as_ref()).unwrap(),
            ])
            .http1_only()
            .build()
            .unwrap()
    }

    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.dev_ca.cert_der().clone()).unwrap();
        roots
    }

    async fn send(
        &self,
        method: &str,
        host: &str,
        path: &str,
        service: &str,
        mut headers: HeaderMap,
        body: Body,
    ) -> (StatusCode, HeaderMap, Bytes) {
        let url = format!("https://{host}{path}");
        let (payload, body) = match &body {
            Body::Hashed(bytes) => (ClientPayload::Bytes(bytes), bytes.clone()),
            Body::Unsigned(bytes) => (ClientPayload::Unsigned, bytes.clone()),
        };
        client_sign(
            method,
            &url,
            &mut headers,
            payload,
            &self.dummy,
            REGION,
            service,
        );
        let response = self
            .client()
            .request(method.parse().unwrap(), &url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        (status, headers, response.bytes().await.unwrap())
    }

    async fn query(&self, host: &str, service: &str, form: &str) -> (StatusCode, Bytes) {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=utf-8"),
        );
        let body = form.as_bytes().to_vec();
        let (status, _, bytes) = self
            .send(
                "POST",
                host,
                "/",
                service,
                headers,
                Body::Hashed(body.clone()),
            )
            .await;
        (status, bytes)
    }

    fn verified(&self) -> usize {
        self.mock
            .requests()
            .iter()
            .filter(|request| request.verdict.is_ok())
            .count()
    }

    fn secrets(&self) -> [&str; 2] {
        [&self.real.access_key_id, &self.real.secret_access_key]
    }
}

enum Body {
    Hashed(Vec<u8>),
    Unsigned(Vec<u8>),
}

fn text(bytes: &Bytes) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[tokio::test]
async fn query_protocol_request_signed_with_the_dummy_is_resigned_and_echoes_are_scrubbed() {
    let logs = capture_logs();
    let f = Fixture::new().await;
    let (status, body) = f
        .query(STS, "sts", "Action=GetCallerIdentity&Version=2011-06-15")
        .await;
    assert_eq!(status, StatusCode::OK, "{}", text(&body));
    let body = text(&body);
    assert!(body.contains("<Account>123456789012</Account>"), "{body}");
    assert!(body.contains(DUMMY), "{body}");
    assert!(!body.contains(&f.real.access_key_id), "{body}");
    let requests = f.mock.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].verdict, Ok(()));
    let auth = requests[0].headers["authorization"].to_str().unwrap();
    assert!(auth.contains(&format!("Credential={}/", f.real.access_key_id)));
    let contents = logs.contents();
    assert!(contents.contains("service=sts"), "{contents}");
    assert!(contents.contains("region=ap-northeast-1"), "{contents}");
    assert!(
        contents.contains("operation=GetCallerIdentity"),
        "{contents}"
    );
    assert!(contents.contains("decision=\"resign\""), "{contents}");
    logs.assert_absent(&f.secrets());
}

#[tokio::test]
async fn json_protocol_request_is_resigned() {
    let logs = capture_logs();
    let f = Fixture::new().await;
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/x-amz-json-1.0"),
    );
    headers.insert(
        "x-amz-target",
        HeaderValue::from_static("DynamoDB_20120810.ListTables"),
    );
    let body = b"{}".to_vec();
    let (status, _, bytes) = f
        .send(
            "POST",
            DYNAMODB,
            "/",
            "dynamodb",
            headers,
            Body::Hashed(body.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{}", text(&bytes));
    assert_eq!(text(&bytes), "{\"TableNames\":[\"credshim\"]}");
    assert_eq!(f.verified(), 1);
    assert!(logs.contents().contains("operation=ListTables"));
    logs.assert_absent(&f.secrets());
}

#[tokio::test]
async fn rest_xml_s3_requests_are_resigned_with_their_declared_payload_hash() {
    let logs = capture_logs();
    let f = Fixture::new().await;
    let object = "日本語 と spaces.txt";
    let path = format!(
        "/{}",
        percent_encoding::utf8_percent_encode(object, percent_encoding::NON_ALPHANUMERIC)
    );
    let content = b"hello from credshim".to_vec();
    let (status, headers, bytes) = f
        .send(
            "PUT",
            S3,
            &path,
            "s3",
            HeaderMap::new(),
            Body::Hashed(content.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{}", text(&bytes));
    assert!(headers.contains_key("etag"));
    assert_eq!(f.mock.object(BUCKET, object), Some(content.clone()));

    let (status, _, bytes) = f
        .send(
            "GET",
            S3,
            "/?list-type=2&prefix=",
            "s3",
            HeaderMap::new(),
            Body::Hashed(Vec::new()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{}", text(&bytes));
    assert!(text(&bytes).contains("<ListBucketResult"));

    let (status, _, bytes) = f
        .send(
            "GET",
            S3,
            &path,
            "s3",
            HeaderMap::new(),
            Body::Unsigned(Vec::new()),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes.as_ref(), content.as_slice());
    assert_eq!(f.verified(), 3);
    logs.assert_absent(&f.secrets());
}

fn aws_chunked(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in data.chunks(64 * 1024) {
        out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\nx-amz-checksum-crc64nvme:AAAAAAAAAAA=\r\n\r\n");
    out
}

#[tokio::test]
async fn s3_aws_chunked_upload_with_expect_continue_streams_past_the_body_limit() {
    let logs = capture_logs();
    let f = Fixture::new().await;
    let data: Vec<u8> = (0..2 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let encoded = aws_chunked(&data);
    let mut headers = HeaderMap::new();
    headers.insert("content-encoding", HeaderValue::from_static("aws-chunked"));
    headers.insert(
        "x-amz-decoded-content-length",
        HeaderValue::from(data.len()),
    );
    headers.insert(
        "x-amz-trailer",
        HeaderValue::from_static("x-amz-checksum-crc64nvme"),
    );
    let url = format!("https://{S3}/big.bin");
    client_sign(
        "PUT",
        &url,
        &mut headers,
        ClientPayload::StreamingUnsignedTrailer,
        &f.dummy,
        REGION,
        "s3",
    );
    let mut head = format!("PUT /big.bin HTTP/1.1\r\nhost: {S3}\r\n");
    for (name, value) in &headers {
        head.push_str(&format!("{name}: {}\r\n", value.to_str().unwrap()));
    }
    head.push_str("expect: 100-continue\r\ntransfer-encoding: chunked\r\n\r\n");

    let (tcp, connected) = connect(f.proxy.local_addr(), &format!("{S3}:443")).await;
    assert!(connected.starts_with("HTTP/1.1 200"), "{connected}");
    let mut tls = tls_over(tcp, f.roots(), S3, true).await.unwrap();
    tls.write_all(head.as_bytes()).await.unwrap();
    let interim = read_head(&mut tls).await;
    assert!(interim.starts_with("HTTP/1.1 100"), "{interim}");
    for piece in encoded.chunks(256 * 1024) {
        tls.write_all(format!("{:x}\r\n", piece.len()).as_bytes())
            .await
            .unwrap();
        tls.write_all(piece).await.unwrap();
        tls.write_all(b"\r\n").await.unwrap();
    }
    tls.write_all(b"0\r\n\r\n").await.unwrap();
    let response = read_head(&mut tls).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert_eq!(f.mock.object(BUCKET, "big.bin"), Some(data));
    assert_eq!(f.verified(), 1);
    logs.assert_absent(&f.secrets());
}

#[tokio::test]
async fn s3_download_streams_a_large_object_intact() {
    let f = Fixture::new().await;
    let len = 24 * 1024 * 1024u64;
    let url = format!("https://{S3}/generated/{len}");
    let mut headers = HeaderMap::new();
    client_sign(
        "GET",
        &url,
        &mut headers,
        ClientPayload::Bytes(b""),
        &f.dummy,
        REGION,
        "s3",
    );
    let response = f.client().get(&url).headers(headers).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.unwrap();
        total += chunk.len() as u64;
        hasher.update(&chunk);
    }
    assert_eq!(total, len);
    assert_eq!(hex::encode(hasher.finalize()), pattern::sha256_hex(len));
}

#[tokio::test]
async fn signed_chunk_uploads_and_oversized_non_s3_bodies_never_reach_aws() {
    let logs = capture_logs();
    let f = Fixture::new().await;
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-amz-content-sha256",
        HeaderValue::from_static("STREAMING-AWS4-HMAC-SHA256-PAYLOAD"),
    );
    let url = format!("https://{S3}/signed.bin");
    client_sign(
        "PUT",
        &url,
        &mut headers,
        ClientPayload::Unsigned,
        &f.dummy,
        REGION,
        "s3",
    );
    headers.insert(
        "x-amz-content-sha256",
        HeaderValue::from_static("STREAMING-AWS4-HMAC-SHA256-PAYLOAD"),
    );
    let response = f
        .client()
        .put(&url)
        .headers(headers)
        .body("0;chunk-signature=00\r\n\r\n")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let form = format!("Action=GetCallerIdentity&Pad={}", "x".repeat(MAX_BODY + 1));
    let (status, _) = f.query(STS, "sts", &form).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(f.mock.requests().is_empty());
    let contents = logs.contents();
    assert!(contents.contains("reason=\"signed_chunks\""), "{contents}");
    assert!(contents.contains("reason=\"body_too_large\""), "{contents}");
}

#[tokio::test]
async fn dummy_sent_outside_aws_is_refused_before_leaving_the_proxy() {
    let f = Fixture::new().await;
    let mut headers = HeaderMap::new();
    client_sign(
        "GET",
        &format!("https://{OPENAI}/v1/models"),
        &mut headers,
        ClientPayload::Bytes(b""),
        &f.dummy,
        REGION,
        "sts",
    );
    let response = f
        .client()
        .get(format!("https://{OPENAI}/v1/models"))
        .headers(headers.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(f.other.requests().is_empty());

    let plain = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{}", f.proxy.local_addr())).unwrap())
        .build()
        .unwrap()
        .get(format!("http://{STS}/"))
        .headers(headers)
        .send()
        .await
        .unwrap();
    assert_eq!(plain.status(), StatusCode::FORBIDDEN);
    assert!(f.mock.requests().is_empty());
}

#[tokio::test]
async fn credential_issuing_operations_are_refused() {
    let logs = capture_logs();
    let f = Fixture::new().await;
    for form in [
        "Action=AssumeRole&RoleArn=arn%3Aaws%3Aiam%3A%3A1%3Arole%2Fx&RoleSessionName=s",
        "Action=GetSessionToken",
        "Action=GetFederationToken&Name=x",
    ] {
        let (status, _) = f.query(STS, "sts", form).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{form}");
    }
    let (status, _) = f
        .query(IAM, "iam", "Action=CreateAccessKey&UserName=x")
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = f
        .send(
            "GET",
            S3,
            "/?session",
            "s3",
            HeaderMap::new(),
            Body::Hashed(Vec::new()),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(f.mock.requests().is_empty());
    assert!(logs.contents().contains("reason=\"credential_operation\""));
}

#[tokio::test]
async fn unsigned_credential_apis_are_refused_without_any_rule_matching() {
    let logs = capture_logs();
    let f = Fixture::new().await;
    let client = f.client();
    for body in [
        "Action=AssumeRoleWithWebIdentity&RoleArn=x&WebIdentityToken=t",
        "Action=AssumeRoleWithSAML&SAMLAssertion=x",
    ] {
        let response = client
            .post(format!("https://{STS}/"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{body}");
    }
    let response = client
        .post(format!("https://{COGNITO}/"))
        .header(
            "x-amz-target",
            "AWSCognitoIdentityService.GetCredentialsForIdentity",
        )
        .body("{\"IdentityId\":\"x\"}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(f.mock.requests().is_empty());

    for host in [
        "oidc.ap-northeast-1.amazonaws.com",
        "portal.sso.ap-northeast-1.amazonaws.com",
        "ap-northeast-1.signin.aws.amazon.com",
        "ap-northeast-1.oauth.signin.aws",
    ] {
        let (_, head) = connect(f.proxy.local_addr(), &format!("{host}:443")).await;
        assert!(head.starts_with("HTTP/1.1 403"), "{host}: {head}");
    }
    let contents = logs.contents();
    assert!(contents.contains("reason=\"unsigned_credential_operation\""));
    assert!(contents.contains("reason=\"sso_oidc\""));

    let response = client
        .post(format!("https://{STS}/"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=GetCallerIdentity")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(f.mock.requests().len(), 1);
    assert!(f.mock.requests()[0].verdict.is_err());
}

#[tokio::test]
async fn services_outside_the_rule_are_refused() {
    let f = Fixture::new().await;
    let body = b"{}".to_vec();
    let (status, _, _) = f
        .send(
            "GET",
            LAMBDA,
            "/2015-03-31/functions/",
            "lambda",
            HeaderMap::new(),
            Body::Hashed(body.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(f.mock.requests().is_empty());
}

#[tokio::test]
async fn a_scope_that_names_another_service_is_rejected_by_aws_after_resigning() {
    let f = Fixture::new().await;
    let (status, body) = f.query(STS, "dynamodb", "Action=GetCallerIdentity").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{}", text(&body));
    let requests = f.mock.requests();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0]
            .verdict
            .as_ref()
            .is_err_and(|err| err.contains("scoped to dynamodb")),
        "{:?}",
        requests[0].verdict
    );
}

#[tokio::test]
async fn unsigned_s3_payload_marker_is_forwarded_verbatim() {
    let f = Fixture::new().await;
    let content = b"unsigned body".to_vec();
    let url = format!("https://{S3}/unsigned.txt");
    let mut headers = HeaderMap::new();
    client_sign(
        "PUT",
        &url,
        &mut headers,
        ClientPayload::Unsigned,
        &f.dummy,
        REGION,
        "s3",
    );
    assert_eq!(headers["x-amz-content-sha256"], UNSIGNED_PAYLOAD);
    let response = f
        .client()
        .put(&url)
        .headers(headers)
        .body(content.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(f.mock.object(BUCKET, "unsigned.txt"), Some(content));
}

#[tokio::test]
async fn aws_hosts_without_a_dummy_pass_through_untouched() {
    let f = Fixture::new().await;
    let mut headers = HeaderMap::new();
    let other = AwsKeys {
        access_key_id: "AKIAOTHERKEYNOTMANAGED".into(),
        secret_access_key: "other".into(),
    };
    let body = b"{}".to_vec();
    let url = format!("https://{DYNAMODB}/");
    headers.insert(
        "x-amz-target",
        HeaderValue::from_static("DynamoDB_20120810.ListTables"),
    );
    client_sign(
        "POST",
        &url,
        &mut headers,
        ClientPayload::Bytes(&body),
        &other,
        REGION,
        "dynamodb",
    );
    let sent = headers["authorization"].clone();
    let response = f
        .client()
        .post(&url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let requests = f.mock.requests();
    assert_eq!(requests[0].headers["authorization"], sent);
}
