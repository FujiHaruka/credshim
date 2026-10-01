use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use credshim_aws::sso::{LogoutOutcome, Transport};
use credshim_aws::{
    Aws, AwsRule, AwsSsoRoleSpec, Signer, SsoOptions, SsoProvider, SsoSession, SsoSessionSpec,
};
use credshim_core::{Injector, RuleSet, Secrets};
use credshim_mitm::{
    CertificateAuthority, Intercept, Proxy, ProxyConfig, TestingHooks, Upstream, UpstreamTransport,
};
use credshim_secrets::{AgeFileStore, SecretStore};
use credshim_testkit::aws::client_sign;
use credshim_testkit::{
    AwsKeys, ClientPayload, Keyring, LogCapture, MockAws, MockSso, MockSsoConfig, TestCa,
    capture_logs, install_crypto_provider,
};
use http::{HeaderMap, HeaderValue, StatusCode};

const REGION: &str = "ap-northeast-1";
const STS: &str = "sts.ap-northeast-1.amazonaws.com";
const DYNAMODB: &str = "dynamodb.ap-northeast-1.amazonaws.com";
const OIDC: &str = "oidc.ap-northeast-1.amazonaws.com";
const PORTAL: &str = "portal.sso.ap-northeast-1.amazonaws.com";
const START_URL: &str = "https://credshim-test.awsapps.com/start";
const SESSION: &str = "work";
const RULE: &str = "aws-sso-dev";
const DUMMY: &str = "CREDSHIMSSODUMMYACCESSKEY01";

struct Fixture {
    proxy: Proxy,
    dev_ca: Arc<CertificateAuthority>,
    aws: MockAws,
    sso: MockSso,
    session: SsoSession,
    store: Arc<dyn SecretStore>,
    transport: Arc<UpstreamTransport>,
    dir: tempfile::TempDir,
}

impl Fixture {
    async fn new(config: MockSsoConfig, options: SsoOptions) -> Self {
        install_crypto_provider();
        let upstream_ca = TestCa::new();
        let keyring = Keyring::default();
        let aws = MockAws::start_with(upstream_ca.issue(&[STS, DYNAMODB]), keyring.clone()).await;
        let sso = MockSso::start(upstream_ca.issue(&[OIDC, PORTAL]), keyring, config).await;
        let dir = tempfile::tempdir().unwrap();
        let dev_ca = Arc::new(CertificateAuthority::init(&dir.path().join("ca")).unwrap());
        let mut overrides: HashMap<String, std::net::SocketAddr> = [STS, DYNAMODB]
            .iter()
            .map(|host| (host.to_string(), aws.addr()))
            .collect();
        overrides.insert(OIDC.to_string(), sso.addr());
        overrides.insert(PORTAL.to_string(), sso.addr());
        let upstream = Upstream::with_testing_hooks(TestingHooks {
            extra_trust_anchors: vec![upstream_ca.cert_der()],
            resolve_overrides: overrides,
        })
        .unwrap();
        let sessions = SsoSession::from_specs(&[SsoSessionSpec {
            name: SESSION.into(),
            start_url: START_URL.into(),
            region: REGION.into(),
        }])
        .unwrap();
        let rules = AwsRule::from_config(
            &[],
            &[AwsSsoRoleSpec {
                name: RULE.into(),
                dummy_access_key_id: DUMMY.into(),
                session: SESSION.into(),
                account_id: "123456789012".into(),
                role_name: "Developer".into(),
                services: None,
                regions: None,
                operations: None,
                limits: Default::default(),
            }],
            &sessions,
        )
        .unwrap();
        let roles: Vec<_> = rules
            .iter()
            .map(|rule| match rule.source() {
                credshim_aws::Source::Sso(role) => (
                    rule.name().to_string(),
                    role.clone(),
                    rule.dummy().to_string(),
                ),
                credshim_aws::Source::Static { .. } => unreachable!(),
            })
            .collect();
        let store: Arc<dyn SecretStore> =
            Arc::new(AgeFileStore::new(dir.path().join("secrets.age"), None));
        let transport = Arc::new(UpstreamTransport::new(upstream.clone()));
        let provider = Arc::new(SsoProvider::new(
            sessions.clone(),
            roles,
            store.clone(),
            transport.clone(),
            options,
        ));
        let injector = Injector::new(RuleSet::default(), Secrets::new())
            .unwrap()
            .with_scrub_source(provider.clone());
        let mut config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
        config.intercept = Some(
            Intercept::new(dev_ca.clone(), std::iter::empty::<&str>())
                .with_domains([credshim_aws::AWS_DOMAIN]),
        );
        config.injector = Arc::new(injector);
        config.aws = Some(Arc::new(
            Aws::new(rules, Signer::default()).with_sso(provider),
        ));
        let proxy = Proxy::bind(config, upstream).await.unwrap();
        Self {
            proxy,
            dev_ca,
            aws,
            sso,
            session: sessions.into_iter().next().unwrap(),
            store,
            transport,
            dir,
        }
    }

    async fn login(&self) {
        let sso = &self.sso;
        credshim_aws::sso::login(
            &self.session,
            self.transport.as_ref(),
            self.store.as_ref(),
            |prompt| sso.approve(&prompt.user_code),
        )
        .await
        .unwrap();
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

    async fn caller_identity(&self) -> (StatusCode, String) {
        let body = b"Action=GetCallerIdentity&Version=2011-06-15".to_vec();
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=utf-8"),
        );
        self.send(STS, "sts", headers, body).await
    }

    async fn list_tables(&self) -> (StatusCode, String) {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/x-amz-json-1.0"),
        );
        headers.insert(
            "x-amz-target",
            HeaderValue::from_static("DynamoDB_20120810.ListTables"),
        );
        self.send(DYNAMODB, "dynamodb", headers, b"{}".to_vec())
            .await
    }

    async fn send(
        &self,
        host: &str,
        service: &str,
        mut headers: HeaderMap,
        body: Vec<u8>,
    ) -> (StatusCode, String) {
        let url = format!("https://{host}/");
        client_sign(
            "POST",
            &url,
            &mut headers,
            ClientPayload::Bytes(&body),
            &AwsKeys {
                access_key_id: DUMMY.into(),
                secret_access_key: "credshim-dummy-secret".into(),
            },
            REGION,
            service,
        );
        let response = self
            .client()
            .post(&url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .unwrap();
        let status = response.status();
        (status, response.text().await.unwrap())
    }

    fn stored(&self) -> Option<String> {
        use secrecy::ExposeSecret;
        self.store
            .get(&self.session.secret_name())
            .unwrap()
            .map(|secret| secret.expose_secret().to_string())
    }

    fn assert_nothing_leaked(&self, logs: &LogCapture, bodies: &[&str]) {
        let secrets = self.sso.issued_secrets();
        assert!(!secrets.is_empty());
        let needles: Vec<&str> = secrets.iter().map(String::as_str).collect();
        logs.assert_absent(&needles);
        for body in bodies {
            for secret in &needles {
                assert!(
                    !body.contains(secret),
                    "a real SSO credential reached the client"
                );
            }
        }
        assert_absent_on_disk(self.dir.path(), &needles);
    }
}

fn assert_absent_on_disk(dir: &Path, needles: &[&str]) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            assert_absent_on_disk(&path, needles);
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        for needle in needles {
            assert!(
                !bytes
                    .windows(needle.len())
                    .any(|window| window == needle.as_bytes()),
                "{} holds a real SSO credential in plaintext",
                path.display()
            );
        }
    }
}

fn quick(refresh_before: Duration) -> SsoOptions {
    SsoOptions {
        refresh_before,
        store_recheck: Duration::ZERO,
    }
}

#[tokio::test]
async fn requests_need_a_login_then_use_role_credentials_that_never_reach_the_client() {
    let logs = capture_logs();
    let f = Fixture::new(MockSsoConfig::default(), SsoOptions::default()).await;

    let (status, body) = f.caller_identity().await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body.contains("<Code>CredShimSsoLoginRequired</Code>"),
        "{body}"
    );
    assert!(body.contains("credshim aws sso login work"), "{body}");
    let (status, json) = f.list_tables().await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        json.contains("\"__type\":\"CredShimSsoLoginRequired\""),
        "{json}"
    );
    assert!(f.aws.requests().is_empty());
    assert!(
        logs.contents().contains("reason=\"sso_login_required\""),
        "{}",
        logs.contents()
    );

    f.login().await;
    assert_eq!(f.sso.start_urls(), [START_URL]);

    let (status, body) = f.caller_identity().await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains(DUMMY), "{body}");
    let (status, tables) = f.list_tables().await;
    assert_eq!(status, StatusCode::OK, "{tables}");
    let requests = f.aws.requests();
    assert_eq!(requests.len(), 2);
    for request in &requests {
        assert_eq!(request.verdict, Ok(()), "{}", request.host);
        assert!(request.headers.contains_key("x-amz-security-token"));
    }
    assert_eq!(f.sso.counts().role_credentials, 1);
    f.assert_nothing_leaked(&logs, &[&body, &tables]);
}

#[tokio::test]
async fn role_credentials_are_replaced_before_they_expire_and_no_request_fails() {
    let logs = capture_logs();
    let f = Fixture::new(
        MockSsoConfig {
            role_lifetime: Duration::from_secs(3),
            ..MockSsoConfig::default()
        },
        quick(Duration::from_secs(2)),
    )
    .await;
    f.login().await;

    let mut bodies = Vec::new();
    for _ in 0..12 {
        let (status, body) = f.caller_identity().await;
        assert_eq!(status, StatusCode::OK, "{body}");
        bodies.push(body);
        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    assert!(f.sso.counts().role_credentials >= 3, "{:?}", f.sso.counts());
    assert!(
        f.aws
            .requests()
            .iter()
            .all(|request| request.verdict.is_ok())
    );
    let bodies: Vec<&str> = bodies.iter().map(String::as_str).collect();
    f.assert_nothing_leaked(&logs, &bodies);
}

#[tokio::test]
async fn an_expiring_sso_token_is_refreshed_and_saved_back_encrypted() {
    let logs = capture_logs();
    let f = Fixture::new(
        MockSsoConfig {
            access_token_lifetime: Duration::from_secs(3),
            ..MockSsoConfig::default()
        },
        quick(Duration::from_secs(2)),
    )
    .await;
    f.login().await;
    let first = f.stored().unwrap();

    for _ in 0..8 {
        let (status, body) = f.caller_identity().await;
        assert_eq!(status, StatusCode::OK, "{body}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let counts = f.sso.counts();
    assert!(counts.refreshes >= 1, "{counts:?}");
    assert_eq!(counts.device_tokens, 1);
    assert_ne!(f.stored().unwrap(), first);
    f.assert_nothing_leaked(&logs, &[]);
}

#[tokio::test]
async fn after_the_sso_token_expires_nothing_reaches_aws_until_the_next_login() {
    let logs = capture_logs();
    let f = Fixture::new(
        MockSsoConfig {
            access_token_lifetime: Duration::from_secs(2),
            issue_refresh_tokens: false,
            ..MockSsoConfig::default()
        },
        quick(Duration::from_secs(1)),
    )
    .await;
    f.login().await;
    let (status, _) = f.caller_identity().await;
    assert_eq!(status, StatusCode::OK);
    let reached = f.aws.requests().len();

    tokio::time::sleep(Duration::from_millis(2200)).await;
    let (status, body) = f.caller_identity().await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("credshim aws sso login work"), "{body}");
    assert_eq!(f.aws.requests().len(), reached);

    f.login().await;
    let (status, body) = f.caller_identity().await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(f.aws.requests().len(), reached + 1);
    f.assert_nothing_leaked(&logs, &[&body]);
}

#[tokio::test]
async fn logout_revokes_the_token_and_the_next_role_fetch_needs_a_login() {
    let logs = capture_logs();
    let f = Fixture::new(
        MockSsoConfig {
            role_lifetime: Duration::from_secs(2),
            ..MockSsoConfig::default()
        },
        quick(Duration::from_secs(1)),
    )
    .await;
    f.login().await;
    let (status, _) = f.caller_identity().await;
    assert_eq!(status, StatusCode::OK);

    let outcome = credshim_aws::sso::logout(&f.session, f.transport.as_ref(), f.store.as_ref())
        .await
        .unwrap();
    assert_eq!(outcome, LogoutOutcome::Revoked);
    assert_eq!(f.stored(), None);
    assert_eq!(f.sso.counts().logouts, 1);
    let outcome = credshim_aws::sso::logout(&f.session, f.transport.as_ref(), f.store.as_ref())
        .await
        .unwrap();
    assert_eq!(outcome, LogoutOutcome::NotLoggedIn);

    tokio::time::sleep(Duration::from_millis(1200)).await;
    let reached = f.aws.requests().len();
    let (status, body) = f.caller_identity().await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(f.aws.requests().len(), reached);
    f.assert_nothing_leaked(&logs, &[&body]);
}

#[tokio::test]
async fn clients_still_cannot_reach_the_sso_endpoints_the_proxy_itself_uses() {
    let f = Fixture::new(MockSsoConfig::default(), SsoOptions::default()).await;
    f.login().await;
    let before = f.sso.counts();

    for host in [OIDC, PORTAL] {
        let err = f
            .client()
            .post(format!("https://{host}/token"))
            .send()
            .await
            .unwrap_err();
        assert!(err.is_connect(), "{host}: {err}");
    }
    assert_eq!(f.sso.counts(), before);

    let direct = f
        .transport
        .send(
            http::Request::get(format!("https://{PORTAL}/federation/credentials"))
                .header("host", PORTAL)
                .body(Bytes::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(direct.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(f.sso.counts().role_requests, before.role_requests + 1);
}

#[tokio::test]
async fn a_login_removed_from_the_store_is_never_written_back_by_a_refresh() {
    let f = Fixture::new(
        MockSsoConfig {
            access_token_lifetime: Duration::from_secs(3),
            ..MockSsoConfig::default()
        },
        quick(Duration::from_secs(2)),
    )
    .await;
    f.login().await;
    let (status, _) = f.caller_identity().await;
    assert_eq!(status, StatusCode::OK);

    assert!(f.store.remove(&f.session.secret_name()).unwrap());
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let reached = f.aws.requests().len();
    let (status, body) = f.caller_identity().await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(f.aws.requests().len(), reached);
    assert_eq!(f.stored(), None);
}

#[tokio::test]
async fn logout_after_the_access_token_expired_refreshes_it_to_end_the_session() {
    let f = Fixture::new(
        MockSsoConfig {
            access_token_lifetime: Duration::from_secs(1),
            ..MockSsoConfig::default()
        },
        SsoOptions::default(),
    )
    .await;
    f.login().await;
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let outcome = credshim_aws::sso::logout(&f.session, f.transport.as_ref(), f.store.as_ref())
        .await
        .unwrap();

    assert_eq!(outcome, LogoutOutcome::Revoked);
    assert_eq!(f.sso.counts().refreshes, 1);
    assert_eq!(f.sso.counts().logouts, 1);
    assert_eq!(f.stored(), None);
}

#[tokio::test]
async fn failing_identity_center_calls_are_not_repeated_for_every_request() {
    let f = Fixture::new(
        MockSsoConfig {
            access_token_lifetime: Duration::from_secs(2),
            ..MockSsoConfig::default()
        },
        quick(Duration::from_secs(1)),
    )
    .await;
    f.login().await;
    f.sso
        .fail_role_credentials(Some(StatusCode::INTERNAL_SERVER_ERROR));
    for _ in 0..3 {
        let (status, body) = f.caller_identity().await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        assert!(body.contains("CredShimSsoUnavailable"), "{body}");
    }
    assert_eq!(f.sso.counts().role_requests, 1);

    f.sso.fail_role_credentials(None);
    f.sso.revoke_refresh_tokens();
    tokio::time::sleep(Duration::from_millis(2200)).await;
    let attempts = f.sso.counts().refresh_attempts;
    for _ in 0..3 {
        let (status, _) = f.caller_identity().await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    assert_eq!(f.sso.counts().refresh_attempts, attempts + 1);
    assert!(f.aws.requests().is_empty());
}
