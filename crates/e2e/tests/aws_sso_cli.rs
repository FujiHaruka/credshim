use std::collections::HashMap;
use std::path::Path;
use std::process::Output;
use std::sync::Arc;
use std::time::Duration;

use credshim_aws::{
    Aws, AwsRule, AwsSsoRoleSpec, Signer, SsoOptions, SsoProvider, SsoSession, SsoSessionSpec,
};
use credshim_core::{Injector, RuleSet, Secrets};
use credshim_mitm::{
    CertificateAuthority, Intercept, Proxy, ProxyConfig, TestingHooks, Upstream, UpstreamTransport,
};
use credshim_secrets::{AgeFileStore, SecretStore};
use credshim_testkit::{
    Keyring, LogCapture, MockAws, MockSso, MockSsoConfig, TestCa, capture_logs,
    install_crypto_provider,
};
use tokio::process::Command;

const REGION: &str = "ap-northeast-1";
const STS: &str = "sts.ap-northeast-1.amazonaws.com";
const DYNAMODB: &str = "dynamodb.ap-northeast-1.amazonaws.com";
const OIDC: &str = "oidc.ap-northeast-1.amazonaws.com";
const PORTAL: &str = "portal.sso.ap-northeast-1.amazonaws.com";
const SESSION: &str = "work";
const DUMMY: &str = "CREDSHIMAWSSSOE2EDUMMYKEY01";

struct Fixture {
    _proxy: Proxy,
    proxy_addr: std::net::SocketAddr,
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
        let ca_dir = dir.path().join("ca");
        let dev_ca = Arc::new(CertificateAuthority::init(&ca_dir).unwrap());
        std::fs::write(
            dir.path().join("bundle.pem"),
            credshim_mitm::ca::trust_bundle(&ca_dir).unwrap(),
        )
        .unwrap();
        let aws_dir = dir.path().join(".aws");
        std::fs::create_dir(&aws_dir).unwrap();
        std::fs::write(
            aws_dir.join("credentials"),
            format!(
                "[default]\naws_access_key_id = {DUMMY}\naws_secret_access_key = credshim-dummy-secret\n"
            ),
        )
        .unwrap();
        std::fs::write(
            aws_dir.join("config"),
            format!("[default]\nregion = {REGION}\noutput = json\n"),
        )
        .unwrap();

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
            start_url: "https://credshim-e2e.awsapps.com/start".into(),
            region: REGION.into(),
        }])
        .unwrap();
        let rules = AwsRule::from_config(
            &[],
            &[AwsSsoRoleSpec {
                name: "aws-sso".into(),
                dummy_access_key_id: DUMMY.into(),
                session: SESSION.into(),
                account_id: "123456789012".into(),
                role_name: "Developer".into(),
                services: None,
                regions: None,
            }],
            &sessions,
        )
        .unwrap();
        let roles: Vec<_> = rules
            .iter()
            .filter_map(|rule| match rule.source() {
                credshim_aws::Source::Sso(role) => Some((
                    rule.name().to_string(),
                    role.clone(),
                    rule.dummy().to_string(),
                )),
                credshim_aws::Source::Static { .. } => None,
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
        let mut proxy_config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
        proxy_config.intercept = Some(
            Intercept::new(dev_ca, std::iter::empty::<&str>())
                .with_domains([credshim_aws::AWS_DOMAIN]),
        );
        proxy_config.injector = Arc::new(injector);
        proxy_config.aws = Some(Arc::new(
            Aws::new(rules, Signer::default()).with_sso(provider),
        ));
        let proxy = Proxy::bind(proxy_config, upstream).await.unwrap();
        Self {
            proxy_addr: proxy.local_addr(),
            _proxy: proxy,
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

    async fn aws(&self, args: &[&str]) -> Output {
        let mut command = Command::new("aws");
        for (name, _) in std::env::vars_os() {
            let name = name.to_string_lossy().into_owned();
            if name.starts_with("AWS_") || name.to_ascii_lowercase().ends_with("_proxy") {
                command.env_remove(&name);
            }
        }
        let aws_dir = self.dir.path().join(".aws");
        command
            .args(args)
            .env("HOME", self.dir.path())
            .env("AWS_SHARED_CREDENTIALS_FILE", aws_dir.join("credentials"))
            .env("AWS_CONFIG_FILE", aws_dir.join("config"))
            .env("AWS_CA_BUNDLE", self.dir.path().join("bundle.pem"))
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env("AWS_PAGER", "")
            .env("AWS_MAX_ATTEMPTS", "1")
            .env("HTTPS_PROXY", format!("http://{}", self.proxy_addr))
            .kill_on_drop(true)
            .output()
            .await
            .expect("the aws CLI v2 is not on PATH")
    }

    fn assert_nothing_leaked(&self, logs: &LogCapture, outputs: &[&Output]) {
        let secrets = self.sso.issued_secrets();
        assert!(!secrets.is_empty());
        let needles: Vec<&str> = secrets.iter().map(String::as_str).collect();
        logs.assert_absent(&needles);
        for output in outputs {
            let all = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            for needle in &needles {
                assert!(
                    !all.contains(needle),
                    "a real SSO credential reached the CLI"
                );
            }
        }
        assert_absent_on_disk(self.dir.path(), &needles);
        assert!(!self.dir.path().join(".aws/sso").exists());
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

fn succeeded(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

fn failed_with_login_hint(output: &Output) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("CredShimSsoLoginRequired"), "{stderr}");
    assert!(stderr.contains("credshim aws sso login work"), "{stderr}");
}

fn quick(refresh_before: Duration) -> SsoOptions {
    SsoOptions {
        refresh_before,
        store_recheck: Duration::ZERO,
    }
}

#[tokio::test]
#[ignore = "needs the aws CLI v2; run with `mise exec -- cargo test -p credshim-e2e -- --ignored`"]
async fn aws_cli_uses_an_sso_role_after_a_credshim_login_with_only_a_dummy_profile() {
    let logs = capture_logs();
    let f = Fixture::new(MockSsoConfig::default(), SsoOptions::default()).await;

    let before = f.aws(&["sts", "get-caller-identity"]).await;
    failed_with_login_hint(&before);
    let tables_before = f.aws(&["dynamodb", "list-tables"]).await;
    failed_with_login_hint(&tables_before);
    assert!(f.aws.requests().is_empty());

    f.login().await;
    let identity = f.aws(&["sts", "get-caller-identity"]).await;
    let stdout = succeeded(&identity);
    assert!(stdout.contains(DUMMY), "{stdout}");
    let tables = f.aws(&["dynamodb", "list-tables"]).await;
    assert!(succeeded(&tables).contains("\"credshim\""));
    for request in f.aws.requests() {
        assert_eq!(request.verdict, Ok(()), "{}", request.host);
    }
    f.assert_nothing_leaked(&logs, &[&before, &tables_before, &identity, &tables]);
}

#[tokio::test]
#[ignore = "needs the aws CLI v2; run with `mise exec -- cargo test -p credshim-e2e -- --ignored`"]
async fn aws_cli_keeps_working_while_role_credentials_expire_and_are_replaced() {
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

    let mut outputs = Vec::new();
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(7) {
        let output = f.aws(&["sts", "get-caller-identity"]).await;
        succeeded(&output);
        outputs.push(output);
    }

    assert!(f.sso.counts().role_credentials >= 3, "{:?}", f.sso.counts());
    assert!(
        f.aws
            .requests()
            .iter()
            .all(|request| request.verdict.is_ok())
    );
    let outputs: Vec<&Output> = outputs.iter().collect();
    f.assert_nothing_leaked(&logs, &outputs);
}

#[tokio::test]
#[ignore = "needs the aws CLI v2; run with `mise exec -- cargo test -p credshim-e2e -- --ignored`"]
async fn aws_cli_reports_an_expired_sso_login_and_recovers_after_logging_in_again() {
    let logs = capture_logs();
    let f = Fixture::new(
        MockSsoConfig {
            access_token_lifetime: Duration::from_secs(3),
            issue_refresh_tokens: false,
            ..MockSsoConfig::default()
        },
        quick(Duration::from_secs(1)),
    )
    .await;
    f.login().await;
    succeeded(&f.aws(&["sts", "get-caller-identity"]).await);
    let reached = f.aws.requests().len();

    tokio::time::sleep(Duration::from_secs(3)).await;
    let expired = f.aws(&["sts", "get-caller-identity"]).await;
    failed_with_login_hint(&expired);
    assert_eq!(f.aws.requests().len(), reached);

    f.login().await;
    let recovered = f.aws(&["sts", "get-caller-identity"]).await;
    assert!(succeeded(&recovered).contains(DUMMY));
    f.assert_nothing_leaked(&logs, &[&expired, &recovered]);
}
