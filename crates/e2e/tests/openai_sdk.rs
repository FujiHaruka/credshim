use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::Arc;

use credshim_core::{InjectSpec, Injector, RuleSet, RuleSpec, Secrets};
use credshim_mitm::{CertificateAuthority, Intercept, Proxy, ProxyConfig, TestingHooks, Upstream};
use credshim_testkit::{
    MOCK_COMPLETION, MockUpstream, TestCa, capture_logs, fake_secret, install_crypto_provider,
};
use secrecy::SecretString;
use tokio::process::Command;

const OPENAI: &str = "api.openai.com";
const DUMMY: &str = "sk-credshim-openai-SDKE2ESDKE2ESDKE2ESDKE2ESDKE2E";

struct Fixture {
    proxy: Proxy,
    mock: MockUpstream,
    secret: String,
    dir: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> Self {
        install_crypto_provider();
        let upstream_ca = TestCa::new();
        let mock = MockUpstream::https(upstream_ca.issue(&[OPENAI]))
            .start()
            .await;
        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join("ca");
        let dev_ca = Arc::new(CertificateAuthority::init(&ca_dir).unwrap());
        std::fs::write(
            dir.path().join("bundle.pem"),
            credshim_mitm::ca::trust_bundle(&ca_dir).unwrap(),
        )
        .unwrap();
        let upstream = Upstream::with_testing_hooks(TestingHooks {
            extra_trust_anchors: vec![upstream_ca.cert_der()],
            resolve_overrides: HashMap::from([(OPENAI.to_string(), mock.addr())]),
        })
        .unwrap();

        let rules = RuleSet::new(vec![RuleSpec {
            name: "openai".into(),
            host: OPENAI.into(),
            port: None,
            path_prefix: None,
            secret: "openai".into(),
            dummy: DUMMY.into(),
            inject: InjectSpec {
                header: Some("authorization".into()),
                ..InjectSpec::default()
            },
        }])
        .unwrap();
        let secret = fake_secret("sdk");
        let mut secrets = Secrets::new();
        secrets.insert("openai", SecretString::from(secret.as_str()));
        let injector = Arc::new(Injector::new(rules, secrets).unwrap());
        let mut config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
        config.intercept = Some(Intercept::new(dev_ca, injector.rules().hosts()));
        config.injector = injector;
        let proxy = Proxy::bind(config, upstream).await.unwrap();
        Self {
            proxy,
            mock,
            secret,
            dir,
        }
    }

    fn sdk_command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        for var in [
            "HTTP_PROXY",
            "http_proxy",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
            "OPENAI_BASE_URL",
            "OPENAI_API_KEY",
        ] {
            command.env_remove(var);
        }
        command
            .env("HTTPS_PROXY", format!("http://{}", self.proxy.local_addr()))
            .env("OPENAI_API_KEY", DUMMY)
            .env("SSL_CERT_FILE", self.dir.path().join("bundle.pem"))
            .env(
                "NODE_EXTRA_CA_CERTS",
                self.dir.path().join("ca").join("ca.pem"),
            )
            .env("NODE_USE_ENV_PROXY", "1")
            .kill_on_drop(true);
        command
    }

    fn assert_sdk_ran_with_the_real_secret(&self, output: &Output) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "stdout: {stdout}\nstderr: {stderr}"
        );
        assert_eq!(stdout, format!("{MOCK_COMPLETION}\n{MOCK_COMPLETION}\n"));
        assert!(!stdout.contains(&self.secret) && !stderr.contains(&self.secret));

        let requests = self.mock.requests();
        assert_eq!(requests.len(), 2, "{requests:#?}");
        for request in requests {
            assert_eq!(request.uri.path(), "/v1/chat/completions");
            assert_eq!(
                request.headers.get("authorization").unwrap(),
                &format!("Bearer {}", self.secret)
            );
        }
    }
}

fn sdk_dir(runtime: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("sdk")
        .join(runtime)
}

async fn run_python(fixture: &Fixture, extra: &[&str]) -> Output {
    fixture
        .sdk_command("uv")
        .args(["run", "--quiet", "--python", "3.13", "chat.py"])
        .args(extra)
        .current_dir(sdk_dir("python"))
        .output()
        .await
        .expect("uv is not installed")
}

#[tokio::test]
#[ignore = "needs uv; run with `cargo test -p credshim-e2e -- --ignored`"]
async fn python_openai_sdk_streams_through_the_proxy() {
    let fixture = Fixture::new().await;

    let output = run_python(&fixture, &[]).await;

    fixture.assert_sdk_ran_with_the_real_secret(&output);
}

#[tokio::test]
#[ignore = "needs uv; run with `cargo test -p credshim-e2e -- --ignored`"]
async fn python_openai_sdk_streams_through_the_proxy_over_http2() {
    let logs = capture_logs();
    let fixture = Fixture::new().await;

    let output = run_python(&fixture, &["--http2"]).await;

    fixture.assert_sdk_ran_with_the_real_secret(&output);
    let contents = logs.contents();
    assert!(
        contents
            .lines()
            .any(|line| line.contains("MITM session established")
                && line.contains(r#"protocol="h2""#)),
        "the SDK did not negotiate h2 with the proxy"
    );
    logs.assert_absent(&[&fixture.secret, DUMMY]);
}

#[tokio::test]
#[ignore = "needs node 24 and `npm ci` in crates/e2e/sdk/node; run with `cargo test -p credshim-e2e -- --ignored`"]
async fn node_openai_sdk_streams_through_the_proxy() {
    let fixture = Fixture::new().await;
    let dir = sdk_dir("node");
    assert!(
        dir.join("node_modules").join("openai").exists(),
        "run `npm ci` in {}",
        dir.display()
    );

    let output = fixture
        .sdk_command("node")
        .arg("chat.mjs")
        .current_dir(dir)
        .output()
        .await
        .expect("node is not installed");

    fixture.assert_sdk_ran_with_the_real_secret(&output);
}
