use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Output;
use std::sync::Arc;

use credshim_aws::{Aws, AwsCredentials, AwsKeySpec, AwsRule, Signer};
use credshim_core::{Injector, RuleSet, Secrets};
use credshim_mitm::{CertificateAuthority, Intercept, Proxy, ProxyConfig, TestingHooks, Upstream};
use credshim_testkit::{
    AwsKeys, MockAws, TestCa, capture_logs, fake_secret, install_crypto_provider,
};
use secrecy::SecretString;
use tokio::process::Command;

const REGION: &str = "ap-northeast-1";
const BUCKET: &str = "credshim-e2e";
const STS: &str = "sts.ap-northeast-1.amazonaws.com";
const DYNAMODB: &str = "dynamodb.ap-northeast-1.amazonaws.com";
const S3: &str = "credshim-e2e.s3.ap-northeast-1.amazonaws.com";
const HOSTS: [&str; 3] = [STS, DYNAMODB, S3];
const DUMMY: &str = "CREDSHIMAWSE2EDUMMYKEY0001";

struct Fixture {
    proxy: Proxy,
    mock: MockAws,
    real: AwsKeys,
    dir: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> Self {
        install_crypto_provider();
        let upstream_ca = TestCa::new();
        let real = AwsKeys {
            access_key_id: format!("AKIA{}", fake_secret("e2e")),
            secret_access_key: fake_secret("e2e-secret"),
        };
        let mock = MockAws::start(upstream_ca.issue(&HOSTS), real.clone()).await;
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

        let upstream = Upstream::with_testing_hooks(TestingHooks {
            extra_trust_anchors: vec![upstream_ca.cert_der()],
            resolve_overrides: HOSTS
                .iter()
                .map(|host| (host.to_string(), mock.addr()))
                .collect::<HashMap<_, _>>(),
        })
        .unwrap();
        let rules = AwsRule::from_specs(&[AwsKeySpec {
            name: "aws".into(),
            dummy_access_key_id: DUMMY.into(),
            access_key_id: "aws-access-key-id".into(),
            secret_access_key: "aws-secret-access-key".into(),
            services: None,
            regions: None,
        }])
        .unwrap();
        let mut signer = Signer::default();
        signer.insert(
            "aws",
            DUMMY,
            AwsCredentials::new(
                SecretString::from(real.access_key_id.as_str()),
                SecretString::from(real.secret_access_key.as_str()),
                None,
            )
            .unwrap(),
        );
        let injector = Injector::new(RuleSet::default(), Secrets::new())
            .unwrap()
            .also_scrub(signer.scrub_pairs());
        let mut config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
        config.intercept = Some(
            Intercept::new(dev_ca, std::iter::empty::<&str>())
                .with_domains([credshim_aws::AWS_DOMAIN]),
        );
        config.injector = Arc::new(injector);
        config.aws = Some(Arc::new(Aws::new(rules, signer)));
        let proxy = Proxy::bind(config, upstream).await.unwrap();
        Self {
            proxy,
            mock,
            real,
            dir,
        }
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
            .env("HTTPS_PROXY", format!("http://{}", self.proxy.local_addr()))
            .kill_on_drop(true)
            .output()
            .await
            .expect("the aws CLI v2 is not on PATH")
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn assert_all_verified(&self) {
        let requests = self.mock.requests();
        assert!(!requests.is_empty());
        for request in requests {
            assert_eq!(
                request.verdict,
                Ok(()),
                "{} {}",
                request.method,
                request.uri
            );
        }
    }

    fn secrets(&self) -> [&str; 2] {
        [&self.real.access_key_id, &self.real.secret_access_key]
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

fn assert_absent(output: &Output, needles: &[&str]) {
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for needle in needles {
        assert!(!all.contains(needle), "a real credential reached the CLI");
    }
}

#[tokio::test]
#[ignore = "needs the aws CLI v2; run with `mise exec -- cargo test -p credshim-e2e -- --ignored`"]
async fn aws_cli_query_and_json_services_work_with_only_a_dummy_profile() {
    let logs = capture_logs();
    let fixture = Fixture::new().await;

    let identity = fixture.aws(&["sts", "get-caller-identity"]).await;
    let stdout = succeeded(&identity);
    assert!(stdout.contains("\"Account\": \"123456789012\""), "{stdout}");
    assert!(stdout.contains(DUMMY), "{stdout}");
    assert_absent(&identity, &fixture.secrets());

    let tables = fixture.aws(&["dynamodb", "list-tables"]).await;
    assert!(succeeded(&tables).contains("\"credshim\""));

    fixture.assert_all_verified();
    logs.assert_absent(&fixture.secrets());
}

#[tokio::test]
#[ignore = "needs the aws CLI v2; run with `mise exec -- cargo test -p credshim-e2e -- --ignored`"]
async fn aws_cli_s3_upload_list_and_download_stream_through_the_proxy() {
    let logs = capture_logs();
    let fixture = Fixture::new().await;
    let data: Vec<u8> = (0..3 * 1024 * 1024u32)
        .map(|i| (i.wrapping_mul(31) % 253) as u8)
        .collect();
    let source = fixture.path("upload.bin");
    std::fs::write(&source, &data).unwrap();
    let object = format!("s3://{BUCKET}/upload.bin");

    let upload = fixture
        .aws(&["s3", "cp", source.to_str().unwrap(), &object])
        .await;
    succeeded(&upload);
    assert_eq!(
        fixture.mock.object(BUCKET, "upload.bin"),
        Some(data.clone())
    );
    let streamed = fixture.mock.requests().into_iter().any(|request| {
        request
            .headers
            .get("x-amz-content-sha256")
            .map(|v| v.as_bytes())
            == Some(b"STREAMING-UNSIGNED-PAYLOAD-TRAILER")
            && request.headers.contains_key("x-amz-trailer")
            && request.headers.get("expect").map(|v| v.as_bytes()) == Some(b"100-continue")
    });
    assert!(
        streamed,
        "the CLI did not upload aws-chunked with a trailer and Expect: 100-continue"
    );

    let listing = fixture.aws(&["s3", "ls", &format!("s3://{BUCKET}/")]).await;
    assert!(succeeded(&listing).contains("upload.bin"));

    let target = fixture.path("download.bin");
    let download = fixture
        .aws(&["s3", "cp", &object, target.to_str().unwrap()])
        .await;
    succeeded(&download);
    assert_eq!(std::fs::read(&target).unwrap(), data);

    fixture.assert_all_verified();
    logs.assert_absent(&fixture.secrets());
}

#[tokio::test]
#[ignore = "needs the aws CLI v2; run with `mise exec -- cargo test -p credshim-e2e -- --ignored`"]
async fn aws_cli_cannot_mint_new_credentials() {
    let fixture = Fixture::new().await;

    let assumed = fixture
        .aws(&[
            "sts",
            "assume-role",
            "--role-arn",
            "arn:aws:iam::123456789012:role/credshim",
            "--role-session-name",
            "e2e",
        ])
        .await;
    assert!(!assumed.status.success());
    let session = fixture.aws(&["sts", "get-session-token"]).await;
    assert!(!session.status.success());
    assert!(fixture.mock.requests().is_empty());
}
