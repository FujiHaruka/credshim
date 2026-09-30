mod common;

use std::path::Path;

use common::{OPENAI_DUMMY, openai_rule, output, spawn_run, store_secret, write_config};
use credshim_testkit::{MockUpstream, fake_secret};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

async fn ca_init(home: &Path) {
    let ca = home.join("ca").display().to_string();
    assert!(
        output(home, &["ca", "init", "--dir", &ca])
            .await
            .status
            .success()
    );
}

async fn aws_preset(home: &Path) -> String {
    let preset = output(home, &["preset", "aws"]).await;
    assert!(preset.status.success(), "{}", stderr(&preset));
    String::from_utf8(preset.stdout).unwrap()
}

fn dummy_of(preset: &str) -> String {
    preset
        .lines()
        .find_map(|line| line.strip_prefix("dummy_access_key_id = "))
        .unwrap()
        .trim_matches('"')
        .to_string()
}

async fn raw(addr: &str, request: &str) -> String {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    tcp.read_to_string(&mut response).await.unwrap();
    response
}

async fn connect_head(addr: &str, host: &str) -> String {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(tcp.read_u8().await.unwrap());
    }
    String::from_utf8(head).unwrap()
}

#[tokio::test]
async fn the_aws_preset_runs_once_both_secrets_exist_and_keeps_the_dummy_off_plain_http() {
    let home = tempfile::tempdir().unwrap();
    ca_init(home.path()).await;
    let preset = aws_preset(home.path()).await;
    let dummy = dummy_of(&preset);
    assert!(dummy.starts_with("CREDSHIMAWS"), "{dummy}");
    let config = write_config(home.path(), &preset);

    let missing = output(
        home.path(),
        &["run", "--listen", "127.0.0.1:0", "--config", &config],
    )
    .await;
    assert!(!missing.status.success());
    assert!(
        stderr(&missing).contains("credshim secret set aws-access-key-id"),
        "{}",
        stderr(&missing)
    );

    store_secret(home.path(), "aws-access-key-id", "AKIA credshim");
    store_secret(home.path(), "aws-secret-access-key", &fake_secret("aws"));
    let unusable = output(
        home.path(),
        &["run", "--listen", "127.0.0.1:0", "--config", &config],
    )
    .await;
    assert!(!unusable.status.success());
    let message = stderr(&unusable);
    assert!(
        message.contains("aws_key \"aws\" cannot be used"),
        "{message}"
    );
    assert!(!message.contains("AKIA credshim"), "{message}");

    store_secret(
        home.path(),
        "aws-access-key-id",
        &format!("AKIA{}", fake_secret("id")),
    );
    let proxy = spawn_run(
        home.path(),
        &["--listen", "127.0.0.1:0", "--config", &config],
    )
    .await;
    let mock = MockUpstream::http().start().await;
    let target = mock.url("127.0.0.1", "/");
    let response = raw(
        &proxy.addr,
        &format!(
            "GET {target} HTTP/1.1\r\nHost: x\r\nAuthorization: AWS4-HMAC-SHA256 Credential={dummy}/20261001/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=00\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert!(mock.requests().is_empty());
}

#[tokio::test]
async fn aws_key_dummies_must_not_overlap_rule_dummies() {
    let home = tempfile::tempdir().unwrap();
    let config = write_config(
        home.path(),
        &format!(
            "{}\n[[aws_key]]\nname = \"aws\"\ndummy_access_key_id = \"{OPENAI_DUMMY}\"\naccess_key_id = \"a\"\nsecret_access_key = \"b\"\n",
            openai_rule("api.openai.com", 443)
        ),
    );
    let run = output(
        home.path(),
        &["run", "--listen", "127.0.0.1:0", "--config", &config],
    )
    .await;
    assert!(!run.status.success());
    assert!(
        stderr(&run).contains("aws_key \"aws\" and rule \"openai\""),
        "{}",
        stderr(&run)
    );

    let config = write_config(
        home.path(),
        "[[aws_key]]\nname = \"aws\"\ndummy_access_key_id = \"short\"\naccess_key_id = \"a\"\nsecret_access_key = \"b\"\n",
    );
    let run = output(
        home.path(),
        &["run", "--listen", "127.0.0.1:0", "--config", &config],
    )
    .await;
    assert!(!run.status.success());
    assert!(
        stderr(&run).contains("dummy_access_key_id must be"),
        "{}",
        stderr(&run)
    );
}

#[tokio::test]
async fn sso_and_signin_endpoints_are_refused_even_without_aws_config() {
    let home = tempfile::tempdir().unwrap();
    let proxy = spawn_run(home.path(), &["--listen", "127.0.0.1:0"]).await;
    for host in [
        "oidc.us-east-1.amazonaws.com",
        "portal.sso.us-east-1.amazonaws.com",
        "us-east-1.signin.aws.amazon.com",
        "oauth.signin.aws",
    ] {
        let response = connect_head(&proxy.addr, host).await;
        assert!(response.starts_with("HTTP/1.1 403"), "{host}: {response}");
    }
}
