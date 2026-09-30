mod common;

use std::os::unix::fs::PermissionsExt;
use std::process::Output;

use common::{openai_rule, output, spawn_run, store_secret, write_config};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

async fn credshim(args: &[&str]) -> Output {
    let home = tempfile::tempdir().unwrap();
    output(home.path(), args).await
}

fn path_arg(dir: &tempfile::TempDir) -> String {
    dir.path().join("ca").display().to_string()
}

#[tokio::test]
async fn ca_init_writes_a_private_key_only_the_owner_can_read() {
    let dir = tempfile::tempdir().unwrap();
    let ca_dir = path_arg(&dir);

    let output = credshim(&["ca", "init", "--dir", &ca_dir]).await;

    assert!(output.status.success(), "{output:?}");
    let printed = String::from_utf8(output.stdout).unwrap();
    assert_eq!(printed.trim(), format!("{ca_dir}/ca.pem"));
    let key_mode = std::fs::metadata(format!("{ca_dir}/ca-key.pem"))
        .unwrap()
        .permissions()
        .mode();
    let dir_mode = std::fs::metadata(&ca_dir).unwrap().permissions().mode();
    assert_eq!(key_mode & 0o777, 0o600);
    assert_eq!(dir_mode & 0o777, 0o700);
    let cert = std::fs::read_to_string(format!("{ca_dir}/ca.pem")).unwrap();
    assert!(cert.contains("BEGIN CERTIFICATE"));
    assert!(!cert.contains("PRIVATE KEY"));
}

#[tokio::test]
async fn ca_init_refuses_to_replace_an_existing_ca() {
    let dir = tempfile::tempdir().unwrap();
    let ca_dir = path_arg(&dir);
    assert!(
        credshim(&["ca", "init", "--dir", &ca_dir])
            .await
            .status
            .success()
    );
    let key_before = std::fs::read(format!("{ca_dir}/ca-key.pem")).unwrap();

    let output = credshim(&["ca", "init", "--dir", &ca_dir]).await;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already exists"));
    assert_eq!(
        std::fs::read(format!("{ca_dir}/ca-key.pem")).unwrap(),
        key_before
    );
}

#[tokio::test]
async fn ca_bundle_appends_the_dev_ca_to_the_os_roots_without_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let ca_dir = path_arg(&dir);
    assert!(
        credshim(&["ca", "init", "--dir", &ca_dir])
            .await
            .status
            .success()
    );
    let dev_ca = std::fs::read_to_string(format!("{ca_dir}/ca.pem")).unwrap();
    let out = dir.path().join("bundle.pem");

    let stdout = credshim(&["ca", "bundle", "--dir", &ca_dir]).await;
    let to_file = credshim(&[
        "ca",
        "bundle",
        "--dir",
        &ca_dir,
        "--out",
        out.to_str().unwrap(),
    ])
    .await;

    assert!(stdout.status.success(), "{stdout:?}");
    assert!(to_file.status.success(), "{to_file:?}");
    let bundle = String::from_utf8(stdout.stdout).unwrap();
    assert_eq!(std::fs::read_to_string(&out).unwrap(), bundle);
    assert!(bundle.contains(dev_ca.trim()));
    assert!(bundle.matches("BEGIN CERTIFICATE").count() > 1);
    assert!(!bundle.contains("PRIVATE KEY"));
}

#[tokio::test]
async fn run_with_rules_needs_an_existing_ca() {
    let home = tempfile::tempdir().unwrap();
    store_secret(home.path(), "openai", "real");
    let config = write_config(home.path(), &openai_rule("api.example.test", 443));

    let output = output(
        home.path(),
        &["run", "--listen", "127.0.0.1:0", "--config", &config],
    )
    .await;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("credshim ca init"));
}

#[tokio::test]
async fn rule_host_with_an_unverifiable_upstream_is_502() {
    let home = tempfile::tempdir().unwrap();
    let ca_dir = home.path().join("ca").display().to_string();
    assert!(
        credshim(&["ca", "init", "--dir", &ca_dir])
            .await
            .status
            .success()
    );
    let mock = credshim_testkit::MockUpstream::https(
        credshim_testkit::TestCa::new().issue(&["localhost"]),
    )
    .start()
    .await;
    store_secret(home.path(), "openai", "real");
    let config = write_config(home.path(), &openai_rule("localhost", mock.port()));
    let proxy = spawn_run(
        home.path(),
        &["--listen", "127.0.0.1:0", "--config", &config],
    )
    .await;

    let mut tcp = TcpStream::connect(&proxy.addr).await.unwrap();
    let target = format!("localhost:{}", mock.port());
    tcp.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = String::new();
    BufReader::new(&mut tcp).read_line(&mut head).await.unwrap();

    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    assert_eq!(mock.request_count(), 0);
}
