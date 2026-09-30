mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use common::{OPENAI_DUMMY, openai_rule, output, spawn_run, store_secret, write_config};
use credshim_testkit::{MockUpstream, fake_secret};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn ca_init(home: &Path) {
    let ca = home.join("ca").display().to_string();
    assert!(
        output(home, &["ca", "init", "--dir", &ca])
            .await
            .status
            .success()
    );
}

async fn ready_home() -> (tempfile::TempDir, String) {
    let home = tempfile::tempdir().unwrap();
    ca_init(home.path()).await;
    store_secret(home.path(), "openai", &fake_secret("harden"));
    let config = write_config(home.path(), &openai_rule("api.openai.com", 443));
    (home, config)
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

async fn run_refused(home: &Path, config: &str) -> String {
    let output = output(
        home,
        &["run", "--listen", "127.0.0.1:0", "--config", config],
    )
    .await;
    assert!(!output.status.success());
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[tokio::test]
async fn run_refuses_a_config_others_could_rewrite() {
    let (home, config) = ready_home().await;
    chmod(Path::new(&config), 0o664);

    let stderr = run_refused(home.path(), &config).await;

    assert!(stderr.contains("config file"), "{stderr}");
    assert!(stderr.contains("writable by group or others"), "{stderr}");
}

#[tokio::test]
async fn every_config_reading_command_refuses_a_config_others_could_rewrite() {
    let (home, config) = ready_home().await;
    chmod(Path::new(&config), 0o664);
    let run_error = run_refused(home.path(), &config).await;

    for args in [
        vec!["secret", "set", "openai", "--config", &config],
        vec!["secret", "list", "--config", &config],
        vec!["env", "--config", &config],
        vec!["status", "--config", &config],
        vec!["tail", "--no-follow", "--config", &config],
    ] {
        let output = output(home.path(), &args).await;

        assert!(!output.status.success(), "{args:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            run_error,
            "{args:?}"
        );
    }
}

#[tokio::test]
async fn run_refuses_a_config_directory_others_could_write() {
    let (home, config) = ready_home().await;
    chmod(home.path(), 0o777);

    let stderr = run_refused(home.path(), &config).await;
    chmod(home.path(), 0o700);

    assert!(
        stderr.contains("directory holding the config file"),
        "{stderr}"
    );
}

#[tokio::test]
async fn run_refuses_secret_store_and_ca_key_others_could_write() {
    for target in ["secrets.age", "secrets.key", "ca/ca-key.pem"] {
        let (home, config) = ready_home().await;
        chmod(&home.path().join(target), 0o666);

        let stderr = run_refused(home.path(), &config).await;

        assert!(
            stderr.contains("writable by group or others"),
            "{target}: {stderr}"
        );
    }
}

#[tokio::test]
async fn run_refuses_secret_files_others_could_read() {
    for target in ["secrets.age", "secrets.key", "ca/ca-key.pem"] {
        let (home, config) = ready_home().await;
        chmod(&home.path().join(target), 0o644);

        let stderr = run_refused(home.path(), &config).await;

        assert!(
            stderr.contains("readable by group or others"),
            "{target}: {stderr}"
        );
    }
}

#[tokio::test]
async fn run_refuses_to_listen_on_every_interface() {
    let (home, config) = ready_home().await;

    let output = output(
        home.path(),
        &["run", "--listen", "0.0.0.0:0", "--config", &config],
    )
    .await;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unspecified address"), "{stderr}");
}

#[tokio::test]
async fn status_socket_reports_rule_names_and_counters_only() {
    let home = tempfile::tempdir().unwrap();
    ca_init(home.path()).await;
    let secret = fake_secret("status");
    store_secret(home.path(), "openai", &secret);
    let socket = home.path().join("status.sock");
    let config = write_config(
        home.path(),
        &format!(
            "[status]\nsocket = \"{}\"\n\n{}",
            socket.display(),
            openai_rule("api.openai.com", 443)
        ),
    );
    let proxy = spawn_run(
        home.path(),
        &["--listen", "127.0.0.1:0", "--config", &config],
    )
    .await;
    let plain = MockUpstream::http().start().await;
    let mut tcp = TcpStream::connect(&proxy.addr).await.unwrap();
    tcp.write_all(
        format!(
            "GET {} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {OPENAI_DUMMY}\r\nConnection: close\r\n\r\n",
            plain.url("127.0.0.1", "/leak")
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut response = String::new();
    tcp.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");

    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let output = output(home.path(), &["status", "--config", &config]).await;
    assert!(output.status.success());
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        status,
        serde_json::json!({
            "rules": {
                "openai": {
                    "injected": 0,
                    "exchanged": 0,
                    "denied": 1,
                    "not_allowed": 0,
                    "limited": 0,
                    "failed": 0
                }
            }
        })
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains(&secret) && !text.contains(OPENAI_DUMMY));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn proxy_memory_and_environment_are_closed_to_the_same_user() {
    let (home, config) = ready_home().await;
    let proxy = spawn_run(
        home.path(),
        &["--listen", "127.0.0.1:0", "--config", &config],
    )
    .await;
    let pid = proxy.child.id().unwrap();

    for file in ["environ", "mem", "maps"] {
        let err = std::fs::read(format!("/proc/{pid}/{file}")).unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "/proc/{pid}/{file}"
        );
    }
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
    let core = limits
        .lines()
        .find(|line| line.starts_with("Max core file size"))
        .unwrap();
    assert!(
        core.split_whitespace().filter(|v| *v == "0").count() >= 2,
        "{core}"
    );
}
