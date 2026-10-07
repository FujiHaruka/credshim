mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use common::{OPENAI_DUMMY, credshim, openai_rule, output, spawn_run, store_secret, write_config};
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
        vec!["env", "--keys", "--config", &config],
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
async fn a_config_named_without_a_directory_still_has_its_directory_checked() {
    let (home, _) = ready_home().await;
    chmod(home.path(), 0o777);

    let output = common::credshim(home.path())
        .current_dir(home.path())
        .args([
            "run",
            "--listen",
            "127.0.0.1:0",
            "--config",
            "credshim.toml",
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .unwrap();
    chmod(home.path(), 0o700);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("directory holding the config file"),
        "{stderr}"
    );
}

#[tokio::test]
async fn a_symlinked_config_has_the_directory_of_its_target_checked() {
    let (home, config) = ready_home().await;
    let shared = home.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    std::fs::rename(&config, shared.join("credshim.toml")).unwrap();
    std::os::unix::fs::symlink(shared.join("credshim.toml"), &config).unwrap();
    chmod(&shared, 0o777);

    let stderr = run_refused(home.path(), &config).await;
    chmod(&shared, 0o700);

    assert!(
        stderr.contains("directory holding the config file"),
        "{stderr}"
    );
}

#[tokio::test]
async fn run_and_env_refuse_ca_certificates_others_could_rewrite() {
    let (home, config) = ready_home().await;
    chmod(&home.path().join("ca/ca.pem"), 0o666);

    let stderr = run_refused(home.path(), &config).await;
    let env = output(home.path(), &["env", "--config", &config]).await;

    assert!(stderr.contains("CA certificate"), "{stderr}");
    assert!(!env.status.success());
    let env_stderr = String::from_utf8_lossy(&env.stderr);
    assert!(env_stderr.contains("CA certificate"), "{env_stderr}");
}

fn write_command_config(home: &Path, program: &str) -> String {
    let config = home.join("command.toml");
    std::fs::write(
        &config,
        format!(
            "[secrets]\nbackend = \"command\"\ncommand = [\"{program}\", \"{{name}}\"]\n\n[ca]\ndir = \"{}\"\n\n{}",
            home.join("ca").display(),
            openai_rule("api.openai.com", 443),
        ),
    )
    .unwrap();
    config.display().to_string()
}

#[tokio::test]
async fn run_refuses_a_secret_store_command_others_could_rewrite() {
    let (home, _) = ready_home().await;
    let program = home.path().join("fetch-secret");
    std::fs::write(&program, "#!/bin/sh\necho value\n").unwrap();
    chmod(&program, 0o777);
    let config = write_command_config(home.path(), &program.display().to_string());

    let stderr = run_refused(home.path(), &config).await;

    assert!(stderr.contains("secret store command"), "{stderr}");
    assert!(stderr.contains("writable by group or others"), "{stderr}");
}

#[tokio::test]
async fn run_resolves_the_secret_store_command_on_path_once_and_checks_that_file() {
    let (home, _) = ready_home().await;
    let bin = home.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let program = bin.join("fetch-secret");
    std::fs::write(&program, "#!/bin/sh\necho value\n").unwrap();
    chmod(&program, 0o755);
    chmod(&bin, 0o777);
    let config = write_command_config(home.path(), "fetch-secret");
    let run_with_path = |path: String| {
        credshim(home.path())
            .env("PATH", path)
            .args(["run", "--listen", "127.0.0.1:0", "--config", &config])
            .stdin(std::process::Stdio::null())
            .output()
    };

    let found = run_with_path(format!("{}:/usr/bin:/bin", bin.display()))
        .await
        .unwrap();
    let missing = run_with_path("/usr/bin:/bin".to_string()).await.unwrap();

    let found = String::from_utf8_lossy(&found.stderr);
    assert!(
        found.contains("the directory holding the secret store command"),
        "{found}"
    );
    assert!(found.contains("writable by group or others"), "{found}");
    let missing = String::from_utf8_lossy(&missing.stderr);
    assert!(
        missing.contains(r#""fetch-secret" is not an executable on PATH"#),
        "{missing}"
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
