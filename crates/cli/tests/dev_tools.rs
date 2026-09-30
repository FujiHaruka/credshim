mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::Duration;

use common::{OPENAI_DUMMY, output, spawn_run, store_secret};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_credshim");

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Home {
    dir: tempfile::TempDir,
    config: PathBuf,
    port: u16,
}

impl Home {
    async fn new(extra: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca");
        let init = output(dir.path(), &["ca", "init", "--dir", ca.to_str().unwrap()]).await;
        assert!(init.status.success(), "{init:?}");
        let port = free_port();
        let config = dir.path().join("credshim.toml");
        std::fs::write(
            &config,
            format!(
                "[listen]\naddr = \"127.0.0.1:{port}\"\n\n[secrets]\nbackend = \"age-file\"\npath = \"{secrets}\"\n\n[ca]\ndir = \"{ca}\"\n\n{extra}",
                secrets = dir.path().join("secrets.age").display(),
                ca = ca.display(),
            ),
        )
        .unwrap();
        Self { dir, config, port }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn config(&self) -> &str {
        self.config.to_str().unwrap()
    }

    fn bin_dir(&self, programs: &[&str]) -> PathBuf {
        let bin = self.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        for program in programs {
            let found = find_in_path(program).unwrap_or_else(|| panic!("{program} is not on PATH"));
            std::os::unix::fs::symlink(found, bin.join(program)).unwrap();
        }
        bin
    }

    async fn fresh_shell(&self, path: &Path, script: &str) -> Output {
        let mut command = Command::new("/bin/sh");
        for (name, _) in std::env::vars() {
            if name.to_ascii_lowercase().ends_with("_proxy")
                || ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"]
                    .contains(&name.as_str())
                || name.starts_with("NODE_")
            {
                command.env_remove(name);
            }
        }
        command
            .env("PATH", path)
            .env("CREDSHIM", BIN)
            .env("CONFIG", self.config())
            .arg("-c")
            .arg(format!(
                "eval \"$(\"$CREDSHIM\" env --config \"$CONFIG\")\" && {script}"
            ))
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output()
            .await
            .unwrap()
    }
}

fn find_in_path(program: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

fn text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_ok_lines(output: &Output, names: &[&str]) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{}", text(output));
    for name in names {
        assert!(
            stdout
                .lines()
                .any(|line| line.starts_with("[ok  ]") && line.contains(&format!(" {name} "))),
            "{name} did not pass\n{}",
            text(output)
        );
    }
}

#[tokio::test]
async fn env_prints_proxy_ca_and_dummy_variables_for_a_shell() {
    let home = Home::new(&format!(
        "[[rule]]\nname = \"openai\"\nhost = \"api.openai.com\"\nsecret = \"openai\"\ndummy = \"{OPENAI_DUMMY}\"\nenv = \"OPENAI_API_KEY\"\ninject = {{ header = \"authorization\" }}\nbase_url_prefix = \"/openai/\"\n"
    ))
    .await;
    let mut config = std::fs::read_to_string(&home.config).unwrap();
    config = config.replacen(
        "[listen]\n",
        "[listen]\nbase_url_addr = \"127.0.0.1:8788\"\n",
        1,
    );
    std::fs::write(&home.config, config).unwrap();

    let env = output(home.path(), &["env", "--config", home.config()]).await;

    assert!(env.status.success(), "{}", text(&env));
    let stdout = String::from_utf8(env.stdout).unwrap();
    let ca = home.path().join("ca");
    for line in [
        format!("export HTTPS_PROXY='http://127.0.0.1:{}'", home.port),
        format!("export http_proxy='http://127.0.0.1:{}'", home.port),
        "export NO_PROXY='localhost,127.0.0.1,::1'".to_string(),
        format!("export SSL_CERT_FILE='{}'", ca.join("bundle.pem").display()),
        format!(
            "export REQUESTS_CA_BUNDLE='{}'",
            ca.join("bundle.pem").display()
        ),
        format!(
            "export NODE_EXTRA_CA_CERTS='{}'",
            ca.join("ca.pem").display()
        ),
        "export NODE_USE_ENV_PROXY='1'".to_string(),
        format!("export OPENAI_API_KEY='{OPENAI_DUMMY}'"),
        "# base URL for openai: http://127.0.0.1:8788/openai".to_string(),
    ] {
        assert!(
            stdout.lines().any(|l| l == line),
            "missing {line}\n{stdout}"
        );
    }
    assert!(String::from_utf8_lossy(&env.stderr).is_empty());
}

#[tokio::test]
async fn env_names_must_be_environment_variables() {
    let home = Home::new(&format!(
        "[[rule]]\nname = \"openai\"\nhost = \"api.openai.com\"\nsecret = \"openai\"\ndummy = \"{OPENAI_DUMMY}\"\nenv = \"X; rm -rf ~\"\ninject = {{ header = \"authorization\" }}\n"
    ))
    .await;

    let env = output(home.path(), &["env", "--config", home.config()]).await;

    assert!(!env.status.success());
    assert!(text(&env).contains("must be an environment variable name"));
}

#[tokio::test]
async fn curl_passes_doctor_in_a_shell_that_loaded_env() {
    let home = Home::new("").await;
    let _proxy = spawn_run(home.path(), &["--config", home.config()]).await;
    let bin = home.bin_dir(&["curl"]);

    let doctor = home.fresh_shell(&bin, "\"$CREDSHIM\" doctor").await;

    assert_ok_lines(&doctor, &["proxy", "curl"]);
    let stdout = String::from_utf8_lossy(&doctor.stdout);
    for runtime in ["python", "node", "go"] {
        assert!(
            stdout
                .lines()
                .any(|l| l.starts_with("[skip]") && l.contains(runtime)),
            "{stdout}"
        );
    }
    assert!(!stdout.contains("[warn]"), "{stdout}");
}

#[tokio::test]
#[ignore = "needs uv, node 24 and go; run with `mise exec -- cargo test -p credshim --test dev_tools -- --ignored`"]
async fn python_node_and_go_samples_pass_doctor_in_a_shell_that_loaded_env() {
    let home = Home::new("").await;
    let _proxy = spawn_run(home.path(), &["--config", home.config()]).await;
    let bin = home.bin_dir(&["curl", "node", "go", "uv"]);
    let python = std::process::Command::new("uv")
        .args(["python", "find", "3.13"])
        .output()
        .expect("uv is not installed");
    assert!(python.status.success(), "run `uv python install 3.13`");
    let python = String::from_utf8(python.stdout).unwrap();
    std::os::unix::fs::symlink(python.trim(), bin.join("python3")).unwrap();
    let sample = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/doctor/requests_httpx.py");

    let doctor = home
        .fresh_shell(
            &bin,
            &format!(
                "\"$CREDSHIM\" doctor && uv run --quiet --python 3.13 {}",
                sample.display()
            ),
        )
        .await;

    assert_ok_lines(&doctor, &["proxy", "curl", "python", "node", "go"]);
    let stdout = String::from_utf8_lossy(&doctor.stdout);
    for line in ["requests http/1.1", "httpx http/1.1", "httpx-h2 h2"] {
        assert!(
            stdout.lines().any(|l| l == line),
            "{line}\n{}",
            text(&doctor)
        );
    }
}

#[tokio::test]
async fn doctor_fails_when_the_proxy_is_not_running() {
    let home = Home::new("").await;

    let doctor = home
        .fresh_shell(&home.bin_dir(&[]), "\"$CREDSHIM\" doctor --no-runtimes")
        .await;

    assert!(!doctor.status.success());
    let stdout = String::from_utf8_lossy(&doctor.stdout);
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with("[fail]") && l.contains("proxy")),
        "{}",
        text(&doctor)
    );
}

#[tokio::test]
async fn doctor_snippets_cover_each_runtime() {
    let home = tempfile::tempdir().unwrap();

    let snippets = output(home.path(), &["doctor", "--snippets"]).await;

    let stdout = String::from_utf8(snippets.stdout).unwrap();
    for needle in [
        "curl https://credshim.test/",
        "import requests",
        "import httpx",
        "fetch(",
        "package main",
    ] {
        assert!(stdout.contains(needle), "{needle}\n{stdout}");
    }
}

#[tokio::test]
async fn base_url_listener_serves_rule_prefixes() {
    let base_port = free_port();
    let home = Home::new(&format!(
        "[[rule]]\nname = \"openai\"\nhost = \"localhost\"\nport = {port}\nsecret = \"openai\"\ndummy = \"{OPENAI_DUMMY}\"\ninject = {{ header = \"authorization\" }}\nbase_url_prefix = \"/openai\"\n",
        port = free_port(),
    ))
    .await;
    let mut config = std::fs::read_to_string(&home.config).unwrap();
    config = config.replacen(
        "[listen]\n",
        &format!("[listen]\nbase_url_addr = \"127.0.0.1:{base_port}\"\n"),
        1,
    );
    std::fs::write(&home.config, config).unwrap();
    store_secret(home.path(), "openai", "fake-openai-secret-value");
    let _proxy = spawn_run(home.path(), &["--config", home.config()]).await;

    let request = |path: &str| {
        format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{base_port}\r\nAuthorization: Bearer {OPENAI_DUMMY}\r\nConnection: close\r\n\r\n"
        )
    };
    let unknown = exchange(base_port, &request("/elsewhere/v1")).await;
    let unreachable = exchange(base_port, &request("/openai/v1/models")).await;

    assert!(unknown.starts_with("HTTP/1.1 404"), "{unknown}");
    assert!(unreachable.starts_with("HTTP/1.1 502"), "{unreachable}");
}

async fn exchange(port: u16, request: &str) -> String {
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    tokio::io::AsyncReadExt::read_to_string(&mut tcp, &mut response)
        .await
        .unwrap();
    response
}

#[tokio::test]
async fn tail_prints_recent_entries_and_follows_new_ones() {
    let home = tempfile::tempdir().unwrap();
    let audit = home.path().join("audit.jsonl");
    let entry = |path: &str, decision: &str| {
        format!(
            "{{\"timestamp\":\"2026-09-30T00:00:00Z\",\"level\":\"INFO\",\"fields\":{{\"message\":\"request\",\"ingress\":\"connect\",\"scheme\":\"https\",\"host\":\"api.openai.com\",\"port\":443,\"method\":\"POST\",\"path\":\"{path}\",\"rules\":\"openai\",\"decision\":\"{decision}\",\"status\":200}},\"target\":\"credshim::audit\"}}\n"
        )
    };
    std::fs::write(
        &audit,
        entry("/old", "pass") + &entry("/v1/models", "inject"),
    )
    .unwrap();
    let config = home.path().join("credshim.toml");
    std::fs::write(
        &config,
        format!("[audit]\npath = \"{}\"\n", audit.display()),
    )
    .unwrap();

    let mut child = common::credshim(home.path())
        .args(["tail", "-n", "1", "--config", config.to_str().unwrap()])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let next = async |lines: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>| {
        tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    };

    let first = next(&mut lines).await;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&audit)
        .unwrap()
        .write_all(entry("/v1/chat/completions", "deny").as_bytes())
        .unwrap();
    let second = next(&mut lines).await;

    assert_eq!(
        first,
        "2026-09-30T00:00:00Z inject      200 POST https://api.openai.com:443/v1/models [openai] via connect"
    );
    assert!(
        second.contains("deny") && second.contains("/v1/chat/completions"),
        "{second}"
    );
}

#[tokio::test]
async fn service_install_needs_root_and_can_print_its_script() {
    let home = tempfile::tempdir().unwrap();

    let refused = output(home.path(), &["service", "install"]).await;
    let printed = output(home.path(), &["service", "install", "--print"]).await;

    assert!(!refused.status.success());
    assert!(
        text(&refused).contains("run it with sudo"),
        "{}",
        text(&refused)
    );
    assert!(printed.status.success());
    let script = String::from_utf8(printed.stdout).unwrap();
    assert!(script.starts_with("#!/usr/bin/env bash"));
    assert!(script.contains("refuse_writable_ancestors"));
}
