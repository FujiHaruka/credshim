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
                || name.starts_with("AWS_")
                || name == "SSH_AUTH_SOCK"
            {
                command.env_remove(name);
            }
        }
        command
            .env("PATH", path)
            .env("HOME", self.path())
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

fn fake_program(bin: &Path, name: &str, script: &str) {
    use std::os::unix::fs::PermissionsExt;
    let path = bin.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn line_with(output: &Output, mark: &str, what: &str, needle: &str) -> bool {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line.starts_with(&format!("[{mark:<4}] {what:<8} ")) && line.contains(needle))
}

const SSH_KEY_RULE: &str = "[[ssh_key]]\nname = \"github\"\nsecret = \"ssh-github\"\nusers = [\"git\"]\nhost_keys = [\"SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU\"]\n";
const AWS_DUMMY: &str = "CREDSHIMAWSDOCTORTESTDUMMY0001";

fn aws_key(name: &str, dummy: &str) -> String {
    format!(
        "[[aws_key]]\nname = \"{name}\"\ndummy_access_key_id = \"{dummy}\"\naccess_key_id = \"{name}-akid\"\nsecret_access_key = \"{name}-secret\"\n"
    )
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
async fn env_prints_proxy_and_ca_variables_and_keys_prints_dummies_for_a_dotenv() {
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
    ] {
        assert!(
            stdout.lines().any(|l| l == line),
            "missing {line}\n{stdout}"
        );
    }
    assert!(!stdout.contains(OPENAI_DUMMY), "{stdout}");
    assert!(!stdout.contains("base URL"), "{stdout}");
    assert!(String::from_utf8_lossy(&env.stderr).is_empty());

    let keys = output(home.path(), &["env", "--keys", "--config", home.config()]).await;

    assert!(keys.status.success(), "{}", text(&keys));
    assert_eq!(
        String::from_utf8(keys.stdout).unwrap(),
        format!(
            "OPENAI_API_KEY='{OPENAI_DUMMY}'\n# base URL for openai: http://127.0.0.1:8788/openai\n"
        )
    );
    assert!(String::from_utf8_lossy(&keys.stderr).is_empty());
}

#[tokio::test]
async fn env_refuses_config_values_that_could_run_or_redirect_the_shell() {
    let rule = |name: &str, env: &str, prefix: &str| {
        format!(
            "[[rule]]\nname = {name:?}\nhost = \"api.openai.com\"\nsecret = \"openai\"\ndummy = \"{OPENAI_DUMMY}\"\nenv = {env:?}\ninject = {{ header = \"authorization\" }}\nbase_url_prefix = {prefix:?}\n"
        )
    };
    for (config, needle) in [
        (
            rule("openai", "X; rm -rf ~", "/openai"),
            "must be an environment variable name",
        ),
        (
            rule("openai", "PROMPT_COMMAND", "/openai"),
            "must end in one of",
        ),
        (rule("openai", "NO_PROXY", "/openai"), "must end in one of"),
        (
            rule("openai", "SSL_CERT_FILE", "/openai"),
            "must end in one of",
        ),
        (
            rule("x\necho pwned", "OPENAI_API_KEY", "/openai"),
            "rule name",
        ),
        (
            rule("openai", "OPENAI_API_KEY", "/openai\necho pwned"),
            "base_url_prefix",
        ),
    ] {
        let home = Home::new(&config).await;

        for args in [
            vec!["env", "--config", home.config()],
            vec!["env", "--keys", "--config", home.config()],
        ] {
            let env = output(home.path(), &args).await;

            assert!(!env.status.success(), "{args:?} {config}");
            assert!(text(&env).contains(needle), "{needle}\n{}", text(&env));
            assert!(env.stdout.is_empty());
        }
    }
}

#[tokio::test]
async fn config_rejects_two_rules_exporting_the_same_env_variable() {
    let rule = |name: &str, host: &str| {
        format!(
            "[[rule]]\nname = {name:?}\nhost = {host:?}\nsecret = {name:?}\ndummy = \"{OPENAI_DUMMY}\"\nenv = \"OPENAI_API_KEY\"\ninject = {{ header = \"authorization\" }}\n\n"
        )
    };
    let home = Home::new(&format!(
        "{}{}",
        rule("openai", "api.openai.com"),
        rule("azure", "example.openai.azure.com")
    ))
    .await;

    for args in [
        vec!["env", "--config", home.config()],
        vec!["env", "--keys", "--config", home.config()],
        vec!["run", "--listen", "127.0.0.1:0", "--config", home.config()],
    ] {
        let output = output(home.path(), &args).await;

        assert!(!output.status.success(), "{args:?}");
        assert!(
            text(&output).contains(r#"rules "openai" and "azure" both set env "OPENAI_API_KEY""#),
            "{}",
            text(&output)
        );
        assert!(output.stdout.is_empty());
    }
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

#[tokio::test]
async fn env_exports_the_agent_socket_and_the_aws_bundle_and_keys_prints_a_lone_aws_dummy() {
    let socket_home = tempfile::tempdir().unwrap();
    let socket = socket_home.path().join("agent.sock");
    let home = Home::new(&format!(
        "[ssh]\nsocket = \"{}\"\n\n{SSH_KEY_RULE}\n{}",
        socket.display(),
        aws_key("aws", AWS_DUMMY)
    ))
    .await;
    let env = output(home.path(), &["env", "--config", home.config()]).await;
    assert!(env.status.success(), "{}", text(&env));
    let stdout = String::from_utf8(env.stdout).unwrap();
    let bundle = home.path().join("ca").join("bundle.pem");
    for line in [
        format!("export AWS_CA_BUNDLE='{}'", bundle.display()),
        format!("export SSH_AUTH_SOCK='{}'", socket.display()),
    ] {
        assert!(
            stdout.lines().any(|l| l == line),
            "missing {line}\n{stdout}"
        );
    }
    assert!(!stdout.contains("AWS_ACCESS_KEY_ID"), "{stdout}");
    let keys = output(home.path(), &["env", "--keys", "--config", home.config()]).await;
    assert!(keys.status.success(), "{}", text(&keys));
    assert_eq!(
        String::from_utf8(keys.stdout).unwrap(),
        format!("AWS_ACCESS_KEY_ID='{AWS_DUMMY}'\nAWS_SECRET_ACCESS_KEY='credshim-dummy'\n")
    );

    let second = "CREDSHIMAWSDOCTORTESTDUMMY0002";
    let home = Home::new(&format!(
        "{}\n{}",
        aws_key("one", AWS_DUMMY),
        aws_key("two", second)
    ))
    .await;
    let env = output(home.path(), &["env", "--config", home.config()]).await;
    assert!(env.status.success(), "{}", text(&env));
    assert!(!String::from_utf8_lossy(&env.stdout).contains("SSH_AUTH_SOCK"));
    let keys = output(home.path(), &["env", "--keys", "--config", home.config()]).await;
    assert!(keys.status.success(), "{}", text(&keys));
    let stdout = String::from_utf8(keys.stdout).unwrap();
    assert!(!stdout.contains("AWS_ACCESS_KEY_ID"), "{stdout}");
    for (name, dummy) in [("one", AWS_DUMMY), ("two", second)] {
        let line = format!(
            "# aws profile for {name}: aws_access_key_id = {dummy}, aws_secret_access_key = credshim-dummy"
        );
        assert!(
            stdout.lines().any(|l| l == line),
            "missing {line}\n{stdout}"
        );
    }
}

#[tokio::test]
async fn doctor_reports_an_unreachable_agent_an_old_openssh_and_leftover_credentials() {
    let home = Home::new("").await;
    let _proxy = spawn_run(home.path(), &["--config", home.config()]).await;
    let bin = home.bin_dir(&[]);
    fake_program(
        &bin,
        "ssh",
        "echo 'OpenSSH_8.2p1 Ubuntu-4ubuntu0.13, OpenSSL 1.1.1f' >&2",
    );
    let ssh_secret = credshim_testkit::fake_secret("ssh-key-body");
    let aws_secret = credshim_testkit::fake_secret("aws-secret");
    let token = credshim_testkit::fake_secret("sso-token");
    let dot_ssh = home.path().join(".ssh");
    std::fs::create_dir_all(&dot_ssh).unwrap();
    std::fs::write(
        dot_ssh.join("id_ed25519"),
        format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{ssh_secret}\n-----END OPENSSH PRIVATE KEY-----\n"
        ),
    )
    .unwrap();
    std::fs::write(dot_ssh.join("id_ed25519.pub"), "ssh-ed25519 AAAA me\n").unwrap();
    std::fs::write(dot_ssh.join("known_hosts"), "github.com ssh-ed25519 AAAA\n").unwrap();
    let dot_aws = home.path().join(".aws");
    std::fs::create_dir_all(dot_aws.join("sso/cache")).unwrap();
    std::fs::write(
        dot_aws.join("credentials"),
        format!(
            "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = {aws_secret}\n\n[dummy]\naws_access_key_id = {AWS_DUMMY}\naws_secret_access_key = credshim-dummy\n"
        ),
    )
    .unwrap();
    std::fs::write(
        dot_aws.join("config"),
        "[profile work]\nsso_session = work\n\n[profile tool]\ncredential_process = /bin/false\n",
    )
    .unwrap();
    std::fs::write(
        dot_aws.join("sso/cache/0123.json"),
        format!("{{\"accessToken\": \"{token}\"}}"),
    )
    .unwrap();

    let doctor = home
        .fresh_shell(
            &bin,
            "SSH_AUTH_SOCK=\"$HOME/missing.sock\" AWS_SESSION_TOKEN=x \"$CREDSHIM\" doctor",
        )
        .await;

    assert!(!doctor.status.success(), "{}", text(&doctor));
    for (mark, what, needle) in [
        ("ok", "proxy", "credshim.test"),
        ("fail", "ssh", "missing.sock"),
        ("warn", "openssh", "OpenSSH 8.2"),
        ("skip", "aws", "not on PATH"),
        ("fail", "files", "~/.ssh/id_ed25519 is a private key"),
        (
            "fail",
            "files",
            "~/.aws/credentials [default] holds a real AWS access key",
        ),
        (
            "warn",
            "files",
            "~/.aws/config [profile work] signs in with `aws sso login`",
        ),
        (
            "warn",
            "files",
            "~/.aws/config [profile tool] runs credential_process",
        ),
        ("fail", "files", "~/.aws/sso/cache holds 1 cached"),
        ("fail", "files", "AWS_SESSION_TOKEN is set"),
    ] {
        assert!(
            line_with(&doctor, mark, what, needle),
            "{mark} {what} {needle}\n{}",
            text(&doctor)
        );
    }
    let all = text(&doctor);
    assert!(!all.contains("id_ed25519.pub"), "{all}");
    assert!(!all.contains("[dummy]"), "{all}");
    for secret in [&ssh_secret, &aws_secret, &token] {
        assert!(!all.contains(secret.as_str()), "{all}");
    }
}

#[tokio::test]
async fn doctor_passes_with_the_credshim_agent_and_a_clean_home() {
    let Some(ssh) = find_in_path("ssh") else {
        panic!("ssh is not on PATH");
    };
    let socket_home = tempfile::Builder::new().prefix("cs").tempdir().unwrap();
    let socket_dir = socket_home.path().join("s");
    std::fs::create_dir(&socket_dir).unwrap();
    let socket = socket_dir.join("agent.sock");
    let home = Home::new(&format!(
        "[ssh]\nsocket = \"{}\"\n\n{SSH_KEY_RULE}",
        socket.display()
    ))
    .await;
    let generated = output(
        home.path(),
        &["ssh", "keygen", "ssh-github", "--config", home.config()],
    )
    .await;
    assert!(generated.status.success(), "{}", text(&generated));
    let _proxy = spawn_run(home.path(), &["--config", home.config()]).await;
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let bin = home.bin_dir(&[]);
    std::os::unix::fs::symlink(ssh, bin.join("ssh")).unwrap();

    let doctor = home.fresh_shell(&bin, "\"$CREDSHIM\" doctor").await;

    assert_ok_lines(&doctor, &["proxy", "ssh", "openssh", "files"]);
    assert!(
        line_with(&doctor, "ok", "ssh", "rules: github"),
        "{}",
        text(&doctor)
    );
    assert!(
        !String::from_utf8_lossy(&doctor.stdout).contains("[warn]"),
        "{}",
        text(&doctor)
    );
}

#[tokio::test]
#[ignore = "needs the aws CLI; run with `mise exec -- cargo test -p credshim --test dev_tools -- --ignored`"]
async fn doctor_checks_that_the_aws_cli_goes_through_the_proxy_and_trusts_the_ca() {
    let home = Home::new("").await;
    let _proxy = spawn_run(home.path(), &["--config", home.config()]).await;
    let bin = home.bin_dir(&["aws"]);

    let doctor = home.fresh_shell(&bin, "\"$CREDSHIM\" doctor").await;
    assert_ok_lines(&doctor, &["proxy", "aws", "files"]);

    let proxy = format!("127.0.0.1:{}", home.port);
    let bypass = home
        .fresh_shell(
            &bin,
            &format!("unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy; \"$CREDSHIM\" doctor --proxy {proxy}"),
        )
        .await;
    assert!(!bypass.status.success());
    assert!(
        line_with(&bypass, "fail", "aws", "Could not connect"),
        "{}",
        text(&bypass)
    );
    assert!(
        text(&bypass).contains("the aws CLI did not use the proxy"),
        "{}",
        text(&bypass)
    );

    let other = home.path().join("other-ca");
    let init = output(
        home.path(),
        &["ca", "init", "--dir", other.to_str().unwrap()],
    )
    .await;
    assert!(init.status.success());
    let untrusted = home
        .fresh_shell(
            &bin,
            &format!(
                "AWS_CA_BUNDLE='{}' \"$CREDSHIM\" doctor",
                other.join("ca.pem").display()
            ),
        )
        .await;
    assert!(!untrusted.status.success());
    assert!(
        line_with(&untrusted, "warn", "env", "AWS_CA_BUNDLE"),
        "{}",
        text(&untrusted)
    );
    assert!(
        line_with(&untrusted, "fail", "aws", ""),
        "{}",
        text(&untrusted)
    );
    assert!(
        text(&untrusted).contains("the aws CLI does not trust the CA"),
        "{}",
        text(&untrusted)
    );
}
