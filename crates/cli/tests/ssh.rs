mod common;

use std::path::Path;
use std::time::Duration;

use common::{output, spawn_run, write_config};
use credshim_secrets::SecretStore;
use credshim_testkit::sshd::{TestSshd, login_user};
use secrecy::ExposeSecret;

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

async fn keygen(home: &Path, config: &str, name: &str) -> std::process::Output {
    output(home, &["ssh", "keygen", name, "--config", config]).await
}

fn private_key_lines(home: &Path, name: &str) -> Vec<String> {
    let secret = credshim_secrets::AgeFileStore::new(home.join("secrets.age"), None)
        .get(name)
        .unwrap()
        .expect("the key is stored");
    let lines: Vec<String> = secret
        .expose_secret()
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .skip(1)
        .map(str::to_string)
        .collect();
    assert!(!lines.is_empty());
    lines
}

fn files_under(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(files_under(&path));
        } else if path.is_file() {
            files.push(path);
        }
    }
    files
}

fn assert_nowhere_on_disk(dir: &Path, needles: &[String]) {
    for file in files_under(dir) {
        let contents = String::from_utf8_lossy(&std::fs::read(&file).unwrap()).into_owned();
        for needle in needles {
            assert!(
                !contents.contains(needle.as_str()),
                "private key material found in {}",
                file.display()
            );
        }
    }
}

#[tokio::test]
async fn keygen_stores_the_private_key_and_prints_only_the_public_half() {
    let home = tempfile::tempdir().unwrap();
    let config = write_config(home.path(), "");

    let first = keygen(home.path(), &config, "ssh-github").await;

    assert!(first.status.success(), "{}", stderr(&first));
    let stdout = String::from_utf8(first.stdout.clone()).unwrap();
    assert!(stdout.starts_with("ssh-ed25519 "), "{stdout}");
    assert!(
        stdout.trim_end().ends_with(" credshim:ssh-github"),
        "{stdout}"
    );
    let private = private_key_lines(home.path(), "ssh-github");
    for line in &private {
        assert!(!stdout.contains(line.as_str()) && !stderr(&first).contains(line.as_str()));
    }
    assert_nowhere_on_disk(home.path(), &private);

    let again = keygen(home.path(), &config, "ssh-github").await;
    assert!(!again.status.success());
    assert!(
        stderr(&again).contains("already exists"),
        "{}",
        stderr(&again)
    );
    assert_eq!(private_key_lines(home.path(), "ssh-github"), private);
}

#[tokio::test]
async fn run_serves_the_agent_and_openssh_logs_in_without_a_key_on_disk() {
    let home = tempfile::tempdir().unwrap();
    let config = write_config(home.path(), "");
    let generated = keygen(home.path(), &config, "ssh-test").await;
    assert!(generated.status.success(), "{}", stderr(&generated));
    let public = String::from_utf8(generated.stdout).unwrap();
    let sshd = TestSshd::start(&public).await;
    let socket = home.path().join("agent.sock");
    let audit = home.path().join("audit.jsonl");
    let config = write_config(
        home.path(),
        &format!(
            "[audit]\npath = \"{audit}\"\n\n[ssh]\nsocket = \"{socket}\"\n\n\
             [[ssh_key]]\nname = \"test\"\nsecret = \"ssh-test\"\nusers = [\"{user}\"]\nhost_keys = [\"{fingerprint}\"]\n",
            audit = audit.display(),
            socket = socket.display(),
            user = login_user(),
            fingerprint = sshd.host_key_fingerprint("ed25519"),
        ),
    );

    let _proxy = spawn_run(
        home.path(),
        &["--listen", "127.0.0.1:0", "--config", &config],
    )
    .await;

    let login = sshd.ssh(&socket, "ssh-ed25519", &[], "echo in").await;
    assert!(login.success, "{}\n{}", login.text, sshd.log());
    let refused = sshd.ssh(&socket, "ecdsa-sha2-nistp256", &[], "true").await;
    assert!(!refused.success, "{}", refused.text);

    let entries: Vec<serde_json::Value> = std::fs::read_to_string(&audit)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let fields: Vec<(&str, &str, &str, &str)> = entries
        .iter()
        .map(|entry| {
            let fields = &entry["fields"];
            (
                fields["ingress"].as_str().unwrap(),
                fields["decision"].as_str().unwrap(),
                fields["reason"].as_str().unwrap(),
                fields["host_key"].as_str().unwrap(),
            )
        })
        .collect();
    let ed25519 = sshd.host_key_fingerprint("ed25519");
    let ecdsa = sshd.host_key_fingerprint("ecdsa");
    assert_eq!(
        fields,
        [
            ("ssh_agent", "sign", "", ed25519.as_str()),
            ("ssh_agent", "deny", "host_key_not_bound", ecdsa.as_str()),
        ]
    );

    let tail = output(home.path(), &["tail", "--no-follow", "--config", &config]).await;
    let tail = String::from_utf8(tail.stdout).unwrap();
    assert!(
        tail.contains(&format!(
            "sign        ssh {}@{ed25519} [test] via ssh_agent",
            login_user()
        )),
        "{tail}"
    );
    assert!(tail.contains("(host_key_not_bound)"), "{tail}");

    let private = private_key_lines(home.path(), "ssh-test");
    assert_nowhere_on_disk(home.path(), &private);
    assert_nowhere_on_disk(sshd.dir(), &private);
}

#[tokio::test]
async fn the_github_preset_is_accepted_once_its_key_exists() {
    let home = tempfile::tempdir().unwrap();
    let preset = output(home.path(), &["preset", "github-ssh"]).await;
    assert!(preset.status.success(), "{}", stderr(&preset));
    let preset = String::from_utf8(preset.stdout).unwrap();
    assert!(preset.contains("secret = \"ssh-github\""), "{preset}");
    let socket = home.path().join("agent.sock");
    let config = write_config(
        home.path(),
        &format!("[ssh]\nsocket = \"{}\"\n\n{preset}", socket.display()),
    );

    let missing = output(
        home.path(),
        &["run", "--listen", "127.0.0.1:0", "--config", &config],
    )
    .await;
    assert!(!missing.status.success());
    assert!(
        stderr(&missing).contains("credshim secret set ssh-github"),
        "{}",
        stderr(&missing)
    );

    assert!(
        keygen(home.path(), &config, "ssh-github")
            .await
            .status
            .success()
    );
    let _proxy = spawn_run(
        home.path(),
        &["--listen", "127.0.0.1:0", "--config", &config],
    )
    .await;
    for _ in 0..50 {
        if socket.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the agent socket never appeared");
}

#[tokio::test]
async fn run_rejects_invalid_ssh_key_rules_and_unusable_secrets() {
    let home = tempfile::tempdir().unwrap();
    let rule = |host_key: &str| {
        format!(
            "[[ssh_key]]\nname = \"bad\"\nsecret = \"ssh-bad\"\nusers = [\"git\"]\nhost_keys = [\"{host_key}\"]\n"
        )
    };
    let config = write_config(home.path(), &rule("MD5:00:11"));
    let out = output(
        home.path(),
        &["run", "--listen", "127.0.0.1:0", "--config", &config],
    )
    .await;
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("SHA256 fingerprint"),
        "{}",
        stderr(&out)
    );

    let config = write_config(
        home.path(),
        &rule("SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"),
    );
    common::store_secret(home.path(), "ssh-bad", "not a key");
    let out = output(
        home.path(),
        &["run", "--listen", "127.0.0.1:0", "--config", &config],
    )
    .await;
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("not an OpenSSH private key"),
        "{}",
        stderr(&out)
    );
    assert!(!stderr(&out).contains("not a key"));
}
