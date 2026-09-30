mod common;

use std::os::unix::fs::PermissionsExt;

use common::{OPENAI_DUMMY, openai_rule, output, spawn_run, store_secret, write_config};
use credshim_testkit::{MockUpstream, fake_secret};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

async fn ca_init(home: &std::path::Path) {
    let ca = home.join("ca").display().to_string();
    assert!(
        output(home, &["ca", "init", "--dir", &ca])
            .await
            .status
            .success()
    );
}

#[tokio::test]
async fn secret_set_refuses_a_non_tty_stdin() {
    let home = tempfile::tempdir().unwrap();
    let config = write_config(home.path(), "");

    let output = output(
        home.path(),
        &["secret", "set", "openai", "--config", &config],
    )
    .await;

    assert!(!output.status.success());
    assert!(stderr(&output).contains("not a TTY"), "{}", stderr(&output));
    assert!(!home.path().join("secrets.age").exists());
}

#[tokio::test]
async fn secret_list_prints_names_and_times_but_never_values() {
    let home = tempfile::tempdir().unwrap();
    let config = write_config(home.path(), "");
    let openai = fake_secret("list-openai");
    store_secret(home.path(), "openai", &openai);
    store_secret(home.path(), "anthropic", "another value");

    let output = output(home.path(), &["secret", "list", "--config", &config]).await;

    assert!(output.status.success(), "{}", stderr(&output));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<(&str, &str)> = stdout
        .lines()
        .map(|line| line.split_once('\t').unwrap())
        .collect();
    assert_eq!(
        lines.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        ["anthropic", "openai"]
    );
    assert!(
        lines
            .iter()
            .all(|(_, time)| time.starts_with("20") && time.ends_with('Z'))
    );
    assert!(!stdout.contains(&openai) && !stdout.contains("another value"));
}

#[tokio::test]
async fn run_refuses_a_rule_whose_secret_is_not_set() {
    let home = tempfile::tempdir().unwrap();
    ca_init(home.path()).await;
    let config = write_config(home.path(), &openai_rule("api.openai.com", 443));

    let output = output(
        home.path(),
        &["run", "--listen", "127.0.0.1:0", "--config", &config],
    )
    .await;

    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("credshim secret set openai"),
        "{}",
        stderr(&output)
    );
}

#[tokio::test]
async fn run_rejects_missing_and_invalid_config_files() {
    let home = tempfile::tempdir().unwrap();
    let missing = home.path().join("nope.toml").display().to_string();

    let output_missing = output(home.path(), &["run", "--config", &missing]).await;
    assert!(!output_missing.status.success());
    assert!(stderr(&output_missing).contains("could not read"));

    for (extra, expected) in [
        ("[listen]\nport = 1\n", "invalid config"),
        ("[[rule]]\nname = \"x\"\n", "invalid config"),
        (
            &openai_rule("API.bad host", 443) as &str,
            "must be a plain lowercase DNS name",
        ),
    ] {
        let config = write_config(home.path(), extra);
        let output = output(
            home.path(),
            &["run", "--listen", "127.0.0.1:0", "--config", &config],
        )
        .await;
        assert!(!output.status.success(), "{extra}");
        assert!(
            stderr(&output).contains(expected),
            "{extra}: {}",
            stderr(&output)
        );
    }
}

#[tokio::test]
async fn presets_produce_rules_the_proxy_accepts() {
    let home = tempfile::tempdir().unwrap();
    ca_init(home.path()).await;
    let mut rules = String::new();
    for name in ["openai", "anthropic", "gemini"] {
        let first = output(home.path(), &["preset", name]).await;
        let second = output(home.path(), &["preset", name]).await;
        assert!(first.status.success(), "{}", stderr(&first));
        assert_ne!(first.stdout, second.stdout);
        rules.push_str(&String::from_utf8(first.stdout).unwrap());
        store_secret(home.path(), name, &fake_secret(name));
    }
    assert!(rules.contains("dummy = \"sk-credshim-openai-"));
    let config = write_config(home.path(), &rules);

    let proxy = spawn_run(
        home.path(),
        &["--listen", "127.0.0.1:0", "--config", &config],
    )
    .await;

    assert!(!proxy.addr.is_empty());
    assert!(
        !output(home.path(), &["preset", "unknown"])
            .await
            .status
            .success()
    );
}

#[tokio::test]
async fn audit_log_records_decisions_as_json_without_values() {
    let home = tempfile::tempdir().unwrap();
    ca_init(home.path()).await;
    let secret = fake_secret("audit");
    store_secret(home.path(), "openai", &secret);
    let audit = home.path().join("audit.jsonl");
    let config = write_config(
        home.path(),
        &format!(
            "[audit]\npath = \"{}\"\n\n{}",
            audit.display(),
            openai_rule("api.openai.com", 443)
        ),
    );
    let proxy = spawn_run(
        home.path(),
        &["--listen", "127.0.0.1:0", "--config", &config],
    )
    .await;
    let plain = MockUpstream::http().start().await;

    for (auth, query) in [
        (format!("Bearer {OPENAI_DUMMY}"), String::new()),
        ("Bearer other".to_string(), "?key=abc".to_string()),
    ] {
        let mut tcp = TcpStream::connect(&proxy.addr).await.unwrap();
        tcp.write_all(
            format!(
                "GET {} HTTP/1.1\r\nHost: x\r\nAuthorization: {auth}\r\nConnection: close\r\n\r\n",
                plain.url("127.0.0.1", &format!("/audited{query}"))
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut response = String::new();
        tcp.read_to_string(&mut response).await.unwrap();
    }

    let contents = std::fs::read_to_string(&audit).unwrap();
    let entries: Vec<serde_json::Value> = contents
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let fields: Vec<(&str, &str, u64)> = entries
        .iter()
        .map(|entry| {
            let fields = &entry["fields"];
            (
                fields["decision"].as_str().unwrap(),
                fields["path"].as_str().unwrap(),
                fields["status"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        fields,
        [("deny", "/audited", 403), ("pass", "/audited", 200)]
    );
    assert!(entries.iter().all(|entry| entry["timestamp"].is_string()));
    assert!(!contents.contains(OPENAI_DUMMY) && !contents.contains(&secret));
    assert_eq!(
        std::fs::metadata(&audit).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
