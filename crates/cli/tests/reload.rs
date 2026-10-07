mod common;

use std::path::Path;

use common::{OPENAI_DUMMY, Running, openai_rule, output, spawn_run, store_secret, write_config};
use credshim_testkit::{MockUpstream, fake_secret};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const OTHER_DUMMY: &str = "credshim-other-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";

fn other_rule() -> String {
    format!(
        "[[rule]]\nname = \"other\"\nhost = \"api.other.test\"\nsecret = \"other\"\ndummy = \"{OTHER_DUMMY}\"\ninject = {{ header = \"authorization\" }}\n"
    )
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

async fn start(home: &Path) -> (Running, String) {
    ca_init(home).await;
    let secret = fake_secret("reload-openai");
    store_secret(home, "openai", &secret);
    let config = write_config(home, &openai_rule("api.openai.com", 443));
    let proxy = spawn_run(home, &["--listen", "127.0.0.1:0", "--config", &config]).await;
    (proxy, secret)
}

fn hangup(proxy: &Running) {
    let pid = rustix::process::Pid::from_raw(proxy.child.id().unwrap() as i32).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::HUP).unwrap();
}

async fn plain_status(proxy: &Running, mock: &MockUpstream, dummy: &str) -> String {
    let mut tcp = TcpStream::connect(&proxy.addr).await.unwrap();
    tcp.write_all(
        format!(
            "GET {} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {dummy}\r\nConnection: close\r\n\r\n",
            mock.url("127.0.0.1", "/echo")
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut response = String::new();
    tcp.read_to_string(&mut response).await.unwrap();
    response.lines().next().unwrap_or_default().to_string()
}

#[tokio::test]
async fn sighup_applies_new_rules_without_dropping_an_open_stream() {
    let home = tempfile::tempdir().unwrap();
    let (mut proxy, openai_secret) = start(home.path()).await;
    let mock = MockUpstream::http().start().await;
    assert_eq!(
        plain_status(&proxy, &mock, OTHER_DUMMY).await,
        "HTTP/1.1 200 OK"
    );
    let mut stream = BufReader::new(TcpStream::connect(&proxy.addr).await.unwrap());
    stream
        .get_mut()
        .write_all(
            format!(
                "GET {} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                mock.url("127.0.0.1", "/sse?count=10&interval_ms=100")
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut line = String::new();
    while !line.starts_with("data:") {
        line.clear();
        stream.read_line(&mut line).await.unwrap();
    }

    let other_secret = fake_secret("reload-other");
    store_secret(home.path(), "other", &other_secret);
    write_config(
        home.path(),
        &format!(
            "[listen]\nallow_non_loopback = false\n\n{}\n{}",
            openai_rule("api.openai.com", 443),
            other_rule()
        ),
    );
    hangup(&proxy);
    let stderr = proxy.wait_for_stderr("reloaded config").await;

    assert!(
        stderr.contains("section=\"listen\"") && stderr.contains("only after a restart"),
        "{stderr}"
    );
    assert_eq!(
        plain_status(&proxy, &mock, OTHER_DUMMY).await,
        "HTTP/1.1 403 Forbidden"
    );
    assert_eq!(
        plain_status(&proxy, &mock, OPENAI_DUMMY).await,
        "HTTP/1.1 403 Forbidden"
    );
    let mut rest = String::new();
    stream.read_to_string(&mut rest).await.unwrap();
    assert_eq!(rest.matches("data:").count(), 9, "{rest}");
    assert!(proxy.child.try_wait().unwrap().is_none());
    let stderr = proxy.stderr.lock().unwrap().clone();
    assert!(!stderr.contains(&openai_secret) && !stderr.contains(&other_secret));
}

#[tokio::test]
async fn a_reload_that_cannot_load_keeps_the_running_rules() {
    let home = tempfile::tempdir().unwrap();
    let (mut proxy, openai_secret) = start(home.path()).await;
    let mock = MockUpstream::http().start().await;
    write_config(
        home.path(),
        &format!("{}\n{}", openai_rule("api.openai.com", 443), other_rule()),
    );

    hangup(&proxy);
    let stderr = proxy
        .wait_for_stderr("reload failed; keeping the running config")
        .await;

    assert!(stderr.contains("credshim secret set other"), "{stderr}");
    assert!(!stderr.contains(&openai_secret));
    assert_eq!(
        plain_status(&proxy, &mock, OPENAI_DUMMY).await,
        "HTTP/1.1 403 Forbidden"
    );
    assert_eq!(
        plain_status(&proxy, &mock, OTHER_DUMMY).await,
        "HTTP/1.1 200 OK"
    );
    assert!(proxy.child.try_wait().unwrap().is_none());
}

#[tokio::test]
async fn run_check_loads_the_rules_and_their_secrets_without_listening() {
    let home = tempfile::tempdir().unwrap();
    ca_init(home.path()).await;
    let config = write_config(home.path(), &openai_rule("api.openai.com", 443));

    let missing = output(home.path(), &["run", "--check", "--config", &config]).await;
    assert!(!missing.status.success());
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("credshim secret set openai"),
        "{}",
        String::from_utf8_lossy(&missing.stderr)
    );

    let secret = fake_secret("check-openai");
    store_secret(home.path(), "openai", &secret);
    let ready = output(home.path(), &["run", "--check", "--config", &config]).await;
    let stderr = String::from_utf8_lossy(&ready.stderr);
    assert!(ready.status.success(), "{stderr}");
    assert!(stderr.contains("load"), "{stderr}");
    assert!(!stderr.contains("proxy listening") && !stderr.contains(&secret));
}
