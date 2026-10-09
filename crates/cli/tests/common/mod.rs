#![allow(dead_code)]

use std::path::Path;
use std::process::{Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

pub fn credshim(home: &Path) -> Command {
    with_test_env(Command::new(env!("CARGO_BIN_EXE_credshim")), home)
}

pub fn credshim_with_open_file_limit(home: &Path, soft: u64) -> Command {
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(format!("ulimit -S -n {soft} && exec \"$0\" \"$@\""))
        .arg(env!("CARGO_BIN_EXE_credshim"));
    with_test_env(command, home)
}

fn with_test_env(mut command: Command, home: &Path) -> Command {
    command
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("HOME", home)
        .env_remove("CREDSHIM_LOG")
        .kill_on_drop(true);
    command
}

pub async fn output(home: &Path, args: &[&str]) -> Output {
    credshim(home)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await
        .unwrap()
}

pub struct Running {
    pub child: Child,
    pub addr: String,
    pub stderr: Arc<Mutex<String>>,
}

impl Running {
    pub async fn wait_for_stderr(&self, needle: &str) -> String {
        for _ in 0..200 {
            let stderr = self.stderr.lock().unwrap().clone();
            if stderr.contains(needle) {
                return stderr;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!(
            "the proxy never logged {needle:?}:\n{}",
            self.stderr.lock().unwrap()
        );
    }
}

pub async fn spawn_run(home: &Path, args: &[&str]) -> Running {
    spawn_run_with(credshim(home), args).await
}

pub async fn spawn_run_with(mut command: Command, args: &[&str]) -> Running {
    let mut child = command
        .arg("run")
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap()).lines();
    let addr = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let line = stderr.next_line().await.unwrap().expect("proxy exited");
            if let Some(rest) = line.split("addr=").nth(1) {
                break rest.split_whitespace().next().unwrap().to_string();
            }
        }
    })
    .await
    .expect("proxy never reported its listen address");
    let collected = Arc::new(Mutex::new(String::new()));
    let sink = collected.clone();
    tokio::spawn(async move {
        while let Ok(Some(line)) = stderr.next_line().await {
            let mut sink = sink.lock().unwrap();
            sink.push_str(&line);
            sink.push('\n');
        }
    });
    Running {
        child,
        addr,
        stderr: collected,
    }
}

pub const OPENAI_DUMMY: &str = "sk-credshim-openai-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";

pub fn write_config(home: &Path, extra: &str) -> String {
    let path = home.join("credshim.toml");
    std::fs::write(
        &path,
        format!(
            "[secrets]\nbackend = \"age-file\"\npath = \"{secrets}\"\n\n[ca]\ndir = \"{ca}\"\n\n{extra}",
            secrets = home.join("secrets.age").display(),
            ca = home.join("ca").display(),
        ),
    )
    .unwrap();
    path.display().to_string()
}

pub fn store_secret(home: &Path, name: &str, value: &str) {
    use credshim_secrets::SecretStore;
    credshim_secrets::AgeFileStore::new(home.join("secrets.age"), None)
        .set(name, secrecy::SecretString::from(value))
        .unwrap();
}

pub fn openai_rule(host: &str, port: u16) -> String {
    format!(
        "[[rule]]\nname = \"openai\"\nhost = \"{host}\"\nport = {port}\nsecret = \"openai\"\ndummy = \"{OPENAI_DUMMY}\"\ninject = {{ header = \"authorization\" }}\n"
    )
}
