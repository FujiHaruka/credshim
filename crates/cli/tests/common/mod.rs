#![allow(dead_code)]

use std::path::Path;
use std::process::{Output, Stdio};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

pub fn credshim(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_credshim"));
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
}

pub async fn spawn_run(home: &Path, args: &[&str]) -> Running {
    let mut child = credshim(home)
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
    tokio::spawn(async move { while let Ok(Some(_)) = stderr.next_line().await {} });
    Running { child, addr }
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
