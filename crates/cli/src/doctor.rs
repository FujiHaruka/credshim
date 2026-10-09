use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::Context;
use credshim_mitm::DOCTOR_HOST;
use credshim_secrets::find_in_path;
use credshim_ssh::ssh_agent_lib::proto::{Request, Response};
use credshim_ssh::ssh_agent_lib::ssh_encoding::{Decode, Encode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::Command;

use crate::leftovers::{self, Places};

const PROXY_TIMEOUT: Duration = Duration::from_secs(10);
const RUNTIME_TIMEOUT: Duration = Duration::from_secs(120);
const AGENT_REPLY_LIMIT: usize = 256 * 1024;
const SESSION_BIND_OPENSSH: (u32, u32) = (8, 9);
const DOCTOR_ACCESS_KEY_ID: &str = "CREDSHIMDOCTORNOTAREALKEY";

const GO_PROBE: &str = r#"package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	res, err := http.Get("https://credshim.test/")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	os.Stdout.Write(body)
}
"#;

const PYTHON_PROBE: &str = "import urllib.request; print(urllib.request.urlopen('https://credshim.test/', timeout=30).read().decode())";
const NODE_PROBE: &str = "fetch('https://credshim.test/').then(r => r.text()).then(t => process.stdout.write(t)).catch(e => { console.error(e.cause?.code ?? e.message); process.exit(1); })";

pub fn snippets() -> String {
    format!(
        "# curl\ncurl https://{DOCTOR_HOST}/\n\n\
         # Python (requests)\npython3 -c 'import requests; print(requests.get(\"https://{DOCTOR_HOST}/\").text)'\n\n\
         # Python (httpx; add http2=True with the h2 extra to try h2)\npython3 -c 'import httpx; print(httpx.get(\"https://{DOCTOR_HOST}/\").text)'\n\n\
         # Node 24+ (fetch reads HTTPS_PROXY only when NODE_USE_ENV_PROXY=1)\nnode -e 'fetch(\"https://{DOCTOR_HOST}/\").then(r => r.text()).then(console.log)'\n\n\
         # Go (save as doctor.go, then `go run doctor.go`)\n{GO_PROBE}"
    )
}

pub struct Inputs {
    pub proxy: SocketAddr,
    pub ca_cert: PathBuf,
    pub runtimes: bool,
}

#[derive(Default)]
struct Tally {
    failed: usize,
}

impl Tally {
    fn line(&mut self, mark: &str, what: &str, detail: &str) {
        if mark == "fail" {
            self.failed += 1;
        }
        let _ = writeln!(std::io::stdout(), "[{mark:<4}] {what:<8} {detail}");
    }
}

pub async fn run(inputs: &Inputs) -> anyhow::Result<bool> {
    let mut tally = Tally::default();
    let ca_pem = std::fs::read_to_string(&inputs.ca_cert).with_context(|| {
        format!(
            "could not read the CA certificate {}; create it with `credshim ca init`",
            inputs.ca_cert.display()
        )
    })?;
    match credshim_mitm::probe(
        inputs.proxy,
        &ca_pem,
        &inputs.ca_cert.display().to_string(),
        PROXY_TIMEOUT,
    )
    .await
    {
        Ok(probe) if is_report(&probe.body) => tally.line(
            "ok",
            "proxy",
            &format!(
                "{DOCTOR_HOST} answered through {} over {}; its certificate chains to {}",
                inputs.proxy,
                probe.protocol,
                inputs.ca_cert.display()
            ),
        ),
        Ok(probe) => tally.line(
            "fail",
            "proxy",
            &format!("unexpected doctor response: {}", probe.body.trim()),
        ),
        Err(err) => tally.line("fail", "proxy", &err.to_string()),
    }
    check_environment(&mut tally, &ca_pem);
    let credshim_agent = check_agent(&mut tally).await;
    if inputs.runtimes {
        for runtime in RUNTIMES {
            runtime.check(&mut tally).await;
        }
        check_openssh(&mut tally, credshim_agent).await;
        check_aws(&mut tally).await;
    }
    check_leftovers(&mut tally);
    Ok(tally.failed == 0)
}

async fn check_agent(tally: &mut Tally) -> bool {
    let Some(socket) = var("SSH_AUTH_SOCK") else {
        tally.line("skip", "ssh", "SSH_AUTH_SOCK is not set");
        return false;
    };
    match tokio::time::timeout(PROXY_TIMEOUT, agent_comments(Path::new(&socket))).await {
        Ok(Ok(comments)) => {
            let rules: Vec<&str> = comments
                .iter()
                .filter_map(|comment| comment.strip_prefix("credshim:"))
                .filter(|rule| {
                    !rule.is_empty()
                        && rule
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
                })
                .collect();
            if rules.is_empty() {
                tally.line(
                    "warn",
                    "ssh",
                    &format!(
                        "SSH_AUTH_SOCK={socket} is an agent that offers no credshim keys ({} other key(s)); load the variables with: eval \"$(credshim env)\"",
                        comments.len()
                    ),
                );
                false
            } else {
                tally.line(
                    "ok",
                    "ssh",
                    &format!(
                        "SSH_AUTH_SOCK={socket} is the credshim agent (rules: {})",
                        rules.join(", ")
                    ),
                );
                true
            }
        }
        Ok(Err(err)) => {
            tally.line(
                "fail",
                "ssh",
                &format!("could not use the agent at SSH_AUTH_SOCK={socket}: {err}; is `credshim run` up, and is this uid in [ssh] client_uids?"),
            );
            false
        }
        Err(_) => {
            tally.line(
                "fail",
                "ssh",
                &format!("the agent at SSH_AUTH_SOCK={socket} did not answer"),
            );
            false
        }
    }
}

async fn agent_comments(socket: &Path) -> std::io::Result<Vec<String>> {
    let invalid =
        |what: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, what.to_string());
    let mut stream = UnixStream::connect(socket).await?;
    let mut frame = Vec::new();
    let request = Request::RequestIdentities;
    let len = request
        .encoded_len()
        .ok()
        .and_then(|len| u32::try_from(len).ok())
        .ok_or_else(|| invalid("request did not encode"))?;
    frame.extend_from_slice(&len.to_be_bytes());
    request
        .encode(&mut frame)
        .map_err(|_| invalid("request did not encode"))?;
    stream.write_all(&frame).await?;
    let len = stream.read_u32().await? as usize;
    if len == 0 || len > AGENT_REPLY_LIMIT {
        return Err(invalid("the agent sent an oversized reply"));
    }
    let mut body = vec![0; len];
    stream.read_exact(&mut body).await?;
    match Response::decode(&mut &body[..]) {
        Ok(Response::IdentitiesAnswer(identities)) => Ok(identities
            .into_iter()
            .map(|identity| identity.comment)
            .collect()),
        _ => Err(invalid("the agent refused to list its keys")),
    }
}

fn openssh_version(text: &str) -> Option<(u32, u32)> {
    let rest = &text[text.find("OpenSSH_")? + "OpenSSH_".len()..];
    let (major, rest) = rest.split_once('.')?;
    let minor: String = rest.chars().take_while(char::is_ascii_digit).collect();
    Some((major.parse().ok()?, minor.parse().ok()?))
}

async fn check_openssh(tally: &mut Tally, credshim_agent: bool) {
    let Some(ssh) = find_in_path("ssh") else {
        tally.line("skip", "openssh", "ssh is not on PATH");
        return;
    };
    let output = Command::new(&ssh)
        .arg("-V")
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output();
    let output = match tokio::time::timeout(PROXY_TIMEOUT, output).await {
        Ok(Ok(output)) => output,
        Ok(Err(err)) => {
            tally.line(
                "fail",
                "openssh",
                &format!("could not run {}: {err}", ssh.display()),
            );
            return;
        }
        Err(_) => {
            tally.line("fail", "openssh", "ssh -V timed out");
            return;
        }
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let (major, minor) = SESSION_BIND_OPENSSH;
    match openssh_version(&text) {
        Some(version) if version >= SESSION_BIND_OPENSSH => tally.line(
            "ok",
            "openssh",
            &format!("{} is OpenSSH {}.{}, which sends session-bind", ssh.display(), version.0, version.1),
        ),
        Some(version) => tally.line(
            if credshim_agent { "fail" } else { "warn" },
            "openssh",
            &format!(
                "{} is OpenSSH {}.{}; the credshim agent signs only for OpenSSH {major}.{minor} or later, which sends session-bind",
                ssh.display(),
                version.0,
                version.1
            ),
        ),
        None => tally.line(
            "warn",
            "openssh",
            &format!("{} is not OpenSSH; the credshim agent needs OpenSSH {major}.{minor} or later", ssh.display()),
        ),
    }
}

async fn check_aws(tally: &mut Tally) {
    let Some(aws) = find_in_path("aws") else {
        tally.line("skip", "aws", "aws is not on PATH");
        return;
    };
    let scratch = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(err) => {
            tally.line("fail", "aws", &format!("no temporary directory: {err}"));
            return;
        }
    };
    let mut command = Command::new(&aws);
    command
        .args([
            "--endpoint-url",
            &format!("https://{DOCTOR_HOST}"),
            "dynamodb",
            "list-tables",
            "--output",
            "json",
        ])
        .env("AWS_ACCESS_KEY_ID", DOCTOR_ACCESS_KEY_ID)
        .env("AWS_SECRET_ACCESS_KEY", DOCTOR_ACCESS_KEY_ID)
        .env("AWS_REGION", "us-east-1")
        .env("AWS_MAX_ATTEMPTS", "1")
        .env("AWS_PAGER", "")
        .env("AWS_EC2_METADATA_DISABLED", "true");
    for name in [
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_SESSION_TOKEN",
        "AWS_ENDPOINT_URL",
        "AWS_ENDPOINT_URL_DYNAMODB",
    ] {
        command.env_remove(name);
    }
    command
        .current_dir(scratch.path())
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let output = match tokio::time::timeout(RUNTIME_TIMEOUT, command.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(err)) => {
            tally.line(
                "fail",
                "aws",
                &format!("could not run {}: {err}", aws.display()),
            );
            return;
        }
        Err(_) => {
            tally.line("fail", "aws", "timed out");
            return;
        }
    };
    if output.status.success() {
        tally.line(
            "ok",
            "aws",
            &format!("the aws CLI reached {DOCTOR_HOST} through the proxy and trusted the CA"),
        );
        return;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let last: String = stderr
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("no output")
        .trim()
        .chars()
        .take(240)
        .collect();
    let lower = stderr.to_ascii_lowercase();
    let hint = if lower.contains("could not connect to the endpoint url") {
        "\n         the aws CLI did not use the proxy: check HTTPS_PROXY/https_proxy"
    } else if lower.contains("ssl validation failed") || lower.contains("certificate") {
        "\n         the aws CLI does not trust the CA: set AWS_CA_BUNDLE to the trust bundle (not the CA alone; it replaces the trust store)"
    } else {
        ""
    };
    tally.line("fail", "aws", &format!("{last}{hint}"));
}

fn check_leftovers(tally: &mut Tally) {
    let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty()) else {
        tally.line("skip", "files", "HOME is not set");
        return;
    };
    let places = Places::from_env(PathBuf::from(home), var);
    let findings = leftovers::scan(&places, var);
    if findings.is_empty() {
        tally.line(
            "ok",
            "files",
            "no private keys in ~/.ssh and no real AWS credentials in ~/.aws or the environment",
        );
    }
    for finding in findings {
        tally.line(finding.mark, "files", &finding.detail);
    }
}

fn check_environment(tally: &mut Tally, ca_pem: &str) {
    let hint = "load the variables with: eval \"$(credshim env)\"";
    match var("HTTPS_PROXY") {
        Some(value) => tally.line("ok", "env", &format!("HTTPS_PROXY={value}")),
        None => tally.line("warn", "env", &format!("HTTPS_PROXY is not set; {hint}")),
    }
    match var("SSL_CERT_FILE") {
        Some(path) => match std::fs::read_to_string(&path) {
            Ok(bundle) if bundle.contains(ca_pem.trim()) => {
                tally.line("ok", "env", &format!("SSL_CERT_FILE={path} includes the CA"))
            }
            Ok(_) => tally.line(
                "warn",
                "env",
                &format!("SSL_CERT_FILE={path} does not include the CA; rebuild it with `credshim ca bundle`"),
            ),
            Err(err) => tally.line("warn", "env", &format!("SSL_CERT_FILE={path}: {err}")),
        },
        None => tally.line("warn", "env", &format!("SSL_CERT_FILE is not set; {hint}")),
    }
    match var("AWS_CA_BUNDLE") {
        Some(path) => match std::fs::read_to_string(&path) {
            Ok(bundle) if bundle.contains(ca_pem.trim()) => tally.line(
                "ok",
                "env",
                &format!("AWS_CA_BUNDLE={path} includes the CA"),
            ),
            Ok(_) => tally.line(
                "warn",
                "env",
                &format!(
                    "AWS_CA_BUNDLE={path} does not include the CA; point it at the trust bundle"
                ),
            ),
            Err(err) => tally.line("warn", "env", &format!("AWS_CA_BUNDLE={path}: {err}")),
        },
        None => tally.line(
            "warn",
            "env",
            &format!("AWS_CA_BUNDLE is not set, so the aws CLI will not trust the CA; {hint}"),
        ),
    }
    if var("NODE_EXTRA_CA_CERTS").is_none() {
        tally.line(
            "warn",
            "env",
            &format!("NODE_EXTRA_CA_CERTS is not set, so Node will not trust the CA; {hint}"),
        );
    }
    if var("NODE_USE_ENV_PROXY").as_deref() != Some("1") {
        tally.line(
            "warn",
            "env",
            "NODE_USE_ENV_PROXY is not 1, so Node's built-in fetch ignores HTTPS_PROXY",
        );
    }
}

fn var(name: &str) -> Option<String> {
    [name.to_string(), name.to_ascii_lowercase()]
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .find(|value| !value.is_empty())
}

pub fn proxy_from_env() -> Option<SocketAddr> {
    let value = var("HTTPS_PROXY")?;
    let rest = value.strip_prefix("http://").unwrap_or(&value);
    rest.trim_end_matches('/').parse().ok()
}

fn is_report(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body.trim())
        .is_ok_and(|report| report["credshim"] == "doctor" && report["via_proxy"] == true)
}

fn protocol(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body.trim())
        .ok()
        .and_then(|report| report["protocol"].as_str().map(str::to_string))
        .unwrap_or_default()
}

struct Runtime {
    name: &'static str,
    program: &'static str,
    probe: Probe,
}

enum Probe {
    Args(&'static [&'static str]),
    GoSource,
}

const RUNTIMES: &[Runtime] = &[
    Runtime {
        name: "curl",
        program: "curl",
        probe: Probe::Args(&["-sS", "--max-time", "30", "https://credshim.test/"]),
    },
    Runtime {
        name: "python",
        program: "python3",
        probe: Probe::Args(&["-c", PYTHON_PROBE]),
    },
    Runtime {
        name: "node",
        program: "node",
        probe: Probe::Args(&["-e", NODE_PROBE]),
    },
    Runtime {
        name: "go",
        program: "go",
        probe: Probe::GoSource,
    },
];

impl Runtime {
    async fn check(&self, tally: &mut Tally) {
        let Some(program) = find_in_path(self.program) else {
            tally.line(
                "skip",
                self.name,
                &format!("{} is not on PATH", self.program),
            );
            return;
        };
        let scratch = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => {
                tally.line("fail", self.name, &format!("no temporary directory: {err}"));
                return;
            }
        };
        let mut command = Command::new(&program);
        match self.probe {
            Probe::Args(args) => {
                command.args(args);
            }
            Probe::GoSource => {
                let source = scratch.path().join("doctor.go");
                if let Err(err) = std::fs::write(&source, GO_PROBE) {
                    tally.line(
                        "fail",
                        self.name,
                        &format!("could not write the probe: {err}"),
                    );
                    return;
                }
                command.arg("run").arg(source);
            }
        }
        command
            .current_dir(scratch.path())
            .stdin(Stdio::null())
            .kill_on_drop(true);
        let output = match tokio::time::timeout(RUNTIME_TIMEOUT, command.output()).await {
            Ok(Ok(output)) => output,
            Ok(Err(err)) => {
                tally.line(
                    "fail",
                    self.name,
                    &format!("could not run {}: {err}", program.display()),
                );
                return;
            }
            Err(_) => {
                tally.line("fail", self.name, "timed out");
                return;
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        if output.status.success() && is_report(&stdout) {
            tally.line(
                "ok",
                self.name,
                &format!("via the proxy, CA trusted, {}", protocol(&stdout)),
            );
            return;
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let last = stderr
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty() && !line.starts_with("exit status"))
            .unwrap_or("no output")
            .trim();
        let last: String = last.chars().take(240).collect();
        tally.line("fail", self.name, &format!("{last}{}", self.hint(&stderr)));
    }

    fn hint(&self, stderr: &str) -> String {
        let lower = stderr.to_ascii_lowercase();
        let bypassed = [
            "enotfound",
            "eai_again",
            "could not resolve host",
            "nodename nor servname",
            "name or service not known",
            "no such host",
            "temporary failure in name resolution",
        ]
        .iter()
        .any(|needle| lower.contains(needle));
        let untrusted = ["certificate", "self_signed", "unable_to_verify", "x509"]
            .iter()
            .any(|needle| lower.contains(needle));
        match (self.name, bypassed, untrusted) {
            ("node", true, _) => "\n         Node's fetch did not use the proxy: set NODE_USE_ENV_PROXY=1 (Node 24+), or pass undici's EnvHttpProxyAgent as the dispatcher".into(),
            (_, true, _) => format!("\n         {} did not use the proxy: check HTTPS_PROXY/https_proxy", self.name),
            ("node", _, true) => "\n         set NODE_EXTRA_CA_CERTS to the CA certificate".into(),
            ("python", _, true) => "\n         this Python's ssl module ignores SSL_CERT_FILE (Apple's /usr/bin/python3 does); requests and httpx read REQUESTS_CA_BUNDLE/SSL_CERT_FILE themselves".into(),
            ("go", _, true) if cfg!(target_os = "macos") => "\n         Go on macOS verifies against the keychain and ignores SSL_CERT_FILE, unless the program was built with Go 1.27+ and either its go.mod says go 1.27+ or it runs with GODEBUG=x509sslcertoverrideplatform=1; see \"Go tools on macOS\" in docs/troubleshooting.md".into(),
            (_, _, true) => format!("\n         {} does not trust the CA: check SSL_CERT_FILE (and REQUESTS_CA_BUNDLE/CURL_CA_BUNDLE)", self.name),
            _ => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openssh_versions_are_read_from_ssh_v() {
        assert_eq!(
            openssh_version("OpenSSH_9.9p2, LibreSSL 3.3.6\n"),
            Some((9, 9))
        );
        assert_eq!(
            openssh_version("OpenSSH_10.0p1 Debian-5, OpenSSL 3.5.0"),
            Some((10, 0))
        );
        assert_eq!(
            openssh_version("OpenSSH_for_Windows_8.1p1, LibreSSL 3.0.2"),
            None
        );
        assert_eq!(openssh_version("Sun_SSH_1.1"), None);
        assert!(Some((8, 9)) >= Some(SESSION_BIND_OPENSSH));
        assert!((8, 8) < SESSION_BIND_OPENSSH);
    }

    #[test]
    fn untrusted_go_on_macos_is_pointed_at_the_keychain_instead_of_ssl_cert_file() {
        let go = RUNTIMES
            .iter()
            .find(|runtime| runtime.name == "go")
            .unwrap();
        let hint = go.hint(
            "tls: failed to verify certificate: x509: \u{201c}credshim.test\u{201d} certificate is not trusted",
        );
        assert_eq!(hint.contains("keychain"), cfg!(target_os = "macos"));
        assert_eq!(
            hint.contains("check SSL_CERT_FILE"),
            !cfg!(target_os = "macos")
        );
    }
}
