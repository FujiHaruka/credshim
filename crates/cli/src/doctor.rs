use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::Context;
use credshim_mitm::DOCTOR_HOST;
use tokio::process::Command;

const PROXY_TIMEOUT: Duration = Duration::from_secs(10);
const RUNTIME_TIMEOUT: Duration = Duration::from_secs(120);

const GO_PROBE: &str = r#"package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if path := os.Getenv("SSL_CERT_FILE"); path != "" {
		if pem, err := os.ReadFile(path); err == nil {
			pool.AppendCertsFromPEM(pem)
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	res, err := (&http.Client{Transport: transport}).Get("https://credshim.test/")
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
    if inputs.runtimes {
        for runtime in RUNTIMES {
            runtime.check(&mut tally).await;
        }
    }
    Ok(tally.failed == 0)
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
            (_, _, true) => format!("\n         {} does not trust the CA: check SSL_CERT_FILE (and REQUESTS_CA_BUNDLE/CURL_CA_BUNDLE)", self.name),
            _ => String::new(),
        }
    }
}

fn find_in_path(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(program))
            .find(|candidate| is_executable(candidate))
    })
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}
