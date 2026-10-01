use std::fmt::Write;
use std::path::Path;

use anyhow::Context;
use credshim_core::BaseUrls;

use crate::config::Config;

const AWS_DUMMY_SECRET: &str = "credshim-dummy";

pub struct CaFiles<'a> {
    pub cert: &'a Path,
    pub bundle: &'a Path,
}

pub fn render(config: &Config, base_urls: &BaseUrls, ca: &CaFiles<'_>) -> anyhow::Result<String> {
    let proxy = format!("http://{}", config.listen());
    let cert = utf8(ca.cert)?;
    let bundle = utf8(ca.bundle)?;
    let mut no_proxy = vec!["localhost".to_string(), "127.0.0.1".into(), "::1".into()];
    if let Some(addr) = config.listen.base_url_addr
        && !addr.ip().is_loopback()
    {
        no_proxy.push(addr.ip().to_string());
    }
    let no_proxy = no_proxy.join(",");
    let ssh_socket = if config.ssh_keys.is_empty() {
        None
    } else {
        Some(config.ssh_socket()?)
    };
    let ssh_socket = ssh_socket.as_deref().map(utf8).transpose()?;
    let (_, aws_rules) = config.aws_rules()?;
    let mut vars: Vec<(&str, &str)> = vec![
        ("HTTPS_PROXY", &proxy),
        ("https_proxy", &proxy),
        ("HTTP_PROXY", &proxy),
        ("http_proxy", &proxy),
        ("NO_PROXY", &no_proxy),
        ("no_proxy", &no_proxy),
        ("SSL_CERT_FILE", bundle),
        ("REQUESTS_CA_BUNDLE", bundle),
        ("CURL_CA_BUNDLE", bundle),
        ("NODE_EXTRA_CA_CERTS", cert),
        ("NODE_USE_ENV_PROXY", "1"),
        ("AWS_CA_BUNDLE", bundle),
    ];
    if let Some(socket) = ssh_socket {
        vars.push(("SSH_AUTH_SOCK", socket));
    }
    if let [only] = aws_rules.as_slice() {
        vars.push(("AWS_ACCESS_KEY_ID", only.dummy()));
        vars.push(("AWS_SECRET_ACCESS_KEY", AWS_DUMMY_SECRET));
    }
    for rule in &config.rules {
        if let Some(name) = &rule.env {
            vars.push((name, &rule.dummy));
        }
    }
    let mut out = String::new();
    for (name, value) in vars {
        writeln!(out, "export {name}={}", quote(value))?;
    }
    if aws_rules.len() > 1 {
        for rule in &aws_rules {
            writeln!(
                out,
                "# aws profile for {}: aws_access_key_id = {}, aws_secret_access_key = {AWS_DUMMY_SECRET}",
                rule.name(),
                rule.dummy()
            )?;
        }
    }
    if let Some(addr) = config.listen.base_url_addr {
        for rule in &config.rules {
            if let Some(prefix) = base_urls.prefix_for(&rule.name) {
                writeln!(out, "# base URL for {}: http://{addr}{prefix}", rule.name)?;
            }
        }
    }
    Ok(out)
}

fn utf8(path: &Path) -> anyhow::Result<&str> {
    path.to_str()
        .with_context(|| format!("{} is not valid UTF-8", path.display()))
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}
