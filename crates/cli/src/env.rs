use std::fmt::Write;
use std::path::Path;

use anyhow::Context;

use crate::config::Config;

pub struct CaFiles<'a> {
    pub cert: &'a Path,
    pub bundle: &'a Path,
}

pub fn render(config: &Config, ca: &CaFiles<'_>) -> anyhow::Result<String> {
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
    ];
    for rule in &config.rules {
        if let Some(name) = &rule.env {
            vars.push((name, &rule.dummy));
        }
    }
    let mut out = String::new();
    for (name, value) in vars {
        writeln!(out, "export {name}={}", quote(value))?;
    }
    if let Some(addr) = config.listen.base_url_addr {
        for rule in &config.rules {
            if let Some(prefix) = &rule.base_url_prefix {
                writeln!(
                    out,
                    "# base URL for {}: http://{addr}{}",
                    rule.name,
                    prefix.trim_end_matches('/')
                )?;
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
