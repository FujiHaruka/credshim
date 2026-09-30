use std::io::Read;
use std::path::{Path, PathBuf};

const REAL_KEY_PREFIXES: [&str; 4] = ["AKIA", "ASIA", "ABIA", "ACCA"];
const AWS_CACHES: [&str; 3] = ["sso/cache", "cli/cache", "login/cache"];
const FIRST_LINE_LIMIT: u64 = 128;

#[derive(Debug, PartialEq, Eq)]
pub struct Finding {
    pub mark: &'static str,
    pub detail: String,
}

impl Finding {
    fn fail(detail: String) -> Self {
        Self {
            mark: "fail",
            detail,
        }
    }

    fn warn(detail: String) -> Self {
        Self {
            mark: "warn",
            detail,
        }
    }
}

pub struct Places {
    pub home: PathBuf,
    pub aws_credentials: PathBuf,
    pub aws_config: PathBuf,
}

impl Places {
    pub fn from_env(home: PathBuf, var: impl Fn(&str) -> Option<String>) -> Self {
        let aws = home.join(".aws");
        Self {
            aws_credentials: var("AWS_SHARED_CREDENTIALS_FILE")
                .map_or_else(|| aws.join("credentials"), PathBuf::from),
            aws_config: var("AWS_CONFIG_FILE").map_or_else(|| aws.join("config"), PathBuf::from),
            home,
        }
    }

    fn show(&self, path: &Path) -> String {
        match path.strip_prefix(&self.home) {
            Ok(rest) => format!("~/{}", rest.display()),
            Err(_) => path.display().to_string(),
        }
    }
}

pub fn scan(places: &Places, var: impl Fn(&str) -> Option<String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    ssh_keys(places, &mut findings);
    aws_files(places, &mut findings);
    aws_caches(places, &mut findings);
    aws_environment(&var, &mut findings);
    findings
}

fn ssh_keys(places: &Places, findings: &mut Vec<Finding>) {
    let dir = places.home.join(".ssh");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.metadata().is_ok_and(|meta| meta.is_file()))
        .collect();
    paths.sort();
    for path in paths {
        match first_line(&path) {
            Ok(line) if is_private_key_header(&line) => findings.push(Finding::fail(format!(
                "{} is a private key; switch to a key from `credshim ssh keygen`, remove this one from the servers that accept it, then delete it",
                places.show(&path)
            ))),
            Ok(_) => {}
            Err(err) => findings.push(Finding::warn(format!(
                "could not read {}: {err}",
                places.show(&path)
            ))),
        }
    }
}

fn first_line(path: &Path) -> std::io::Result<String> {
    let mut head = Vec::new();
    std::fs::File::open(path)?
        .take(FIRST_LINE_LIMIT)
        .read_to_end(&mut head)?;
    let end = head.iter().position(|b| *b == b'\n').unwrap_or(head.len());
    Ok(String::from_utf8_lossy(&head[..end]).trim().to_string())
}

fn is_private_key_header(line: &str) -> bool {
    (line.starts_with("-----BEGIN ") && line.ends_with("PRIVATE KEY-----"))
        || line.starts_with("PuTTY-User-Key-File-")
}

fn is_real_access_key_id(value: &str) -> bool {
    value.len() == 20
        && REAL_KEY_PREFIXES
            .iter()
            .any(|prefix| value.starts_with(prefix))
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

struct Section {
    name: String,
    keys: Vec<(String, String)>,
}

impl Section {
    fn get(&self, key: &str) -> Option<&str> {
        self.keys
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    fn has(&self, key: &str) -> bool {
        self.get(key).is_some_and(|value| !value.is_empty())
    }
}

fn sections(text: &str) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            sections.push(Section {
                name: printable(name.trim()),
                keys: Vec::new(),
            });
        } else if let (Some(section), Some((key, value))) =
            (sections.last_mut(), line.split_once('='))
        {
            section
                .keys
                .push((key.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    sections
}

fn printable(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .take(64)
        .collect()
}

fn aws_files(places: &Places, findings: &mut Vec<Finding>) {
    for path in [&places.aws_credentials, &places.aws_config] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let shown = places.show(path);
        for section in sections(&text) {
            let real_key = section
                .get("aws_access_key_id")
                .is_some_and(is_real_access_key_id);
            if real_key || section.has("aws_session_token") {
                findings.push(Finding::fail(format!(
                    "{shown} [{}] holds a real AWS access key; replace it with the rule's dummy_access_key_id, then deactivate and delete the key in IAM",
                    section.name
                )));
            }
            if section.has("credential_process") {
                findings.push(Finding::warn(format!(
                    "{shown} [{}] runs credential_process, which hands real credentials to the aws CLI",
                    section.name
                )));
            }
            if section.has("sso_session") || section.has("sso_start_url") {
                findings.push(Finding::warn(format!(
                    "{shown} [{}] signs in with `aws sso login`; use `credshim aws sso login` and a dummy key instead",
                    section.name
                )));
            }
            if section.has("login_session") {
                findings.push(Finding::warn(format!(
                    "{shown} [{}] signs in with `aws login`, which the proxy refuses",
                    section.name
                )));
            }
        }
    }
}

fn aws_caches(places: &Places, findings: &mut Vec<Finding>) {
    for cache in AWS_CACHES {
        let dir = places.home.join(".aws").join(cache);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let cached = entries
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.path().extension().is_some_and(|ext| ext == "json")
                    && entry.metadata().is_ok_and(|meta| meta.is_file())
            })
            .count();
        if cached > 0 {
            findings.push(Finding::fail(format!(
                "{} holds {cached} cached token or credential file(s); run `aws sso logout`, then delete them",
                places.show(&dir)
            )));
        }
    }
}

fn aws_environment(var: &impl Fn(&str) -> Option<String>, findings: &mut Vec<Finding>) {
    if var("AWS_ACCESS_KEY_ID").is_some_and(|value| is_real_access_key_id(&value)) {
        findings.push(Finding::fail(
            "AWS_ACCESS_KEY_ID in this environment is a real access key".to_string(),
        ));
    }
    if var("AWS_SESSION_TOKEN").is_some_and(|value| !value.is_empty()) {
        findings.push(Finding::fail(
            "AWS_SESSION_TOKEN is set in this environment, so real temporary credentials are in reach".to_string(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_access_key_ids_are_recognised_by_shape() {
        assert!(is_real_access_key_id("AKIAIOSFODNN7EXAMPLE"));
        assert!(is_real_access_key_id("ASIAIOSFODNN7EXAMPLE"));
        assert!(!is_real_access_key_id("CREDSHIMAWSxxxxxxxxxxxxxxxxxxxx"));
        assert!(!is_real_access_key_id("AKIAIOSFODNN7EXAMPL"));
        assert!(!is_real_access_key_id("akiaiosfodnn7example"));
    }

    #[test]
    fn private_key_headers_are_recognised() {
        for header in [
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "PuTTY-User-Key-File-3: ssh-ed25519",
        ] {
            assert!(is_private_key_header(header), "{header}");
        }
        assert!(!is_private_key_header("ssh-ed25519 AAAA credshim:github"));
        assert!(!is_private_key_header("-----BEGIN CERTIFICATE-----"));
    }
}
