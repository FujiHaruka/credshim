use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use anyhow::bail;

use crate::config::{self, Config};
use crate::handoff::{Handoff, shell_word};
use crate::routing::RESTART_ONLY;

pub const TOPIC: &str = "configuration#checking-a-draft";
const RULES_TOPIC: &str = "configuration#writing-rules";

pub fn check(path: &Path, handoff: &Handoff) -> anyhow::Result<String> {
    let text = config::read(path)?;
    let (config, table) = config::parse(&text).map_err(|problem| problem.into_error(path))?;
    let problems = config.problems();
    if !problems.is_empty() {
        let mut listing = format!(
            "{} has {} problem{}",
            path.display(),
            problems.len(),
            if problems.len() == 1 { "" } else { "s" }
        );
        for (number, problem) in problems.iter().enumerate() {
            let _ = write!(
                listing,
                "\n  {}. {:#}\n     docs: credshim docs {}",
                number + 1,
                problem.error,
                problem.topic
            );
        }
        bail!(listing);
    }
    let mut steps = vec![format!(
        "Add it to the config (credshim docs {RULES_TOPIC})."
    )];
    steps.extend(apply_steps(&config, &table, handoff));
    Ok(format!(
        "{} is a valid config.\n\
         Not checked here: whether its secrets are stored, the CA, and file permissions. `credshim run --check` checks them, and `service reload` runs it before it applies anything.\n\n\
         To apply it, a person with admin access runs these steps:\n{}",
        path.display(),
        numbered(&steps)
    ))
}

pub fn apply_steps(config: &Config, table: &toml::Table, handoff: &Handoff) -> Vec<String> {
    let mut steps = Vec::new();
    let secrets: BTreeSet<&str> = config
        .rules
        .iter()
        .map(|rule| rule.secret.as_str())
        .chain(
            config
                .aws_keys
                .iter()
                .flat_map(|key| [key.access_key_id.as_str(), key.secret_access_key.as_str()]),
        )
        .chain(
            config
                .oauth
                .iter()
                .filter_map(|provider| provider.client_secret_name()),
        )
        .collect();
    let ssh_keys: BTreeSet<&str> = config
        .ssh_keys
        .iter()
        .map(|key| key.secret.as_str())
        .collect();
    if !secrets.is_empty() || !ssh_keys.is_empty() {
        let mut step = String::from(
            "Store each secret it names that is not stored yet, typing the value at a terminal:",
        );
        for name in secrets {
            let command = handoff.as_service(&format!("secret set {}", shell_word(name)), None);
            let _ = write!(step, "\n  {command}");
        }
        for name in ssh_keys {
            let command = handoff.as_service(&format!("ssh keygen {}", shell_word(name)), None);
            let _ = write!(
                step,
                "\n  {command}    (generates a key; `secret set {name}` imports an existing one)"
            );
        }
        steps.push(step);
    }
    if !config.aws_sso_sessions.is_empty() {
        let mut step = String::from("Log in to each AWS SSO session with a browser:");
        for session in &config.aws_sso_sessions {
            let command = handoff.as_service(
                &format!("aws sso login {}", shell_word(&session.name)),
                None,
            );
            let _ = write!(step, "\n  {command}");
        }
        steps.push(step);
    }
    let mut apply = format!("Apply it: {}", handoff.reload());
    let restart: Vec<&str> = RESTART_ONLY
        .into_iter()
        .filter(|section| table.contains_key(*section))
        .collect();
    if !restart.is_empty() {
        let _ = write!(
            apply,
            "\n  These sections apply only after a restart ({}): {}",
            handoff.restart(),
            restart.join(", ")
        );
    }
    steps.push(apply);
    steps
}

pub fn numbered(steps: &[String]) -> String {
    let mut out = String::new();
    for (number, step) in steps.iter().enumerate() {
        let mut lines = step.lines();
        let _ = writeln!(
            out,
            "  {}. {}",
            number + 1,
            lines.next().unwrap_or_default()
        );
        for line in lines {
            let _ = writeln!(out, "   {line}");
        }
    }
    out
}
