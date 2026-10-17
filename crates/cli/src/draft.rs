use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use anyhow::bail;

use credshim_aws::rule::customer_hosted_reach;
use credshim_core::Limits;

use crate::config::{self, Config};
use crate::handoff::{Handoff, shell_word};
use crate::preset;
use crate::routing::RESTART_ONLY;
use crate::terminal::printable_lines;

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
        "Check every destination above, then add it to the config (credshim docs {RULES_TOPIC})."
    )];
    steps.extend(apply_steps(&config, &table, handoff));
    Ok(printable_lines(&format!(
        "{} is a valid config.\n\
         Not checked here: whether its secrets are stored, the CA, and file permissions. `credshim run --check` checks them, and `service reload` runs it before it applies anything.\n\n\
         {}\n\
         To apply it, a person with admin access runs these steps:\n{}",
        path.display(),
        destinations(&config),
        numbered(&steps)
    )))
}

pub fn destinations(config: &Config) -> String {
    let mut out = String::from("Where it lets each real key go:\n");
    for rule in &config.rules {
        let target = format!(
            "{}:{}{}",
            rule.host,
            rule.port.unwrap_or(443),
            rule.path_prefix.as_deref().unwrap_or_default()
        );
        let _ = writeln!(
            out,
            "  rule {:?}: secret {} -> https://{target}{}",
            rule.name,
            rule.secret,
            origin(preset::preset_for_host(&rule.host), "host")
        );
        let _ = writeln!(
            out,
            "      methods: {}; paths: {}; limits: {}",
            listed(rule.allow_methods.as_deref()),
            listed(rule.allow_paths.as_deref()),
            limits(&rule.limits)
        );
    }
    for key in &config.aws_keys {
        let _ = writeln!(
            out,
            "  aws_key {:?}: secrets {} and {} -> {}",
            key.name,
            key.access_key_id,
            key.secret_access_key,
            aws_reach(key.services.as_deref())
        );
        aws_scope(
            &mut out,
            key.services.as_deref(),
            key.regions.as_deref(),
            key.operations.as_deref(),
            &key.limits,
        );
    }
    for session in &config.aws_sso_sessions {
        let _ = writeln!(
            out,
            "  aws_sso_session {:?}: a person logs in at {} ({})",
            session.name, session.start_url, session.region
        );
    }
    for role in &config.aws_sso_roles {
        let _ = writeln!(
            out,
            "  aws_sso_role {:?}: role {} in account {} through session {:?} -> {}",
            role.name,
            role.role_name,
            role.account_id,
            role.session,
            aws_reach(role.services.as_deref())
        );
        aws_scope(
            &mut out,
            role.services.as_deref(),
            role.regions.as_deref(),
            role.operations.as_deref(),
            &role.limits,
        );
    }
    for key in &config.ssh_keys {
        let _ = writeln!(
            out,
            "  ssh_key {:?}: secret {} -> SSH as {} to servers with host key {}{}",
            key.name,
            key.secret,
            key.users.join(", "),
            key.host_keys.join(", "),
            origin(preset::preset_for_host_keys(&key.host_keys), "host keys")
        );
    }
    for provider in &config.oauth {
        let (refresh, revoke_receives) = if provider.client_secret.is_some() {
            (
                "client secret and refresh tokens",
                "client secret, access and refresh tokens",
            )
        } else {
            ("refresh tokens", "access and refresh tokens")
        };
        let _ = writeln!(
            out,
            "  oauth {:?}: {refresh} -> {}{}",
            provider.name,
            provider.token_endpoint,
            origin(endpoint_preset(&provider.token_endpoint), "host")
        );
        if let Some(revoke) = &provider.revoke_endpoint {
            let _ = writeln!(
                out,
                "      revoke: {revoke_receives} -> {revoke}{}",
                origin(endpoint_preset(revoke), "host")
            );
        }
        if provider.resource_hosts.is_empty() {
            let _ = writeln!(out, "      access tokens: no resource hosts");
        }
        for host in &provider.resource_hosts {
            let _ = writeln!(
                out,
                "      access tokens -> https://{host}:443{}",
                origin(preset::preset_for_host(&host.to_ascii_lowercase()), "host")
            );
        }
    }
    if out.lines().count() == 1 {
        out.push_str("  nowhere: it names no rules\n");
    }
    out
}

fn origin(preset: Option<&str>, what: &str) -> String {
    match preset {
        Some(name) => format!("  ({name} preset {what})"),
        None => format!("  !! {what} not from a preset: confirm with the service"),
    }
}

fn endpoint_preset(url: &str) -> Option<&'static str> {
    let authority = url.strip_prefix("https://")?.split('/').next()?;
    let host = authority.split(':').next()?;
    preset::preset_for_host(&host.to_ascii_lowercase())
}

fn aws_reach(services: Option<&[String]>) -> String {
    let customer_hosted = customer_hosted_reach(services);
    if customer_hosted.is_empty() {
        "AWS endpoints only".to_string()
    } else {
        format!(
            "AWS endpoints, including {} in any AWS account  !! whoever runs such an endpoint gets the request: confirm the rule needs it",
            customer_hosted.join(", ")
        )
    }
}

fn listed(values: Option<&[String]>) -> String {
    values.map_or_else(|| "all".to_string(), |values| values.join(", "))
}

fn limits(limits: &Limits) -> String {
    let set: Vec<String> = [
        ("per_minute", limits.per_minute),
        ("per_day", limits.per_day),
        ("concurrent", limits.concurrent),
    ]
    .into_iter()
    .filter_map(|(name, value)| value.map(|value| format!("{name} {value}")))
    .collect();
    if set.is_empty() {
        "none".to_string()
    } else {
        set.join(", ")
    }
}

fn aws_scope(
    out: &mut String,
    services: Option<&[String]>,
    regions: Option<&[String]>,
    operations: Option<&[String]>,
    limits_spec: &Limits,
) {
    let _ = writeln!(
        out,
        "      services: {}; regions: {}; operations: {}; limits: {}",
        listed(services),
        listed(regions),
        listed(operations),
        limits(limits_spec)
    );
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
