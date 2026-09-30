use http::{Method, StatusCode};

pub const AUDIT_TARGET: &str = "credshim::audit";

#[derive(Debug)]
pub(crate) enum Outcome {
    Pass,
    Injected(Vec<String>),
    Denied(String),
    Misdirected,
    Failed(String),
}

impl Outcome {
    fn decision(&self) -> &'static str {
        match self {
            Outcome::Pass => "pass",
            Outcome::Injected(_) => "inject",
            Outcome::Denied(_) => "deny",
            Outcome::Misdirected => "misdirected",
            Outcome::Failed(_) => "error",
        }
    }

    fn rules(&self) -> String {
        match self {
            Outcome::Injected(rules) => rules.join(","),
            Outcome::Denied(rule) | Outcome::Failed(rule) => rule.clone(),
            Outcome::Pass | Outcome::Misdirected => String::new(),
        }
    }
}

pub(crate) struct Entry<'a> {
    pub scheme: &'static str,
    pub host: &'a str,
    pub port: u16,
    pub method: &'a Method,
    pub path: &'a str,
}

pub(crate) fn record(entry: &Entry<'_>, outcome: &Outcome, status: StatusCode) {
    tracing::info!(
        target: AUDIT_TARGET,
        scheme = entry.scheme,
        host = entry.host,
        port = entry.port,
        method = %entry.method,
        path = entry.path,
        rules = %outcome.rules(),
        decision = outcome.decision(),
        status = status.as_u16(),
        "request"
    );
}
