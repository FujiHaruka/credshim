use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::Mutex;

use http::{Method, StatusCode};

pub const AUDIT_TARGET: &str = "credshim::audit";

#[derive(Debug)]
pub(crate) enum Outcome {
    Pass,
    Injected(Vec<String>),
    Exchanged(String),
    Denied(String),
    NotAllowed(String),
    Limited(String),
    Misdirected,
    Failed(String),
    Tunnel,
    Rejected,
}

impl Outcome {
    fn decision(&self) -> &'static str {
        match self {
            Outcome::Pass => "pass",
            Outcome::Injected(_) => "inject",
            Outcome::Exchanged(_) => "oauth",
            Outcome::Denied(_) => "deny",
            Outcome::NotAllowed(_) => "not_allowed",
            Outcome::Limited(_) => "limited",
            Outcome::Misdirected => "misdirected",
            Outcome::Failed(_) => "error",
            Outcome::Tunnel => "tunnel",
            Outcome::Rejected => "rejected",
        }
    }

    fn rules(&self) -> String {
        match self {
            Outcome::Injected(rules) => rules.join(","),
            Outcome::Exchanged(rule)
            | Outcome::Denied(rule)
            | Outcome::NotAllowed(rule)
            | Outcome::Limited(rule)
            | Outcome::Failed(rule) => rule.clone(),
            Outcome::Pass | Outcome::Misdirected | Outcome::Tunnel | Outcome::Rejected => {
                String::new()
            }
        }
    }
}

pub(crate) struct Entry<'a> {
    pub ingress: &'static str,
    pub scheme: &'static str,
    pub host: &'a str,
    pub port: u16,
    pub method: &'a Method,
    pub path: &'a str,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub injected: u64,
    pub exchanged: u64,
    pub denied: u64,
    pub not_allowed: u64,
    pub limited: u64,
    pub failed: u64,
}

#[derive(Debug, Default)]
pub struct Stats {
    rules: Mutex<BTreeMap<String, Counts>>,
}

impl Stats {
    pub fn new<I, S>(rules: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            rules: Mutex::new(
                rules
                    .into_iter()
                    .map(|name| (name.into(), Counts::default()))
                    .collect(),
            ),
        }
    }

    pub fn snapshot(&self) -> BTreeMap<String, Counts> {
        self.lock().clone()
    }

    pub fn to_json(&self) -> String {
        let mut out = String::from("{\"rules\":{");
        for (i, (name, c)) in self.lock().iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                "\"{}\":{{\"injected\":{},\"exchanged\":{},\"denied\":{},\"not_allowed\":{},\"limited\":{},\"failed\":{}}}",
                name.escape_default(),
                c.injected,
                c.exchanged,
                c.denied,
                c.not_allowed,
                c.limited,
                c.failed
            );
        }
        out.push_str("}}\n");
        out
    }

    fn record(&self, outcome: &Outcome) {
        let mut rules = self.lock();
        let mut bump = |name: &str, field: fn(&mut Counts) -> &mut u64| {
            *field(rules.entry(name.to_string()).or_default()) += 1;
        };
        match outcome {
            Outcome::Injected(names) => {
                for name in names {
                    bump(name, |c| &mut c.injected);
                }
            }
            Outcome::Exchanged(name) => bump(name, |c| &mut c.exchanged),
            Outcome::Denied(name) => bump(name, |c| &mut c.denied),
            Outcome::NotAllowed(name) => bump(name, |c| &mut c.not_allowed),
            Outcome::Limited(name) => bump(name, |c| &mut c.limited),
            Outcome::Failed(name) => bump(name, |c| &mut c.failed),
            Outcome::Pass | Outcome::Misdirected | Outcome::Tunnel | Outcome::Rejected => {}
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Counts>> {
        self.rules
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

pub(crate) fn record(entry: &Entry<'_>, outcome: &Outcome, status: StatusCode, stats: &Stats) {
    stats.record(outcome);
    tracing::info!(
        target: AUDIT_TARGET,
        ingress = entry.ingress,
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

pub(crate) fn record_connect(
    scheme: &'static str,
    host: &str,
    port: u16,
    outcome: &Outcome,
    status: StatusCode,
    stats: &Stats,
) {
    let entry = Entry {
        ingress: "connect",
        scheme,
        host,
        port,
        method: &Method::CONNECT,
        path: "",
    };
    record(&entry, outcome, status, stats);
}
