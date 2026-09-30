use http::request::Parts;

use crate::rule::{self, Location, Rule, RuleError, RuleSpec};
use crate::scan;

#[derive(Clone, Copy, Debug)]
pub struct Destination<'a> {
    pub host: &'a str,
    pub port: u16,
}

#[derive(Clone, Debug, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

#[derive(Debug)]
pub enum Decision<'r> {
    Pass,
    Inject(Vec<Edit<'r>>),
    Deny(&'r Rule),
}

#[derive(Clone, Copy, Debug)]
pub struct Edit<'r> {
    rule: &'r Rule,
    location: &'r Location,
}

impl<'r> Edit<'r> {
    pub fn rule(&self) -> &'r Rule {
        self.rule
    }

    pub fn location(&self) -> &'r Location {
        self.location
    }
}

impl RuleSet {
    pub fn new(specs: Vec<RuleSpec>) -> Result<Self, RuleError> {
        Ok(Self {
            rules: rule::validate(specs)?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.rules.iter().map(Rule::host)
    }

    pub fn decide(&self, dest: Destination<'_>, parts: &Parts) -> Decision<'_> {
        let mut edits = Vec::new();
        for rule in &self.rules {
            let hits = scan::hits(rule.dummy(), parts);
            if hits.is_empty() {
                continue;
            }
            if !rule.applies_to(dest.host, dest.port, parts.uri.path()) {
                return Decision::Deny(rule);
            }
            edits.extend(
                rule.locations()
                    .iter()
                    .filter(|location| hits.iter().any(|hit| hit.is_at(location)))
                    .map(|location| Edit { rule, location }),
            );
        }
        if edits.is_empty() {
            Decision::Pass
        } else {
            Decision::Inject(edits)
        }
    }

    pub fn first_dummy_in(&self, parts: &Parts) -> Option<&Rule> {
        self.rules
            .iter()
            .find(|rule| !scan::hits(rule.dummy(), parts).is_empty())
    }
}
