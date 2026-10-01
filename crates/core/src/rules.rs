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
    NotAllowed(&'r Rule),
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
        Self::from_rules(
            specs
                .into_iter()
                .map(Rule::from_spec)
                .collect::<Result<_, _>>()?,
        )
    }

    pub fn from_rules(rules: Vec<Rule>) -> Result<Self, RuleError> {
        Ok(Self {
            rules: rule::validate(rules)?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.rules.iter().flat_map(Rule::hosts)
    }

    pub fn decide(&self, dest: Destination<'_>, parts: &Parts) -> Decision<'_> {
        decide(&self.rules, dest, parts)
    }

    pub fn first_dummy_in(&self, parts: &Parts) -> Option<&Rule> {
        first_dummy_in(&self.rules, parts)
    }
}

pub(crate) fn decide<'r>(
    rules: impl IntoIterator<Item = &'r Rule>,
    dest: Destination<'_>,
    parts: &Parts,
) -> Decision<'r> {
    let mut edits: Vec<Edit<'r>> = Vec::new();
    for rule in rules {
        let hits = scan::hits(rule.dummy(), parts);
        if hits.is_empty() {
            continue;
        }
        let mut bound = rule
            .bindings()
            .iter()
            .filter(|binding| binding.applies_to(dest.host, dest.port, parts.uri.path()))
            .peekable();
        if bound.peek().is_none() {
            return Decision::Deny(rule);
        }
        for location in bound.flat_map(|binding| binding.locations()) {
            let hit = hits.iter().any(|hit| hit.is_at(location));
            let seen = edits
                .iter()
                .any(|edit| std::ptr::eq(edit.rule, rule) && edit.location == location);
            if hit && !seen {
                edits.push(Edit { rule, location });
            }
        }
    }
    if let Some(edit) = edits.iter().find(|edit| {
        !edit
            .rule
            .policy()
            .allows(&parts.method, parts.uri.path(), &parts.headers)
    }) {
        return Decision::NotAllowed(edit.rule);
    }
    if edits.is_empty() {
        Decision::Pass
    } else {
        Decision::Inject(edits)
    }
}

pub(crate) fn first_dummy_in<'r>(
    rules: impl IntoIterator<Item = &'r Rule>,
    parts: &Parts,
) -> Option<&'r Rule> {
    rules
        .into_iter()
        .find(|rule| !scan::hits(rule.dummy(), parts).is_empty())
}
