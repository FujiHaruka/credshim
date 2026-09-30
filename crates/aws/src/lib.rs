pub mod auth;
mod credential_operations;
pub mod hosts;
pub mod operation;
pub mod policy;
pub mod resign;
pub mod rule;

use http::request::Parts;

pub use auth::{AuthError, Scope, SigV4Auth};
pub use hosts::{AWS_DOMAIN, BlockedHost, blocked, is_aws_host};
pub use policy::{Decision, Denial, Labels, Payload, Reason, Resign};
pub use resign::{AwsCredentials, CredentialsError, ResignError, Signer};
pub use rule::{AwsKeySpec, AwsRule, AwsRuleError};

pub const DEFAULT_MAX_BODY: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub struct Aws {
    rules: Vec<AwsRule>,
    signer: Signer,
    max_body: usize,
}

impl Aws {
    pub fn new(rules: Vec<AwsRule>, signer: Signer) -> Self {
        Self {
            rules,
            signer,
            max_body: DEFAULT_MAX_BODY,
        }
    }

    pub fn with_max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body;
        self
    }

    pub fn rules(&self) -> &[AwsRule] {
        &self.rules
    }

    pub fn signer(&self) -> &Signer {
        &self.signer
    }

    pub fn max_body(&self) -> usize {
        self.max_body
    }

    pub fn first_dummy_in(&self, parts: &Parts) -> Option<&str> {
        self.rules
            .iter()
            .find(|rule| credshim_core::appears_in(rule.dummy(), parts))
            .map(AwsRule::name)
    }

    pub fn needs_body(&self, host: &str, parts: &Parts) -> bool {
        policy::needs_body(&self.rules, host, parts)
    }

    pub fn decide(&self, host: &str, parts: &Parts, body: Option<&[u8]>) -> Decision<'_> {
        policy::decide(&self.rules, host, parts, body)
    }
}
