pub mod auth;
mod credential_operations;
pub mod hosts;
pub mod operation;
pub mod policy;
pub mod refusal;
pub mod resign;
#[rustfmt::skip]
mod rest_operations;
pub mod rule;
mod service_endpoints;
pub mod sso;

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use credshim_core::{Limiter, Permit};
use http::request::Parts;

pub use auth::{AuthError, Scope, SigV4Auth};
pub use hosts::{AWS_DOMAIN, BlockedHost, blocked, is_aws_host};
pub use policy::{Decision, Denial, Labels, Payload, Reason, Resign};
pub use resign::{AwsCredentials, CredentialsError, ResignError, Signer, resign};
pub use rule::{AwsKeySpec, AwsRule, AwsRuleError, AwsSsoRoleSpec, Source, SsoRole};
pub use sso::{CredentialError, SsoOptions, SsoProvider, SsoSession, SsoSessionSpec};

pub const DEFAULT_MAX_BODY: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub struct Aws {
    rules: Vec<AwsRule>,
    signer: Signer,
    sso: Option<Arc<SsoProvider>>,
    max_body: usize,
    limiter: Arc<Limiter>,
}

impl Aws {
    pub fn new(rules: Vec<AwsRule>, signer: Signer) -> Self {
        Self {
            rules,
            signer,
            sso: None,
            max_body: DEFAULT_MAX_BODY,
            limiter: Arc::default(),
        }
    }

    pub fn with_sso(mut self, sso: Arc<SsoProvider>) -> Self {
        self.sso = Some(sso);
        self
    }

    pub fn with_limiter(mut self, limiter: Arc<Limiter>) -> Self {
        self.limiter = limiter;
        self
    }

    pub fn limiter(&self) -> Arc<Limiter> {
        self.limiter.clone()
    }

    pub async fn credentials(
        &self,
        rule: &AwsRule,
    ) -> Result<Arc<AwsCredentials>, CredentialError> {
        let missing = || CredentialError::NotLoaded(rule.name().to_string());
        match rule.source() {
            Source::Static { .. } => self.signer.credentials(rule.name()).ok_or_else(missing),
            Source::Sso(_) => {
                self.sso
                    .as_ref()
                    .ok_or_else(missing)?
                    .credentials(rule.name())
                    .await
            }
        }
    }

    pub fn admit(&self, rule: &AwsRule) -> Option<Permit> {
        self.limiter
            .admit(
                [(rule.name(), rule.limits())],
                Instant::now(),
                SystemTime::now(),
            )
            .ok()
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
