pub mod base_url;
pub mod dummy;
pub mod inject;
pub mod policy;
pub mod rule;
pub mod rules;
mod scan;
pub mod scrub;

pub const AUDIT_TARGET: &str = "credshim::audit";

pub use base_url::{BaseUrlError, BaseUrls, Resolved};
pub use inject::{
    InjectError, Injector, InjectorError, ScrubSource, Secrets, TokenResolver, Verdict,
};
pub use policy::{Limiter, Limits, Permit, Policy, PolicyError};
pub use rule::{
    Binding, BindingError, DEFAULT_PORT, InjectSpec, Location, Rule, RuleError, RuleSpec, SecretRef,
};
pub use rules::{Decision, Destination, Edit, RuleSet};
pub use scan::{appears_in, decode_basic};
pub use scrub::{ScrubStream, Scrubber};
