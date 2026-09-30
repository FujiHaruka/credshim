#[cfg(all(feature = "testing", not(debug_assertions)))]
compile_error!("the `testing` feature must never be enabled in a release build");

pub mod audit;
pub mod ca;
pub mod intercept;
pub mod proxy;
mod scrub;
mod status;
pub mod upstream;

pub use audit::{AUDIT_TARGET, Counts, Stats};
pub use ca::{CaError, CertificateAuthority};
pub use intercept::{Intercept, VerifiedTarget};
pub use proxy::{BindError, Proxy, ProxyConfig};
pub use status::serve_status;
pub use upstream::Upstream;
#[cfg(feature = "testing")]
pub use upstream::{TESTING_HOOKS_MARKER, TestingHooks};
