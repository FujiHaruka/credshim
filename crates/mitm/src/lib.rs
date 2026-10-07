#[cfg(all(feature = "testing", not(debug_assertions)))]
compile_error!("the `testing` feature must never be enabled in a release build");

pub mod audit;
mod base_url;
pub mod ca;
mod doctor;
pub mod intercept;
mod live;
pub mod proxy;
mod scrub;
mod sso_transport;
mod status;
pub mod upstream;

pub use audit::{AUDIT_TARGET, Counts, Stats};
pub use ca::{CaError, CertificateAuthority};
pub use doctor::{DOCTOR_HOST, Probe, ProbeError, probe};
pub use intercept::{Intercept, VerifiedTarget};
pub use proxy::{BindError, Proxy, ProxyConfig, Reload, Reloader};
pub use sso_transport::UpstreamTransport;
pub use status::serve_status;
pub use upstream::Upstream;
#[cfg(feature = "testing")]
pub use upstream::{TESTING_HOOKS_MARKER, TestingHooks};
