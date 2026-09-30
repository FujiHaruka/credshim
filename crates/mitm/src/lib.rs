#[cfg(all(feature = "testing", not(debug_assertions)))]
compile_error!("the `testing` feature must never be enabled in a release build");

pub mod proxy;
pub mod upstream;

pub use proxy::{BindError, Proxy, ProxyConfig};
pub use upstream::Upstream;
#[cfg(feature = "testing")]
pub use upstream::{TESTING_HOOKS_MARKER, TestingHooks};
