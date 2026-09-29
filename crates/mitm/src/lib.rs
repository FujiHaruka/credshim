#[cfg(all(feature = "testing", not(debug_assertions)))]
compile_error!("the `testing` feature must never be enabled in a release build");

pub mod upstream;

pub use upstream::Upstream;
#[cfg(feature = "testing")]
pub use upstream::{TESTING_HOOKS_MARKER, TestingHooks};
