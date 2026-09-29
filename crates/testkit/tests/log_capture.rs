use credshim_testkit::{capture_logs, fake_secret};

#[test]
fn capture_sees_events_and_detects_a_leak() {
    let logs = capture_logs();
    let secret = fake_secret("probe");
    tracing::info!(rule = "openai", "request forwarded");
    logs.assert_absent(&[&secret]);

    tracing::debug!(value = %secret, "oops");
    let leaked = std::panic::catch_unwind(|| logs.assert_absent(&[&secret]));
    assert!(
        leaked.is_err(),
        "assert_absent must fail once the secret is logged"
    );
}

#[test]
fn fake_secrets_are_unique_and_labelled() {
    let a = fake_secret("x");
    let b = fake_secret("x");
    assert_ne!(a, b);
    assert!(a.starts_with("FAKE-SECRET-x-"));
    assert!(a.len() >= 40);
}
