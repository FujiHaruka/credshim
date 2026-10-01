use std::time::{Duration, Instant, SystemTime};

use credshim_core::{
    Destination, Injector, Limiter, Limits, Policy, PolicyError, RuleError, RuleSet, RuleSpec,
    Secrets, Verdict,
};
use http::{HeaderMap, Method, Request};
use secrecy::SecretString;

const DUMMY: &str = "sk-credshim-openai-AAAAAAAAAAAAAAAAAAAAAAAA";
const OPENAI: Destination = Destination {
    host: "api.openai.com",
    port: 443,
};

fn spec(extra: &str) -> RuleSpec {
    toml::from_str(&format!(
        r#"
name = "openai"
host = "api.openai.com"
secret = "openai"
dummy = "{DUMMY}"
inject = {{ header = "authorization" }}
{extra}
"#
    ))
    .unwrap()
}

fn injector(extra: &str) -> Injector {
    let mut secrets = Secrets::new();
    secrets.insert("openai", SecretString::from("real-openai-key"));
    Injector::new(RuleSet::new(vec![spec(extra)]).unwrap(), secrets).unwrap()
}

fn apply(injector: &Injector, method: Method, path: &str, with_dummy: bool) -> Verdict {
    let mut builder = Request::builder().method(method).uri(path);
    if with_dummy {
        builder = builder.header("authorization", format!("Bearer {DUMMY}"));
    }
    let (mut parts, ()) = builder.body(()).unwrap().into_parts();
    injector.apply(OPENAI, &mut parts).unwrap()
}

#[test]
fn allow_lists_admit_only_listed_methods_and_path_subtrees() {
    let injector = injector(
        r#"allow_methods = ["post"]
allow_paths = ["/v1/chat/completions", "/v1/embeddings"]"#,
    );

    for path in [
        "/v1/chat/completions",
        "/v1/chat/completions/abc",
        "/v1/embeddings",
    ] {
        assert_eq!(
            apply(&injector, Method::POST, path, true),
            Verdict::Injected(vec!["openai".into()]),
            "{path}"
        );
    }
    for path in [
        "/v1/organization/api_keys",
        "/v1/chat/completionsX",
        "/v1/chat/completions/../../organization",
        "/v1/chat/completions/..;/..;/organization",
        "/v1/chat/completions/.;/x",
        "/v1/chat/completions/%2e%2e/x",
        "/v1/chat%2fcompletions",
    ] {
        assert_eq!(
            apply(&injector, Method::POST, path, true),
            Verdict::NotAllowed("openai".into()),
            "{path}"
        );
    }
    assert_eq!(
        apply(&injector, Method::GET, "/v1/chat/completions", true),
        Verdict::NotAllowed("openai".into())
    );
}

#[test]
fn method_override_headers_are_refused_when_methods_are_listed() {
    let listed = injector(r#"allow_methods = ["post"]"#);
    let unlisted = injector(r#"allow_paths = ["/v1"]"#);
    for name in [
        "x-http-method-override",
        "X-HTTP-Method",
        "x-method-override",
    ] {
        let request = |injector: &Injector| {
            let (mut parts, ()) = Request::builder()
                .method(Method::POST)
                .uri("/v1/files/abc")
                .header("authorization", format!("Bearer {DUMMY}"))
                .header(name, "DELETE")
                .body(())
                .unwrap()
                .into_parts();
            injector.apply(OPENAI, &mut parts).unwrap()
        };
        assert_eq!(
            request(&listed),
            Verdict::NotAllowed("openai".into()),
            "{name}"
        );
        assert_eq!(
            request(&unlisted),
            Verdict::Injected(vec!["openai".into()]),
            "{name}"
        );
    }
}

#[test]
fn requests_without_the_dummy_are_not_policed() {
    let injector = injector(r#"allow_paths = ["/v1/chat/completions"]"#);

    assert_eq!(
        apply(&injector, Method::DELETE, "/v1/organization", false),
        Verdict::Pass
    );
}

#[test]
fn invalid_policies_are_rejected() {
    for (extra, expected) in [
        ("allow_methods = []", PolicyError::NoMethods),
        (
            r#"allow_methods = ["GE T"]"#,
            PolicyError::InvalidMethod("GE T".into()),
        ),
        ("allow_paths = []", PolicyError::NoPaths),
        (
            r#"allow_paths = ["/v1/../admin"]"#,
            PolicyError::InvalidPath("/v1/../admin".into()),
        ),
        (
            r#"allow_paths = ["v1"]"#,
            PolicyError::InvalidPath("v1".into()),
        ),
        ("limits = { per_minute = 0 }", PolicyError::ZeroLimit),
    ] {
        let err = RuleSet::new(vec![spec(extra)]).unwrap_err();
        assert_eq!(
            err,
            RuleError::InvalidPolicy {
                rule: "openai".into(),
                source: expected
            },
            "{extra}"
        );
    }
}

#[test]
fn unknown_limit_keys_are_rejected() {
    let err = toml::from_str::<RuleSpec>(&format!(
        r#"
name = "openai"
host = "api.openai.com"
secret = "openai"
dummy = "{DUMMY}"
inject = {{ header = "authorization" }}
limits = {{ per_hour = 3 }}
"#
    ))
    .unwrap_err();
    assert!(err.to_string().contains("per_hour"), "{err}");
}

fn limits(per_minute: Option<u32>, per_day: Option<u32>, concurrent: Option<u32>) -> Limits {
    Limits {
        per_minute,
        per_day,
        concurrent,
    }
}

#[test]
fn per_minute_limit_uses_a_sliding_window() {
    let limiter = Limiter::default();
    let rule = [("r", limits(Some(2), None, None))];
    let start = Instant::now();
    let wall = SystemTime::now();

    assert!(limiter.admit(rule, start, wall).is_ok());
    assert!(
        limiter
            .admit(rule, start + Duration::from_secs(30), wall)
            .is_ok()
    );
    assert_eq!(
        limiter
            .admit(rule, start + Duration::from_secs(59), wall)
            .unwrap_err(),
        "r"
    );
    assert!(
        limiter
            .admit(rule, start + Duration::from_secs(60), wall)
            .is_ok()
    );
    assert!(
        limiter
            .admit(rule, start + Duration::from_secs(61), wall)
            .is_err()
    );
}

#[test]
fn per_day_limit_resets_at_the_utc_day_boundary() {
    let limiter = Limiter::default();
    let rule = [("r", limits(None, Some(1), None))];
    let now = Instant::now();
    let day = SystemTime::UNIX_EPOCH + Duration::from_secs(20_000 * 86_400);

    assert!(
        limiter
            .admit(rule, now, day + Duration::from_secs(10))
            .is_ok()
    );
    assert!(
        limiter
            .admit(rule, now, day + Duration::from_secs(86_399))
            .is_err()
    );
    assert!(
        limiter
            .admit(rule, now, day + Duration::from_secs(86_400))
            .is_ok()
    );
}

#[test]
fn concurrency_permits_are_returned_on_drop() {
    let limiter = Limiter::default();
    let rule = [("r", limits(None, None, Some(1)))];
    let now = Instant::now();
    let wall = SystemTime::now();

    let first = limiter.admit(rule, now, wall).unwrap();
    assert!(limiter.admit(rule, now, wall).is_err());
    drop(first);
    assert!(limiter.admit(rule, now, wall).is_ok());
}

#[test]
fn a_refused_request_consumes_no_quota_of_other_rules() {
    let limiter = Limiter::default();
    let now = Instant::now();
    let wall = SystemTime::now();
    let open = ("open", limits(Some(1), None, None));
    let full = ("full", limits(None, None, Some(1)));

    let _held = limiter.admit([full], now, wall).unwrap();
    assert_eq!(limiter.admit([open, full], now, wall).unwrap_err(), "full");
    assert!(limiter.admit([open], now, wall).is_ok());
}

#[test]
fn policy_without_lists_allows_everything() {
    let policy = Policy::new(None, None, Limits::default()).unwrap();
    assert!(policy.allows(&Method::DELETE, "/anything/../x", &HeaderMap::new()));
}
