use credshim_core::{BaseUrlError, BaseUrls, Resolved, RuleSpec};

fn spec(name: &str, host: &str, prefix: Option<&str>) -> RuleSpec {
    let prefix = prefix
        .map(|prefix| format!("base_url_prefix = {prefix:?}"))
        .unwrap_or_default();
    toml::from_str(&format!(
        r#"
name = "{name}"
host = "{host}"
secret = "{name}"
dummy = "credshim-{name}-0123456789abcdefghijklmnop"
inject = {{ header = "authorization" }}
{prefix}
"#
    ))
    .unwrap()
}

fn map(specs: &[RuleSpec]) -> BaseUrls {
    BaseUrls::from_specs(specs).unwrap()
}

#[test]
fn prefixes_map_to_their_rule_host_with_the_prefix_stripped() {
    let urls = map(&[
        spec("openai", "api.openai.com", Some("/openai")),
        spec("anthropic", "api.anthropic.com", Some("/anthropic/")),
        spec("plain", "plain.example.test", None),
    ]);

    assert_eq!(
        urls.resolve("/openai/v1/chat/completions"),
        Some(Resolved {
            rule: "openai",
            host: "api.openai.com",
            port: 443,
            path: "/v1/chat/completions",
        })
    );
    assert_eq!(
        urls.resolve("/anthropic/v1/messages").unwrap().host,
        "api.anthropic.com"
    );
    assert_eq!(urls.resolve("/openai").unwrap().path, "/");
    assert_eq!(urls.resolve("/openai/").unwrap().path, "/");
    assert_eq!(urls.prefix_for("anthropic"), Some("/anthropic"));
    assert_eq!(urls.prefix_for("plain"), None);
}

#[test]
fn only_whole_segments_match() {
    let urls = map(&[spec("openai", "api.openai.com", Some("/openai"))]);

    assert_eq!(urls.resolve("/openaix/v1"), None);
    assert_eq!(urls.resolve("/open"), None);
    assert_eq!(urls.resolve("/"), None);
    assert_eq!(urls.resolve("/other/openai/v1"), None);
}

#[test]
fn paths_that_could_climb_out_of_a_prefix_never_resolve() {
    let urls = map(&[
        spec("openai", "api.openai.com", Some("/openai")),
        spec("anthropic", "api.anthropic.com", Some("/anthropic")),
    ]);

    for path in [
        "/openai/../anthropic/v1/messages",
        "/openai/./v1",
        "/openai/..;/anthropic",
        "/openai/%2e%2e/anthropic",
        "/openai%2f..%2fanthropic",
        "/openai/%2F",
        "/openai\\..\\anthropic",
        "/openai/v1/%5c",
    ] {
        assert_eq!(urls.resolve(path), None, "{path}");
    }
}

#[test]
fn port_follows_the_rule() {
    let mut rule = spec("local", "api.example.test", Some("/local"));
    rule.port = Some(8443);
    let urls = map(&[rule]);

    assert_eq!(urls.resolve("/local/x").unwrap().port, 8443);
}

#[test]
fn unsafe_or_ambiguous_prefixes_are_rejected() {
    for prefix in [
        "",
        "/",
        "openai",
        "/a/../b",
        "/a%2fb",
        "/a?x",
        "/a#x",
        "/a\\b",
        "/./a",
        "/a\necho x",
        "/a b",
        "/a'b",
    ] {
        let err =
            BaseUrls::from_specs(&[spec("openai", "api.openai.com", Some(prefix))]).unwrap_err();
        assert!(
            matches!(err, BaseUrlError::InvalidPrefix { .. }),
            "{prefix:?}: {err}"
        );
    }

    for (a, b) in [
        ("/api", "/api"),
        ("/api", "/api/openai"),
        ("/api/openai/", "/api"),
    ] {
        let err = BaseUrls::from_specs(&[
            spec("one", "one.example.test", Some(a)),
            spec("two", "two.example.test", Some(b)),
        ])
        .unwrap_err();
        assert_eq!(
            err,
            BaseUrlError::Overlapping("one".into(), "two".into()),
            "{a} {b}"
        );
    }
}
