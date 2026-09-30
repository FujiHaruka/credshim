use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use credshim_core::{
    Decision, Destination, InjectSpec, Injector, InjectorError, RuleError, RuleSet, RuleSpec,
    Secrets, Verdict,
};
use http::request::Parts;
use http::{HeaderValue, Request};
use secrecy::SecretString;

const OPENAI_DUMMY: &str = "sk-credshim-openai-0123456789abcdefghij";
const OPENAI_SECRET: &str = "sk-real-openai-secret";
const GEMINI_DUMMY: &str = "credshim-gemini-0123456789abcdefghijkl";
const GEMINI_SECRET: &str = "real gemini/secret&x=1";
const BASIC_DUMMY: &str = "credshim-basic-0123456789abcdefghijklm";
const BASIC_SECRET: &str = "real:basic:secret";

const OPENAI: Destination = Destination {
    host: "api.openai.com",
    port: 443,
};
const GEMINI: Destination = Destination {
    host: "generativelanguage.googleapis.com",
    port: 443,
};
const BASIC_HOST: Destination = Destination {
    host: "basic.example.test",
    port: 443,
};
const ELSEWHERE: Destination = Destination {
    host: "attacker.example.test",
    port: 443,
};

fn spec(name: &str, host: &str, dummy: &str, inject: InjectSpec) -> RuleSpec {
    RuleSpec {
        name: name.to_string(),
        host: host.to_string(),
        port: None,
        path_prefix: None,
        allow_methods: None,
        allow_paths: None,
        limits: Default::default(),
        base_url_prefix: None,
        env: None,
        secret: name.to_string(),
        dummy: dummy.to_string(),
        inject,
    }
}

fn header(name: &str) -> InjectSpec {
    InjectSpec {
        header: Some(name.to_string()),
        ..InjectSpec::default()
    }
}

fn specs() -> Vec<RuleSpec> {
    vec![
        spec(
            "openai",
            "api.openai.com",
            OPENAI_DUMMY,
            header("authorization"),
        ),
        spec(
            "gemini",
            "generativelanguage.googleapis.com",
            GEMINI_DUMMY,
            InjectSpec {
                header: None,
                query: Some("key".to_string()),
                basic: false,
            },
        ),
        spec(
            "basic",
            "basic.example.test",
            BASIC_DUMMY,
            InjectSpec {
                basic: true,
                ..InjectSpec::default()
            },
        ),
    ]
}

fn secrets() -> Secrets {
    let mut secrets = Secrets::new();
    secrets.insert("openai", SecretString::from(OPENAI_SECRET));
    secrets.insert("gemini", SecretString::from(GEMINI_SECRET));
    secrets.insert("basic", SecretString::from(BASIC_SECRET));
    secrets
}

fn injector_with(specs: Vec<RuleSpec>) -> Injector {
    Injector::new(RuleSet::new(specs).unwrap(), secrets()).unwrap()
}

fn injector() -> Injector {
    injector_with(specs())
}

fn request(uri: &str, headers: &[(&str, &str)]) -> Parts {
    let mut builder = Request::builder().uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(()).unwrap().into_parts().0
}

fn snapshot(parts: &Parts) -> (String, Vec<(String, Vec<u8>)>) {
    (
        parts.uri.to_string(),
        parts
            .headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
            .collect(),
    )
}

fn basic(credentials: &str) -> String {
    format!("Basic {}", STANDARD.encode(credentials))
}

#[test]
fn bearer_dummy_in_the_bound_header_is_replaced() {
    let mut parts = request(
        "/v1/chat/completions",
        &[("authorization", &format!("Bearer {OPENAI_DUMMY}"))],
    );

    let verdict = injector().apply(OPENAI, &mut parts).unwrap();

    assert_eq!(verdict, Verdict::Injected(vec!["openai".to_string()]));
    let value = parts.headers.get("authorization").unwrap();
    assert_eq!(value, &format!("Bearer {OPENAI_SECRET}"));
    assert!(value.is_sensitive());
}

#[test]
fn every_value_of_a_repeated_header_is_replaced() {
    let mut parts = request(
        "/",
        &[
            ("authorization", &format!("Bearer {OPENAI_DUMMY}")),
            ("authorization", "Bearer untouched"),
            ("authorization", OPENAI_DUMMY),
        ],
    );

    injector().apply(OPENAI, &mut parts).unwrap();

    let values: Vec<&HeaderValue> = parts.headers.get_all("authorization").iter().collect();
    assert_eq!(
        values,
        [
            &format!("Bearer {OPENAI_SECRET}"),
            "Bearer untouched",
            OPENAI_SECRET
        ]
    );
}

#[test]
fn requests_without_dummies_are_left_byte_identical() {
    let injector = injector();
    let cases = [
        request(
            "/v1/models?key=abc&x=%41%2b+&&=",
            &[
                ("authorization", "Bearer sk-someone-elses-key"),
                ("x-api-key", "unrelated"),
                ("cookie", "a=b; c=d"),
            ],
        ),
        request("/", &[("authorization", "Basic !!!not-base64")]),
        request("/", &[]),
    ];
    for dest in [OPENAI, GEMINI, BASIC_HOST, ELSEWHERE] {
        for original in &cases {
            let mut parts = request(
                &original.uri.to_string(),
                &original
                    .headers
                    .iter()
                    .map(|(n, v)| (n.as_str(), v.to_str().unwrap()))
                    .collect::<Vec<_>>(),
            );
            let before = snapshot(&parts);
            assert_eq!(injector.apply(dest, &mut parts).unwrap(), Verdict::Pass);
            assert_eq!(snapshot(&parts), before);
        }
    }
}

#[test]
fn dummy_sent_to_an_unbound_destination_is_denied_and_left_untouched() {
    let injector = injector();
    let other_port = Destination {
        host: "api.openai.com",
        port: 8443,
    };
    for dest in [ELSEWHERE, GEMINI, other_port] {
        let mut parts = request("/", &[("authorization", &format!("Bearer {OPENAI_DUMMY}"))]);
        let before = snapshot(&parts);

        let verdict = injector.apply(dest, &mut parts).unwrap();

        assert_eq!(verdict, Verdict::Denied("openai".to_string()), "{dest:?}");
        assert_eq!(snapshot(&parts), before);
    }
}

#[test]
fn dummy_hidden_anywhere_in_the_request_is_found() {
    let injector = injector();
    let encoded: String = OPENAI_DUMMY.bytes().map(|b| format!("%{b:02X}")).collect();
    let cases = [
        request(
            "/",
            &[("x-anything", &format!("prefix{OPENAI_DUMMY}suffix"))],
        ),
        request(
            "/",
            &[("authorization", &basic(&format!("user:{OPENAI_DUMMY}")))],
        ),
        request(
            "/",
            &[("proxy-authorization", &basic(&format!("{OPENAI_DUMMY}:x")))],
        ),
        request(&format!("/leak/{OPENAI_DUMMY}"), &[]),
        request(&format!("/leak/{encoded}"), &[]),
        request(&format!("/?q={encoded}"), &[]),
        request(&format!("/?{OPENAI_DUMMY}=1"), &[]),
    ];
    for mut parts in cases {
        let verdict = injector.apply(ELSEWHERE, &mut parts).unwrap();
        assert_eq!(verdict, Verdict::Denied("openai".to_string()), "{parts:?}");
    }
}

#[test]
fn bound_dummy_alongside_a_foreign_dummy_is_denied() {
    let mut parts = request(
        &format!("/?key={GEMINI_DUMMY}"),
        &[("authorization", &format!("Bearer {OPENAI_DUMMY}"))],
    );
    let before = snapshot(&parts);

    let verdict = injector().apply(OPENAI, &mut parts).unwrap();

    assert_eq!(verdict, Verdict::Denied("gemini".to_string()));
    assert_eq!(snapshot(&parts), before);
}

#[test]
fn bound_dummy_outside_its_configured_location_passes_unchanged() {
    let mut parts = request(
        &format!("/?key={OPENAI_DUMMY}"),
        &[("x-api-key", OPENAI_DUMMY)],
    );
    let before = snapshot(&parts);

    assert_eq!(injector().apply(OPENAI, &mut parts).unwrap(), Verdict::Pass);
    assert_eq!(snapshot(&parts), before);
}

#[test]
fn query_parameter_is_replaced_and_percent_encoded_leaving_other_pairs_intact() {
    let mut parts = request(
        &format!("/v1/models?alt=sse&key={GEMINI_DUMMY}&x=%41+b&key2={GEMINI_DUMMY}"),
        &[],
    );

    let verdict = injector().apply(GEMINI, &mut parts).unwrap();

    assert_eq!(verdict, Verdict::Injected(vec!["gemini".to_string()]));
    assert_eq!(
        parts.uri.to_string(),
        format!(
            "/v1/models?alt=sse&key=real%20gemini%2Fsecret%26x%3D1&x=%41+b&key2={GEMINI_DUMMY}"
        )
    );
}

#[test]
fn percent_encoded_query_dummy_is_replaced() {
    let encoded: String = GEMINI_DUMMY.bytes().map(|b| format!("%{b:02x}")).collect();
    let mut parts = request(
        &format!("https://generativelanguage.googleapis.com/v1?key={encoded}"),
        &[],
    );

    injector().apply(GEMINI, &mut parts).unwrap();

    assert_eq!(
        parts.uri.to_string(),
        "https://generativelanguage.googleapis.com/v1?key=real%20gemini%2Fsecret%26x%3D1"
    );
}

#[test]
fn basic_auth_is_decoded_replaced_and_reencoded() {
    let injector = injector();
    for (credentials, expected) in [
        (
            format!("client-id:{BASIC_DUMMY}"),
            format!("client-id:{BASIC_SECRET}"),
        ),
        (format!("{BASIC_DUMMY}:"), format!("{BASIC_SECRET}:")),
    ] {
        let mut parts = request("/", &[("authorization", &basic(&credentials))]);

        let verdict = injector.apply(BASIC_HOST, &mut parts).unwrap();

        assert_eq!(verdict, Verdict::Injected(vec!["basic".to_string()]));
        let value = parts.headers.get("authorization").unwrap();
        assert_eq!(value, &basic(&expected));
        assert!(value.is_sensitive());
    }
}

#[test]
fn unpadded_lowercase_basic_scheme_is_recognised() {
    let encoded = STANDARD.encode(format!("u:{BASIC_DUMMY}"));
    let mut parts = request(
        "/",
        &[(
            "authorization",
            &format!("basic {}", encoded.trim_end_matches('=')),
        )],
    );

    let verdict = injector().apply(BASIC_HOST, &mut parts).unwrap();

    assert_eq!(verdict, Verdict::Injected(vec!["basic".to_string()]));
}

#[test]
fn path_prefix_binds_the_dummy_to_that_subtree() {
    let mut scoped = spec(
        "openai",
        "api.openai.com",
        OPENAI_DUMMY,
        header("authorization"),
    );
    scoped.path_prefix = Some("/v1".to_string());
    let injector = injector_with(vec![scoped]);
    let auth = format!("Bearer {OPENAI_DUMMY}");

    for path in ["/v1", "/v1/chat/completions", "/v1?x=1"] {
        let mut parts = request(path, &[("authorization", &auth)]);
        assert!(
            matches!(
                injector.apply(OPENAI, &mut parts).unwrap(),
                Verdict::Injected(_)
            ),
            "{path}"
        );
    }
    for path in [
        "/v10/x",
        "/",
        "/admin",
        "/v1/../admin",
        "/v1/./x",
        "/v1/%2e%2e/admin",
        "/v1%2fadmin",
        "/v1/..%5cadmin",
    ] {
        let mut parts = request(path, &[("authorization", &auth)]);
        assert_eq!(
            injector.apply(OPENAI, &mut parts).unwrap(),
            Verdict::Denied("openai".to_string()),
            "{path}"
        );
    }
}

#[test]
fn host_comparison_ignores_case_but_port_must_match() {
    let mut on_8443 = spec(
        "openai",
        "API.OpenAI.com",
        OPENAI_DUMMY,
        header("authorization"),
    );
    on_8443.port = Some(8443);
    let injector = injector_with(vec![on_8443]);
    let auth = format!("Bearer {OPENAI_DUMMY}");

    let mut parts = request("/", &[("authorization", &auth)]);
    let upper = Destination {
        host: "api.OPENAI.com",
        port: 8443,
    };
    assert!(matches!(
        injector.apply(upper, &mut parts).unwrap(),
        Verdict::Injected(_)
    ));

    let mut parts = request("/", &[("authorization", &auth)]);
    assert_eq!(
        injector.apply(OPENAI, &mut parts).unwrap(),
        Verdict::Denied("openai".to_string())
    );
}

#[test]
fn decision_is_pure_and_names_the_edits() {
    let rules = RuleSet::new(specs()).unwrap();
    let parts = request(
        &format!("/?key={GEMINI_DUMMY}"),
        &[("authorization", &format!("Bearer {GEMINI_DUMMY}"))],
    );

    let Decision::Inject(edits) = rules.decide(GEMINI, &parts) else {
        panic!("expected an injection");
    };
    assert_eq!(edits.len(), 1);
    assert_eq!(edits[0].rule().name(), "gemini");
    assert!(matches!(rules.first_dummy_in(&parts), Some(rule) if rule.name() == "gemini"));
}

#[test]
fn invalid_rules_are_rejected() {
    let ok = || {
        spec(
            "openai",
            "api.openai.com",
            OPENAI_DUMMY,
            header("authorization"),
        )
    };
    let with = |edit: fn(&mut RuleSpec)| {
        let mut spec = ok();
        edit(&mut spec);
        RuleSet::new(vec![spec]).unwrap_err()
    };

    assert!(matches!(
        with(|s| s.name = "has space".into()),
        RuleError::InvalidName(_)
    ));
    assert!(matches!(
        with(|s| s.name = String::new()),
        RuleError::InvalidName(_)
    ));
    for host in [
        "api.openai.com:443",
        "*.openai.com",
        "",
        "a..b",
        "-a.com",
        "a_b.com",
    ] {
        let mut spec = ok();
        spec.host = host.to_string();
        assert!(
            matches!(RuleSet::new(vec![spec]), Err(RuleError::InvalidHost { .. })),
            "{host}"
        );
    }
    assert!(matches!(
        with(|s| s.port = Some(0)),
        RuleError::InvalidPort(_)
    ));
    for prefix in ["v1", "/v1/../x", "/v1/%2e", "/v1?x", "/v1#x", "/./v1"] {
        let mut spec = ok();
        spec.path_prefix = Some(prefix.to_string());
        assert!(
            matches!(
                RuleSet::new(vec![spec]),
                Err(RuleError::InvalidPathPrefix { .. })
            ),
            "{prefix}"
        );
    }
    assert!(matches!(
        with(|s| s.secret = "a/b".into()),
        RuleError::InvalidSecretName { .. }
    ));
    for dummy in [
        "short",
        "sk-credshim-openai-0123456789 abcdef",
        "sk-credshim:openai-0123456789abcdef",
    ] {
        let mut spec = ok();
        spec.dummy = dummy.to_string();
        assert!(
            matches!(RuleSet::new(vec![spec]), Err(RuleError::InvalidDummy(_))),
            "{dummy}"
        );
    }
    assert!(matches!(
        with(|s| s.dummy = "x".repeat(257)),
        RuleError::InvalidDummy(_)
    ));
    assert!(matches!(
        with(|s| s.inject = InjectSpec::default()),
        RuleError::NoLocation(_)
    ));
    for name in [
        "host",
        "content-length",
        "proxy-authorization",
        "bad header",
    ] {
        let mut spec = ok();
        spec.inject = header(name);
        assert!(
            matches!(
                RuleSet::new(vec![spec]),
                Err(RuleError::InvalidHeader { .. })
            ),
            "{name}"
        );
    }
    assert!(matches!(
        with(|s| s.inject = InjectSpec {
            query: Some(String::new()),
            ..InjectSpec::default()
        }),
        RuleError::InvalidQueryParam(_)
    ));
}

#[test]
fn duplicate_names_and_overlapping_dummies_are_rejected() {
    let a = spec("a", "a.example.test", OPENAI_DUMMY, header("authorization"));
    assert_eq!(
        RuleSet::new(vec![a.clone(), a.clone()]).unwrap_err(),
        RuleError::DuplicateName("a".to_string())
    );

    let mut b = spec("b", "b.example.test", "", header("authorization"));
    b.dummy = format!("{OPENAI_DUMMY}-longer");
    assert_eq!(
        RuleSet::new(vec![a.clone(), b]).unwrap_err(),
        RuleError::OverlappingDummies("a".to_string(), "b".to_string())
    );
}

#[test]
fn secrets_are_checked_when_the_injector_is_built() {
    let rules = || {
        RuleSet::new(vec![spec(
            "openai",
            "api.openai.com",
            OPENAI_DUMMY,
            header("authorization"),
        )])
        .unwrap()
    };

    assert!(matches!(
        Injector::new(rules(), Secrets::new()).unwrap_err(),
        InjectorError::MissingSecret { .. }
    ));
    for bad in ["", " padded", "line\nbreak", "nul\0"] {
        let mut secrets = Secrets::new();
        secrets.insert("openai", SecretString::from(bad));
        assert!(Injector::new(rules(), secrets).is_err(), "{bad:?}");
    }

    let mut query_only = spec(
        "q",
        "q.example.test",
        GEMINI_DUMMY,
        InjectSpec {
            query: Some("key".into()),
            ..InjectSpec::default()
        },
    );
    query_only.secret = "q".into();
    let mut secrets = Secrets::new();
    secrets.insert(
        "q",
        SecretString::from(" spaces and\nnewlines are fine in a query "),
    );
    assert!(Injector::new(RuleSet::new(vec![query_only]).unwrap(), secrets).is_ok());
}

#[test]
fn debug_output_never_contains_secret_values() {
    let rendered = format!("{:?}", injector());

    for secret in [OPENAI_SECRET, GEMINI_SECRET, BASIC_SECRET] {
        assert!(!rendered.contains(secret));
    }
}

#[test]
fn rule_specs_parse_from_toml() {
    #[derive(serde::Deserialize)]
    struct File {
        rule: Vec<RuleSpec>,
    }
    let file: File = toml::from_str(&format!(
        r#"
        [[rule]]
        name = "gemini"
        host = "generativelanguage.googleapis.com"
        secret = "gemini"
        dummy = "{GEMINI_DUMMY}"
        inject = {{ header = "x-goog-api-key", query = "key" }}
        "#
    ))
    .unwrap();
    let rules = RuleSet::new(file.rule).unwrap();

    assert_eq!(rules.rules()[0].bindings()[0].locations().len(), 2);
    assert_eq!(
        rules.hosts().collect::<Vec<_>>(),
        ["generativelanguage.googleapis.com"]
    );
}

#[test]
fn generated_dummies_are_valid_and_distinct() {
    let a = credshim_core::dummy::generate("sk-credshim-openai-");
    let b = credshim_core::dummy::generate("sk-credshim-openai-");

    assert_ne!(a, b);
    assert!(a.starts_with("sk-credshim-openai-"));
    let mut spec = spec("openai", "api.openai.com", &a, header("authorization"));
    spec.dummy = a;
    assert!(RuleSet::new(vec![spec]).is_ok());
}
