use std::collections::HashMap;
use std::sync::Arc;

use credshim_core::dummy::{self, ACCESS_TOKEN_PREFIX, REFRESH_TOKEN_PREFIX};
use credshim_core::{
    Binding, Destination, InjectSpec, Injector, Location, Rule, RuleError, RuleSet, RuleSpec,
    SecretRef, Secrets, TokenResolver, Verdict,
};
use http::Request;
use http::header::AUTHORIZATION;
use http::request::Parts;
use secrecy::SecretString;

const RESOURCE: Destination = Destination {
    host: "api.example.test",
    port: 443,
};
const TOKEN_HOST: Destination = Destination {
    host: "oauth.example.test",
    port: 443,
};
const REAL_ACCESS: &str = "real-access-token";
const REAL_REFRESH: &str = "real-refresh-token";

#[derive(Debug, Default)]
struct Tokens(HashMap<String, (&'static str, Vec<Binding>)>);

impl TokenResolver for Tokens {
    fn resolve(&self, dummy: &str) -> Option<Rule> {
        let (real, bindings) = self.0.get(dummy)?;
        Some(Rule::issued(
            "oauth.example.access".to_string(),
            dummy.to_string(),
            SecretString::from(*real),
            bindings.clone(),
        ))
    }
}

struct Fixture {
    injector: Injector,
    access: String,
    refresh: String,
}

fn fixture() -> Fixture {
    let access = dummy::generate(ACCESS_TOKEN_PREFIX);
    let refresh = dummy::generate(REFRESH_TOKEN_PREFIX);
    let mut tokens = Tokens::default();
    tokens.0.insert(
        access.clone(),
        (
            REAL_ACCESS,
            vec![
                Binding::new(
                    "api.example.test",
                    443,
                    None,
                    vec![Location::Header(AUTHORIZATION)],
                )
                .unwrap(),
            ],
        ),
    );
    tokens.0.insert(
        refresh.clone(),
        (
            REAL_REFRESH,
            vec![Binding::new("oauth.example.test", 443, Some("/token".into()), vec![]).unwrap()],
        ),
    );
    let injector = Injector::new(RuleSet::default(), Secrets::new())
        .unwrap()
        .with_tokens(Arc::new(tokens));
    Fixture {
        injector,
        access,
        refresh,
    }
}

fn request(uri: &str, headers: &[(&str, &str)]) -> Parts {
    let mut builder = Request::builder().uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(()).unwrap().into_parts().0
}

#[test]
fn issued_access_token_is_replaced_only_at_its_resource_hosts() {
    let f = fixture();
    let bearer = format!("Bearer {}", f.access);

    let mut parts = request("/v1/me", &[("authorization", &bearer)]);
    let verdict = f.injector.apply(RESOURCE, &mut parts).unwrap();
    assert_eq!(
        verdict,
        Verdict::Injected(vec!["oauth.example.access".to_string()])
    );
    assert_eq!(
        parts.headers.get(AUTHORIZATION).unwrap(),
        &format!("Bearer {REAL_ACCESS}")
    );

    let mut parts = request("/token", &[("authorization", &bearer)]);
    assert!(matches!(
        f.injector.apply(TOKEN_HOST, &mut parts).unwrap(),
        Verdict::Denied(_)
    ));
    assert_eq!(parts.headers.get(AUTHORIZATION).unwrap(), &bearer);
}

#[test]
fn binding_without_locations_allows_the_dummy_but_never_substitutes() {
    let f = fixture();
    let mut parts = request("/token", &[("x-debug", &format!("refresh={}", f.refresh))]);
    let before = parts.headers.clone();

    assert_eq!(
        f.injector.apply(TOKEN_HOST, &mut parts).unwrap(),
        Verdict::Pass
    );
    assert_eq!(parts.headers, before);

    let mut parts = request("/other", &[("x-debug", &f.refresh)]);
    assert!(matches!(
        f.injector.apply(TOKEN_HOST, &mut parts).unwrap(),
        Verdict::Denied(_)
    ));
}

#[test]
fn unknown_issued_tokens_pass_untouched() {
    let f = fixture();
    let stranger = dummy::generate(ACCESS_TOKEN_PREFIX);
    let bearer = format!("Bearer {stranger}");
    let mut parts = request("/v1/me", &[("authorization", &bearer)]);

    assert_eq!(
        f.injector.apply(TOKEN_HOST, &mut parts).unwrap(),
        Verdict::Pass
    );
    assert_eq!(parts.headers.get(AUTHORIZATION).unwrap(), &bearer);
}

#[test]
fn issued_tokens_are_found_in_queries_and_plain_http_checks() {
    let f = fixture();
    let parts = request(&format!("/v1/me?access_token={}", f.access), &[]);

    assert_eq!(
        f.injector.first_dummy_in(&parts).as_deref(),
        Some("oauth.example.access")
    );
    assert_eq!(f.injector.first_dummy_in(&request("/", &[])), None);
}

#[test]
fn a_rule_may_be_bound_to_several_destinations() {
    let bindings = vec![
        Binding::new(
            "oauth.example.test",
            443,
            Some("/token".into()),
            vec![Location::BasicAuth],
        )
        .unwrap(),
        Binding::new(
            "oauth.example.test",
            443,
            Some("/revoke".into()),
            vec![Location::BasicAuth],
        )
        .unwrap(),
    ];
    let dummy = "credshim-client-secret-0123456789abcdef";
    let rule = Rule::new(
        "oauth.example".to_string(),
        dummy.to_string(),
        SecretRef::Named("client".to_string()),
        bindings,
    )
    .unwrap();
    let mut secrets = Secrets::new();
    secrets.insert("client", SecretString::from("real-client-secret"));
    let injector = Injector::new(RuleSet::from_rules(vec![rule]).unwrap(), secrets).unwrap();
    let basic = |secret: &str| {
        use base64::Engine;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("client-id:{secret}"))
        )
    };

    for path in ["/token", "/revoke"] {
        let mut parts = request(path, &[("authorization", &basic(dummy))]);
        assert!(matches!(
            injector.apply(TOKEN_HOST, &mut parts).unwrap(),
            Verdict::Injected(_)
        ));
        assert_eq!(
            parts.headers.get(AUTHORIZATION).unwrap(),
            &basic("real-client-secret")
        );
    }
    let mut parts = request("/userinfo", &[("authorization", &basic(dummy))]);
    assert!(matches!(
        injector.apply(TOKEN_HOST, &mut parts).unwrap(),
        Verdict::Denied(_)
    ));
}

#[test]
fn static_dummies_may_not_use_issued_token_prefixes() {
    let spec = RuleSpec {
        name: "x".to_string(),
        host: "x.example.test".to_string(),
        port: None,
        path_prefix: None,
        allow_methods: None,
        allow_paths: None,
        limits: Default::default(),
        base_url_prefix: None,
        env: None,
        secret: "x".to_string(),
        dummy: format!("prefix-{}", dummy::generate(ACCESS_TOKEN_PREFIX)),
        inject: InjectSpec {
            header: Some("authorization".to_string()),
            ..InjectSpec::default()
        },
    };

    assert_eq!(
        RuleSet::new(vec![spec]).unwrap_err(),
        RuleError::ReservedDummy("x".to_string())
    );
}

#[test]
fn issued_token_finder_needs_the_full_random_part() {
    let token = dummy::generate(REFRESH_TOKEN_PREFIX);
    let text = format!("a={token}&b=csh_at_short");

    assert_eq!(
        dummy::find_issued(text.as_bytes()).collect::<Vec<_>>(),
        [token.as_str()]
    );
}
