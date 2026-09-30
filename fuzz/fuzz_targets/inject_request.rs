#![no_main]

use std::sync::LazyLock;

use credshim_core::{Destination, InjectSpec, Injector, RuleSet, RuleSpec, Secrets, Verdict};
use libfuzzer_sys::fuzz_target;
use secrecy::SecretString;

const REAL: &str = "REAL-SECRET-VALUE-0123456789";

static INJECTOR: LazyLock<Injector> = LazyLock::new(|| {
    let spec = |name: &str, dummy: &str, inject: InjectSpec| RuleSpec {
        name: name.into(),
        host: "api.example.test".into(),
        port: None,
        path_prefix: Some("/v1".into()),
        allow_methods: None,
        allow_paths: None,
        limits: Default::default(),
        secret: "real".into(),
        dummy: dummy.into(),
        inject,
    };
    let rules = RuleSet::new(vec![
        spec(
            "header",
            "credshim-fuzz-header-000000000000",
            InjectSpec {
                header: Some("authorization".into()),
                ..InjectSpec::default()
            },
        ),
        spec(
            "basic",
            "credshim-fuzz-basic-1111111111111",
            InjectSpec {
                basic: true,
                ..InjectSpec::default()
            },
        ),
        spec(
            "query",
            "credshim-fuzz-query-2222222222222",
            InjectSpec {
                query: Some("key".into()),
                ..InjectSpec::default()
            },
        ),
    ])
    .unwrap();
    let mut secrets = Secrets::new();
    secrets.insert("real", SecretString::from(REAL));
    Injector::new(rules, secrets).unwrap()
});

fuzz_target!(|data: &[u8]| {
    let mut fields = data.split(|b| *b == 0);
    let path = fields.next().unwrap_or_default();
    let Ok(path) = std::str::from_utf8(path) else {
        return;
    };
    let Ok(mut builder) = http::Request::builder()
        .uri(format!("/{path}"))
        .body(())
        .map(|req| req.into_parts().0)
    else {
        return;
    };
    for (i, value) in fields.enumerate() {
        let name = ["authorization", "x-api-key", "cookie"][i % 3];
        if let Ok(value) = http::HeaderValue::from_bytes(value) {
            builder.headers.append(name, value);
        }
    }
    let before = format!("{:?}{:?}", builder.uri, builder.headers);
    for host in ["api.example.test", "evil.example.test"] {
        let mut parts = builder.clone();
        let verdict = INJECTOR
            .apply(Destination { host, port: 443 }, &mut parts)
            .unwrap_or(Verdict::Pass);
        let after = format!("{:?}{:?}", parts.uri, parts.headers);
        if !matches!(verdict, Verdict::Injected(_)) {
            assert_eq!(before, after, "only an injection may change the request");
        }
        if host == "evil.example.test" {
            assert!(!after.contains(REAL) || before.contains(REAL));
        }
    }
});
