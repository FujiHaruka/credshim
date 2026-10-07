mod common;

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use common::h2_over_proxy;
use credshim_core::{InjectSpec, Injector, Limiter, Limits, RuleSet, RuleSpec, Secrets};
use credshim_mitm::{
    BindError, CertificateAuthority, Intercept, Proxy, ProxyConfig, Reload, TestingHooks, Upstream,
};
use credshim_testkit::{
    Alpn, Echo, MockUpstream, SseTick, TestCa, capture_logs, fake_secret, install_crypto_provider,
};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http2::SendRequest;
use rustls::RootCertStore;
use secrecy::SecretString;

const API: &str = "api.example.test";
const OTHER: &str = "other.example.test";
const API_DUMMY: &str = "credshim-reload-api-EEEEEEEEEEEEEEEEEEEEEEEEEEEEE";
const OTHER_DUMMY: &str = "credshim-reload-other-EEEEEEEEEEEEEEEEEEEEEEEEEEE";

struct Setup {
    proxy: Proxy,
    dev_ca: Arc<CertificateAuthority>,
    mock: MockUpstream,
    _dir: tempfile::TempDir,
}

fn rule(name: &str, host: &str, dummy: &str, limits: Limits) -> RuleSpec {
    RuleSpec {
        name: name.into(),
        host: host.into(),
        port: None,
        path_prefix: None,
        allow_methods: None,
        allow_paths: None,
        limits,
        base_url_prefix: None,
        env: None,
        secret: name.into(),
        dummy: dummy.into(),
        inject: InjectSpec {
            header: Some("authorization".into()),
            ..InjectSpec::default()
        },
    }
}

fn injector(rules: Vec<(RuleSpec, &str)>, limiter: Option<Arc<Limiter>>) -> Arc<Injector> {
    let mut secrets = Secrets::new();
    for (spec, secret) in &rules {
        secrets.insert(spec.name.clone(), SecretString::from(*secret));
    }
    let injector = Injector::new(
        RuleSet::new(rules.into_iter().map(|(spec, _)| spec).collect()).unwrap(),
        secrets,
    )
    .unwrap();
    Arc::new(match limiter {
        Some(limiter) => injector.with_limiter(limiter),
        None => injector,
    })
}

impl Setup {
    async fn new(injector: Arc<Injector>) -> Self {
        install_crypto_provider();
        let upstream_ca = TestCa::new();
        let mock = MockUpstream::https(upstream_ca.issue(&[API, OTHER]))
            .alpn(Alpn::H2Only)
            .start()
            .await;
        let dir = tempfile::tempdir().unwrap();
        let dev_ca = Arc::new(CertificateAuthority::init(dir.path()).unwrap());
        let upstream = Upstream::with_testing_hooks(TestingHooks {
            extra_trust_anchors: vec![upstream_ca.cert_der()],
            resolve_overrides: HashMap::from([
                (API.to_string(), mock.addr()),
                (OTHER.to_string(), mock.addr()),
            ]),
        })
        .unwrap();
        let mut config = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
        config.intercept = Some(Intercept::new(dev_ca.clone(), [API]));
        config.injector = injector;
        let proxy = Proxy::bind(config, upstream).await.unwrap();
        Self {
            proxy,
            dev_ca,
            mock,
            _dir: dir,
        }
    }

    fn reload(&self, hosts: &[&str], injector: Arc<Injector>) -> Result<(), BindError> {
        self.proxy.reloader().reload(Reload {
            intercept: Some(Intercept::new(self.dev_ca.clone(), hosts)),
            injector,
            oauth: None,
            aws: None,
            scrub: true,
            base_urls: Default::default(),
        })
    }

    async fn connection(&self, host: &str) -> SendRequest<Full<Bytes>> {
        let mut roots = RootCertStore::empty();
        roots.add(self.dev_ca.cert_der().clone()).unwrap();
        h2_over_proxy(self.proxy.local_addr(), &format!("{host}:443"), roots).await
    }
}

fn request(host: &str, path: &str, dummy: &str) -> http::Request<Full<Bytes>> {
    http::Request::get(format!("https://{host}{path}"))
        .header("authorization", format!("Bearer {dummy}"))
        .body(Full::new(Bytes::new()))
        .unwrap()
}

async fn echoed_authorization(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    dummy: &str,
) -> (u16, Option<String>) {
    let response = sender
        .send_request(request(host, "/echo", dummy))
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let authorization = serde_json::from_slice::<Echo>(&body)
        .ok()
        .and_then(|echo| echo.header("authorization").map(str::to_string));
    (status, authorization)
}

async fn next_tick(body: &mut hyper::body::Incoming) -> Option<SseTick> {
    loop {
        let frame = body.frame().await?.unwrap();
        if let Ok(data) = frame.into_data() {
            let text = String::from_utf8(data.to_vec()).unwrap();
            if let Some(json) = text.trim().strip_prefix("data:") {
                return Some(serde_json::from_str(json.trim()).unwrap());
            }
        }
    }
}

#[tokio::test]
async fn reload_applies_to_the_next_request_on_an_open_connection_and_leaves_a_stream_running() {
    let logs = capture_logs();
    let old_secret = fake_secret("reload-old");
    let new_secret = fake_secret("reload-new");
    let other_secret = fake_secret("reload-other");
    let setup = Setup::new(injector(
        vec![(rule("api", API, API_DUMMY, Limits::default()), &old_secret)],
        None,
    ))
    .await;
    let mut api = setup.connection(API).await;

    let stream = api
        .send_request(request(API, "/sse?count=8&interval_ms=100", API_DUMMY))
        .await
        .unwrap();
    assert_eq!(stream.status(), 200);
    let mut stream = stream.into_body();
    assert_eq!(next_tick(&mut stream).await.unwrap().seq, 0);
    assert_eq!(
        echoed_authorization(&mut api, API, API_DUMMY).await,
        (200, Some(format!("Bearer {old_secret}")))
    );

    setup
        .reload(
            &[API, OTHER],
            injector(
                vec![
                    (rule("api", API, API_DUMMY, Limits::default()), &new_secret),
                    (
                        rule("other", OTHER, OTHER_DUMMY, Limits::default()),
                        &other_secret,
                    ),
                ],
                None,
            ),
        )
        .unwrap();

    assert_eq!(
        echoed_authorization(&mut api, API, API_DUMMY).await,
        (200, Some(format!("Bearer {new_secret}")))
    );
    let mut other = setup.connection(OTHER).await;
    assert_eq!(
        echoed_authorization(&mut other, OTHER, OTHER_DUMMY).await,
        (200, Some(format!("Bearer {other_secret}")))
    );
    let mut seqs = Vec::new();
    while let Some(tick) = next_tick(&mut stream).await {
        seqs.push(tick.seq);
    }
    assert_eq!(seqs, (1..8).collect::<Vec<_>>());
    logs.assert_absent(&[&old_secret, &new_secret, &other_secret]);
}

#[tokio::test]
async fn a_reload_whose_rule_host_is_not_intercepted_is_refused_and_the_running_rules_stay() {
    let secret = fake_secret("reload-refused");
    let setup = Setup::new(injector(
        vec![(rule("api", API, API_DUMMY, Limits::default()), &secret)],
        None,
    ))
    .await;

    let refused = setup.reload(
        &[API],
        injector(
            vec![(
                rule("other", OTHER, OTHER_DUMMY, Limits::default()),
                &secret,
            )],
            None,
        ),
    );

    assert!(matches!(refused, Err(BindError::RuleHostNotIntercepted(host)) if host == OTHER));
    let mut api = setup.connection(API).await;
    assert_eq!(
        echoed_authorization(&mut api, API, API_DUMMY).await,
        (200, Some(format!("Bearer {secret}")))
    );
}

#[tokio::test]
async fn limits_count_across_a_reload_that_carries_the_limiter() {
    let secret = fake_secret("reload-limits");
    let limits = Limits {
        concurrent: Some(1),
        per_minute: Some(2),
        ..Limits::default()
    };
    let running = injector(vec![(rule("api", API, API_DUMMY, limits), &secret)], None);
    let limiter = running.limiter();
    let setup = Setup::new(running).await;
    let mut api = setup.connection(API).await;
    let stream = api
        .send_request(request(API, "/sse?count=4&interval_ms=100", API_DUMMY))
        .await
        .unwrap();
    let mut stream = stream.into_body();
    assert!(next_tick(&mut stream).await.is_some());

    setup
        .reload(
            &[API],
            injector(
                vec![(rule("api", API, API_DUMMY, limits), &secret)],
                Some(limiter),
            ),
        )
        .unwrap();

    assert_eq!(
        echoed_authorization(&mut api, API, API_DUMMY).await.0,
        429,
        "the stream opened before the reload still holds the one concurrent slot"
    );
    while next_tick(&mut stream).await.is_some() {}
    drop(stream);
    let mut after_stream = 429;
    for _ in 0..50 {
        after_stream = echoed_authorization(&mut api, API, API_DUMMY).await.0;
        if after_stream != 429 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(after_stream, 200);
    assert_eq!(
        echoed_authorization(&mut api, API, API_DUMMY).await.0,
        429,
        "two requests this minute, one of them before the reload"
    );
    assert_eq!(setup.mock.request_count(), 2);
}
