use std::sync::Arc;
use std::time::Duration as StdDuration;

use credshim_mitm::CertificateAuthority;
use credshim_testkit::install_crypto_provider;
use rustls::time_provider::TimeProvider;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::{ServerName, UnixTime};
use time::{Duration, OffsetDateTime};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const API: &str = "api.example.test";

#[derive(Debug)]
struct WallClock(OffsetDateTime);

impl TimeProvider for WallClock {
    fn current_time(&self) -> Option<UnixTime> {
        let seconds = u64::try_from(self.0.unix_timestamp()).ok()?;
        Some(UnixTime::since_unix_epoch(StdDuration::from_secs(seconds)))
    }
}

fn dev_ca() -> (CertificateAuthority, tempfile::TempDir) {
    install_crypto_provider();
    let dir = tempfile::tempdir().unwrap();
    let ca = CertificateAuthority::init(&dir.path().join("ca")).unwrap();
    (ca, dir)
}

async fn handshake_at(
    ca: &CertificateAuthority,
    config: Arc<ServerConfig>,
    now: OffsetDateTime,
) -> std::io::Result<()> {
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert_der().clone()).unwrap();
    let client = ClientConfig::builder_with_details(
        Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        Arc::new(WallClock(now)),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (connected, _) = tokio::join!(
        TlsConnector::from(Arc::new(client)).connect(ServerName::try_from(API).unwrap(), client_io),
        TlsAcceptor::from(config).accept(server_io),
    );
    connected.map(drop)
}

#[tokio::test]
async fn a_leaf_cached_before_a_long_sleep_is_reissued_for_the_wall_clock_on_wake() {
    let (ca, _dir) = dev_ca();
    let issued = OffsetDateTime::now_utc();
    let before_sleep = ca.server_config_at(API, issued).unwrap();
    handshake_at(&ca, before_sleep.clone(), issued)
        .await
        .unwrap();

    let wake = issued + Duration::hours(63);
    let err = handshake_at(&ca, before_sleep.clone(), wake)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("expired"), "{err}");

    let after_wake = ca.server_config_at(API, wake).unwrap();

    assert!(!Arc::ptr_eq(&before_sleep, &after_wake));
    handshake_at(&ca, after_wake.clone(), wake).await.unwrap();
    assert!(Arc::ptr_eq(
        &after_wake,
        &ca.server_config_at(API, wake + Duration::minutes(5))
            .unwrap()
    ));
}

#[tokio::test]
async fn a_leaf_is_reused_while_it_has_half_its_validity_left_and_reissued_after() {
    let (ca, _dir) = dev_ca();
    let issued = OffsetDateTime::now_utc();
    let first = ca.server_config_at(API, issued).unwrap();

    let reused = ca
        .server_config_at(API, issued + Duration::hours(11))
        .unwrap();
    assert!(Arc::ptr_eq(&first, &reused));

    let near_expiry = issued + Duration::hours(13);
    let renewed = ca.server_config_at(API, near_expiry).unwrap();
    assert!(!Arc::ptr_eq(&first, &renewed));
    handshake_at(&ca, renewed, near_expiry + Duration::hours(20))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_leaf_is_reissued_when_the_wall_clock_moves_back_before_its_start() {
    let (ca, _dir) = dev_ca();
    let issued = OffsetDateTime::now_utc();
    let first = ca.server_config_at(API, issued).unwrap();

    let rewound = issued - Duration::hours(3);
    let renewed = ca.server_config_at(API, rewound).unwrap();

    assert!(!Arc::ptr_eq(&first, &renewed));
    handshake_at(&ca, renewed, rewound).await.unwrap();
}
