use std::io;
use std::sync::Arc;

use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use rustls_platform_verifier::Verifier;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

#[cfg(feature = "testing")]
pub const TESTING_HOOKS_MARKER: &str = "credshim-testing-hooks-enabled";

#[cfg(feature = "testing")]
#[derive(Clone, Default)]
pub struct TestingHooks {
    pub extra_trust_anchors: Vec<rustls_pki_types::CertificateDer<'static>>,
    pub resolve_overrides: std::collections::HashMap<String, std::net::SocketAddr>,
}

#[derive(Clone)]
pub struct Upstream {
    tls: Arc<ClientConfig>,
    #[cfg(feature = "testing")]
    hooks: TestingHooks,
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("could not connect to upstream {host}:{port}: {source}")]
    Tcp {
        host: String,
        port: u16,
        source: io::Error,
    },
    #[error("upstream {host}:{port} failed TLS verification: {source}")]
    Tls {
        host: String,
        port: u16,
        source: io::Error,
    },
    #[error("invalid upstream server name {0:?}")]
    InvalidName(String),
}

impl Upstream {
    pub fn new() -> anyhow::Result<Self> {
        let verifier = Verifier::new(crypto_provider())?;
        Ok(Self {
            tls: Arc::new(client_config(verifier)),
            #[cfg(feature = "testing")]
            hooks: TestingHooks::default(),
        })
    }

    #[cfg(feature = "testing")]
    pub fn with_testing_hooks(hooks: TestingHooks) -> anyhow::Result<Self> {
        tracing::warn!(
            marker = TESTING_HOOKS_MARKER,
            "upstream testing hooks are active"
        );
        let verifier =
            Verifier::new_with_extra_roots(hooks.extra_trust_anchors.clone(), crypto_provider())?;
        Ok(Self {
            tls: Arc::new(client_config(verifier)),
            hooks,
        })
    }

    pub async fn connect_tcp(&self, host: &str, port: u16) -> Result<TcpStream, ConnectError> {
        #[cfg(feature = "testing")]
        if let Some(addr) = self.hooks.resolve_overrides.get(host) {
            return TcpStream::connect(addr)
                .await
                .map_err(|source| ConnectError::Tcp {
                    host: host.to_string(),
                    port,
                    source,
                });
        }
        TcpStream::connect((host, port))
            .await
            .map_err(|source| ConnectError::Tcp {
                host: host.to_string(),
                port,
                source,
            })
    }

    pub async fn connect_tls(
        &self,
        host: &str,
        port: u16,
        alpn: &[&[u8]],
    ) -> Result<TlsStream<TcpStream>, ConnectError> {
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| ConnectError::InvalidName(host.to_string()))?;
        let tcp = self.connect_tcp(host, port).await?;
        let mut config = (*self.tls).clone();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        TlsConnector::from(Arc::new(config))
            .connect(server_name, tcp)
            .await
            .map_err(|source| ConnectError::Tls {
                host: host.to_string(),
                port,
                source,
            })
    }
}

fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn client_config(verifier: Verifier) -> ClientConfig {
    ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth()
}
