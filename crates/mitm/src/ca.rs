use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration, OffsetDateTime};

pub const CERT_FILE: &str = "ca.pem";
pub const KEY_FILE: &str = "ca-key.pem";

const CA_VALIDITY: Duration = Duration::days(5 * 365);
const LEAF_VALIDITY: Duration = Duration::hours(24);
const LEAF_BACKDATE: Duration = Duration::hours(1);
const LEAF_CACHE_TTL: StdDuration = StdDuration::from_secs(12 * 60 * 60);
const LEAF_CACHE_CAPACITY: u64 = 1024;

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("a CA key already exists at {0}; refusing to replace a CA that clients may trust")]
    AlreadyExists(PathBuf),
    #[error("could not access {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("invalid CA material in {path}: {source}")]
    Invalid { path: PathBuf, source: rcgen::Error },
    #[error("could not issue a certificate for {host}: {reason}")]
    Issue { host: String, reason: String },
}

pub struct CertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    cert_der: CertificateDer<'static>,
    leaves: moka::sync::Cache<String, Arc<ServerConfig>>,
}

impl std::fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateAuthority")
            .finish_non_exhaustive()
    }
}

impl CertificateAuthority {
    pub fn init(dir: &Path) -> Result<Self, CaError> {
        let key_path = dir.join(KEY_FILE);
        if key_path.exists() {
            return Err(CaError::AlreadyExists(key_path));
        }
        create_private_dir(dir)?;
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|source| {
            CaError::Invalid {
                path: key_path.clone(),
                source,
            }
        })?;
        let cert = root_params()
            .self_signed(&key)
            .map_err(|source| CaError::Invalid {
                path: dir.join(CERT_FILE),
                source,
            })?;
        write_new(&key_path, key.serialize_pem().as_bytes(), 0o600)?;
        write_new(&dir.join(CERT_FILE), cert.pem().as_bytes(), 0o644)?;
        Self::load(dir)
    }

    pub fn load(dir: &Path) -> Result<Self, CaError> {
        let key_path = dir.join(KEY_FILE);
        let cert_path = dir.join(CERT_FILE);
        let key_pem = read(&key_path)?;
        let cert_pem = read(&cert_path)?;
        let key = KeyPair::from_pem(&key_pem).map_err(|source| CaError::Invalid {
            path: key_path,
            source,
        })?;
        let cert_der = pem::parse(&cert_pem)
            .map(|pem| CertificateDer::from(pem.into_contents()))
            .map_err(|_| CaError::Invalid {
                path: cert_path.clone(),
                source: rcgen::Error::CouldNotParseCertificate,
            })?;
        let issuer =
            Issuer::from_ca_cert_der(&cert_der, key).map_err(|source| CaError::Invalid {
                path: cert_path,
                source,
            })?;
        Ok(Self {
            issuer,
            cert_der,
            leaves: moka::sync::Cache::builder()
                .max_capacity(LEAF_CACHE_CAPACITY)
                .time_to_live(LEAF_CACHE_TTL)
                .build(),
        })
    }

    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, CaError> {
        let host = host.to_ascii_lowercase();
        self.leaves
            .try_get_with_by_ref(&host, || self.issue(&host))
            .map_err(|err| CaError::Issue {
                host: host.clone(),
                reason: err.to_string(),
            })
    }

    fn issue(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        let mut params =
            CertificateParams::new(vec![host.to_string()]).map_err(|e| e.to_string())?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        let now = OffsetDateTime::now_utc();
        params.not_before = now - LEAF_BACKDATE;
        params.not_after = now + LEAF_VALIDITY;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let key =
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
        let cert = params
            .signed_by(&key, &self.issuer)
            .map_err(|e| e.to_string())?;
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key_der)
        .map_err(|e| e.to_string())?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }
}

pub fn trust_bundle(dir: &Path) -> Result<String, CaError> {
    let dev_ca = read(&dir.join(CERT_FILE))?;
    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() {
        tracing::warn!(
            errors = native.errors.len(),
            "some OS root certificates could not be loaded"
        );
    }
    let mut roots: Vec<Vec<u8>> = native.certs.iter().map(|c| c.as_ref().to_vec()).collect();
    roots.sort();
    roots.dedup();
    let lf = pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF);
    let mut bundle = String::new();
    for der in roots {
        bundle.push_str(&pem::encode_config(&pem::Pem::new("CERTIFICATE", der), lf));
    }
    bundle.push_str(&dev_ca);
    Ok(bundle)
}

fn root_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "credshim development CA");
    dn.push(DnType::OrganizationName, "credshim");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - LEAF_BACKDATE;
    params.not_after = now + CA_VALIDITY;
    params
}

fn read(path: &Path) -> Result<String, CaError> {
    fs::read_to_string(path).map_err(|source| CaError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn create_private_dir(dir: &Path) -> Result<(), CaError> {
    let io_err = |source| CaError::Io {
        path: dir.to_path_buf(),
        source,
    };
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir).map_err(io_err)
}

fn write_new(path: &Path, contents: &[u8], mode: u32) -> Result<(), CaError> {
    let io_err = |source| CaError::Io {
        path: path.to_path_buf(),
        source,
    };
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode);
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options.open(path).map_err(io_err)?;
    file.write_all(contents).map_err(io_err)?;
    file.sync_all().map_err(io_err)
}
