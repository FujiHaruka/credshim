use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration, OffsetDateTime};
pub struct TestCa {
    issuer: CertifiedIssuer<'static, KeyPair>,
}
#[derive(Clone)]
pub struct LeafCert {
    pub cert_der: CertificateDer<'static>,
    pub key_der: Arc<PrivatePkcs8KeyDer<'static>>,
    pub chain: Vec<CertificateDer<'static>>,
}
#[derive(Clone, Debug)]
pub struct LeafOptions {
    pub names: Vec<String>,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

impl LeafOptions {
    pub fn valid_for(names: &[&str]) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            names: names.iter().map(|n| n.to_string()).collect(),
            not_before: now - Duration::hours(1),
            not_after: now + Duration::days(7),
        }
    }

    pub fn expired(names: &[&str]) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            names: names.iter().map(|n| n.to_string()).collect(),
            not_before: now - Duration::days(30),
            not_after: now - Duration::days(1),
        }
    }
}

impl TestCa {
    pub fn new() -> Self {
        Self::with_name("credshim test CA")
    }

    pub fn with_name(common_name: &str) -> Self {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1);
        params.not_after = now + Duration::days(30);
        let key = KeyPair::generate().expect("generate CA key");
        let issuer = CertifiedIssuer::self_signed(params, key).expect("self-sign CA");
        Self { issuer }
    }

    pub fn cert_der(&self) -> CertificateDer<'static> {
        self.issuer.der().clone()
    }

    pub fn cert_pem(&self) -> String {
        self.issuer.pem()
    }

    pub fn root_store(&self) -> RootCertStore {
        let mut store = RootCertStore::empty();
        store
            .add(self.cert_der())
            .expect("add test CA to root store");
        store
    }

    pub fn issue(&self, names: &[&str]) -> LeafCert {
        self.issue_with(LeafOptions::valid_for(names))
    }

    pub fn issue_with(&self, opts: LeafOptions) -> LeafCert {
        let mut params = CertificateParams::new(opts.names.clone()).expect("leaf params");
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            opts.names.first().cloned().unwrap_or_default(),
        );
        params.distinguished_name = dn;
        params.not_before = opts.not_before;
        params.not_after = opts.not_after;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let key = KeyPair::generate().expect("generate leaf key");
        let cert = params.signed_by(&key, &self.issuer).expect("sign leaf");
        let cert_der = cert.der().clone();
        LeafCert {
            chain: vec![cert_der.clone()],
            cert_der,
            key_der: Arc::new(PrivatePkcs8KeyDer::from(key.serialize_der())),
        }
    }
}

impl Default for TestCa {
    fn default() -> Self {
        Self::new()
    }
}

impl LeafCert {
    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(self.key_der.clone_key())
    }

    pub fn server_config(&self, alpn: &[&[u8]]) -> Arc<rustls::ServerConfig> {
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.chain.clone(), self.private_key())
            .expect("server config");
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Arc::new(config)
    }
}
