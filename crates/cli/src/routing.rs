use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use credshim_core::{BaseUrls, Injector, Limiter, Rule, RuleSet};
use credshim_mitm::{CertificateAuthority, Intercept, Reload, Upstream};
use credshim_oauth::OAuth;
use credshim_secrets::{BackendConfig, SecretStore};

use crate::config::Config;

const RESTART_ONLY: [&str; 10] = [
    "listen", "ca", "secrets", "audit", "status", "ssh", "ssh_key", "oauth", "vault", "limits",
];

pub fn restart_only_changes(running: &toml::Table, loaded: &toml::Table) -> Vec<&'static str> {
    RESTART_ONLY
        .into_iter()
        .filter(|section| running.get(*section) != loaded.get(*section))
        .collect()
}

pub struct Sources {
    backend: BackendConfig,
    store: Option<Arc<dyn SecretStore>>,
    ca_dir: PathBuf,
    ca: Option<Arc<CertificateAuthority>>,
    upstream: Upstream,
    oauth: Option<Arc<OAuth>>,
    base_url_listener: bool,
    rule_limiter: Arc<Limiter>,
    aws_limiter: Arc<Limiter>,
}

impl Sources {
    pub fn new(
        backend: BackendConfig,
        config: &Config,
        upstream: Upstream,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            backend,
            store: None,
            ca_dir: config.ca_dir()?,
            ca: None,
            upstream,
            oauth: None,
            base_url_listener: config.listen.base_url_addr.is_some(),
            rule_limiter: Arc::default(),
            aws_limiter: Arc::default(),
        })
    }

    pub fn store(&mut self) -> anyhow::Result<Arc<dyn SecretStore>> {
        if let Some(store) = &self.store {
            return Ok(store.clone());
        }
        let store: Arc<dyn SecretStore> = Arc::from(self.backend.open()?);
        self.store = Some(store.clone());
        Ok(store)
    }

    pub fn ca(&mut self) -> anyhow::Result<Option<Arc<CertificateAuthority>>> {
        if self.ca.is_none() && self.ca_dir.join(credshim_mitm::ca::KEY_FILE).exists() {
            self.ca = Some(Arc::new(CertificateAuthority::load(&self.ca_dir)?));
        }
        Ok(self.ca.clone())
    }

    pub fn set_oauth(&mut self, oauth: Arc<OAuth>) {
        self.oauth = Some(oauth);
    }

    pub fn build(&mut self, config: &Config) -> anyhow::Result<Reload> {
        let mut rules = config
            .rules
            .iter()
            .cloned()
            .map(Rule::from_spec)
            .collect::<Result<Vec<_>, _>>()?;
        let mut reload = Reload {
            intercept: None,
            injector: Arc::new(Injector::default().with_limiter(self.rule_limiter.clone())),
            oauth: self.oauth.clone(),
            aws: None,
            scrub: config.scrub.enabled.unwrap_or(true),
            base_urls: self.base_urls(config)?,
        };
        if rules.is_empty() && self.oauth.is_none() && !config.has_aws() {
            return Ok(reload);
        }
        if let Some(oauth) = &self.oauth {
            rules.extend(oauth.client_secret_rules()?);
        }
        let store = self.store()?;
        let rules = RuleSet::from_rules(rules)?;
        let secrets = crate::load_secrets(store.as_ref(), &rules)?;
        let aws = crate::load_aws(config, &store, &self.upstream)?;
        let mut injector = Injector::new(rules, secrets)?
            .with_limiter(self.rule_limiter.clone())
            .also_scrub(
                aws.iter()
                    .flat_map(|(aws, _)| aws.signer().scrub_pairs())
                    .collect(),
            );
        if let Some((_, Some(sso))) = &aws {
            injector = injector.with_scrub_source(sso.clone());
        }
        let aws = aws.map(|(aws, _)| aws.with_limiter(self.aws_limiter.clone()));
        for rule in injector.unscrubbable_rules() {
            tracing::warn!(
                %rule,
                "secret is shorter than {} bytes, so responses echoing it cannot be scrubbed",
                credshim_core::scrub::MIN_SCRUB_LEN
            );
        }
        if let Some(oauth) = &self.oauth {
            injector = injector.with_tokens(oauth.clone());
        }
        let ca = self
            .ca()?
            .context("rules need a CA; create one with `credshim ca init`")?;
        let hosts = injector
            .rules()
            .hosts()
            .chain(self.oauth.iter().flat_map(|oauth| oauth.hosts()));
        let mut intercept = Intercept::new(ca, hosts);
        if aws.is_some() {
            intercept = intercept.with_domains([credshim_aws::AWS_DOMAIN]);
        }
        reload.intercept = Some(intercept);
        reload.injector = Arc::new(injector);
        reload.aws = aws.map(Arc::new);
        Ok(reload)
    }

    fn base_urls(&self, config: &Config) -> anyhow::Result<BaseUrls> {
        let base_urls = BaseUrls::from_specs(&config.rules)?;
        if self.base_url_listener {
            return Ok(base_urls);
        }
        if !base_urls.is_empty() {
            tracing::info!(
                "rules name a base_url_prefix but [listen] base_url_addr is not set; base URL mode is off"
            );
        }
        Ok(BaseUrls::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use credshim_testkit::fake_secret;
    use secrecy::SecretString;

    #[test]
    fn every_build_counts_against_the_same_limiters() {
        credshim_testkit::install_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        CertificateAuthority::init(&dir.path().join("ca")).unwrap();
        let backend = BackendConfig::AgeFile {
            path: dir.path().join("secrets.age"),
            identity: None,
        };
        let store = backend.open().unwrap();
        for name in ["openai", "aws-access-key-id", "aws-secret-access-key"] {
            store
                .set(name, SecretString::from(fake_secret(name)))
                .unwrap();
        }
        let config: Config = toml::from_str(&format!(
            r#"
            [ca]
            dir = "{ca}"

            [[rule]]
            name = "openai"
            host = "api.openai.com"
            secret = "openai"
            dummy = "sk-credshim-openai-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
            inject = {{ header = "authorization" }}

            [[aws_key]]
            name = "aws"
            dummy_access_key_id = "CREDSHIMAWSEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
            access_key_id = "aws-access-key-id"
            secret_access_key = "aws-secret-access-key"
            "#,
            ca = dir.path().join("ca").display()
        ))
        .unwrap();
        let mut sources = Sources::new(backend, &config, Upstream::new().unwrap()).unwrap();

        let first = sources.build(&config).unwrap();
        let second = sources.build(&config).unwrap();

        assert!(Arc::ptr_eq(
            &first.injector.limiter(),
            &second.injector.limiter()
        ));
        assert!(Arc::ptr_eq(
            &first.aws.unwrap().limiter(),
            &second.aws.unwrap().limiter()
        ));
    }

    #[test]
    fn only_sections_that_need_a_restart_are_reported() {
        let running: toml::Table =
            toml::from_str("[listen]\naddr = \"127.0.0.1:8787\"\n[scrub]\nenabled = true\n")
                .unwrap();
        let loaded: toml::Table = toml::from_str(
            "[listen]\naddr = \"127.0.0.1:8788\"\n[scrub]\nenabled = false\n[[oauth]]\nname = \"x\"\n[[rule]]\nname = \"y\"\n",
        )
        .unwrap();

        assert_eq!(restart_only_changes(&running, &loaded), ["listen", "oauth"]);
        assert!(restart_only_changes(&running, &running).is_empty());
    }
}
