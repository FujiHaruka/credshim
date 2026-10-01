mod config;
mod doctor;
mod env;
mod harden;
mod leftovers;
mod preset;
mod service;
mod tail;

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{IsTerminal, Write};
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use credshim_aws::{Aws, AwsCredentials, Signer, SsoOptions, SsoProvider, SsoSession};
use credshim_core::{BaseUrls, Injector, Rule, RuleSet, Secrets};
use credshim_mitm::{
    AUDIT_TARGET, CertificateAuthority, Intercept, Proxy, ProxyConfig, Stats, Upstream,
    UpstreamTransport,
};
use credshim_oauth::{DEFAULT_MAX_BODY, OAuth, Provider, Vault};
use credshim_secrets::SecretStore;
use credshim_ssh::{Agent, SigningKey, SshRule};
use secrecy::SecretString;
use tracing_subscriber::filter::{EnvFilter, Targets};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, fmt};

const VAULT_KEY_SECRET: &str = "credshim-oauth-vault-key";

#[derive(Parser)]
#[command(
    name = "credshim",
    version,
    about = "Credential-injecting proxy for local development"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run {
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
        #[arg(long)]
        listen: Option<SocketAddr>,
    },
    Ca {
        #[command(subcommand)]
        command: CaCommand,
    },
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    Status {
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
    Preset {
        #[arg(value_parser = clap::builder::PossibleValuesParser::new(
            preset::names()
        ))]
        name: String,
    },
    Env {
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
        #[arg(long, value_name = "FILE")]
        bundle: Option<PathBuf>,
    },
    Doctor {
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
        #[arg(long)]
        proxy: Option<SocketAddr>,
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
        #[arg(long)]
        snippets: bool,
        #[arg(long)]
        no_runtimes: bool,
    },
    Tail {
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
        #[arg(short = 'n', long, default_value_t = 10)]
        lines: usize,
        #[arg(long)]
        no_follow: bool,
    },
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    Ssh {
        #[command(subcommand)]
        command: SshCommand,
    },
    Aws {
        #[command(subcommand)]
        command: AwsCommand,
    },
}

#[derive(Subcommand)]
enum AwsCommand {
    Sso {
        #[command(subcommand)]
        command: SsoCommand,
    },
}

#[derive(Subcommand)]
enum SsoCommand {
    Login {
        session: String,
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
    Logout {
        session: String,
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum SshCommand {
    Keygen {
        name: String,
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ServiceCommand {
    Install {
        #[arg(long)]
        print: bool,
        #[arg(long)]
        upgrade: bool,
        #[arg(long, value_name = "NAME")]
        user: Option<String>,
    },
}

#[derive(Subcommand)]
enum CaCommand {
    Init {
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
    },
    Bundle {
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum SecretCommand {
    Set {
        name: String,
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
    List {
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    harden::disable_core_dumps()?;
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("a rustls crypto provider is already installed"))?;
    match Cli::parse().command {
        Command::Run { config, listen } => run(config.as_deref(), listen).await,
        Command::Ca {
            command: CaCommand::Init { dir },
        } => {
            init_logging(None)?;
            ca_init(&ca_dir_or_default(dir)?)
        }
        Command::Ca {
            command: CaCommand::Bundle { dir, out },
        } => {
            init_logging(None)?;
            ca_bundle(&ca_dir_or_default(dir)?, out.as_deref())
        }
        Command::Secret {
            command: SecretCommand::Set { name, config },
        } => {
            init_logging(None)?;
            secret_set(config.as_deref(), &name)
        }
        Command::Secret {
            command: SecretCommand::List { config },
        } => {
            init_logging(None)?;
            secret_list(config.as_deref())
        }
        Command::Status { config } => status(config.as_deref()).await,
        Command::Preset { name } => {
            let rendered = preset::render(&name).context("unknown preset")?;
            write!(std::io::stdout(), "{rendered}")?;
            Ok(())
        }
        Command::Env {
            config,
            ca_cert,
            bundle,
        } => print_env(config.as_deref(), ca_cert, bundle),
        Command::Doctor {
            config,
            proxy,
            ca_cert,
            snippets,
            no_runtimes,
        } => {
            if snippets {
                write!(std::io::stdout(), "{}", doctor::snippets())?;
                return Ok(());
            }
            run_doctor(config.as_deref(), proxy, ca_cert, !no_runtimes).await
        }
        Command::Tail {
            config,
            lines,
            no_follow,
        } => {
            let config = load_config(config.as_deref())?.config;
            let path = config.audit.path.context("no [audit] path is configured")?;
            tail::run(&path, lines, !no_follow).await
        }
        Command::Service {
            command:
                ServiceCommand::Install {
                    print,
                    upgrade,
                    user,
                },
        } => service::install(print, upgrade, user),
        Command::Ssh {
            command: SshCommand::Keygen { name, config },
        } => {
            init_logging(None)?;
            ssh_keygen(config.as_deref(), &name)
        }
        Command::Aws {
            command:
                AwsCommand::Sso {
                    command: SsoCommand::Login { session, config },
                },
        } => {
            init_logging(None)?;
            aws_sso_login(config.as_deref(), &session).await
        }
        Command::Aws {
            command:
                AwsCommand::Sso {
                    command: SsoCommand::Logout { session, config },
                },
        } => {
            init_logging(None)?;
            aws_sso_logout(config.as_deref(), &session).await
        }
    }
}

fn print_env(
    config_path: Option<&Path>,
    ca_cert: Option<PathBuf>,
    bundle: Option<PathBuf>,
) -> anyhow::Result<()> {
    let loaded = load_config(config_path)?;
    let config = loaded.config;
    for spec in &config.rules {
        Rule::from_spec(spec.clone())?;
    }
    let base_urls = BaseUrls::from_specs(&config.rules)?;
    let ca_dir = config.ca_dir()?;
    let cert = ca_cert.unwrap_or_else(|| ca_dir.join(credshim_mitm::ca::CERT_FILE));
    let bundle = bundle.unwrap_or_else(|| ca_dir.join(credshim_mitm::ca::BUNDLE_FILE));
    check_trust_files(&cert, &bundle)?;
    for (path, fix) in [
        (&cert, "credshim ca init"),
        (&bundle, "credshim ca bundle --out <file>"),
    ] {
        if !path.exists() {
            writeln!(
                std::io::stderr(),
                "credshim: {} does not exist yet; create it with `{fix}`",
                path.display()
            )?;
        }
    }
    let rendered = env::render(
        &config,
        &base_urls,
        &env::CaFiles {
            cert: &cert,
            bundle: &bundle,
        },
    )?;
    write!(std::io::stdout(), "{rendered}")?;
    Ok(())
}

async fn run_doctor(
    config_path: Option<&Path>,
    proxy: Option<SocketAddr>,
    ca_cert: Option<PathBuf>,
    runtimes: bool,
) -> anyhow::Result<()> {
    let proxy = proxy.or_else(doctor::proxy_from_env);
    let ca_cert = ca_cert.or_else(|| std::env::var_os("NODE_EXTRA_CA_CERTS").map(PathBuf::from));
    let (proxy, ca_cert) = match (proxy, ca_cert) {
        (Some(proxy), Some(ca_cert)) => (proxy, ca_cert),
        (proxy, ca_cert) => {
            let config = config::load(config_path)?.config;
            (
                proxy.unwrap_or_else(|| config.listen()),
                match ca_cert {
                    Some(path) => path,
                    None => config.ca_dir()?.join(credshim_mitm::ca::CERT_FILE),
                },
            )
        }
    };
    let passed = doctor::run(&doctor::Inputs {
        proxy,
        ca_cert,
        runtimes,
    })
    .await?;
    if !passed {
        bail!("doctor found problems");
    }
    Ok(())
}

fn load_config(path: Option<&Path>) -> anyhow::Result<config::Loaded> {
    let loaded = config::load(path)?;
    if let Some(source) = &loaded.source {
        harden::check_private(source, "config file")?;
    }
    Ok(loaded)
}

fn init_logging(audit: Option<File>) -> anyhow::Result<()> {
    let stderr = fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_filter(
            EnvFilter::try_from_env("CREDSHIM_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        );
    let audit = audit.map(|file| {
        fmt::layer()
            .json()
            .with_writer(Mutex::new(file))
            .with_filter(Targets::new().with_target(AUDIT_TARGET, tracing::Level::INFO))
    });
    tracing_subscriber::registry()
        .with(stderr)
        .with(audit)
        .try_init()
        .context("could not install the logger")
}

async fn run(config_path: Option<&Path>, listen: Option<SocketAddr>) -> anyhow::Result<()> {
    let loaded = load_config(config_path)?;
    let config = loaded.config;
    check_state_paths(&config)?;
    let audit = config
        .audit
        .path
        .as_deref()
        .map(open_audit_log)
        .transpose()?;
    init_logging(audit)?;
    match &loaded.source {
        Some(path) => tracing::info!(
            config = %path.display(),
            rules = config.rules.len(),
            oauth = config.oauth.len(),
            "loaded config"
        ),
        None => tracing::info!("no config file; running without rules"),
    }

    let mut rules = config
        .rules
        .iter()
        .cloned()
        .map(Rule::from_spec)
        .collect::<Result<Vec<_>, _>>()?;
    let mut proxy_config = ProxyConfig::new(listen.unwrap_or_else(|| config.listen()));
    proxy_config.allow_non_loopback = config.listen.allow_non_loopback;
    let ca_dir = config.ca_dir()?;
    let ca = if ca_dir.join(credshim_mitm::ca::KEY_FILE).exists() {
        Some(Arc::new(CertificateAuthority::load(&ca_dir)?))
    } else {
        tracing::info!(
            "no CA yet, so `credshim doctor` cannot check TLS; create one with `credshim ca init`"
        );
        None
    };
    proxy_config.doctor_ca = ca.clone();
    let base_urls = BaseUrls::from_specs(&config.rules)?;
    match config.listen.base_url_addr {
        Some(addr) => {
            proxy_config.base_url_listen = Some(addr);
            proxy_config.base_urls = base_urls;
        }
        None if !base_urls.is_empty() => {
            tracing::info!(
                "rules name a base_url_prefix but [listen] base_url_addr is not set; base URL mode is off"
            )
        }
        None => {}
    }
    proxy_config.scrub = config.scrub.enabled.unwrap_or(true);
    if !proxy_config.scrub {
        tracing::warn!("response scrubbing is disabled");
    }
    let intercepts = !rules.is_empty() || !config.oauth.is_empty() || config.has_aws();
    let store: Option<Arc<dyn SecretStore>> = if intercepts || !config.ssh_keys.is_empty() {
        Some(Arc::from(config.secrets()?.open()?))
    } else {
        None
    };
    let upstream = Upstream::new()?;
    let _agent = match &store {
        Some(store) if !config.ssh_keys.is_empty() => {
            Some(start_ssh_agent(&config, store.as_ref())?)
        }
        _ => None,
    };
    if let Some(store) = store.filter(|_| intercepts) {
        let oauth = if config.oauth.is_empty() {
            None
        } else {
            Some(Arc::new(load_oauth(&config, store.as_ref())?))
        };
        if let Some(oauth) = &oauth {
            rules.extend(oauth.client_secret_rules()?);
        }
        let rules = RuleSet::from_rules(rules)?;
        let secrets = load_secrets(store.as_ref(), &rules)?;
        let aws = load_aws(&config, &store, &upstream)?;
        let mut injector = Injector::new(rules, secrets)?.also_scrub(
            aws.iter()
                .flat_map(|(aws, _)| aws.signer().scrub_pairs())
                .collect(),
        );
        if let Some((_, Some(sso))) = &aws {
            injector = injector.with_scrub_source(sso.clone());
        }
        let aws = aws.map(|(aws, _)| aws);
        for rule in injector.unscrubbable_rules() {
            tracing::warn!(
                %rule,
                "secret is shorter than {} bytes, so responses echoing it cannot be scrubbed",
                credshim_core::scrub::MIN_SCRUB_LEN
            );
        }
        if let Some(oauth) = &oauth {
            injector = injector.with_tokens(oauth.clone());
        }
        let ca = ca.context("rules need a CA; create one with `credshim ca init`")?;
        let hosts = injector
            .rules()
            .hosts()
            .chain(oauth.iter().flat_map(|oauth| oauth.hosts()));
        let mut intercept = Intercept::new(ca, hosts);
        if aws.is_some() {
            intercept = intercept.with_domains([credshim_aws::AWS_DOMAIN]);
        }
        proxy_config.intercept = Some(intercept);
        proxy_config.injector = Arc::new(injector);
        proxy_config.oauth = oauth;
        proxy_config.aws = aws.map(Arc::new);
    }
    let aws_rules = proxy_config
        .aws
        .iter()
        .flat_map(|aws| aws.rules())
        .map(|rule| rule.name().to_string());
    proxy_config.stats = Arc::new(Stats::new(
        proxy_config
            .injector
            .rules()
            .rules()
            .iter()
            .map(|rule| rule.name().to_string())
            .chain(aws_rules),
    ));
    let _status = config
        .status
        .socket
        .as_deref()
        .map(|path| {
            harden::check_private(path, "status socket")?;
            credshim_mitm::serve_status(path, proxy_config.stats.clone())
                .with_context(|| format!("could not open status socket {}", path.display()))
        })
        .transpose()?;
    let proxy = Proxy::bind(proxy_config, upstream).await?;
    tokio::select! {
        _ = proxy.wait() => {}
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
    }
    Ok(())
}

fn load_aws(
    config: &config::Config,
    store: &Arc<dyn SecretStore>,
    upstream: &Upstream,
) -> anyhow::Result<Option<(Aws, Option<Arc<SsoProvider>>)>> {
    if !config.has_aws() {
        return Ok(None);
    }
    let (sessions, rules) = config.aws_rules()?;
    let mut signer = Signer::default();
    let mut roles = Vec::new();
    for rule in &rules {
        match rule.source() {
            credshim_aws::Source::Static {
                access_key_id,
                secret_access_key,
            } => {
                let credentials = AwsCredentials::new(
                    required_secret(store.as_ref(), access_key_id)?,
                    required_secret(store.as_ref(), secret_access_key)?,
                    None,
                )
                .with_context(|| format!("aws_key {:?} cannot be used", rule.name()))?;
                signer.insert(rule.name(), rule.dummy(), credentials);
            }
            credshim_aws::Source::Sso(role) => roles.push((
                rule.name().to_string(),
                role.clone(),
                rule.dummy().to_string(),
            )),
        }
    }
    let sso = (!roles.is_empty()).then(|| {
        Arc::new(SsoProvider::new(
            sessions,
            roles,
            store.clone(),
            Arc::new(UpstreamTransport::new(upstream.clone())),
            SsoOptions::default(),
        ))
    });
    let max_body = config
        .aws
        .max_body_bytes
        .unwrap_or(credshim_aws::DEFAULT_MAX_BODY);
    let mut aws = Aws::new(rules, signer).with_max_body(max_body);
    if let Some(sso) = &sso {
        aws = aws.with_sso(sso.clone());
    }
    Ok(Some((aws, sso)))
}

fn sso_session(config: &config::Config, name: &str) -> anyhow::Result<SsoSession> {
    let (sessions, _) = config.aws_rules()?;
    sessions
        .into_iter()
        .find(|session| session.name() == name)
        .with_context(|| format!("no [[aws_sso_session]] is named {name:?}"))
}

async fn aws_sso_login(config_path: Option<&Path>, name: &str) -> anyhow::Result<()> {
    if !std::io::stdin().is_terminal() {
        bail!("`credshim aws sso login` is for a person at a terminal; stdin is not a TTY");
    }
    let config = load_config(config_path)?.config;
    let session = sso_session(&config, name)?;
    let store = config.secrets()?.open()?;
    let transport = UpstreamTransport::new(Upstream::new()?);
    credshim_aws::sso::login(&session, &transport, store.as_ref(), |prompt| {
        let url = prompt
            .verification_uri_complete
            .as_deref()
            .unwrap_or(&prompt.verification_uri);
        let _ = writeln!(
            std::io::stderr(),
            "Open {url} in a browser and confirm the code {code}.\nWaiting up to {minutes} minutes for the approval...",
            code = prompt.user_code,
            minutes = prompt.expires_in.as_secs().div_ceil(60),
        );
    })
    .await?;
    writeln!(
        std::io::stderr(),
        "logged in to AWS SSO session {name}; a running credshim uses it from its next AWS request"
    )?;
    Ok(())
}

async fn aws_sso_logout(config_path: Option<&Path>, name: &str) -> anyhow::Result<()> {
    let config = load_config(config_path)?.config;
    let session = sso_session(&config, name)?;
    let store = config.secrets()?.open()?;
    let transport = UpstreamTransport::new(Upstream::new()?);
    let mut stderr = std::io::stderr();
    match credshim_aws::sso::logout(&session, &transport, store.as_ref()).await? {
        credshim_aws::sso::LogoutOutcome::NotLoggedIn => {
            writeln!(stderr, "AWS SSO session {name} was not logged in")?
        }
        credshim_aws::sso::LogoutOutcome::Revoked => writeln!(
            stderr,
            "logged out of AWS SSO session {name}; role credentials a running credshim already holds stay valid until they expire"
        )?,
        credshim_aws::sso::LogoutOutcome::RemovedWithoutRevoking(reason) => writeln!(
            stderr,
            "removed the AWS SSO login for {name}, but IAM Identity Center did not confirm the logout ({reason}); sign out in the browser to end the session"
        )?,
    }
    Ok(())
}

fn start_ssh_agent(
    config: &config::Config,
    store: &dyn SecretStore,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let entries = SshRule::from_specs(&config.ssh_keys)?
        .into_iter()
        .map(|rule| {
            let secret = required_secret(store, rule.secret_name())?;
            let signer = SigningKey::from_secret(&secret).with_context(|| {
                format!(
                    "ssh_key {:?}: secret {:?} cannot be used",
                    rule.name(),
                    rule.secret_name()
                )
            })?;
            Ok((rule, signer))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let path = config.ssh_socket()?;
    let mut agent = Agent::new(entries);
    if let Some(uids) = &config.ssh.client_uids {
        agent = agent.with_clients(uids.clone());
    }
    Arc::new(agent)
        .bind(&path)
        .with_context(|| format!("could not open ssh agent socket {}", path.display()))
}

fn ssh_keygen(config_path: Option<&Path>, name: &str) -> anyhow::Result<()> {
    credshim_secrets::check_name(name)?;
    let store = load_config(config_path)?.config.secrets()?.open()?;
    if store.get(name)?.is_some() {
        bail!(
            "secret {name:?} already exists; choose another name so the key in use is not replaced"
        );
    }
    let (private, public) = SigningKey::generate(&format!("credshim:{name}"))?;
    store.set(name, private)?;
    writeln!(std::io::stdout(), "{}", public.to_openssh()?)?;
    writeln!(
        std::io::stderr(),
        "stored {name}; register the public key above with the server, then point an [[ssh_key]] rule at secret {name:?}"
    )?;
    Ok(())
}

fn check_state_paths(config: &config::Config) -> anyhow::Result<()> {
    let ca_dir = config.ca_dir()?;
    harden::check_secret(&ca_dir.join(credshim_mitm::ca::KEY_FILE), "CA private key")?;
    check_trust_files(
        &ca_dir.join(credshim_mitm::ca::CERT_FILE),
        &ca_dir.join(credshim_mitm::ca::BUNDLE_FILE),
    )?;
    match &config.secrets()? {
        credshim_secrets::BackendConfig::AgeFile { path, identity } => {
            harden::check_secret(path, "secret store")?;
            let store = credshim_secrets::AgeFileStore::new(path.clone(), identity.clone());
            harden::check_secret(store.identity_path(), "secret store key")?;
        }
        credshim_secrets::BackendConfig::Command { command, .. } => {
            if let Some(program) = command.first().and_then(|p| harden::find_program(p)) {
                harden::check_private(&program, "secret store command")?;
            }
        }
        credshim_secrets::BackendConfig::Keychain { .. } => {}
    }
    if !config.oauth.is_empty() {
        harden::check_secret(&config.vault_path()?, "OAuth token vault")?;
    }
    if let Some(path) = &config.audit.path {
        harden::check_private(path, "audit log")?;
    }
    if !config.ssh_keys.is_empty()
        && let Some(dir) = config.ssh_socket()?.parent()
    {
        harden::check_private_dir(dir, "directory holding the ssh agent socket")?;
    }
    Ok(())
}

fn check_trust_files(cert: &Path, bundle: &Path) -> anyhow::Result<()> {
    harden::check_private(cert, "CA certificate")?;
    harden::check_private(bundle, "CA bundle")
}

async fn status(config_path: Option<&Path>) -> anyhow::Result<()> {
    let config = load_config(config_path)?.config;
    let socket = config
        .status
        .socket
        .context("no [status] socket is configured")?;
    let mut stream = tokio::net::UnixStream::connect(&socket)
        .await
        .with_context(|| format!("could not connect to {}", socket.display()))?;
    let mut body = String::new();
    tokio::io::AsyncReadExt::read_to_string(&mut stream, &mut body).await?;
    write!(std::io::stdout(), "{body}")?;
    Ok(())
}

fn load_secrets(store: &dyn SecretStore, rules: &RuleSet) -> anyhow::Result<Secrets> {
    let names: BTreeSet<&str> = rules
        .rules()
        .iter()
        .filter_map(|rule| rule.secret_name())
        .collect();
    let mut secrets = Secrets::new();
    for name in names {
        secrets.insert(name, required_secret(store, name)?);
    }
    Ok(secrets)
}

fn required_secret(store: &dyn SecretStore, name: &str) -> anyhow::Result<SecretString> {
    store
        .get(name)?
        .with_context(|| format!("secret {name:?} is not set; run `credshim secret set {name}`"))
}

fn load_oauth(config: &config::Config, store: &dyn SecretStore) -> anyhow::Result<OAuth> {
    let providers = config
        .oauth
        .iter()
        .map(|spec| {
            let client_secret = spec
                .client_secret_name()
                .map(|name| required_secret(store, name))
                .transpose()?;
            Ok(Provider::new(spec.clone(), client_secret)?)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let key = match store.get(VAULT_KEY_SECRET)? {
        Some(key) => key,
        None => {
            let key = Vault::generate_key();
            store.set(VAULT_KEY_SECRET, key.clone()).with_context(|| {
                format!("could not create the OAuth vault key; store an age identity as secret {VAULT_KEY_SECRET:?}")
            })?;
            tracing::info!(secret = VAULT_KEY_SECRET, "created the OAuth vault key");
            key
        }
    };
    let vault = Vault::open(config.vault_path()?, &key)?;
    Ok(OAuth::new(providers, vault)?.with_max_body(
        config
            .limits
            .max_token_body_bytes
            .unwrap_or(DEFAULT_MAX_BODY),
    ))
}

fn open_audit_log(path: &Path) -> anyhow::Result<File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("could not open audit log {}", path.display()))
}

fn secret_set(config_path: Option<&Path>, name: &str) -> anyhow::Result<()> {
    credshim_secrets::check_name(name)?;
    let backend = load_config(config_path)?.config.secrets()?;
    if !std::io::stdin().is_terminal() {
        bail!("`credshim secret set` reads the value from a terminal; stdin is not a TTY");
    }
    let store = backend.open()?;
    let value = non_empty_value(
        name,
        rpassword::prompt_password(format!("value for {name}: "))
            .context("could not read the value from the terminal")?,
    )?;
    store.set(name, value)?;
    writeln!(std::io::stderr(), "stored {name}")?;
    Ok(())
}

fn non_empty_value(name: &str, value: String) -> anyhow::Result<SecretString> {
    if value.is_empty() {
        bail!("the value for {name} is empty; nothing was stored");
    }
    Ok(SecretString::from(value))
}

fn secret_list(config_path: Option<&Path>) -> anyhow::Result<()> {
    let store = load_config(config_path)?.config.secrets()?.open()?;
    let mut stdout = std::io::stdout();
    for info in store.list()? {
        let updated = time::OffsetDateTime::from(info.updated_at)
            .format(&time::format_description::well_known::Rfc3339)?;
        writeln!(stdout, "{}\t{updated}", info.name)?;
    }
    Ok(())
}

fn ca_init(dir: &Path) -> anyhow::Result<()> {
    CertificateAuthority::init(dir)?;
    let bundle = dir.join(credshim_mitm::ca::BUNDLE_FILE);
    std::fs::write(&bundle, credshim_mitm::ca::trust_bundle(dir)?)
        .with_context(|| format!("could not write {}", bundle.display()))?;
    let cert = dir.join(credshim_mitm::ca::CERT_FILE);
    writeln!(std::io::stdout(), "{}", cert.display())?;
    Ok(())
}

fn ca_bundle(dir: &Path, out: Option<&Path>) -> anyhow::Result<()> {
    let bundle = credshim_mitm::ca::trust_bundle(dir)?;
    match out {
        Some(path) => std::fs::write(path, bundle)
            .with_context(|| format!("could not write {}", path.display()))?,
        None => std::io::stdout().write_all(bundle.as_bytes())?,
    }
    Ok(())
}

fn ca_dir_or_default(dir: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    match dir {
        Some(dir) => Ok(dir),
        None => config::default_ca_dir(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_set_rejects_an_empty_value() {
        assert!(non_empty_value("openai", credshim_testkit::fake_secret("set")).is_ok());
        let err = non_empty_value("openai", String::new()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "the value for openai is empty; nothing was stored"
        );
    }
}
