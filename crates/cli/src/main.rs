mod config;
mod preset;

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{IsTerminal, Write};
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use credshim_core::{Injector, RuleSet, Secrets};
use credshim_mitm::{AUDIT_TARGET, CertificateAuthority, Intercept, Proxy, ProxyConfig, Upstream};
use credshim_secrets::SecretStore;
use secrecy::SecretString;
use tracing_subscriber::filter::{EnvFilter, Targets};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, fmt};

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
    Preset {
        #[arg(value_parser = clap::builder::PossibleValuesParser::new(
            preset::PRESETS.iter().map(|preset| preset.name)
        ))]
        name: String,
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
        Command::Preset { name } => {
            let preset = preset::find(&name).context("unknown preset")?;
            write!(std::io::stdout(), "{}", preset.render())?;
            Ok(())
        }
    }
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
    let loaded = config::load(config_path)?;
    let config = loaded.config;
    let audit = config
        .audit
        .path
        .as_deref()
        .map(open_audit_log)
        .transpose()?;
    init_logging(audit)?;
    match &loaded.source {
        Some(path) => {
            tracing::info!(config = %path.display(), rules = config.rules.len(), "loaded config")
        }
        None => tracing::info!("no config file; running without rules"),
    }

    let rules = RuleSet::new(config.rules.clone())?;
    let mut proxy_config = ProxyConfig::new(listen.unwrap_or_else(|| config.listen()));
    if !rules.is_empty() {
        let store = config.secrets()?.open()?;
        let secrets = load_secrets(store.as_ref(), &rules)?;
        let injector = Arc::new(Injector::new(rules, secrets)?);
        let ca_dir = config.ca_dir()?;
        let ca = CertificateAuthority::load(&ca_dir)
            .context("rules need a CA; create one with `credshim ca init`")?;
        proxy_config.intercept = Some(Intercept::new(Arc::new(ca), injector.rules().hosts()));
        proxy_config.injector = injector;
    }
    let proxy = Proxy::bind(proxy_config, Upstream::new()?).await?;
    tokio::select! {
        _ = proxy.wait() => {}
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
    }
    Ok(())
}

fn load_secrets(store: &dyn SecretStore, rules: &RuleSet) -> anyhow::Result<Secrets> {
    let names: BTreeSet<&str> = rules.rules().iter().map(|rule| rule.secret()).collect();
    let mut secrets = Secrets::new();
    for name in names {
        let value = store.get(name)?.with_context(|| {
            format!("secret {name:?} is not set; run `credshim secret set {name}`")
        })?;
        secrets.insert(name, value);
    }
    Ok(secrets)
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
    if !std::io::stdin().is_terminal() {
        bail!("`credshim secret set` reads the value from a terminal; stdin is not a TTY");
    }
    let store = config::load(config_path)?.config.secrets()?.open()?;
    let value = SecretString::from(
        rpassword::prompt_password(format!("value for {name}: "))
            .context("could not read the value from the terminal")?,
    );
    store.set(name, value)?;
    writeln!(std::io::stderr(), "stored {name}")?;
    Ok(())
}

fn secret_list(config_path: Option<&Path>) -> anyhow::Result<()> {
    let store = config::load(config_path)?.config.secrets()?.open()?;
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
