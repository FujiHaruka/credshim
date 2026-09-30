use std::io::{IsTerminal, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use credshim_mitm::{CertificateAuthority, Intercept, Proxy, ProxyConfig, Upstream};
use tracing_subscriber::EnvFilter;

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
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: SocketAddr,
        #[arg(long, value_name = "DIR")]
        ca_dir: Option<PathBuf>,
        #[arg(long = "intercept", value_name = "HOST")]
        intercept: Vec<String>,
    },
    Ca {
        #[command(subcommand)]
        command: CaCommand,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("CREDSHIM_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("a rustls crypto provider is already installed"))?;
    match Cli::parse().command {
        Command::Run {
            listen,
            ca_dir,
            intercept,
        } => run(listen, ca_dir, intercept).await,
        Command::Ca {
            command: CaCommand::Init { dir },
        } => ca_init(&ca_dir_or_default(dir)?),
        Command::Ca {
            command: CaCommand::Bundle { dir, out },
        } => ca_bundle(&ca_dir_or_default(dir)?, out.as_deref()),
    }
}

async fn run(
    listen: SocketAddr,
    ca_dir: Option<PathBuf>,
    intercept: Vec<String>,
) -> anyhow::Result<()> {
    let mut config = ProxyConfig::new(listen);
    if !intercept.is_empty() {
        let ca_dir = ca_dir_or_default(ca_dir)?;
        let ca = CertificateAuthority::load(&ca_dir)
            .context("--intercept needs a CA; create one with `credshim ca init`")?;
        config.intercept = Some(Intercept::new(Arc::new(ca), &intercept));
    }
    let proxy = Proxy::bind(config, Upstream::new()?).await?;
    tokio::select! {
        _ = proxy.wait() => {}
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
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
    if let Some(dir) = dir {
        return Ok(dir);
    }
    let config_home = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".config"),
    };
    Ok(config_home.join("credshim").join("ca"))
}
