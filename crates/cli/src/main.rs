use std::io::IsTerminal;
use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use credshim_mitm::{Proxy, ProxyConfig, Upstream};
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
        Command::Run { listen } => {
            let proxy = Proxy::bind(ProxyConfig::new(listen), Upstream::new()?).await?;
            tokio::select! {
                _ = proxy.wait() => {}
                _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
            }
        }
    }
    Ok(())
}
