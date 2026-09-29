use clap::Parser;

#[derive(Parser)]
#[command(
    name = "credshim",
    version,
    about = "Credential-injecting proxy for local development"
)]
struct Cli {}

fn main() {
    Cli::parse();
}
