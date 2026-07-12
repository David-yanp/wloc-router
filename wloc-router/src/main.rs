mod certs;
mod config;
mod server;
mod wloc;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "wloc-router")]
#[command(about = "Small router-side Apple WLOC MITM service")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(short, long, default_value = "/etc/wloc-router/config.toml")]
        config: PathBuf,
    },
    GenCerts {
        #[arg(short, long, default_value = "/etc/wloc-router")]
        out_dir: PathBuf,
    },
}

#[tokio::main(flavor = "multi_thread", worker_threads = 1)]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Serve { config } => server::serve(config).await,
        Command::GenCerts { out_dir } => certs::generate(&out_dir).await,
    }
}
