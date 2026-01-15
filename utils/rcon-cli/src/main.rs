mod cli;
mod client;
mod framing;
mod messages;
mod server;

use std::env;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::cli::{Cli, Commands};
use crate::client::run_client;
use crate::server::run_server;

#[tokio::main]
async fn main() {
    init_tracing();
    apply_legacy_env_aliases();

    let cli = Cli::parse();
    if let Err(error) = dispatch(cli).await {
        eprintln!("Error: {error:?}");
        std::process::exit(1);
    }
}

async fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Server(opts) => run_server(opts).await,
        Commands::Client(opts) => run_client(opts).await,
    }
}

fn apply_legacy_env_aliases() {
    const MAPPINGS: &[(&str, &str)] = &[
        ("RCON_BIND", "HTY_RCON_BIND"),
        ("RCON_PASSWORD", "HTY_RCON_PASSWORD"),
        ("RCON_CHILD_COMMAND", "HTY_RCON_CHILD_COMMAND"),
        ("RCON_CHILD_ARG", "HTY_RCON_CHILD_ARG"),
        ("RCON_CHILD_DIR", "HTY_RCON_CHILD_DIR"),
        ("RCON_RESPONSE_TIMEOUT_MS", "HTY_RCON_RESPONSE_TIMEOUT_MS"),
        ("RCON_LOG_COMMANDS", "HTY_RCON_LOG_COMMANDS"),
        ("RCON_RESPAWN", "HTY_RCON_RESPAWN"),
        ("RCON_RESPAWN_BACKOFF_MS", "HTY_RCON_RESPAWN_BACKOFF_MS"),
        ("RCON_HOST", "HTY_RCON_HOST"),
        ("RCON_PORT", "HTY_RCON_PORT"),
    ];

    for (new_key, legacy_key) in MAPPINGS {
        if env::var(new_key).is_err() {
            if let Ok(value) = env::var(legacy_key) {
                unsafe {
                    env::set_var(new_key, value);
                }
            }
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}
