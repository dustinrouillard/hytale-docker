use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "rcon-cli",
    version,
    about = "Remote console bridge and client for the Hytale dedicated server",
    propagate_version = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Run the server-side TCP bridge that interacts with the child process.
    Server(ServerOpts),
    /// Connect to the RCON bridge and issue commands.
    Client(ClientOpts),
}

/// Options specific to the `server` subcommand.
#[derive(Parser, Debug, Clone)]
pub struct ServerOpts {
    /// TCP listen address for the RCON bridge.
    #[arg(long, env = "RCON_BIND", default_value = "0.0.0.0:25900")]
    pub bind: SocketAddr,

    /// Password required for clients to authenticate.
    #[arg(
        long,
        env = "RCON_PASSWORD",
        default_value = "hytale",
        hide_env_values = true
    )]
    pub password: String,

    /// Path to the child executable (for example, java).
    #[arg(
        long = "child-command",
        env = "RCON_CHILD_COMMAND",
        value_name = "PATH"
    )]
    pub child_command: PathBuf,

    /// Arguments forwarded to the child executable.
    #[arg(
        long = "child-arg",
        env = "RCON_CHILD_ARG",
        value_name = "ARG",
        action = ArgAction::Append,
        allow_hyphen_values = true
    )]
    pub child_args: Vec<String>,

    /// Working directory for the child process.
    #[arg(long = "child-dir", env = "RCON_CHILD_DIR", value_name = "PATH")]
    pub child_dir: Option<PathBuf>,

    /// Timeout in milliseconds when waiting for a response line.
    #[arg(
        long,
        env = "RCON_RESPONSE_TIMEOUT_MS",
        default_value_t = 2000_u64,
        value_name = "MILLISECONDS"
    )]
    pub response_timeout_ms: u64,

    /// Emit forwarded commands at info level.
    #[arg(long, env = "RCON_LOG_COMMANDS")]
    pub log_commands: bool,

    /// Attempt to restart the child process if it exits unexpectedly.
    #[arg(long, env = "RCON_RESPAWN")]
    pub respawn: bool,

    /// Backoff between respawn attempts in milliseconds.
    #[arg(
        long,
        env = "RCON_RESPAWN_BACKOFF_MS",
        default_value_t = 5000_u64,
        value_name = "MILLISECONDS"
    )]
    pub respawn_backoff_ms: u64,
}

/// Options specific to the `client` subcommand.
#[derive(Parser, Debug, Clone)]
pub struct ClientOpts {
    /// Host running the RCON bridge.
    #[arg(
        long = "host",
        short = 'H',
        env = "RCON_HOST",
        default_value = "127.0.0.1"
    )]
    pub host: String,

    /// TCP port exposed by the RCON bridge.
    #[arg(long = "port", short = 'P', env = "RCON_PORT", default_value_t = 25900)]
    pub port: u16,

    /// Authentication password.
    #[arg(
        long = "password",
        short = 'p',
        env = "RCON_PASSWORD",
        hide_env_values = true
    )]
    pub password: Option<String>,

    /// Single command to execute.
    #[arg(long = "command", short = 'c', value_name = "COMMAND")]
    pub command: Option<String>,

    /// Force interactive shell even when a command is supplied.
    #[arg(long = "interactive", short = 'i')]
    pub interactive: bool,

    /// Do not wait for the server to produce a response.
    #[arg(long = "no-response")]
    pub no_response: bool,

    /// Send a latency probe before executing other commands.
    #[arg(long = "ping")]
    pub ping: bool,

    /// Timeout in milliseconds for acknowledgements and responses.
    #[arg(
        long = "timeout-ms",
        default_value_t = 2000_u64,
        value_name = "MILLISECONDS"
    )]
    pub timeout_ms: u64,
}
