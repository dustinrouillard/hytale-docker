use serde::{Deserialize, Serialize};

pub const SHUTDOWN_INFO_MESSAGE: &str = "Server shutting down";

/// Frames emitted by the client when talking to the bridge.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Auth {
        password: String,
    },
    Command {
        id: u64,
        command: String,
        expect_response: bool,
    },
    Ping {
        id: u64,
    },
}

/// Frames emitted by the server back to the client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    AuthOk,
    AuthError { message: String },
    CommandAccepted { id: u64 },
    CommandRejected { id: u64, message: String },
    CommandOutput { id: u64, output: String, more: bool },
    Pong { id: u64 },
    Info { message: String },
}
