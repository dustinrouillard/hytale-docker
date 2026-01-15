use std::env;
use std::io::Write;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::io::{self as tokio_io, AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::{self, Instant as TokioInstant};
use tracing::debug;

use crate::cli::ClientOpts;
use crate::framing::{read_json_message, write_json_message};
use crate::messages::{ClientMessage, ServerMessage};

/// Connect to the RCON bridge and execute commands based on the supplied options.
pub async fn run_client(mut opts: ClientOpts) -> Result<()> {
    let address = format!("{}:{}", opts.host, opts.port);
    let expect_response = !opts.no_response;
    let timeout = Duration::from_millis(opts.timeout_ms);

    let password = opts.password.take().unwrap_or_else(|| {
        env::var("RCON_PASSWORD")
            .or_else(|_| env::var("HTY_RCON_PASSWORD"))
            .unwrap_or_else(|_| "hytale".to_string())
    });

    let stream = TcpStream::connect(&address)
        .await
        .with_context(|| format!("failed to connect to {address}"))?;
    if let Err(err) = stream.set_nodelay(true) {
        debug!(error = %err, "unable to enable TCP_NODELAY on client socket");
    }
    let peer_addr = stream.peer_addr().ok();
    debug!(?peer_addr, "connected to RCON bridge");

    let (mut reader, mut writer) = stream.into_split();
    write_json_message(&mut writer, &ClientMessage::Auth { password }).await?;

    let auth_frame = read_json_message::<_, ServerMessage>(&mut reader)
        .await?
        .ok_or_else(|| anyhow!("connection closed during authentication"))?;
    match auth_frame {
        ServerMessage::AuthOk => {
            debug!("authentication succeeded");
        }
        ServerMessage::AuthError { message } => {
            bail!("authentication rejected: {message}");
        }
        other => bail!("unexpected frame during authentication: {:?}", other),
    }

    if opts.ping {
        send_ping(&mut reader, &mut writer, timeout).await?;
        if opts.command.is_none() && !opts.interactive {
            return Ok(());
        }
    }

    let mut next_id = 1_u64;
    let command_to_send = opts.command.take();
    let interactive_mode = opts.interactive || (command_to_send.is_none() && !opts.ping);

    if let Some(command) = command_to_send {
        let outputs = execute_command(
            &mut writer,
            &mut reader,
            next_id,
            &command,
            expect_response,
            timeout,
        )
        .await?;
        if outputs.is_empty() {
            println!("OK");
        } else {
            for line in outputs {
                println!("{line}");
            }
        }
        next_id = next_id.saturating_add(1);
    }

    if interactive_mode {
        interactive_loop(&mut writer, &mut reader, expect_response, timeout, next_id).await?;
    }

    Ok(())
}

async fn interactive_loop(
    writer: &mut OwnedWriteHalf,
    reader: &mut OwnedReadHalf,
    expect_response: bool,
    timeout: Duration,
    mut next_id: u64,
) -> Result<()> {
    let mut stdin = BufReader::new(tokio_io::stdin());
    let mut buffer = String::new();

    println!("Connected. Type commands to send them to the server, or 'exit' to quit.");
    loop {
        print!("> ");
        let _ = std::io::stdout().flush();

        buffer.clear();
        let bytes = stdin.read_line(&mut buffer).await?;
        if bytes == 0 {
            println!("EOF received, closing connection");
            break;
        }

        let command = buffer.trim();
        if command.is_empty() {
            continue;
        }
        if matches_ignore_ascii_case(command, "exit") || matches_ignore_ascii_case(command, "quit")
        {
            println!("Goodbye!");
            break;
        }

        match execute_command(writer, reader, next_id, command, expect_response, timeout).await {
            Ok(outputs) => {
                if outputs.is_empty() {
                    println!("OK");
                } else {
                    for line in outputs {
                        println!("{line}");
                    }
                }
            }
            Err(err) => {
                eprintln!("Command failed: {err}");
            }
        }

        next_id = next_id.saturating_add(1);
    }

    Ok(())
}

async fn execute_command(
    writer: &mut OwnedWriteHalf,
    reader: &mut OwnedReadHalf,
    request_id: u64,
    command: &str,
    expect_response: bool,
    timeout: Duration,
) -> Result<Vec<String>> {
    let message = ClientMessage::Command {
        id: request_id,
        command: command.to_string(),
        expect_response,
    };
    write_json_message(writer, &message).await?;

    let mut outputs = Vec::new();
    let mut acknowledged = false;
    let mut deadline = TokioInstant::now() + timeout;

    loop {
        let now = TokioInstant::now();
        if now >= deadline {
            if acknowledged {
                bail!("timed out waiting for command output");
            } else {
                bail!("timed out waiting for command acknowledgement");
            }
        }

        let remaining = deadline.saturating_duration_since(now);
        let frame_opt =
            match time::timeout(remaining, read_json_message::<_, ServerMessage>(reader)).await {
                Ok(result) => result?,
                Err(_) => {
                    if acknowledged {
                        bail!("timed out waiting for command output");
                    } else {
                        bail!("timed out waiting for command acknowledgement");
                    }
                }
            };

        let frame = frame_opt.ok_or_else(|| anyhow!("connection closed by server"))?;
        match frame {
            ServerMessage::CommandAccepted { id } if id == request_id => {
                acknowledged = true;
                if !expect_response {
                    return Ok(outputs);
                }
                deadline = TokioInstant::now() + timeout;
            }
            ServerMessage::CommandOutput { id, output, more } if id == request_id => {
                outputs.push(output);
                if more {
                    deadline = TokioInstant::now() + timeout;
                } else {
                    return Ok(outputs);
                }
            }
            ServerMessage::CommandRejected { id, message } if id == request_id => {
                bail!(message);
            }
            ServerMessage::AuthError { message } => {
                bail!(message);
            }
            ServerMessage::Info { message } => {
                eprintln!("info: {message}");
            }
            ServerMessage::Pong { .. } => {
                debug!("received pong while awaiting command response");
            }
            ServerMessage::AuthOk => {
                debug!("server acknowledged authentication again");
            }
            _ => {
                debug!("ignoring unrelated frame while awaiting response");
            }
        }
    }
}

async fn send_ping(
    reader: &mut OwnedReadHalf,
    writer: &mut OwnedWriteHalf,
    timeout: Duration,
) -> Result<()> {
    let ping_id = 0_u64;
    let start = std::time::Instant::now();
    write_json_message(writer, &ClientMessage::Ping { id: ping_id }).await?;

    let mut deadline = TokioInstant::now() + timeout;
    loop {
        let now = TokioInstant::now();
        if now >= deadline {
            bail!("timed out waiting for pong");
        }
        let remaining = deadline.saturating_duration_since(now);
        let frame_opt =
            match time::timeout(remaining, read_json_message::<_, ServerMessage>(reader)).await {
                Ok(result) => result?,
                Err(_) => bail!("timed out waiting for pong"),
            };

        let frame = frame_opt.ok_or_else(|| anyhow!("connection closed while waiting for pong"))?;
        match frame {
            ServerMessage::Pong { id } if id == ping_id => {
                let elapsed = start.elapsed();
                println!("pong in {} ms", elapsed.as_millis());
                return Ok(());
            }
            ServerMessage::Info { message } => {
                eprintln!("info: {message}");
            }
            _ => {
                debug!("ignoring frame while awaiting pong");
            }
        }
        deadline = TokioInstant::now() + timeout;
    }
}

fn matches_ignore_ascii_case(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}
