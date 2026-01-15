use std::env;
use std::io::{ErrorKind, IsTerminal};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
#[cfg(unix)]
use std::thread::sleep;

use anyhow::{Context, Result, anyhow};
use tokio::io::{self as tokio_io, AsyncBufReadExt, AsyncWriteExt, BufReader};

use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::select;
use tokio::signal;
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal as unix_signal};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{Mutex, broadcast, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{self, MissedTickBehavior};
use tracing::{debug, error, info, warn};

use crate::cli::ServerOpts;
use crate::framing::{read_json_message, write_json_message};
use crate::messages::{ClientMessage, SHUTDOWN_INFO_MESSAGE, ServerMessage};

pub async fn run_server(opts: ServerOpts) -> Result<()> {
    let (output_tx, _output_rx) = broadcast::channel(1024);
    let (shutdown_tx, _shutdown_rx) = watch::channel(false);
    let shared = Arc::new(ServerShared::new(
        opts.password.clone(),
        output_tx.clone(),
        Duration::from_millis(opts.response_timeout_ms),
        opts.log_commands,
        shutdown_tx,
    ));

    let mut child_runtime = spawn_child_runtime(&opts, &shared).await?;
    let listener = TcpListener::bind(opts.bind)
        .await
        .with_context(|| format!("failed to bind RCON listener on {}", opts.bind))?;
    info!(bind = %opts.bind, "RCON bridge listening");

    let console_task = if std::io::stdin().is_terminal() {
        Some(tokio::spawn(console_forwarder(Arc::clone(&shared))))
    } else {
        None
    };

    let ctrl_c = signal::ctrl_c();
    tokio::pin!(ctrl_c);
    #[cfg(unix)]
    let mut sigterm =
        unix_signal(SignalKind::terminate()).context("failed to register SIGTERM handler")?;

    let mut healthcheck = time::interval(Duration::from_secs(1));
    healthcheck.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut shutdown_reason: Option<ShutdownSignal> = None;
    let mut last_child_status: Option<ExitStatus> = None;
    let mut client_tasks = JoinSet::new();

    #[cfg(unix)]
    loop {
        select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, addr)) => {
                        let shared_clone = Arc::clone(&shared);
                        client_tasks.spawn(async move {
                            if let Err(err) = handle_client(stream, shared_clone).await {
                                warn!(peer = %addr, error = %err, "client disconnected with error");
                            } else {
                                debug!(peer = %addr, "client disconnected");
                            }
                        });
                    }
                    Err(err) => {
                        warn!(error = %err, "failed to accept incoming connection");
                    }
                }

                match monitor_child(&mut child_runtime, &shared, &opts).await? {
                    ChildState::Running => {}
                    ChildState::Exited(status) => {
                        last_child_status = Some(status);
                        shutdown_reason.get_or_insert(ShutdownSignal::Terminate);
                        break;
                    }
                    ChildState::Errored => {
                        shutdown_reason.get_or_insert(ShutdownSignal::Terminate);
                        break;
                    }
                }
            },
            result = &mut ctrl_c => {
                match result {
                    Ok(()) => {
                        info!("shutdown signal received (SIGINT)");
                        shutdown_reason = Some(ShutdownSignal::Interrupt);
                    }
                    Err(err) => {
                        warn!(error = %err, "error while waiting for Ctrl+C signal");
                    }
                }
                break;
            },
            maybe = sigterm.recv() => {
                match maybe {
                    Some(_) => {
                        info!("shutdown signal received (SIGTERM)");
                        shutdown_reason = Some(ShutdownSignal::Terminate);
                        break;
                    }
                    None => {
                        warn!("SIGTERM signal listener closed unexpectedly");
                    }
                }
            },
            _ = healthcheck.tick() => {
                match monitor_child(&mut child_runtime, &shared, &opts).await? {
                    ChildState::Running => {}
                    ChildState::Exited(status) => {
                        last_child_status = Some(status);
                        shutdown_reason.get_or_insert(ShutdownSignal::Terminate);
                        break;
                    }
                    ChildState::Errored => {
                        shutdown_reason.get_or_insert(ShutdownSignal::Terminate);
                        break;
                    }
                }
            },
        }
    }

    #[cfg(not(unix))]
    loop {
        select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, addr)) => {
                        let shared_clone = Arc::clone(&shared);
                        client_tasks.spawn(async move {
                            if let Err(err) = handle_client(stream, shared_clone).await {
                                warn!(peer = %addr, error = %err, "client disconnected with error");
                            } else {
                                debug!(peer = %addr, "client disconnected");
                            }
                        });
                    }
                    Err(err) => {
                        warn!(error = %err, "failed to accept incoming connection");
                    }
                }

                match monitor_child(&mut child_runtime, &shared, &opts).await? {
                    ChildState::Running => {}
                    ChildState::Exited(status) => {
                        last_child_status = Some(status);
                        shutdown_reason.get_or_insert(ShutdownSignal::Terminate);
                        break;
                    }
                    ChildState::Errored => {
                        shutdown_reason.get_or_insert(ShutdownSignal::Terminate);
                        break;
                    }
                }
            },
            result = &mut ctrl_c => {
                match result {
                    Ok(()) => {
                        info!("shutdown signal received (SIGINT)");
                        shutdown_reason = Some(ShutdownSignal::Interrupt);
                    }
                    Err(err) => {
                        warn!(error = %err, "error while waiting for Ctrl+C signal");
                    }
                }
                break;
            },
            _ = healthcheck.tick() => {
                match monitor_child(&mut child_runtime, &shared, &opts).await? {
                    ChildState::Running => {}
                    ChildState::Exited(status) => {
                        last_child_status = Some(status);
                        shutdown_reason.get_or_insert(ShutdownSignal::Terminate);
                        break;
                    }
                    ChildState::Errored => {
                        shutdown_reason.get_or_insert(ShutdownSignal::Terminate);
                        break;
                    }
                }
            },
        }
    }

    shared.initiate_shutdown(SHUTDOWN_INFO_MESSAGE);

    if let Some(handle) = console_task {
        handle.abort();
        if let Err(err) = handle.await {
            if !err.is_cancelled() {
                warn!(error = %err, "console forwarder task terminated with error");
            }
        }
    }

    while let Some(join_result) = client_tasks.join_next().await {
        if let Err(err) = join_result {
            if !err.is_cancelled() {
                warn!(error = %err, "client task terminated with join error");
            }
        }
    }

    shared.clear_writer().await;

    match finalize_child_shutdown(&mut child_runtime, shutdown_reason).await {
        Ok(Some(status)) => {
            last_child_status = Some(status);
        }
        Ok(None) => {}
        Err(err) => {
            warn!(error = %err, "error while finalizing child shutdown");
        }
    }

    if let Some(handle) = child_runtime.stdout_task.take() {
        if let Err(err) = handle.await {
            if !err.is_cancelled() {
                warn!(error = %err, "stdout forwarder task terminated with error");
            }
        }
    }

    terminate_refresh_maintenance();

    let exit_code = last_child_status
        .as_ref()
        .map(exit_code_from_status)
        .unwrap_or_else(|| fallback_exit_code(shutdown_reason));

    std::process::exit(exit_code);
}

struct CommandSink {
    inner: CommandSinkInner,
}

enum CommandSinkInner {
    Child(ChildStdin),
}

impl CommandSink {
    fn child(stdin: ChildStdin) -> Self {
        Self {
            inner: CommandSinkInner::Child(stdin),
        }
    }

    async fn execute(&mut self, command: &str) -> Result<()> {
        match &mut self.inner {
            CommandSinkInner::Child(stdin) => {
                stdin.write_all(command.as_bytes()).await?;
                if !command.ends_with('\n') {
                    stdin.write_all(b"\n").await?;
                }
                stdin.flush().await?;
                Ok(())
            }
        }
    }
}

struct ServerShared {
    password: String,
    writer: Mutex<Option<CommandSink>>,
    output: broadcast::Sender<String>,
    response_timeout: Duration,
    log_commands: bool,
    shutdown_flag: AtomicBool,
    shutdown_tx: watch::Sender<bool>,
}

impl ServerShared {
    fn new(
        password: String,
        output: broadcast::Sender<String>,
        response_timeout: Duration,
        log_commands: bool,
        shutdown_tx: watch::Sender<bool>,
    ) -> Self {
        Self {
            password,
            writer: Mutex::new(None),
            output,
            response_timeout,
            log_commands,
            shutdown_flag: AtomicBool::new(false),
            shutdown_tx,
        }
    }

    async fn forward_command(&self, command: &str) -> Result<()> {
        let mut guard = self.writer.lock().await;
        let sink = guard
            .as_mut()
            .ok_or_else(|| anyhow!("command sink unavailable"))?;
        sink.execute(command).await
    }

    async fn replace_writer(&self, sink: CommandSink) {
        let mut guard = self.writer.lock().await;
        *guard = Some(sink);
    }

    async fn clear_writer(&self) {
        let mut guard = self.writer.lock().await;
        *guard = None;
    }

    fn subscribe_output(&self) -> broadcast::Receiver<String> {
        self.output.subscribe()
    }

    fn response_timeout(&self) -> Duration {
        self.response_timeout
    }

    fn subscribe_shutdown(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }

    fn initiate_shutdown(&self, message: &str) {
        if self
            .shutdown_flag
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let _ = self.output.send(message.to_string());
            let _ = self.shutdown_tx.send(true);
        }
    }
}

struct ChildRuntime {
    child: Child,
    stdout_task: Option<JoinHandle<()>>,
}

#[derive(Debug)]
enum ChildState {
    Running,
    Exited(ExitStatus),
    Errored,
}

#[derive(Debug, Clone, Copy)]
enum ShutdownSignal {
    Interrupt,
    Terminate,
}

#[cfg(unix)]
fn send_signal_to_child(child: &Child, signal: ShutdownSignal) -> Result<bool> {
    let pid = match child.id() {
        Some(id) => id as libc::pid_t,
        None => return Ok(false),
    };

    let sig: libc::c_int = match signal {
        ShutdownSignal::Interrupt => libc::SIGINT,
        ShutdownSignal::Terminate => libc::SIGTERM,
    };

    let rc = unsafe { libc::kill(pid, sig) };
    if rc == 0 {
        Ok(true)
    } else {
        let os_err = std::io::Error::last_os_error();
        if os_err.raw_os_error() == Some(libc::ESRCH) {
            Ok(false)
        } else {
            Err(anyhow!(
                "failed to send signal {} to child PID {}: {}",
                sig,
                pid,
                os_err
            ))
        }
    }
}

async fn finalize_child_shutdown(
    child_runtime: &mut ChildRuntime,
    reason: Option<ShutdownSignal>,
) -> Result<Option<ExitStatus>> {
    match child_runtime.child.try_wait() {
        Ok(Some(status)) => {
            debug!(
                exit_status = %status,
                "child process already exited before shutdown"
            );
            return Ok(Some(status));
        }
        Ok(None) => {}
        Err(err) => {
            warn!(
                error = %err,
                "failed to poll child process status prior to shutdown"
            );
        }
    }

    if let Some(reason) = reason {
        #[cfg(unix)]
        match send_signal_to_child(&child_runtime.child, reason) {
            Ok(true) => info!(?reason, "forwarded shutdown signal to child process"),
            Ok(false) => {
                debug!(?reason, "child process exited before signal delivery");
            }
            Err(err) => {
                warn!(
                    ?reason,
                    error = %err,
                    "failed to forward shutdown signal to child process"
                );
            }
        };

        #[cfg(not(unix))]
        info!(
            ?reason,
            "shutdown signal forwarding is unsupported on this platform; child will not receive the signal directly"
        );
    }

    let wait_result = time::timeout(Duration::from_secs(15), child_runtime.child.wait()).await;
    match wait_result {
        Ok(Ok(status)) => {
            if reason.is_some() {
                info!(exit_status = %status, "child process exited during shutdown");
            } else {
                debug!(
                    exit_status = %status,
                    "child process exited before shutdown completion"
                );
            }
            Ok(Some(status))
        }
        Ok(Err(err)) => {
            warn!(error = %err, "failed to wait for child process exit");
            Ok(None)
        }
        Err(_) => {
            warn!("child process did not exit within timeout; forcing termination");
            if let Err(err) = child_runtime.child.kill().await {
                if err.kind() != ErrorKind::InvalidInput {
                    warn!(error = %err, "failed to kill child process after timeout");
                }
            }
            match child_runtime.child.wait().await {
                Ok(status) => {
                    info!(
                        exit_status = %status,
                        "child process exited after forced termination"
                    );
                    Ok(Some(status))
                }
                Err(err) => {
                    warn!(
                        error = %err,
                        "failed to reap child process after forced termination"
                    );
                    Ok(None)
                }
            }
        }
    }
}

#[cfg(unix)]
fn wait_for_pid_exit(pid: libc::pid_t, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let mut status = 0;
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if rc == pid {
            return true;
        } else if rc == 0 {
            if Instant::now() >= deadline {
                return false;
            }
            sleep(Duration::from_millis(50));
        } else if rc == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ECHILD) {
                return true;
            } else {
                debug!(
                    pid,
                    error = %err,
                    "waitpid failed while waiting for OAuth refresh maintenance process"
                );
                return false;
            }
        }
    }
}

#[cfg(unix)]
fn terminate_refresh_maintenance() {
    if let Ok(pid_str) = env::var("AUTH_REFRESH_MAINTENANCE_PID") {
        let pid_str_trimmed = pid_str.trim();
        if pid_str_trimmed.is_empty() {
            return;
        }
        match pid_str_trimmed.parse::<libc::pid_t>() {
            Ok(pid) => {
                let kill_result = unsafe { libc::kill(pid, libc::SIGTERM) };
                if kill_result == 0 {
                    debug!(pid, "sent SIGTERM to OAuth refresh maintenance process");
                    if !wait_for_pid_exit(pid, Duration::from_secs(5)) {
                        warn!(
                            pid,
                            "OAuth refresh maintenance process did not exit after SIGTERM; escalating to SIGKILL"
                        );
                        let force_result = unsafe { libc::kill(pid, libc::SIGKILL) };
                        if force_result == 0 {
                            if wait_for_pid_exit(pid, Duration::from_secs(1)) {
                                debug!(
                                    pid,
                                    "OAuth refresh maintenance process terminated after SIGKILL"
                                );
                            } else {
                                warn!(
                                    pid,
                                    "OAuth refresh maintenance process still running after SIGKILL"
                                );
                            }
                        } else {
                            let os_err = std::io::Error::last_os_error();
                            if os_err.raw_os_error() != Some(libc::ESRCH) {
                                warn!(
                                    pid,
                                    error = %os_err,
                                    "failed to send SIGKILL to OAuth refresh maintenance process"
                                );
                            }
                        }
                    }
                } else {
                    let os_err = std::io::Error::last_os_error();
                    if os_err.raw_os_error() == Some(libc::ESRCH) {
                        debug!(pid, "OAuth refresh maintenance process already exited");
                    } else {
                        warn!(
                            pid,
                            error = %os_err,
                            "failed to terminate OAuth refresh maintenance process with SIGTERM"
                        );
                    }
                }
            }
            Err(err) => {
                debug!(
                    pid_str = pid_str_trimmed,
                    error = %err,
                    "unable to parse AUTH_REFRESH_MAINTENANCE_PID; skipping maintenance termination"
                );
            }
        }
    }
}

#[cfg(not(unix))]
fn terminate_refresh_maintenance() {}

async fn spawn_child_runtime(
    opts: &ServerOpts,
    shared: &Arc<ServerShared>,
) -> Result<ChildRuntime> {
    let mut command = Command::new(&opts.child_command);
    command.args(&opts.child_args);
    if let Some(dir) = &opts.child_dir {
        command.current_dir(dir);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let mut child = command.spawn().with_context(|| {
        format!(
            "failed to spawn child command {}",
            opts.child_command.display()
        )
    })?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("child stdin unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("child stdout unavailable"))?;

    shared.replace_writer(CommandSink::child(stdin)).await;

    let tx = shared.output.clone();
    let stdout_task = tokio::spawn(async move {
        forward_output(stdout, tx).await;
    });

    info!(pid = child.id(), "spawned child process");
    Ok(ChildRuntime {
        child,
        stdout_task: Some(stdout_task),
    })
}

async fn monitor_child(
    child_runtime: &mut ChildRuntime,
    shared: &Arc<ServerShared>,
    opts: &ServerOpts,
) -> Result<ChildState> {
    match child_runtime.child.try_wait() {
        Ok(Some(status)) => {
            shared.clear_writer().await;
            info!(exit_status = %status, "child process exited");
            if let Some(handle) = child_runtime.stdout_task.take() {
                handle.abort();
            }

            if opts.respawn {
                warn!(
                    "respawning child process after {} ms",
                    opts.respawn_backoff_ms
                );
                time::sleep(Duration::from_millis(opts.respawn_backoff_ms)).await;
                let new_runtime = spawn_child_runtime(opts, shared).await?;
                *child_runtime = new_runtime;
                Ok(ChildState::Running)
            } else {
                Ok(ChildState::Exited(status))
            }
        }
        Ok(None) => Ok(ChildState::Running),
        Err(err) => {
            error!(error = %err, "failed to poll child process status");
            Ok(ChildState::Errored)
        }
    }
}

async fn console_forwarder(shared: Arc<ServerShared>) {
    let mut stdin = BufReader::new(tokio_io::stdin());
    let mut buffer = String::new();

    loop {
        buffer.clear();
        match stdin.read_line(&mut buffer).await {
            Ok(0) => break,
            Ok(_) => {
                let command = buffer.trim();
                if command.is_empty() {
                    continue;
                }
                if shared.log_commands {
                    info!(source = "stdin", %command, "forwarding command");
                } else {
                    debug!(source = "stdin", %command, "forwarding command");
                }
                if let Err(err) = shared.forward_command(command).await {
                    error!(source = "stdin", error = %err, "failed to forward command");
                }
            }
            Err(err) => {
                error!(
                    source = "stdin",
                    error = %err,
                    "failed to read from stdin for console forwarding"
                );
                break;
            }
        }
    }

    info!(source = "stdin", "interactive console detached");
}

async fn forward_output(stdout: ChildStdout, tx: broadcast::Sender<String>) {
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                debug!("child stdout reached EOF");
                break;
            }
            Ok(_) => {
                let sanitized = line.trim_end_matches(['\r', '\n']).to_string();
                if tx.send(sanitized.clone()).is_err() {
                    debug!("no listeners for child stdout line");
                }
                println!("{sanitized}");
            }
            Err(err) => {
                warn!(error = %err, "error while reading child stdout");
                break;
            }
        }
    }
}

async fn handle_client(stream: TcpStream, shared: Arc<ServerShared>) -> Result<()> {
    if let Err(err) = stream.set_nodelay(true) {
        debug!(error = %err, "unable to enable TCP_NODELAY");
    }
    let peer_addr = stream.peer_addr().ok();
    info!(?peer_addr, "client connected");

    let (mut reader, mut writer) = stream.into_split();
    let mut authenticated = false;
    let mut shutdown_rx = shared.subscribe_shutdown();

    loop {
        select! {
            shutdown = shutdown_rx.changed() => {
                match shutdown {
                    Ok(()) => {
                        if *shutdown_rx.borrow() {
                            let _ = write_json_message(&mut writer, &ServerMessage::Info { message: SHUTDOWN_INFO_MESSAGE.to_string() }).await;
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = write_json_message(&mut writer, &ServerMessage::Info { message: SHUTDOWN_INFO_MESSAGE.to_string() }).await;
                        break;
                    }
                }
            }
            message = read_json_message::<_, ClientMessage>(&mut reader) => {
                let maybe = message?;
                match maybe {
                    None => break,
                    Some(ClientMessage::Auth { password }) => {
                        if authenticated {
                            write_json_message(
                                &mut writer,
                                &ServerMessage::AuthError {
                                    message: "already authenticated".to_string(),
                                },
                            )
                            .await?;
                            continue;
                        }
                        if constant_time_eq(password.as_bytes(), shared.password.as_bytes()) {
                            authenticated = true;
                            write_json_message(&mut writer, &ServerMessage::AuthOk).await?;
                            info!(?peer_addr, "client authenticated");
                        } else {
                            warn!(?peer_addr, "client presented invalid password");
                            write_json_message(
                                &mut writer,
                                &ServerMessage::AuthError {
                                    message: "invalid password".to_string(),
                                },
                            )
                            .await?;
                            break;
                        }
                    }
                    Some(ClientMessage::Command { id, command, expect_response }) => {
                        if !authenticated {
                            write_json_message(
                                &mut writer,
                                &ServerMessage::AuthError {
                                    message: "authentication required".to_string(),
                                },
                            )
                            .await?;
                            continue;
                        }

                        let trimmed = command.trim();
                        if trimmed.is_empty() {
                            write_json_message(
                                &mut writer,
                                &ServerMessage::CommandRejected {
                                    id,
                                    message: "command cannot be empty".to_string(),
                                },
                            )
                            .await?;
                            continue;
                        }

                        if shared.log_commands {
                            info!(?peer_addr, %trimmed, "forwarding command");
                        } else {
                            debug!(?peer_addr, %trimmed, "forwarding command");
                        }

                        if let Err(err) = shared.forward_command(trimmed).await {
                            error!(?peer_addr, error = %err, "failed to forward command");
                            write_json_message(
                                &mut writer,
                                &ServerMessage::CommandRejected {
                                    id,
                                    message: format!("failed to write command: {err}"),
                                },
                            )
                            .await?;
                            continue;
                        }

                        write_json_message(&mut writer, &ServerMessage::CommandAccepted { id }).await?;

                        if !expect_response {
                            continue;
                        }

                        let mut rx = shared.subscribe_output();
                        let timeout = shared.response_timeout();
                        let response = match time::timeout(timeout, rx.recv()).await {
                            Ok(Ok(line)) => ServerMessage::CommandOutput { id, output: line, more: false },
                            Ok(Err(RecvError::Lagged(skipped))) => ServerMessage::CommandOutput {
                                id,
                                output: format!("response skipped {skipped} lines; retry the command"),
                                more: false,
                            },
                            Ok(Err(RecvError::Closed)) => ServerMessage::CommandOutput {
                                id,
                                output: "output stream closed unexpectedly".to_string(),
                                more: false,
                            },
                            Err(_) => ServerMessage::CommandOutput {
                                id,
                                output: format!("no response within {} ms", timeout.as_millis()),
                                more: false,
                            },
                        };
                        write_json_message(&mut writer, &response).await?;
                    }
                    Some(ClientMessage::Ping { id }) => {
                        if !authenticated {
                            write_json_message(
                                &mut writer,
                                &ServerMessage::AuthError {
                                    message: "authentication required".to_string(),
                                },
                            )
                            .await?;
                            continue;
                        }
                        write_json_message(&mut writer, &ServerMessage::Pong { id }).await?;
                    }
                }
            }
        }
    }

    info!(?peer_addr, "client connection closed");
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0_u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

fn exit_code_from_status(status: &ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        code
    } else {
        #[cfg(unix)]
        {
            status.signal().map(|sig| 128 + sig).unwrap_or(1)
        }
        #[cfg(not(unix))]
        {
            1
        }
    }
}

fn fallback_exit_code(reason: Option<ShutdownSignal>) -> i32 {
    match reason {
        Some(ShutdownSignal::Interrupt) => 130,
        Some(ShutdownSignal::Terminate) => 143,
        None => 0,
    }
}
