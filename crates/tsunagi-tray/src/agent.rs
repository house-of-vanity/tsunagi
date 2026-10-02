//! The client side: a background worker that talks to the agent over the local
//! control socket, off the UI thread.
//!
//! The UI never blocks on IO. A worker on a tokio runtime polls the agent for
//! status on an interval and runs the commands the UI sends (join, leave,
//! activate, broadcast), writing the latest snapshot into shared state and
//! asking egui to repaint. The whole thing is a thin layer over
//! [`tsunagi::ipc`]; no protocol is re-implemented here.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;
use tokio::sync::mpsc;

use tsunagi::ipc::{self, StatusReport};

/// How often the worker refreshes status while idle.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// A request from the UI to the agent.
pub(crate) enum Command {
    /// Re-read status now.
    Refresh,
    /// Stop serving a network, or start serving it again.
    SetActive { network_id: String, active: bool },
    /// Turn local broadcast participation on or off for a network.
    SetBroadcast { network_id: String, enabled: bool },
    /// Join a network, or start one already configured.
    Join { name: String, secret: String },
    /// Leave a network entirely.
    Leave { network_id: String },
    /// Change the hostname this device announces.
    SetHostname(String),
}

/// The latest the worker knows, read by the UI each frame.
#[derive(Clone, Default)]
pub(crate) struct Snapshot {
    /// The last status, or the reason it could not be read (agent down, no
    /// permission on the socket, …).
    pub status: Option<Result<StatusReport, String>>,
    /// The outcome of the most recent command, for a transient banner.
    pub last_action: Option<Result<String, String>>,
    /// Whether a command is currently being executed.
    pub busy: bool,
    /// Bumped each time `status` is refreshed, so the UI can tell new data from
    /// a repaint of the same data and sample traffic rates only on change.
    pub generation: u64,
    /// When this status was read, for computing rates between refreshes.
    pub at: Option<Instant>,
}

/// Handle the UI holds: send commands, read the latest snapshot.
pub(crate) struct AgentClient {
    socket: PathBuf,
    tx: mpsc::UnboundedSender<Command>,
    shared: Arc<Mutex<Snapshot>>,
}

impl AgentClient {
    /// Starts the worker on `runtime`, reporting to `ctx` (for repaints).
    pub(crate) fn spawn(
        runtime: &tokio::runtime::Handle,
        ctx: egui::Context,
        socket: PathBuf,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Mutex::new(Snapshot::default()));
        runtime.spawn(worker(socket.clone(), rx, Arc::clone(&shared), ctx));
        Self { socket, tx, shared }
    }

    /// The control socket this client talks to.
    pub(crate) fn socket(&self) -> &std::path::Path {
        &self.socket
    }

    /// Sends a command; a dropped worker simply means nothing happens.
    pub(crate) fn send(&self, command: Command) {
        let _ = self.tx.send(command);
    }

    /// A copy of the latest snapshot.
    pub(crate) fn snapshot(&self) -> Snapshot {
        lock(&self.shared).clone()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// The worker loop: refresh on an interval and whenever a command runs.
async fn worker(
    socket: PathBuf,
    mut rx: mpsc::UnboundedReceiver<Command>,
    shared: Arc<Mutex<Snapshot>>,
    ctx: egui::Context,
) {
    refresh(&socket, &shared, &ctx).await;
    let mut tick = tokio::time::interval(POLL_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = tick.tick() => {
                refresh(&socket, &shared, &ctx).await;
            }
            command = rx.recv() => {
                let Some(command) = command else { return };
                run(&socket, command, &shared, &ctx).await;
                refresh(&socket, &shared, &ctx).await;
            }
        }
    }
}

/// Reads status and stores it, mapping any failure to a human string.
async fn refresh(socket: &std::path::Path, shared: &Arc<Mutex<Snapshot>>, ctx: &egui::Context) {
    let status = ipc::request_status(socket)
        .await
        .map_err(|err| err.to_string());
    {
        let mut guard = lock(shared);
        guard.status = Some(status);
        guard.generation = guard.generation.wrapping_add(1);
        guard.at = Some(Instant::now());
    }
    ctx.request_repaint();
}

/// Runs one command and records its outcome.
async fn run(
    socket: &std::path::Path,
    command: Command,
    shared: &Arc<Mutex<Snapshot>>,
    ctx: &egui::Context,
) {
    lock(shared).busy = true;
    ctx.request_repaint();

    let outcome: Result<String, String> = match command {
        Command::Refresh => Ok(String::new()),
        Command::SetActive { network_id, active } => ipc::set_active(socket, &network_id, active)
            .await
            .map(|report| {
                let state = if report.active { "started" } else { "stopped" };
                format!("{} {}", state, report.name)
            })
            .map_err(|err| err.to_string()),
        Command::SetBroadcast {
            network_id,
            enabled,
        } => ipc::set_broadcast(socket, &network_id, enabled)
            .await
            .map(|on| format!("broadcast {}", if on { "on" } else { "off" }))
            .map_err(|err| err.to_string()),
        Command::Join { name, secret } => ipc::join_network(socket, &name, &secret)
            .await
            .map(|report| format!("joined {}", report.name))
            .map_err(|err| err.to_string()),
        Command::Leave { network_id } => ipc::leave_network(socket, &network_id)
            .await
            .map(|report| format!("left {}", report.name))
            .map_err(|err| err.to_string()),
        Command::SetHostname(name) => ipc::set_hostname(socket, &name)
            .await
            .map(|accepted| format!("hostname: {accepted}"))
            .map_err(|err| err.to_string()),
    };

    {
        let mut guard = lock(shared);
        guard.busy = false;
        guard.last_action = if matches!(&outcome, Ok(message) if message.is_empty()) {
            None
        } else {
            Some(outcome)
        };
    }
    ctx.request_repaint();
}

/// Where the GUI looks for the agent: `TSUNAGI_CONTROL_SOCKET` if set, else the
/// platform default (the system service's path).
pub(crate) fn resolve_socket() -> PathBuf {
    if let Some(path) = std::env::var_os("TSUNAGI_CONTROL_SOCKET") {
        return PathBuf::from(path);
    }
    ipc::default_control_socket_path()
}
