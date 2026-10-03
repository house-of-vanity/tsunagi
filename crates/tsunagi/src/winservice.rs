//! The agent as a Windows service.
//!
//! `tsng service` is what the installer registers with the service control
//! manager (`sc create`); nobody types it. The manager starts the process,
//! which must call into the dispatcher quickly and then report its state, so
//! this is the only place the Windows service API is touched. Everything the
//! agent does is the same `up` that runs in a console; the only differences
//! are that it stops when the manager says so rather than on Ctrl-C, and that
//! it logs to a file because a service has no console.
//!
//! The one `unsafe` here is not ours: `define_windows_service!` expands to the
//! `extern "system"` entry point the manager calls, which has to be unsafe.

#![allow(unsafe_code)]

use std::ffi::OsString;
use std::sync::OnceLock;
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::{define_windows_service, service_dispatcher};

/// The name the installer registers the service under.
pub const SERVICE_NAME: &str = "Tsunagi";

/// How long the manager waits for a stop before it gives up on us. The agent's
/// own shutdown is bounded and shorter.
const STOP_WAIT: Duration = Duration::from_secs(25);

/// Set when the manager asks the service to stop.
static STOP: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// What `up` does, handed over by `main` because the manager's entry point
/// cannot take arguments.
type Body = Box<dyn Fn() -> Result<(), String> + Send + Sync>;
static BODY: OnceLock<Body> = OnceLock::new();

/// Where the manager's status handle is kept, so the stop handler can report.
static STATUS: OnceLock<ServiceStatusHandle> = OnceLock::new();

/// Resolves when the manager has asked the service to stop.
pub async fn stop_requested() {
    STOP.notified().await;
}

define_windows_service!(ffi_service_main, service_main);

/// Hands the process to the service control manager and returns when the
/// service has stopped. Fails at once when not started by the manager, which
/// is how running `tsng service` in a console is reported.
pub fn run(body: Body) -> Result<(), windows_service::Error> {
    let _ = BODY.set(body);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn service_main(_arguments: Vec<OsString>) {
    let result = serve();
    let code = match &result {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(err) => {
            tracing::error!("the service failed: {err}");
            // A non-zero exit lets the recovery actions restart it.
            ServiceExitCode::ServiceSpecific(1)
        }
    };
    if let Some(handle) = STATUS.get() {
        let _ = handle.set_service_status(status(ServiceState::Stopped, code, Duration::ZERO));
    }
}

fn serve() -> Result<(), String> {
    let handle = service_control_handler::register(SERVICE_NAME, |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(handle) = STATUS.get() {
                let _ = handle.set_service_status(status(
                    ServiceState::StopPending,
                    ServiceExitCode::Win32(0),
                    STOP_WAIT,
                ));
            }
            STOP.notify_one();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .map_err(|err| format!("cannot register with the service control manager: {err}"))?;
    let _ = STATUS.set(handle);
    handle
        .set_service_status(status(
            ServiceState::Running,
            ServiceExitCode::Win32(0),
            Duration::ZERO,
        ))
        .map_err(|err| format!("cannot report the service as running: {err}"))?;
    match BODY.get() {
        Some(body) => body(),
        None => Err("the service has nothing to run".to_string()),
    }
}

fn status(state: ServiceState, exit_code: ServiceExitCode, wait_hint: Duration) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code,
        checkpoint: 0,
        wait_hint,
        process_id: None,
    }
}
