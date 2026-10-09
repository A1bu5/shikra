#![allow(unsafe_code)]

//! In-memory (reflective) PE DLL loader.
//!
//! Maps a DLL image from memory without touching disk: allocates the image,
//! copies headers and sections, applies base relocations, resolves imports
//! against the live module list, sets per-section protections and calls the
//! entry point (`DllMain(DLL_PROCESS_ATTACH)`).
//!
//! The implementation is deliberately strict: malformed images are rejected
//! with an error instead of being mapped partially.

use crate::windows::{export_address, load_library};
use shikra_obf::obf;
use std::ffi::c_void;
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE,
};

const PE_SIGNATURE: &[u8; 4] = b"PE\0\0";
const OPTIONAL_MAGIC_PE32: u16 = 0x010B;
const OPTIONAL_MAGIC_PE32P: u16 = 0x020B;
const DLL_PROCESS_ATTACH: u32 = 1;

/// Maps a DLL image into this process and calls its entry point.
///
/// Returns the mapped base address and the `DllMain` result.
pub unsafe fn load_dll(image: &[u8]) -> Result<(usize, u32), String> {
    if image.len() < 0x40 || &image[0..2] != b"MZ" {
        return Err("not a PE image (missing MZ header)".into());
    }
    let pe_offset = read_u32(image, 0x3c)? as usize;
    if image.len() < pe_offset + 24 || &image[pe_offset..pe_offset + 4] != PE_SIGNATURE {
        return Err("invalid PE header".into());
    }
    let coff = pe_offset + 4;
    let section_count = read_u16(image, coff + 2)? as usize;
    let optional_size = read_u16(image, coff + 16)? as usize;
    let optional = coff + 20;
    let magic = read_u16(image, optional)?;
    let is_64 = match magic {
        OPTIONAL_MAGIC_PE32P => true,
        OPTIONAL_MAGIC_PE32 => false,
        other => return Err(format!("unsupported optional header magic 0x{other:04x}")),
    };
    if image.len() < optional + optional_size {
        return Err("truncated optional header".into());
    }

    let entry_rva = read_u32(image, optional + 16)?;
    let image_base = if is_64 {
        read_u64(image, optional + 24)?
    } else {
        read_u32(image, optional + 28)? as u64
    };
    let size_of_image = read_u32(image, optional + 56)? as usize;
    let size_of_headers = read_u32(image, optional + 60)? as usize;
    if size_of_image < size_of_headers || size_of_image > 512 * 1024 * 1024 {
        return Err("implausible SizeOfImage".into());
    }
    let data_directory = optional + if is_64 { 112 } else { 96 };

    let sections_offset = optional + optional_size;
    if image.len() < sections_offset + section_count * 40 {
        return Err("truncated section table".into());
    }

    let base = VirtualAlloc(
        std::ptr::null(),
        size_of_image,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) as usize;
    if base == 0 {
        return Err("VirtualAlloc for image failed".into());
    }

    // Headers, then sections.
    let headers_len = size_of_headers.min(image.len());
    std::ptr::copy_nonoverlapping(image.as_ptr(), base as *mut u8, headers_len);
    for index in 0..section_count {
        let section = sections_offset + index * 40;
        let virtual_size = read_u32(image, section + 8)? as usize;
        let virtual_address = read_u32(image, section + 12)? as usize;
        let raw_size = read_u32(image, section + 16)? as usize;
        let raw_offset = read_u32(image, section + 20)? as usize;
        let copy_len = raw_size.min(image.len().saturating_sub(raw_offset).max(0));
        if virtual_address + virtual_size.max(copy_len) > size_of_image {
            return Err("section exceeds SizeOfImage".into());
        }
        if copy_len > 0 && raw_offset <= image.len() {
            std::ptr::copy_nonoverlapping(
                image.as_ptr().add(raw_offset),
                (base + virtual_address) as *mut u8,
                copy_len,
            );
        }
    }

    let delta = base as i64 - image_base as i64;

    // Base relocations.
    let reloc_rva = read_u32(image, data_directory + 5 * 8)? as usize;
    let reloc_size = read_u32(image, data_directory + 5 * 8 + 4)? as usize;
    if reloc_rva != 0 && reloc_size > 0 {
        apply_relocations(base, size_of_image, reloc_rva, reloc_size, delta, is_64)?;
    }

    // Imports.
    let import_rva = read_u32(image, data_directory + 8)? as usize;
    let import_size = read_u32(image, data_directory + 12)? as usize;
    if import_rva != 0 && import_size > 0 {
        resolve_imports(base, size_of_image, import_rva, import_size, is_64)?;
    }

    // Per-section protections.
    for index in 0..section_count {
        let section = sections_offset + index * 40;
        let virtual_size = read_u32(image, section + 8)? as usize;
        let virtual_address = read_u32(image, section + 12)? as usize;
        let characteristics = read_u32(image, section + 36)?;
        if virtual_size == 0 {
            continue;
        }
        let protection = section_protection(characteristics);
        let mut previous = 0u32;
        VirtualProtect(
            (base + virtual_address) as *const c_void,
            virtual_size,
            protection,
            &mut previous,
        );
    }

    // Instruction cache: required on ARM64, harmless elsewhere.
    if let Ok(kernel32) = load_library(&obf!("kernel32.dll")) {
        if let Some(flush) = export_address(kernel32, &obf!("FlushInstructionCache")) {
            type FlushFn = unsafe extern "system" fn(usize, *const c_void, usize) -> i32;
            let flush: FlushFn = std::mem::transmute(flush);
            flush(usize::MAX, base as *const c_void, size_of_image);
        }
    }

    let mut dll_main_result = 0u32;
    if entry_rva != 0 {
        let entry = base + entry_rva as usize;
        let dll_main: unsafe extern "system" fn(usize, u32, usize) -> u32 =
            std::mem::transmute(entry);
        dll_main_result = dll_main(base, DLL_PROCESS_ATTACH, 0);
    }

    Ok((base, dll_main_result))
}

unsafe fn apply_relocations(
    base: usize,
    size_of_image: usize,
    reloc_rva: usize,
    reloc_size: usize,
    delta: i64,
    is_64: bool,
) -> Result<(), String> {
    if reloc_rva + reloc_size > size_of_image {
        return Err("relocation directory out of bounds".into());
    }
    let end = reloc_rva + reloc_size;
    let mut offset = reloc_rva;
    while offset + 8 <= end {
        let page_rva = read_mem_u32(base + offset);
        let block_size = read_mem_u32(base + offset + 4) as usize;
        if block_size < 8 || offset + block_size > end {
            return Err("malformed relocation block".into());
        }
        let entries = (block_size - 8) / 2;
        for index in 0..entries {
            let entry = read_mem_u16(base + offset + 8 + index * 2);
            let kind = (entry >> 12) as u32;
            let page_offset = (entry & 0x0fff) as usize;
            let target = base + page_rva as usize + page_offset;
            if target + 8 > base + size_of_image {
                return Err("relocation target out of bounds".into());
            }
            match kind {
                0 => {} // IMAGE_REL_BASED_ABSOLUTE padding
                10 if is_64 => {
                    let value = read_mem_u64(target) as i64 + delta;
                    std::ptr::write_unaligned(target as *mut u64, value as u64);
                }
                3 if !is_64 => {
                    let value = read_mem_u32(target) as i64 + delta;
                    std::ptr::write_unaligned(target as *mut u32, value as u32);
                }
                other => {
                    return Err(format!("unsupported relocation type {other}"));
                }
            }
        }
        offset += block_size;
    }
    Ok(())
}

unsafe fn resolve_imports(
    base: usize,
    size_of_image: usize,
    import_rva: usize,
    import_size: usize,
    is_64: bool,
) -> Result<(), String> {
    if import_rva + import_size > size_of_image {
        return Err("import directory out of bounds".into());
    }
    let mut descriptor = base + import_rva;
    let descriptor_end = base + import_rva + import_size;
    loop {
        if descriptor + 20 > descriptor_end {
            break;
        }
        let original_first_thunk = read_mem_u32(descriptor) as usize;
        let name_rva = read_mem_u32(descriptor + 12) as usize;
        let first_thunk = read_mem_u32(descriptor + 16) as usize;
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        if name_rva == 0 || name_rva >= size_of_image {
            return Err("import descriptor without module name".into());
        }
        let module_name = read_c_string(base, name_rva, size_of_image)?;
        let module = load_library(&module_name)
            .map_err(|err| format!("failed to load import module {module_name}: {err}"))?;

        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        let pointer_size = if is_64 { 8 } else { 4 };
        let mut index = 0usize;
        loop {
            let thunk_offset = thunk_rva + index * pointer_size;
            let thunk = if is_64 {
                read_mem_u64(base + thunk_offset)
            } else {
                read_mem_u32(base + thunk_offset) as u64
            };
            if thunk == 0 {
                break;
            }
            let ordinal_flag = if is_64 { 1u64 << 63 } else { 1u64 << 31 };
            let resolved = if thunk & ordinal_flag != 0 {
                let ordinal = (thunk & 0xffff) as usize;
                resolve_by_ordinal(module, ordinal)?
            } else {
                let name_offset = thunk as usize + 2; // skip the hint word
                if name_offset >= size_of_image {
                    return Err("import name out of bounds".into());
                }
                let function_name = read_c_string(base, name_offset, size_of_image)?;
                export_address(module, &function_name)
                    .ok_or_else(|| format!("export {function_name} not found in {module_name}"))?
            };
            let iat_slot = base + first_thunk + index * pointer_size;
            if is_64 {
                std::ptr::write_unaligned(iat_slot as *mut u64, resolved as u64);
            } else {
                std::ptr::write_unaligned(iat_slot as *mut u32, resolved as u32);
            }
            index += 1;
        }
        descriptor += 20;
    }
    Ok(())
}

fn resolve_by_ordinal(module: usize, ordinal: usize) -> Result<usize, String> {
    // Export by ordinal: walk the export directory address table directly.
    let ordinal = ordinal as u32;
    unsafe {
        let dos = module as *const u8;
        if std::ptr::read_unaligned(dos) != b'M' || std::ptr::read_unaligned(dos.add(1)) != b'Z' {
            return Err("module is not a PE image".into());
        }
        let pe_offset = std::ptr::read_unaligned(dos.add(0x3c) as *const u32) as usize;
        let optional = module + pe_offset + 24;
        let magic = std::ptr::read_unaligned(optional as *const u16);
        let data_directory = optional
            + if magic == OPTIONAL_MAGIC_PE32P {
                112
            } else {
                96
            };
        let export_rva = std::ptr::read_unaligned((data_directory + 0) as *const u32) as usize;
        if export_rva == 0 {
            return Err("module has no exports".into());
        }
        let export = module + export_rva;
        let base = std::ptr::read_unaligned(export as *const u32) as u32;
        let number_of_functions = std::ptr::read_unaligned((export + 20) as *const u32);
        let functions = module + std::ptr::read_unaligned((export + 28) as *const u32) as usize;
        let index = ordinal.wrapping_sub(base) as usize;
        if index >= number_of_functions as usize {
            return Err(format!("ordinal {ordinal} out of range"));
        }
        let function_rva = std::ptr::read_unaligned((functions + index * 4) as *const u32) as usize;
        if function_rva == 0 {
            return Err(format!("ordinal {ordinal} is not exported"));
        }
        Ok(module + function_rva)
    }
}

fn section_protection(characteristics: u32) -> u32 {
    const MEM_EXECUTE: u32 = 0x2000_0000;
    const MEM_READ: u32 = 0x4000_0000;
    const MEM_WRITE: u32 = 0x8000_0000;
    let execute = characteristics & MEM_EXECUTE != 0;
    let read = characteristics & MEM_READ != 0;
    let write = characteristics & MEM_WRITE != 0;
    match (execute, read, write) {
        (true, _, true) => PAGE_EXECUTE_READWRITE,
        (true, _, false) => PAGE_EXECUTE_READ,
        (false, _, true) => PAGE_READWRITE,
        (false, true, false) => PAGE_READONLY,
        (false, false, false) => PAGE_READONLY,
    }
}

fn read_u16(image: &[u8], offset: usize) -> Result<u16, String> {
    image
        .get(offset..offset + 2)
        .map(|slice| u16::from_le_bytes([slice[0], slice[1]]))
        .ok_or_else(|| format!("read u16 at 0x{offset:x} out of bounds"))
}

fn read_u32(image: &[u8], offset: usize) -> Result<u32, String> {
    image
        .get(offset..offset + 4)
        .map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
        .ok_or_else(|| format!("read u32 at 0x{offset:x} out of bounds"))
}

fn read_u64(image: &[u8], offset: usize) -> Result<u64, String> {
    image
        .get(offset..offset + 8)
        .map(|slice| {
            u64::from_le_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
            ])
        })
        .ok_or_else(|| format!("read u64 at 0x{offset:x} out of bounds"))
}

unsafe fn read_mem_u16(address: usize) -> u16 {
    std::ptr::read_unaligned(address as *const u16)
}

unsafe fn read_mem_u32(address: usize) -> u32 {
    std::ptr::read_unaligned(address as *const u32)
}

unsafe fn read_mem_u64(address: usize) -> u64 {
    std::ptr::read_unaligned(address as *const u64)
}

unsafe fn read_c_string(base: usize, rva: usize, size_of_image: usize) -> Result<String, String> {
    if rva >= size_of_image {
        return Err("string RVA out of bounds".into());
    }
    let mut length = 0usize;
    let pointer = (base + rva) as *const u8;
    while rva + length < size_of_image {
        if std::ptr::read_unaligned(pointer.add(length)) == 0 {
            break;
        }
        length += 1;
    }
    let bytes = std::slice::from_raw_parts(pointer, length);
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|_| "import string is not UTF-8".to_string())
}
