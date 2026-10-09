//! Minimal, bounds-checked PE parsing helpers.
//!
//! All functions operate on an image already mapped into memory, where an RVA
//! equals the offset into the buffer. They are platform-neutral so they can be
//! unit tested on any host.

/// Returns the `SizeOfImage` field from a PE32/PE32+ header.
pub fn image_size(image: &[u8]) -> Option<usize> {
    let opt = optional_header_offset(image)?;
    read_u32(image, opt + 0x38).map(|value| value as usize)
}

/// Looks up an export by name and returns its RVA.
pub fn find_export_rva(image: &[u8], name: &str) -> Option<u32> {
    let opt = optional_header_offset(image)?;
    let data_dir = match read_u16(image, opt)? {
        0x20B => opt + 0x70, // PE32+
        0x10B => opt + 0x60, // PE32
        _ => return None,
    };
    let export_rva = read_u32(image, data_dir)? as usize;
    if export_rva == 0 {
        return None;
    }
    let num_names = read_u32(image, export_rva + 24)? as usize;
    let functions = read_u32(image, export_rva + 28)? as usize;
    let names = read_u32(image, export_rva + 32)? as usize;
    let ordinals = read_u32(image, export_rva + 36)? as usize;
    for index in 0..num_names {
        let name_rva = read_u32(image, names + index * 4)? as usize;
        if read_cstr(image, name_rva)? != name.as_bytes() {
            continue;
        }
        let ordinal = read_u16(image, ordinals + index * 2)? as usize;
        let rva = read_u32(image, functions + ordinal * 4)?;
        return (rva != 0).then_some(rva);
    }
    None
}

/// Returns `(virtual_address, size)` for every executable section.
pub fn exec_ranges(image: &[u8]) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let Some(e_lfanew) = read_u32(image, 0x3C).map(|value| value as usize) else {
        return ranges;
    };
    let Some(num_sections) = read_u16(image, e_lfanew + 6) else {
        return ranges;
    };
    let Some(opt_size) = read_u16(image, e_lfanew + 20) else {
        return ranges;
    };
    let sections = e_lfanew + 24 + opt_size as usize;
    for index in 0..num_sections as usize {
        let section = sections + index * 40;
        let Some(virtual_size) = read_u32(image, section + 8) else {
            continue;
        };
        let Some(virtual_address) = read_u32(image, section + 12) else {
            continue;
        };
        let Some(characteristics) = read_u32(image, section + 36) else {
            continue;
        };
        let size = virtual_size as usize;
        let start = virtual_address as usize;
        if characteristics & 0x2000_0000 == 0 || size == 0 {
            continue;
        }
        if start
            .checked_add(size)
            .is_some_and(|end| end <= image.len())
        {
            ranges.push((start, size));
        }
    }
    ranges
}

/// Case-insensitive ASCII comparison of a UTF-16 buffer against a `&str`.
pub fn utf16_eq_ascii(chars: &[u16], name: &str) -> bool {
    if chars.len() != name.len() {
        return false;
    }
    chars
        .iter()
        .zip(name.bytes())
        .all(|(c, expected)| *c <= 0x7F && (*c as u8).eq_ignore_ascii_case(&expected))
}

fn optional_header_offset(image: &[u8]) -> Option<usize> {
    let e_lfanew = read_u32(image, 0x3C)? as usize;
    if read_u32(image, e_lfanew)? != 0x0000_4550 {
        return None;
    }
    Some(e_lfanew + 24)
}

fn read_u16(image: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        image.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(image: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        image.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_cstr(image: &[u8], offset: usize) -> Option<&[u8]> {
    let tail = image.get(offset..)?;
    let end = tail.iter().take(512).position(|byte| *byte == 0)?;
    Some(&tail[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_image() -> Vec<u8> {
        let mut image = vec![0u8; 0x1600];
        image[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        image[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        image[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        image[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes());
        image[0x98 + 0x38..0x98 + 0x3C].copy_from_slice(&0x1600u32.to_le_bytes());
        image[0x98 + 0x70..0x98 + 0x74].copy_from_slice(&0x200u32.to_le_bytes());
        image[0x98 + 0x74..0x98 + 0x78].copy_from_slice(&0x100u32.to_le_bytes());
        let export = 0x200;
        image[export + 24..export + 28].copy_from_slice(&2u32.to_le_bytes());
        image[export + 28..export + 32].copy_from_slice(&0x240u32.to_le_bytes());
        image[export + 32..export + 36].copy_from_slice(&0x260u32.to_le_bytes());
        image[export + 36..export + 40].copy_from_slice(&0x280u32.to_le_bytes());
        image[0x240..0x244].copy_from_slice(&0x1000u32.to_le_bytes());
        image[0x244..0x248].copy_from_slice(&0x1010u32.to_le_bytes());
        image[0x260..0x264].copy_from_slice(&0x2A0u32.to_le_bytes());
        image[0x264..0x268].copy_from_slice(&0x2B0u32.to_le_bytes());
        image[0x280..0x282].copy_from_slice(&0u16.to_le_bytes());
        image[0x282..0x284].copy_from_slice(&1u16.to_le_bytes());
        image[0x2A0..0x2A8].copy_from_slice(b"NtClose\0");
        image[0x2B0..0x2C1].copy_from_slice(b"NtDelayExecution\0");
        let section = 0x98 + 0xF0;
        image[section..section + 8].copy_from_slice(b".text\0\0\0");
        image[section + 8..section + 12].copy_from_slice(&0x500u32.to_le_bytes());
        image[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        image[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        image
    }

    #[test]
    fn finds_exports_by_name() {
        let image = synthetic_image();
        assert_eq!(find_export_rva(&image, "NtClose"), Some(0x1000));
        assert_eq!(find_export_rva(&image, "NtDelayExecution"), Some(0x1010));
        assert_eq!(find_export_rva(&image, "NtMissing"), None);
    }

    #[test]
    fn reads_image_size() {
        assert_eq!(image_size(&synthetic_image()), Some(0x1600));
        assert_eq!(image_size(&[0u8; 16]), None);
    }

    #[test]
    fn reports_executable_sections() {
        let image = synthetic_image();
        assert_eq!(exec_ranges(&image), vec![(0x1000, 0x500)]);
    }

    #[test]
    fn utf16_comparison_is_case_insensitive() {
        let name: Vec<u16> = "ntdll.dll".encode_utf16().collect();
        assert!(utf16_eq_ascii(&name, "NTDLL.DLL"));
        assert!(utf16_eq_ascii(&name, "ntdll.dll"));
        assert!(!utf16_eq_ascii(&name, "kernel32.dll"));
        assert!(!utf16_eq_ascii(&name, "ntdll.dl"));
        assert!(!utf16_eq_ascii(&[0x141u16], "a"));
    }
}
