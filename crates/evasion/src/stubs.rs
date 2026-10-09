//! Parsing helpers for ntdll syscall stubs.
//!
//! Classic x64 stubs look like `4C 8B D1 B8 <imm32>` (mov r10, rcx; mov eax,
//! ssn) followed by an optional branch and the `syscall` instruction. The
//! helpers here are platform-neutral and unit tested on any host.

/// Extracts the system service number from a classic x64 syscall stub.
///
/// Returns `None` when the prologue does not match, which is the case when a
/// usermode hook has replaced the first bytes.
pub fn extract_ssn_x64(stub: &[u8]) -> Option<u32> {
    if stub.len() < 8 {
        return None;
    }
    for offset in 0..stub.len() - 7 {
        if stub[offset..offset + 3] == [0x4C, 0x8B, 0xD1] && stub[offset + 3] == 0xB8 {
            let immediate = u32::from_le_bytes(stub[offset + 4..offset + 8].try_into().ok()?);
            if immediate < 0x2000 {
                return Some(immediate);
            }
        }
    }
    None
}

/// Returns the offset of a `0F 05 C3` (syscall; ret) gadget.
pub fn find_syscall_gadget(code: &[u8]) -> Option<usize> {
    code.windows(3)
        .position(|window| window == [0x0F, 0x05, 0xC3])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ssn_from_stub() {
        let stub = [
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0xB8, 0x18, 0x00, 0x00, 0x00, // mov eax, 0x18
            0x0F, 0x05, 0xC3, // syscall; ret
        ];
        assert_eq!(extract_ssn_x64(&stub), Some(0x18));
    }

    #[test]
    fn rejects_hooked_stub() {
        let hooked = [
            0xE9, 0x00, 0x00, 0x00, 0x00, // jmp rel32
            0x90, 0x90, 0x90,
        ];
        assert_eq!(extract_ssn_x64(&hooked), None);
    }

    #[test]
    fn rejects_absurd_ssn() {
        let mut stub = vec![0x4C, 0x8B, 0xD1, 0xB8];
        stub.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert_eq!(extract_ssn_x64(&stub), None);
    }

    #[test]
    fn finds_syscall_gadget() {
        let code = [0x90, 0x48, 0x89, 0x0F, 0x05, 0xC3, 0x90];
        assert_eq!(find_syscall_gadget(&code), Some(3));
        assert_eq!(find_syscall_gadget(&[0x0F, 0x05, 0x90]), None);
    }
}
