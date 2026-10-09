/// Constant-time byte comparison for secrets (length leaks only).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_slices_match() {
        assert!(ct_eq(b"shikra-token", b"shikra-token"));
    }

    #[test]
    fn different_slices_reject() {
        assert!(!ct_eq(b"shikra-token", b"shikra-tokeN"));
        assert!(!ct_eq(b"short", b"longer"));
        assert!(!ct_eq(b"", b"x"));
    }
}
