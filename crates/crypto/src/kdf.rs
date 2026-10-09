use crate::error::{CryptoError, Result};
use hkdf::Hkdf;
use sha2::Sha256;

pub const DERIVED_KEY_LEN: usize = 32;

pub fn derive_key(
    input_key_material: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; DERIVED_KEY_LEN]> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), input_key_material);
    let mut output = [0u8; DERIVED_KEY_LEN];
    hkdf.expand(info, &mut output)
        .map_err(|err| CryptoError::Hkdf(err.to_string()))?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let a = derive_key(b"ikm", b"salt", b"session-key").expect("derive");
        let b = derive_key(b"ikm", b"salt", b"session-key").expect("derive");
        assert_eq!(a, b);
    }

    #[test]
    fn different_info_produces_different_keys() {
        let a = derive_key(b"ikm", b"salt", b"session-key").expect("derive");
        let b = derive_key(b"ikm", b"salt", b"traffic-key").expect("derive");
        assert_ne!(a, b);
    }
}
