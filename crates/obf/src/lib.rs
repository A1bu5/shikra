//! Compile-time string obfuscation for Shikra implants.
//!
//! `obf!` XORs each string literal with a key derived from a per-build seed
//! (`SHIKRA_OBF_SEED`, stable when unset) and emits a small decoder so the
//! clear text never appears in the binary. `obf_bytes!` does the same for
//! byte-string literals (e.g. embedded certificates or shellcode).

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitByteStr, LitStr};

fn seed() -> u64 {
    std::env::var("SHIKRA_OBF_SEED")
        .ok()
        .and_then(|raw| {
            let trimmed = raw.trim();
            let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
            u64::from_str_radix(hex, 16)
                .ok()
                .or_else(|| trimmed.parse().ok())
        })
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
}

/// Derives a per-literal key so identical strings in different locations do
/// not share a keystream.
fn key_for(seed: u64, len: usize, salt: u64) -> Vec<u8> {
    let mut state = seed ^ salt.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (len as u64);
    let mut key = Vec::with_capacity(16);
    while key.len() < 16 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        key.extend_from_slice(&state.to_le_bytes());
    }
    key.truncate(16);
    key
}

fn salt_for(bytes: &[u8]) -> u64 {
    let mut hash = 0xCBF2_9CE4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

fn xor_bytes(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(index, byte)| byte ^ key[index % key.len()])
        .collect()
}

/// Returns the decoded payload folded with a folded 64-bit hash so the
/// generated code resists trivial CFG recovery of the clear text.
fn folded_hash(data: &[u8]) -> u64 {
    let mut hash = 0u64;
    for (index, byte) in data.iter().enumerate() {
        hash = hash.rotate_left(7) ^ u64::from(*byte).wrapping_mul(index as u64 + 1);
    }
    hash
}

#[proc_macro]
pub fn obf(input: TokenStream) -> TokenStream {
    let literal = parse_macro_input!(input as LitStr);
    let plaintext = literal.value();
    let bytes = plaintext.as_bytes();
    let seed = seed();
    let key = key_for(seed, bytes.len(), salt_for(bytes));
    let encoded = xor_bytes(bytes, &key);

    let len = encoded.len();
    let key_len = key.len();
    let key_bytes = &key;
    let hash = folded_hash(bytes);
    let encoded = &encoded;

    let expanded = quote! {{
        #[inline(never)]
        fn __shikra_obf_decode(
            encoded: &[u8; #len],
            key: &[u8; #key_len],
            hash: u64,
        ) -> ::std::string::String {
            let mut bytes = ::std::vec::Vec::with_capacity(#len);
            let mut acc = 0u64;
            for (index, byte) in encoded.iter().enumerate() {
                let value = byte ^ key[index % #key_len];
                acc = acc.rotate_left(7) ^ (value as u64).wrapping_mul(index as u64 + 1);
                bytes.push(value);
            }
            if acc != hash {
                return ::std::string::String::new();
            }
            match ::std::string::String::from_utf8(bytes) {
                Ok(value) => value,
                Err(_) => ::std::string::String::new(),
            }
        }
        __shikra_obf_decode(
            ::std::hint::black_box(&[#(#encoded),*]),
            ::std::hint::black_box(&[#(#key_bytes),*]),
            #hash,
        )
    }};
    expanded.into()
}

#[proc_macro]
pub fn obf_bytes(input: TokenStream) -> TokenStream {
    let literal = parse_macro_input!(input as LitByteStr);
    let plaintext = literal.value();
    let seed = seed();
    let key = key_for(seed, plaintext.len(), salt_for(&plaintext));
    let encoded = xor_bytes(&plaintext, &key);

    let len = encoded.len();
    let key_len = key.len();
    let key_bytes = &key;
    let hash = folded_hash(&plaintext);
    let encoded = &encoded;

    let expanded = quote! {{
        #[inline(never)]
        fn __shikra_obf_decode_bytes(
            encoded: &[u8; #len],
            key: &[u8; #key_len],
            hash: u64,
        ) -> ::std::vec::Vec<u8> {
            let mut bytes = ::std::vec::Vec::with_capacity(#len);
            let mut acc = 0u64;
            for (index, byte) in encoded.iter().enumerate() {
                let value = byte ^ key[index % #key_len];
                acc = acc.rotate_left(7) ^ (value as u64).wrapping_mul(index as u64 + 1);
                bytes.push(value);
            }
            if acc != hash {
                bytes.clear();
            }
            bytes
        }
        __shikra_obf_decode_bytes(
            ::std::hint::black_box(&[#(#encoded),*]),
            ::std::hint::black_box(&[#(#key_bytes),*]),
            #hash,
        )
    }};
    expanded.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_deterministic_for_same_input() {
        let bytes = b"shikra";
        assert_eq!(
            key_for(7, bytes.len(), salt_for(bytes)),
            key_for(7, bytes.len(), salt_for(bytes))
        );
    }

    #[test]
    fn different_literals_get_different_keys() {
        let left = key_for(7, 6, salt_for(b"shikra"));
        let right = key_for(7, 6, salt_for(b"shikra"));
        let other = key_for(7, 5, salt_for(b"dagge"));
        assert_eq!(left, right);
        assert_ne!(left, other);
    }

    #[test]
    fn xor_roundtrip() {
        let data = b"hello world";
        let key = key_for(1, data.len(), salt_for(data));
        let encoded = xor_bytes(data, &key);
        assert_ne!(encoded, data);
        assert_eq!(xor_bytes(&encoded, &key), data);
    }

    #[test]
    fn folded_hash_detects_tampering() {
        let data = b"payload";
        let hash = folded_hash(data);
        let mut tampered = data.to_vec();
        tampered[0] ^= 1;
        assert_ne!(folded_hash(&tampered), hash);
    }
}
