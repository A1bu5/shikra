//! Encrypted-at-rest memory buffers.
//!
//! Command output, tokens and other sensitive blobs otherwise sit in plaintext
//! heap while the implant sleeps. [`MaskedBytes`] keeps them sealed with an
//! AEAD under a random per-buffer key and only opens them on demand, zeroizing
//! both key and plaintext scratch space on drop.

use crate::error::{EvasionError, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// A byte buffer stored encrypted in memory.
pub struct MaskedBytes {
    key: Zeroizing<[u8; 32]>,
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
    plaintext_len: usize,
    cleared: bool,
}

impl MaskedBytes {
    /// Seals `plaintext` under a fresh random key.
    pub fn new(plaintext: &[u8]) -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(key.as_mut());
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).expect("32-byte key");
        let ciphertext = if plaintext.is_empty() {
            Vec::new()
        } else {
            cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: plaintext,
                        aad: &[],
                    },
                )
                .unwrap_or_default()
        };
        Self {
            key,
            nonce,
            ciphertext,
            plaintext_len: plaintext.len(),
            cleared: false,
        }
    }

    /// Decrypts the buffer into zeroizing scratch space.
    pub fn open(&self) -> Result<Zeroizing<Vec<u8>>> {
        if self.cleared {
            return Err(EvasionError::Cipher);
        }
        if self.plaintext_len == 0 {
            return Ok(Zeroizing::new(Vec::new()));
        }
        let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| EvasionError::InvalidKey("mask key".into()))?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &[],
                },
            )
            .map_err(|_| EvasionError::Cipher)?;
        Ok(Zeroizing::new(plaintext))
    }

    /// Re-seals the buffer with a new key and nonce.
    pub fn replace(&mut self, plaintext: &[u8]) {
        *self = Self::new(plaintext);
    }

    /// Overwrites the ciphertext with zeros and drops the key.
    pub fn clear(&mut self) {
        self.ciphertext.zeroize();
        self.key.zeroize();
        self.plaintext_len = 0;
        self.cleared = true;
    }

    pub fn is_empty(&self) -> bool {
        self.plaintext_len == 0 && !self.cleared
    }

    pub fn plaintext_len(&self) -> usize {
        self.plaintext_len
    }

    pub fn sealed_len(&self) -> usize {
        self.ciphertext.len()
    }
}

impl Drop for MaskedBytes {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let masked = MaskedBytes::new(b"top secret output");
        assert_eq!(masked.open().unwrap().as_slice(), b"top secret output");
    }

    #[test]
    fn ciphertext_is_not_plaintext() {
        let masked = MaskedBytes::new(b"top secret output");
        assert_ne!(&masked.ciphertext, b"top secret output");
        assert!(masked.sealed_len() >= "top secret output".len() + TAG_LEN);
    }

    #[test]
    fn replace_reseals() {
        let mut masked = MaskedBytes::new(b"first");
        let first = masked.ciphertext.clone();
        masked.replace(b"second");
        assert_ne!(masked.ciphertext, first);
        assert_eq!(masked.open().unwrap().as_slice(), b"second");
    }

    #[test]
    fn clear_erases_material() {
        let mut masked = MaskedBytes::new(b"secret");
        masked.clear();
        assert_eq!(masked.sealed_len(), 0);
        assert!(masked.open().is_err());
    }

    #[test]
    fn empty_roundtrips() {
        let masked = MaskedBytes::new(b"");
        assert_eq!(masked.open().unwrap().as_slice(), b"");
    }
}
