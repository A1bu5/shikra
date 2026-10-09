use crate::error::{CryptoError, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AeadKey([u8; KEY_LEN]);

impl AeadKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.0))
    }

    pub fn seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.cipher()
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|err| CryptoError::Encrypt(err.to_string()))
    }

    pub fn open(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.cipher()
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)
    }
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = AeadKey::generate();
        let nonce = random_nonce();
        let aad = b"shikra-envelope";
        let plaintext = b"authorized testing only";

        let sealed = key.seal(&nonce, aad, plaintext).expect("seal");
        assert_ne!(sealed.as_slice(), plaintext.as_slice());

        let opened = key.open(&nonce, aad, &sealed).expect("open");
        assert_eq!(opened.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn open_fails_on_wrong_aad() {
        let key = AeadKey::generate();
        let nonce = random_nonce();
        let sealed = key.seal(&nonce, b"aad-a", b"secret").expect("seal");
        assert!(key.open(&nonce, b"aad-b", &sealed).is_err());
    }

    #[test]
    fn open_fails_on_tampered_ciphertext() {
        let key = AeadKey::generate();
        let nonce = random_nonce();
        let mut sealed = key.seal(&nonce, b"aad", b"secret").expect("seal");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(key.open(&nonce, b"aad", &sealed).is_err());
    }
}
