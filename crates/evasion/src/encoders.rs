//! Symmetric payload encoders.
//!
//! Wire format for every encoder: `[u8 version][u8 kind][payload...]` so the
//! decoder can be selected from the first byte by a minimal stub. Keys and
//! nonces travel separately (operator config), never inside the encoded blob.

use crate::error::{EvasionError, Result};
use aes::cipher::{KeyIvInit, StreamCipher};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;
type ChaCha = chacha20::ChaCha20;

const FORMAT_VERSION: u8 = 1;
const KIND_XOR: u8 = 1;
const KIND_AES256_CTR: u8 = 2;
const KIND_CHACHA20: u8 = 3;

pub const AES_KEY_LEN: usize = 32;
pub const AES_NONCE_LEN: usize = 16;
pub const CHACHA_KEY_LEN: usize = 32;
pub const CHACHA_NONCE_LEN: usize = 12;
pub const MAX_XOR_KEY_LEN: usize = 64;

/// Encoder selection plus key material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EncoderSpec {
    /// Repeating-key XOR. `key` is 1..=64 bytes.
    Xor { key: Vec<u8> },
    /// AES-256 in big-endian counter mode.
    Aes256Ctr { key: Vec<u8>, nonce: Vec<u8> },
    /// ChaCha20 with a 96-bit nonce.
    ChaCha20 { key: Vec<u8>, nonce: Vec<u8> },
}

/// A validated encoder ready to transform payloads.
pub struct Encoder {
    kind: u8,
    key: Zeroizing<Vec<u8>>,
    nonce: Vec<u8>,
}

impl Encoder {
    pub fn new(spec: &EncoderSpec) -> Result<Self> {
        match spec {
            EncoderSpec::Xor { key } => {
                if key.is_empty() || key.len() > MAX_XOR_KEY_LEN {
                    return Err(EvasionError::InvalidKey(format!(
                        "XOR key must be 1..={MAX_XOR_KEY_LEN} bytes, got {}",
                        key.len()
                    )));
                }
                Ok(Self {
                    kind: KIND_XOR,
                    key: Zeroizing::new(key.clone()),
                    nonce: Vec::new(),
                })
            }
            EncoderSpec::Aes256Ctr { key, nonce } => {
                if key.len() != AES_KEY_LEN {
                    return Err(EvasionError::InvalidKey(format!(
                        "AES key must be {AES_KEY_LEN} bytes, got {}",
                        key.len()
                    )));
                }
                if nonce.len() != AES_NONCE_LEN {
                    return Err(EvasionError::InvalidKey(format!(
                        "AES nonce must be {AES_NONCE_LEN} bytes, got {}",
                        nonce.len()
                    )));
                }
                Ok(Self {
                    kind: KIND_AES256_CTR,
                    key: Zeroizing::new(key.clone()),
                    nonce: nonce.clone(),
                })
            }
            EncoderSpec::ChaCha20 { key, nonce } => {
                if key.len() != CHACHA_KEY_LEN {
                    return Err(EvasionError::InvalidKey(format!(
                        "ChaCha20 key must be {CHACHA_KEY_LEN} bytes, got {}",
                        key.len()
                    )));
                }
                if nonce.len() != CHACHA_NONCE_LEN {
                    return Err(EvasionError::InvalidKey(format!(
                        "ChaCha20 nonce must be {CHACHA_NONCE_LEN} bytes, got {}",
                        nonce.len()
                    )));
                }
                Ok(Self {
                    kind: KIND_CHACHA20,
                    key: Zeroizing::new(key.clone()),
                    nonce: nonce.clone(),
                })
            }
        }
    }

    /// Generates a fresh random spec for `kind` ("xor", "aes256_ctr", "chacha20").
    pub fn random(kind: &str) -> Result<EncoderSpec> {
        let mut rng = rand::rngs::OsRng;
        match kind {
            "xor" => {
                let len = 8 + (rng.next_u32() as usize % 24);
                let mut key = vec![0u8; len];
                rng.fill_bytes(&mut key);
                Ok(EncoderSpec::Xor { key })
            }
            "aes256_ctr" | "aes" => {
                let mut key = vec![0u8; AES_KEY_LEN];
                let mut nonce = vec![0u8; AES_NONCE_LEN];
                rng.fill_bytes(&mut key);
                rng.fill_bytes(&mut nonce);
                Ok(EncoderSpec::Aes256Ctr { key, nonce })
            }
            "chacha20" | "chacha" => {
                let mut key = vec![0u8; CHACHA_KEY_LEN];
                let mut nonce = vec![0u8; CHACHA_NONCE_LEN];
                rng.fill_bytes(&mut key);
                rng.fill_bytes(&mut nonce);
                Ok(EncoderSpec::ChaCha20 { key, nonce })
            }
            other => Err(EvasionError::InvalidKey(format!(
                "unknown encoder kind {other:?}"
            ))),
        }
    }

    /// Encodes a payload into `[version][kind][ciphertext]`.
    pub fn encode(&self, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(payload.len() + 2);
        out.push(FORMAT_VERSION);
        out.push(self.kind);
        self.transform(payload, &mut out, true);
        out
    }

    /// Reverses [`Encoder::encode`].
    pub fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        if encoded.len() < 2 {
            return Err(EvasionError::Truncated(encoded.len()));
        }
        if encoded[0] != FORMAT_VERSION {
            return Err(EvasionError::Cipher);
        }
        if encoded[1] != self.kind {
            return Err(EvasionError::Cipher);
        }
        let mut out = Vec::with_capacity(encoded.len() - 2);
        self.transform(&encoded[2..], &mut out, false);
        Ok(out)
    }

    fn transform(&self, input: &[u8], out: &mut Vec<u8>, out_has_header: bool) {
        debug_assert_eq!(out_has_header, out.len() >= 2);
        match self.kind {
            KIND_XOR => {
                let key = &self.key[..];
                out.extend(
                    input
                        .iter()
                        .enumerate()
                        .map(|(index, byte)| byte ^ key[index % key.len()]),
                );
            }
            KIND_AES256_CTR => {
                let mut cipher = Aes256Ctr::new_from_slices(&self.key, &self.nonce)
                    .expect("validated key and nonce lengths");
                let mut buffer = input.to_vec();
                cipher.apply_keystream(&mut buffer);
                out.extend_from_slice(&buffer);
            }
            KIND_CHACHA20 => {
                let mut cipher = ChaCha::new_from_slices(&self.key, &self.nonce)
                    .expect("validated key and nonce lengths");
                let mut buffer = input.to_vec();
                cipher.apply_keystream(&mut buffer);
                out.extend_from_slice(&buffer);
            }
            _ => unreachable!("kind validated at construction"),
        }
    }
}

/// One-shot convenience wrapper.
pub fn encode(spec: &EncoderSpec, payload: &[u8]) -> Result<Vec<u8>> {
    Ok(Encoder::new(spec)?.encode(payload))
}

/// One-shot decode wrapper.
pub fn decode(spec: &EncoderSpec, encoded: &[u8]) -> Result<Vec<u8>> {
    Encoder::new(spec)?.decode(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xor_spec() -> EncoderSpec {
        EncoderSpec::Xor {
            key: b"shikra-key".to_vec(),
        }
    }

    fn aes_spec() -> EncoderSpec {
        EncoderSpec::Aes256Ctr {
            key: vec![0x11; AES_KEY_LEN],
            nonce: vec![0x22; AES_NONCE_LEN],
        }
    }

    fn chacha_spec() -> EncoderSpec {
        EncoderSpec::ChaCha20 {
            key: vec![0x33; CHACHA_KEY_LEN],
            nonce: vec![0x44; CHACHA_NONCE_LEN],
        }
    }

    #[test]
    fn xor_roundtrip() {
        let payload = b"the quick brown fox jumps over the lazy dog";
        let encoded = encode(&xor_spec(), payload).unwrap();
        assert_eq!(encoded[0], FORMAT_VERSION);
        assert_eq!(encoded[1], KIND_XOR);
        assert_ne!(&encoded[2..], payload);
        assert_eq!(decode(&xor_spec(), &encoded).unwrap(), payload);
    }

    #[test]
    fn aes_roundtrip() {
        let payload: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let encoded = encode(&aes_spec(), &payload).unwrap();
        assert_eq!(encoded[1], KIND_AES256_CTR);
        assert_ne!(&encoded[2..], payload.as_slice());
        assert_eq!(decode(&aes_spec(), &encoded).unwrap(), payload);
    }

    #[test]
    fn chacha_roundtrip() {
        let payload: Vec<u8> = (0..4096).map(|i| (i % 253) as u8).collect();
        let encoded = encode(&chacha_spec(), &payload).unwrap();
        assert_eq!(encoded[1], KIND_CHACHA20);
        assert_eq!(decode(&chacha_spec(), &encoded).unwrap(), payload);
    }

    #[test]
    fn empty_payload_roundtrips() {
        for spec in [xor_spec(), aes_spec(), chacha_spec()] {
            let encoded = encode(&spec, &[]).unwrap();
            assert_eq!(decode(&spec, &encoded).unwrap(), Vec::<u8>::new());
        }
    }

    #[test]
    fn wrong_key_fails_or_differs() {
        let payload = b"secret payload";
        let encoded = encode(&xor_spec(), payload).unwrap();
        let wrong = EncoderSpec::Xor {
            key: b"other-key".to_vec(),
        };
        assert_ne!(decode(&wrong, &encoded).unwrap(), payload);
    }

    #[test]
    fn wrong_encoder_kind_is_rejected() {
        let encoded = encode(&xor_spec(), b"data").unwrap();
        let err = decode(&chacha_spec(), &encoded).unwrap_err();
        assert!(matches!(err, EvasionError::Cipher));
    }

    #[test]
    fn truncated_input_is_rejected() {
        assert!(matches!(
            decode(&xor_spec(), &[FORMAT_VERSION]),
            Err(EvasionError::Truncated(1))
        ));
    }

    #[test]
    fn key_lengths_are_validated() {
        assert!(Encoder::new(&EncoderSpec::Xor { key: Vec::new() }).is_err());
        assert!(Encoder::new(&EncoderSpec::Xor {
            key: vec![0u8; MAX_XOR_KEY_LEN + 1]
        })
        .is_err());
        assert!(Encoder::new(&EncoderSpec::Aes256Ctr {
            key: vec![0u8; 16],
            nonce: vec![0u8; AES_NONCE_LEN]
        })
        .is_err());
        assert!(Encoder::new(&EncoderSpec::ChaCha20 {
            key: vec![0u8; CHACHA_KEY_LEN],
            nonce: vec![0u8; 8]
        })
        .is_err());
    }

    #[test]
    fn spec_json_roundtrip() {
        let spec = aes_spec();
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains("aes256_ctr"));
        let parsed: EncoderSpec = serde_json::from_str(&json).unwrap();
        let payload = b"json roundtrip";
        assert_eq!(
            decode(&parsed, &encode(&spec, payload).unwrap()).unwrap(),
            payload
        );
    }

    #[test]
    fn random_specs_roundtrip() {
        for kind in ["xor", "aes256_ctr", "chacha20"] {
            let spec = Encoder::random(kind).unwrap();
            let payload = b"random spec payload";
            assert_eq!(
                decode(&spec, &encode(&spec, payload).unwrap()).unwrap(),
                payload
            );
        }
        assert!(Encoder::random("rot13").is_err());
    }
}
