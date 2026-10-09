use crate::error::{CryptoError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SECRET_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_seed(seed: &[u8; SECRET_KEY_LEN]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
        }
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn secret_key_bytes(&self) -> [u8; SECRET_KEY_LEN] {
        self.signing_key.to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
}

pub fn verify(public_key: &[u8; PUBLIC_KEY_LEN], message: &[u8], signature: &[u8]) -> Result<()> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidKey)?;
    let signature_bytes: &[u8; SIGNATURE_LEN] =
        signature.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let signature = Signature::from_bytes(signature_bytes);
    verifying_key
        .verify(message, &signature)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let identity = Identity::generate();
        let public = identity.public_key_bytes();
        let message = b"beacon-check-in";
        let signature = identity.sign(message);

        verify(&public, message, &signature.to_bytes()).expect("valid signature");
        assert!(verify(&public, b"tampered", &signature.to_bytes()).is_err());
    }

    #[test]
    fn seed_is_deterministic() {
        let seed = [7u8; SECRET_KEY_LEN];
        let a = Identity::from_seed(&seed);
        let b = Identity::from_seed(&seed);
        assert_eq!(a.public_key_bytes(), b.public_key_bytes());
    }
}
