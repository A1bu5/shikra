use crate::error::{CryptoError, Result};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| CryptoError::PasswordHash(err.to_string()))
}

pub fn verify_password(password: &str, encoded_hash: &str) -> Result<()> {
    let parsed = PasswordHash::new(encoded_hash)
        .map_err(|err| CryptoError::PasswordHash(err.to_string()))?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| CryptoError::PasswordVerify)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let hash = hash_password("correct horse battery staple").expect("hash");
        verify_password("correct horse battery staple", &hash).expect("verify");
        assert!(verify_password("wrong", &hash).is_err());
    }
}
