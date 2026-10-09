use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid key material")]
    InvalidKey,
    #[error("invalid nonce")]
    InvalidNonce,
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("replay or out-of-order frame rejected")]
    Replay,
    #[error("encryption failed: {0}")]
    Encrypt(String),
    #[error("hkdf expansion failed: {0}")]
    Hkdf(String),
    #[error("password hashing failed: {0}")]
    PasswordHash(String),
    #[error("password verification failed")]
    PasswordVerify,
}

pub type Result<T> = std::result::Result<T, CryptoError>;
