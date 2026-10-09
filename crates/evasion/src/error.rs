use thiserror::Error;

#[derive(Debug, Error)]
pub enum EvasionError {
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("payload is too short: {0} bytes")]
    Truncated(usize),
    #[error("cipher operation failed")]
    Cipher,
}

pub type Result<T> = std::result::Result<T, EvasionError>;
