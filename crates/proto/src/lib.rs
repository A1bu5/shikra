#![allow(clippy::all)]

pub mod convert;

pub mod v1 {
    tonic::include_proto!("shikra.v1");

    pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("shikra_descriptor");
}

pub use v1::*;
