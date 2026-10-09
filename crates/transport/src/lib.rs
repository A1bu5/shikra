pub mod dns;
pub mod extension;
pub mod profile;
pub mod tls;
pub mod wg;
pub mod wire;

use serde::{Deserialize, Serialize};
use shikra_core::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    Mtls,
    Https,
    Dns,
    WireGuard,
    Quic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerSpec {
    pub name: String,
    pub kind: TransportKind,
    pub bind_addr: String,
    pub config: serde_json::Value,
}

pub trait Listener: Send + Sync {
    fn spec(&self) -> &ListenerSpec;
    fn start(&self) -> Result<()>;
    fn stop(&self) -> Result<()>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeHeader {
    pub version: u16,
    pub session_id: String,
    pub sequence: u64,
    pub nonce: [u8; 12],
}
