//! Userspace WireGuard transport built on `boringtun`.
//!
//! No TUN device is required: application payloads are wrapped in minimal
//! IPv4/UDP headers and handed to boringtun as opaque IP packets. The peer
//! then strips the headers again after decryption.

use anyhow::{Context, Result};
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::net::IpAddr;
use std::path::Path;

pub use boringtun::x25519::{PublicKey as WgPublicKey, StaticSecret as WgStaticSecret};

const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const WG_SRC_V4: [u8; 4] = [10, 66, 0, 2];
const WG_DST_V4: [u8; 4] = [10, 66, 0, 1];
const WG_SRC_PORT: u16 = 40000;
const WG_DST_PORT: u16 = 40001;

/// Largest UDP datagram accepted from or produced for the network.
pub const MAX_WG_PACKET: usize = 65_535;

/// Wraps an application payload in a minimal IPv4 + UDP packet.
pub fn wrap_payload(payload: &[u8]) -> Vec<u8> {
    let total = IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len();
    let mut packet = vec![0u8; total];
    packet[0] = 0x45; // IPv4, IHL 5
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[8] = 64; // TTL
    packet[9] = 17; // UDP
    packet[12..16].copy_from_slice(&WG_SRC_V4);
    packet[16..20].copy_from_slice(&WG_DST_V4);
    packet[20..22].copy_from_slice(&WG_SRC_PORT.to_be_bytes());
    packet[22..24].copy_from_slice(&WG_DST_PORT.to_be_bytes());
    packet[24..26].copy_from_slice(&((UDP_HEADER_LEN + payload.len()) as u16).to_be_bytes());
    packet[IPV4_HEADER_LEN + UDP_HEADER_LEN..].copy_from_slice(payload);
    packet
}

/// Strips the IPv4 + UDP headers from a decapsulated packet.
pub fn unwrap_payload(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < IPV4_HEADER_LEN + UDP_HEADER_LEN || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0F) * 4;
    if ihl < IPV4_HEADER_LEN || packet.len() < ihl + UDP_HEADER_LEN || packet[9] != 17 {
        return None;
    }
    Some(&packet[ihl + UDP_HEADER_LEN..])
}

/// Generates a fresh static keypair for a WireGuard peer.
pub fn generate_static_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Classification of an inbound WireGuard datagram on the server side.
#[derive(Debug, Clone, Copy)]
pub enum WgIncoming {
    /// Anonymous handshake init carrying the initiator's static public key.
    HandshakeInit {
        peer_index: u32,
        peer_static_public: [u8; 32],
    },
    /// A packet that must be routed to an existing peer by session index.
    Routed { receiver_idx: u32 },
    /// Malformed or unsupported packet.
    Invalid,
}

/// Inspects an inbound datagram without decrypting its payload.
///
/// Handshake initiations are parsed anonymously with the server static key to
/// learn the initiator's static public key; every other packet type is routed
/// by `receiver_idx`, the same scheme boringtun's device uses.
pub fn classify_incoming(
    server_private: &StaticSecret,
    server_public: &PublicKey,
    datagram: &[u8],
) -> WgIncoming {
    match Tunn::parse_incoming_packet(datagram) {
        Ok(Packet::HandshakeInit(init)) => {
            match parse_handshake_anon(server_private, server_public, &init) {
                Ok(half) => WgIncoming::HandshakeInit {
                    peer_index: half.peer_index,
                    peer_static_public: half.peer_static_public,
                },
                Err(_) => WgIncoming::Invalid,
            }
        }
        Ok(Packet::HandshakeResponse(p)) => WgIncoming::Routed {
            receiver_idx: p.receiver_idx,
        },
        Ok(Packet::PacketCookieReply(p)) => WgIncoming::Routed {
            receiver_idx: p.receiver_idx,
        },
        Ok(Packet::PacketData(p)) => WgIncoming::Routed {
            receiver_idx: p.receiver_idx,
        },
        Err(_) => WgIncoming::Invalid,
    }
}

/// Loads (or creates and persists) the server static keypair.
pub fn load_or_create_server_identity(state_dir: &Path) -> Result<(StaticSecret, PublicKey)> {
    let key_path = state_dir.join("wg-server.key");
    let public_path = state_dir.join("wg-server.pub");
    let secret = if key_path.exists() {
        let hex_seed = crate::tls::read_text_file(&key_path)?;
        let bytes = crate::tls::hex_decode(&hex_seed)?;
        let seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .context("WireGuard key must be 32 bytes")?;
        StaticSecret::from(seed)
    } else {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        crate::tls::write_secret_file(
            &key_path,
            crate::tls::hex_encode(&secret.to_bytes()).as_bytes(),
        )?;
        secret
    };
    let public = PublicKey::from(&secret);
    if !public_path.exists() {
        std::fs::write(
            &public_path,
            crate::tls::hex_encode(public.as_bytes()).as_bytes(),
        )?;
    }
    Ok((secret, public))
}

/// Network datagrams and decrypted payloads produced by a tunnel operation.
#[derive(Debug, Default)]
pub struct WgOutcome {
    pub outbound: Vec<Vec<u8>>,
    pub payloads: Vec<Vec<u8>>,
}

impl WgOutcome {
    pub fn is_empty(&self) -> bool {
        self.outbound.is_empty() && self.payloads.is_empty()
    }
}

/// A point-to-point WireGuard tunnel driven manually over any datagram socket.
pub struct WgTunnel {
    tunn: Tunn,
}

impl WgTunnel {
    pub fn new(
        static_private: StaticSecret,
        peer_public: PublicKey,
        index: u32,
        keepalive_secs: Option<u16>,
    ) -> Self {
        Self {
            tunn: Tunn::new(
                static_private,
                peer_public,
                None,
                keepalive_secs,
                index,
                None,
            ),
        }
    }

    /// Encrypts `payload`, returning datagrams to send. The payload is queued
    /// until the handshake completes when no session exists yet.
    pub fn encapsulate(&mut self, payload: &[u8]) -> WgOutcome {
        let wrapped = wrap_payload(payload);
        let mut dst = vec![0u8; wrapped.len() + 64];
        let mut outcome = WgOutcome::default();
        let result = self.tunn.encapsulate(&wrapped, &mut dst);
        Self::collect(result, &mut outcome);
        self.flush(&mut outcome);
        outcome
    }

    /// Processes one datagram received from the peer.
    pub fn decapsulate(&mut self, src: IpAddr, datagram: &[u8]) -> WgOutcome {
        let mut dst = vec![0u8; MAX_WG_PACKET + 64];
        let mut outcome = WgOutcome::default();
        let result = self.tunn.decapsulate(Some(src), datagram, &mut dst);
        Self::collect(result, &mut outcome);
        self.flush(&mut outcome);
        outcome
    }

    /// Advances protocol timers (handshake retries, keepalives, rekeys).
    pub fn update_timers(&mut self) -> WgOutcome {
        let mut dst = vec![0u8; 2048];
        let mut outcome = WgOutcome::default();
        let result = self.tunn.update_timers(&mut dst);
        Self::collect(result, &mut outcome);
        self.flush(&mut outcome);
        outcome
    }

    fn collect(result: TunnResult<'_>, outcome: &mut WgOutcome) {
        match result {
            TunnResult::Done => {}
            TunnResult::Err(err) => tracing::debug!(?err, "wireguard packet rejected"),
            TunnResult::WriteToNetwork(packet) => outcome.outbound.push(packet.to_vec()),
            TunnResult::WriteToTunnelV4(packet, _) => {
                if let Some(payload) = unwrap_payload(packet) {
                    outcome.payloads.push(payload.to_vec());
                }
            }
            TunnResult::WriteToTunnelV6(packet, _) => {
                if let Some(payload) = unwrap_payload(packet) {
                    outcome.payloads.push(payload.to_vec());
                }
            }
        }
    }

    fn flush(&mut self, outcome: &mut WgOutcome) {
        let mut dst = vec![0u8; MAX_WG_PACKET + 64];
        loop {
            match self.tunn.decapsulate(None, &[], &mut dst) {
                TunnResult::Done | TunnResult::Err(_) => break,
                other => Self::collect(other, outcome),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn loopback() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    #[test]
    fn payload_wrap_roundtrip() {
        let payload = b"shikra-wg-payload";
        let packet = wrap_payload(payload);
        assert_eq!(&packet[..2], &[0x45, 0x00]);
        assert_eq!(unwrap_payload(&packet).unwrap(), payload);
    }

    #[test]
    fn rejects_non_ipv4_packets() {
        assert!(unwrap_payload(&[0xF0, 0x00]).is_none());
        assert!(unwrap_payload(b"not-an-ip-packet-at-all").is_none());
    }

    #[test]
    fn handshake_and_payload_roundtrip() {
        let (a_secret, a_public) = generate_static_keypair();
        let (b_secret, b_public) = generate_static_keypair();
        let mut a = WgTunnel::new(a_secret, b_public, 1, None);
        let mut b = WgTunnel::new(b_secret, a_public, 2, None);

        let payload = b"hello-through-wireguard";
        let initial = a.encapsulate(payload);
        assert!(initial.payloads.is_empty());
        assert_eq!(initial.outbound.len(), 1);

        let mut b_payloads = Vec::new();
        let mut a_outbound = Vec::new();
        for pkt in &initial.outbound {
            let outcome = b.decapsulate(loopback(), pkt);
            b_payloads.extend(outcome.payloads);
            a_outbound.extend(outcome.outbound);
        }
        for pkt in &a_outbound {
            let outcome = a.decapsulate(loopback(), pkt);
            for produced in &outcome.outbound {
                let b_outcome = b.decapsulate(loopback(), produced);
                b_payloads.extend(b_outcome.payloads);
            }
        }
        assert!(
            b_payloads.iter().any(|p| p == payload),
            "peer must receive the queued payload after the handshake"
        );
    }

    #[test]
    fn session_survives_timer_updates() {
        let (a_secret, a_public) = generate_static_keypair();
        let (b_secret, b_public) = generate_static_keypair();
        let mut a = WgTunnel::new(a_secret, b_public, 10, Some(25));
        let mut b = WgTunnel::new(b_secret, a_public, 20, Some(25));

        let initial = a.encapsulate(b"first");
        let mut to_a = Vec::new();
        for pkt in &initial.outbound {
            to_a.extend(b.decapsulate(loopback(), pkt).outbound);
        }
        let mut to_b = Vec::new();
        for pkt in &to_a {
            let outcome = a.decapsulate(loopback(), pkt);
            to_b.extend(outcome.outbound);
        }
        let mut a_payloads = Vec::new();
        for pkt in &to_b {
            let outcome = b.decapsulate(loopback(), pkt);
            for reply in &outcome.outbound {
                a_payloads.extend(a.decapsulate(loopback(), reply).payloads);
            }
        }
        assert!(a_payloads.is_empty());

        let follow_up = a.encapsulate(b"second");
        let mut delivered = Vec::new();
        for pkt in &follow_up.outbound {
            delivered.extend(b.decapsulate(loopback(), pkt).payloads);
        }
        assert!(
            delivered.iter().any(|p| p == b"second"),
            "established session must deliver follow-up payloads directly"
        );
        let _ = a.update_timers();
        let _ = b.update_timers();
    }
}
