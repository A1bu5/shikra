//! WireGuard beacon transport.
//!
//! A userspace WireGuard endpoint built on `boringtun` with no TUN device.
//! Application frames (`[u8 opcode][protobuf]`) travel inside minimal IPv4/UDP
//! packets that are encrypted by the tunnel and unwrapped on the far side.
//!
//! Peers are learned from anonymous handshake initiations, so no key
//! pre-registration is required; authorization happens at the enrollment
//! layer through the token and agent identity signature.

use crate::state::ServerState;
use anyhow::{Context, Result};
use shikra_transport::wg::{self, WgIncoming, WgTunnel};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const TIMER_TICK: Duration = Duration::from_secs(1);
const PEER_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

struct Peer {
    tunnel: WgTunnel,
    addr: SocketAddr,
    last_seen: Instant,
}

/// Serves WireGuard beacon traffic until the process exits.
pub async fn serve(socket: UdpSocket, state: Arc<ServerState>, state_dir: PathBuf) -> Result<()> {
    let (server_private, server_public) =
        wg::load_or_create_server_identity(&state_dir).context("failed to load WireGuard key")?;
    let mut peers: HashMap<[u8; 32], Peer> = HashMap::new();
    let mut by_index: HashMap<u32, [u8; 32]> = HashMap::new();
    let mut next_index: u32 = 1;
    let mut buf = vec![0u8; wg::MAX_WG_PACKET];
    let mut ticker = tokio::time::interval(TIMER_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    tracing::info!(
        addr = %socket.local_addr()?,
        public_key = %shikra_transport::tls::hex_encode(server_public.as_bytes()),
        "WireGuard beacon listener ready"
    );

    loop {
        tokio::select! {
            received = socket.recv_from(&mut buf) => {
                let (len, addr) = received.context("wireguard recv failed")?;
                let datagram = &buf[..len];
                let key = match wg::classify_incoming(&server_private, &server_public, datagram) {
                    WgIncoming::HandshakeInit { peer_static_public, .. } => peer_static_public,
                    WgIncoming::Routed { receiver_idx } => {
                        match by_index.get(&(receiver_idx >> 8)) {
                            Some(key) => *key,
                            None => continue,
                        }
                    }
                    WgIncoming::Invalid => continue,
                };

                if let std::collections::hash_map::Entry::Vacant(slot) = peers.entry(key) {
                    let index = next_index;
                    next_index = next_index.wrapping_add(1).max(1);
                    let tunnel = WgTunnel::new(
                        server_private.clone(),
                        wg::WgPublicKey::from(key),
                        index,
                        Some(25),
                    );
                    by_index.insert(index, key);
                    slot.insert(Peer {
                        tunnel,
                        addr,
                        last_seen: Instant::now(),
                    });
                    tracing::info!(peer = %shikra_transport::tls::hex_encode(&key), "wireguard peer registered");
                }
                let peer = peers.get_mut(&key).expect("peer inserted above");
                peer.addr = addr;
                peer.last_seen = Instant::now();
                let outcome = peer.tunnel.decapsulate(addr.ip(), datagram);
                for packet in &outcome.outbound {
                    let _ = socket.send_to(packet, peer.addr).await;
                }
                for payload in &outcome.payloads {
                    let response = crate::enrollment::process_transport_frame(
                        &state,
                        &addr.to_string(),
                        payload,
                    )
                    .await;
                    if response.is_empty() {
                        continue;
                    }
                    let outcome = peer.tunnel.encapsulate(&response);
                    for packet in &outcome.outbound {
                        let _ = socket.send_to(packet, peer.addr).await;
                    }
                }
            }
            _ = ticker.tick() => {
                let now = Instant::now();
                let mut idle: Vec<[u8; 32]> = Vec::new();
                for (key, peer) in peers.iter_mut() {
                    // Only drive timers for peers with recent traffic. Driving
                    // an expired tunnel makes boringtun initiate its own
                    // handshakes, which collides with the client's retries and
                    // stalls recovery; the client owns rekeying.
                    if now.duration_since(peer.last_seen) <= Duration::from_secs(60) {
                        let outcome = peer.tunnel.update_timers();
                        for packet in &outcome.outbound {
                            let _ = socket.send_to(packet, peer.addr).await;
                        }
                    }
                    if now.duration_since(peer.last_seen) > PEER_IDLE_TIMEOUT {
                        idle.push(*key);
                    }
                }
                for key in idle {
                    peers.remove(&key);
                    by_index.retain(|_, public| *public != key);
                }
            }
        }
    }
}
