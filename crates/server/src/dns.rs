//! DNS beacon transport.
//!
//! Each request is a TXT query whose name carries a base32 payload chunk:
//! `<txid>.<seq>.<total>.<data labels...>.<zone>`. The server reassembles
//! chunks per client address, processes the frame once complete and returns
//! the response as base32 TXT answer strings (empty answer = chunk ACK).

use crate::state::ServerState;
use anyhow::{anyhow, Result};
use shikra_transport::dns;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const TRANSFER_TTL: Duration = Duration::from_secs(120);
const MAX_CHUNKS: u32 = 4096;

struct Transfer {
    total: u32,
    chunks: Vec<Option<Vec<u8>>>,
    created: Instant,
    response: Option<Vec<u8>>,
}

/// Serves DNS beacon traffic on `socket` until the process exits.
pub async fn serve(socket: UdpSocket, state: Arc<ServerState>, zone: String) {
    let zone_labels: Vec<String> = zone
        .split('.')
        .filter(|label| !label.is_empty())
        .map(str::to_string)
        .collect();
    let mut transfers: HashMap<(SocketAddr, u32), Transfer> = HashMap::new();
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(err) => {
                tracing::warn!(%err, "dns recv failed");
                continue;
            }
        };
        prune_expired(&mut transfers);
        let response =
            match handle_query(&state, &mut transfers, &zone_labels, peer, &buf[..len]).await {
                Ok(response) => response,
                Err(err) => {
                    tracing::debug!(%err, %peer, "dns query rejected");
                    continue;
                }
            };
        if !response.is_empty() {
            if let Err(err) = socket.send_to(&response, peer).await {
                tracing::warn!(%err, %peer, "dns send failed");
            }
        }
    }
}

fn prune_expired(transfers: &mut HashMap<(SocketAddr, u32), Transfer>) {
    let now = Instant::now();
    transfers.retain(|_, transfer| now.duration_since(transfer.created) < TRANSFER_TTL);
}

async fn handle_query(
    state: &Arc<ServerState>,
    transfers: &mut HashMap<(SocketAddr, u32), Transfer>,
    zone_labels: &[String],
    peer: SocketAddr,
    packet: &[u8],
) -> Result<Vec<u8>> {
    let (id, qname) = dns::decode_query(packet)?;
    let mut labels: Vec<String> = qname
        .split('.')
        .filter(|label| !label.is_empty())
        .map(str::to_string)
        .collect();
    if !zone_labels.is_empty() && labels.ends_with(zone_labels) {
        labels.truncate(labels.len() - zone_labels.len());
    }
    if labels.len() < 4 {
        return Err(anyhow!("dns: request name is missing chunk metadata"));
    }
    let txid =
        u32::from_str_radix(&labels[0], 16).map_err(|_| anyhow!("dns: invalid transfer id"))?;
    let seq: u32 = labels[1]
        .parse()
        .map_err(|_| anyhow!("dns: invalid sequence number"))?;
    let total: u32 = labels[2]
        .parse()
        .map_err(|_| anyhow!("dns: invalid chunk count"))?;
    if total == 0 || total > MAX_CHUNKS || seq >= total {
        return Err(anyhow!("dns: invalid chunk metadata"));
    }
    let chunk = dns::labels_to_payload(&labels[3..])?;

    let key = (peer, txid);
    let transfer = transfers.entry(key).or_insert_with(|| Transfer {
        total,
        chunks: vec![None; total as usize],
        created: Instant::now(),
        response: None,
    });
    if transfer.total != total {
        *transfer = Transfer {
            total,
            chunks: vec![None; total as usize],
            created: Instant::now(),
            response: None,
        };
    }

    if transfer.response.is_none() {
        transfer.chunks[seq as usize] = Some(chunk);
        if transfer.chunks.iter().all(Option::is_some) {
            let mut frame = Vec::new();
            for part in &transfer.chunks {
                frame.extend_from_slice(part.as_deref().unwrap_or_default());
            }
            transfer.response = Some(
                crate::enrollment::process_transport_frame(state, &peer.to_string(), &frame).await,
            );
        }
    }

    match &transfer.response {
        Some(body) => Ok(dns::encode_response(id, &qname, body)?),
        None => Ok(dns::encode_response(id, &qname, &[])?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_pruning_removes_expired_entries() {
        let mut transfers = HashMap::new();
        transfers.insert(
            ("127.0.0.1:1".parse().unwrap(), 7u32),
            Transfer {
                total: 1,
                chunks: vec![None],
                created: Instant::now() - TRANSFER_TTL - Duration::from_secs(1),
                response: None,
            },
        );
        prune_expired(&mut transfers);
        assert!(transfers.is_empty());
    }
}
