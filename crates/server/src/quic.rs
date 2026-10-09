//! QUIC beacon transport.
//!
//! Wire format on each bidirectional stream: `[u8 opcode][u32 le length][payload]`.
//! - opcode `1` = enroll (payload = `CheckInRequest`, response = `CheckInResponse`)
//! - opcode `2` = poll   (payload = `Envelope`, response = `Envelope`)

use crate::state::ServerState;
use anyhow::{Context, Result};
use prost::Message;
use quinn::{Endpoint, ServerConfig};
use shikra_proto::v1::{CheckInRequest, CheckInResponse, Envelope};
use std::sync::Arc;

pub const OP_ENROLL: u8 = 1;
pub const OP_POLL: u8 = 2;
pub const MAX_FRAME: usize = 8 * 1024 * 1024;

/// Builds a QUIC server endpoint reusing the teamserver TLS material.
pub fn server_endpoint(
    cert_pem: &str,
    key_pem: &str,
    addr: std::net::SocketAddr,
) -> Result<Endpoint> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to parse server certificate")?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .context("failed to parse server key")?
        .context("server key is empty")?;
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to build rustls server config")?;
    tls.alpn_protocols = vec![b"shikra".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .context("failed to build QUIC crypto config")?;
    let config = ServerConfig::with_crypto(Arc::new(crypto));
    Endpoint::server(config, addr).context("failed to bind QUIC endpoint")
}

/// Serves QUIC beacon traffic until the endpoint is closed.
pub async fn serve(endpoint: Endpoint, state: Arc<ServerState>) {
    while let Some(incoming) = endpoint.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            let connection = match incoming.await {
                Ok(connection) => connection,
                Err(err) => {
                    tracing::debug!(%err, "QUIC handshake failed");
                    return;
                }
            };
            handle_connection(connection, state).await;
        });
    }
}

async fn handle_connection(connection: quinn::Connection, state: Arc<ServerState>) {
    loop {
        let (mut send, mut recv) = match connection.accept_bi().await {
            Ok(stream) => stream,
            Err(_) => return,
        };
        let state = state.clone();
        tokio::spawn(async move {
            let request = match recv.read_to_end(MAX_FRAME).await {
                Ok(bytes) => bytes,
                Err(_) => return,
            };
            let response = process_frame(&state, &request).await;
            if let Some(response) = response {
                let _ = send.write_all(&response).await;
            }
            let _ = send.finish();
        });
    }
}

/// Processes a QUIC request frame, returning the raw response body.
pub async fn process_frame(state: &Arc<ServerState>, frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() < 5 {
        return None;
    }
    let opcode = frame[0];
    let length = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
    let payload = frame.get(5..5 + length)?;

    match opcode {
        OP_ENROLL => {
            let request = CheckInRequest::decode(payload).ok()?;
            match crate::enrollment::enroll(state, request, String::new()).await {
                Ok(response) => Some(response.encode_to_vec()),
                Err(status) => {
                    let error = CheckInResponse {
                        session_id: format!("error:{}", status.message()),
                        ..Default::default()
                    };
                    Some(error.encode_to_vec())
                }
            }
        }
        OP_POLL => {
            let request = Envelope::decode(payload).ok()?;
            crate::enrollment::handle_beacon_poll(state, &request.encode_to_vec())
                .await
                .ok()
        }
        _ => None,
    }
}

/// Encodes a response frame (length-prefixed body).
pub fn encode_frame(body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(body);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let body = b"hello-quic";
        let frame = encode_frame(body);
        assert_eq!(&frame[..4], &(body.len() as u32).to_le_bytes());
        assert_eq!(&frame[4..], body);
    }

    #[tokio::test]
    async fn rejects_short_frames() {
        let state = test_state();
        assert!(process_frame(&state, &[1, 2, 3]).await.is_none());
    }

    #[tokio::test]
    async fn rejects_unknown_opcode() {
        let state = test_state();
        let mut frame = vec![99u8];
        frame.extend_from_slice(&0u32.to_le_bytes());
        assert!(process_frame(&state, &frame).await.is_none());
    }

    fn test_state() -> Arc<ServerState> {
        Arc::new(ServerState {
            pool: sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://placeholder")
                .expect("lazy pool"),
            identity: Arc::new(shikra_crypto::signing::Identity::generate()),
            enroll_token: Arc::new("enroll".into()),
            operator_token: Arc::new("operator".into()),
            engagement_id: uuid::Uuid::nil(),
            sessions: Arc::new(crate::state::SessionRegistry::new()),
            tunnels: Arc::new(crate::tunnel::TunnelHub::new()),
            forwards: Arc::new(crate::tunnel::ForwardRegistry::new()),
            operators: Arc::new(crate::state::OperatorRegistry::new()),
            hosting_dir: Arc::new(std::path::PathBuf::from("/tmp")),
            armory_public: [0u8; 32],
            enroll_limiter: Arc::new(crate::rate_limit::AttemptLimiter::new(
                30,
                std::time::Duration::from_secs(60),
            )),
            profiles: Arc::new(tokio::sync::RwLock::new(
                shikra_transport::profile::ProfileSet::default(),
            )),
            state_dir: Arc::new(std::path::PathBuf::from("/tmp")),
            listeners: Arc::new(crate::listeners::ListenerRegistry::new()),
            webhook: Arc::new(tokio::sync::RwLock::new(None)),
            relay_token: Arc::new("relay".into()),
            external_tokens: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        })
    }
}
