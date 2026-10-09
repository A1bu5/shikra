use crate::state::{ServerState, SessionHandle};
use prost::Message;
use shikra_crypto::channel::SessionKeys;
use shikra_crypto::kex::KeyPair;
use shikra_crypto::signing::verify;
use shikra_crypto::util::ct_eq;
use shikra_proto::v1::{
    AgentResult, AgentTask, AgentTaskBatch, CheckInRequest, CheckInResponse, Envelope, Platform,
    SessionInfo, SessionKind, SessionStatus,
};
use shikra_transport::wire;
use std::sync::Arc;
use tonic::Status;
use uuid::Uuid;

/// Shared enrollment path used by both the gRPC `AgentLink` service and the
/// HTTP(S) beacon listener. Verifies the enrollment token and agent identity,
/// derives per-session keys, registers the session and returns the signed
/// server handshake response.
pub async fn enroll(
    state: &ServerState,
    request: CheckInRequest,
    remote_addr: String,
) -> Result<CheckInResponse, Status> {
    // Slow down token guessing per peer address. Empty addresses (HTTP
    // listener without ConnectInfo) share a single bucket.
    let limiter_key = if remote_addr.is_empty() {
        "unknown".to_string()
    } else {
        remote_addr.clone()
    };
    if !state.enroll_limiter.check(&limiter_key).await {
        let _ = shikra_store::repo::insert_event(
            &state.pool,
            "enrollment_rate_limited",
            None,
            serde_json::json!({ "remote_addr": remote_addr }),
        )
        .await;
        tracing::warn!(%remote_addr, "enrollment rate limit exceeded");
        return Err(Status::resource_exhausted("too many enrollment attempts"));
    }

    if !ct_eq(
        request.enrollment_token.as_bytes(),
        state.enroll_token.as_bytes(),
    ) {
        let _ = shikra_store::repo::insert_event(
            &state.pool,
            "enrollment_rejected",
            None,
            serde_json::json!({
                "remote_addr": remote_addr,
                "reason": "invalid token",
                "hostname": request.hostname,
            }),
        )
        .await;
        return Err(Status::unauthenticated("invalid enrollment token"));
    }

    let identity_public: [u8; 32] = request
        .identity_public
        .as_slice()
        .try_into()
        .map_err(|_| Status::invalid_argument("identity_public must be 32 bytes"))?;
    let agent_kex: [u8; 32] = request
        .kex_public
        .as_slice()
        .try_into()
        .map_err(|_| Status::invalid_argument("kex_public must be 32 bytes"))?;

    if verify(
        &identity_public,
        &wire::enroll_message(&agent_kex),
        &request.identity_signature,
    )
    .is_err()
    {
        let _ = shikra_store::repo::insert_event(
            &state.pool,
            "enrollment_rejected",
            None,
            serde_json::json!({
                "remote_addr": remote_addr,
                "reason": "identity signature",
                "hostname": request.hostname,
            }),
        )
        .await;
        return Err(Status::unauthenticated("agent identity signature rejected"));
    }

    let session_id = Uuid::new_v4().to_string();
    let is_beacon = matches!(SessionKind::try_from(request.kind), Ok(SessionKind::Beacon));

    let server_kex = KeyPair::generate();
    let shared = server_kex.diffie_hellman(&agent_kex);
    let server_kex_public = server_kex.public_key();
    let signature = state.identity.sign(&wire::checkin_response_message(
        &session_id,
        &agent_kex,
        &server_kex_public,
    ));

    let keys = SessionKeys::derive(&session_id, &shared, false)
        .map_err(|_| Status::internal("session key derivation failed"))?;

    let now = time::OffsetDateTime::now_utc();
    let info = SessionInfo {
        id: session_id.clone(),
        engagement_id: state.engagement_id.to_string(),
        kind: normalize_kind(request.kind),
        status: SessionStatus::Active as i32,
        platform: normalize_platform(request.platform),
        architecture: request.architecture,
        hostname: request.hostname.clone(),
        username: request.username.clone(),
        process_name: request.process_name.clone(),
        remote_addr: remote_addr.clone(),
        first_seen: Some(wire::to_timestamp(now)),
        last_seen: Some(wire::to_timestamp(now)),
        killdate_unix: request.killdate_unix,
        working_hours: request.working_hours.clone(),
        color: String::new(),
        operator_status: String::new(),
    };

    let handle = Arc::new(SessionHandle::new(
        session_id.clone(),
        is_beacon,
        info.clone(),
        keys,
    ));
    // Persist before exposing the session so a task inserted immediately
    // after enrollment cannot violate the tasks.session_id foreign key.
    state.session_insert(&handle).await;
    state.sessions.insert(handle.clone()).await;
    crate::webhook::notify_new_session(state, &info).await;

    let _ = shikra_store::repo::insert_event(
        &state.pool,
        "session_registered",
        Some(Uuid::parse_str(&session_id).unwrap_or_else(|_| Uuid::new_v4())),
        serde_json::json!({
            "hostname": request.hostname,
            "platform": platform_str(request.platform),
            "user": request.username,
            "remote_addr": remote_addr,
            "transport": if is_beacon { "http-beacon" } else { "grpc-session" },
        }),
    )
    .await;

    state.enroll_limiter.reset(&limiter_key).await;
    tracing::info!(
        session = %session_id,
        host = %request.hostname,
        beacon = is_beacon,
        "agent checked in"
    );

    Ok(CheckInResponse {
        session_id,
        engagement_id: state.engagement_id.to_string(),
        server_kex_public: server_kex_public.to_vec(),
        server_identity_public: state.identity.public_key_bytes().to_vec(),
        server_signature: signature.to_bytes().to_vec(),
        server_time: Some(wire::to_timestamp(now)),
        heartbeat_interval_secs: if is_beacon { 0 } else { 15 },
    })
}

/// Metadata supplied by an external agent at registration.
#[derive(Debug, Clone)]
pub struct ExternalRegistration {
    pub hostname: String,
    pub username: String,
    pub platform: i32,
    pub architecture: i32,
    pub process_name: String,
}

/// Registers an external (bring-your-own) agent as a beacon-style session.
///
/// External agents are TLS-protected by the teamserver certificate but do not
/// implement the end-to-end session crypto; they authenticate every request
/// with the per-session bearer token returned here.
pub async fn register_external(
    state: &ServerState,
    registration: ExternalRegistration,
    remote_addr: String,
) -> Result<(String, String), Status> {
    let session_id = Uuid::new_v4().to_string();
    let agent_kex = shikra_crypto::kex::KeyPair::generate();
    let server_kex = shikra_crypto::kex::KeyPair::generate();
    let shared = server_kex.diffie_hellman(&agent_kex.public_key());
    let keys = shikra_crypto::channel::SessionKeys::derive(&session_id, &shared, true)
        .map_err(|_| Status::internal("session key derivation failed"))?;

    let now = time::OffsetDateTime::now_utc();
    let info = SessionInfo {
        id: session_id.clone(),
        engagement_id: state.engagement_id.to_string(),
        kind: SessionKind::External as i32,
        status: SessionStatus::Active as i32,
        platform: normalize_platform(registration.platform),
        architecture: registration.architecture,
        hostname: registration.hostname,
        username: registration.username,
        process_name: registration.process_name,
        remote_addr,
        first_seen: Some(wire::to_timestamp(now)),
        last_seen: Some(wire::to_timestamp(now)),
        killdate_unix: 0,
        working_hours: String::new(),
        color: String::new(),
        operator_status: String::new(),
    };

    let token = crate::bootstrap::new_token();
    let handle = Arc::new(SessionHandle::new(
        session_id.clone(),
        true,
        info.clone(),
        keys,
    ));
    state.session_insert(&handle).await;
    state.sessions.insert(handle).await;
    state
        .external_tokens
        .lock()
        .await
        .insert(session_id.clone(), token.clone());

    let _ = shikra_store::repo::insert_event(
        &state.pool,
        "session_registered",
        Some(Uuid::parse_str(&session_id).unwrap_or_else(|_| Uuid::new_v4())),
        serde_json::json!({
            "kind": "external",
            "hostname": info.hostname,
            "username": info.username,
            "remote_addr": info.remote_addr,
        }),
    )
    .await;
    crate::webhook::notify_new_session(state, &info).await;

    Ok((session_id, token))
}

/// Handles one encrypted beacon poll: decrypts the inbound envelope, processes
/// heartbeat/result payloads, drains queued tasks and seals the response.
pub async fn handle_beacon_poll(
    state: &ServerState,
    envelope_bytes: &[u8],
) -> Result<Vec<u8>, Status> {
    let envelope = wire::decode_envelope(envelope_bytes)
        .map_err(|_| Status::invalid_argument("malformed envelope"))?;

    let handle = state
        .sessions
        .get(&envelope.session_id)
        .await
        .ok_or_else(|| Status::not_found("unknown session"))?;
    if !handle.is_beacon {
        return Err(Status::failed_precondition("session is not a beacon"));
    }

    process_beacon_envelope(state, &handle, &envelope).await?;
    state.touch_session(&handle).await;

    let tasks = handle
        .drain_beacon_tasks(crate::BEACON_TASKS_PER_POLL)
        .await;

    let message = AgentMessageWithTasks { tasks };
    let sealed = {
        let mut keys = handle.keys.lock().await;
        wire::seal_message(&mut keys, &message.into_message())
            .map_err(|_| Status::internal("failed to seal beacon response"))?
    };
    wire::encode_envelope(&sealed).map_err(|_| Status::internal("failed to encode envelope"))
}

struct AgentMessageWithTasks {
    tasks: Vec<AgentTask>,
}

impl AgentMessageWithTasks {
    fn into_message(self) -> shikra_proto::v1::AgentMessage {
        use shikra_proto::v1::agent_message;
        shikra_proto::v1::AgentMessage {
            body: Some(agent_message::Body::Tasks(AgentTaskBatch {
                tasks: self.tasks,
            })),
        }
    }
}

async fn process_beacon_envelope(
    state: &ServerState,
    handle: &SessionHandle,
    envelope: &shikra_proto::v1::Envelope,
) -> Result<(), Status> {
    use shikra_proto::v1::agent_message;

    let message = {
        let mut keys = handle.keys.lock().await;
        wire::open_message(&mut keys, envelope)
            .map_err(|_| Status::unauthenticated("envelope rejected"))?
    };

    match message.body {
        Some(agent_message::Body::Results(batch)) => {
            for result in batch.results {
                deliver_result(handle, result).await;
            }
        }
        Some(agent_message::Body::Heartbeat(_)) => {}
        Some(agent_message::Body::Result(result)) => {
            deliver_result(handle, result).await;
        }
        Some(agent_message::Body::Task(_))
        | Some(agent_message::Body::Tasks(_))
        | Some(agent_message::Body::TunnelOpen(_)) => {
            return Err(Status::invalid_argument("agents must not send tasks"));
        }
        Some(agent_message::Body::TunnelData(_))
        | Some(agent_message::Body::TunnelClose(_))
        | Some(agent_message::Body::TunnelAccept(_)) => {
            return Err(Status::failed_precondition(
                "beacons do not support tunnel frames",
            ));
        }
        None => {}
    }
    let _ = state;
    Ok(())
}

async fn deliver_result(handle: &SessionHandle, result: AgentResult) {
    let waiter = handle.pending.lock().await.remove(&result.task_id);
    if let Some(waiter) = waiter {
        let _ = waiter.send(result);
    } else {
        tracing::warn!(session = %handle.id, task = %result.task_id, "result for unknown task");
    }
}

fn normalize_kind(kind: i32) -> i32 {
    match SessionKind::try_from(kind) {
        Ok(SessionKind::Beacon) => SessionKind::Beacon as i32,
        _ => SessionKind::Session as i32,
    }
}

fn normalize_platform(platform: i32) -> i32 {
    match Platform::try_from(platform) {
        Ok(value) => value as i32,
        Err(_) => Platform::Unspecified as i32,
    }
}

fn platform_str(value: i32) -> String {
    match Platform::try_from(value) {
        Ok(Platform::Windows) => "windows".into(),
        Ok(Platform::Linux) => "linux".into(),
        Ok(Platform::Macos) => "macos".into(),
        _ => "unknown".into(),
    }
}

/// Processes a `[u8 opcode][protobuf]` frame used by the DNS and WireGuard
/// beacon transports. Returns the raw response body, or an empty vector when
/// the frame is malformed or the opcode is unknown.
pub async fn process_transport_frame(
    state: &Arc<ServerState>,
    remote_addr: &str,
    frame: &[u8],
) -> Vec<u8> {
    let Some((&opcode, payload)) = frame.split_first() else {
        return Vec::new();
    };
    match opcode {
        crate::OP_ENROLL => {
            let request = match CheckInRequest::decode(payload) {
                Ok(request) => request,
                Err(_) => return Vec::new(),
            };
            match enroll(state, request, remote_addr.to_string()).await {
                Ok(response) => response.encode_to_vec(),
                Err(status) => CheckInResponse {
                    session_id: format!("error:{}", status.message()),
                    ..Default::default()
                }
                .encode_to_vec(),
            }
        }
        crate::OP_POLL => {
            let request = match Envelope::decode(payload) {
                Ok(request) => request,
                Err(_) => return Vec::new(),
            };
            handle_beacon_poll(state, &request.encode_to_vec())
                .await
                .unwrap_or_default()
        }
        _ => Vec::new(),
    }
}
