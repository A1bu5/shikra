//! Built-in agentic operator: maps model tool calls onto the teamserver.
//!
//! The tool surface is shared by the CLI (`shikra-client ai`) and the Tauri
//! console panel. Risk tiers for these names live in `shikra_ai::policy`.

use crate::OperatorClient;
use serde_json::json;
use shikra_ai::{ApprovalPolicy, ToolCall, ToolDefinition, ToolExecutor};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Tool executor backed by an `OperatorClient` connection.
pub struct C2ToolExecutor {
    client: Arc<Mutex<OperatorClient>>,
}

impl C2ToolExecutor {
    pub fn new(client: Arc<Mutex<OperatorClient>>) -> Self {
        Self { client }
    }
}

fn platform_name(value: i32) -> &'static str {
    use shikra_proto::v1::Platform;
    match Platform::try_from(value) {
        Ok(Platform::Windows) => "windows",
        Ok(Platform::Linux) => "linux",
        Ok(Platform::Macos) => "macos",
        _ => "unknown",
    }
}

fn architecture_name(value: i32) -> &'static str {
    use shikra_proto::v1::Architecture;
    match Architecture::try_from(value) {
        Ok(Architecture::X8664) => "x86_64",
        Ok(Architecture::Aarch64) => "aarch64",
        _ => "unknown",
    }
}

fn kind_name(value: i32) -> &'static str {
    use shikra_proto::v1::SessionKind;
    match SessionKind::try_from(value) {
        Ok(SessionKind::Session) => "session",
        Ok(SessionKind::Beacon) => "beacon",
        Ok(SessionKind::External) => "external",
        _ => "unknown",
    }
}

fn status_name(value: i32) -> &'static str {
    use shikra_proto::v1::SessionStatus;
    match SessionStatus::try_from(value) {
        Ok(SessionStatus::Active) => "active",
        Ok(SessionStatus::Stale) => "stale",
        Ok(SessionStatus::Dead) => "dead",
        _ => "unknown",
    }
}

fn task_state_name(value: i32) -> &'static str {
    use shikra_proto::v1::TaskState;
    match TaskState::try_from(value) {
        Ok(TaskState::Pending) => "pending",
        Ok(TaskState::Dispatched) => "dispatched",
        Ok(TaskState::Running) => "running",
        Ok(TaskState::Completed) => "completed",
        Ok(TaskState::Failed) => "failed",
        Ok(TaskState::Cancelled) => "cancelled",
        _ => "unknown",
    }
}

fn session_json(info: shikra_proto::v1::SessionInfo) -> serde_json::Value {
    json!({
        "id": info.id,
        "hostname": info.hostname,
        "username": info.username,
        "platform": platform_name(info.platform),
        "architecture": architecture_name(info.architecture),
        "kind": kind_name(info.kind),
        "status": status_name(info.status),
        "remote_addr": info.remote_addr,
        "process_name": info.process_name,
        "last_seen_unix": info.last_seen.map(|ts| ts.seconds),
        "first_seen_unix": info.first_seen.map(|ts| ts.seconds),
    })
}

/// Tool definitions exposed to the model by both the CLI and the console
/// copilot panel. Risk tiers for these names live in `shikra_ai::policy`.
pub fn tool_definitions() -> Vec<ToolDefinition> {
    let session_id = |properties: &mut serde_json::Map<String, serde_json::Value>| {
        properties.insert("session_id".into(), json!({ "type": "string" }));
    };
    let object = |properties: serde_json::Value, required: Vec<&str>| {
        json!({
            "type": "object",
            "properties": properties,
            "required": required,
        })
    };
    let empty = || json!({ "type": "object", "properties": {} });

    let mut with_session = serde_json::Map::new();
    session_id(&mut with_session);

    vec![
        ToolDefinition {
            name: "list_sessions".into(),
            description: "List active sessions and beacons known to the teamserver.".into(),
            parameters: empty(),
        },
        ToolDefinition {
            name: "session_info".into(),
            description:
                "Detailed metadata for one session: platform, architecture, kind, status, \
                 process, remote address and first/last seen timestamps."
                    .into(),
            parameters: object(with_session.clone().into(), vec!["session_id"]),
        },
        ToolDefinition {
            name: "list_tasks".into(),
            description:
                "Recent tasks for a session, including whether each task was initiated by \
                 the AI copilot."
                    .into(),
            parameters: {
                let mut properties = with_session.clone();
                properties.insert("limit".into(), json!({ "type": "integer", "minimum": 1 }));
                object(properties.into(), vec!["session_id"])
            },
        },
        ToolDefinition {
            name: "list_listeners".into(),
            description: "Running beacon listeners (HTTP, QUIC, DNS, WireGuard).".into(),
            parameters: empty(),
        },
        ToolDefinition {
            name: "list_pivots".into(),
            description: "Active remote port forwards (pivot chains) with connection counts."
                .into(),
            parameters: empty(),
        },
        ToolDefinition {
            name: "list_extensions".into(),
            description: "Signed extension registry contents.".into(),
            parameters: empty(),
        },
        ToolDefinition {
            name: "list_credentials".into(),
            description: "Team credential store (secrets are not returned).".into(),
            parameters: empty(),
        },
        ToolDefinition {
            name: "list_loot".into(),
            description: "Team loot store metadata (file contents are not returned).".into(),
            parameters: empty(),
        },
        ToolDefinition {
            name: "fs_ls".into(),
            description: "List a remote directory, returns JSON entries with name/size/type."
                .into(),
            parameters: {
                let mut properties = with_session.clone();
                properties.insert("path".into(), json!({ "type": "string" }));
                object(properties.into(), vec!["session_id", "path"])
            },
        },
        ToolDefinition {
            name: "fs_cat".into(),
            description: "Read a remote file's contents.".into(),
            parameters: {
                let mut properties = with_session.clone();
                properties.insert("path".into(), json!({ "type": "string" }));
                object(properties.into(), vec!["session_id", "path"])
            },
        },
        ToolDefinition {
            name: "fs_upload".into(),
            description: "Upload a local file to the target.".into(),
            parameters: {
                let mut properties = with_session.clone();
                properties.insert("local_path".into(), json!({ "type": "string" }));
                properties.insert("remote_path".into(), json!({ "type": "string" }));
                object(
                    properties.into(),
                    vec!["session_id", "local_path", "remote_path"],
                )
            },
        },
        ToolDefinition {
            name: "fs_download".into(),
            description: "Download a remote file to the operator host.".into(),
            parameters: {
                let mut properties = with_session.clone();
                properties.insert("remote_path".into(), json!({ "type": "string" }));
                properties.insert("local_path".into(), json!({ "type": "string" }));
                object(
                    properties.into(),
                    vec!["session_id", "remote_path", "local_path"],
                )
            },
        },
        ToolDefinition {
            name: "ps".into(),
            description: "List processes on the target (JSON rows: pid, name, user, memory…)."
                .into(),
            parameters: object(with_session.clone().into(), vec!["session_id"]),
        },
        ToolDefinition {
            name: "netstat".into(),
            description: "List network connections on the target.".into(),
            parameters: object(with_session.clone().into(), vec!["session_id"]),
        },
        ToolDefinition {
            name: "ifconfig".into(),
            description: "List network interfaces and addresses on the target.".into(),
            parameters: object(with_session.clone().into(), vec!["session_id"]),
        },
        ToolDefinition {
            name: "env_dump".into(),
            description: "Dump the target's environment variables.".into(),
            parameters: object(with_session.clone().into(), vec!["session_id"]),
        },
        ToolDefinition {
            name: "run_shell".into(),
            description: "Execute a shell command on a target session and return its output."
                .into(),
            parameters: {
                let mut properties = with_session.clone();
                properties.insert("command".into(), json!({ "type": "string" }));
                object(properties.into(), vec!["session_id", "command"])
            },
        },
        ToolDefinition {
            name: "portscan".into(),
            description:
                "Run a TCP connect scan from the agent's network position. Returns the open \
                 ports among the requested ones."
                    .into(),
            parameters: {
                let mut properties = with_session.clone();
                properties.insert("target".into(), json!({ "type": "string" }));
                properties.insert(
                    "ports".into(),
                    json!({ "type": "string", "description": "e.g. \"22,80,443\" or \"1-1024\"" }),
                );
                properties.insert("timeout_ms".into(), json!({ "type": "integer" }));
                object(properties.into(), vec!["session_id", "target", "ports"])
            },
        },
        ToolDefinition {
            name: "screenshot".into(),
            description:
                "Capture the target desktop and save it on the operator host; returns the \
                 file path and size."
                    .into(),
            parameters: object(with_session.clone().into(), vec!["session_id"]),
        },
        ToolDefinition {
            name: "listener_start".into(),
            description: "Start a beacon listener: kind is http, quic, dns or wireguard.".into(),
            parameters: {
                let mut properties = serde_json::Map::new();
                properties.insert(
                    "kind".into(),
                    json!({ "type": "string", "enum": ["http", "quic", "dns", "wireguard"] }),
                );
                properties.insert(
                    "addr".into(),
                    json!({ "type": "string", "description": "e.g. 0.0.0.0:8080" }),
                );
                properties.insert("dns_zone".into(), json!({ "type": "string" }));
                object(properties.into(), vec!["kind", "addr"])
            },
        },
        ToolDefinition {
            name: "listener_stop".into(),
            description: "Stop a running listener by id.".into(),
            parameters: {
                let mut properties = serde_json::Map::new();
                properties.insert("id".into(), json!({ "type": "string" }));
                object(properties.into(), vec!["id"])
            },
        },
        ToolDefinition {
            name: "bof_run".into(),
            description: "Execute a Beacon Object File (COFF) on the target.".into(),
            parameters: {
                let mut properties = with_session.clone();
                properties.insert("file".into(), json!({ "type": "string" }));
                properties.insert("args".into(), json!({ "type": "string" }));
                object(properties.into(), vec!["session_id", "file"])
            },
        },
        ToolDefinition {
            name: "wasm_load".into(),
            description: "Register a WASM extension on the target.".into(),
            parameters: {
                let mut properties = with_session.clone();
                properties.insert("name".into(), json!({ "type": "string" }));
                properties.insert("file".into(), json!({ "type": "string" }));
                object(properties.into(), vec!["session_id", "name", "file"])
            },
        },
        ToolDefinition {
            name: "wasm_run".into(),
            description: "Run a registered WASM extension on the target.".into(),
            parameters: {
                let mut properties = with_session.clone();
                properties.insert("name".into(), json!({ "type": "string" }));
                properties.insert("args".into(), json!({ "type": "string" }));
                object(properties.into(), vec!["session_id", "name"])
            },
        },
        ToolDefinition {
            name: "wasm_list".into(),
            description: "List WASM extensions registered on a target.".into(),
            parameters: object(with_session.into(), vec!["session_id"]),
        },
    ]
}

fn require_str(args: &serde_json::Value, key: &str) -> Result<String, shikra_ai::AiError> {
    args.get(key)
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
        .ok_or_else(|| shikra_ai::AiError::Tool(format!("missing argument `{key}`")))
}

fn optional_str(args: &serde_json::Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
}

fn task_to_json(result: shikra_proto::v1::TaskResult) -> serde_json::Value {
    json!({
        "task_id": result.task_id,
        "exit_code": result.exit_code,
        "output": String::from_utf8_lossy(&result.output),
        "state": task_state_name(result.state),
    })
}

/// Saves screenshot bytes to the operator host and returns the path.
fn save_screenshot(bytes: &[u8]) -> std::io::Result<PathBuf> {
    let directory = std::env::temp_dir().join("shikra-screenshots");
    std::fs::create_dir_all(&directory)?;
    let extension = if bytes.starts_with(b"\x89PNG") {
        "png"
    } else {
        "bmp"
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    let path = directory.join(format!("screenshot-{stamp}.{extension}"));
    std::fs::write(&path, bytes)?;
    Ok(path)
}

#[async_trait::async_trait]
impl ToolExecutor for C2ToolExecutor {
    async fn call_tool(&self, call: &ToolCall) -> shikra_ai::Result<serde_json::Value> {
        let mut client = self.client.lock().await;
        match call.name.as_str() {
            "list_sessions" => {
                let sessions = client
                    .sessions()
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                Ok(json!(sessions
                    .into_iter()
                    .map(session_json)
                    .collect::<Vec<_>>()))
            }
            "session_info" => {
                let session_id = require_str(&call.arguments, "session_id")?;
                let sessions = client
                    .sessions()
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                match sessions.into_iter().find(|info| info.id == session_id) {
                    Some(info) => Ok(session_json(info)),
                    None => Ok(json!({ "error": format!("unknown session {session_id}") })),
                }
            }
            "list_tasks" => {
                let session_id = require_str(&call.arguments, "session_id")?;
                let limit = call
                    .arguments
                    .get("limit")
                    .and_then(|value| value.as_u64())
                    .unwrap_or(20)
                    .clamp(1, 200) as u32;
                let tasks = client
                    .list_tasks(Some(&session_id), limit)
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                let rows: Vec<serde_json::Value> = tasks
                    .into_iter()
                    .map(|task| {
                        json!({
                            "id": task.id,
                            "command": task.command,
                            "state": task_state_name(task.state),
                            "exit_code": task.exit_code,
                            "ai_initiated": task.ai_initiated,
                            "output": task.output,
                            "created_at_unix": task.created_at.map(|ts| ts.seconds),
                            "completed_at_unix": task.completed_at.map(|ts| ts.seconds),
                        })
                    })
                    .collect();
                Ok(json!(rows))
            }
            "list_listeners" => {
                let listeners = client
                    .listeners()
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                let rows: Vec<serde_json::Value> = listeners
                    .into_iter()
                    .map(|listener| {
                        json!({
                            "id": listener.id,
                            "kind": listener.kind,
                            "addr": listener.addr,
                            "running": listener.running,
                            "detail": listener.detail,
                        })
                    })
                    .collect();
                Ok(json!(rows))
            }
            "list_pivots" => {
                let pivots = client
                    .list_rportfwds()
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                let rows: Vec<serde_json::Value> = pivots
                    .into_iter()
                    .map(|pivot| {
                        json!({
                            "forward_id": pivot.forward_id,
                            "session_id": pivot.session_id,
                            "bind": pivot.bind,
                            "to": pivot.to,
                            "connections": pivot.connections,
                            "transport": pivot.transport,
                        })
                    })
                    .collect();
                Ok(json!(rows))
            }
            "list_extensions" => {
                let extensions = client
                    .list_extensions()
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                let rows: Vec<serde_json::Value> = extensions
                    .into_iter()
                    .map(|extension| {
                        json!({
                            "id": extension.id,
                            "name": extension.name,
                            "version": extension.version,
                            "kind": extension.kind,
                            "platform": extension.platform,
                            "architecture": extension.architecture,
                            "description": extension.description,
                            "sha256": extension.sha256,
                        })
                    })
                    .collect();
                Ok(json!(rows))
            }
            "list_credentials" => {
                let credentials = client
                    .list_credentials()
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                let rows: Vec<serde_json::Value> = credentials
                    .into_iter()
                    .map(|credential| {
                        // Secrets stay on the teamserver; the model only sees metadata.
                        json!({
                            "id": credential.id,
                            "host": credential.host,
                            "domain": credential.domain,
                            "username": credential.username,
                            "kind": credential.kind,
                            "source": credential.source,
                        })
                    })
                    .collect();
                Ok(json!(rows))
            }
            "list_loot" => {
                let loot = client
                    .list_loot()
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                let rows: Vec<serde_json::Value> = loot
                    .into_iter()
                    .map(|entry| {
                        json!({
                            "id": entry.id,
                            "kind": entry.kind,
                            "name": entry.name,
                            "size": entry.size,
                            "sha256": entry.sha256,
                        })
                    })
                    .collect();
                Ok(json!(rows))
            }
            "fs_ls" => {
                let session_id = require_str(&call.arguments, "session_id")?;
                let path = require_str(&call.arguments, "path")?;
                let result = client
                    .run_task_ai(&session_id, "ls", json!({ "path": path }))
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                if result.exit_code != 0 {
                    return Ok(json!({
                        "error": String::from_utf8_lossy(&result.output),
                    }));
                }
                serde_json::from_slice(&result.output)
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))
            }
            "fs_cat" => {
                let session_id = require_str(&call.arguments, "session_id")?;
                let path = require_str(&call.arguments, "path")?;
                let result = client
                    .run_task_ai(&session_id, "cat", json!({ "path": path }))
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                Ok(json!({
                    "exit_code": result.exit_code,
                    "output": String::from_utf8_lossy(&result.output),
                }))
            }
            "fs_upload" => {
                let session_id = require_str(&call.arguments, "session_id")?;
                let local = require_str(&call.arguments, "local_path")?;
                let remote = require_str(&call.arguments, "remote_path")?;
                let bytes = client
                    .upload(&session_id, &PathBuf::from(local), &remote)
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                Ok(json!({ "uploaded": bytes }))
            }
            "fs_download" => {
                let session_id = require_str(&call.arguments, "session_id")?;
                let remote = require_str(&call.arguments, "remote_path")?;
                let local = require_str(&call.arguments, "local_path")?;
                let bytes = client
                    .download(&session_id, &remote, &PathBuf::from(local))
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                Ok(json!({ "downloaded": bytes }))
            }
            "ps" | "netstat" | "ifconfig" | "env_dump" => {
                let session_id = require_str(&call.arguments, "session_id")?;
                let kind = match call.name.as_str() {
                    "ps" => "ps",
                    "netstat" => "netstat",
                    "ifconfig" => "ifconfig",
                    _ => "env",
                };
                let result = client
                    .run_task_ai(&session_id, kind, serde_json::Value::Null)
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                Ok(task_to_json(result))
            }
            "run_shell" => {
                let session_id = require_str(&call.arguments, "session_id")?;
                let command = require_str(&call.arguments, "command")?;
                let result = client
                    .run_task_ai(&session_id, "shell", json!({ "command": command }))
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                Ok(task_to_json(result))
            }
            "portscan" => {
                let session_id = require_str(&call.arguments, "session_id")?;
                let target = require_str(&call.arguments, "target")?;
                let ports = require_str(&call.arguments, "ports")?;
                let timeout_ms = call
                    .arguments
                    .get("timeout_ms")
                    .and_then(|value| value.as_u64())
                    .unwrap_or(500);
                let result = client
                    .run_task_ai(
                        &session_id,
                        "portscan",
                        json!({ "target": target, "ports": ports, "timeout_ms": timeout_ms }),
                    )
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                if result.exit_code != 0 {
                    return Ok(json!({
                        "exit_code": result.exit_code,
                        "output": String::from_utf8_lossy(&result.output),
                    }));
                }
                match serde_json::from_slice::<serde_json::Value>(&result.output) {
                    Ok(report) => Ok(report),
                    Err(_) => Ok(json!({
                        "exit_code": result.exit_code,
                        "output": String::from_utf8_lossy(&result.output),
                    })),
                }
            }
            "screenshot" => {
                let session_id = require_str(&call.arguments, "session_id")?;
                let result = client
                    .run_task_ai(&session_id, "screenshot", serde_json::Value::Null)
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                if result.exit_code != 0 {
                    return Ok(json!({
                        "exit_code": result.exit_code,
                        "output": String::from_utf8_lossy(&result.output),
                    }));
                }
                match save_screenshot(&result.output) {
                    Ok(path) => Ok(json!({
                        "path": path.display().to_string(),
                        "bytes": result.output.len(),
                    })),
                    Err(err) => Ok(json!({
                        "bytes": result.output.len(),
                        "error": format!("failed to save screenshot: {err}"),
                    })),
                }
            }
            "listener_start" => {
                let kind = require_str(&call.arguments, "kind")?;
                let addr = require_str(&call.arguments, "addr")?;
                let dns_zone = optional_str(&call.arguments, "dns_zone")
                    .unwrap_or_else(|| "dns.shikra".into());
                let listener = client
                    .start_listener(&kind, &addr, &dns_zone)
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                Ok(json!({
                    "id": listener.id,
                    "kind": listener.kind,
                    "addr": listener.addr,
                    "running": listener.running,
                    "detail": listener.detail,
                }))
            }
            "listener_stop" => {
                let id = require_str(&call.arguments, "id")?;
                client
                    .stop_listener(&id)
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                Ok(json!({ "stopped": id }))
            }
            "bof_run" => {
                let session_id = require_str(&call.arguments, "session_id")?;
                let file = require_str(&call.arguments, "file")?;
                let args = optional_str(&call.arguments, "args").unwrap_or_default();
                let payload = std::fs::read(&file)
                    .map_err(|err| shikra_ai::AiError::Tool(format!("read {file}: {err}")))?;
                let results = client
                    .submit_task_ai(&session_id, "bof", json!({ "args": args }), payload)
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                match results.into_iter().next() {
                    Some(result) => Ok(task_to_json(result)),
                    None => Ok(json!({ "error": "no task result" })),
                }
            }
            "wasm_load" => {
                let session_id = require_str(&call.arguments, "session_id")?;
                let name = require_str(&call.arguments, "name")?;
                let file = require_str(&call.arguments, "file")?;
                let payload = std::fs::read(&file)
                    .map_err(|err| shikra_ai::AiError::Tool(format!("read {file}: {err}")))?;
                let results = client
                    .submit_task_ai(&session_id, "wasm_load", json!({ "name": name }), payload)
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                match results.into_iter().next() {
                    Some(result) => Ok(task_to_json(result)),
                    None => Ok(json!({ "error": "no task result" })),
                }
            }
            "wasm_run" => {
                let session_id = require_str(&call.arguments, "session_id")?;
                let name = require_str(&call.arguments, "name")?;
                let args = optional_str(&call.arguments, "args").unwrap_or_default();
                let result = client
                    .run_task_ai(
                        &session_id,
                        "wasm_run",
                        json!({ "name": name, "args": args }),
                    )
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                Ok(task_to_json(result))
            }
            "wasm_list" => {
                let session_id = require_str(&call.arguments, "session_id")?;
                let result = client
                    .run_task_ai(&session_id, "wasm_list", serde_json::Value::Null)
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                Ok(json!({
                    "extensions": String::from_utf8_lossy(&result.output).lines().collect::<Vec<_>>(),
                }))
            }
            other => Err(shikra_ai::AiError::Tool(format!("unknown tool `{other}`"))),
        }
    }
}

/// Policy preset for interactive CLI sessions: read-only plus shell, with
/// destructive tools requiring an explicit `--allow-destructive` flag.
pub fn interactive_policy(allow_mutating: bool, allow_destructive: bool) -> ApprovalPolicy {
    ApprovalPolicy {
        auto_approve_mutating: allow_mutating,
        allow_destructive,
        allowed_tools: Default::default(),
    }
}

/// Prints tool call events as they happen (operator-visible audit trail).
pub struct ConsoleSink;

impl shikra_ai::ToolCallSink for ConsoleSink {
    fn on_tool_start(&self, call: &ToolCall, risk: shikra_ai::Risk, _description: &str) {
        eprintln!(
            "  [..] {}({}) [{}]",
            call.name,
            compact_json(&call.arguments),
            risk_label(risk)
        );
    }

    fn on_tool_call(&self, event: &shikra_ai::ToolCallEvent) {
        let status = if event.approved { "run" } else { "DENIED" };
        eprintln!(
            "  [{}] {}({})",
            status,
            event.name,
            compact_json(&event.arguments)
        );
        if let Some(error) = &event.error {
            eprintln!("    error: {error}");
        }
        if let Some(result) = &event.result {
            let rendered = compact_json(result);
            let rendered = if rendered.len() > 500 {
                format!("{}…", &rendered[..500])
            } else {
                rendered
            };
            eprintln!("    -> {rendered}");
        }
    }
}

fn risk_label(risk: shikra_ai::Risk) -> &'static str {
    match risk {
        shikra_ai::Risk::ReadOnly => "read-only",
        shikra_ai::Risk::Mutating => "mutating",
        shikra_ai::Risk::Destructive => "destructive",
    }
}

fn compact_json(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<invalid>".into())
}

/// System prompt shared by the CLI and the console copilot.
pub fn system_prompt() -> String {
    "You are Shikra, an operator assistant for an authorized red-team engagement. \
     You control a C2 teamserver through tools. Work step by step: prefer read-only \
     reconnaissance before state-changing actions, explain your plan briefly, and \
     never invent tool output. When a tool is denied by policy, adapt or stop and \
     report. Summarize findings concisely at the end."
        .to_string()
}

/// Runs the built-in agentic loop against the connected teamserver.
pub async fn run_ai_session(
    client: &OperatorClient,
    prompt: Option<String>,
    auto_approve: bool,
    allow_destructive: bool,
    max_iterations: usize,
) -> anyhow::Result<()> {
    let config = shikra_ai::OpenAiCompatConfig::from_env().ok_or_else(|| {
        anyhow::anyhow!(
            "LLM not configured: set SHIKRA_LLM_BASE_URL, SHIKRA_LLM_MODEL \
             (and optionally SHIKRA_LLM_API_KEY / SHIKRA_LLM_TEMPERATURE)"
        )
    })?;
    let provider = shikra_ai::OpenAiCompatProvider::new(config.clone());
    let policy = interactive_policy(auto_approve, allow_destructive);
    let agent = shikra_ai::AgenticLoop::new(provider)
        .with_max_iterations(max_iterations)
        .with_policy(policy);
    let executor =
        C2ToolExecutor::new(std::sync::Arc::new(tokio::sync::Mutex::new(client.clone())));
    let tools = tool_definitions();
    let sink = ConsoleSink;

    eprintln!(
        "model: {} @ {} | mutating auto-approve: {auto_approve} | destructive: {allow_destructive}",
        config.model, config.base_url
    );

    let mut messages = vec![shikra_ai::ChatMessage::system(system_prompt())];

    match prompt {
        Some(prompt) => {
            messages.push(shikra_ai::ChatMessage::user(prompt));
            let completion = agent
                .run_turn(&mut messages, &tools, &executor, &sink)
                .await
                .map_err(|err| anyhow::anyhow!(err.to_string()))?;
            if let Some(content) = completion.content {
                println!("{content}");
            }
        }
        None => {
            eprintln!("interactive AI session — type `exit` to quit");
            use tokio::io::AsyncBufReadExt;
            let stdin = tokio::io::BufReader::new(tokio::io::stdin());
            let mut lines = stdin.lines();
            loop {
                eprint!("ai> ");
                let Some(line) = lines.next_line().await? else {
                    break;
                };
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                if line == "exit" || line == "quit" {
                    break;
                }
                messages.push(shikra_ai::ChatMessage::user(line));
                match agent
                    .run_turn(&mut messages, &tools, &executor, &sink)
                    .await
                {
                    Ok(completion) => {
                        if let Some(content) = completion.content {
                            println!("{content}");
                        }
                    }
                    Err(err) => eprintln!("ai error: {err}"),
                }
            }
        }
    }

    Ok(())
}
