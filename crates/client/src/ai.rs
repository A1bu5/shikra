//! Built-in agentic operator: maps model tool calls onto the teamserver.

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

/// Tool definitions exposed to the model. Mirrors the MCP surface so both
/// control paths behave identically.
pub fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "list_sessions".into(),
            description: "List active sessions and beacons known to the teamserver.".into(),
            parameters: json!({ "type": "object", "properties": {} }),
        },
        ToolDefinition {
            name: "run_shell".into(),
            description: "Execute a shell command on a target session and return its output."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "command": { "type": "string" }
                },
                "required": ["session_id", "command"]
            }),
        },
        ToolDefinition {
            name: "fs_ls".into(),
            description: "List a remote directory, returns JSON entries with name/size/type."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "path": { "type": "string" }
                },
                "required": ["session_id", "path"]
            }),
        },
        ToolDefinition {
            name: "fs_cat".into(),
            description: "Read a remote file's contents.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "path": { "type": "string" }
                },
                "required": ["session_id", "path"]
            }),
        },
        ToolDefinition {
            name: "fs_upload".into(),
            description: "Upload a local file to the target.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "local_path": { "type": "string" },
                    "remote_path": { "type": "string" }
                },
                "required": ["session_id", "local_path", "remote_path"]
            }),
        },
        ToolDefinition {
            name: "fs_download".into(),
            description: "Download a remote file to the operator host.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "remote_path": { "type": "string" },
                    "local_path": { "type": "string" }
                },
                "required": ["session_id", "remote_path", "local_path"]
            }),
        },
        ToolDefinition {
            name: "bof_run".into(),
            description: "Execute a Beacon Object File (COFF) on the target.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "file": { "type": "string" },
                    "args": { "type": "string" }
                },
                "required": ["session_id", "file"]
            }),
        },
        ToolDefinition {
            name: "wasm_load".into(),
            description: "Register a WASM extension on the target.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "name": { "type": "string" },
                    "file": { "type": "string" }
                },
                "required": ["session_id", "name", "file"]
            }),
        },
        ToolDefinition {
            name: "wasm_run".into(),
            description: "Run a registered WASM extension on the target.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "name": { "type": "string" },
                    "args": { "type": "string" }
                },
                "required": ["session_id", "name"]
            }),
        },
        ToolDefinition {
            name: "wasm_list".into(),
            description: "List WASM extensions registered on a target.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" }
                },
                "required": ["session_id"]
            }),
        },
    ]
}

fn require_str(args: &serde_json::Value, key: &str) -> Result<String, shikra_ai::AiError> {
    args.get(key)
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
        .ok_or_else(|| shikra_ai::AiError::Tool(format!("missing argument `{key}`")))
}

fn task_to_json(result: shikra_proto::v1::TaskResult) -> serde_json::Value {
    json!({
        "task_id": result.task_id,
        "exit_code": result.exit_code,
        "output": String::from_utf8_lossy(&result.output),
    })
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
                let sessions: Vec<serde_json::Value> = sessions
                    .into_iter()
                    .map(|session| {
                        json!({
                            "id": session.id,
                            "hostname": session.hostname,
                            "username": session.username,
                            "platform": session.platform,
                            "remote_addr": session.remote_addr,
                        })
                    })
                    .collect();
                Ok(json!(sessions))
            }
            "run_shell" => {
                let session_id = require_str(&call.arguments, "session_id")?;
                let command = require_str(&call.arguments, "command")?;
                let result = client
                    .run_task(&session_id, "shell", json!({ "command": command }))
                    .await
                    .map_err(|err| shikra_ai::AiError::Tool(err.to_string()))?;
                Ok(task_to_json(result))
            }
            "fs_ls" => {
                let session_id = require_str(&call.arguments, "session_id")?;
                let path = require_str(&call.arguments, "path")?;
                let result = client
                    .run_task(&session_id, "ls", json!({ "path": path }))
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
                    .run_task(&session_id, "cat", json!({ "path": path }))
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
            "bof_run" => {
                let session_id = require_str(&call.arguments, "session_id")?;
                let file = require_str(&call.arguments, "file")?;
                let args = call
                    .arguments
                    .get("args")
                    .and_then(|value| value.as_str())
                    .unwrap_or("")
                    .to_string();
                let payload = std::fs::read(&file)
                    .map_err(|err| shikra_ai::AiError::Tool(format!("read {file}: {err}")))?;
                let results = client
                    .submit_task(&session_id, "bof", json!({ "args": args }), payload)
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
                    .submit_task(&session_id, "wasm_load", json!({ "name": name }), payload)
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
                let args = call
                    .arguments
                    .get("args")
                    .and_then(|value| value.as_str())
                    .unwrap_or("")
                    .to_string();
                let result = client
                    .run_task(
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
                    .run_task(&session_id, "wasm_list", serde_json::Value::Null)
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

fn compact_json(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<invalid>".into())
}

fn system_prompt() -> String {
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
