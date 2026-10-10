//! AI copilot panel backend: agentic loop, live events and the approval gate.
//!
//! The console reuses the same tool surface and policy as the CLI
//! (`shikra-client ai`); anything the policy does not auto-approve becomes an
//! interactive approve/deny card in the panel.

use crate::AppState;
use serde::{Deserialize, Serialize};
use serde_json::json;
use shikra_ai::{
    AgenticLoop, ApprovalPolicy, Approver, ChatMessage, OpenAiCompatConfig, OpenAiCompatProvider,
    Risk, ToolCall, ToolCallEvent, ToolCallSink,
};
use shikra_client::ai::{system_prompt, tool_definitions, C2ToolExecutor};
use std::collections::HashMap;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::{oneshot, Mutex};

/// Conversation + approval state for the panel (one per app instance).
#[derive(Default)]
pub struct AiState {
    messages: Mutex<Vec<ChatMessage>>,
    pending: Mutex<HashMap<String, oneshot::Sender<bool>>>,
    running: Mutex<bool>,
}

/// LLM settings persisted inside the console config file (`ai` object).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiSettings {
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub auto_approve: bool,
    #[serde(default)]
    pub allow_destructive: bool,
}

struct ResolvedAi {
    config: OpenAiCompatConfig,
    source: &'static str,
    auto_approve: bool,
    allow_destructive: bool,
}

fn settings_from_console_config() -> AiSettings {
    let path = crate::console_config_path();
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return AiSettings::default();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return AiSettings::default();
    };
    let mut settings: AiSettings = value
        .get("ai")
        .and_then(|ai| serde_json::from_value(ai.clone()).ok())
        .unwrap_or_default();
    if let Ok(model) = std::env::var("SHIKRA_LLM_MODEL") {
        settings.model = model;
    }
    if let Ok(base) = std::env::var("SHIKRA_LLM_BASE_URL") {
        settings.base_url = base;
    }
    if let Ok(key) = std::env::var("SHIKRA_LLM_API_KEY") {
        settings.api_key = key;
    }
    settings
}

fn resolve_ai(settings: &AiSettings) -> Result<ResolvedAi, String> {
    let env_configured =
        std::env::var("SHIKRA_LLM_BASE_URL").is_ok() && std::env::var("SHIKRA_LLM_MODEL").is_ok();
    let base_url = settings.base_url.trim().trim_end_matches('/').to_string();
    let model = settings.model.trim().to_string();
    if base_url.is_empty() || model.is_empty() {
        return Err(
            "AI is not configured: set the provider URL and model in the panel (or the \
             SHIKRA_LLM_BASE_URL / SHIKRA_LLM_MODEL environment variables)"
                .into(),
        );
    }
    let temperature = std::env::var("SHIKRA_LLM_TEMPERATURE")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0.2);
    let api_key = if settings.api_key.trim().is_empty() {
        None
    } else {
        Some(settings.api_key.trim().to_string())
    };
    Ok(ResolvedAi {
        config: OpenAiCompatConfig {
            base_url,
            api_key,
            model,
            temperature,
        },
        source: if env_configured {
            "environment"
        } else {
            "console"
        },
        auto_approve: settings.auto_approve,
        allow_destructive: settings.allow_destructive,
    })
}

#[tauri::command]
pub async fn ai_status(
    ai: State<'_, Arc<AiState>>,
    _state: State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let settings = settings_from_console_config();
    let configured = resolve_ai(&settings);
    let running = *ai.running.lock().await;
    Ok(match configured {
        Ok(resolved) => json!({
            "configured": true,
            "base_url": resolved.config.base_url,
            "model": resolved.config.model,
            "has_key": resolved.config.api_key.is_some(),
            "source": resolved.source,
            "auto_approve": resolved.auto_approve,
            "allow_destructive": resolved.allow_destructive,
            "running": running,
            "history": ai.messages.lock().await.len(),
        }),
        Err(message) => json!({
            "configured": false,
            "base_url": settings.base_url,
            "model": settings.model,
            "has_key": !settings.api_key.trim().is_empty(),
            "auto_approve": settings.auto_approve,
            "allow_destructive": settings.allow_destructive,
            "running": running,
            "error": message,
        }),
    })
}

#[tauri::command]
pub async fn ai_config_save(settings: AiSettings) -> Result<(), String> {
    let path = crate::console_config_path();
    let mut config: serde_json::Value = if path.exists() {
        let raw = std::fs::read_to_string(&path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        serde_json::from_str(&raw).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };
    if !config.is_object() {
        config = json!({});
    }
    config["ai"] = serde_json::to_value(&settings).map_err(|err| err.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    let raw =
        serde_json::to_string_pretty(&config).map_err(|err| format!("config encode: {err}"))?;
    std::fs::write(&path, raw)
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Interactive approver: emits a card and waits for the operator's answer.
struct GuiApprover {
    app: AppHandle,
    ai: Arc<AiState>,
}

#[async_trait::async_trait]
impl Approver for GuiApprover {
    async fn approve(&self, call: &ToolCall, risk: Risk) -> bool {
        let (tx, rx) = oneshot::channel();
        self.ai.pending.lock().await.insert(call.id.clone(), tx);
        let _ = self.app.emit(
            "ai-event",
            json!({
                "type": "approval_request",
                "call_id": call.id,
                "name": call.name,
                "arguments": call.arguments,
                "risk": risk,
            }),
        );
        let decision = tokio::time::timeout(std::time::Duration::from_secs(600), rx)
            .await
            .ok()
            .and_then(|result| result.ok())
            .unwrap_or(false);
        self.ai.pending.lock().await.remove(&call.id);
        let _ = self.app.emit(
            "ai-event",
            json!({ "type": "approval_resolved", "call_id": call.id, "approved": decision }),
        );
        decision
    }
}

/// Live tool-call observer: streams every step to the panel.
struct GuiSink {
    app: AppHandle,
}

impl ToolCallSink for GuiSink {
    fn on_tool_start(&self, call: &ToolCall, risk: Risk, description: &str) {
        let _ = self.app.emit(
            "ai-event",
            json!({
                "type": "tool_start",
                "call_id": call.id,
                "name": call.name,
                "arguments": call.arguments,
                "risk": risk,
                "description": description,
            }),
        );
    }

    fn on_tool_call(&self, event: &ToolCallEvent) {
        let _ = self.app.emit(
            "ai-event",
            json!({
                "type": "tool_call",
                "call_id": event.call_id,
                "name": event.name,
                "arguments": event.arguments,
                "risk": event.risk,
                "description": event.risk_description,
                "approved": event.approved,
                "result": event.result,
                "error": event.error,
            }),
        );
    }
}

#[tauri::command]
pub async fn ai_approve(
    ai: State<'_, Arc<AiState>>,
    call_id: String,
    approved: bool,
) -> Result<(), String> {
    let sender = ai.pending.lock().await.remove(&call_id);
    match sender {
        Some(sender) => sender
            .send(approved)
            .map_err(|_| "approval request already resolved".to_string()),
        None => Err(format!("no pending approval for {call_id}")),
    }
}

#[tauri::command]
pub async fn ai_reset(ai: State<'_, Arc<AiState>>) -> Result<(), String> {
    if *ai.running.lock().await {
        return Err("copilot is still running".into());
    }
    ai.messages.lock().await.clear();
    Ok(())
}

#[tauri::command]
pub async fn ai_send(
    app: AppHandle,
    ai: State<'_, Arc<AiState>>,
    state: State<'_, Arc<AppState>>,
    prompt: String,
    max_iterations: Option<usize>,
) -> Result<(), String> {
    let prompt = prompt.trim().to_string();
    if prompt.is_empty() {
        return Err("prompt is empty".into());
    }

    let settings = settings_from_console_config();
    let resolved = resolve_ai(&settings)?;

    let client = {
        let guard = state.client.lock().await;
        guard
            .clone()
            .ok_or_else(|| "not connected to a teamserver".to_string())?
    };

    {
        let mut running = ai.running.lock().await;
        if *running {
            return Err("copilot is already running".into());
        }
        *running = true;
    }

    let ai_state = ai.inner().clone();
    let executor = C2ToolExecutor::new(Arc::new(Mutex::new(client)));
    let provider = OpenAiCompatProvider::new(resolved.config.clone());
    let policy = ApprovalPolicy {
        auto_approve_mutating: resolved.auto_approve,
        allow_destructive: resolved.allow_destructive,
        allowed_tools: Default::default(),
    };
    let approver = Arc::new(GuiApprover {
        app: app.clone(),
        ai: ai_state.clone(),
    });
    let agent = AgenticLoop::new(provider)
        .with_max_iterations(max_iterations.unwrap_or(25).clamp(1, 100))
        .with_policy(policy)
        .with_approver(approver);
    let tools = tool_definitions();
    let sink = GuiSink { app: app.clone() };

    let _ = app.emit(
        "ai-event",
        json!({
            "type": "user_message",
            "content": prompt,
        }),
    );

    tauri::async_runtime::spawn(async move {
        let result = {
            let mut messages = ai_state.messages.lock().await;
            if messages.is_empty() {
                messages.push(ChatMessage::system(system_prompt()));
            }
            messages.push(ChatMessage::user(prompt));
            agent
                .run_turn(&mut messages, &tools, &executor, &sink)
                .await
        };

        match result {
            Ok(completion) => {
                if let Some(content) = completion.content {
                    let _ = app.emit(
                        "ai-event",
                        json!({ "type": "assistant_message", "content": content }),
                    );
                }
            }
            Err(err) => {
                let _ = app.emit(
                    "ai-event",
                    json!({ "type": "error", "message": err.to_string() }),
                );
            }
        }
        *ai_state.running.lock().await = false;
        let _ = app.emit("ai-event", json!({ "type": "turn_done" }));
    });

    Ok(())
}
