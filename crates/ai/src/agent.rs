use crate::policy::ApprovalPolicy;
use crate::provider::{
    ChatMessage, Completion, CompletionProvider, Result, ToolCall, ToolDefinition,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const DEFAULT_MAX_ITERATIONS: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnState {
    Idle,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Chat,
    Reasoning,
    ToolCall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemVisibility {
    Context,
    UiOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationItem {
    pub item_id: Uuid,
    pub turn_id: Uuid,
    pub kind: ItemKind,
    pub visibility: ItemVisibility,
    pub include_in_context: bool,
    pub state: TurnState,
    pub role: Option<String>,
    pub content: String,
    pub tool_name: Option<String>,
    pub tool_arguments: Option<serde_json::Value>,
    pub tool_result: Option<serde_json::Value>,
}

/// Emitted for every tool call so UIs can render or audit the agent's actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallEvent {
    pub call_id: String,
    pub name: String,
    pub arguments: serde_json::Value,
    pub risk_description: String,
    pub approved: bool,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}

/// Optional observer for tool call lifecycle events.
pub trait ToolCallSink: Send + Sync {
    fn on_tool_call(&self, event: &ToolCallEvent);
}

/// Sink that discards events (useful for tests and headless runs).
pub struct NullSink;

impl ToolCallSink for NullSink {
    fn on_tool_call(&self, _event: &ToolCallEvent) {}
}

#[derive(Debug, Clone)]
pub struct AgenticLoop<P> {
    provider: P,
    max_iterations: usize,
    policy: ApprovalPolicy,
}

impl<P: CompletionProvider> AgenticLoop<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            max_iterations: DEFAULT_MAX_ITERATIONS,
            policy: ApprovalPolicy::default(),
        }
    }

    pub fn with_max_iterations(mut self, max_iterations: usize) -> Self {
        self.max_iterations = max_iterations;
        self
    }

    pub fn with_policy(mut self, policy: ApprovalPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn policy(&self) -> &ApprovalPolicy {
        &self.policy
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    /// Runs one agentic turn: model completion → policy gate → tool execution
    /// → feed results back, until the model stops calling tools.
    pub async fn run_turn(
        &self,
        messages: &mut Vec<ChatMessage>,
        tools: &[ToolDefinition],
        executor: &dyn ToolExecutor,
        sink: &dyn ToolCallSink,
    ) -> Result<Completion> {
        for _ in 0..self.max_iterations {
            let completion = self.provider.complete(messages, tools).await?;

            if completion.tool_calls.is_empty() {
                if let Some(content) = &completion.content {
                    messages.push(ChatMessage::assistant(content.clone()));
                }
                return Ok(completion);
            }

            messages.push(ChatMessage::assistant_with_calls(
                completion.content.clone().unwrap_or_default(),
                completion.tool_calls.clone(),
            ));

            for call in &completion.tool_calls {
                let approved = self.policy.evaluate(&call.name)?;
                let risk_description = self.policy.describe(&call.name).to_string();

                let (result, error) = if approved {
                    match executor.call_tool(call).await {
                        Ok(value) => (Some(value), None),
                        Err(err) => (None, Some(err.to_string())),
                    }
                } else {
                    (
                        None,
                        Some(format!(
                            "denied by approval policy: {}",
                            self.policy.describe(&call.name)
                        )),
                    )
                };

                sink.on_tool_call(&ToolCallEvent {
                    call_id: call.id.clone(),
                    name: call.name.clone(),
                    arguments: call.arguments.clone(),
                    risk_description,
                    approved,
                    result: result.clone(),
                    error: error.clone(),
                });

                let tool_content = match (result, error) {
                    (Some(value), _) => serde_json::json!({
                        "name": call.name,
                        "result": value,
                    }),
                    (None, Some(err)) => serde_json::json!({
                        "name": call.name,
                        "error": err,
                    }),
                    (None, None) => serde_json::json!({ "name": call.name }),
                };
                messages.push(ChatMessage::tool_result(
                    call.id.clone(),
                    tool_content.to_string(),
                ));
            }
        }

        Err(crate::provider::AiError::IterationLimit)
    }
}

#[async_trait::async_trait]
pub trait ToolExecutor: Send + Sync {
    async fn call_tool(&self, call: &ToolCall) -> Result<serde_json::Value>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{Completion, ToolCall};
    use std::sync::Mutex;

    struct ScriptedProvider {
        completions: Mutex<Vec<Completion>>,
    }

    #[async_trait::async_trait]
    impl CompletionProvider for ScriptedProvider {
        async fn complete(
            &self,
            _messages: &[ChatMessage],
            _tools: &[ToolDefinition],
        ) -> Result<Completion> {
            let mut completions = self.completions.lock().expect("lock");
            if completions.is_empty() {
                Err(crate::provider::AiError::Provider("no script".into()))
            } else {
                Ok(completions.remove(0))
            }
        }
    }

    struct EchoExecutor;

    #[async_trait::async_trait]
    impl ToolExecutor for EchoExecutor {
        async fn call_tool(&self, call: &ToolCall) -> Result<serde_json::Value> {
            Ok(serde_json::json!({ "echo": call.name }))
        }
    }

    #[derive(Default)]
    struct Recorder {
        events: Mutex<Vec<ToolCallEvent>>,
    }

    impl ToolCallSink for Recorder {
        fn on_tool_call(&self, event: &ToolCallEvent) {
            self.events.lock().expect("lock").push(event.clone());
        }
    }

    #[tokio::test]
    async fn loop_executes_tools_and_returns_final() {
        let provider = ScriptedProvider {
            completions: Mutex::new(vec![
                Completion {
                    content: None,
                    tool_calls: vec![ToolCall {
                        id: "c1".into(),
                        name: "fs_ls".into(),
                        arguments: serde_json::json!({"path": "."}),
                    }],
                },
                Completion {
                    content: Some("found files".into()),
                    tool_calls: Vec::new(),
                },
            ]),
        };
        let loop_runner = AgenticLoop::new(provider);
        let mut messages = vec![ChatMessage::user("list files")];
        let recorder = Recorder::default();
        let completion = loop_runner
            .run_turn(&mut messages, &[], &EchoExecutor, &recorder)
            .await
            .expect("turn");
        assert_eq!(completion.content.as_deref(), Some("found files"));
        let events = recorder.events.lock().expect("lock");
        assert_eq!(events.len(), 1);
        assert!(events[0].approved);
    }

    #[tokio::test]
    async fn destructive_tool_denied_by_default() {
        let provider = ScriptedProvider {
            completions: Mutex::new(vec![
                Completion {
                    content: None,
                    tool_calls: vec![ToolCall {
                        id: "c1".into(),
                        name: "bof_run".into(),
                        arguments: serde_json::json!({}),
                    }],
                },
                Completion {
                    content: Some("ok".into()),
                    tool_calls: Vec::new(),
                },
            ]),
        };
        let loop_runner = AgenticLoop::new(provider);
        let mut messages = vec![ChatMessage::user("run bof")];
        let recorder = Recorder::default();
        loop_runner
            .run_turn(&mut messages, &[], &EchoExecutor, &recorder)
            .await
            .expect("turn");
        let events = recorder.events.lock().expect("lock");
        assert_eq!(events.len(), 1);
        assert!(!events[0].approved);
        assert!(events[0].error.as_deref().unwrap().contains("denied"));
    }

    #[tokio::test]
    async fn preapproved_destructive_tool_runs() {
        let provider = ScriptedProvider {
            completions: Mutex::new(vec![
                Completion {
                    content: None,
                    tool_calls: vec![ToolCall {
                        id: "c1".into(),
                        name: "bof_run".into(),
                        arguments: serde_json::json!({}),
                    }],
                },
                Completion {
                    content: Some("ok".into()),
                    tool_calls: Vec::new(),
                },
            ]),
        };
        let policy = ApprovalPolicy {
            auto_approve_mutating: true,
            allow_destructive: true,
            allowed_tools: Default::default(),
        };
        let loop_runner = AgenticLoop::new(provider).with_policy(policy);
        let mut messages = vec![ChatMessage::user("run bof")];
        let recorder = Recorder::default();
        loop_runner
            .run_turn(&mut messages, &[], &EchoExecutor, &recorder)
            .await
            .expect("turn");
        let events = recorder.events.lock().expect("lock");
        assert!(events[0].approved);
        assert!(events[0].result.is_some());
    }
}
