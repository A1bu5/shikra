use crate::provider::{
    AiError, ChatMessage, Completion, CompletionProvider, Role, ToolCall, ToolDefinition,
};
use serde_json::{json, Value};

/// OpenAI-compatible chat-completions provider (works with OpenAI, Azure
/// OpenAI-compatible gateways, OpenRouter, Ollama, vLLM, LM Studio, …).
pub struct OpenAiCompatProvider {
    client: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
    model: String,
    temperature: f32,
}

#[derive(Debug, Clone)]
pub struct OpenAiCompatConfig {
    pub base_url: String,
    pub api_key: Option<String>,
    pub model: String,
    pub temperature: f32,
}

impl OpenAiCompatConfig {
    /// Reads configuration from the environment:
    /// `SHIKRA_LLM_BASE_URL`, `SHIKRA_LLM_API_KEY`, `SHIKRA_LLM_MODEL`,
    /// `SHIKRA_LLM_TEMPERATURE`.
    pub fn from_env() -> Option<Self> {
        let base_url = std::env::var("SHIKRA_LLM_BASE_URL").ok()?;
        let model = std::env::var("SHIKRA_LLM_MODEL").ok()?;
        let api_key = std::env::var("SHIKRA_LLM_API_KEY")
            .ok()
            .filter(|k| !k.is_empty());
        let temperature = std::env::var("SHIKRA_LLM_TEMPERATURE")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0.2);
        Some(Self {
            base_url,
            api_key,
            model,
            temperature,
        })
    }
}

impl OpenAiCompatProvider {
    pub fn new(config: OpenAiCompatConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: config.base_url.trim_end_matches('/').to_string(),
            api_key: config.api_key,
            model: config.model,
            temperature: config.temperature,
        }
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    fn endpoint(&self) -> String {
        format!("{}/chat/completions", self.base_url)
    }
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::System => "system",
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => "tool",
    }
}

fn message_to_wire(message: &ChatMessage) -> Value {
    let mut wire = json!({
        "role": role_name(message.role),
    });
    match message.role {
        Role::Tool => {
            wire["content"] = json!(message.content);
            if let Some(call_id) = &message.tool_call_id {
                wire["tool_call_id"] = json!(call_id);
            }
        }
        Role::Assistant => {
            if message.content.is_empty() {
                wire["content"] = Value::Null;
            } else {
                wire["content"] = json!(message.content);
            }
            if let Some(calls) = &message.tool_calls {
                let calls: Vec<Value> = calls
                    .iter()
                    .map(|call| {
                        json!({
                            "id": call.id,
                            "type": "function",
                            "function": {
                                "name": call.name,
                                "arguments": call.arguments.to_string(),
                            }
                        })
                    })
                    .collect();
                wire["tool_calls"] = Value::Array(calls);
            }
        }
        _ => {
            wire["content"] = json!(message.content);
        }
    }
    wire
}

fn tools_to_wire(tools: &[ToolDefinition]) -> Vec<Value> {
    tools
        .iter()
        .map(|tool| {
            json!({
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters,
                }
            })
        })
        .collect()
}

fn parse_completion(body: &Value) -> Result<Completion, AiError> {
    let choices = body
        .get("choices")
        .and_then(|value| value.as_array())
        .ok_or_else(|| AiError::Provider("response missing choices".into()))?;
    let message = choices
        .first()
        .and_then(|choice| choice.get("message"))
        .ok_or_else(|| AiError::Provider("response missing message".into()))?;

    let content = message
        .get("content")
        .and_then(|value| value.as_str())
        .map(|text| text.to_string())
        .filter(|text| !text.is_empty());

    let mut tool_calls = Vec::new();
    if let Some(calls) = message.get("tool_calls").and_then(|value| value.as_array()) {
        for call in calls {
            let id = call
                .get("id")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string();
            let function = call.get("function").cloned().unwrap_or(Value::Null);
            let name = function
                .get("name")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string();
            let raw_args = function
                .get("arguments")
                .and_then(|value| value.as_str())
                .unwrap_or("{}");
            let arguments = serde_json::from_str(raw_args).unwrap_or(Value::Null);
            tool_calls.push(ToolCall {
                id,
                name,
                arguments,
            });
        }
    }

    Ok(Completion {
        content,
        tool_calls,
    })
}

#[async_trait::async_trait]
impl CompletionProvider for OpenAiCompatProvider {
    async fn complete(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolDefinition],
    ) -> crate::Result<Completion> {
        let mut payload = json!({
            "model": self.model,
            "temperature": self.temperature,
            "messages": messages.iter().map(message_to_wire).collect::<Vec<_>>(),
        });
        if !tools.is_empty() {
            payload["tools"] = Value::Array(tools_to_wire(tools));
            payload["tool_choice"] = json!("auto");
        }

        let mut request = self.client.post(self.endpoint()).json(&payload);
        if let Some(api_key) = &self.api_key {
            request = request.bearer_auth(api_key);
        }

        let response = request
            .send()
            .await
            .map_err(|err| AiError::Provider(format!("request failed: {err}")))?;

        let status = response.status();
        let body: Value = response
            .json()
            .await
            .map_err(|err| AiError::Provider(format!("invalid JSON response: {err}")))?;

        if !status.is_success() {
            let message = body
                .get("error")
                .and_then(|error| error.get("message"))
                .and_then(|value| value.as_str())
                .unwrap_or("unknown provider error");
            return Err(AiError::Provider(format!("HTTP {status}: {message}")));
        }

        parse_completion(&body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn canned_server(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0u8; 8192];
                let _ = stream.read(&mut buffer);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{addr}/v1")
    }

    fn provider(base_url: String) -> OpenAiCompatProvider {
        OpenAiCompatProvider::new(OpenAiCompatConfig {
            base_url,
            api_key: Some("test-key".into()),
            model: "test-model".into(),
            temperature: 0.0,
        })
    }

    #[tokio::test]
    async fn parses_tool_calls() {
        let base = canned_server(
            r#"{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call-1","type":"function","function":{"name":"list_sessions","arguments":"{\"limit\":5}"}}]}}]}"#,
        );
        let provider = provider(base);
        let completion = provider
            .complete(
                &[ChatMessage::user("hi")],
                &[ToolDefinition {
                    name: "list_sessions".into(),
                    description: "list".into(),
                    parameters: json!({"type":"object"}),
                }],
            )
            .await
            .expect("completion");
        assert!(completion.content.is_none());
        assert_eq!(completion.tool_calls.len(), 1);
        assert_eq!(completion.tool_calls[0].name, "list_sessions");
        assert_eq!(completion.tool_calls[0].arguments["limit"], 5);
    }

    #[tokio::test]
    async fn parses_text_completion() {
        let base = canned_server(
            r#"{"choices":[{"message":{"role":"assistant","content":"hello operator"}}]}"#,
        );
        let provider = provider(base);
        let completion = provider
            .complete(&[ChatMessage::user("hi")], &[])
            .await
            .expect("completion");
        assert_eq!(completion.content.as_deref(), Some("hello operator"));
        assert!(completion.tool_calls.is_empty());
    }

    #[test]
    fn tool_wire_format_is_openai_compatible() {
        let calls = vec![ToolCall {
            id: "c1".into(),
            name: "run_shell".into(),
            arguments: json!({"command": "whoami"}),
        }];
        let message = ChatMessage::assistant_with_calls("", calls);
        let wire = message_to_wire(&message);
        assert_eq!(wire["role"], "assistant");
        assert_eq!(wire["tool_calls"][0]["type"], "function");
        assert_eq!(wire["tool_calls"][0]["function"]["name"], "run_shell");
        assert!(wire["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap()
            .contains("whoami"));

        let tool = ChatMessage::tool_result("c1", "output");
        let wire = message_to_wire(&tool);
        assert_eq!(wire["role"], "tool");
        assert_eq!(wire["tool_call_id"], "c1");
    }
}
