//! Metasploit RPC (msgrpc) integration.
//!
//! Talks to `msfrpcd` over its MessagePack API. Configuration via environment:
//! - `SHIKRA_MSF_RPC_URL` (e.g. `http://127.0.0.1:5552`)
//! - `SHIKRA_MSF_RPC_USER` / `SHIKRA_MSF_RPC_PASSWORD`

use anyhow::{anyhow, Context, Result};
use rmpv::Value;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct MsfConfig {
    pub url: String,
    pub user: String,
    pub password: String,
}

impl MsfConfig {
    pub fn from_env() -> Option<Self> {
        let url = std::env::var("SHIKRA_MSF_RPC_URL").ok()?;
        let user = std::env::var("SHIKRA_MSF_RPC_USER").unwrap_or_else(|_| "msf".into());
        let password = std::env::var("SHIKRA_MSF_RPC_PASSWORD").ok()?;
        Some(Self {
            url: url.trim_end_matches('/').to_string(),
            user,
            password,
        })
    }
}

pub struct MsfClient {
    client: reqwest::Client,
    config: MsfConfig,
    token: Option<String>,
}

impl MsfClient {
    pub fn new(config: MsfConfig) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("failed to build HTTP client"),
            config,
            token: None,
        }
    }

    /// Authenticates against msfrpcd, caching the session token.
    pub async fn login(&mut self) -> Result<()> {
        if self.token.is_some() {
            return Ok(());
        }
        let response = self
            .request(&[
                Value::from("auth.login"),
                Value::from(self.config.user.clone()),
                Value::from(self.config.password.clone()),
            ])
            .await?;
        let result = map_get(&response, "result")
            .and_then(value_as_str)
            .unwrap_or_default()
            .to_string();
        if result != "success" {
            return Err(anyhow!("msf auth.login result: {result}"));
        }
        let token = map_get(&response, "token")
            .and_then(value_as_str)
            .context("msf auth response missing token")?
            .to_string();
        self.token = Some(token);
        Ok(())
    }

    /// Returns the msfrpcd/core version string.
    pub async fn version(&mut self) -> Result<String> {
        self.login().await?;
        let response = self.authenticated_request("core.version", &[]).await?;
        let version = map_get(&response, "version")
            .and_then(value_as_str)
            .unwrap_or("unknown")
            .to_string();
        Ok(version)
    }

    /// Runs a console command and returns the collected output.
    pub async fn console_exec(&mut self, command: &str) -> Result<String> {
        self.login().await?;
        let created = self.authenticated_request("console.create", &[]).await?;
        let console_id = map_get(&created, "id")
            .map(|value| match value {
                Value::Integer(int) => int.to_string(),
                other => value_as_str(other).unwrap_or_default().to_string(),
            })
            .context("console.create missing id")?;

        self.authenticated_request(
            "console.write",
            &[Value::from(console_id.clone()), Value::from(command)],
        )
        .await?;

        let mut output = String::new();
        for _ in 0..120 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let read = self
                .authenticated_request("console.read", &[Value::from(console_id.clone())])
                .await?;
            if let Some(data) = map_get(&read, "data").and_then(value_as_str) {
                output.push_str(data);
            }
            let busy = map_get(&read, "busy")
                .and_then(|value| match value {
                    Value::Boolean(flag) => Some(*flag),
                    other => value_as_str(other).map(|text| text == "true"),
                })
                .unwrap_or(false);
            if !busy {
                break;
            }
        }

        let _ = self
            .authenticated_request("console.destroy", &[Value::from(console_id)])
            .await;
        Ok(output)
    }

    async fn authenticated_request(&self, method: &str, args: &[Value]) -> Result<Value> {
        let token = self.token.clone().context("not authenticated")?;
        let mut values = vec![Value::from(method), Value::from(token)];
        values.extend_from_slice(args);
        self.request(&values).await
    }

    async fn request(&self, values: &[Value]) -> Result<Value> {
        let body = rmp_serde::to_vec(&Value::Array(values.to_vec()))
            .context("failed to encode msf request")?;
        let response = self
            .client
            .post(format!("{}/api/", self.config.url))
            .header("Content-Type", "binary/message-pack")
            .body(body)
            .send()
            .await
            .context("msf RPC request failed")?;
        if !response.status().is_success() {
            anyhow::bail!("msf RPC HTTP {}", response.status());
        }
        let bytes = response.bytes().await.context("msf RPC read failed")?;
        rmp_serde::from_slice(&bytes).context("failed to decode msf response")
    }
}

/// msfrpcd encodes strings as msgpack binary; accept both forms.
fn value_as_str(value: &Value) -> Option<&str> {
    match value {
        Value::String(text) => text.as_str(),
        Value::Binary(bytes) => std::str::from_utf8(bytes).ok(),
        _ => None,
    }
}

fn map_get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.as_map()?.iter().find_map(|(map_key, map_value)| {
        if value_as_str(map_key) == Some(key) {
            Some(map_value)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_get_reads_keys() {
        let value = Value::Map(vec![
            (Value::from("result"), Value::from("success")),
            (Value::from("token"), Value::from("abc123")),
        ]);
        assert_eq!(
            map_get(&value, "result").and_then(|v| v.as_str()),
            Some("success")
        );
        assert_eq!(
            map_get(&value, "token").and_then(|v| v.as_str()),
            Some("abc123")
        );
        assert!(map_get(&value, "missing").is_none());
    }

    #[test]
    fn request_encoding_roundtrips() {
        let values = vec![
            Value::from("auth.login"),
            Value::from("msf"),
            Value::from("pass"),
        ];
        let encoded = rmp_serde::to_vec(&Value::Array(values.clone())).expect("encode");
        let decoded: Value = rmp_serde::from_slice(&encoded).expect("decode");
        assert_eq!(decoded, Value::Array(values));
    }

    #[tokio::test]
    async fn login_without_server_fails_gracefully() {
        let mut client = MsfClient::new(MsfConfig {
            url: "http://127.0.0.1:1".into(),
            user: "msf".into(),
            password: "pass".into(),
        });
        assert!(client.login().await.is_err());
    }
}
