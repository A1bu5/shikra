//! Discord webhook notifications for new sessions.
//!
//! The URL is configured by operators (`SetWebhook`) and persisted to
//! `<state_dir>/webhook.json`. Notifications are best-effort: failures are
//! logged and never block enrollment.

use crate::state::ServerState;
use std::path::Path;

const CONFIG_FILE: &str = "webhook.json";

pub fn load(state_dir: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(state_dir.join(CONFIG_FILE)).ok()?;
    let value: serde_json::Value = serde_json::from_str(&raw).ok()?;
    value
        .get("discord_url")
        .and_then(|url| url.as_str())
        .map(str::to_string)
        .filter(|url| !url.trim().is_empty())
}

pub fn persist(state_dir: &Path, url: Option<&str>) -> std::io::Result<()> {
    let path = state_dir.join(CONFIG_FILE);
    let value = serde_json::json!({ "discord_url": url.unwrap_or("") });
    std::fs::write(path, serde_json::to_string_pretty(&value)?)
}

/// Validates that a URL looks like a Discord webhook endpoint.
pub fn validate_discord_url(url: &str) -> Result<(), String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    if !trimmed.starts_with("https://discord.com/api/webhooks/")
        && !trimmed.starts_with("https://discordapp.com/api/webhooks/")
    {
        return Err(
            "webhook URL must be a Discord API webhook (https://discord.com/api/webhooks/…)".into(),
        );
    }
    Ok(())
}

/// Sends a new-session embed when a webhook is configured.
pub async fn notify_new_session(state: &ServerState, info: &shikra_proto::v1::SessionInfo) {
    let url = state.webhook.read().await.clone();
    let Some(url) = url else {
        return;
    };
    let payload = serde_json::json!({
        "embeds": [{
            "title": "New session",
            "color": 3_358_177,
            "fields": [
                { "name": "Agent", "value": format!("`{}`", info.id), "inline": true },
                { "name": "User", "value": info.username.clone(), "inline": true },
                { "name": "Host", "value": info.hostname.clone(), "inline": true },
                { "name": "Platform", "value": format!("{}/{}", info.platform, info.architecture), "inline": true },
                { "name": "Process", "value": info.process_name.clone(), "inline": true },
                { "name": "Address", "value": if info.remote_addr.is_empty() { "-".into() } else { info.remote_addr.clone() }, "inline": true },
            ],
        }],
    });
    let body = match serde_json::to_vec(&payload) {
        Ok(body) => body,
        Err(err) => {
            tracing::warn!(%err, "failed to encode webhook payload");
            return;
        }
    };
    let client = reqwest::Client::new();
    match client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {}
        Ok(response) => {
            tracing::warn!(status = %response.status(), "discord webhook rejected notification");
        }
        Err(err) => tracing::warn!(%err, "discord webhook delivery failed"),
    }
}
