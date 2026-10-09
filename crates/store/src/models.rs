use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct OperatorRow {
    pub id: Uuid,
    pub name: String,
    pub role: String,
    pub password_hash: String,
    pub token_hash: Option<String>,
    pub totp_secret: Option<String>,
    pub disabled: bool,
    pub created_at: OffsetDateTime,
    pub last_seen_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct EngagementRow {
    pub id: Uuid,
    pub name: String,
    pub scope: serde_json::Value,
    pub started_at: OffsetDateTime,
    pub ended_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ListenerRow {
    pub id: Uuid,
    pub profile_id: Option<Uuid>,
    pub name: String,
    pub protocol: String,
    pub bind_addr: String,
    pub config: serde_json::Value,
    pub running: bool,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ImplantRow {
    pub id: Uuid,
    pub name: String,
    pub platform: String,
    pub architecture: String,
    pub config: serde_json::Value,
    pub sha256: Option<String>,
    pub generated_at: OffsetDateTime,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SessionRow {
    pub id: Uuid,
    pub engagement_id: Uuid,
    pub implant_id: Option<Uuid>,
    pub kind: String,
    pub status: String,
    pub platform: String,
    pub architecture: String,
    pub hostname: String,
    pub username: String,
    pub process_name: String,
    pub remote_addr: Option<String>,
    pub metadata: serde_json::Value,
    pub first_seen: OffsetDateTime,
    pub last_seen: OffsetDateTime,
    pub color: Option<String>,
    pub operator_status: Option<String>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ChatMessageRow {
    pub id: i64,
    pub operator: String,
    pub message: String,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct TaskRow {
    pub id: Uuid,
    pub session_id: Uuid,
    pub operator_id: Option<Uuid>,
    pub command: String,
    pub payload: serde_json::Value,
    pub state: String,
    pub exit_code: Option<i32>,
    pub output: Option<String>,
    pub ai_initiated: bool,
    pub approved_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub dispatched_at: Option<OffsetDateTime>,
    pub completed_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct EventRow {
    pub id: Uuid,
    pub kind: String,
    pub subject: Option<Uuid>,
    pub payload: serde_json::Value,
    pub occurred_at: OffsetDateTime,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AuditLogRow {
    pub id: i64,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub details: serde_json::Value,
    pub prev_hash: Option<Vec<u8>>,
    pub hash: Vec<u8>,
    pub recorded_at: OffsetDateTime,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AiConversationRow {
    pub id: Uuid,
    pub operator_id: Option<Uuid>,
    pub title: Option<String>,
    pub target_session_id: Option<Uuid>,
    pub active_turn_id: Option<Uuid>,
    pub turn_state: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AiMessageRow {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub turn_id: Option<Uuid>,
    pub item_id: Option<Uuid>,
    pub kind: String,
    pub visibility: String,
    pub include_in_context: bool,
    pub state: String,
    pub role: String,
    pub content: String,
    pub tool_name: Option<String>,
    pub tool_arguments: Option<serde_json::Value>,
    pub tool_result: Option<serde_json::Value>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct CredentialRow {
    pub id: Uuid,
    pub engagement_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    pub host: String,
    pub domain: String,
    pub username: String,
    pub secret: String,
    pub kind: String,
    pub source: String,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct LootRow {
    pub id: Uuid,
    pub engagement_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    pub kind: String,
    pub name: String,
    pub size: i64,
    pub sha256: Option<String>,
    pub data: Option<Vec<u8>>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct CanaryRow {
    pub id: Uuid,
    pub token: String,
    pub kind: String,
    pub note: String,
    pub triggered: bool,
    pub triggered_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ExtensionRow {
    pub id: Uuid,
    pub engagement_id: Option<Uuid>,
    pub name: String,
    pub version: String,
    pub kind: String,
    pub platform: String,
    pub architecture: String,
    pub description: String,
    pub sha256: String,
    pub size: i64,
    pub signer: String,
    pub manifest: serde_json::Value,
    pub payload: Option<Vec<u8>>,
    pub installed_by: String,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ReactionRuleRow {
    pub id: Uuid,
    pub event_kind: String,
    pub action: String,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct HostRow {
    pub id: Uuid,
    pub engagement_id: Option<Uuid>,
    pub ip: String,
    pub hostname: String,
    pub os: String,
    pub ports: serde_json::Value,
    pub source: String,
    pub discovered_at: OffsetDateTime,
}
