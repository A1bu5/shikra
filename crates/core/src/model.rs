use crate::ids::{EngagementId, ImplantId, ListenerId, OperatorId, SessionId, TaskId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Windows,
    Linux,
    Macos,
}

impl Platform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::Macos => "macos",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
}

impl Architecture {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    Session,
    Beacon,
}

impl SessionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Beacon => "beacon",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Active,
    Stale,
    Dead,
}

impl SessionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Stale => "stale",
            Self::Dead => "dead",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Pending,
    Dispatched,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl TaskState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Dispatched => "dispatched",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRole {
    Admin,
    Operator,
    Watcher,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operator {
    pub id: OperatorId,
    pub name: String,
    pub role: OperatorRole,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Engagement {
    pub id: EngagementId,
    pub name: String,
    pub scope: Vec<String>,
    pub started_at: OffsetDateTime,
    pub ended_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Listener {
    pub id: ListenerId,
    pub name: String,
    pub protocol: String,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    pub engagement_id: EngagementId,
    pub kind: SessionKind,
    pub status: SessionStatus,
    pub platform: Platform,
    pub architecture: Architecture,
    pub hostname: String,
    pub username: String,
    pub process_name: String,
    pub remote_addr: Option<String>,
    pub first_seen: OffsetDateTime,
    pub last_seen: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: TaskId,
    pub session_id: SessionId,
    pub command: String,
    pub state: TaskState,
    pub created_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
    pub output: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplantBuild {
    pub id: ImplantId,
    pub name: String,
    pub platform: Platform,
    pub architecture: Architecture,
    pub generated_at: OffsetDateTime,
}
