use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    SessionRegistered,
    SessionHeartbeat,
    SessionDead,
    TaskCreated,
    TaskCompleted,
    OperatorConnected,
    OperatorDisconnected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: Uuid,
    pub kind: EventKind,
    pub subject: Option<Uuid>,
    pub payload: serde_json::Value,
    pub occurred_at: OffsetDateTime,
}

impl Event {
    pub fn new(kind: EventKind, subject: Option<Uuid>, payload: serde_json::Value) -> Self {
        Self {
            id: Uuid::now_v7(),
            kind,
            subject,
            payload,
            occurred_at: OffsetDateTime::now_utc(),
        }
    }
}
