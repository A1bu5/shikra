//! Team chat and operator-facing session UI state.

use crate::models::ChatMessageRow;
use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

pub async fn insert_chat_message(
    pool: &PgPool,
    operator: &str,
    message: &str,
) -> Result<ChatMessageRow, sqlx::Error> {
    sqlx::query_as::<_, ChatMessageRow>(
        "INSERT INTO chat_messages (operator, message) VALUES ($1, $2) RETURNING *",
    )
    .bind(operator)
    .bind(message)
    .fetch_one(pool)
    .await
}

pub async fn recent_chat_messages(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<ChatMessageRow>, sqlx::Error> {
    sqlx::query_as::<_, ChatMessageRow>(
        "SELECT * FROM chat_messages ORDER BY created_at DESC LIMIT $1",
    )
    .bind(limit.clamp(1, 500))
    .fetch_all(pool)
    .await
}

/// Sets the operator-facing color and/or status of a session.
pub async fn set_session_ui(
    pool: &PgPool,
    session_id: Uuid,
    color: Option<&str>,
    operator_status: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE sessions SET color = COALESCE($2, color), \
         operator_status = COALESCE($3, operator_status) WHERE id = $1",
    )
    .bind(session_id)
    .bind(color)
    .bind(operator_status)
    .execute(pool)
    .await?;
    Ok(())
}

/// Loads persisted operator UI state for a session.
pub async fn session_ui(
    pool: &PgPool,
    session_id: Uuid,
) -> Result<Option<(Option<String>, Option<String>)>, sqlx::Error> {
    let row: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT color, operator_status FROM sessions WHERE id = $1")
            .bind(session_id)
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

pub fn _unused(_: OffsetDateTime, _: Value) {}
