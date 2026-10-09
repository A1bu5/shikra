use crate::models::{EventRow, SessionRow, TaskRow};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct NewSession {
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
}

pub async fn default_engagement(pool: &PgPool) -> Result<Uuid, sqlx::Error> {
    let existing: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM engagements ORDER BY started_at ASC LIMIT 1")
            .fetch_optional(pool)
            .await?;
    if let Some((id,)) = existing {
        return Ok(id);
    }

    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO engagements (id, name, scope) VALUES ($1, $2, $3)")
        .bind(id)
        .bind("default")
        .bind(serde_json::json!([]))
        .execute(pool)
        .await?;
    Ok(id)
}

pub async fn upsert_session(pool: &PgPool, session: &NewSession) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO sessions (
            id, engagement_id, implant_id, kind, status, platform, architecture,
            hostname, username, process_name, remote_addr, metadata, first_seen, last_seen
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, now(), now())
        ON CONFLICT (id) DO UPDATE SET
            status = EXCLUDED.status,
            hostname = EXCLUDED.hostname,
            username = EXCLUDED.username,
            process_name = EXCLUDED.process_name,
            remote_addr = EXCLUDED.remote_addr,
            metadata = EXCLUDED.metadata,
            last_seen = now()
        "#,
    )
    .bind(session.id)
    .bind(session.engagement_id)
    .bind(session.implant_id)
    .bind(&session.kind)
    .bind(&session.status)
    .bind(&session.platform)
    .bind(&session.architecture)
    .bind(&session.hostname)
    .bind(&session.username)
    .bind(&session.process_name)
    .bind(&session.remote_addr)
    .bind(&session.metadata)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn touch_session(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE sessions SET last_seen = now(), status = 'active' WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_session_status(pool: &PgPool, id: Uuid, status: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE sessions SET status = $2 WHERE id = $1")
        .bind(id)
        .bind(status)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_sessions(pool: &PgPool) -> Result<Vec<SessionRow>, sqlx::Error> {
    sqlx::query_as::<_, SessionRow>(
        "SELECT * FROM sessions WHERE status <> 'dead' ORDER BY last_seen DESC",
    )
    .fetch_all(pool)
    .await
}

pub async fn get_session(pool: &PgPool, id: Uuid) -> Result<Option<SessionRow>, sqlx::Error> {
    sqlx::query_as::<_, SessionRow>("SELECT * FROM sessions WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn insert_task(pool: &PgPool, task: &TaskRow) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO tasks (
            id, session_id, operator_id, command, payload, state, exit_code, output,
            ai_initiated, approved_by, created_at, dispatched_at, completed_at
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
        "#,
    )
    .bind(task.id)
    .bind(task.session_id)
    .bind(task.operator_id)
    .bind(&task.command)
    .bind(&task.payload)
    .bind(&task.state)
    .bind(task.exit_code)
    .bind(&task.output)
    .bind(task.ai_initiated)
    .bind(task.approved_by)
    .bind(task.created_at)
    .bind(task.dispatched_at)
    .bind(task.completed_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_task_state(
    pool: &PgPool,
    task_id: Uuid,
    state: &str,
    exit_code: Option<i32>,
    output: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE tasks SET state = $2, exit_code = $3, output = $4, completed_at = now() WHERE id = $1",
    )
    .bind(task_id)
    .bind(state)
    .bind(exit_code)
    .bind(output)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_tasks(pool: &PgPool, session_id: Uuid) -> Result<Vec<TaskRow>, sqlx::Error> {
    sqlx::query_as::<_, TaskRow>(
        "SELECT * FROM tasks WHERE session_id = $1 ORDER BY created_at DESC LIMIT 200",
    )
    .bind(session_id)
    .fetch_all(pool)
    .await
}

pub async fn insert_event(
    pool: &PgPool,
    kind: &str,
    subject: Option<Uuid>,
    payload: serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO events (id, kind, subject, payload, occurred_at) VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(Uuid::now_v7())
    .bind(kind)
    .bind(subject)
    .bind(payload)
    .bind(OffsetDateTime::now_utc())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn recent_events(pool: &PgPool, limit: i64) -> Result<Vec<EventRow>, sqlx::Error> {
    sqlx::query_as::<_, EventRow>("SELECT * FROM events ORDER BY occurred_at DESC LIMIT $1")
        .bind(limit)
        .fetch_all(pool)
        .await
}

pub async fn list_tasks_filtered(
    pool: &PgPool,
    session_id: Option<Uuid>,
    limit: i64,
) -> Result<Vec<TaskRow>, sqlx::Error> {
    match session_id {
        Some(session_id) => {
            sqlx::query_as::<_, TaskRow>(
                "SELECT * FROM tasks WHERE session_id = $1 ORDER BY created_at DESC LIMIT $2",
            )
            .bind(session_id)
            .bind(limit)
            .fetch_all(pool)
            .await
        }
        None => {
            sqlx::query_as::<_, TaskRow>("SELECT * FROM tasks ORDER BY created_at DESC LIMIT $1")
                .bind(limit)
                .fetch_all(pool)
                .await
        }
    }
}
