use crate::models::{
    AuditLogRow, CanaryRow, CredentialRow, HostRow, LootRow, OperatorRow, ReactionRuleRow,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

/// Advisory lock key that serializes audit-chain appends across processes.
const AUDIT_CHAIN_LOCK: i64 = 0x6461_7564_6974_0001;
use time::OffsetDateTime;
use uuid::Uuid;

// ---------------------------------------------------------------- operators

pub async fn list_operators(pool: &PgPool) -> Result<Vec<OperatorRow>, sqlx::Error> {
    sqlx::query_as::<_, OperatorRow>("SELECT * FROM operators ORDER BY created_at ASC")
        .fetch_all(pool)
        .await
}

pub async fn find_operator_by_token_hash(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<OperatorRow>, sqlx::Error> {
    sqlx::query_as::<_, OperatorRow>("SELECT * FROM operators WHERE token_hash = $1")
        .bind(token_hash)
        .fetch_optional(pool)
        .await
}

pub async fn insert_operator(
    pool: &PgPool,
    id: Uuid,
    name: &str,
    role: &str,
    password_hash: &str,
    token_hash: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO operators (id, name, role, password_hash, token_hash, created_at) \
         VALUES ($1, $2, $3, $4, $5, now())",
    )
    .bind(id)
    .bind(name)
    .bind(role)
    .bind(password_hash)
    .bind(token_hash)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn set_operator_token_hash(
    pool: &PgPool,
    id: Uuid,
    token_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE operators SET token_hash = $2 WHERE id = $1")
        .bind(id)
        .bind(token_hash)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_operator(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM operators WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

// -------------------------------------------------------------- credentials

pub async fn insert_credential(pool: &PgPool, row: &CredentialRow) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO credentials (id, engagement_id, session_id, host, domain, username, secret, kind, source, created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(row.id)
    .bind(row.engagement_id)
    .bind(row.session_id)
    .bind(&row.host)
    .bind(&row.domain)
    .bind(&row.username)
    .bind(&row.secret)
    .bind(&row.kind)
    .bind(&row.source)
    .bind(row.created_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_credentials(
    pool: &PgPool,
    engagement_id: Uuid,
) -> Result<Vec<CredentialRow>, sqlx::Error> {
    sqlx::query_as::<_, CredentialRow>(
        "SELECT * FROM credentials WHERE engagement_id = $1 ORDER BY created_at DESC",
    )
    .bind(engagement_id)
    .fetch_all(pool)
    .await
}

pub async fn delete_credential(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM credentials WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

// --------------------------------------------------------------------- loot

pub async fn insert_loot(pool: &PgPool, row: &LootRow) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO loot (id, engagement_id, session_id, kind, name, size, sha256, data, created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(row.id)
    .bind(row.engagement_id)
    .bind(row.session_id)
    .bind(&row.kind)
    .bind(&row.name)
    .bind(row.size)
    .bind(&row.sha256)
    .bind(&row.data)
    .bind(row.created_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_loot(
    pool: &PgPool,
    engagement_id: Uuid,
    include_data: bool,
) -> Result<Vec<LootRow>, sqlx::Error> {
    if include_data {
        sqlx::query_as::<_, LootRow>(
            "SELECT * FROM loot WHERE engagement_id = $1 ORDER BY created_at DESC",
        )
        .bind(engagement_id)
        .fetch_all(pool)
        .await
    } else {
        sqlx::query_as::<_, LootRow>(
            "SELECT id, engagement_id, session_id, kind, name, size, sha256, NULL::bytea AS data, created_at \
             FROM loot WHERE engagement_id = $1 ORDER BY created_at DESC",
        )
        .bind(engagement_id)
        .fetch_all(pool)
        .await
    }
}

pub async fn delete_loot(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM loot WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

// ----------------------------------------------------------------- canaries

pub async fn insert_canary(pool: &PgPool, row: &CanaryRow) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO canaries (id, token, kind, note, triggered, triggered_at, created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(row.id)
    .bind(&row.token)
    .bind(&row.kind)
    .bind(&row.note)
    .bind(row.triggered)
    .bind(row.triggered_at)
    .bind(row.created_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_canaries(pool: &PgPool) -> Result<Vec<CanaryRow>, sqlx::Error> {
    sqlx::query_as::<_, CanaryRow>("SELECT * FROM canaries ORDER BY created_at DESC")
        .fetch_all(pool)
        .await
}

pub async fn trigger_canary_by_token(
    pool: &PgPool,
    token: &str,
) -> Result<Option<CanaryRow>, sqlx::Error> {
    let row = sqlx::query_as::<_, CanaryRow>(
        "UPDATE canaries SET triggered = TRUE, triggered_at = COALESCE(triggered_at, now()) \
         WHERE token = $1 RETURNING *",
    )
    .bind(token)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

// ----------------------------------------------------------------- reactions

pub async fn insert_reaction_rule(pool: &PgPool, row: &ReactionRuleRow) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO reaction_rules (id, event_kind, action, enabled, created_at) \
         VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(row.id)
    .bind(&row.event_kind)
    .bind(&row.action)
    .bind(row.enabled)
    .bind(row.created_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_reaction_rules(pool: &PgPool) -> Result<Vec<ReactionRuleRow>, sqlx::Error> {
    sqlx::query_as::<_, ReactionRuleRow>("SELECT * FROM reaction_rules ORDER BY created_at ASC")
        .fetch_all(pool)
        .await
}

pub async fn delete_reaction_rule(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM reaction_rules WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

// --------------------------------------------------------------- audit chain

/// Appends an audit entry, extending the tamper-evident hash chain.
///
/// `hash = sha256(prev_hash || actor || action || target || details || recorded_at)`
pub async fn append_audit(
    pool: &PgPool,
    actor: &str,
    action: &str,
    target: Option<&str>,
    details: serde_json::Value,
) -> Result<AuditLogRow, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Serialize appends: `FOR UPDATE` on the tip row cannot lock an empty
    // table and concurrent readers of the same tip would fork the chain.
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(AUDIT_CHAIN_LOCK)
        .execute(&mut *tx)
        .await?;

    let previous: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")
            .fetch_optional(&mut *tx)
            .await?;
    let prev_hash = previous.map(|(hash,)| hash);

    let recorded_at = OffsetDateTime::now_utc();
    let hash = compute_audit_hash(
        prev_hash.as_deref(),
        actor,
        action,
        target,
        &details,
        recorded_at,
    );

    let row: AuditLogRow = sqlx::query_as(
        "INSERT INTO audit_log (actor, action, target, details, prev_hash, hash, recorded_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *",
    )
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(&details)
    .bind(&prev_hash)
    .bind(&hash)
    .bind(recorded_at)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(row)
}

pub fn compute_audit_hash(
    prev_hash: Option<&[u8]>,
    actor: &str,
    action: &str,
    target: Option<&str>,
    details: &serde_json::Value,
    recorded_at: OffsetDateTime,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    if let Some(prev) = prev_hash {
        hasher.update(prev);
    }
    hasher.update(actor.as_bytes());
    hasher.update([0]);
    hasher.update(action.as_bytes());
    hasher.update([0]);
    hasher.update(target.unwrap_or("").as_bytes());
    hasher.update([0]);
    hasher.update(
        serde_json::to_string(details)
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update([0]);
    hasher.update(recorded_at.unix_timestamp_nanos().to_be_bytes());
    hasher.finalize().to_vec()
}

/// Verifies the entire audit chain; returns the number of verified entries.
pub async fn verify_audit_chain(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let rows = sqlx::query_as::<_, AuditLogRow>("SELECT * FROM audit_log ORDER BY id ASC")
        .fetch_all(pool)
        .await?;

    let mut prev: Option<Vec<u8>> = None;
    let mut verified = 0u64;
    for row in rows {
        let expected = compute_audit_hash(
            prev.as_deref(),
            &row.actor,
            &row.action,
            row.target.as_deref(),
            &row.details,
            row.recorded_at,
        );
        if expected != row.hash {
            return Err(sqlx::Error::Protocol(format!(
                "audit chain broken at entry {}",
                row.id
            )));
        }
        prev = Some(row.hash.clone());
        verified += 1;
    }
    Ok(verified)
}

/// Convenience wrapper used by the server to record actions.
pub async fn audit(
    pool: &PgPool,
    actor: &str,
    action: &str,
    target: Option<&str>,
    details: serde_json::Value,
) {
    if let Err(err) = append_audit(pool, actor, action, target, details).await {
        tracing::warn!(%err, action, "failed to append audit entry");
    }
}

/// Helper for tests and callers that only need a JSON payload.
pub fn details(payload: serde_json::Value) -> serde_json::Value {
    json!({ "payload": payload })
}

// -------------------------------------------------------------------- hosts

#[allow(clippy::too_many_arguments)]
pub async fn upsert_host(
    pool: &PgPool,
    id: Uuid,
    engagement_id: Uuid,
    ip: &str,
    hostname: &str,
    os: &str,
    ports: &serde_json::Value,
    source: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO hosts (id, engagement_id, ip, hostname, os, ports, source, discovered_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7, now()) \
         ON CONFLICT (engagement_id, ip) DO UPDATE SET \
            hostname = EXCLUDED.hostname, \
            os = EXCLUDED.os, \
            ports = EXCLUDED.ports, \
            source = EXCLUDED.source, \
            discovered_at = now()",
    )
    .bind(id)
    .bind(engagement_id)
    .bind(ip)
    .bind(hostname)
    .bind(os)
    .bind(ports)
    .bind(source)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_hosts(pool: &PgPool, engagement_id: Uuid) -> Result<Vec<HostRow>, sqlx::Error> {
    sqlx::query_as::<_, HostRow>("SELECT * FROM hosts WHERE engagement_id = $1 ORDER BY ip ASC")
        .bind(engagement_id)
        .fetch_all(pool)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_hash_is_deterministic_and_chains() {
        let now = OffsetDateTime::now_utc();
        let details = serde_json::json!({"action": "test"});

        let first = compute_audit_hash(None, "alice", "login", Some("server"), &details, now);
        let repeated = compute_audit_hash(None, "alice", "login", Some("server"), &details, now);
        assert_eq!(first, repeated, "hash must be deterministic");

        let second = compute_audit_hash(
            Some(&first),
            "bob",
            "task",
            Some("session-1"),
            &details,
            now,
        );
        assert_ne!(first, second, "chained hash must differ");

        let tampered = compute_audit_hash(None, "mallory", "login", Some("server"), &details, now);
        assert_ne!(first, tampered, "actor change must alter the hash");
    }
}
