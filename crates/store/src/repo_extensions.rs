//! Extension registry persistence.

use crate::models::ExtensionRow;
use sqlx::PgPool;
use uuid::Uuid;

/// Upserts an extension and returns the persisted row (without the payload).
///
/// On conflict the existing row keeps its id and creation time; callers must
/// use the returned row rather than the input when reporting back.
pub async fn insert_extension(
    pool: &PgPool,
    row: &ExtensionRow,
) -> Result<ExtensionRow, sqlx::Error> {
    sqlx::query_as::<_, ExtensionRow>(
        "INSERT INTO extensions \
         (id, engagement_id, name, version, kind, platform, architecture, description, \
          sha256, size, signer, manifest, payload, installed_by, created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) \
         ON CONFLICT (engagement_id, name, version) DO UPDATE SET \
          kind = EXCLUDED.kind, platform = EXCLUDED.platform, \
          architecture = EXCLUDED.architecture, description = EXCLUDED.description, \
          sha256 = EXCLUDED.sha256, size = EXCLUDED.size, signer = EXCLUDED.signer, \
          manifest = EXCLUDED.manifest, payload = EXCLUDED.payload, \
          installed_by = EXCLUDED.installed_by, created_at = now() \
         RETURNING id, engagement_id, name, version, kind, platform, architecture, \
                   description, sha256, size, signer, manifest, NULL::bytea AS payload, \
                   installed_by, created_at",
    )
    .bind(row.id)
    .bind(row.engagement_id)
    .bind(&row.name)
    .bind(&row.version)
    .bind(&row.kind)
    .bind(&row.platform)
    .bind(&row.architecture)
    .bind(&row.description)
    .bind(&row.sha256)
    .bind(row.size)
    .bind(&row.signer)
    .bind(&row.manifest)
    .bind(row.payload.as_deref())
    .bind(&row.installed_by)
    .bind(row.created_at)
    .fetch_one(pool)
    .await
}

pub async fn list_extensions(
    pool: &PgPool,
    engagement_id: Uuid,
) -> Result<Vec<ExtensionRow>, sqlx::Error> {
    sqlx::query_as::<_, ExtensionRow>(
        "SELECT id, engagement_id, name, version, kind, platform, architecture, description, \
                sha256, size, signer, manifest, NULL::bytea AS payload, installed_by, created_at \
         FROM extensions WHERE engagement_id = $1 ORDER BY name ASC, version ASC",
    )
    .bind(engagement_id)
    .fetch_all(pool)
    .await
}

pub async fn get_extension(
    pool: &PgPool,
    engagement_id: Uuid,
    id: Uuid,
) -> Result<Option<ExtensionRow>, sqlx::Error> {
    sqlx::query_as::<_, ExtensionRow>(
        "SELECT * FROM extensions WHERE engagement_id = $1 AND id = $2",
    )
    .bind(engagement_id)
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn find_extension_by_name(
    pool: &PgPool,
    engagement_id: Uuid,
    name: &str,
    platform: Option<&str>,
) -> Result<Option<ExtensionRow>, sqlx::Error> {
    match platform {
        Some(platform) => {
            sqlx::query_as::<_, ExtensionRow>(
                "SELECT * FROM extensions WHERE engagement_id = $1 AND name = $2 \
                 AND platform IN ($3, 'any') ORDER BY created_at DESC LIMIT 1",
            )
            .bind(engagement_id)
            .bind(name)
            .bind(platform)
            .fetch_optional(pool)
            .await
        }
        None => {
            sqlx::query_as::<_, ExtensionRow>(
                "SELECT * FROM extensions WHERE engagement_id = $1 AND name = $2 \
                 ORDER BY created_at DESC LIMIT 1",
            )
            .bind(engagement_id)
            .bind(name)
            .fetch_optional(pool)
            .await
        }
    }
}

pub async fn delete_extension(
    pool: &PgPool,
    engagement_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM extensions WHERE engagement_id = $1 AND id = $2")
        .bind(engagement_id)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
