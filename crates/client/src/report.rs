//! Engagement report generation: aggregates teamserver state into Markdown.

use crate::OperatorClient;
use anyhow::{Context, Result};
use std::fmt::Write as _;

/// Generates a Markdown engagement report from the connected teamserver.
pub async fn generate_report(client: &mut OperatorClient) -> Result<String> {
    let version = client.version().await?;
    let sessions = client.sessions().await?;
    let credentials = client.list_credentials().await?;
    let loot = client.list_loot().await?;
    let canaries = client.list_canaries().await?;
    let audit = client.verify_audit().await?;
    let mut tasks = Vec::new();
    for session in &sessions {
        match client.list_tasks(Some(&session.id), 200).await {
            Ok(session_tasks) => tasks.extend(session_tasks),
            Err(err) => {
                eprintln!("warning: failed to list tasks for {}: {err}", session.id);
            }
        }
    }

    let generated_at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".into());

    let mut report = String::new();
    writeln!(report, "# Shikra Engagement Report")?;
    writeln!(report)?;
    writeln!(report, "- Generated: {generated_at}")?;
    writeln!(report, "- Teamserver: v{version}")?;
    writeln!(report, "- Sessions: {}", sessions.len())?;
    writeln!(report, "- Tasks: {}", tasks.len())?;
    writeln!(report, "- Credentials: {}", credentials.len())?;
    writeln!(report, "- Loot items: {}", loot.len())?;
    writeln!(report, "- Canaries: {}", canaries.len())?;
    writeln!(
        report,
        "- Audit chain: {} ({} entries)",
        if audit.valid { "valid" } else { "BROKEN" },
        audit.entries
    )?;

    writeln!(report)?;
    writeln!(report, "## Sessions")?;
    writeln!(report)?;
    if sessions.is_empty() {
        writeln!(report, "_No sessions recorded._")?;
    } else {
        writeln!(report, "| Session | Host | User | Platform | Last seen |")?;
        writeln!(report, "|---|---|---|---|---|")?;
        for session in &sessions {
            let last_seen = session
                .last_seen
                .as_ref()
                .map(|ts| format_unix(ts.seconds))
                .unwrap_or_else(|| "-".into());
            writeln!(
                report,
                "| `{}` | {} | {} | {}/{} | {} |",
                short_id(&session.id),
                escape(&session.hostname),
                escape(&session.username),
                platform_name(session.platform),
                architecture_name(session.architecture),
                last_seen
            )?;
        }
    }

    writeln!(report)?;
    writeln!(report, "## Activity Timeline")?;
    writeln!(report)?;
    if tasks.is_empty() {
        writeln!(report, "_No tasks recorded._")?;
    } else {
        let mut sorted = tasks.clone();
        sorted.sort_by_key(|task| task.created_at.map(|ts| ts.seconds).unwrap_or_default());
        writeln!(report, "| Time | Session | Command | State | Exit |")?;
        writeln!(report, "|---|---|---|---|---|")?;
        for task in sorted.iter().take(200) {
            let created = task
                .created_at
                .as_ref()
                .map(|ts| format_unix(ts.seconds))
                .unwrap_or_else(|| "-".into());
            writeln!(
                report,
                "| {} | `{}` | {} | {} | {} |",
                created,
                short_id(&task.session_id),
                escape(&task.command),
                task_state(task.state),
                task.exit_code
            )?;
        }
    }

    writeln!(report)?;
    writeln!(report, "## Credentials")?;
    writeln!(report)?;
    if credentials.is_empty() {
        writeln!(report, "_No credentials collected._")?;
    } else {
        writeln!(report, "| Host | Username | Type | Secret |")?;
        writeln!(report, "|---|---|---|---|")?;
        for credential in &credentials {
            writeln!(
                report,
                "| {} | {} | {} | `{}` |",
                escape(&credential.host),
                escape(&credential.username),
                escape(&credential.kind),
                escape(&credential.secret)
            )?;
        }
    }

    writeln!(report)?;
    writeln!(report, "## Loot")?;
    writeln!(report)?;
    if loot.is_empty() {
        writeln!(report, "_No loot collected._")?;
    } else {
        writeln!(report, "| Name | Kind | Size | SHA-256 |")?;
        writeln!(report, "|---|---|---|---|")?;
        for item in &loot {
            writeln!(
                report,
                "| {} | {} | {} | `{}` |",
                escape(&item.name),
                escape(&item.kind),
                item.size,
                item.sha256
            )?;
        }
    }

    writeln!(report)?;
    writeln!(report, "## Canaries")?;
    writeln!(report)?;
    if canaries.is_empty() {
        writeln!(report, "_No canaries deployed._")?;
    } else {
        writeln!(report, "| Kind | Note | Triggered |")?;
        writeln!(report, "|---|---|---|")?;
        for canary in &canaries {
            writeln!(
                report,
                "| {} | {} | {} |",
                escape(&canary.kind),
                escape(&canary.note),
                if canary.triggered { "yes" } else { "no" }
            )?;
        }
    }

    writeln!(report)?;
    writeln!(report, "---")?;
    writeln!(
        report,
        "_Generated by Shikra Console. Handle according to engagement rules of engagement._"
    )?;

    Ok(report)
}

fn short_id(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}

fn escape(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

fn format_unix(seconds: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .map(|ts| {
            ts.format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| seconds.to_string())
        })
        .unwrap_or_else(|_| seconds.to_string())
}

fn platform_name(value: i32) -> &'static str {
    use shikra_proto::v1::Platform;
    match Platform::try_from(value) {
        Ok(Platform::Windows) => "windows",
        Ok(Platform::Linux) => "linux",
        Ok(Platform::Macos) => "macos",
        _ => "unknown",
    }
}

fn architecture_name(value: i32) -> &'static str {
    use shikra_proto::v1::Architecture;
    match Architecture::try_from(value) {
        Ok(Architecture::X8664) => "x86_64",
        Ok(Architecture::Aarch64) => "aarch64",
        _ => "unknown",
    }
}

fn task_state(value: i32) -> &'static str {
    use shikra_proto::v1::TaskState;
    match TaskState::try_from(value) {
        Ok(TaskState::Completed) => "completed",
        Ok(TaskState::Failed) => "failed",
        Ok(TaskState::Cancelled) => "cancelled",
        Ok(TaskState::Running) => "running",
        Ok(TaskState::Dispatched) => "dispatched",
        _ => "pending",
    }
}

/// Writes the report to the given path, or stdout when `output` is `None`.
pub async fn save_report(
    client: &mut OperatorClient,
    output: Option<&std::path::Path>,
) -> Result<()> {
    let report = generate_report(client).await?;
    match output {
        Some(path) => {
            tokio::fs::write(path, &report)
                .await
                .with_context(|| format!("failed to write {}", path.display()))?;
            println!(
                "report written to {} ({} bytes)",
                path.display(),
                report.len()
            );
        }
        None => print!("{report}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn short_id_truncates() {
        assert_eq!(super::short_id("1234567890"), "12345678");
        assert_eq!(super::short_id("abc"), "abc");
    }

    #[test]
    fn escape_pipes() {
        assert_eq!(super::escape("a|b\nc"), "a\\|b c");
    }
}
