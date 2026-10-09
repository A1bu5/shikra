use crate::error::{Error, Result};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

impl LogFormat {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => Err(Error::Config(format!("unsupported log format {other:?}"))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub grpc_addr: SocketAddr,
    pub health_addr: SocketAddr,
    pub http_addr: SocketAddr,
    pub quic_addr: SocketAddr,
    pub dns_addr: SocketAddr,
    pub wg_addr: SocketAddr,
    pub dns_zone: String,
    pub database_url: String,
    pub state_dir: PathBuf,
    pub log_format: LogFormat,
}

impl ServerConfig {
    pub fn from_env() -> Result<Self> {
        let grpc_addr = env_or("SHIKRA_GRPC_ADDR", "127.0.0.1:8443")
            .parse::<SocketAddr>()
            .map_err(|err| Error::Config(format!("invalid SHIKRA_GRPC_ADDR: {err}")))?;

        let health_addr = env_or("SHIKRA_HEALTH_ADDR", "127.0.0.1:8081")
            .parse::<SocketAddr>()
            .map_err(|err| Error::Config(format!("invalid SHIKRA_HEALTH_ADDR: {err}")))?;

        let http_addr = env_or("SHIKRA_HTTP_ADDR", "127.0.0.1:8080")
            .parse::<SocketAddr>()
            .map_err(|err| Error::Config(format!("invalid SHIKRA_HTTP_ADDR: {err}")))?;

        let quic_addr = env_or("SHIKRA_QUIC_ADDR", "127.0.0.1:8444")
            .parse::<SocketAddr>()
            .map_err(|err| Error::Config(format!("invalid SHIKRA_QUIC_ADDR: {err}")))?;

        let dns_addr = env_or("SHIKRA_DNS_ADDR", "127.0.0.1:5353")
            .parse::<SocketAddr>()
            .map_err(|err| Error::Config(format!("invalid SHIKRA_DNS_ADDR: {err}")))?;

        let wg_addr = env_or("SHIKRA_WG_ADDR", "127.0.0.1:51820")
            .parse::<SocketAddr>()
            .map_err(|err| Error::Config(format!("invalid SHIKRA_WG_ADDR: {err}")))?;

        let database_url = std::env::var("SHIKRA_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .map_err(|_| {
                Error::Config(
                    "SHIKRA_DATABASE_URL (or DATABASE_URL) is required \
                     (see deploy/docker-compose.yml)"
                        .into(),
                )
            })?;

        let state_dir = PathBuf::from(env_or("SHIKRA_STATE_DIR", "./run"));

        Ok(Self {
            grpc_addr,
            health_addr,
            http_addr,
            quic_addr,
            dns_addr,
            wg_addr,
            dns_zone: env_or("SHIKRA_DNS_ZONE", "dns.shikra"),
            database_url,
            state_dir,
            log_format: LogFormat::parse(&env_or("SHIKRA_LOG_FORMAT", "text"))?,
        })
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
