use anyhow::Context;
use clap::Parser;
use shikra_core::config::{LogFormat, ServerConfig};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "shikra-server", version, about = "Shikra C2 teamserver")]
struct Cli {
    /// Initialize the state directory (CA, server certificate, enroll and
    /// operator tokens, identity keys) and print the material as JSON, then
    /// exit. Safe to run repeatedly; existing material is reused.
    #[arg(long)]
    bootstrap: bool,

    /// Directory holding teamserver state (CA, keys, tokens, profiles).
    #[arg(long, env = "SHIKRA_STATE_DIR", default_value = "./run")]
    state_dir: PathBuf,

    /// PostgreSQL connection string.
    #[arg(long, env = "SHIKRA_DATABASE_URL")]
    database_url: Option<String>,

    /// gRPC listener (operator + agent link).
    #[arg(long, env = "SHIKRA_GRPC_ADDR", default_value = "127.0.0.1:8443")]
    grpc_addr: SocketAddr,

    /// Health/ready listener.
    #[arg(long, env = "SHIKRA_HEALTH_ADDR", default_value = "127.0.0.1:8081")]
    health_addr: SocketAddr,

    /// Log format: text or json.
    #[arg(long, env = "SHIKRA_LOG_FORMAT", default_value = "text")]
    log_format: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.bootstrap {
        let bootstrap = shikra_server::bootstrap::bootstrap(&cli.state_dir)
            .with_context(|| format!("failed to initialize {}", cli.state_dir.display()))?;
        let join = |name: &str| cli.state_dir.join(name).display().to_string();
        let material = serde_json::json!({
            "state_dir": cli.state_dir.display().to_string(),
            "ca_pem": join("ca.pem"),
            "server_cert": join("server.pem"),
            "server_key": join("server-key.pem"),
            "enroll_token_file": join("enroll.token"),
            "operator_token_file": join("operator.token"),
            "server_identity": join("server-identity.pub"),
            "enroll_token": bootstrap.enroll_token,
            "operator_token": bootstrap.operator_token,
            "server_identity_hex": bootstrap.server_identity_hex(),
            "armory_public_hex": shikra_transport::tls::hex_encode(&bootstrap.armory_public),
        });
        println!("{material}");
        return Ok(());
    }

    let database_url = cli
        .database_url
        .clone()
        .context("DATABASE_URL is required (pass --database-url or set the env var)")?;
    let log_format = LogFormat::parse(&cli.log_format)?;
    let config = ServerConfig {
        grpc_addr: cli.grpc_addr,
        health_addr: cli.health_addr,
        // Beacon listener addresses are chosen at runtime from the console.
        http_addr: "127.0.0.1:8080".parse().expect("static address"),
        quic_addr: "127.0.0.1:8444".parse().expect("static address"),
        dns_addr: "127.0.0.1:5353".parse().expect("static address"),
        wg_addr: "127.0.0.1:51820".parse().expect("static address"),
        dns_zone: "dns.shikra".into(),
        database_url,
        state_dir: cli.state_dir.clone(),
        log_format,
    };
    shikra_server::tracing_from_config(&config);
    shikra_server::run(config).await
}
