//! Runtime beacon listeners.
//!
//! Beacon-facing transports (HTTP, QUIC, DNS, WireGuard) are not started with
//! the teamserver. Operators start and stop them after login through the
//! control plane, so ports can be chosen freely and conflicts surfaced in the
//! console instead of crashing the server at boot.

use crate::state::ServerState;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};
use uuid::Uuid;

pub const KINDS: [&str; 4] = ["http", "quic", "dns", "wireguard"];

struct ListenerEntry {
    id: String,
    kind: String,
    addr: SocketAddr,
    detail: String,
    shutdown: Option<oneshot::Sender<()>>,
}

#[derive(Default)]
pub struct ListenerRegistry {
    entries: Mutex<HashMap<String, ListenerEntry>>,
}

/// Snapshot returned to operators.
pub struct ListenerView {
    pub id: String,
    pub kind: String,
    pub addr: String,
    pub running: bool,
    pub detail: String,
}

impl ListenerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn list(&self) -> Vec<ListenerView> {
        let entries = self.entries.lock().await;
        let mut views: Vec<ListenerView> = entries
            .values()
            .map(|entry| ListenerView {
                id: entry.id.clone(),
                kind: entry.kind.clone(),
                addr: entry.addr.to_string(),
                running: true,
                detail: entry.detail.clone(),
            })
            .collect();
        views.sort_by(|a, b| (&a.kind, &a.addr).cmp(&(&b.kind, &b.addr)));
        views
    }

    async fn insert(
        &self,
        kind: &str,
        addr: SocketAddr,
        detail: String,
        shutdown: oneshot::Sender<()>,
    ) -> String {
        let id = Uuid::new_v4().to_string();
        self.entries.lock().await.insert(
            id.clone(),
            ListenerEntry {
                id: id.clone(),
                kind: kind.to_string(),
                addr,
                detail,
                shutdown: Some(shutdown),
            },
        );
        id
    }

    pub async fn stop(&self, id: &str) -> bool {
        let entry = self.entries.lock().await.remove(id);
        match entry {
            Some(mut entry) => {
                if let Some(shutdown) = entry.shutdown.take() {
                    let _ = shutdown.send(());
                }
                true
            }
            None => false,
        }
    }

    pub async fn stop_all(&self) {
        let entries: Vec<ListenerEntry> =
            self.entries.lock().await.drain().map(|(_, v)| v).collect();
        for mut entry in entries {
            if let Some(shutdown) = entry.shutdown.take() {
                let _ = shutdown.send(());
            }
        }
    }

    pub async fn is_empty(&self) -> bool {
        self.entries.lock().await.is_empty()
    }
}

/// Starts a listener of `kind` on `addr`. Returns the registry id, the actual
/// local address and an optional human-readable detail (e.g. WireGuard key).
pub async fn start(
    state: &Arc<ServerState>,
    kind: &str,
    addr: SocketAddr,
    dns_zone: &str,
) -> Result<(String, SocketAddr, String)> {
    match kind {
        "http" => start_http(state, addr).await,
        "quic" => start_quic(state, addr).await,
        "dns" => start_dns(state, addr, dns_zone).await,
        "wireguard" => start_wireguard(state, addr).await,
        other => anyhow::bail!("unsupported listener kind {other:?}"),
    }
}

async fn start_http(
    state: &Arc<ServerState>,
    addr: SocketAddr,
) -> Result<(String, SocketAddr, String)> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind HTTP listener {addr}"))?;
    let local = listener.local_addr()?;
    let router = crate::http::router(state.clone(), state.profiles.clone());
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    tokio::spawn(async move {
        let result = axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
        if let Err(err) = result {
            tracing::error!(%err, "HTTP beacon listener exited");
        }
    });
    let id = state
        .listeners
        .insert("http", local, String::new(), shutdown_tx)
        .await;
    Ok((id, local, String::new()))
}

async fn start_quic(
    state: &Arc<ServerState>,
    addr: SocketAddr,
) -> Result<(String, SocketAddr, String)> {
    let tls = shikra_transport::tls::ensure_tls_material(&state.state_dir)?;
    let endpoint = crate::quic::server_endpoint(&tls.server_cert_pem, &tls.server_key_pem, addr)?;
    let local = endpoint.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let serve_endpoint = endpoint.clone();
    let state_clone = state.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = crate::quic::serve(serve_endpoint, state_clone) => {}
            _ = &mut shutdown_rx => {
                endpoint.close(0u32.into(), b"listener stopped");
            }
        }
    });
    let id = state
        .listeners
        .insert("quic", local, String::new(), shutdown_tx)
        .await;
    Ok((id, local, String::new()))
}

async fn start_dns(
    state: &Arc<ServerState>,
    addr: SocketAddr,
    zone: &str,
) -> Result<(String, SocketAddr, String)> {
    let socket = tokio::net::UdpSocket::bind(addr)
        .await
        .with_context(|| format!("failed to bind DNS listener {addr}"))?;
    let local = socket.local_addr()?;
    let zone = if zone.trim().is_empty() {
        "dns.shikra".to_string()
    } else {
        zone.trim().to_string()
    };
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let state_clone = state.clone();
    let serve_zone = zone.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = crate::dns::serve(socket, state_clone, serve_zone) => {}
            _ = &mut shutdown_rx => {}
        }
    });
    let id = state
        .listeners
        .insert("dns", local, format!("zone {zone}"), shutdown_tx)
        .await;
    Ok((id, local, format!("zone {zone}")))
}

async fn start_wireguard(
    state: &Arc<ServerState>,
    addr: SocketAddr,
) -> Result<(String, SocketAddr, String)> {
    let socket = tokio::net::UdpSocket::bind(addr)
        .await
        .with_context(|| format!("failed to bind WireGuard listener {addr}"))?;
    let local = socket.local_addr()?;
    let (server_private, server_public) =
        shikra_transport::wg::load_or_create_server_identity(&state.state_dir)
            .context("failed to load WireGuard key")?;
    let _ = server_private;
    let detail = shikra_transport::tls::hex_encode(server_public.as_bytes());
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let state_clone = state.clone();
    let state_dir = state.state_dir.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = crate::wg::serve(socket, state_clone, state_dir.to_path_buf()) => {}
            _ = &mut shutdown_rx => {}
        }
    });
    let id = state
        .listeners
        .insert("wireguard", local, detail.clone(), shutdown_tx)
        .await;
    Ok((id, local, detail))
}
