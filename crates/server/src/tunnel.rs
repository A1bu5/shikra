//! Tunnel routing between operator streams and agent sessions.
//!
//! # Pivot transports
//!
//! - `tcp`: the agent binds a TCP listener; every connection is announced to
//!   the teamserver, which dials the configured destination and bridges bytes.
//!   This is the portable default and supports arbitrary hop chains because
//!   each hop's agent keeps its own C2 channel to the teamserver.
//! - `pipe`: on Windows agents the listener is a named pipe
//!   (`\\.\pipe\<name>`); accepted connections are bridged identically, so the
//!   teamserver stays transport-agnostic. Evaluation conclusion: a cross
//!   platform teamserver cannot dial SMB named pipes on the target directly
//!   (that requires SMB client support or an implant relay), so named-pipe
//!   pivots are exposed from the agent side and downstream traffic is carried
//!   through the agent's existing C2 channel. Where an SMB-reachable named
//!   pipe is required, the TCP pivot over an SMB-forwarded port is the
//!   supported alternative.

use shikra_proto::v1::{
    agent_message, operator_tunnel_frame, AgentMessage, OperatorTunnelFrame, TunnelAccept,
    TunnelClose, TunnelData, TunnelOpen,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

/// Routes tunnel frames between operator streams and agent sessions.
///
/// Each operator `StreamTunnel` call owns one or more tunnel ids. Frames from
/// the agent are looked up by `(session_id, tunnel_id)` and forwarded to the
/// matching operator channel. Frames from operators are sealed and pushed to
/// the agent via the session handle.
#[derive(Default)]
pub struct TunnelHub {
    routes: RwLock<HashMap<(String, String), mpsc::Sender<OperatorTunnelFrame>>>,
}

#[derive(Debug)]
pub struct ForwardRule {
    pub id: String,
    pub session_id: String,
    pub bind: String,
    pub to: String,
    /// "tcp" (default) or "pipe" for a Windows named-pipe listener.
    pub transport: String,
    pub connections: AtomicU64,
}

impl ForwardRule {
    pub fn record_connection(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Default)]
pub struct ForwardRegistry {
    rules: RwLock<HashMap<String, Arc<ForwardRule>>>,
}

impl TunnelHub {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn register(
        &self,
        session_id: &str,
        tunnel_id: &str,
        sender: mpsc::Sender<OperatorTunnelFrame>,
    ) {
        self.routes
            .write()
            .await
            .insert((session_id.to_string(), tunnel_id.to_string()), sender);
    }

    pub async fn unregister(&self, session_id: &str, tunnel_id: &str) {
        self.routes
            .write()
            .await
            .remove(&(session_id.to_string(), tunnel_id.to_string()));
    }

    /// Returns true when the frame was routed to an operator stream.
    pub async fn deliver_from_agent(&self, session_id: &str, message: &AgentMessage) -> bool {
        let (tunnel_id, frame) = match &message.body {
            Some(agent_message::Body::TunnelData(data)) => (
                data.tunnel_id.clone(),
                OperatorTunnelFrame {
                    session_id: session_id.to_string(),
                    tunnel_id: data.tunnel_id.clone(),
                    body: Some(operator_tunnel_frame::Body::Data(TunnelData {
                        tunnel_id: data.tunnel_id.clone(),
                        data: data.data.clone(),
                    })),
                },
            ),
            Some(agent_message::Body::TunnelAccept(accept)) => (
                accept.tunnel_id.clone(),
                OperatorTunnelFrame {
                    session_id: session_id.to_string(),
                    tunnel_id: accept.tunnel_id.clone(),
                    body: Some(operator_tunnel_frame::Body::Accept(TunnelAccept {
                        tunnel_id: accept.tunnel_id.clone(),
                        remote_addr: accept.remote_addr.clone(),
                        bind: accept.bind.clone(),
                    })),
                },
            ),
            Some(agent_message::Body::TunnelClose(close)) => (
                close.tunnel_id.clone(),
                OperatorTunnelFrame {
                    session_id: session_id.to_string(),
                    tunnel_id: close.tunnel_id.clone(),
                    body: Some(operator_tunnel_frame::Body::Close(TunnelClose {
                        tunnel_id: close.tunnel_id.clone(),
                        reason: close.reason.clone(),
                    })),
                },
            ),
            _ => return false,
        };

        let sender = self
            .routes
            .read()
            .await
            .get(&(session_id.to_string(), tunnel_id.clone()))
            .cloned();

        match sender {
            Some(sender) => {
                if matches!(frame.body, Some(operator_tunnel_frame::Body::Close(_))) {
                    self.unregister(session_id, &tunnel_id).await;
                }
                sender.send(frame).await.is_ok()
            }
            None => false,
        }
    }
}

impl ForwardRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn add(
        &self,
        session_id: &str,
        bind: &str,
        to: &str,
        transport: &str,
    ) -> Arc<ForwardRule> {
        let rule = Arc::new(ForwardRule {
            id: Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            bind: bind.to_string(),
            to: to.to_string(),
            transport: transport.to_string(),
            connections: AtomicU64::new(0),
        });
        self.rules
            .write()
            .await
            .insert(rule.id.clone(), rule.clone());
        rule
    }

    pub async fn remove(&self, id: &str) -> Option<Arc<ForwardRule>> {
        self.rules.write().await.remove(id)
    }

    pub async fn find_by_bind(&self, session_id: &str, bind: &str) -> Option<Arc<ForwardRule>> {
        self.rules
            .read()
            .await
            .values()
            .find(|rule| rule.session_id == session_id && rule.bind == bind)
            .cloned()
    }

    pub async fn list(&self) -> Vec<Arc<ForwardRule>> {
        self.rules.read().await.values().cloned().collect()
    }
}

/// Builds an agent-facing tunnel frame for the given session.
pub fn to_agent_message(
    body: operator_tunnel_frame::Body,
    tunnel_id: &str,
    _session_id: &str,
) -> AgentMessage {
    let body = match body {
        operator_tunnel_frame::Body::Open(open) => agent_message::Body::TunnelOpen(TunnelOpen {
            tunnel_id: tunnel_id.to_string(),
            host: open.host,
            port: open.port,
        }),
        operator_tunnel_frame::Body::Data(data) => agent_message::Body::TunnelData(TunnelData {
            tunnel_id: tunnel_id.to_string(),
            data: data.data,
        }),
        operator_tunnel_frame::Body::Close(close) => {
            agent_message::Body::TunnelClose(TunnelClose {
                tunnel_id: tunnel_id.to_string(),
                reason: close.reason,
            })
        }
        operator_tunnel_frame::Body::Accept(accept) => {
            agent_message::Body::TunnelAccept(TunnelAccept {
                tunnel_id: tunnel_id.to_string(),
                remote_addr: accept.remote_addr,
                bind: accept.bind,
            })
        }
    };
    AgentMessage { body: Some(body) }
}

pub type SharedTunnelHub = Arc<TunnelHub>;
pub type SharedForwardRegistry = Arc<ForwardRegistry>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hub_routes_data_between_operator_and_agent() {
        let hub = TunnelHub::new();
        let (tx, mut rx) = mpsc::channel(8);
        hub.register("s-1", "t-1", tx).await;

        let message = AgentMessage {
            body: Some(agent_message::Body::TunnelData(TunnelData {
                tunnel_id: "t-1".into(),
                data: b"hello".to_vec(),
            })),
        };
        assert!(hub.deliver_from_agent("s-1", &message).await);

        let frame = rx.recv().await.expect("frame");
        assert_eq!(frame.tunnel_id, "t-1");
        match frame.body {
            Some(operator_tunnel_frame::Body::Data(data)) => assert_eq!(data.data, b"hello"),
            other => panic!("unexpected frame: {other:?}"),
        }
    }

    #[tokio::test]
    async fn hub_unroutes_after_close() {
        let hub = TunnelHub::new();
        let (tx, _rx) = mpsc::channel(8);
        hub.register("s-1", "t-1", tx).await;

        let close = AgentMessage {
            body: Some(agent_message::Body::TunnelClose(TunnelClose {
                tunnel_id: "t-1".into(),
                reason: "done".into(),
            })),
        };
        assert!(hub.deliver_from_agent("s-1", &close).await);

        let data = AgentMessage {
            body: Some(agent_message::Body::TunnelData(TunnelData {
                tunnel_id: "t-1".into(),
                data: b"late".to_vec(),
            })),
        };
        assert!(!hub.deliver_from_agent("s-1", &data).await);
    }

    #[tokio::test]
    async fn forward_registry_finds_by_bind() {
        let registry = ForwardRegistry::new();
        let rule = registry
            .add("s-1", "127.0.0.1:9000", "127.0.0.1:8080", "tcp")
            .await;
        let found = registry
            .find_by_bind("s-1", "127.0.0.1:9000")
            .await
            .expect("rule");
        assert_eq!(found.id, rule.id);
        assert!(registry
            .find_by_bind("s-2", "127.0.0.1:9000")
            .await
            .is_none());
    }
}
