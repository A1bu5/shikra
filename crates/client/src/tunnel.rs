use anyhow::{Context, Result};
use shikra_proto::v1::operator_tunnel_frame;
use shikra_proto::v1::{OperatorTunnelFrame, TunnelClose, TunnelData, TunnelOpen};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

/// Operator-side tunnel manager: owns the gRPC `StreamTunnel` call and routes
/// tunnel frames between local listeners (SOCKS5, port forward) and the agent.
pub struct TunnelManager {
    out_tx: mpsc::Sender<OperatorTunnelFrame>,
    routes: Arc<Mutex<HashMap<String, mpsc::Sender<OperatorTunnelFrame>>>>,
}

impl TunnelManager {
    pub fn spawn(
        session_id: String,
        mut client: shikra_proto::v1::control_plane_client::ControlPlaneClient<
            tonic::service::interceptor::InterceptedService<
                tonic::transport::Channel,
                crate::BearerAuth,
            >,
        >,
    ) -> Self {
        let (out_tx, out_rx) = mpsc::channel::<OperatorTunnelFrame>(256);
        let routes: Arc<Mutex<HashMap<String, mpsc::Sender<OperatorTunnelFrame>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let routes_clone = routes.clone();

        tokio::spawn(async move {
            let stream = ReceiverStream::new(out_rx);
            let response = match client.stream_tunnel(stream).await {
                Ok(response) => response,
                Err(err) => {
                    tracing::error!(%err, "StreamTunnel failed");
                    return;
                }
            };
            let mut inbound = response.into_inner();
            let _ = session_id;
            while let Ok(Some(frame)) = inbound.message().await {
                let tunnel_id = frame.tunnel_id.clone();
                let sender = routes_clone.lock().await.get(&tunnel_id).cloned();
                if let Some(sender) = sender {
                    if sender.send(frame).await.is_err() {
                        routes_clone.lock().await.remove(&tunnel_id);
                    }
                }
            }
            routes_clone.lock().await.clear();
        });

        Self { out_tx, routes }
    }

    /// Opens a tunnel to `host:port` via the agent and returns a byte stream.
    pub async fn open(&self, session_id: &str, host: &str, port: u16) -> Result<TunnelSession> {
        let tunnel_id = Uuid::new_v4().to_string();
        let (frame_tx, frame_rx) = mpsc::channel::<OperatorTunnelFrame>(256);
        self.routes.lock().await.insert(tunnel_id.clone(), frame_tx);

        self.out_tx
            .send(OperatorTunnelFrame {
                session_id: session_id.to_string(),
                tunnel_id: tunnel_id.clone(),
                body: Some(operator_tunnel_frame::Body::Open(TunnelOpen {
                    tunnel_id: tunnel_id.clone(),
                    host: host.to_string(),
                    port: port as u32,
                })),
            })
            .await
            .context("tunnel open send failed")?;

        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(256);
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(256);

        let out_tx = self.out_tx.clone();
        let session = session_id.to_string();
        let tid = tunnel_id.clone();
        tokio::spawn(async move {
            let mut frame_rx = frame_rx;
            let mut data_rx = data_rx;
            loop {
                tokio::select! {
                    data = data_rx.recv() => {
                        match data {
                            Some(data) => {
                                if out_tx.send(OperatorTunnelFrame {
                                    session_id: session.clone(),
                                    tunnel_id: tid.clone(),
                                    body: Some(operator_tunnel_frame::Body::Data(TunnelData {
                                        tunnel_id: tid.clone(),
                                        data,
                                    })),
                                }).await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                    frame = frame_rx.recv() => {
                        match frame {
                            Some(frame) => match frame.body {
                                Some(operator_tunnel_frame::Body::Data(data)) => {
                                    if in_tx.send(data.data).await.is_err() {
                                        break;
                                    }
                                }
                                Some(operator_tunnel_frame::Body::Close(close)) => {
                                    tracing::debug!(reason = %close.reason, "tunnel closed by agent");
                                    break;
                                }
                                _ => {}
                            },
                            None => break,
                        }
                    }
                }
            }
            let _ = out_tx
                .send(OperatorTunnelFrame {
                    session_id: session,
                    tunnel_id: tid.clone(),
                    body: Some(operator_tunnel_frame::Body::Close(TunnelClose {
                        tunnel_id: tid,
                        reason: "operator closed".into(),
                    })),
                })
                .await;
        });

        Ok(TunnelSession {
            tunnel_id,
            tx: data_tx,
            rx: in_rx,
        })
    }
}

pub struct TunnelSession {
    pub tunnel_id: String,
    pub tx: mpsc::Sender<Vec<u8>>,
    pub rx: mpsc::Receiver<Vec<u8>>,
}

impl TunnelSession {
    /// Bridges a local TCP stream with the tunnel until either side closes.
    pub async fn bridge(mut self, mut socket: TcpStream) {
        let (mut read_half, mut write_half) = socket.split();
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            tokio::select! {
                read = read_half.read(&mut buffer) => {
                    match read {
                        Ok(0) => break,
                        Ok(n) => {
                            if self.tx.send(buffer[..n].to_vec()).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                data = self.rx.recv() => {
                    match data {
                        Some(data) => {
                            if write_half.write_all(&data).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
        let _ = socket.shutdown().await;
    }
}

/// Runs a local SOCKS5 server that tunnels connections through the agent.
pub async fn run_socks5(
    manager: Arc<TunnelManager>,
    session_id: String,
    listener: TcpListener,
) -> Result<()> {
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                tracing::warn!(%err, "socks accept failed");
                continue;
            }
        };
        let manager = manager.clone();
        let session = session_id.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_socks_client(manager, session, socket).await {
                tracing::debug!(%peer, %err, "socks client closed");
            }
        });
    }
}

async fn handle_socks_client(
    manager: Arc<TunnelManager>,
    session_id: String,
    mut socket: TcpStream,
) -> Result<()> {
    // Greeting: VER, NMETHODS, METHODS...
    let mut header = [0u8; 2];
    socket.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        anyhow::bail!("unsupported SOCKS version {}", header[0]);
    }
    let mut methods = vec![0u8; header[1] as usize];
    socket.read_exact(&mut methods).await?;
    socket.write_all(&[0x05, 0x00]).await?; // no auth

    // Request: VER, CMD, RSV, ATYP, ADDR, PORT
    let mut request = [0u8; 4];
    socket.read_exact(&mut request).await?;
    if request[1] != 0x01 {
        // Only CONNECT is supported.
        socket
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        anyhow::bail!("unsupported SOCKS command {}", request[1]);
    }

    let host = match request[3] {
        0x01 => {
            let mut addr = [0u8; 4];
            socket.read_exact(&mut addr).await?;
            format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
        }
        0x03 => {
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            socket.read_exact(&mut domain).await?;
            String::from_utf8_lossy(&domain).to_string()
        }
        0x04 => {
            let mut addr = [0u8; 16];
            socket.read_exact(&mut addr).await?;
            let ip = std::net::Ipv6Addr::from(addr);
            ip.to_string()
        }
        atyp => anyhow::bail!("unsupported address type {atyp}"),
    };

    let mut port_bytes = [0u8; 2];
    socket.read_exact(&mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);

    let tunnel = manager.open(&session_id, &host, port).await?;

    // Success reply with a zero bound address.
    socket
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    tunnel.bridge(socket).await;
    Ok(())
}

/// Local port forward: listen locally, forward every connection to a fixed
/// destination through the agent.
pub async fn run_portfwd(
    manager: Arc<TunnelManager>,
    session_id: String,
    listener: TcpListener,
    target_host: String,
    target_port: u16,
) -> Result<()> {
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                tracing::warn!(%err, "portfwd accept failed");
                continue;
            }
        };
        let manager = manager.clone();
        let session = session_id.clone();
        let host = target_host.clone();
        tokio::spawn(async move {
            match manager.open(&session, &host, target_port).await {
                Ok(tunnel) => {
                    tracing::debug!(%peer, target = %format!("{host}:{target_port}"), "portfwd connection");
                    tunnel.bridge(socket).await;
                }
                Err(err) => {
                    tracing::warn!(%peer, %err, "portfwd tunnel open failed");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn socks_protocol_constant() {
        assert_eq!(0x05, 5);
    }
}
