//! Reconnaissance: runs nmap on the teamserver host, parses XML output and
//! upserts discovered hosts into the inventory.

use crate::state::ServerState;
use anyhow::{Context, Result};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::process::Stdio;
use std::time::Duration;

#[derive(Debug, Default, Clone)]
pub struct DiscoveredHost {
    pub ip: String,
    pub hostname: String,
    pub os: String,
    pub ports: Vec<PortEntry>,
}

#[derive(Debug, Clone)]
pub struct PortEntry {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: String,
    pub product: String,
}

/// Runs an nmap scan and returns parsed hosts. `target` is passed as a
/// separate argv entry (never through a shell) to avoid command injection.
pub async fn run_nmap(
    target: &str,
    ports: Option<&str>,
    extra_args: Option<&str>,
) -> Result<Vec<DiscoveredHost>> {
    let mut command = tokio::process::Command::new("nmap");
    command
        .arg("-oX")
        .arg("-")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    if let Some(ports) = ports.filter(|value| !value.trim().is_empty()) {
        command.arg("-p").arg(ports.trim());
    }
    if let Some(extra) = extra_args.filter(|value| !value.trim().is_empty()) {
        for part in extra.split_whitespace() {
            command.arg(part);
        }
    }
    command.arg(target);

    let child = command.spawn().context("failed to spawn nmap")?;
    let output = tokio::time::timeout(Duration::from_secs(300), child.wait_with_output())
        .await
        .context("nmap timed out")?
        .context("nmap failed")?;

    if !output.status.success() {
        anyhow::bail!(
            "nmap exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    parse_nmap_xml(&output.stdout)
}

fn attr_value(event: &quick_xml::events::BytesStart<'_>, key: &str) -> Option<String> {
    for attr in event.attributes().flatten() {
        if attr.key.as_ref() == key {
            return Some(attr.value.to_string());
        }
    }
    None
}

/// Parses `nmap -oX -` output into discovered hosts.
pub fn parse_nmap_xml(xml: &[u8]) -> Result<Vec<DiscoveredHost>> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);

    let mut hosts = Vec::new();
    let mut current: Option<DiscoveredHost> = None;
    let mut current_port: Option<PortEntry> = None;
    let mut up = false;

    loop {
        let event = reader.read_event().context("invalid nmap XML")?;
        match event {
            Event::Start(ref event) | Event::Empty(ref event) => match event.name().as_ref() {
                "host" => {
                    current = Some(DiscoveredHost::default());
                    up = false;
                }
                "status" if current.is_some() => {
                    if let Some(state) = attr_value(event, "state") {
                        up = state == "up";
                    }
                }
                "address" if current.is_some() => {
                    if let Some(addr) = attr_value(event, "addr") {
                        if let Some(host) = current.as_mut() {
                            if host.ip.is_empty() {
                                host.ip = addr;
                            }
                        }
                    }
                }
                "hostname" if current.is_some() => {
                    if let Some(name) = attr_value(event, "name") {
                        if let Some(host) = current.as_mut() {
                            if host.hostname.is_empty() {
                                host.hostname = name;
                            }
                        }
                    }
                }
                "osmatch" if current.is_some() => {
                    if let Some(name) = attr_value(event, "name") {
                        if let Some(host) = current.as_mut() {
                            host.os = name;
                        }
                    }
                }
                "port" if current.is_some() => {
                    let port = PortEntry {
                        port: attr_value(event, "portid")
                            .and_then(|value| value.parse().ok())
                            .unwrap_or(0),
                        protocol: attr_value(event, "protocol").unwrap_or_default(),
                        state: String::new(),
                        service: String::new(),
                        product: String::new(),
                    };
                    current_port = Some(port);
                }
                "state" => {
                    if let Some(port) = current_port.as_mut() {
                        if let Some(state) = attr_value(event, "state") {
                            port.state = state;
                        }
                    }
                }
                "service" => {
                    if let Some(port) = current_port.as_mut() {
                        if let Some(name) = attr_value(event, "name") {
                            port.service = name;
                        }
                        if let Some(product) = attr_value(event, "product") {
                            port.product = if port.product.is_empty() {
                                product
                            } else {
                                format!("{} {}", port.product, product)
                            };
                        }
                    }
                }
                _ => {}
            },
            Event::End(ref event) => match event.name().as_ref() {
                "port" => {
                    if let (Some(host), Some(port)) = (current.as_mut(), current_port.take()) {
                        if port.port != 0 {
                            host.ports.push(port);
                        }
                    }
                }
                "host" => {
                    if let Some(host) = current.take() {
                        if up && !host.ip.is_empty() {
                            hosts.push(host);
                        }
                    }
                    up = false;
                    current_port = None;
                }
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
    }

    Ok(hosts)
}

/// Persists discovered hosts into the engagement inventory.
pub async fn store_hosts(state: &ServerState, hosts: &[DiscoveredHost]) {
    for host in hosts {
        let ports: Vec<serde_json::Value> = host
            .ports
            .iter()
            .map(|port| {
                serde_json::json!({
                    "port": port.port,
                    "protocol": port.protocol,
                    "state": port.state,
                    "service": port.service,
                    "product": port.product,
                })
            })
            .collect();
        if let Err(err) = shikra_store::repo_team::upsert_host(
            &state.pool,
            uuid::Uuid::new_v4(),
            state.engagement_id,
            &host.ip,
            &host.hostname,
            &host.os,
            &serde_json::Value::Array(ports),
            "nmap",
        )
        .await
        {
            tracing::warn!(%err, ip = %host.ip, "failed to upsert host");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = br#"<?xml version="1.0"?>
<nmaprun>
<host>
  <status state="up" reason="syn-ack"/>
  <address addr="10.0.0.5" addrtype="ipv4"/>
  <hostnames><hostname name="web01.local" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="9.6"/>
    </port>
    <port protocol="tcp" portid="443">
      <state state="open" reason="syn-ack"/>
      <service name="https" product="nginx"/>
    </port>
  </ports>
  <os><osmatch name="Linux 5.x" accuracy="98"/></os>
</host>
<host>
  <status state="down" reason="no-response"/>
  <address addr="10.0.0.6" addrtype="ipv4"/>
</host>
</nmaprun>"#;

    #[test]
    fn parses_hosts_ports_and_os() {
        let hosts = parse_nmap_xml(SAMPLE).expect("parse");
        assert_eq!(hosts.len(), 1, "down host must be skipped");
        let host = &hosts[0];
        assert_eq!(host.ip, "10.0.0.5");
        assert_eq!(host.hostname, "web01.local");
        assert_eq!(host.os, "Linux 5.x");
        assert_eq!(host.ports.len(), 2);
        assert_eq!(host.ports[0].port, 22);
        assert_eq!(host.ports[0].state, "open");
        assert_eq!(host.ports[0].service, "ssh");
        assert!(host.ports[0].product.contains("OpenSSH"));
    }

    #[test]
    fn handles_empty_ports() {
        let xml =
            br#"<nmaprun><host><status state="up"/><address addr="10.0.0.9"/></host></nmaprun>"#;
        let hosts = parse_nmap_xml(xml).expect("parse");
        assert_eq!(hosts.len(), 1);
        assert!(hosts[0].ports.is_empty());
    }
}
