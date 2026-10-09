//! Shikra MCP server: exposes the teamserver tool surface to AI agents over
//! stdio JSON-RPC, guarded by an approval policy.
//!
//! Configuration (environment):
//! - `SHIKRA_SERVER` — teamserver endpoint, e.g. `https://127.0.0.1:8443`
//! - `SHIKRA_CA_CERT` — path to the pinned `ca.pem`
//! - `SHIKRA_OPERATOR_TOKEN` — operator bearer token
//! - `SHIKRA_MCP_ALLOW_MUTATING=1` — allow routine state-changing tools
//! - `SHIKRA_MCP_ALLOW_DESTRUCTIVE=1` — additionally allow destructive tools

use anyhow::{Context, Result};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::transport::stdio;
use rmcp::{schemars, tool, tool_router, ServiceExt};
use serde::Deserialize;
use shikra_ai::{risk_of, Risk};
use shikra_client::{ClientConfig, OperatorClient};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListSessionsParams {
    /// Optional hostname substring filter.
    #[serde(default)]
    filter: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RunShellParams {
    /// Target session id.
    session_id: String,
    /// Command line executed through the target shell.
    command: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SessionPathParams {
    session_id: String,
    /// Remote path; relative paths resolve against the agent working dir.
    path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct TransferParams {
    session_id: String,
    /// Local filesystem path on the MCP host.
    local_path: String,
    /// Remote path on the target.
    remote_path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct BofParams {
    session_id: String,
    /// Local path to the COFF object file.
    file: String,
    /// Arguments string passed to the BOF entry point.
    #[serde(default)]
    args: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WasmLoadParams {
    session_id: String,
    name: String,
    /// Local path to the .wasm module.
    file: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WasmRunParams {
    session_id: String,
    name: String,
    #[serde(default)]
    args: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SessionOnlyParams {
    session_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RportFwdParams {
    session_id: String,
    bind: String,
    to: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ForwardIdParams {
    forward_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SocksParams {
    session_id: String,
    listen: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct PortFwdParams {
    session_id: String,
    listen: String,
    target: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RunTaskParams {
    session_id: String,
    kind: String,
    #[serde(default)]
    args: serde_json::Value,
}

#[derive(Clone)]
struct McpState {
    client: Arc<Mutex<Option<OperatorClient>>>,
    config: ClientConfig,
    allow_mutating: bool,
    allow_destructive: bool,
    listeners: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl McpState {
    fn from_env() -> Result<Self> {
        let endpoint =
            std::env::var("SHIKRA_SERVER").unwrap_or_else(|_| "https://127.0.0.1:8443".into());
        let ca_path: PathBuf = std::env::var("SHIKRA_CA_CERT")
            .map(PathBuf::from)
            .context("SHIKRA_CA_CERT is required")?;
        let token =
            std::env::var("SHIKRA_OPERATOR_TOKEN").context("SHIKRA_OPERATOR_TOKEN is required")?;
        let ca_pem = std::fs::read_to_string(&ca_path)
            .with_context(|| format!("failed to read {}", ca_path.display()))?;

        Ok(Self {
            client: Arc::new(Mutex::new(None)),
            config: ClientConfig {
                endpoint,
                ca_pem,
                token,
                domain: std::env::var("SHIKRA_TLS_DOMAIN").unwrap_or_else(|_| "localhost".into()),
            },
            allow_mutating: env_flag("SHIKRA_MCP_ALLOW_MUTATING"),
            allow_destructive: env_flag("SHIKRA_MCP_ALLOW_DESTRUCTIVE"),
            listeners: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn check_risk(&self, tool: &str) -> Result<(), String> {
        match risk_of(tool) {
            Risk::ReadOnly => Ok(()),
            Risk::Mutating if self.allow_mutating => Ok(()),
            Risk::Mutating => Err(format!(
                "tool `{tool}` is mutating; set SHIKRA_MCP_ALLOW_MUTATING=1 to allow"
            )),
            Risk::Destructive if self.allow_mutating && self.allow_destructive => Ok(()),
            Risk::Destructive => Err(format!(
                "tool `{tool}` is destructive; set SHIKRA_MCP_ALLOW_MUTATING=1 and SHIKRA_MCP_ALLOW_DESTRUCTIVE=1 to allow"
            )),
        }
    }

    /// Returns a connected client, dialing the teamserver on first use.
    async fn client(&self) -> Result<OperatorClient, String> {
        let mut guard = self.client.lock().await;
        if guard.is_none() {
            let client = OperatorClient::connect(&self.config)
                .await
                .map_err(|err| format!("failed to connect to teamserver: {err}"))?;
            *guard = Some(client);
        }
        Ok(guard.as_ref().expect("connected above").clone())
    }
}

fn env_flag(key: &str) -> bool {
    matches!(
        std::env::var(key).as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn result_to_json(result: shikra_proto::v1::TaskResult) -> serde_json::Value {
    serde_json::json!({
        "task_id": result.task_id,
        "exit_code": result.exit_code,
        "output": String::from_utf8_lossy(&result.output),
    })
}

#[derive(Clone)]
struct ShikraMcp {
    state: McpState,
}

#[tool_router(server_handler)]
impl ShikraMcp {
    #[tool(description = "List active sessions and beacons known to the teamserver")]
    async fn list_sessions(&self, Parameters(params): Parameters<ListSessionsParams>) -> String {
        match self.state.client().await {
            Ok(mut client) => match client.sessions().await {
                Ok(sessions) => {
                    let filtered: Vec<serde_json::Value> = sessions
                        .into_iter()
                        .filter(|session| {
                            params
                                .filter
                                .as_deref()
                                .map(|needle| session.hostname.contains(needle))
                                .unwrap_or(true)
                        })
                        .map(|session| {
                            serde_json::json!({
                                "id": session.id,
                                "hostname": session.hostname,
                                "username": session.username,
                                "platform": session.platform,
                                "kind": session.kind,
                                "remote_addr": session.remote_addr,
                            })
                        })
                        .collect();
                    serde_json::to_string(&filtered).unwrap_or_else(|_| "[]".into())
                }
                Err(err) => error_json(&err.to_string()),
            },
            Err(err) => error_json(&err),
        }
    }

    #[tool(description = "Execute a shell command on a target session")]
    async fn run_shell(&self, Parameters(params): Parameters<RunShellParams>) -> String {
        if let Err(err) = self.state.check_risk("run_shell") {
            return error_json(&err);
        }
        self.run_kind(
            &params.session_id,
            "shell",
            serde_json::json!({ "command": params.command }),
        )
        .await
    }

    #[tool(description = "Run a named task kind with JSON args on a target session")]
    async fn run_task(&self, Parameters(params): Parameters<RunTaskParams>) -> String {
        if let Err(err) = self.state.check_risk("run_task") {
            return error_json(&err);
        }
        self.run_named(&params.session_id, &params.kind, params.args)
            .await
    }

    #[tool(description = "List a remote directory (JSON entries)")]
    async fn fs_ls(&self, Parameters(params): Parameters<SessionPathParams>) -> String {
        if let Err(err) = self.state.check_risk("fs_ls") {
            return error_json(&err);
        }
        self.run_kind(
            &params.session_id,
            "ls",
            serde_json::json!({ "path": params.path }),
        )
        .await
    }

    #[tool(description = "Read a remote file's contents")]
    async fn fs_cat(&self, Parameters(params): Parameters<SessionPathParams>) -> String {
        if let Err(err) = self.state.check_risk("fs_cat") {
            return error_json(&err);
        }
        self.run_kind(
            &params.session_id,
            "cat",
            serde_json::json!({ "path": params.path }),
        )
        .await
    }

    #[tool(description = "Download a remote file to the MCP host")]
    async fn fs_download(&self, Parameters(params): Parameters<TransferParams>) -> String {
        if let Err(err) = self.state.check_risk("fs_download") {
            return error_json(&err);
        }
        match self.state.client().await {
            Ok(mut client) => match client
                .download(
                    &params.session_id,
                    &params.remote_path,
                    &PathBuf::from(&params.local_path),
                )
                .await
            {
                Ok(bytes) => serde_json::json!({ "downloaded": bytes, "local": params.local_path })
                    .to_string(),
                Err(err) => error_json(&err.to_string()),
            },
            Err(err) => error_json(&err),
        }
    }

    #[tool(description = "Upload a local file to the target")]
    async fn fs_upload(&self, Parameters(params): Parameters<TransferParams>) -> String {
        if let Err(err) = self.state.check_risk("fs_upload") {
            return error_json(&err);
        }
        match self.state.client().await {
            Ok(mut client) => match client
                .upload(
                    &params.session_id,
                    &PathBuf::from(&params.local_path),
                    &params.remote_path,
                )
                .await
            {
                Ok(bytes) => serde_json::json!({ "uploaded": bytes, "remote": params.remote_path })
                    .to_string(),
                Err(err) => error_json(&err.to_string()),
            },
            Err(err) => error_json(&err),
        }
    }

    #[tool(description = "Execute a Beacon Object File (COFF) on the target")]
    async fn bof_run(&self, Parameters(params): Parameters<BofParams>) -> String {
        if let Err(err) = self.state.check_risk("bof_run") {
            return error_json(&err);
        }
        let payload = match std::fs::read(&params.file) {
            Ok(bytes) => bytes,
            Err(err) => return error_json(&format!("failed to read {}: {err}", params.file)),
        };
        match self.state.client().await {
            Ok(mut client) => match client
                .submit_task(
                    &params.session_id,
                    "bof",
                    serde_json::json!({ "args": params.args }),
                    payload,
                )
                .await
            {
                Ok(results) => match results.into_iter().next() {
                    Some(result) => result_to_json(result).to_string(),
                    None => error_json("no task result"),
                },
                Err(err) => error_json(&err.to_string()),
            },
            Err(err) => error_json(&err),
        }
    }

    #[tool(description = "Register a WASM extension on the target")]
    async fn wasm_load(&self, Parameters(params): Parameters<WasmLoadParams>) -> String {
        if let Err(err) = self.state.check_risk("wasm_load") {
            return error_json(&err);
        }
        let payload = match std::fs::read(&params.file) {
            Ok(bytes) => bytes,
            Err(err) => return error_json(&format!("failed to read {}: {err}", params.file)),
        };
        match self.state.client().await {
            Ok(mut client) => match client
                .submit_task(
                    &params.session_id,
                    "wasm_load",
                    serde_json::json!({ "name": params.name }),
                    payload,
                )
                .await
            {
                Ok(results) => match results.into_iter().next() {
                    Some(result) => result_to_json(result).to_string(),
                    None => error_json("no task result"),
                },
                Err(err) => error_json(&err.to_string()),
            },
            Err(err) => error_json(&err),
        }
    }

    #[tool(description = "Run a registered WASM extension on the target")]
    async fn wasm_run(&self, Parameters(params): Parameters<WasmRunParams>) -> String {
        if let Err(err) = self.state.check_risk("wasm_run") {
            return error_json(&err);
        }
        self.run_kind(
            &params.session_id,
            "wasm_run",
            serde_json::json!({ "name": params.name, "args": params.args }),
        )
        .await
    }

    #[tool(description = "List WASM extensions registered on the target")]
    async fn wasm_list(&self, Parameters(params): Parameters<SessionOnlyParams>) -> String {
        if let Err(err) = self.state.check_risk("wasm_list") {
            return error_json(&err);
        }
        self.run_kind(&params.session_id, "wasm_list", serde_json::Value::Null)
            .await
    }

    #[tool(description = "Start a remote port forward (agent binds, server dials target)")]
    async fn rportfwd_start(&self, Parameters(params): Parameters<RportFwdParams>) -> String {
        if let Err(err) = self.state.check_risk("rportfwd_start") {
            return error_json(&err);
        }
        match self.state.client().await {
            Ok(mut client) => match client
                .start_rportfwd(&params.session_id, &params.bind, &params.to)
                .await
            {
                Ok(status) => serde_json::json!({
                    "forward_id": status.forward_id,
                    "running": status.running,
                    "message": status.message,
                })
                .to_string(),
                Err(err) => error_json(&err.to_string()),
            },
            Err(err) => error_json(&err),
        }
    }

    #[tool(description = "Stop a remote port forward by id")]
    async fn rportfwd_stop(&self, Parameters(params): Parameters<ForwardIdParams>) -> String {
        if let Err(err) = self.state.check_risk("rportfwd_stop") {
            return error_json(&err);
        }
        match self.state.client().await {
            Ok(mut client) => match client.stop_rportfwd(&params.forward_id).await {
                Ok(status) => serde_json::json!({
                    "forward_id": status.forward_id,
                    "running": status.running,
                    "message": status.message,
                })
                .to_string(),
                Err(err) => error_json(&err.to_string()),
            },
            Err(err) => error_json(&err),
        }
    }

    #[tool(description = "Start a SOCKS5 proxy on the MCP host tunneling through a session")]
    async fn socks_start(&self, Parameters(params): Parameters<SocksParams>) -> String {
        if let Err(err) = self.state.check_risk("socks_start") {
            return error_json(&err);
        }
        let client = match self.state.client().await {
            Ok(client) => client,
            Err(err) => return error_json(&err),
        };
        let manager = Arc::new(client.tunnel_manager(&params.session_id));
        let listener = match tokio::net::TcpListener::bind(&params.listen).await {
            Ok(listener) => listener,
            Err(err) => return error_json(&format!("failed to bind {}: {err}", params.listen)),
        };
        let session = params.session_id.clone();
        let handle = tokio::spawn(async move {
            let _ = shikra_client::run_socks5(manager, session, listener).await;
        });
        self.state.listeners.lock().await.push(handle);
        serde_json::json!({ "listening": params.listen }).to_string()
    }

    #[tool(description = "Start a local port forward through a session")]
    async fn portfwd_start(&self, Parameters(params): Parameters<PortFwdParams>) -> String {
        if let Err(err) = self.state.check_risk("portfwd_start") {
            return error_json(&err);
        }
        let (host, port) = match params.target.rsplit_once(':') {
            Some((host, port)) => match port.parse::<u16>() {
                Ok(port) => (host.to_string(), port),
                Err(_) => return error_json("invalid target port"),
            },
            None => return error_json("target must be host:port"),
        };
        let client = match self.state.client().await {
            Ok(client) => client,
            Err(err) => return error_json(&err),
        };
        let manager = Arc::new(client.tunnel_manager(&params.session_id));
        let listener = match tokio::net::TcpListener::bind(&params.listen).await {
            Ok(listener) => listener,
            Err(err) => return error_json(&format!("failed to bind {}: {err}", params.listen)),
        };
        let session = params.session_id.clone();
        let handle = tokio::spawn(async move {
            let _ = shikra_client::run_portfwd(manager, session, listener, host, port).await;
        });
        self.state.listeners.lock().await.push(handle);
        serde_json::json!({
            "listening": params.listen,
            "target": params.target,
        })
        .to_string()
    }
}

impl ShikraMcp {
    async fn run_kind(&self, session_id: &str, kind: &str, args: serde_json::Value) -> String {
        match self.state.client().await {
            Ok(mut client) => match client.run_task(session_id, kind, args).await {
                Ok(result) => result_to_json(result).to_string(),
                Err(err) => error_json(&err.to_string()),
            },
            Err(err) => error_json(&err),
        }
    }

    async fn run_named(&self, session_id: &str, kind: &str, args: serde_json::Value) -> String {
        if let Err(err) = self.state.check_risk("run_task") {
            return error_json(&err);
        }
        self.run_kind(session_id, kind, args).await
    }
}

fn error_json(message: &str) -> String {
    serde_json::json!({ "error": message }).to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let state = McpState::from_env()?;
    tracing::info!(
        mutating = state.allow_mutating,
        destructive = state.allow_destructive,
        "starting shikra-mcp (stdio transport)"
    );

    let service = ShikraMcp { state }.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
