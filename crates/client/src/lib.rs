use anyhow::{Context, Result};
use shikra_proto::v1::control_plane_client::ControlPlaneClient;
use shikra_proto::v1::{Empty, SessionInfo, TaskRequest, TaskResult};
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tonic::{Request, Status};

pub mod ai;
pub mod report;
pub mod tunnel;

pub use ai::{interactive_policy, tool_definitions, C2ToolExecutor};
pub use report::{generate_report, save_report};
pub use tunnel::{run_portfwd, run_socks5, TunnelManager};

pub const TRANSFER_CHUNK: usize = 1024 * 1024;
const MAX_MESSAGE_SIZE: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub struct BearerAuth {
    token: String,
}

impl BearerAuth {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

impl Interceptor for BearerAuth {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let value: MetadataValue<_> = format!("Bearer {}", self.token)
            .parse()
            .map_err(|_| Status::internal("invalid operator token"))?;
        request.metadata_mut().insert("authorization", value);
        Ok(request)
    }
}

#[derive(Clone)]
pub struct OperatorClient {
    inner: ControlPlaneClient<tonic::service::interceptor::InterceptedService<Channel, BearerAuth>>,
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub endpoint: String,
    pub ca_pem: String,
    pub token: String,
    pub domain: String,
}

impl OperatorClient {
    pub async fn connect(config: &ClientConfig) -> Result<Self> {
        const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(config.ca_pem.clone()))
            .domain_name(config.domain.clone());

        let endpoint = Channel::from_shared(config.endpoint.clone())
            .context("invalid server endpoint")?
            .tls_config(tls)
            .context("invalid TLS configuration")?
            .connect_timeout(CONNECT_TIMEOUT);
        let channel = tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect())
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "timed out connecting to {} after {}s — is the teamserver running?",
                    config.endpoint,
                    CONNECT_TIMEOUT.as_secs()
                )
            })?
            .context("failed to connect to teamserver")?;

        let inner = ControlPlaneClient::with_interceptor(channel, BearerAuth::new(&config.token))
            .max_decoding_message_size(MAX_MESSAGE_SIZE)
            .max_encoding_message_size(MAX_MESSAGE_SIZE);
        Ok(Self { inner })
    }

    /// Creates a tunnel manager bound to this client's channel.
    pub fn tunnel_manager(&self, session_id: &str) -> TunnelManager {
        TunnelManager::spawn(session_id.to_string(), self.inner.clone())
    }

    /// Starts a remote port forward on the agent and registers the rule.
    pub async fn start_rportfwd(
        &mut self,
        session_id: &str,
        bind: &str,
        to: &str,
    ) -> Result<shikra_proto::v1::RportFwdStatus> {
        self.start_rportfwd_transport(session_id, bind, to, "tcp")
            .await
    }

    pub async fn start_rportfwd_transport(
        &mut self,
        session_id: &str,
        bind: &str,
        to: &str,
        transport: &str,
    ) -> Result<shikra_proto::v1::RportFwdStatus> {
        let response = self
            .inner
            .start_rport_fwd(shikra_proto::v1::RportFwdRequest {
                session_id: session_id.to_string(),
                bind: bind.to_string(),
                to: to.to_string(),
                transport: transport.to_string(),
            })
            .await
            .context("StartRportFwd failed")?
            .into_inner();
        Ok(response)
    }

    pub async fn list_rportfwds(&mut self) -> Result<Vec<shikra_proto::v1::RportFwdInfo>> {
        let mut stream = self
            .inner
            .list_rport_fwds(Empty {})
            .await
            .context("ListRportFwds failed")?
            .into_inner();
        let mut forwards = Vec::new();
        while let Some(item) = stream.message().await.context("rportfwd stream error")? {
            forwards.push(item);
        }
        Ok(forwards)
    }

    /// Stops a remote port forward by its id.
    pub async fn stop_rportfwd(
        &mut self,
        forward_id: &str,
    ) -> Result<shikra_proto::v1::RportFwdStatus> {
        let response = self
            .inner
            .stop_rport_fwd(shikra_proto::v1::RportFwdId {
                forward_id: forward_id.to_string(),
            })
            .await
            .context("StopRportFwd failed")?
            .into_inner();
        Ok(response)
    }

    pub async fn version(&mut self) -> Result<String> {
        let response = self
            .inner
            .get_version(Empty {})
            .await
            .context("GetVersion failed")?
            .into_inner();
        Ok(response.semver)
    }

    pub async fn sessions(&mut self) -> Result<Vec<SessionInfo>> {
        let mut stream = self
            .inner
            .list_sessions(Empty {})
            .await
            .context("ListSessions failed")?
            .into_inner();

        let mut sessions = Vec::new();
        while let Some(session) = stream.message().await.context("session stream error")? {
            sessions.push(session);
        }
        Ok(sessions)
    }

    // ------------------------------------------------------------ team ops

    pub async fn list_operators(&mut self) -> Result<Vec<shikra_proto::v1::OperatorInfo>> {
        let mut stream = self
            .inner
            .list_operators(Empty {})
            .await
            .context("ListOperators failed")?
            .into_inner();
        let mut operators = Vec::new();
        while let Some(operator) = stream.message().await.context("operator stream error")? {
            operators.push(operator);
        }
        Ok(operators)
    }

    pub async fn create_operator(
        &mut self,
        name: &str,
        role: &str,
    ) -> Result<shikra_proto::v1::CreateOperatorResponse> {
        self.inner
            .create_operator(shikra_proto::v1::CreateOperatorRequest {
                name: name.to_string(),
                role: role.to_string(),
            })
            .await
            .context("CreateOperator failed")
            .map(|response| response.into_inner())
    }

    pub async fn delete_operator(&mut self, id: &str) -> Result<()> {
        self.inner
            .delete_operator(shikra_proto::v1::OperatorId { id: id.to_string() })
            .await
            .context("DeleteOperator failed")?;
        Ok(())
    }

    pub async fn list_credentials(&mut self) -> Result<Vec<shikra_proto::v1::CredentialInfo>> {
        let mut stream = self
            .inner
            .list_credentials(Empty {})
            .await
            .context("ListCredentials failed")?
            .into_inner();
        let mut credentials = Vec::new();
        while let Some(credential) = stream.message().await.context("credential stream error")? {
            credentials.push(credential);
        }
        Ok(credentials)
    }

    pub async fn add_credential(
        &mut self,
        host: &str,
        username: &str,
        secret: &str,
        kind: &str,
    ) -> Result<shikra_proto::v1::CredentialInfo> {
        self.inner
            .add_credential(shikra_proto::v1::AddCredentialRequest {
                host: host.to_string(),
                domain: String::new(),
                username: username.to_string(),
                secret: secret.to_string(),
                kind: kind.to_string(),
                source: "operator".into(),
            })
            .await
            .context("AddCredential failed")
            .map(|response| response.into_inner())
    }

    pub async fn list_loot(&mut self) -> Result<Vec<shikra_proto::v1::LootInfo>> {
        let mut stream = self
            .inner
            .list_loot(Empty {})
            .await
            .context("ListLoot failed")?
            .into_inner();
        let mut loot = Vec::new();
        while let Some(item) = stream.message().await.context("loot stream error")? {
            loot.push(item);
        }
        Ok(loot)
    }

    pub async fn add_loot(
        &mut self,
        name: &str,
        data: Vec<u8>,
        kind: &str,
    ) -> Result<shikra_proto::v1::LootInfo> {
        self.inner
            .add_loot(shikra_proto::v1::AddLootRequest {
                kind: kind.to_string(),
                name: name.to_string(),
                data,
            })
            .await
            .context("AddLoot failed")
            .map(|response| response.into_inner())
    }

    pub async fn list_canaries(&mut self) -> Result<Vec<shikra_proto::v1::CanaryInfo>> {
        let mut stream = self
            .inner
            .list_canaries(Empty {})
            .await
            .context("ListCanaries failed")?
            .into_inner();
        let mut canaries = Vec::new();
        while let Some(canary) = stream.message().await.context("canary stream error")? {
            canaries.push(canary);
        }
        Ok(canaries)
    }

    pub async fn create_canary(
        &mut self,
        kind: &str,
        note: &str,
    ) -> Result<shikra_proto::v1::CanaryInfo> {
        self.inner
            .create_canary(shikra_proto::v1::CreateCanaryRequest {
                kind: kind.to_string(),
                note: note.to_string(),
            })
            .await
            .context("CreateCanary failed")
            .map(|response| response.into_inner())
    }

    pub async fn verify_audit(&mut self) -> Result<shikra_proto::v1::AuditStatus> {
        self.inner
            .verify_audit(Empty {})
            .await
            .context("VerifyAudit failed")
            .map(|response| response.into_inner())
    }

    pub async fn list_tasks(
        &mut self,
        session_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<shikra_proto::v1::TaskRecord>> {
        let mut stream = self
            .inner
            .list_tasks(shikra_proto::v1::TaskQuery {
                session_id: session_id.unwrap_or_default().to_string(),
                limit,
            })
            .await
            .context("ListTasks failed")?
            .into_inner();
        let mut tasks = Vec::new();
        while let Some(task) = stream.message().await.context("task stream error")? {
            tasks.push(task);
        }
        Ok(tasks)
    }

    pub async fn run_scan(
        &mut self,
        target: &str,
        ports: &str,
        arguments: &str,
    ) -> Result<shikra_proto::v1::ScanResult> {
        self.inner
            .run_scan(shikra_proto::v1::ScanRequest {
                target: target.to_string(),
                ports: ports.to_string(),
                arguments: arguments.to_string(),
            })
            .await
            .context("RunScan failed")
            .map(|response| response.into_inner())
    }

    pub async fn list_hosts(&mut self) -> Result<Vec<shikra_proto::v1::HostInfo>> {
        let mut stream = self
            .inner
            .list_hosts(Empty {})
            .await
            .context("ListHosts failed")?
            .into_inner();
        let mut hosts = Vec::new();
        while let Some(host) = stream.message().await.context("host stream error")? {
            hosts.push(host);
        }
        Ok(hosts)
    }

    pub async fn msf_status(&mut self) -> Result<shikra_proto::v1::MsfStatusInfo> {
        self.inner
            .msf_status(Empty {})
            .await
            .context("MsfStatus failed")
            .map(|response| response.into_inner())
    }

    pub async fn list_extensions(&mut self) -> Result<Vec<shikra_proto::v1::ExtensionInfo>> {
        let mut stream = self
            .inner
            .list_extensions(Empty {})
            .await
            .context("ListExtensions failed")?
            .into_inner();
        let mut extensions = Vec::new();
        while let Some(item) = stream.message().await.context("extension stream error")? {
            extensions.push(item);
        }
        Ok(extensions)
    }

    pub async fn install_extension(
        &mut self,
        package: Vec<u8>,
    ) -> Result<shikra_proto::v1::ExtensionInfo> {
        self.inner
            .install_extension(shikra_proto::v1::InstallExtensionRequest { package })
            .await
            .context("InstallExtension failed")
            .map(|response| response.into_inner())
    }

    pub async fn fetch_extension(
        &mut self,
        id: &str,
    ) -> Result<shikra_proto::v1::FetchExtensionResponse> {
        self.inner
            .fetch_extension(shikra_proto::v1::FetchExtensionRequest {
                id: id.to_string(),
                by_name: false,
                platform: String::new(),
            })
            .await
            .context("FetchExtension failed")
            .map(|response| response.into_inner())
    }

    pub async fn fetch_extension_by_name(
        &mut self,
        name: &str,
        platform: &str,
    ) -> Result<shikra_proto::v1::FetchExtensionResponse> {
        self.inner
            .fetch_extension(shikra_proto::v1::FetchExtensionRequest {
                id: name.to_string(),
                by_name: true,
                platform: platform.to_string(),
            })
            .await
            .context("FetchExtension failed")
            .map(|response| response.into_inner())
    }

    pub async fn delete_extension(&mut self, id: &str) -> Result<()> {
        self.inner
            .delete_extension(shikra_proto::v1::ExtensionId { id: id.to_string() })
            .await
            .context("DeleteExtension failed")?;
        Ok(())
    }

    pub async fn armory_key(&mut self) -> Result<String> {
        self.inner
            .get_armory_key(Empty {})
            .await
            .context("GetArmoryKey failed")
            .map(|response| response.into_inner().public_key_hex)
    }

    pub async fn cancel_task(&mut self, session_id: &str, task_id: &str) -> Result<()> {
        self.inner
            .cancel_task(shikra_proto::v1::TaskCancel {
                session_id: session_id.to_string(),
                task_id: task_id.to_string(),
            })
            .await
            .context("CancelTask failed")?;
        Ok(())
    }

    pub async fn chat(&mut self, limit: i64) -> Result<Vec<shikra_proto::v1::ChatMessageInfo>> {
        self.inner
            .list_chat(shikra_proto::v1::ChatQuery { limit })
            .await
            .context("ListChat failed")
            .map(|response| response.into_inner().messages)
    }

    pub async fn send_chat(&mut self, message: &str) -> Result<()> {
        self.inner
            .send_chat(shikra_proto::v1::ChatMessageRequest {
                message: message.to_string(),
            })
            .await
            .context("SendChat failed")?;
        Ok(())
    }

    pub async fn events(&mut self, limit: i64) -> Result<Vec<shikra_proto::v1::EventInfo>> {
        self.inner
            .list_events(shikra_proto::v1::EventQuery { limit })
            .await
            .context("ListEvents failed")
            .map(|response| response.into_inner().events)
    }

    pub async fn set_session_ui(
        &mut self,
        session_id: &str,
        color: &str,
        operator_status: &str,
    ) -> Result<()> {
        self.inner
            .set_session_ui(shikra_proto::v1::SessionUiRequest {
                session_id: session_id.to_string(),
                color: color.to_string(),
                operator_status: operator_status.to_string(),
            })
            .await
            .context("SetSessionUi failed")?;
        Ok(())
    }

    pub async fn webhook(&mut self) -> Result<String> {
        self.inner
            .get_webhook(Empty {})
            .await
            .context("GetWebhook failed")
            .map(|response| response.into_inner().discord_url)
    }

    pub async fn set_webhook(&mut self, url: &str) -> Result<()> {
        self.inner
            .set_webhook(shikra_proto::v1::WebhookInfo {
                discord_url: url.to_string(),
            })
            .await
            .context("SetWebhook failed")?;
        Ok(())
    }

    pub async fn listeners(&mut self) -> Result<Vec<shikra_proto::v1::ListenerInfo>> {
        self.inner
            .list_listeners(Empty {})
            .await
            .context("ListListeners failed")
            .map(|response| response.into_inner().listeners)
    }

    pub async fn start_listener(
        &mut self,
        kind: &str,
        addr: &str,
        dns_zone: &str,
    ) -> Result<shikra_proto::v1::ListenerInfo> {
        self.inner
            .start_listener(shikra_proto::v1::StartListenerRequest {
                kind: kind.to_string(),
                addr: addr.to_string(),
                dns_zone: dns_zone.to_string(),
            })
            .await
            .context("StartListener failed")
            .map(|response| response.into_inner())
    }

    pub async fn stop_listener(&mut self, id: &str) -> Result<()> {
        self.inner
            .stop_listener(shikra_proto::v1::ListenerId { id: id.to_string() })
            .await
            .context("StopListener failed")?;
        Ok(())
    }

    pub async fn profiles(&mut self) -> Result<Vec<shikra_proto::v1::ProfileInfo>> {
        self.inner
            .get_profiles(Empty {})
            .await
            .context("GetProfiles failed")
            .map(|response| response.into_inner().profiles)
    }

    pub async fn set_profiles(
        &mut self,
        profiles: Vec<shikra_proto::v1::ProfileInfo>,
    ) -> Result<()> {
        self.inner
            .set_profiles(shikra_proto::v1::ProfileSetInfo { profiles })
            .await
            .context("SetProfiles failed")?;
        Ok(())
    }

    pub async fn msf_exec(&mut self, command: &str) -> Result<shikra_proto::v1::MsfExecResult> {
        self.inner
            .msf_exec(shikra_proto::v1::MsfExecRequest {
                command: command.to_string(),
            })
            .await
            .context("MsfExec failed")
            .map(|response| response.into_inner())
    }

    pub async fn list_reactions(&mut self) -> Result<Vec<shikra_proto::v1::ReactionInfo>> {
        let mut stream = self
            .inner
            .list_reactions(Empty {})
            .await
            .context("ListReactions failed")?
            .into_inner();
        let mut reactions = Vec::new();
        while let Some(reaction) = stream.message().await.context("reaction stream error")? {
            reactions.push(reaction);
        }
        Ok(reactions)
    }

    pub async fn add_reaction(
        &mut self,
        event_kind: &str,
        action: &str,
    ) -> Result<shikra_proto::v1::ReactionInfo> {
        self.inner
            .add_reaction(shikra_proto::v1::AddReactionRequest {
                event_kind: event_kind.to_string(),
                action: action.to_string(),
            })
            .await
            .context("AddReaction failed")
            .map(|response| response.into_inner())
    }

    pub async fn submit_task(
        &mut self,
        session_id: &str,
        command: &str,
        args: serde_json::Value,
        payload: Vec<u8>,
    ) -> Result<Vec<TaskResult>> {
        let request = TaskRequest {
            session_id: session_id.to_string(),
            command: command.to_string(),
            args: serde_json::to_vec(&args).unwrap_or_default(),
            payload,
        };

        let mut stream = self
            .inner
            .submit_task(request)
            .await
            .context("SubmitTask failed")?
            .into_inner();

        let mut results = Vec::new();
        while let Some(result) = stream.message().await.context("task stream error")? {
            results.push(result);
        }
        Ok(results)
    }

    /// Convenience helper returning the single result for simple tasks.
    pub async fn run_task(
        &mut self,
        session_id: &str,
        command: &str,
        args: serde_json::Value,
    ) -> Result<TaskResult> {
        let results = self
            .submit_task(session_id, command, args, Vec::new())
            .await?;
        results
            .into_iter()
            .next()
            .context("teamserver returned no task result")
    }

    /// Chunked download: streams the remote file into `dest`.
    pub async fn download(
        &mut self,
        session_id: &str,
        remote_path: &str,
        dest: &Path,
    ) -> Result<u64> {
        self.download_resumable(session_id, remote_path, dest, false)
            .await
    }

    /// Chunked download with optional resume.
    ///
    /// When `resume` is true and `dest` already exists, transfer starts at the
    /// current file length so an interrupted download continues where it
    /// stopped. Returns the full remote size on success.
    pub async fn download_resumable(
        &mut self,
        session_id: &str,
        remote_path: &str,
        dest: &Path,
        resume: bool,
    ) -> Result<u64> {
        let stat = self
            .run_task(
                session_id,
                "stat",
                serde_json::json!({ "path": remote_path }),
            )
            .await
            .context("remote stat failed")?;
        if stat.exit_code != 0 {
            anyhow::bail!(
                "remote stat failed: {}",
                String::from_utf8_lossy(&stat.output)
            );
        }
        let stat_json: serde_json::Value =
            serde_json::from_slice(&stat.output).context("invalid stat response")?;
        let size = stat_json["size"].as_u64().unwrap_or(0);
        if stat_json["is_dir"].as_bool().unwrap_or(false) {
            anyhow::bail!("remote path is a directory: {remote_path}");
        }

        let mut offset: u64 = 0;
        let mut file = if resume {
            match tokio::fs::metadata(dest).await {
                Ok(metadata) if metadata.is_file() && metadata.len() <= size => {
                    offset = metadata.len();
                    tokio::fs::OpenOptions::new()
                        .append(true)
                        .open(dest)
                        .await
                        .with_context(|| format!("failed to reopen {}", dest.display()))?
                }
                _ => tokio::fs::File::create(dest)
                    .await
                    .with_context(|| format!("failed to create {}", dest.display()))?,
            }
        } else {
            tokio::fs::File::create(dest)
                .await
                .with_context(|| format!("failed to create {}", dest.display()))?
        };

        while offset < size {
            let length = (size - offset).min(TRANSFER_CHUNK as u64);
            let chunk = self
                .run_task(
                    session_id,
                    "download",
                    serde_json::json!({
                        "path": remote_path,
                        "offset": offset,
                        "length": length,
                    }),
                )
                .await
                .context("download chunk failed")?;
            if chunk.exit_code != 0 {
                anyhow::bail!(
                    "download chunk failed: {}",
                    String::from_utf8_lossy(&chunk.output)
                );
            }
            if chunk.output.is_empty() && offset < size {
                anyhow::bail!("remote file shrank during download at offset {offset}");
            }
            file.write_all(&chunk.output)
                .await
                .context("write failed")?;
            offset += chunk.output.len() as u64;
        }
        file.flush().await.context("flush failed")?;
        Ok(size)
    }

    /// Chunked upload: streams the local file to `remote_path`.
    pub async fn upload(
        &mut self,
        session_id: &str,
        local: &Path,
        remote_path: &str,
    ) -> Result<u64> {
        let data = tokio::fs::read(local)
            .await
            .with_context(|| format!("failed to read {}", local.display()))?;
        let mut offset: u64 = 0;
        while offset < data.len() as u64 {
            let end = (offset as usize + TRANSFER_CHUNK).min(data.len());
            let chunk = data[offset as usize..end].to_vec();
            let result = self
                .submit_task(
                    session_id,
                    "upload",
                    serde_json::json!({
                        "path": remote_path,
                        "offset": offset,
                    }),
                    chunk,
                )
                .await
                .context("upload chunk failed")?;
            let result = result.first().context("no upload result")?;
            if result.exit_code != 0 {
                anyhow::bail!(
                    "upload chunk failed: {}",
                    String::from_utf8_lossy(&result.output)
                );
            }
            offset = end as u64;
        }
        // Empty file still needs a create call.
        if data.is_empty() {
            let _ = self
                .submit_task(
                    session_id,
                    "upload",
                    serde_json::json!({"path": remote_path, "offset": 0}),
                    Vec::new(),
                )
                .await?;
        }
        Ok(data.len() as u64)
    }
}
