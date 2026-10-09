use crate::tunnel::{ForwardRegistry, TunnelHub};
use shikra_crypto::channel::SessionKeys;
use shikra_crypto::signing::Identity;
use shikra_proto::v1::SessionInfo;
use shikra_store::repo::NewSession;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use uuid::Uuid;

use shikra_proto::v1::{AgentMessage, AgentTask};

/// Role hierarchy for RBAC checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OperatorRole {
    Watcher,
    Operator,
    Admin,
}

impl OperatorRole {
    pub fn parse(raw: &str) -> Self {
        match raw.to_ascii_lowercase().as_str() {
            "admin" => Self::Admin,
            "watcher" => Self::Watcher,
            _ => Self::Operator,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Watcher => "watcher",
        }
    }
}

#[derive(Debug, Clone)]
pub struct OperatorIdentity {
    pub id: Uuid,
    pub name: String,
    pub role: OperatorRole,
}

/// In-memory token -> identity map used by the synchronous gRPC interceptor.
#[derive(Default)]
pub struct OperatorRegistry {
    by_token_hash: std::sync::RwLock<HashMap<String, OperatorIdentity>>,
}

impl OperatorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, token_hash: String, identity: OperatorIdentity) {
        self.by_token_hash
            .write()
            .expect("operator registry poisoned")
            .insert(token_hash, identity);
    }

    pub fn remove(&self, token_hash: &str) {
        self.by_token_hash
            .write()
            .expect("operator registry poisoned")
            .remove(token_hash);
    }

    pub fn lookup(&self, token_hash: &str) -> Option<OperatorIdentity> {
        self.by_token_hash
            .read()
            .expect("operator registry poisoned")
            .get(token_hash)
            .cloned()
    }
}

/// Hashes an operator bearer token for storage/lookup (SHA-256, hex).
pub fn hash_operator_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub struct SessionHandle {
    pub id: String,
    pub is_beacon: bool,
    pub info: Mutex<SessionInfo>,
    pub keys: Mutex<SessionKeys>,
    pub task_tx: Mutex<Option<mpsc::Sender<AgentMessage>>>,
    pub task_rx: Mutex<Option<mpsc::Receiver<AgentMessage>>>,
    pub beacon_queue: Mutex<VecDeque<AgentTask>>,
    pub pending: Mutex<HashMap<String, oneshot::Sender<shikra_proto::v1::AgentResult>>>,
    /// Tasks cancelled by operators; the submit stream reports them as such.
    pub cancelled: Mutex<std::collections::HashSet<String>>,
    /// Estimated beacon check-in interval (EMA, milliseconds).
    pub avg_interval_ms: Mutex<Option<u64>>,
}

impl SessionHandle {
    pub fn new(id: String, is_beacon: bool, info: SessionInfo, keys: SessionKeys) -> Self {
        let (task_tx, task_rx) = mpsc::channel(64);
        Self {
            id,
            is_beacon,
            info: Mutex::new(info),
            keys: Mutex::new(keys),
            task_tx: Mutex::new(Some(task_tx)),
            task_rx: Mutex::new(Some(task_rx)),
            beacon_queue: Mutex::new(VecDeque::new()),
            pending: Mutex::new(HashMap::new()),
            cancelled: Mutex::new(std::collections::HashSet::new()),
            avg_interval_ms: Mutex::new(None),
        }
    }

    /// Records a check-in and updates the interval estimate. Call this before
    /// overwriting `last_seen`.
    pub async fn note_checkin(
        &self,
        previous_seen: Option<time::OffsetDateTime>,
        now: time::OffsetDateTime,
    ) {
        if let Some(previous) = previous_seen {
            let delta_ms = (now - previous).whole_milliseconds().max(0) as u64;
            if delta_ms > 0 {
                let mut estimate = self.avg_interval_ms.lock().await;
                *estimate = Some(match *estimate {
                    Some(avg) => (avg * 3 + delta_ms) / 4,
                    None => delta_ms,
                });
            }
        }
    }

    /// Seconds after which a silent beacon is considered stale.
    ///
    /// Once a check-in cadence is known (EMA of observed intervals) the
    /// threshold is 3 missed intervals with a 90s floor. Before the first
    /// interval estimate the beacon gets a conservative 5 minute grace so
    /// slow-polling builds are not misclassified right after enrollment.
    pub async fn stale_after_secs(&self) -> u64 {
        const FLOOR_SECS: u64 = 90;
        const UNKNOWN_SECS: u64 = 300;
        match *self.avg_interval_ms.lock().await {
            Some(avg_ms) => ((avg_ms * 3) / 1000).max(FLOOR_SECS),
            None => UNKNOWN_SECS,
        }
    }

    pub async fn send_task(&self, task: AgentTask) -> Result<(), &'static str> {
        if self.is_beacon {
            self.beacon_queue.lock().await.push_back(task);
            return Ok(());
        }
        self.send_message(AgentMessage {
            body: Some(shikra_proto::v1::agent_message::Body::Task(task)),
        })
        .await
    }

    /// Streams an arbitrary agent message (tunnel frames are session-only).
    pub async fn send_message(&self, message: AgentMessage) -> Result<(), &'static str> {
        if self.is_beacon {
            return Err("beacons cannot receive tunnel frames");
        }
        let guard = self.task_tx.lock().await;
        let tx = guard.as_ref().ok_or("session stream not established")?;
        tx.send(message).await.map_err(|_| "session stream closed")
    }

    pub async fn drain_beacon_tasks(&self, max: usize) -> Vec<AgentTask> {
        let mut queue = self.beacon_queue.lock().await;
        let mut tasks = Vec::new();
        while tasks.len() < max {
            match queue.pop_front() {
                Some(task) => tasks.push(task),
                None => break,
            }
        }
        tasks
    }

    pub async fn take_task_rx(&self) -> Option<mpsc::Receiver<AgentMessage>> {
        self.task_rx.lock().await.take()
    }
}

#[derive(Default)]
pub struct SessionRegistry {
    inner: RwLock<HashMap<String, Arc<SessionHandle>>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn insert(&self, handle: Arc<SessionHandle>) {
        self.inner.write().await.insert(handle.id.clone(), handle);
    }

    pub async fn get(&self, id: &str) -> Option<Arc<SessionHandle>> {
        self.inner.read().await.get(id).cloned()
    }

    pub async fn remove(&self, id: &str) -> Option<Arc<SessionHandle>> {
        self.inner.write().await.remove(id)
    }

    pub async fn list(&self) -> Vec<Arc<SessionHandle>> {
        self.inner.read().await.values().cloned().collect()
    }
}

pub struct ServerState {
    pub pool: sqlx::PgPool,
    pub identity: Arc<Identity>,
    pub enroll_token: Arc<String>,
    pub operator_token: Arc<String>,
    pub engagement_id: Uuid,
    pub sessions: Arc<SessionRegistry>,
    pub tunnels: Arc<TunnelHub>,
    pub forwards: Arc<ForwardRegistry>,
    pub operators: Arc<OperatorRegistry>,
    /// Directory served by the `/cdn/{file}` staged-payload endpoint.
    pub hosting_dir: Arc<std::path::PathBuf>,
    /// Ed25519 public key extension packages must be signed with.
    pub armory_public: [u8; 32],
    /// Per-peer enrollment attempt limiter.
    pub enroll_limiter: Arc<crate::rate_limit::AttemptLimiter>,
    /// Live malleable C2 profiles (hot-reloadable through `SetProfiles`).
    pub profiles: Arc<tokio::sync::RwLock<shikra_transport::profile::ProfileSet>>,
    /// Teamserver state directory (`profiles.json` lives here).
    pub state_dir: Arc<std::path::PathBuf>,
    /// Beacon listeners started at runtime from the operator console.
    pub listeners: Arc<crate::listeners::ListenerRegistry>,
    /// Discord webhook URL for new-session notifications.
    pub webhook: Arc<tokio::sync::RwLock<Option<String>>>,
    /// Bearer token external agents use to register.
    pub relay_token: Arc<String>,
    /// Per-session bearer token for external agent task/result endpoints.
    pub external_tokens: Arc<Mutex<std::collections::HashMap<String, String>>>,
}

impl ServerState {
    pub async fn session_insert(&self, handle: &SessionHandle) {
        let info = handle.info.lock().await.clone();
        let platform = platform_str(info.platform);
        let architecture = architecture_str(info.architecture);
        let kind = kind_str(info.kind);
        let record = NewSession {
            id: Uuid::parse_str(&handle.id).unwrap_or_else(|_| Uuid::new_v4()),
            engagement_id: self.engagement_id,
            implant_id: None,
            kind,
            status: "active".into(),
            platform,
            architecture,
            hostname: info.hostname.clone(),
            username: info.username.clone(),
            process_name: info.process_name.clone(),
            remote_addr: if info.remote_addr.is_empty() {
                None
            } else {
                Some(info.remote_addr.clone())
            },
            metadata: serde_json::json!({}),
        };
        if let Err(err) = shikra_store::repo::upsert_session(&self.pool, &record).await {
            tracing::warn!(%err, session = %handle.id, "failed to persist session");
        }
    }
}

pub fn platform_str(value: i32) -> String {
    use shikra_proto::v1::Platform;
    match Platform::try_from(value) {
        Ok(Platform::Windows) => "windows".into(),
        Ok(Platform::Linux) => "linux".into(),
        Ok(Platform::Macos) => "macos".into(),
        _ => "unknown".into(),
    }
}

pub fn architecture_str(value: i32) -> String {
    use shikra_proto::v1::Architecture;
    match Architecture::try_from(value) {
        Ok(Architecture::X8664) => "x86_64".into(),
        Ok(Architecture::Aarch64) => "aarch64".into(),
        _ => "unknown".into(),
    }
}

pub fn kind_str(value: i32) -> String {
    use shikra_proto::v1::SessionKind;
    match SessionKind::try_from(value) {
        Ok(SessionKind::Beacon) => "beacon".into(),
        Ok(SessionKind::External) => "external".into(),
        _ => "session".into(),
    }
}
