use crate::state::{hash_operator_token, OperatorIdentity, OperatorRole, ServerState};
use shikra_crypto::util::ct_eq;
use std::sync::Arc;
use tonic::service::Interceptor;
use tonic::{Request, Status};

/// Metadata key carrying the authenticated operator identity.
pub const OPERATOR_IDENTITY_KEY: &str = "shikra-operator";

#[derive(Clone)]
pub struct OperatorAuth {
    state: Arc<ServerState>,
}

impl OperatorAuth {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

impl Interceptor for OperatorAuth {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let presented = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("missing operator token"))?
            .to_string();

        // Bootstrap admin token (state-dir file) always maps to the admin role.
        if ct_eq(presented.as_bytes(), self.state.operator_token.as_bytes()) {
            let identity = OperatorIdentity {
                id: uuid::Uuid::nil(),
                name: "admin".into(),
                role: OperatorRole::Admin,
            };
            request.extensions_mut().insert(OperatorContext(identity));
            return Ok(request);
        }

        let token_hash = hash_operator_token(&presented);
        match self.state.operators.lookup(&token_hash) {
            Some(identity) => {
                request.extensions_mut().insert(OperatorContext(identity));
                Ok(request)
            }
            None => {
                audit_auth_failure(&self.state);
                Err(Status::unauthenticated("invalid operator token"))
            }
        }
    }
}

/// Records a throttled audit event for failed operator authentication.
///
/// At most one event is written per `AUTH_AUDIT_INTERVAL` so a token-guessing
/// flood cannot amplify into unbounded database writes.
fn audit_auth_failure(state: &Arc<ServerState>) {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    use std::time::{SystemTime, UNIX_EPOCH};

    const AUTH_AUDIT_INTERVAL: u64 = 5;
    static LAST_EVENT: OnceLock<AtomicU64> = OnceLock::new();
    let last = LAST_EVENT.get_or_init(|| AtomicU64::new(0));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let previous = last.load(Ordering::Relaxed);
    if now.saturating_sub(previous) < AUTH_AUDIT_INTERVAL {
        return;
    }
    if last
        .compare_exchange(previous, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return;
    }

    let pool = state.pool.clone();
    tokio::spawn(async move {
        let _ = shikra_store::repo::insert_event(
            &pool,
            "operator_auth_failed",
            None,
            serde_json::json!({ "reason": "invalid token" }),
        )
        .await;
    });
}

/// Identity attached to authenticated requests.
#[derive(Debug, Clone)]
pub struct OperatorContext(pub OperatorIdentity);

/// Extracts the authenticated operator from a request, if present.
pub fn operator_of<T>(request: &Request<T>) -> Option<OperatorIdentity> {
    request
        .extensions()
        .get::<OperatorContext>()
        .map(|context| context.0.clone())
}

/// Requires the authenticated operator to hold at least `required` role.
pub fn require_role<T>(
    request: &Request<T>,
    required: OperatorRole,
) -> Result<OperatorIdentity, Status> {
    let identity =
        operator_of(request).ok_or_else(|| Status::unauthenticated("missing operator identity"))?;
    if identity.role < required {
        return Err(Status::permission_denied(format!(
            "role `{}` cannot perform this action (requires `{}`)",
            identity.role.as_str(),
            required.as_str()
        )));
    }
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::OperatorRegistry;
    use std::sync::Arc;

    fn state_with_operator(token: &str, role: OperatorRole) -> Arc<ServerState> {
        let registry = Arc::new(OperatorRegistry::new());
        registry.insert(
            hash_operator_token(token),
            OperatorIdentity {
                id: uuid::Uuid::new_v4(),
                name: "alice".into(),
                role,
            },
        );
        Arc::new(ServerState {
            pool: sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://placeholder")
                .expect("lazy pool"),
            identity: Arc::new(shikra_crypto::signing::Identity::generate()),
            enroll_token: Arc::new("enroll".into()),
            operator_token: Arc::new("bootstrap-admin-token".into()),
            engagement_id: uuid::Uuid::nil(),
            sessions: Arc::new(crate::state::SessionRegistry::new()),
            tunnels: Arc::new(crate::tunnel::TunnelHub::new()),
            forwards: Arc::new(crate::tunnel::ForwardRegistry::new()),
            operators: registry,
            hosting_dir: Arc::new(std::path::PathBuf::from("/tmp")),
            armory_public: [0u8; 32],
            enroll_limiter: Arc::new(crate::rate_limit::AttemptLimiter::new(
                30,
                std::time::Duration::from_secs(60),
            )),
            profiles: Arc::new(tokio::sync::RwLock::new(
                shikra_transport::profile::ProfileSet::default(),
            )),
            state_dir: Arc::new(std::path::PathBuf::from("/tmp")),
            listeners: Arc::new(crate::listeners::ListenerRegistry::new()),
            webhook: Arc::new(tokio::sync::RwLock::new(None)),
            relay_token: Arc::new("relay".into()),
            external_tokens: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        })
    }

    fn request_with_token(token: &str) -> Request<()> {
        let mut request = Request::new(());
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {token}").parse().expect("metadata"),
        );
        request
    }

    #[tokio::test]
    async fn bootstrap_token_is_admin() {
        let state = state_with_operator("alice-token", OperatorRole::Operator);
        let mut auth = OperatorAuth::new(state);
        let request = auth
            .call(request_with_token("bootstrap-admin-token"))
            .expect("authorized");
        let identity = operator_of(&request).expect("identity");
        assert_eq!(identity.role, OperatorRole::Admin);
    }

    #[tokio::test]
    async fn registered_token_maps_to_role() {
        let state = state_with_operator("alice-token", OperatorRole::Watcher);
        let mut auth = OperatorAuth::new(state);
        let request = auth
            .call(request_with_token("alice-token"))
            .expect("authorized");
        let identity = operator_of(&request).expect("identity");
        assert_eq!(identity.role, OperatorRole::Watcher);
    }

    #[tokio::test]
    async fn unknown_token_is_rejected() {
        let state = state_with_operator("alice-token", OperatorRole::Operator);
        let mut auth = OperatorAuth::new(state);
        assert!(auth.call(request_with_token("nope")).is_err());
    }

    #[tokio::test]
    async fn role_gate_rejects_low_roles() {
        let state = state_with_operator("alice-token", OperatorRole::Watcher);
        let mut auth = OperatorAuth::new(state);
        let request = auth
            .call(request_with_token("alice-token"))
            .expect("authorized");
        assert!(require_role(&request, OperatorRole::Admin).is_err());
        assert!(require_role(&request, OperatorRole::Watcher).is_ok());
    }
}
