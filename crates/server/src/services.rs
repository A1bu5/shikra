use crate::auth::require_role;
use crate::state::{OperatorIdentity, OperatorRole, ServerState, SessionHandle};
use crate::tunnel::to_agent_message;
use shikra_proto::v1::agent_link_server::AgentLink;
use shikra_proto::v1::agent_message;
use shikra_proto::v1::control_plane_server::ControlPlane;
use shikra_proto::v1::operator_tunnel_frame;
use shikra_proto::v1::{
    AddCredentialRequest, AddLootRequest, AddReactionRequest, AgentResult, AgentTask,
    ArmoryKeyInfo, AuditStatus, CanaryInfo, ChatMessageInfo, ChatMessageRequest, ChatMessages,
    ChatQuery, CheckInRequest, CheckInResponse, CreateCanaryRequest, CreateOperatorRequest,
    CreateOperatorResponse, CredentialId, CredentialInfo, Empty, Envelope, EventInfo, EventList,
    EventQuery, ExtensionId, ExtensionInfo, FetchExtensionRequest, FetchExtensionResponse,
    HostInfo, InstallExtensionRequest, ListenerId, ListenerInfo, ListenerSet, LootId, LootInfo,
    MsfExecRequest, MsfExecResult, MsfStatusInfo, OperatorId, OperatorInfo, OperatorTunnelFrame,
    ProfileInfo, ProfileSetInfo, ReactionId, ReactionInfo, RportFwdId, RportFwdInfo,
    RportFwdRequest, RportFwdStatus, ScanRequest, ScanResult, SessionInfo, SessionUiRequest,
    StartListenerRequest, TaskCancel, TaskQuery, TaskRecord, TaskRequest, TaskResult, TaskState,
    VersionInfo, WebhookInfo,
};
use shikra_transport::wire;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use uuid::Uuid;

type EnvelopeStream = Pin<Box<dyn Stream<Item = Result<Envelope, Status>> + Send>>;

pub struct AgentLinkService {
    state: Arc<ServerState>,
}

impl AgentLinkService {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl AgentLink for AgentLinkService {
    async fn check_in(
        &self,
        request: Request<CheckInRequest>,
    ) -> Result<Response<CheckInResponse>, Status> {
        let remote_addr = request
            .remote_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_default();
        let response =
            crate::enrollment::enroll(&self.state, request.into_inner(), remote_addr).await?;
        Ok(Response::new(response))
    }

    type StreamTasksStream = EnvelopeStream;

    async fn stream_tasks(
        &self,
        request: Request<tonic::Streaming<Envelope>>,
    ) -> Result<Response<Self::StreamTasksStream>, Status> {
        let mut inbound = request.into_inner();

        let first = inbound
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("empty task stream"))?;

        let session_id = first.session_id.clone();
        let handle = self
            .state
            .sessions
            .get(&session_id)
            .await
            .ok_or_else(|| Status::not_found("unknown session"))?;

        let task_rx = handle
            .take_task_rx()
            .await
            .ok_or_else(|| Status::failed_precondition("session already has an active stream"))?;

        // Validate the first envelope before accepting the stream.
        {
            let mut keys = handle.keys.lock().await;
            wire::open_message(&mut keys, &first)
                .map_err(|_| Status::unauthenticated("envelope rejected"))?;
        }
        self.state.touch_session(&handle).await;

        let (out_tx, out_rx) = mpsc::channel::<Result<Envelope, Status>>(64);

        let state = self.state.clone();
        let writer_handle = handle.clone();
        tokio::spawn(async move {
            let mut task_rx = task_rx;
            let mut shutdown = false;

            while !shutdown {
                tokio::select! {
                    incoming = inbound.message() => {
                        match incoming {
                            Ok(Some(envelope)) => {
                                if let Err(err) = state.process_envelope(&writer_handle, &envelope).await {
                                    tracing::warn!(session = %writer_handle.id, %err, "dropping agent stream");
                                    shutdown = true;
                                }
                            }
                            Ok(None) => shutdown = true,
                            Err(_) => shutdown = true,
                        }
                    }
                    outgoing = task_rx.recv() => {
                        match outgoing {
                            Some(message) => {
                                let sealed = {
                                    let mut keys = writer_handle.keys.lock().await;
                                    wire::seal_message(&mut keys, &message)
                                };
                                match sealed {
                                    Ok(envelope) => {
                                        if out_tx.send(Ok(envelope)).await.is_err() {
                                            shutdown = true;
                                        }
                                    }
                                    Err(err) => {
                                        tracing::error!(session = %writer_handle.id, %err, "failed to seal outbound envelope");
                                        shutdown = true;
                                    }
                                }
                            }
                            None => shutdown = true,
                        }
                    }
                }
            }

            state.retire_session(&writer_handle).await;
            tracing::info!(session = %writer_handle.id, "agent stream ended");
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(out_rx))))
    }
}

pub struct ControlPlaneService {
    state: Arc<ServerState>,
}

impl ControlPlaneService {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl ControlPlane for ControlPlaneService {
    async fn get_version(&self, _request: Request<Empty>) -> Result<Response<VersionInfo>, Status> {
        Ok(Response::new(VersionInfo {
            semver: env!("CARGO_PKG_VERSION").to_string(),
            commit: option_env!("SHIKRA_GIT_COMMIT")
                .unwrap_or("unknown")
                .to_string(),
            build_time: option_env!("SHIKRA_BUILD_TIME")
                .unwrap_or("unknown")
                .to_string(),
        }))
    }

    type ListSessionsStream = Pin<Box<dyn Stream<Item = Result<SessionInfo, Status>> + Send>>;

    async fn list_sessions(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::ListSessionsStream>, Status> {
        let handles = self.state.sessions.list().await;
        let mut sessions = Vec::with_capacity(handles.len());
        for handle in handles {
            sessions.push(handle.info.lock().await.clone());
        }
        Ok(Response::new(Box::pin(tokio_stream::iter(
            sessions.into_iter().map(Ok),
        ))))
    }

    type SubmitTaskStream = Pin<Box<dyn Stream<Item = Result<TaskResult, Status>> + Send>>;

    async fn submit_task(
        &self,
        request: Request<TaskRequest>,
    ) -> Result<Response<Self::SubmitTaskStream>, Status> {
        let request = request.into_inner();
        let handle = self
            .state
            .sessions
            .get(&request.session_id)
            .await
            .ok_or_else(|| Status::not_found("unknown or disconnected session"))?;

        if handle.is_beacon {
            let info = handle.info.lock().await;
            if info.status == shikra_proto::v1::SessionStatus::Stale as i32 {
                return Err(Status::failed_precondition(
                    "beacon is stale (missed check-ins); wait for it to reconnect",
                ));
            }
        }

        let task_id = Uuid::now_v7().to_string();
        let args = if request.args.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&request.args).unwrap_or(serde_json::Value::Null)
        };

        let task_row = shikra_store::models::TaskRow {
            id: Uuid::parse_str(&task_id).unwrap_or_else(|_| Uuid::new_v4()),
            session_id: Uuid::parse_str(&request.session_id).unwrap_or_else(|_| Uuid::new_v4()),
            operator_id: None,
            command: request.command.clone(),
            payload: args.clone(),
            state: "dispatched".into(),
            exit_code: None,
            output: None,
            ai_initiated: false,
            approved_by: None,
            created_at: time::OffsetDateTime::now_utc(),
            dispatched_at: Some(time::OffsetDateTime::now_utc()),
            completed_at: None,
        };
        shikra_store::repo::insert_task(&self.state.pool, &task_row)
            .await
            .map_err(|err| Status::internal(format!("failed to persist task: {err}")))?;

        let (result_tx, result_rx) = oneshot::channel::<AgentResult>();
        handle
            .pending
            .lock()
            .await
            .insert(task_id.clone(), result_tx);

        let task_message = AgentTask {
            task_id: task_id.clone(),
            kind: request.command.clone(),
            args: request.args.clone(),
            payload: request.payload.clone(),
        };

        if let Err(err) = handle.send_task(task_message).await {
            handle.pending.lock().await.remove(&task_id);
            let _ = shikra_store::repo::update_task_state(
                &self.state.pool,
                task_row.id,
                "failed",
                None,
                Some(err),
            )
            .await;
            return Err(Status::unavailable(err));
        }

        let session_id = handle.id.clone();
        let pool = self.state.pool.clone();
        let task_uuid = task_row.id;
        let command = request.command.clone();
        let handle_for_stream = handle.clone();
        // Beacons poll at their own cadence, so the operator waits longer.
        let wait_secs = if handle.is_beacon { 300 } else { 120 };

        let stream = async_stream::stream! {
            let outcome = tokio::time::timeout(Duration::from_secs(wait_secs), result_rx).await;
            let result = match outcome {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => {
                    let _ = shikra_store::repo::update_task_state(&pool, task_uuid, "failed", None, Some("agent disconnected")).await;
                    yield Err(Status::unavailable("agent disconnected before returning a result"));
                    return;
                }
                Err(_) => {
                    let _ = shikra_store::repo::update_task_state(&pool, task_uuid, "failed", None, Some("task timed out")).await;
                    yield Err(Status::deadline_exceeded("task timed out"));
                    return;
                }
            };

            // Binary or large outputs must not be stored verbatim in the audit DB.
            let persisted = persistable_output(&command, &result.stdout);
            let cancelled = handle_for_stream
                .cancelled
                .lock()
                .await
                .remove(&result.task_id);
            let state = if cancelled {
                "cancelled"
            } else if result.exit_code == 0 {
                "completed"
            } else {
                "failed"
            };
            let _ = shikra_store::repo::update_task_state(
                &pool,
                task_uuid,
                state,
                Some(result.exit_code),
                persisted.as_deref(),
            )
            .await;
            let _ = shikra_store::repo::insert_event(
                &pool,
                "task_completed",
                Some(task_uuid),
                serde_json::json!({
                    "session_id": session_id,
                    "command": command,
                    "exit_code": result.exit_code,
                    "output_bytes": result.stdout.len(),
                }),
            )
            .await;

            let proto_state = if cancelled {
                TaskState::Cancelled as i32
            } else if result.exit_code == 0 {
                TaskState::Completed as i32
            } else {
                TaskState::Failed as i32
            };

            tracing::info!(session = %session_id, task = %result.task_id, "task completed");
            let mut output = result.stdout;
            if !result.stderr.is_empty() {
                if !output.is_empty() {
                    output.push(b'\n');
                }
                output.extend_from_slice(&result.stderr);
            }
            yield Ok(TaskResult {
                task_id: result.task_id,
                session_id,
                state: proto_state,
                exit_code: result.exit_code,
                output,
                completed_at: Some(wire::to_timestamp(time::OffsetDateTime::now_utc())),
            });
        };

        Ok(Response::new(Box::pin(stream)))
    }

    type StreamTunnelStream =
        Pin<Box<dyn Stream<Item = Result<OperatorTunnelFrame, Status>> + Send>>;

    async fn stream_tunnel(
        &self,
        request: Request<tonic::Streaming<OperatorTunnelFrame>>,
    ) -> Result<Response<Self::StreamTunnelStream>, Status> {
        let mut inbound = request.into_inner();
        let (out_tx, out_rx) = mpsc::channel::<Result<OperatorTunnelFrame, Status>>(256);
        let (route_tx, mut route_rx) = mpsc::channel::<OperatorTunnelFrame>(256);
        let state = self.state.clone();

        // Frames routed by the hub arrive as plain frames; forward them to gRPC.
        let forward_tx = out_tx.clone();
        tokio::spawn(async move {
            while let Some(frame) = route_rx.recv().await {
                if forward_tx.send(Ok(frame)).await.is_err() {
                    break;
                }
            }
        });

        tokio::spawn(async move {
            let mut registered: Vec<(String, String)> = Vec::new();
            while let Ok(Some(frame)) = inbound.message().await {
                let session_id = frame.session_id.clone();
                let tunnel_id = frame.tunnel_id.clone();
                let handle = match state.sessions.get(&session_id).await {
                    Some(handle) => handle,
                    None => {
                        let _ = out_tx
                            .send(Ok(OperatorTunnelFrame {
                                session_id: session_id.clone(),
                                tunnel_id: tunnel_id.clone(),
                                body: Some(operator_tunnel_frame::Body::Close(
                                    shikra_proto::v1::TunnelClose {
                                        tunnel_id: tunnel_id.clone(),
                                        reason: "session not connected".into(),
                                    },
                                )),
                            }))
                            .await;
                        continue;
                    }
                };

                if handle.is_beacon {
                    let _ = out_tx
                        .send(Ok(OperatorTunnelFrame {
                            session_id: session_id.clone(),
                            tunnel_id: tunnel_id.clone(),
                            body: Some(operator_tunnel_frame::Body::Close(
                                shikra_proto::v1::TunnelClose {
                                    tunnel_id: tunnel_id.clone(),
                                    reason: "beacons do not support tunnels".into(),
                                },
                            )),
                        }))
                        .await;
                    continue;
                }

                let Some(body) = frame.body else { continue };
                let is_close = matches!(body, operator_tunnel_frame::Body::Close(_));
                let agent_message = to_agent_message(body, &tunnel_id, &session_id);

                if matches!(agent_message.body, Some(agent_message::Body::TunnelOpen(_))) {
                    state
                        .tunnels
                        .register(&session_id, &tunnel_id, route_tx.clone())
                        .await;
                    registered.push((session_id.clone(), tunnel_id.clone()));
                }

                if let Err(err) = handle.send_message(agent_message).await {
                    let _ = out_tx
                        .send(Ok(OperatorTunnelFrame {
                            session_id: session_id.clone(),
                            tunnel_id: tunnel_id.clone(),
                            body: Some(operator_tunnel_frame::Body::Close(
                                shikra_proto::v1::TunnelClose {
                                    tunnel_id: tunnel_id.clone(),
                                    reason: err.to_string(),
                                },
                            )),
                        }))
                        .await;
                }

                if is_close {
                    state.tunnels.unregister(&session_id, &tunnel_id).await;
                    registered.retain(|(s, t)| !(s == &session_id && t == &tunnel_id));
                }
            }

            for (session_id, tunnel_id) in registered {
                state.tunnels.unregister(&session_id, &tunnel_id).await;
                if let Some(handle) = state.sessions.get(&session_id).await {
                    let _ = handle
                        .send_message(shikra_proto::v1::AgentMessage {
                            body: Some(agent_message::Body::TunnelClose(
                                shikra_proto::v1::TunnelClose {
                                    tunnel_id,
                                    reason: "operator stream closed".into(),
                                },
                            )),
                        })
                        .await;
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(out_rx))))
    }

    async fn start_rport_fwd(
        &self,
        request: Request<RportFwdRequest>,
    ) -> Result<Response<RportFwdStatus>, Status> {
        let request = request.into_inner();
        let handle = self
            .state
            .sessions
            .get(&request.session_id)
            .await
            .ok_or_else(|| Status::not_found("unknown or disconnected session"))?;
        if handle.is_beacon {
            return Err(Status::failed_precondition(
                "remote port forwarding requires a session",
            ));
        }

        let transport = if request.transport.is_empty() {
            "tcp".to_string()
        } else {
            request.transport.clone()
        };
        if !matches!(transport.as_str(), "tcp" | "pipe") {
            return Err(Status::invalid_argument("transport must be tcp or pipe"));
        }
        let rule = self
            .state
            .forwards
            .add(&request.session_id, &request.bind, &request.to, &transport)
            .await;

        let task = AgentTask {
            task_id: Uuid::now_v7().to_string(),
            kind: "rportfwd_start".into(),
            args: serde_json::to_vec(
                &serde_json::json!({ "bind": request.bind, "transport": transport }),
            )
            .unwrap_or_default(),
            payload: Vec::new(),
        };
        if let Err(err) = handle.send_task(task).await {
            self.state.forwards.remove(&rule.id).await;
            return Err(Status::unavailable(err));
        }

        let _ = shikra_store::repo::insert_event(
            &self.state.pool,
            "rportfwd_started",
            Uuid::parse_str(&request.session_id).ok(),
            serde_json::json!({ "bind": request.bind, "to": request.to, "forward_id": rule.id }),
        )
        .await;

        Ok(Response::new(RportFwdStatus {
            forward_id: rule.id.clone(),
            running: true,
            message: format!("listening on {} -> {}", request.bind, request.to),
        }))
    }

    async fn stop_rport_fwd(
        &self,
        request: Request<RportFwdId>,
    ) -> Result<Response<RportFwdStatus>, Status> {
        let request = request.into_inner();
        let rule = self
            .state
            .forwards
            .remove(&request.forward_id)
            .await
            .ok_or_else(|| Status::not_found("unknown forward id"))?;

        let task = AgentTask {
            task_id: Uuid::now_v7().to_string(),
            kind: "rportfwd_stop".into(),
            args: serde_json::to_vec(&serde_json::json!({ "bind": rule.bind })).unwrap_or_default(),
            payload: Vec::new(),
        };
        if let Some(handle) = self.state.sessions.get(&rule.session_id).await {
            let _ = handle.send_task(task).await;
        }

        Ok(Response::new(RportFwdStatus {
            forward_id: rule.id.clone(),
            running: false,
            message: "stopped".into(),
        }))
    }

    type ListRportFwdsStream = Pin<Box<dyn Stream<Item = Result<RportFwdInfo, Status>> + Send>>;

    async fn list_rport_fwds(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<Self::ListRportFwdsStream>, Status> {
        require_role(&request, OperatorRole::Watcher)?;
        let rules = self.state.forwards.list().await;
        let infos: Vec<RportFwdInfo> = rules
            .into_iter()
            .map(|rule| RportFwdInfo {
                forward_id: rule.id.clone(),
                session_id: rule.session_id.clone(),
                bind: rule.bind.clone(),
                to: rule.to.clone(),
                connections: rule.connections.load(std::sync::atomic::Ordering::Relaxed),
                transport: rule.transport.clone(),
            })
            .collect();
        Ok(Response::new(Box::pin(tokio_stream::iter(
            infos.into_iter().map(Ok),
        ))))
    }

    type ListOperatorsStream = Pin<Box<dyn Stream<Item = Result<OperatorInfo, Status>> + Send>>;

    type ListTasksStream = Pin<Box<dyn Stream<Item = Result<TaskRecord, Status>> + Send>>;

    async fn cancel_task(&self, request: Request<TaskCancel>) -> Result<Response<Empty>, Status> {
        let actor = require_role(&request, OperatorRole::Operator)?;
        let request = request.into_inner();
        let handle = self
            .state
            .sessions
            .get(&request.session_id)
            .await
            .ok_or_else(|| Status::not_found("unknown or disconnected session"))?;

        let task_uuid = Uuid::parse_str(&request.task_id)
            .map_err(|_| Status::invalid_argument("invalid task id"))?;
        let row = shikra_store::repo::list_tasks_filtered(&self.state.pool, None, 1000)
            .await
            .map_err(|err| Status::internal(err.to_string()))?
            .into_iter()
            .find(|task| task.id == task_uuid)
            .ok_or_else(|| Status::not_found("unknown task"))?;
        if !matches!(row.state.as_str(), "dispatched" | "running") {
            return Err(Status::failed_precondition(format!(
                "task is already {}",
                row.state
            )));
        }

        handle
            .cancelled
            .lock()
            .await
            .insert(request.task_id.clone());
        // Best effort: ask the agent to stop the job (session agents process
        // this out of band on their job task).
        let _ = handle
            .send_task(AgentTask {
                task_id: Uuid::now_v7().to_string(),
                kind: "job_kill".into(),
                args: serde_json::json!({ "task_id": request.task_id })
                    .to_string()
                    .into_bytes(),
                payload: Vec::new(),
            })
            .await;

        // Unblock the waiting submit stream when the agent never answers.
        if let Some(sender) = handle.pending.lock().await.remove(&request.task_id) {
            let _ = sender.send(AgentResult {
                task_id: request.task_id.clone(),
                exit_code: 137,
                stdout: Vec::new(),
                stderr: b"cancelled by operator".to_vec(),
            });
        }

        let _ = shikra_store::repo::update_task_state(
            &self.state.pool,
            task_uuid,
            "cancelled",
            None,
            Some("cancelled by operator"),
        )
        .await;
        shikra_store::repo_team::audit(
            &self.state.pool,
            "operator",
            "task_cancelled",
            Some(&actor.name),
            serde_json::json!({
                "session_id": request.session_id,
                "task_id": request.task_id,
            }),
        )
        .await;
        Ok(Response::new(Empty {}))
    }

    async fn list_tasks(
        &self,
        request: Request<TaskQuery>,
    ) -> Result<Response<Self::ListTasksStream>, Status> {
        require_role(&request, OperatorRole::Watcher)?;
        let request = request.into_inner();
        let session_id = if request.session_id.is_empty() {
            None
        } else {
            Some(
                Uuid::parse_str(&request.session_id)
                    .map_err(|_| Status::invalid_argument("invalid session id"))?,
            )
        };
        let limit = if request.limit == 0 {
            200
        } else {
            request.limit.min(1000) as i64
        };
        let rows = shikra_store::repo::list_tasks_filtered(&self.state.pool, session_id, limit)
            .await
            .map_err(internal)?;
        let records: Vec<TaskRecord> = rows.into_iter().map(task_record).collect();
        Ok(Response::new(Box::pin(tokio_stream::iter(
            records.into_iter().map(Ok),
        ))))
    }

    async fn list_operators(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<Self::ListOperatorsStream>, Status> {
        require_role(&request, OperatorRole::Operator)?;
        let operators = shikra_store::repo_team::list_operators(&self.state.pool)
            .await
            .map_err(internal)?;
        let infos: Vec<OperatorInfo> = operators
            .into_iter()
            .map(|operator| OperatorInfo {
                id: operator.id.to_string(),
                name: operator.name,
                role: operator.role,
                disabled: operator.disabled,
                created_at: Some(wire::to_timestamp(operator.created_at)),
            })
            .collect();
        Ok(Response::new(Box::pin(tokio_stream::iter(
            infos.into_iter().map(Ok),
        ))))
    }

    async fn create_operator(
        &self,
        request: Request<CreateOperatorRequest>,
    ) -> Result<Response<CreateOperatorResponse>, Status> {
        let actor = require_role(&request, OperatorRole::Admin)?;
        let request = request.into_inner();
        if request.name.trim().is_empty() {
            return Err(Status::invalid_argument("operator name is required"));
        }
        let role = OperatorRole::parse(&request.role);
        let token = crate::bootstrap::new_token();
        let token_hash = crate::state::hash_operator_token(&token);
        let id = Uuid::new_v4();
        let password_hash = "!token-only".to_string();
        shikra_store::repo_team::insert_operator(
            &self.state.pool,
            id,
            request.name.trim(),
            role.as_str(),
            &password_hash,
            Some(&token_hash),
        )
        .await
        .map_err(internal)?;

        self.state.operators.insert(
            token_hash,
            OperatorIdentity {
                id,
                name: request.name.trim().to_string(),
                role,
            },
        );
        shikra_store::repo_team::audit(
            &self.state.pool,
            &actor.name,
            "operator_created",
            Some(&request.name),
            serde_json::json!({ "role": role.as_str() }),
        )
        .await;

        Ok(Response::new(CreateOperatorResponse {
            operator: Some(OperatorInfo {
                id: id.to_string(),
                name: request.name.trim().to_string(),
                role: role.as_str().into(),
                disabled: false,
                created_at: Some(wire::to_timestamp(time::OffsetDateTime::now_utc())),
            }),
            token,
        }))
    }

    async fn delete_operator(
        &self,
        request: Request<OperatorId>,
    ) -> Result<Response<Empty>, Status> {
        let actor = require_role(&request, OperatorRole::Admin)?;
        let request = request.into_inner();
        let id = Uuid::parse_str(&request.id)
            .map_err(|_| Status::invalid_argument("invalid operator id"))?;
        let operators = shikra_store::repo_team::list_operators(&self.state.pool)
            .await
            .map_err(internal)?;
        if let Some(operator) = operators.iter().find(|operator| operator.id == id) {
            if let Some(token_hash) = &operator.token_hash {
                self.state.operators.remove(token_hash);
            }
            shikra_store::repo_team::delete_operator(&self.state.pool, id)
                .await
                .map_err(internal)?;
            shikra_store::repo_team::audit(
                &self.state.pool,
                &actor.name,
                "operator_deleted",
                Some(&operator.name),
                serde_json::json!({}),
            )
            .await;
            Ok(Response::new(Empty {}))
        } else {
            Err(Status::not_found("operator not found"))
        }
    }

    type ListCredentialsStream = Pin<Box<dyn Stream<Item = Result<CredentialInfo, Status>> + Send>>;

    async fn list_credentials(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<Self::ListCredentialsStream>, Status> {
        require_role(&request, OperatorRole::Watcher)?;
        let rows =
            shikra_store::repo_team::list_credentials(&self.state.pool, self.state.engagement_id)
                .await
                .map_err(internal)?;
        let infos: Vec<CredentialInfo> = rows.into_iter().map(credential_info).collect();
        Ok(Response::new(Box::pin(tokio_stream::iter(
            infos.into_iter().map(Ok),
        ))))
    }

    async fn add_credential(
        &self,
        request: Request<AddCredentialRequest>,
    ) -> Result<Response<CredentialInfo>, Status> {
        let actor = require_role(&request, OperatorRole::Operator)?;
        let request = request.into_inner();
        if request.username.trim().is_empty() || request.secret.is_empty() {
            return Err(Status::invalid_argument("username and secret are required"));
        }
        let row = shikra_store::models::CredentialRow {
            id: Uuid::new_v4(),
            engagement_id: Some(self.state.engagement_id),
            session_id: None,
            host: request.host,
            domain: request.domain,
            username: request.username,
            secret: request.secret,
            kind: if request.kind.is_empty() {
                "password".into()
            } else {
                request.kind
            },
            source: request.source,
            created_at: time::OffsetDateTime::now_utc(),
        };
        shikra_store::repo_team::insert_credential(&self.state.pool, &row)
            .await
            .map_err(internal)?;
        shikra_store::repo_team::audit(
            &self.state.pool,
            &actor.name,
            "credential_added",
            Some(&row.username),
            serde_json::json!({ "host": row.host, "kind": row.kind }),
        )
        .await;
        let info = credential_info(row);
        self.state.trigger_reactions("credential_added").await;
        Ok(Response::new(info))
    }

    async fn delete_credential(
        &self,
        request: Request<CredentialId>,
    ) -> Result<Response<Empty>, Status> {
        let actor = require_role(&request, OperatorRole::Operator)?;
        let request = request.into_inner();
        let id = Uuid::parse_str(&request.id)
            .map_err(|_| Status::invalid_argument("invalid credential id"))?;
        let deleted = shikra_store::repo_team::delete_credential(&self.state.pool, id)
            .await
            .map_err(internal)?;
        if !deleted {
            return Err(Status::not_found("credential not found"));
        }
        shikra_store::repo_team::audit(
            &self.state.pool,
            &actor.name,
            "credential_deleted",
            Some(&request.id),
            serde_json::json!({}),
        )
        .await;
        Ok(Response::new(Empty {}))
    }

    type ListLootStream = Pin<Box<dyn Stream<Item = Result<LootInfo, Status>> + Send>>;

    async fn list_loot(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<Self::ListLootStream>, Status> {
        require_role(&request, OperatorRole::Watcher)?;
        let rows =
            shikra_store::repo_team::list_loot(&self.state.pool, self.state.engagement_id, false)
                .await
                .map_err(internal)?;
        let infos: Vec<LootInfo> = rows.into_iter().map(loot_info).collect();
        Ok(Response::new(Box::pin(tokio_stream::iter(
            infos.into_iter().map(Ok),
        ))))
    }

    async fn add_loot(
        &self,
        request: Request<AddLootRequest>,
    ) -> Result<Response<LootInfo>, Status> {
        let actor = require_role(&request, OperatorRole::Operator)?;
        let request = request.into_inner();
        if request.name.trim().is_empty() {
            return Err(Status::invalid_argument("loot name is required"));
        }
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&request.data);
        let sha256: String = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        let row = shikra_store::models::LootRow {
            id: Uuid::new_v4(),
            engagement_id: Some(self.state.engagement_id),
            session_id: None,
            kind: if request.kind.is_empty() {
                "file".into()
            } else {
                request.kind
            },
            name: request.name,
            size: request.data.len() as i64,
            sha256: Some(sha256),
            data: Some(request.data),
            created_at: time::OffsetDateTime::now_utc(),
        };
        shikra_store::repo_team::insert_loot(&self.state.pool, &row)
            .await
            .map_err(internal)?;
        shikra_store::repo_team::audit(
            &self.state.pool,
            &actor.name,
            "loot_added",
            Some(&row.name),
            serde_json::json!({ "size": row.size, "kind": row.kind }),
        )
        .await;
        let info = loot_info(row);
        Ok(Response::new(info))
    }

    async fn delete_loot(&self, request: Request<LootId>) -> Result<Response<Empty>, Status> {
        let actor = require_role(&request, OperatorRole::Operator)?;
        let request = request.into_inner();
        let id = Uuid::parse_str(&request.id)
            .map_err(|_| Status::invalid_argument("invalid loot id"))?;
        let deleted = shikra_store::repo_team::delete_loot(&self.state.pool, id)
            .await
            .map_err(internal)?;
        if !deleted {
            return Err(Status::not_found("loot not found"));
        }
        shikra_store::repo_team::audit(
            &self.state.pool,
            &actor.name,
            "loot_deleted",
            Some(&request.id),
            serde_json::json!({}),
        )
        .await;
        Ok(Response::new(Empty {}))
    }

    type ListCanariesStream = Pin<Box<dyn Stream<Item = Result<CanaryInfo, Status>> + Send>>;

    async fn list_canaries(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<Self::ListCanariesStream>, Status> {
        require_role(&request, OperatorRole::Watcher)?;
        let rows = shikra_store::repo_team::list_canaries(&self.state.pool)
            .await
            .map_err(internal)?;
        let infos: Vec<CanaryInfo> = rows.into_iter().map(canary_info).collect();
        Ok(Response::new(Box::pin(tokio_stream::iter(
            infos.into_iter().map(Ok),
        ))))
    }

    async fn create_canary(
        &self,
        request: Request<CreateCanaryRequest>,
    ) -> Result<Response<CanaryInfo>, Status> {
        let actor = require_role(&request, OperatorRole::Operator)?;
        let request = request.into_inner();
        let token = crate::bootstrap::new_token();
        let row = shikra_store::models::CanaryRow {
            id: Uuid::new_v4(),
            token: token.clone(),
            kind: if request.kind.is_empty() {
                "http".into()
            } else {
                request.kind
            },
            note: request.note,
            triggered: false,
            triggered_at: None,
            created_at: time::OffsetDateTime::now_utc(),
        };
        shikra_store::repo_team::insert_canary(&self.state.pool, &row)
            .await
            .map_err(internal)?;
        shikra_store::repo_team::audit(
            &self.state.pool,
            &actor.name,
            "canary_created",
            Some(&token),
            serde_json::json!({ "kind": row.kind }),
        )
        .await;
        let info = canary_info(row);
        Ok(Response::new(info))
    }

    async fn verify_audit(&self, request: Request<Empty>) -> Result<Response<AuditStatus>, Status> {
        require_role(&request, OperatorRole::Operator)?;
        match shikra_store::repo_team::verify_audit_chain(&self.state.pool).await {
            Ok(entries) => Ok(Response::new(AuditStatus {
                valid: true,
                entries,
                message: "audit chain intact".into(),
            })),
            Err(err) => Ok(Response::new(AuditStatus {
                valid: false,
                entries: 0,
                message: err.to_string(),
            })),
        }
    }

    type ListReactionsStream = Pin<Box<dyn Stream<Item = Result<ReactionInfo, Status>> + Send>>;

    async fn list_reactions(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<Self::ListReactionsStream>, Status> {
        require_role(&request, OperatorRole::Watcher)?;
        let rows = shikra_store::repo_team::list_reaction_rules(&self.state.pool)
            .await
            .map_err(internal)?;
        let infos: Vec<ReactionInfo> = rows
            .into_iter()
            .map(|row| ReactionInfo {
                id: row.id.to_string(),
                event_kind: row.event_kind,
                action: row.action,
                enabled: row.enabled,
            })
            .collect();
        Ok(Response::new(Box::pin(tokio_stream::iter(
            infos.into_iter().map(Ok),
        ))))
    }

    async fn add_reaction(
        &self,
        request: Request<AddReactionRequest>,
    ) -> Result<Response<ReactionInfo>, Status> {
        let actor = require_role(&request, OperatorRole::Operator)?;
        let request = request.into_inner();
        if request.event_kind.trim().is_empty() || request.action.trim().is_empty() {
            return Err(Status::invalid_argument(
                "event_kind and action are required",
            ));
        }
        let row = shikra_store::models::ReactionRuleRow {
            id: Uuid::new_v4(),
            event_kind: request.event_kind.trim().to_string(),
            action: request.action.trim().to_string(),
            enabled: true,
            created_at: time::OffsetDateTime::now_utc(),
        };
        shikra_store::repo_team::insert_reaction_rule(&self.state.pool, &row)
            .await
            .map_err(internal)?;
        shikra_store::repo_team::audit(
            &self.state.pool,
            &actor.name,
            "reaction_added",
            Some(&row.event_kind),
            serde_json::json!({ "action": row.action }),
        )
        .await;
        Ok(Response::new(ReactionInfo {
            id: row.id.to_string(),
            event_kind: row.event_kind,
            action: row.action,
            enabled: row.enabled,
        }))
    }

    async fn delete_reaction(
        &self,
        request: Request<ReactionId>,
    ) -> Result<Response<Empty>, Status> {
        let actor = require_role(&request, OperatorRole::Operator)?;
        let request = request.into_inner();
        let id = Uuid::parse_str(&request.id)
            .map_err(|_| Status::invalid_argument("invalid reaction id"))?;
        let deleted = shikra_store::repo_team::delete_reaction_rule(&self.state.pool, id)
            .await
            .map_err(internal)?;
        if !deleted {
            return Err(Status::not_found("reaction rule not found"));
        }
        shikra_store::repo_team::audit(
            &self.state.pool,
            &actor.name,
            "reaction_deleted",
            Some(&request.id),
            serde_json::json!({}),
        )
        .await;
        Ok(Response::new(Empty {}))
    }

    async fn run_scan(
        &self,
        request: Request<ScanRequest>,
    ) -> Result<Response<ScanResult>, Status> {
        let actor = require_role(&request, OperatorRole::Operator)?;
        let request = request.into_inner();
        if request.target.trim().is_empty() {
            return Err(Status::invalid_argument("scan target is required"));
        }
        let ports = request.ports.trim();
        let extra = request.arguments.trim();
        let hosts = crate::recon::run_nmap(
            &request.target,
            (!ports.is_empty()).then_some(ports),
            (!extra.is_empty()).then_some(extra),
        )
        .await
        .map_err(internal)?;
        crate::recon::store_hosts(&self.state, &hosts).await;
        shikra_store::repo_team::audit(
            &self.state.pool,
            &actor.name,
            "scan_run",
            Some(&request.target),
            serde_json::json!({ "hosts": hosts.len(), "ports": request.ports }),
        )
        .await;
        Ok(Response::new(ScanResult {
            ok: true,
            hosts_found: hosts.len() as u32,
            message: format!("{} live host(s) discovered", hosts.len()),
        }))
    }

    type ListHostsStream = Pin<Box<dyn Stream<Item = Result<HostInfo, Status>> + Send>>;

    async fn list_hosts(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<Self::ListHostsStream>, Status> {
        require_role(&request, OperatorRole::Watcher)?;
        let hosts = shikra_store::repo_team::list_hosts(&self.state.pool, self.state.engagement_id)
            .await
            .map_err(internal)?;
        let infos: Vec<HostInfo> = hosts
            .into_iter()
            .map(|host| HostInfo {
                id: host.id.to_string(),
                ip: host.ip,
                hostname: host.hostname,
                os: host.os,
                ports: serde_json::to_string(&host.ports).unwrap_or_else(|_| "[]".into()),
                source: host.source,
                discovered_at: Some(wire::to_timestamp(host.discovered_at)),
            })
            .collect();
        Ok(Response::new(Box::pin(tokio_stream::iter(
            infos.into_iter().map(Ok),
        ))))
    }

    async fn msf_status(&self, request: Request<Empty>) -> Result<Response<MsfStatusInfo>, Status> {
        require_role(&request, OperatorRole::Operator)?;
        let Some(config) = crate::msf::MsfConfig::from_env() else {
            return Ok(Response::new(MsfStatusInfo {
                connected: false,
                version: String::new(),
                message: "MSF RPC not configured (set SHIKRA_MSF_RPC_URL/USER/PASSWORD)".into(),
            }));
        };
        let mut client = crate::msf::MsfClient::new(config);
        match client.version().await {
            Ok(version) => Ok(Response::new(MsfStatusInfo {
                connected: true,
                version,
                message: "connected".into(),
            })),
            Err(err) => Ok(Response::new(MsfStatusInfo {
                connected: false,
                version: String::new(),
                message: err.to_string(),
            })),
        }
    }

    async fn msf_exec(
        &self,
        request: Request<MsfExecRequest>,
    ) -> Result<Response<MsfExecResult>, Status> {
        let actor = require_role(&request, OperatorRole::Operator)?;
        let request = request.into_inner();
        if request.command.trim().is_empty() {
            return Err(Status::invalid_argument("MSF command is required"));
        }
        let config = crate::msf::MsfConfig::from_env()
            .ok_or_else(|| Status::failed_precondition("MSF RPC not configured"))?;
        let mut client = crate::msf::MsfClient::new(config);
        let output = client
            .console_exec(&request.command)
            .await
            .map_err(internal)?;
        shikra_store::repo_team::audit(
            &self.state.pool,
            &actor.name,
            "msf_exec",
            None,
            serde_json::json!({ "command": request.command }),
        )
        .await;
        Ok(Response::new(MsfExecResult { ok: true, output }))
    }

    // ------------------------------------------------------------ extensions

    type ListExtensionsStream = Pin<Box<dyn Stream<Item = Result<ExtensionInfo, Status>> + Send>>;

    async fn list_extensions(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<Self::ListExtensionsStream>, Status> {
        require_role(&request, OperatorRole::Watcher)?;
        let rows = shikra_store::repo_extensions::list_extensions(
            &self.state.pool,
            self.state.engagement_id,
        )
        .await
        .map_err(internal)?;
        let infos: Vec<ExtensionInfo> = rows.into_iter().map(extension_info).collect();
        Ok(Response::new(Box::pin(tokio_stream::iter(
            infos.into_iter().map(Ok),
        ))))
    }

    async fn install_extension(
        &self,
        request: Request<InstallExtensionRequest>,
    ) -> Result<Response<ExtensionInfo>, Status> {
        let actor = require_role(&request, OperatorRole::Operator)?;
        let request = request.into_inner();
        if request.package.is_empty() {
            return Err(Status::invalid_argument("extension package is required"));
        }
        let package = shikra_transport::extension::ExtensionPackage::from_json(&request.package)
            .map_err(|err| Status::invalid_argument(format!("invalid extension package: {err}")))?;
        let payload = package
            .verify(&self.state.armory_public)
            .map_err(|err| Status::permission_denied(format!("extension rejected: {err}")))?;

        let manifest = &package.manifest;
        let row = shikra_store::models::ExtensionRow {
            id: Uuid::new_v4(),
            engagement_id: Some(self.state.engagement_id),
            name: manifest.name.clone(),
            version: manifest.version.clone(),
            kind: manifest.kind.as_str().to_string(),
            platform: manifest.platform.as_str().to_string(),
            architecture: manifest.architecture.clone(),
            description: manifest.description.clone(),
            sha256: manifest.sha256.clone(),
            size: manifest.size as i64,
            signer: package.signer.clone(),
            manifest: serde_json::to_value(manifest)
                .map_err(|_| Status::internal("failed to encode manifest"))?,
            payload: Some(payload),
            installed_by: actor.name.clone(),
            created_at: time::OffsetDateTime::now_utc(),
        };
        let row = shikra_store::repo_extensions::insert_extension(&self.state.pool, &row)
            .await
            .map_err(internal)?;

        let _ = shikra_store::repo::insert_event(
            &self.state.pool,
            "extension_installed",
            None,
            serde_json::json!({
                "name": row.name,
                "version": row.version,
                "kind": row.kind,
                "platform": row.platform,
                "operator": actor.name,
            }),
        )
        .await;
        let _ = shikra_store::repo_team::audit(
            &self.state.pool,
            &actor.name,
            "extension_install",
            Some(&row.id.to_string()),
            serde_json::json!({ "name": row.name, "version": row.version }),
        )
        .await;

        Ok(Response::new(extension_info(row)))
    }

    async fn fetch_extension(
        &self,
        request: Request<FetchExtensionRequest>,
    ) -> Result<Response<FetchExtensionResponse>, Status> {
        require_role(&request, OperatorRole::Watcher)?;
        let request = request.into_inner();
        let row = if request.by_name {
            if request.id.trim().is_empty() {
                return Err(Status::invalid_argument("extension name is required"));
            }
            let platform = (!request.platform.is_empty()).then_some(request.platform.as_str());
            shikra_store::repo_extensions::find_extension_by_name(
                &self.state.pool,
                self.state.engagement_id,
                request.id.trim(),
                platform,
            )
            .await
            .map_err(internal)?
        } else {
            let id = Uuid::parse_str(request.id.trim())
                .map_err(|_| Status::invalid_argument("invalid extension id"))?;
            shikra_store::repo_extensions::get_extension(
                &self.state.pool,
                self.state.engagement_id,
                id,
            )
            .await
            .map_err(internal)?
        };
        let row = row.ok_or_else(|| Status::not_found("extension not found"))?;
        let payload = row.payload.clone().unwrap_or_default();
        Ok(Response::new(FetchExtensionResponse {
            info: Some(extension_info(row)),
            payload,
        }))
    }

    async fn delete_extension(
        &self,
        request: Request<ExtensionId>,
    ) -> Result<Response<Empty>, Status> {
        let actor = require_role(&request, OperatorRole::Operator)?;
        let request = request.into_inner();
        let id = Uuid::parse_str(request.id.trim())
            .map_err(|_| Status::invalid_argument("invalid extension id"))?;
        let deleted = shikra_store::repo_extensions::delete_extension(
            &self.state.pool,
            self.state.engagement_id,
            id,
        )
        .await
        .map_err(internal)?;
        if !deleted {
            return Err(Status::not_found("extension not found"));
        }
        let _ = shikra_store::repo_team::audit(
            &self.state.pool,
            &actor.name,
            "extension_delete",
            Some(&request.id),
            serde_json::json!({}),
        )
        .await;
        Ok(Response::new(Empty {}))
    }

    async fn get_armory_key(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<ArmoryKeyInfo>, Status> {
        require_role(&request, OperatorRole::Watcher)?;
        Ok(Response::new(ArmoryKeyInfo {
            public_key_hex: shikra_transport::tls::hex_encode(&self.state.armory_public),
        }))
    }

    async fn get_profiles(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<ProfileSetInfo>, Status> {
        require_role(&request, OperatorRole::Watcher)?;
        let profiles = self.state.profiles.read().await;
        Ok(Response::new(ProfileSetInfo {
            profiles: profiles.iter().map(profile_info).collect(),
        }))
    }

    async fn list_chat(
        &self,
        request: Request<ChatQuery>,
    ) -> Result<Response<ChatMessages>, Status> {
        require_role(&request, OperatorRole::Watcher)?;
        let limit = request.into_inner().limit.clamp(1, 500);
        let rows = shikra_store::repo_team_ui::recent_chat_messages(&self.state.pool, limit)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        let mut messages: Vec<ChatMessageInfo> = rows
            .into_iter()
            .map(|row| ChatMessageInfo {
                operator: row.operator,
                message: row.message,
                created_at: Some(wire::to_timestamp(row.created_at)),
            })
            .collect();
        messages.reverse();
        Ok(Response::new(ChatMessages { messages }))
    }

    async fn send_chat(
        &self,
        request: Request<ChatMessageRequest>,
    ) -> Result<Response<Empty>, Status> {
        let actor = require_role(&request, OperatorRole::Watcher)?;
        let text = request.into_inner().message.trim().to_string();
        if text.is_empty() || text.chars().count() > 4000 {
            return Err(Status::invalid_argument(
                "message must be 1-4000 characters",
            ));
        }
        shikra_store::repo_team_ui::insert_chat_message(&self.state.pool, &actor.name, &text)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    async fn list_events(
        &self,
        request: Request<EventQuery>,
    ) -> Result<Response<EventList>, Status> {
        require_role(&request, OperatorRole::Watcher)?;
        let limit = request.into_inner().limit.clamp(1, 500);
        let rows = shikra_store::repo::recent_events(&self.state.pool, limit)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        let events = rows
            .into_iter()
            .map(|row| EventInfo {
                id: row.id.to_string(),
                kind: row.kind,
                subject: row
                    .subject
                    .map(|subject| subject.to_string())
                    .unwrap_or_default(),
                payload_json: row.payload.to_string(),
                occurred_at: Some(wire::to_timestamp(row.occurred_at)),
            })
            .collect();
        Ok(Response::new(EventList { events }))
    }

    async fn set_session_ui(
        &self,
        request: Request<SessionUiRequest>,
    ) -> Result<Response<Empty>, Status> {
        let actor = require_role(&request, OperatorRole::Operator)?;
        let request = request.into_inner();
        Uuid::parse_str(&request.session_id)
            .map_err(|_| Status::invalid_argument("invalid session id"))?;
        let color = match request.color.trim() {
            "" => None,
            value => {
                let valid = value.len() == 7
                    && value.starts_with('#')
                    && value[1..].chars().all(|ch| ch.is_ascii_hexdigit());
                if !valid {
                    return Err(Status::invalid_argument("color must look like #rrggbb"));
                }
                Some(value.to_string())
            }
        };
        let status = match request.operator_status.trim() {
            "" => None,
            "dead" | "alive" => Some(request.operator_status.trim().to_string()),
            _ => {
                return Err(Status::invalid_argument(
                    "operator_status must be dead or alive",
                ))
            }
        };
        if color.is_none() && status.is_none() {
            return Err(Status::invalid_argument("nothing to update"));
        }
        let handle = self
            .state
            .sessions
            .get(&request.session_id)
            .await
            .ok_or_else(|| Status::not_found("unknown or disconnected session"))?;
        {
            let mut info = handle.info.lock().await;
            if let Some(color) = &color {
                info.color = color.clone();
            }
            if let Some(status) = &status {
                info.operator_status = status.clone();
            }
        }
        if let Ok(id) = Uuid::parse_str(&request.session_id) {
            let _ = shikra_store::repo_team_ui::set_session_ui(
                &self.state.pool,
                id,
                color.as_deref(),
                status.as_deref(),
            )
            .await;
        }
        shikra_store::repo_team::audit(
            &self.state.pool,
            "operator",
            "session_ui_updated",
            Some(&actor.name),
            serde_json::json!({
                "session_id": request.session_id,
                "color": color,
                "operator_status": status,
            }),
        )
        .await;
        Ok(Response::new(Empty {}))
    }

    async fn get_webhook(&self, request: Request<Empty>) -> Result<Response<WebhookInfo>, Status> {
        require_role(&request, OperatorRole::Watcher)?;
        let url = self.state.webhook.read().await.clone().unwrap_or_default();
        Ok(Response::new(WebhookInfo { discord_url: url }))
    }

    async fn set_webhook(&self, request: Request<WebhookInfo>) -> Result<Response<Empty>, Status> {
        let actor = require_role(&request, OperatorRole::Admin)?;
        let url = request.into_inner().discord_url.trim().to_string();
        crate::webhook::validate_discord_url(&url).map_err(Status::invalid_argument)?;
        let url = if url.is_empty() { None } else { Some(url) };
        crate::webhook::persist(&self.state.state_dir, url.as_deref())
            .map_err(|err| Status::internal(format!("failed to persist webhook: {err}")))?;
        *self.state.webhook.write().await = url.clone();
        shikra_store::repo_team::audit(
            &self.state.pool,
            "operator",
            "webhook_updated",
            Some(&actor.name),
            serde_json::json!({ "enabled": url.is_some() }),
        )
        .await;
        Ok(Response::new(Empty {}))
    }

    async fn list_listeners(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<ListenerSet>, Status> {
        require_role(&request, OperatorRole::Watcher)?;
        let listeners = self
            .state
            .listeners
            .list()
            .await
            .into_iter()
            .map(|listener| ListenerInfo {
                id: listener.id,
                kind: listener.kind,
                addr: listener.addr,
                running: listener.running,
                detail: listener.detail,
            })
            .collect();
        Ok(Response::new(ListenerSet { listeners }))
    }

    async fn start_listener(
        &self,
        request: Request<StartListenerRequest>,
    ) -> Result<Response<ListenerInfo>, Status> {
        let actor = require_role(&request, OperatorRole::Operator)?;
        let request = request.into_inner();
        let kind = request.kind.trim().to_ascii_lowercase();
        if !crate::listeners::KINDS.contains(&kind.as_str()) {
            return Err(Status::invalid_argument(format!(
                "unsupported listener kind {:?} (expected one of {:?})",
                request.kind,
                crate::listeners::KINDS
            )));
        }
        let addr: std::net::SocketAddr = request.addr.trim().parse().map_err(|_| {
            Status::invalid_argument(format!("invalid listen address {:?}", request.addr))
        })?;
        let (id, local, detail) =
            crate::listeners::start(&self.state, &kind, addr, request.dns_zone.trim())
                .await
                .map_err(|err| Status::failed_precondition(err.to_string()))?;
        shikra_store::repo_team::audit(
            &self.state.pool,
            "operator",
            "listener_started",
            Some(&actor.name),
            serde_json::json!({ "kind": kind, "addr": local.to_string() }),
        )
        .await;
        Ok(Response::new(ListenerInfo {
            id,
            kind,
            addr: local.to_string(),
            running: true,
            detail,
        }))
    }

    async fn stop_listener(&self, request: Request<ListenerId>) -> Result<Response<Empty>, Status> {
        let actor = require_role(&request, OperatorRole::Operator)?;
        let id = request.into_inner().id;
        if !self.state.listeners.stop(&id).await {
            return Err(Status::not_found("unknown listener"));
        }
        shikra_store::repo_team::audit(
            &self.state.pool,
            "operator",
            "listener_stopped",
            Some(&actor.name),
            serde_json::json!({ "listener": id }),
        )
        .await;
        Ok(Response::new(Empty {}))
    }

    async fn set_profiles(
        &self,
        request: Request<ProfileSetInfo>,
    ) -> Result<Response<Empty>, Status> {
        let actor = require_role(&request, OperatorRole::Admin)?;
        let incoming = request.into_inner();
        if incoming.profiles.is_empty() {
            return Err(Status::invalid_argument(
                "at least one C2 profile is required",
            ));
        }
        let mut profiles = Vec::with_capacity(incoming.profiles.len());
        let mut names = std::collections::HashSet::new();
        let mut enroll_uris = std::collections::HashSet::new();
        let mut poll_uris = std::collections::HashSet::new();
        for raw in incoming.profiles {
            let profile = validate_profile(raw)?;
            if !names.insert(profile.name.clone()) {
                return Err(Status::invalid_argument(format!(
                    "duplicate profile name {:?}",
                    profile.name
                )));
            }
            if !enroll_uris.insert(profile.enroll_uri.clone())
                || !poll_uris.insert(profile.poll_uri.clone())
            {
                return Err(Status::invalid_argument(
                    "enroll and poll URIs must be unique per profile",
                ));
            }
            profiles.push(profile);
        }
        let set = shikra_transport::profile::ProfileSet { profiles };
        let raw = serde_json::to_string_pretty(&set)
            .map_err(|err| Status::internal(format!("failed to encode profiles: {err}")))?;
        let path = self.state.state_dir.join("profiles.json");
        let temp = self.state.state_dir.join("profiles.json.tmp");
        tokio::fs::write(&temp, raw)
            .await
            .map_err(|err| Status::internal(format!("failed to write profiles: {err}")))?;
        tokio::fs::rename(&temp, &path)
            .await
            .map_err(|err| Status::internal(format!("failed to persist profiles: {err}")))?;
        let count = set.len();
        *self.state.profiles.write().await = set;
        shikra_store::repo_team::audit(
            &self.state.pool,
            "operator",
            "profiles_updated",
            Some(&actor.name),
            serde_json::json!({ "profiles": count }),
        )
        .await;
        Ok(Response::new(Empty {}))
    }
}

fn profile_info(profile: &shikra_transport::profile::C2Profile) -> ProfileInfo {
    ProfileInfo {
        name: profile.name.clone(),
        user_agent: profile.user_agent.clone(),
        enroll_uri: profile.enroll_uri.clone(),
        poll_uri: profile.poll_uri.clone(),
        request_headers: profile.request_headers.clone().into_iter().collect(),
        response_headers: profile.response_headers.clone().into_iter().collect(),
        poll_interval_secs: profile.poll_interval_secs,
        jitter_secs: profile.jitter_secs,
    }
}

fn validate_profile(raw: ProfileInfo) -> Result<shikra_transport::profile::C2Profile, Status> {
    let name = raw.name.trim().to_string();
    if name.is_empty() || name.len() > 64 {
        return Err(Status::invalid_argument("profile name must be 1-64 chars"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(Status::invalid_argument(format!(
            "profile name {name:?} may only contain letters, digits, '-', '_' and '.'"
        )));
    }
    if raw.user_agent.is_empty() || raw.user_agent.len() > 512 {
        return Err(Status::invalid_argument("user agent must be 1-512 chars"));
    }
    if raw.user_agent.contains(['\r', '\n']) {
        return Err(Status::invalid_argument(
            "user agent must not contain newlines",
        ));
    }
    for (label, uri) in [("enroll_uri", &raw.enroll_uri), ("poll_uri", &raw.poll_uri)] {
        if !uri.starts_with('/') || uri.len() > 128 || uri.contains(char::is_whitespace) {
            return Err(Status::invalid_argument(format!(
                "{label} must start with '/' and contain no whitespace"
            )));
        }
        if uri.starts_with("/cdn/") || uri.starts_with("/canary/") {
            return Err(Status::invalid_argument(format!(
                "{label} conflicts with a reserved server route"
            )));
        }
    }
    if raw.enroll_uri == raw.poll_uri {
        return Err(Status::invalid_argument(
            "enroll_uri and poll_uri must differ within a profile",
        ));
    }
    if raw.poll_interval_secs == 0 || raw.poll_interval_secs > 86_400 {
        return Err(Status::invalid_argument(
            "poll_interval_secs must be 1-86400",
        ));
    }
    if raw.jitter_secs > 86_400 {
        return Err(Status::invalid_argument(
            "jitter_secs must be at most 86400",
        ));
    }
    let request_headers = validate_headers("request header", raw.request_headers)?;
    let response_headers = validate_headers("response header", raw.response_headers)?;
    Ok(shikra_transport::profile::C2Profile {
        name,
        user_agent: raw.user_agent,
        enroll_uri: raw.enroll_uri,
        poll_uri: raw.poll_uri,
        request_headers,
        response_headers,
        poll_interval_secs: raw.poll_interval_secs,
        jitter_secs: raw.jitter_secs,
    })
}

fn validate_headers(
    label: &str,
    headers: std::collections::HashMap<String, String>,
) -> Result<std::collections::BTreeMap<String, String>, Status> {
    let mut out = std::collections::BTreeMap::new();
    for (name, value) in headers {
        if axum::http::HeaderName::try_from(name.as_str()).is_err() {
            return Err(Status::invalid_argument(format!(
                "invalid {label} name {name:?}"
            )));
        }
        if axum::http::HeaderValue::try_from(value.as_str()).is_err() {
            return Err(Status::invalid_argument(format!(
                "invalid {label} value for {name:?}"
            )));
        }
        out.insert(name, value);
    }
    Ok(out)
}

fn extension_info(row: shikra_store::models::ExtensionRow) -> ExtensionInfo {
    ExtensionInfo {
        id: row.id.to_string(),
        name: row.name,
        version: row.version,
        kind: row.kind,
        platform: row.platform,
        architecture: row.architecture,
        description: row.description,
        sha256: row.sha256,
        size: row.size as u64,
        signer: row.signer,
        installed_by: row.installed_by,
        created_at: Some(wire::to_timestamp(row.created_at)),
    }
}

fn internal(err: impl std::fmt::Display) -> Status {
    Status::internal(err.to_string())
}

fn credential_info(row: shikra_store::models::CredentialRow) -> CredentialInfo {
    CredentialInfo {
        id: row.id.to_string(),
        host: row.host,
        domain: row.domain,
        username: row.username,
        secret: row.secret,
        kind: row.kind,
        source: row.source,
        created_at: Some(wire::to_timestamp(row.created_at)),
    }
}

fn loot_info(row: shikra_store::models::LootRow) -> LootInfo {
    LootInfo {
        id: row.id.to_string(),
        kind: row.kind,
        name: row.name,
        size: row.size,
        sha256: row.sha256.unwrap_or_default(),
        data: row.data.unwrap_or_default(),
        created_at: Some(wire::to_timestamp(row.created_at)),
    }
}

fn canary_info(row: shikra_store::models::CanaryRow) -> CanaryInfo {
    CanaryInfo {
        id: row.id.to_string(),
        token: row.token,
        kind: row.kind,
        note: row.note,
        triggered: row.triggered,
        triggered_at: row.triggered_at.map(wire::to_timestamp),
        created_at: Some(wire::to_timestamp(row.created_at)),
    }
}

fn task_record(row: shikra_store::models::TaskRow) -> TaskRecord {
    let state = match row.state.as_str() {
        "completed" => TaskState::Completed as i32,
        "failed" => TaskState::Failed as i32,
        "cancelled" => TaskState::Cancelled as i32,
        "running" => TaskState::Running as i32,
        "dispatched" => TaskState::Dispatched as i32,
        _ => TaskState::Pending as i32,
    };
    TaskRecord {
        id: row.id.to_string(),
        session_id: row.session_id.to_string(),
        command: row.command,
        args: serde_json::to_string(&row.payload).unwrap_or_default(),
        state,
        exit_code: row.exit_code.unwrap_or_default(),
        output: row.output.unwrap_or_default(),
        ai_initiated: row.ai_initiated,
        created_at: Some(wire::to_timestamp(row.created_at)),
        completed_at: row.completed_at.map(wire::to_timestamp),
    }
}

impl ServerState {
    /// Evaluates enabled reaction rules for an event kind.
    pub async fn trigger_reactions(&self, event_kind: &str) {
        let rules = match shikra_store::repo_team::list_reaction_rules(&self.pool).await {
            Ok(rules) => rules,
            Err(err) => {
                tracing::warn!(%err, "failed to load reaction rules");
                return;
            }
        };
        for rule in rules
            .into_iter()
            .filter(|rule| rule.enabled && rule.event_kind == event_kind)
        {
            tracing::info!(event = event_kind, action = %rule.action, "reaction triggered");
            let _ = shikra_store::repo::insert_event(
                &self.pool,
                "reaction_triggered",
                None,
                serde_json::json!({
                    "event_kind": event_kind,
                    "action": rule.action,
                    "rule_id": rule.id.to_string(),
                }),
            )
            .await;
        }
    }
}

impl ServerState {
    pub async fn touch_session(&self, handle: &SessionHandle) {
        let now = time::OffsetDateTime::now_utc();
        let previous = {
            let info = handle.info.lock().await;
            info.last_seen
                .as_ref()
                .map(shikra_transport::wire::from_timestamp)
        };
        handle.note_checkin(previous, now).await;
        {
            let mut info = handle.info.lock().await;
            info.last_seen = Some(wire::to_timestamp(now));
            info.status = shikra_proto::v1::SessionStatus::Active as i32;
        }
        if let Ok(id) = Uuid::parse_str(&handle.id) {
            if let Err(err) = shikra_store::repo::touch_session(&self.pool, id).await {
                tracing::warn!(%err, session = %handle.id, "failed to touch session");
            }
        }
    }

    /// Marks a session stale, fails its pending tasks immediately and updates
    /// the persisted status. Stale sessions stay listed but are no longer
    /// treated as routable targets by the client.
    pub async fn mark_session_stale(&self, handle: &SessionHandle) {
        {
            let mut info = handle.info.lock().await;
            if info.status == shikra_proto::v1::SessionStatus::Stale as i32 {
                return;
            }
            info.status = shikra_proto::v1::SessionStatus::Stale as i32;
        }
        if let Ok(id) = Uuid::parse_str(&handle.id) {
            let _ = shikra_store::repo::set_session_status(&self.pool, id, "stale").await;
            let _ = shikra_store::repo::insert_event(
                &self.pool,
                "session_stale",
                Some(id),
                serde_json::json!({}),
            )
            .await;
        }
        // Dropping the senders makes waiting `submit_task` streams fail fast
        // instead of blocking until the beacon timeout.
        handle.pending.lock().await.clear();
        tracing::warn!(session = %handle.id, "session marked stale");
    }

    pub async fn retire_session(&self, handle: &SessionHandle) {
        self.sessions.remove(&handle.id).await;
        if let Ok(id) = Uuid::parse_str(&handle.id) {
            let _ = shikra_store::repo::set_session_status(&self.pool, id, "dead").await;
            let _ = shikra_store::repo::insert_event(
                &self.pool,
                "session_dead",
                Some(id),
                serde_json::json!({}),
            )
            .await;
        }
        let mut pending = handle.pending.lock().await;
        pending.clear();
    }

    pub async fn process_envelope(
        &self,
        handle: &Arc<SessionHandle>,
        envelope: &Envelope,
    ) -> Result<(), Status> {
        let message = {
            let mut keys = handle.keys.lock().await;
            wire::open_message(&mut keys, envelope)
                .map_err(|_| Status::unauthenticated("envelope rejected"))?
        };

        match message.body {
            Some(agent_message::Body::Heartbeat(_)) => {
                self.touch_session(handle).await;
            }
            Some(agent_message::Body::Result(result)) => {
                self.touch_session(handle).await;
                deliver_result(handle, result).await;
            }
            Some(agent_message::Body::Results(batch)) => {
                self.touch_session(handle).await;
                for result in batch.results {
                    deliver_result(handle, result).await;
                }
            }
            Some(agent_message::Body::Task(_)) | Some(agent_message::Body::Tasks(_)) => {
                return Err(Status::invalid_argument("agents must not send tasks"));
            }
            Some(agent_message::Body::TunnelOpen(_)) => {
                return Err(Status::invalid_argument("agents must not open tunnels"));
            }
            Some(agent_message::Body::TunnelAccept(accept)) => {
                self.touch_session(handle).await;
                self.handle_remote_accept(handle, accept).await;
            }
            Some(agent_message::Body::TunnelData(_))
            | Some(agent_message::Body::TunnelClose(_)) => {
                self.touch_session(handle).await;
                if !self.tunnels.deliver_from_agent(&handle.id, &message).await {
                    // No operator route: answer with a close so the agent frees the socket.
                    if let Some(agent_message::Body::TunnelData(data)) = &message.body {
                        let close = shikra_proto::v1::AgentMessage {
                            body: Some(agent_message::Body::TunnelClose(
                                shikra_proto::v1::TunnelClose {
                                    tunnel_id: data.tunnel_id.clone(),
                                    reason: "no route".into(),
                                },
                            )),
                        };
                        let _ = handle.send_message(close).await;
                    }
                }
            }
            None => {}
        }
        Ok(())
    }

    /// Handles a remote port-forward accept: dial the configured destination
    /// and bridge bytes between the destination socket and the agent tunnel.
    async fn handle_remote_accept(
        &self,
        handle: &Arc<SessionHandle>,
        accept: shikra_proto::v1::TunnelAccept,
    ) {
        let rule = match self.forwards.find_by_bind(&handle.id, &accept.bind).await {
            Some(rule) => {
                rule.record_connection();
                rule
            }
            None => {
                let close = shikra_proto::v1::AgentMessage {
                    body: Some(agent_message::Body::TunnelClose(
                        shikra_proto::v1::TunnelClose {
                            tunnel_id: accept.tunnel_id.clone(),
                            reason: "no forward rule".into(),
                        },
                    )),
                };
                let _ = handle.send_message(close).await;
                return;
            }
        };

        let stream = match tokio::net::TcpStream::connect(&rule.to).await {
            Ok(stream) => stream,
            Err(err) => {
                tracing::warn!(%err, to = %rule.to, "rportfwd destination dial failed");
                let close = shikra_proto::v1::AgentMessage {
                    body: Some(agent_message::Body::TunnelClose(
                        shikra_proto::v1::TunnelClose {
                            tunnel_id: accept.tunnel_id.clone(),
                            reason: format!("destination dial failed: {err}"),
                        },
                    )),
                };
                let _ = handle.send_message(close).await;
                return;
            }
        };

        let session_id = handle.id.clone();
        let tunnel_id = accept.tunnel_id.clone();
        let hub = self.tunnels.clone();
        let (out_tx, mut out_rx) = mpsc::channel::<OperatorTunnelFrame>(256);
        hub.register(&session_id, &tunnel_id, out_tx).await;

        let sender_handle = handle.clone();
        let sender_session = session_id.clone();
        let sender_tunnel = tunnel_id.clone();
        tokio::spawn(async move {
            let (mut read_half, mut write_half) = stream.into_split();
            let mut buffer = vec![0u8; 32 * 1024];
            loop {
                tokio::select! {
                    read = tokio::io::AsyncReadExt::read(&mut read_half, &mut buffer) => {
                        match read {
                            Ok(0) => break,
                            Ok(n) => {
                                let message = shikra_proto::v1::AgentMessage {
                                    body: Some(agent_message::Body::TunnelData(
                                        shikra_proto::v1::TunnelData {
                                            tunnel_id: sender_tunnel.clone(),
                                            data: buffer[..n].to_vec(),
                                        },
                                    )),
                                };
                                if sender_handle.send_message(message).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    frame = out_rx.recv() => {
                        match frame {
                            Some(frame) => {
                                let is_close = matches!(frame.body, Some(operator_tunnel_frame::Body::Close(_)));
                                if let Some(operator_tunnel_frame::Body::Data(data)) = frame.body {
                                    if tokio::io::AsyncWriteExt::write_all(&mut write_half, &data.data).await.is_err() {
                                        break;
                                    }
                                }
                                if is_close {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
            hub.unregister(&sender_session, &sender_tunnel).await;
            let close = shikra_proto::v1::AgentMessage {
                body: Some(agent_message::Body::TunnelClose(
                    shikra_proto::v1::TunnelClose {
                        tunnel_id: sender_tunnel.clone(),
                        reason: "destination closed".into(),
                    },
                )),
            };
            let _ = sender_handle.send_message(close).await;
        });
    }
}

async fn deliver_result(handle: &SessionHandle, result: AgentResult) {
    let waiter = handle.pending.lock().await.remove(&result.task_id);
    if let Some(waiter) = waiter {
        let _ = waiter.send(result);
    } else {
        tracing::warn!(session = %handle.id, task = %result.task_id, "result for unknown task");
    }
}

/// Outputs over 64 KiB or non-UTF-8 payloads are summarized instead of stored.
fn persistable_output(command: &str, output: &[u8]) -> Option<String> {
    const MAX_STORED: usize = 64 * 1024;
    match std::str::from_utf8(output) {
        Ok(text) if text.len() <= MAX_STORED => Some(text.to_string()),
        Ok(_) => Some(format!(
            "[{command}: output truncated, {} bytes]",
            output.len()
        )),
        Err(_) => Some(format!(
            "[{command}: binary output, {} bytes]",
            output.len()
        )),
    }
}
