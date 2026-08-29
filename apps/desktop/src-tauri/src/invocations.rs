use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use serde::Serialize;
use ssdev_invocation_ledger::{
    BeginDecision, DurableStatus, InvocationLedger, LedgerError, OperationIdentity, OperationLookup,
};
use thiserror::Error;
use tokio::sync::{oneshot, Mutex, Notify};
use tokio::time::{Duration, Instant};
use tracing::warn;
use webplus_controller::PluginController;
use webplus_protocol::{InvokeRequest, InvokeResponse};

pub(crate) const MAX_RUNTIME_OPERATIONS: usize = 64;
pub(crate) const MAX_RETAINED_RESPONSE_BYTES: usize = 512 * 1024;
pub(crate) const RUNTIME_RESULT_RETENTION: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "camelCase")]
pub(crate) enum TrackedInvocationStatus {
    Unknown,
    Pending,
    Completed {
        response: InvokeResponse,
        durable: bool,
    },
    Indeterminate,
    CompletedWithoutResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvocationCoordinatorStats {
    pub accepting: bool,
    pub runtime_operations: usize,
    pub pending_operations: usize,
    pub retained_results: usize,
    pub durable_operations: usize,
    pub persistence_failures: u64,
}

pub(crate) struct InvocationCoordinator {
    ledger: Arc<InvocationLedger>,
    runtime: Mutex<HashMap<String, Arc<RuntimeOperation>>>,
    begin_gate: Mutex<()>,
    accepting: AtomicBool,
    active_workflows: AtomicUsize,
    workflow_notify: Notify,
    persistence_failures: AtomicU64,
}

struct ActiveWorkflowGuard {
    coordinator: Arc<InvocationCoordinator>,
}

impl Drop for ActiveWorkflowGuard {
    fn drop(&mut self) {
        self.coordinator
            .active_workflows
            .fetch_sub(1, Ordering::AcqRel);
        self.coordinator.workflow_notify.notify_waiters();
    }
}

struct RuntimeOperation {
    identity: OperationIdentity,
    state: Mutex<RuntimeState>,
}

enum RuntimeState {
    Pending {
        waiters: Vec<oneshot::Sender<Result<TrackedInvocationStatus, &'static str>>>,
    },
    Completed {
        response: Option<Arc<InvokeResponse>>,
        durable: bool,
        completed_at: Instant,
    },
    Terminal {
        status: TrackedInvocationStatus,
        completed_at: Instant,
    },
    Failed {
        error_code: &'static str,
        completed_at: Instant,
    },
}

enum RuntimeAttachment {
    Missing,
    Wait(oneshot::Receiver<Result<TrackedInvocationStatus, &'static str>>),
    Immediate(TrackedInvocationStatus),
    Failed(&'static str),
}

impl InvocationCoordinator {
    pub(crate) fn open(directory: PathBuf) -> Result<Self, CoordinatorError> {
        Ok(Self {
            ledger: Arc::new(InvocationLedger::open(directory, SystemTime::now())?),
            runtime: Mutex::new(HashMap::new()),
            begin_gate: Mutex::new(()),
            accepting: AtomicBool::new(true),
            active_workflows: AtomicUsize::new(0),
            workflow_notify: Notify::new(),
            persistence_failures: AtomicU64::new(0),
        })
    }

    pub(crate) async fn invoke(
        self: &Arc<Self>,
        origin: &str,
        operation_id: &str,
        request: InvokeRequest,
        controller: Arc<PluginController>,
    ) -> Result<TrackedInvocationStatus, CoordinatorError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(CoordinatorError::Stopping);
        }
        request
            .validate()
            .map_err(|error| CoordinatorError::InvalidRequest(error.to_string()))?;
        let identity = OperationIdentity::for_request(operation_id, origin, &request)?;
        let runtime_key = identity.runtime_key();
        match self.attach_runtime(&runtime_key, &identity).await? {
            RuntimeAttachment::Wait(receiver) => return await_result(receiver).await,
            RuntimeAttachment::Immediate(status) => return Ok(status),
            RuntimeAttachment::Failed(code) => {
                return Err(CoordinatorError::RuntimeWorkflowFailed(code));
            }
            RuntimeAttachment::Missing => {}
        }

        let receiver = {
            let _begin = self.begin_gate.lock().await;
            if !self.accepting.load(Ordering::Acquire) {
                return Err(CoordinatorError::Stopping);
            }
            match self.attach_runtime(&runtime_key, &identity).await? {
                RuntimeAttachment::Wait(receiver) => {
                    drop(_begin);
                    return await_result(receiver).await;
                }
                RuntimeAttachment::Immediate(status) => {
                    drop(_begin);
                    return Ok(status);
                }
                RuntimeAttachment::Failed(code) => {
                    drop(_begin);
                    return Err(CoordinatorError::RuntimeWorkflowFailed(code));
                }
                RuntimeAttachment::Missing => {}
            }
            self.prepare_runtime_capacity().await?;
            let (sender, receiver) = oneshot::channel();
            let operation = Arc::new(RuntimeOperation {
                identity: identity.clone(),
                state: Mutex::new(RuntimeState::Pending {
                    waiters: vec![sender],
                }),
            });
            self.runtime
                .lock()
                .await
                .insert(runtime_key.clone(), operation);
            self.active_workflows.fetch_add(1, Ordering::AcqRel);
            receiver
        };

        let workflow_runtime_key = runtime_key.clone();
        let workflow_identity = identity.clone();
        let coordinator = Arc::clone(self);
        let workflow = tokio::spawn(async move {
            coordinator
                .run_workflow(workflow_runtime_key, workflow_identity, request, controller)
                .await;
        });
        self.supervise_workflow(runtime_key, identity, workflow);
        await_result(receiver).await
    }

    pub(crate) async fn stop_accepting(&self) {
        self.accepting.store(false, Ordering::Release);
        // Synchronize with the final acceptance check and active-workflow increment.
        let gate = self.begin_gate.lock().await;
        drop(gate);
    }

    pub(crate) async fn drain(&self) {
        loop {
            let notified = self.workflow_notify.notified();
            if self.active_workflows.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn resume_after_shutdown(&self) {
        self.accepting.store(true, Ordering::Release);
    }

    pub(crate) fn is_accepting(&self) -> bool {
        self.accepting.load(Ordering::Acquire)
    }

    pub(crate) async fn status(
        &self,
        origin: &str,
        operation_id: &str,
        service_id: &str,
        method: &str,
    ) -> Result<TrackedInvocationStatus, CoordinatorError> {
        let lookup = OperationLookup::for_route(operation_id, origin, service_id, method)?;
        let runtime_key = lookup.runtime_key();
        if let Some(operation) = self.runtime.lock().await.get(&runtime_key).cloned() {
            if operation.identity.lookup() != lookup {
                return Err(CoordinatorError::OperationConflict);
            }
            let state = operation.state.lock().await;
            return Ok(match &*state {
                RuntimeState::Pending { .. } => TrackedInvocationStatus::Pending,
                RuntimeState::Completed {
                    response: Some(response),
                    durable,
                    ..
                } => TrackedInvocationStatus::Completed {
                    response: response.as_ref().clone(),
                    durable: *durable,
                },
                RuntimeState::Completed { response: None, .. } => {
                    TrackedInvocationStatus::CompletedWithoutResult
                }
                RuntimeState::Terminal { status, .. } => status.clone(),
                RuntimeState::Failed { error_code, .. } => {
                    return Err(CoordinatorError::RuntimeWorkflowFailed(error_code));
                }
            });
        }
        Ok(
            match status_durable(Arc::clone(&self.ledger), lookup).await? {
                DurableStatus::Unknown => TrackedInvocationStatus::Unknown,
                DurableStatus::Indeterminate => TrackedInvocationStatus::Indeterminate,
                DurableStatus::CompletedWithoutResult => {
                    TrackedInvocationStatus::CompletedWithoutResult
                }
            },
        )
    }

    pub(crate) async fn stats(&self) -> InvocationCoordinatorStats {
        let mut runtime = self.runtime.lock().await;
        cleanup_runtime(&mut runtime).await;
        let runtime_operations = runtime.len();
        let operations = runtime.values().cloned().collect::<Vec<_>>();
        drop(runtime);
        let mut pending_operations = 0;
        let mut retained_results = 0;
        for operation in operations {
            match &*operation.state.lock().await {
                RuntimeState::Pending { .. } => pending_operations += 1,
                RuntimeState::Completed {
                    response: Some(_), ..
                } => retained_results += 1,
                RuntimeState::Completed { response: None, .. } => {}
                RuntimeState::Terminal { .. } | RuntimeState::Failed { .. } => {}
            }
        }
        InvocationCoordinatorStats {
            accepting: self.is_accepting(),
            runtime_operations,
            pending_operations,
            retained_results,
            durable_operations: self.ledger.operation_count(),
            persistence_failures: self.persistence_failures.load(Ordering::Relaxed),
        }
    }

    async fn attach_runtime(
        &self,
        runtime_key: &str,
        identity: &OperationIdentity,
    ) -> Result<RuntimeAttachment, CoordinatorError> {
        let operation = self.runtime.lock().await.get(runtime_key).cloned();
        let Some(operation) = operation else {
            return Ok(RuntimeAttachment::Missing);
        };
        if operation.identity != *identity {
            return Err(CoordinatorError::OperationConflict);
        }
        let mut state = operation.state.lock().await;
        Ok(match &mut *state {
            RuntimeState::Pending { waiters } => {
                let (sender, receiver) = oneshot::channel();
                waiters.push(sender);
                RuntimeAttachment::Wait(receiver)
            }
            RuntimeState::Completed {
                response: Some(response),
                durable,
                ..
            } => RuntimeAttachment::Immediate(TrackedInvocationStatus::Completed {
                response: response.as_ref().clone(),
                durable: *durable,
            }),
            RuntimeState::Completed { response: None, .. } => {
                RuntimeAttachment::Immediate(TrackedInvocationStatus::CompletedWithoutResult)
            }
            RuntimeState::Terminal { status, .. } => RuntimeAttachment::Immediate(status.clone()),
            RuntimeState::Failed { error_code, .. } => RuntimeAttachment::Failed(error_code),
        })
    }

    async fn prepare_runtime_capacity(&self) -> Result<(), CoordinatorError> {
        let mut runtime = self.runtime.lock().await;
        cleanup_runtime(&mut runtime).await;
        while runtime.len() >= MAX_RUNTIME_OPERATIONS {
            let operations = runtime
                .iter()
                .map(|(key, operation)| (key.clone(), Arc::clone(operation)))
                .collect::<Vec<_>>();
            let mut oldest_completed = None;
            for (key, operation) in operations {
                let completed_at = match &*operation.state.lock().await {
                    RuntimeState::Pending { .. } => None,
                    RuntimeState::Completed { completed_at, .. }
                    | RuntimeState::Terminal { completed_at, .. }
                    | RuntimeState::Failed { completed_at, .. } => Some(*completed_at),
                };
                if let Some(completed_at) = completed_at {
                    if oldest_completed
                        .as_ref()
                        .is_none_or(|(_, oldest)| &completed_at < oldest)
                    {
                        oldest_completed = Some((key, completed_at));
                    }
                }
            }
            let Some((key, _)) = oldest_completed else {
                return Err(CoordinatorError::RuntimeCapacity(MAX_RUNTIME_OPERATIONS));
            };
            runtime.remove(&key);
        }
        Ok(())
    }

    async fn finish(
        &self,
        runtime_key: String,
        identity: OperationIdentity,
        response: Arc<InvokeResponse>,
    ) {
        let durable = match complete_durable(Arc::clone(&self.ledger), identity).await {
            Ok(()) => true,
            Err(error) => {
                self.persistence_failures.fetch_add(1, Ordering::Relaxed);
                warn!(
                    event_code = "tracked-invocation-completion-persist-failed",
                    error_code = error.diagnostic_code(),
                    "tracked invocation completed but its durable completion marker failed"
                );
                false
            }
        };
        let Some(operation) = self.runtime.lock().await.get(&runtime_key).cloned() else {
            return;
        };
        let retained = serde_json::to_vec(response.as_ref())
            .is_ok_and(|bytes| bytes.len() <= MAX_RETAINED_RESPONSE_BYTES);
        let status = TrackedInvocationStatus::Completed {
            response: response.as_ref().clone(),
            durable,
        };
        let waiters = {
            let mut state = operation.state.lock().await;
            let RuntimeState::Pending { waiters } = &mut *state else {
                return;
            };
            let waiters = std::mem::take(waiters);
            *state = RuntimeState::Completed {
                response: retained.then_some(response),
                durable,
                completed_at: Instant::now(),
            };
            waiters
        };
        for waiter in waiters {
            let _ = waiter.send(Ok(status.clone()));
        }
    }

    async fn run_workflow(
        self: Arc<Self>,
        runtime_key: String,
        identity: OperationIdentity,
        request: InvokeRequest,
        controller: Arc<PluginController>,
    ) {
        match begin_durable(Arc::clone(&self.ledger), identity.clone()).await {
            Ok(BeginDecision::Started) => {
                let response = Arc::new(controller.invoke(request).await);
                self.finish(runtime_key, identity, response).await;
            }
            Ok(BeginDecision::Indeterminate) => {
                self.publish_terminal(runtime_key, TrackedInvocationStatus::Indeterminate)
                    .await;
            }
            Ok(BeginDecision::CompletedWithoutResult) => {
                self.publish_terminal(runtime_key, TrackedInvocationStatus::CompletedWithoutResult)
                    .await;
            }
            Err(error) => {
                self.publish_failure(runtime_key, error.diagnostic_code())
                    .await;
            }
        }
    }

    fn supervise_workflow(
        self: &Arc<Self>,
        runtime_key: String,
        identity: OperationIdentity,
        workflow: tokio::task::JoinHandle<()>,
    ) {
        let coordinator = Arc::clone(self);
        let active = ActiveWorkflowGuard {
            coordinator: Arc::clone(&coordinator),
        };
        tokio::spawn(async move {
            let _active = active;
            if workflow.await.is_err() {
                coordinator
                    .reconcile_terminated_workflow(runtime_key, identity)
                    .await;
            }
        });
    }

    async fn reconcile_terminated_workflow(
        &self,
        runtime_key: String,
        identity: OperationIdentity,
    ) {
        warn!(
            event_code = "tracked-invocation-workflow-terminated",
            error_code = "tracked-invocation-task-failed",
            "tracked invocation workflow terminated before publishing a result"
        );
        match status_durable(Arc::clone(&self.ledger), identity.lookup()).await {
            Ok(DurableStatus::Unknown) => {
                self.publish_retryable_failure(runtime_key, "tracked-invocation-task-failed")
                    .await;
            }
            Ok(DurableStatus::Indeterminate) => {
                self.publish_terminal(runtime_key, TrackedInvocationStatus::Indeterminate)
                    .await;
            }
            Ok(DurableStatus::CompletedWithoutResult) => {
                self.publish_terminal(runtime_key, TrackedInvocationStatus::CompletedWithoutResult)
                    .await;
            }
            Err(error) => {
                self.persistence_failures.fetch_add(1, Ordering::Relaxed);
                warn!(
                    event_code = "tracked-invocation-workflow-reconcile-failed",
                    error_code = error.diagnostic_code(),
                    "tracked invocation workflow state could not be reconciled"
                );
                self.publish_terminal(runtime_key, TrackedInvocationStatus::Indeterminate)
                    .await;
            }
        }
    }

    async fn publish_terminal(&self, runtime_key: String, status: TrackedInvocationStatus) {
        let Some(operation) = self.runtime.lock().await.get(&runtime_key).cloned() else {
            return;
        };
        let waiters = {
            let mut state = operation.state.lock().await;
            let RuntimeState::Pending { waiters } = &mut *state else {
                return;
            };
            let waiters = std::mem::take(waiters);
            *state = RuntimeState::Terminal {
                status: status.clone(),
                completed_at: Instant::now(),
            };
            waiters
        };
        for waiter in waiters {
            let _ = waiter.send(Ok(status.clone()));
        }
    }

    async fn publish_failure(&self, runtime_key: String, error_code: &'static str) {
        let Some(operation) = self.runtime.lock().await.get(&runtime_key).cloned() else {
            return;
        };
        let waiters = {
            let mut state = operation.state.lock().await;
            let RuntimeState::Pending { waiters } = &mut *state else {
                return;
            };
            let waiters = std::mem::take(waiters);
            *state = RuntimeState::Failed {
                error_code,
                completed_at: Instant::now(),
            };
            waiters
        };
        for waiter in waiters {
            let _ = waiter.send(Err(error_code));
        }
    }

    async fn publish_retryable_failure(&self, runtime_key: String, error_code: &'static str) {
        let mut runtime = self.runtime.lock().await;
        let Some(operation) = runtime.get(&runtime_key).cloned() else {
            return;
        };
        let waiters = {
            let mut state = operation.state.lock().await;
            let RuntimeState::Pending { waiters } = &mut *state else {
                return;
            };
            let waiters = std::mem::take(waiters);
            *state = RuntimeState::Failed {
                error_code,
                completed_at: Instant::now(),
            };
            waiters
        };
        runtime.remove(&runtime_key);
        drop(runtime);
        for waiter in waiters {
            let _ = waiter.send(Err(error_code));
        }
    }
}

async fn cleanup_runtime(runtime: &mut HashMap<String, Arc<RuntimeOperation>>) {
    let operations = runtime
        .iter()
        .map(|(key, operation)| (key.clone(), Arc::clone(operation)))
        .collect::<Vec<_>>();
    for (key, operation) in operations {
        let expired = match &*operation.state.lock().await {
            RuntimeState::Pending { .. } => false,
            RuntimeState::Completed { completed_at, .. } => {
                completed_at.elapsed() >= RUNTIME_RESULT_RETENTION
            }
            RuntimeState::Terminal { completed_at, .. }
            | RuntimeState::Failed { completed_at, .. } => {
                completed_at.elapsed() >= RUNTIME_RESULT_RETENTION
            }
        };
        if expired {
            runtime.remove(&key);
        }
    }
}

async fn await_result(
    receiver: oneshot::Receiver<Result<TrackedInvocationStatus, &'static str>>,
) -> Result<TrackedInvocationStatus, CoordinatorError> {
    receiver
        .await
        .map_err(|_| CoordinatorError::RuntimeTaskFailed)?
        .map_err(CoordinatorError::RuntimeWorkflowFailed)
}

async fn begin_durable(
    ledger: Arc<InvocationLedger>,
    identity: OperationIdentity,
) -> Result<BeginDecision, CoordinatorError> {
    tokio::task::spawn_blocking(move || ledger.begin(&identity, SystemTime::now()))
        .await
        .map_err(|_| CoordinatorError::PersistenceTaskFailed)?
        .map_err(Into::into)
}

async fn complete_durable(
    ledger: Arc<InvocationLedger>,
    identity: OperationIdentity,
) -> Result<(), CoordinatorError> {
    tokio::task::spawn_blocking(move || ledger.complete(&identity, SystemTime::now()))
        .await
        .map_err(|_| CoordinatorError::PersistenceTaskFailed)?
        .map_err(Into::into)
}

async fn status_durable(
    ledger: Arc<InvocationLedger>,
    lookup: OperationLookup,
) -> Result<DurableStatus, CoordinatorError> {
    tokio::task::spawn_blocking(move || ledger.status(&lookup, SystemTime::now()))
        .await
        .map_err(|_| CoordinatorError::PersistenceTaskFailed)?
        .map_err(Into::into)
}

#[derive(Debug, Error)]
pub(crate) enum CoordinatorError {
    #[error("tracked invocation request is invalid: {0}")]
    InvalidRequest(String),
    #[error("tracked invocation operation ID conflicts with an existing request")]
    OperationConflict,
    #[error("tracked invocation runtime reached its bounded capacity of {0}")]
    RuntimeCapacity(usize),
    #[error("tracked invocation coordinator is stopping")]
    Stopping,
    #[error("tracked invocation runtime task ended before publishing a result")]
    RuntimeTaskFailed,
    #[error("tracked invocation workflow failed ({0})")]
    RuntimeWorkflowFailed(&'static str),
    #[error("tracked invocation persistence task failed")]
    PersistenceTaskFailed,
    #[error("tracked invocation ledger failed: {0}")]
    Ledger(#[from] LedgerError),
}

impl CoordinatorError {
    pub(crate) fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "tracked-invocation-invalid-request",
            Self::OperationConflict => "tracked-invocation-conflict",
            Self::RuntimeCapacity(_) => "tracked-invocation-capacity",
            Self::Stopping => "tracked-invocation-stopping",
            Self::RuntimeTaskFailed => "tracked-invocation-task-failed",
            Self::RuntimeWorkflowFailed(code) => code,
            Self::PersistenceTaskFailed => "tracked-invocation-persistence-task-failed",
            Self::Ledger(error) => error.diagnostic_code(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::{json, Map};
    use tempfile::tempdir;
    use webplus_controller::{PluginTrust, SupervisorConfig};
    use webplus_plugin_config::PluginManifest;

    use super::*;

    const OPERATION_ID: &str = "123e4567-e89b-42d3-a456-426614174000";

    fn request(copies: i64) -> InvokeRequest {
        InvokeRequest {
            service_id: "printer".into(),
            method: "print".into(),
            parameters: Map::from_iter([("copies".into(), json!(copies))]),
        }
    }

    #[test]
    fn public_status_names_match_the_sdk_contract() {
        assert_eq!(
            serde_json::to_value(TrackedInvocationStatus::Indeterminate).unwrap()["state"],
            "indeterminate"
        );
        assert_eq!(
            serde_json::to_value(TrackedInvocationStatus::CompletedWithoutResult).unwrap()["state"],
            "completedWithoutResult"
        );
    }

    async fn controller(root: &std::path::Path) -> Arc<PluginController> {
        let plugin = root.join("printer-plugin");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("api.json"),
            r#"{"serviceId":"printer","mainClass":"printer.dll"}"#,
        )
        .unwrap();
        let manifest = PluginManifest::load("printer-plugin", plugin).unwrap();
        let controller = Arc::new(
            PluginController::new(SupervisorConfig {
                x86_host: root.join("missing-x86-host"),
                x64_host: root.join("missing-x64-host"),
                request_timeout: Duration::from_secs(1),
                max_in_flight_invocations: 8,
                plugin_trust: PluginTrust::AllowUnsigned,
            })
            .unwrap(),
        );
        controller.replace_manifests(&[manifest]).await.unwrap();
        controller
    }

    async fn pending_operation(
        coordinator: &Arc<InvocationCoordinator>,
        operation_id: &str,
    ) -> (
        String,
        OperationIdentity,
        oneshot::Receiver<Result<TrackedInvocationStatus, &'static str>>,
    ) {
        let identity =
            OperationIdentity::for_request(operation_id, "https://business.example", &request(1))
                .unwrap();
        let runtime_key = identity.runtime_key();
        let (sender, receiver) = oneshot::channel();
        coordinator.runtime.lock().await.insert(
            runtime_key.clone(),
            Arc::new(RuntimeOperation {
                identity: identity.clone(),
                state: Mutex::new(RuntimeState::Pending {
                    waiters: vec![sender],
                }),
            }),
        );
        coordinator.active_workflows.fetch_add(1, Ordering::AcqRel);
        (runtime_key, identity, receiver)
    }

    #[tokio::test]
    async fn concurrent_same_id_executes_the_controller_only_once() {
        let root = tempdir().unwrap();
        let controller = controller(root.path()).await;
        let coordinator = Arc::new(
            InvocationCoordinator::open(root.path().join("ledger"))
                .expect("coordinator should open"),
        );
        let first = {
            let coordinator = Arc::clone(&coordinator);
            let controller = Arc::clone(&controller);
            tokio::spawn(async move {
                coordinator
                    .invoke(
                        "https://business.example",
                        OPERATION_ID,
                        request(1),
                        controller,
                    )
                    .await
            })
        };
        let second = {
            let coordinator = Arc::clone(&coordinator);
            let controller = Arc::clone(&controller);
            tokio::spawn(async move {
                coordinator
                    .invoke(
                        "https://business.example",
                        OPERATION_ID,
                        request(1),
                        controller,
                    )
                    .await
            })
        };

        let first = first.await.unwrap().unwrap();
        let second = second.await.unwrap().unwrap();
        for status in [first, second] {
            let TrackedInvocationStatus::Completed { response, durable } = status else {
                panic!("tracked invocation did not complete");
            };
            assert_eq!(response.res_code, -32000);
            assert!(durable);
        }
        assert_eq!(controller.plugin_host_stats().failed_starts, 1);
        assert_eq!(coordinator.stats().await.durable_operations, 1);
    }

    #[tokio::test]
    async fn completed_result_is_queryable_in_process_and_not_replayed_after_restart() {
        let root = tempdir().unwrap();
        let controller = controller(root.path()).await;
        let ledger = root.path().join("ledger");
        let coordinator = Arc::new(InvocationCoordinator::open(ledger.clone()).unwrap());
        let completed = coordinator
            .invoke(
                "https://business.example",
                OPERATION_ID,
                request(1),
                Arc::clone(&controller),
            )
            .await
            .unwrap();
        assert!(matches!(
            completed,
            TrackedInvocationStatus::Completed { durable: true, .. }
        ));
        assert!(matches!(
            coordinator
                .status("https://business.example", OPERATION_ID, "printer", "print")
                .await
                .unwrap(),
            TrackedInvocationStatus::Completed { durable: true, .. }
        ));
        drop(coordinator);

        let recovered = InvocationCoordinator::open(ledger).unwrap();
        assert_eq!(
            recovered
                .status("https://business.example", OPERATION_ID, "printer", "print")
                .await
                .unwrap(),
            TrackedInvocationStatus::CompletedWithoutResult
        );
        assert_eq!(controller.plugin_host_stats().failed_starts, 1);
    }

    #[tokio::test]
    async fn same_id_cannot_be_rebound_to_parameters_or_authorization() {
        let root = tempdir().unwrap();
        let controller = controller(root.path()).await;
        let coordinator =
            Arc::new(InvocationCoordinator::open(root.path().join("ledger")).unwrap());
        coordinator
            .invoke(
                "https://business.example",
                OPERATION_ID,
                request(1),
                Arc::clone(&controller),
            )
            .await
            .unwrap();

        let conflict = coordinator
            .invoke(
                "https://business.example",
                OPERATION_ID,
                request(2),
                controller,
            )
            .await
            .unwrap_err();
        assert_eq!(conflict.diagnostic_code(), "tracked-invocation-conflict");
        let route_conflict = coordinator
            .status(
                "https://business.example",
                OPERATION_ID,
                "printer",
                "other-method",
            )
            .await
            .unwrap_err();
        assert_eq!(
            route_conflict.diagnostic_code(),
            "tracked-invocation-conflict"
        );
    }

    #[tokio::test]
    async fn completed_results_are_evicted_before_new_work_is_rejected() {
        let root = tempdir().unwrap();
        let controller = controller(root.path()).await;
        let coordinator =
            Arc::new(InvocationCoordinator::open(root.path().join("ledger")).unwrap());
        for index in 0..=MAX_RUNTIME_OPERATIONS {
            let operation_id = format!("123e4567-e89b-42d3-a456-{index:012x}");
            assert!(matches!(
                coordinator
                    .invoke(
                        "https://business.example",
                        &operation_id,
                        request(1),
                        Arc::clone(&controller),
                    )
                    .await
                    .unwrap(),
                TrackedInvocationStatus::Completed { .. }
            ));
        }

        let stats = coordinator.stats().await;
        assert_eq!(stats.runtime_operations, MAX_RUNTIME_OPERATIONS);
        assert_eq!(stats.durable_operations, MAX_RUNTIME_OPERATIONS + 1);
        assert_eq!(
            coordinator
                .status(
                    "https://business.example",
                    "123e4567-e89b-42d3-a456-000000000000",
                    "printer",
                    "print",
                )
                .await
                .unwrap(),
            TrackedInvocationStatus::CompletedWithoutResult
        );
    }

    #[tokio::test]
    async fn stopping_rejects_new_work_without_writing_the_ledger_and_can_resume() {
        let root = tempdir().unwrap();
        let controller = controller(root.path()).await;
        let coordinator =
            Arc::new(InvocationCoordinator::open(root.path().join("ledger")).unwrap());

        coordinator.stop_accepting().await;
        let error = coordinator
            .invoke(
                "https://business.example",
                OPERATION_ID,
                request(1),
                Arc::clone(&controller),
            )
            .await
            .unwrap_err();
        assert_eq!(error.diagnostic_code(), "tracked-invocation-stopping");
        assert_eq!(coordinator.stats().await.durable_operations, 0);

        coordinator.resume_after_shutdown();
        assert!(matches!(
            coordinator
                .invoke(
                    "https://business.example",
                    OPERATION_ID,
                    request(1),
                    controller,
                )
                .await
                .unwrap(),
            TrackedInvocationStatus::Completed { durable: true, .. }
        ));
    }

    #[tokio::test]
    async fn drain_waits_for_the_completion_persistence_workflow() {
        let root = tempdir().unwrap();
        let coordinator =
            Arc::new(InvocationCoordinator::open(root.path().join("ledger")).unwrap());
        coordinator.active_workflows.fetch_add(1, Ordering::AcqRel);
        let active = ActiveWorkflowGuard {
            coordinator: Arc::clone(&coordinator),
        };
        let mut drain = {
            let coordinator = Arc::clone(&coordinator);
            tokio::spawn(async move {
                coordinator.stop_accepting().await;
                coordinator.drain().await;
            })
        };

        assert!(tokio::time::timeout(Duration::from_millis(20), &mut drain)
            .await
            .is_err());
        drop(active);
        tokio::time::timeout(Duration::from_secs(1), drain)
            .await
            .expect("drain should be notified")
            .expect("drain task should succeed");
    }

    #[tokio::test]
    async fn terminated_workflow_without_durable_acceptance_fails_waiters_and_drains() {
        let root = tempdir().unwrap();
        let controller = controller(root.path()).await;
        let coordinator =
            Arc::new(InvocationCoordinator::open(root.path().join("ledger")).unwrap());
        let (runtime_key, identity, receiver) = pending_operation(&coordinator, OPERATION_ID).await;
        let workflow = tokio::spawn(async move {
            panic!("synthetic workflow failure before durable acceptance");
        });
        coordinator.supervise_workflow(runtime_key, identity, workflow);

        let error = tokio::time::timeout(Duration::from_secs(1), await_result(receiver))
            .await
            .expect("workflow waiter should be released")
            .unwrap_err();
        assert_eq!(error.diagnostic_code(), "tracked-invocation-task-failed");
        tokio::time::timeout(Duration::from_secs(1), coordinator.drain())
            .await
            .expect("terminated workflow should not block drain");
        assert_eq!(coordinator.stats().await.pending_operations, 0);
        assert!(matches!(
            coordinator
                .invoke(
                    "https://business.example",
                    OPERATION_ID,
                    request(1),
                    controller,
                )
                .await
                .unwrap(),
            TrackedInvocationStatus::Completed { durable: true, .. }
        ));
    }

    #[tokio::test]
    async fn terminated_workflow_after_durable_acceptance_becomes_indeterminate() {
        let root = tempdir().unwrap();
        let coordinator =
            Arc::new(InvocationCoordinator::open(root.path().join("ledger")).unwrap());
        let (runtime_key, identity, receiver) = pending_operation(&coordinator, OPERATION_ID).await;
        assert_eq!(
            begin_durable(Arc::clone(&coordinator.ledger), identity.clone())
                .await
                .unwrap(),
            BeginDecision::Started
        );
        let workflow = tokio::spawn(async move {
            panic!("synthetic workflow failure after durable acceptance");
        });
        coordinator.supervise_workflow(runtime_key, identity, workflow);

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), await_result(receiver))
                .await
                .expect("workflow waiter should be released")
                .unwrap(),
            TrackedInvocationStatus::Indeterminate
        );
        tokio::time::timeout(Duration::from_secs(1), coordinator.drain())
            .await
            .expect("terminated workflow should not block drain");
        assert_eq!(coordinator.stats().await.pending_operations, 0);
        assert_eq!(
            coordinator
                .status("https://business.example", OPERATION_ID, "printer", "print",)
                .await
                .unwrap(),
            TrackedInvocationStatus::Indeterminate
        );
    }
}
