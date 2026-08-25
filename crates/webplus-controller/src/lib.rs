use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::process::{Child, Command};
use tokio::sync::{
    Mutex, MutexGuard, OwnedMutexGuard, OwnedRwLockWriteGuard, RwLock, RwLockReadGuard,
    RwLockWriteGuard, Semaphore,
};
use tokio::time::{timeout, timeout_at, Instant};
use tracing::{info, warn};
use webplus_ipc::{read_frame_async, write_frame_async, FrameError};
use webplus_plugin_config::PluginManifest;
use webplus_protocol::{
    HostCommand, HostPayload, HostRequest, HostResponse, HostResult, InvokeRequest, InvokeResponse,
    PluginArchitecture, HOST_PROTOCOL_VERSION,
};

const INVALID_REQUEST: i32 = -32602;
const SERVICE_NOT_FOUND: i32 = -32601;
const HOST_FAILURE: i32 = -32000;
const SERVER_BUSY: i32 = -32001;
const CONTROLLER_STOPPING: i32 = -32002;
const EXECUTION_LANE_TIMEOUT: i32 = -32003;
const CONTROLLER_MAINTENANCE: i32 = -32010;
pub const DEFAULT_MAX_IN_FLIGHT_INVOCATIONS: usize = 8;
const MAX_IN_FLIGHT_INVOCATIONS_LIMIT: usize = 1024;
const HOST_START_TIMEOUT: Duration = Duration::from_secs(120);
const HOST_RESTART_BACKOFF: Duration = Duration::from_secs(1);
#[cfg(windows)]
const HOST_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginDescriptor {
    pub plugin_id: String,
    pub plugin_dir: PathBuf,
    pub architecture: PluginArchitecture,
}

#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    pub x86_host: PathBuf,
    pub x64_host: PathBuf,
    pub request_timeout: Duration,
    pub max_in_flight_invocations: usize,
    pub plugin_trust: PluginTrust,
}

#[derive(Debug, Clone)]
pub enum PluginTrust {
    Strict { trust_store: PathBuf },
    AllowUnsigned,
}

impl SupervisorConfig {
    fn host_for(&self, architecture: PluginArchitecture) -> &Path {
        match architecture {
            PluginArchitecture::X86 => &self.x86_host,
            PluginArchitecture::X64 => &self.x64_host,
        }
    }
}

pub struct PluginController {
    routes: RwLock<HashMap<String, ServiceRoute>>,
    plugin_lifecycles: Mutex<HashMap<String, Arc<PluginLifecycle>>>,
    supervisor: PluginSupervisor,
    lifecycle: RwLock<()>,
    maintenance_gate: Mutex<()>,
    lifecycle_epoch: AtomicU64,
    global_maintenance_active: AtomicBool,
    active_plugin_maintenances: AtomicUsize,
    admission: Semaphore,
    max_in_flight_invocations: usize,
    rejected_invocations: AtomicU64,
    caller_detachments: AtomicU64,
    shutdown_rejections: AtomicU64,
    execution_lane_timeouts: AtomicU64,
    maintenance_rejections: AtomicU64,
    accepting_invocations: AtomicBool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvocationAdmissionStats {
    pub max_in_flight: usize,
    pub in_flight: usize,
    pub rejected: u64,
    pub caller_detachments: u64,
    pub shutdown_rejections: u64,
    pub execution_lane_timeouts: u64,
    pub maintenance_rejections: u64,
    pub maintenance_active: bool,
    pub global_maintenance_active: bool,
    pub active_plugin_maintenances: usize,
    pub accepting: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PluginPreflightReport {
    pub hosts_started: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PluginHostStats {
    pub active_hosts: usize,
    pub successful_starts: u64,
    pub failed_starts: u64,
}

#[derive(Clone)]
struct ServiceRoute {
    descriptor: PluginDescriptor,
    default_timeout: Option<Duration>,
    method_timeouts: HashMap<String, Duration>,
}

struct PluginLifecycle {
    lifecycle: Arc<RwLock<()>>,
    maintenance_gate: Arc<Mutex<()>>,
    epoch: AtomicU64,
    maintenance_active: AtomicBool,
}

impl PluginLifecycle {
    fn new() -> Self {
        Self {
            lifecycle: Arc::new(RwLock::new(())),
            maintenance_gate: Arc::new(Mutex::new(())),
            epoch: AtomicU64::new(0),
            maintenance_active: AtomicBool::new(false),
        }
    }
}

impl PluginController {
    pub fn new(config: SupervisorConfig) -> Result<Self, ControllerError> {
        if !(1..=MAX_IN_FLIGHT_INVOCATIONS_LIMIT).contains(&config.max_in_flight_invocations) {
            return Err(ControllerError::InvalidInvocationLimit {
                actual: config.max_in_flight_invocations,
                maximum: MAX_IN_FLIGHT_INVOCATIONS_LIMIT,
            });
        }
        let max_in_flight_invocations = config.max_in_flight_invocations;
        Ok(Self {
            routes: RwLock::new(HashMap::new()),
            plugin_lifecycles: Mutex::new(HashMap::new()),
            supervisor: PluginSupervisor::new(config),
            lifecycle: RwLock::new(()),
            maintenance_gate: Mutex::new(()),
            lifecycle_epoch: AtomicU64::new(0),
            global_maintenance_active: AtomicBool::new(false),
            active_plugin_maintenances: AtomicUsize::new(0),
            admission: Semaphore::new(max_in_flight_invocations),
            max_in_flight_invocations,
            rejected_invocations: AtomicU64::new(0),
            caller_detachments: AtomicU64::new(0),
            shutdown_rejections: AtomicU64::new(0),
            execution_lane_timeouts: AtomicU64::new(0),
            maintenance_rejections: AtomicU64::new(0),
            accepting_invocations: AtomicBool::new(true),
        })
    }

    pub async fn register_service(
        &self,
        service_id: impl Into<String>,
        descriptor: PluginDescriptor,
    ) -> Result<(), ControllerError> {
        let service_id = service_id.into();
        if service_id.trim().is_empty() {
            return Err(ControllerError::EmptyServiceId);
        }
        self.plugin_lifecycle(&descriptor.plugin_id).await;

        let mut routes = self.routes.write().await;
        if let Some(existing) = routes.get(&service_id) {
            if existing.descriptor != descriptor {
                return Err(ControllerError::DuplicateService(service_id));
            }
            return Ok(());
        }
        routes.insert(
            service_id,
            ServiceRoute {
                descriptor,
                default_timeout: None,
                method_timeouts: HashMap::new(),
            },
        );
        Ok(())
    }

    pub async fn register_manifest(
        &self,
        manifest: &PluginManifest,
    ) -> Result<(), ControllerError> {
        for service in &manifest.services {
            self.register_service(
                service.service_id.clone(),
                PluginDescriptor {
                    plugin_id: manifest.plugin_id.clone(),
                    plugin_dir: manifest.plugin_dir.clone(),
                    architecture: service.architecture,
                },
            )
            .await?;
            let mut routes = self.routes.write().await;
            if let Some(route) = routes.get_mut(&service.service_id) {
                route.default_timeout = configured_timeout(service.timeout);
                for method in &service.methods {
                    if let Some(timeout) = configured_timeout(method.timeout) {
                        route.method_timeouts.insert(method.name.clone(), timeout);
                        if let Some(alias) = &method.alias {
                            route.method_timeouts.insert(alias.clone(), timeout);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn service_count(&self) -> usize {
        self.routes.read().await.len()
    }

    pub fn invocation_admission_stats(&self) -> InvocationAdmissionStats {
        let global_maintenance_active = self.global_maintenance_active.load(Ordering::Acquire);
        let active_plugin_maintenances = self.active_plugin_maintenances.load(Ordering::Acquire);
        InvocationAdmissionStats {
            max_in_flight: self.max_in_flight_invocations,
            in_flight: self
                .max_in_flight_invocations
                .saturating_sub(self.admission.available_permits()),
            rejected: self.rejected_invocations.load(Ordering::Relaxed),
            caller_detachments: self.caller_detachments.load(Ordering::Relaxed),
            shutdown_rejections: self.shutdown_rejections.load(Ordering::Relaxed),
            execution_lane_timeouts: self.execution_lane_timeouts.load(Ordering::Relaxed),
            maintenance_rejections: self.maintenance_rejections.load(Ordering::Relaxed),
            maintenance_active: global_maintenance_active || active_plugin_maintenances > 0,
            global_maintenance_active,
            active_plugin_maintenances,
            accepting: self.accepting_invocations.load(Ordering::Acquire),
        }
    }

    pub fn plugin_host_stats(&self) -> PluginHostStats {
        self.supervisor.stats()
    }

    pub fn validate_manifests(manifests: &[PluginManifest]) -> Result<(), ControllerError> {
        routes_from_manifests(manifests).map(|_| ())
    }

    /// Verifies a signed candidate from its staging directory without changing
    /// active routes or stopping healthy plugin hosts. The lifecycle read lock
    /// prevents activation, reload, or shutdown from racing the candidate host.
    pub async fn preflight_candidate_manifest(
        &self,
        manifest: &PluginManifest,
    ) -> Result<PluginPreflightReport, ControllerError> {
        let plugin_lifecycle = self.plugin_lifecycle(&manifest.plugin_id).await;
        let lifecycle_epoch = self.lifecycle_epoch.load(Ordering::Acquire);
        let plugin_epoch = plugin_lifecycle.epoch.load(Ordering::Acquire);
        if !self.accepting_invocations.load(Ordering::Acquire)
            || self.global_maintenance_active.load(Ordering::Acquire)
            || plugin_lifecycle.maintenance_active.load(Ordering::Acquire)
        {
            return Err(ControllerError::PreflightUnavailable);
        }
        let _lifecycle = self.lifecycle.read().await;
        let _plugin_lifecycle = plugin_lifecycle.lifecycle.read().await;
        if !self.accepting_invocations.load(Ordering::Acquire)
            || self.global_maintenance_active.load(Ordering::Acquire)
            || plugin_lifecycle.maintenance_active.load(Ordering::Acquire)
            || self.lifecycle_epoch.load(Ordering::Acquire) != lifecycle_epoch
            || plugin_lifecycle.epoch.load(Ordering::Acquire) != plugin_epoch
        {
            return Err(ControllerError::PreflightUnavailable);
        }
        self.preflight_manifest_hosts(manifest).await
    }

    pub async fn begin_maintenance(&self) -> PluginMaintenance<'_> {
        let maintenance_gate = self.maintenance_gate.lock().await;
        let maintenance_state = MaintenanceStateGuard::activate(self);
        let lifecycle = self.lifecycle.write().await;
        let maintenance = PluginMaintenance {
            controller: self,
            _lifecycle: lifecycle,
            _maintenance_gate: maintenance_gate,
            _maintenance_state: maintenance_state,
        };
        maintenance.controller.supervisor.shutdown().await;
        maintenance
    }

    /// Drains and replaces only one plugin. Unrelated plugin calls and hosts
    /// remain available while the selected plugin directory and routes switch.
    pub async fn begin_plugin_maintenance(
        &self,
        plugin_id: &str,
    ) -> Result<ScopedPluginMaintenance<'_>, ControllerError> {
        if plugin_id.trim().is_empty() {
            return Err(ControllerError::EmptyPluginId);
        }
        let plugin_lifecycle = self.plugin_lifecycle(plugin_id).await;
        let maintenance_gate = Arc::clone(&plugin_lifecycle.maintenance_gate)
            .lock_owned()
            .await;
        let lifecycle_epoch = self.lifecycle_epoch.load(Ordering::Acquire);
        if !self.accepting_invocations.load(Ordering::Acquire)
            || self.global_maintenance_active.load(Ordering::Acquire)
        {
            return Err(ControllerError::MaintenanceUnavailable);
        }
        let global_lifecycle = self.lifecycle.read().await;
        if !self.accepting_invocations.load(Ordering::Acquire)
            || self.global_maintenance_active.load(Ordering::Acquire)
            || self.lifecycle_epoch.load(Ordering::Acquire) != lifecycle_epoch
        {
            return Err(ControllerError::MaintenanceUnavailable);
        }
        let maintenance_state =
            ScopedMaintenanceStateGuard::activate(self, Arc::clone(&plugin_lifecycle));
        let plugin_guard = Arc::clone(&plugin_lifecycle.lifecycle).write_owned().await;
        self.supervisor.shutdown_plugin(plugin_id).await;
        Ok(ScopedPluginMaintenance {
            controller: self,
            plugin_id: plugin_id.to_owned(),
            _global_lifecycle: global_lifecycle,
            _plugin_lifecycle: plugin_guard,
            _maintenance_gate: maintenance_gate,
            _maintenance_state: maintenance_state,
        })
    }

    pub async fn replace_manifests(
        &self,
        manifests: &[PluginManifest],
    ) -> Result<(), ControllerError> {
        let maintenance = self.begin_maintenance().await;
        maintenance.replace_manifests(manifests).await
    }

    /// Runs accepted native work independently from the lifetime of the caller
    /// waiting for its response. Dropping this future detaches the waiter but
    /// does not cancel a possibly non-idempotent hardware operation.
    pub async fn invoke(self: &Arc<Self>, request: InvokeRequest) -> InvokeResponse {
        let controller = Arc::clone(self);
        let task = tokio::spawn(async move { controller.invoke_inner(request).await });
        let mut waiter = CallerWaitGuard::new(&self.caller_detachments);
        let result = task.await;
        waiter.complete();
        match result {
            Ok(response) => response,
            Err(_) => {
                warn!(
                    event_code = "plugin-invocation-task-failed",
                    "supervised plugin invocation task failed"
                );
                InvokeResponse::error(HOST_FAILURE, "native plugin invocation task failed")
            }
        }
    }

    async fn invoke_inner(&self, request: InvokeRequest) -> InvokeResponse {
        if let Err(error) = request.validate() {
            return InvokeResponse::error(INVALID_REQUEST, error.to_string());
        }
        let lifecycle_epoch = self.lifecycle_epoch.load(Ordering::Acquire);
        if !self.accepting_invocations.load(Ordering::Acquire) {
            return self.reject_stopping_invocation();
        }
        if self.global_maintenance_active.load(Ordering::Acquire) {
            return self.reject_maintenance_invocation();
        }
        let route = {
            let routes = self.routes.read().await;
            routes.get(&request.service_id).cloned()
        };
        let plugin_lifecycle = match &route {
            Some(route) => Some(self.plugin_lifecycle(&route.descriptor.plugin_id).await),
            None => None,
        };
        let plugin_epoch = plugin_lifecycle
            .as_ref()
            .map(|lifecycle| lifecycle.epoch.load(Ordering::Acquire));
        if plugin_lifecycle
            .as_ref()
            .is_some_and(|lifecycle| lifecycle.maintenance_active.load(Ordering::Acquire))
        {
            return self.reject_maintenance_invocation();
        }
        let Ok(_admission) = self.admission.try_acquire() else {
            self.rejected_invocations.fetch_add(1, Ordering::Relaxed);
            return InvokeResponse::error(
                SERVER_BUSY,
                "native plugin invocation capacity is busy; retry later",
            );
        };
        let _lifecycle = self.lifecycle.read().await;
        let _plugin_lifecycle = match &plugin_lifecycle {
            Some(lifecycle) => Some(lifecycle.lifecycle.read().await),
            None => None,
        };
        if !self.accepting_invocations.load(Ordering::Acquire) {
            return self.reject_stopping_invocation();
        }
        if self.global_maintenance_active.load(Ordering::Acquire)
            || self.lifecycle_epoch.load(Ordering::Acquire) != lifecycle_epoch
            || plugin_lifecycle.as_ref().is_some_and(|lifecycle| {
                lifecycle.maintenance_active.load(Ordering::Acquire)
                    || Some(lifecycle.epoch.load(Ordering::Acquire)) != plugin_epoch
            })
        {
            return self.reject_maintenance_invocation();
        }
        let Some(route) = route else {
            return InvokeResponse::error(
                SERVICE_NOT_FOUND,
                format!("service [{}] could not find!", request.service_id),
            );
        };

        let request_timeout = route
            .method_timeouts
            .get(&request.method)
            .copied()
            .or(route.default_timeout)
            .unwrap_or(self.supervisor.config.request_timeout);
        match self
            .supervisor
            .invoke(&route.descriptor, request, request_timeout)
            .await
        {
            Ok(response) => response,
            Err(error) => {
                warn!(
                    event_code = "plugin-host-request-failed",
                    plugin_id = route.descriptor.plugin_id,
                    error_code = error.diagnostic_code(),
                    "plugin host request failed"
                );
                self.host_failure_response(&error)
            }
        }
    }

    fn host_failure_response(&self, error: &ControllerError) -> InvokeResponse {
        if matches!(error, ControllerError::ExecutionLaneTimeout { .. }) {
            self.execution_lane_timeouts.fetch_add(1, Ordering::Relaxed);
            InvokeResponse::error(
                EXECUTION_LANE_TIMEOUT,
                "native plugin execution lane timed out; request was not executed",
            )
        } else {
            InvokeResponse::error(HOST_FAILURE, public_host_failure(error))
        }
    }

    fn reject_stopping_invocation(&self) -> InvokeResponse {
        self.shutdown_rejections.fetch_add(1, Ordering::Relaxed);
        InvokeResponse::error(
            CONTROLLER_STOPPING,
            "native plugin controller is stopping; request was not executed",
        )
    }

    fn reject_maintenance_invocation(&self) -> InvokeResponse {
        self.maintenance_rejections.fetch_add(1, Ordering::Relaxed);
        InvokeResponse::error(
            CONTROLLER_MAINTENANCE,
            "native plugin controller is reloading; request was not executed",
        )
    }

    async fn plugin_lifecycle(&self, plugin_id: &str) -> Arc<PluginLifecycle> {
        let mut lifecycles = self.plugin_lifecycles.lock().await;
        Arc::clone(
            lifecycles
                .entry(plugin_id.to_owned())
                .or_insert_with(|| Arc::new(PluginLifecycle::new())),
        )
    }

    async fn preflight_manifest_hosts(
        &self,
        manifest: &PluginManifest,
    ) -> Result<PluginPreflightReport, ControllerError> {
        let descriptors = preflight_descriptors(manifest);
        let result = match descriptors.as_slice() {
            [] => Ok(()),
            [descriptor] => self.supervisor.preflight(descriptor).await,
            [first, second] => {
                let (first, second) = tokio::join!(
                    self.supervisor.preflight(first),
                    self.supervisor.preflight(second)
                );
                first.and(second)
            }
            descriptors => {
                let mut result = Ok(());
                for descriptor in descriptors {
                    if let Err(failure) = self.supervisor.preflight(descriptor).await {
                        result = Err(failure);
                        break;
                    }
                }
                result
            }
        };
        if let Err(failure) = result {
            warn!(
                event_code = "plugin-host-preflight-failed",
                plugin_id = manifest.plugin_id,
                error_code = failure.diagnostic_code(),
                "plugin host preflight failed"
            );
            return Err(failure);
        }
        info!(
            event_code = "plugin-host-preflight-succeeded",
            plugin_id = manifest.plugin_id,
            host_count = descriptors.len(),
            "plugin host preflight succeeded"
        );
        Ok(PluginPreflightReport {
            hosts_started: descriptors.len(),
        })
    }

    pub async fn shutdown(&self) {
        self.accepting_invocations.store(false, Ordering::Release);
        let _lifecycle = self.lifecycle.write().await;
        self.supervisor.shutdown().await;
    }

    /// Reopens admission only after a terminal operation, such as an application
    /// update installation, failed after `shutdown` completed.
    pub async fn resume_after_shutdown(&self) {
        let _lifecycle = self.lifecycle.write().await;
        self.accepting_invocations.store(true, Ordering::Release);
    }
}

struct CallerWaitGuard<'a> {
    counter: &'a AtomicU64,
    completed: bool,
}

impl<'a> CallerWaitGuard<'a> {
    fn new(counter: &'a AtomicU64) -> Self {
        Self {
            counter,
            completed: false,
        }
    }

    fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for CallerWaitGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.counter.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub struct PluginMaintenance<'a> {
    controller: &'a PluginController,
    _lifecycle: RwLockWriteGuard<'a, ()>,
    _maintenance_gate: MutexGuard<'a, ()>,
    _maintenance_state: MaintenanceStateGuard<'a>,
}

struct MaintenanceStateGuard<'a> {
    controller: &'a PluginController,
}

impl<'a> MaintenanceStateGuard<'a> {
    fn activate(controller: &'a PluginController) -> Self {
        controller.lifecycle_epoch.fetch_add(1, Ordering::AcqRel);
        controller
            .global_maintenance_active
            .store(true, Ordering::Release);
        Self { controller }
    }
}

impl Drop for MaintenanceStateGuard<'_> {
    fn drop(&mut self) {
        self.controller
            .global_maintenance_active
            .store(false, Ordering::Release);
    }
}

impl PluginMaintenance<'_> {
    pub async fn replace_manifests(
        &self,
        manifests: &[PluginManifest],
    ) -> Result<(), ControllerError> {
        let routes = routes_from_manifests(manifests)?;
        for manifest in manifests {
            self.controller.plugin_lifecycle(&manifest.plugin_id).await;
        }
        *self.controller.routes.write().await = routes;
        Ok(())
    }

    /// Starts one isolated host for every architecture used by the selected
    /// plugin, completes the authenticated Health handshake, and then stops it.
    /// No native business method is invoked during this installation gate.
    pub async fn preflight_manifest(
        &self,
        manifest: &PluginManifest,
    ) -> Result<PluginPreflightReport, ControllerError> {
        {
            let routes = self.controller.routes.read().await;
            for service in &manifest.services {
                let expected = PluginDescriptor {
                    plugin_id: manifest.plugin_id.clone(),
                    plugin_dir: manifest.plugin_dir.clone(),
                    architecture: service.architecture,
                };
                if !routes
                    .get(&service.service_id)
                    .is_some_and(|route| route.descriptor == expected)
                {
                    return Err(ControllerError::PreflightRouteMismatch(
                        service.service_id.clone(),
                    ));
                }
            }
        }

        self.controller.preflight_manifest_hosts(manifest).await
    }
}

pub struct ScopedPluginMaintenance<'a> {
    controller: &'a PluginController,
    plugin_id: String,
    _global_lifecycle: RwLockReadGuard<'a, ()>,
    _plugin_lifecycle: OwnedRwLockWriteGuard<()>,
    _maintenance_gate: OwnedMutexGuard<()>,
    _maintenance_state: ScopedMaintenanceStateGuard<'a>,
}

struct ScopedMaintenanceStateGuard<'a> {
    controller: &'a PluginController,
    lifecycle: Arc<PluginLifecycle>,
}

impl<'a> ScopedMaintenanceStateGuard<'a> {
    fn activate(controller: &'a PluginController, lifecycle: Arc<PluginLifecycle>) -> Self {
        lifecycle.epoch.fetch_add(1, Ordering::AcqRel);
        lifecycle.maintenance_active.store(true, Ordering::Release);
        controller
            .active_plugin_maintenances
            .fetch_add(1, Ordering::AcqRel);
        Self {
            controller,
            lifecycle,
        }
    }
}

impl Drop for ScopedMaintenanceStateGuard<'_> {
    fn drop(&mut self) {
        self.lifecycle
            .maintenance_active
            .store(false, Ordering::Release);
        self.controller
            .active_plugin_maintenances
            .fetch_sub(1, Ordering::AcqRel);
    }
}

impl ScopedPluginMaintenance<'_> {
    /// Replaces or removes exactly the selected plugin's routes while keeping
    /// every unrelated route unchanged. The caller must update the matching
    /// plugin directory under the same guard.
    pub async fn replace_manifest(
        &self,
        manifest: Option<&PluginManifest>,
    ) -> Result<(), ControllerError> {
        if let Some(manifest) = manifest {
            if manifest.plugin_id != self.plugin_id {
                return Err(ControllerError::MaintenancePluginMismatch {
                    expected: self.plugin_id.clone(),
                    actual: manifest.plugin_id.clone(),
                });
            }
        }
        let replacement = manifest
            .map(|manifest| routes_from_manifests(std::slice::from_ref(manifest)))
            .transpose()?
            .unwrap_or_default();
        let mut routes = self.controller.routes.write().await;
        for service_id in replacement.keys() {
            if routes
                .get(service_id)
                .is_some_and(|route| route.descriptor.plugin_id != self.plugin_id)
            {
                return Err(ControllerError::DuplicateService(service_id.clone()));
            }
        }
        routes.retain(|_, route| route.descriptor.plugin_id != self.plugin_id);
        routes.extend(replacement);
        Ok(())
    }
}

fn preflight_descriptors(manifest: &PluginManifest) -> Vec<PluginDescriptor> {
    let mut keys = HashSet::new();
    let mut descriptors = Vec::new();
    for service in &manifest.services {
        let descriptor = PluginDescriptor {
            plugin_id: manifest.plugin_id.clone(),
            plugin_dir: manifest.plugin_dir.clone(),
            architecture: service.architecture,
        };
        if keys.insert(WorkerKey::from(&descriptor)) {
            descriptors.push(descriptor);
        }
    }
    descriptors
}

fn routes_from_manifests(
    manifests: &[PluginManifest],
) -> Result<HashMap<String, ServiceRoute>, ControllerError> {
    let mut routes = HashMap::new();
    for manifest in manifests {
        for service in &manifest.services {
            let service_id = service.service_id.clone();
            let descriptor = PluginDescriptor {
                plugin_id: manifest.plugin_id.clone(),
                plugin_dir: manifest.plugin_dir.clone(),
                architecture: service.architecture,
            };
            let mut method_timeouts = HashMap::new();
            for method in &service.methods {
                if let Some(timeout) = configured_timeout(method.timeout) {
                    method_timeouts.insert(method.name.clone(), timeout);
                    if let Some(alias) = &method.alias {
                        method_timeouts.insert(alias.clone(), timeout);
                    }
                }
            }
            if routes
                .insert(
                    service_id.clone(),
                    ServiceRoute {
                        descriptor,
                        default_timeout: configured_timeout(service.timeout),
                        method_timeouts,
                    },
                )
                .is_some()
            {
                return Err(ControllerError::DuplicateService(service_id));
            }
        }
    }
    Ok(routes)
}

struct PluginSupervisor {
    config: SupervisorConfig,
    workers: Mutex<HashMap<WorkerKey, Arc<WorkerSlot>>>,
    active_hosts: AtomicUsize,
    successful_starts: AtomicU64,
    failed_starts: AtomicU64,
}

struct WorkerSlot {
    state: Mutex<WorkerSlotState>,
}

enum WorkerSlotState {
    Vacant,
    Ready(Arc<Mutex<PluginWorker>>),
    Failed { retry_after: Instant },
}

impl WorkerSlot {
    fn vacant() -> Self {
        Self {
            state: Mutex::new(WorkerSlotState::Vacant),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct WorkerKey {
    plugin_id: String,
    plugin_dir: PathBuf,
    architecture: PluginArchitecture,
}

impl From<&PluginDescriptor> for WorkerKey {
    fn from(descriptor: &PluginDescriptor) -> Self {
        Self {
            plugin_id: descriptor.plugin_id.clone(),
            plugin_dir: descriptor.plugin_dir.clone(),
            architecture: descriptor.architecture,
        }
    }
}

impl PluginSupervisor {
    fn new(config: SupervisorConfig) -> Self {
        Self {
            config,
            workers: Mutex::new(HashMap::new()),
            active_hosts: AtomicUsize::new(0),
            successful_starts: AtomicU64::new(0),
            failed_starts: AtomicU64::new(0),
        }
    }

    fn stats(&self) -> PluginHostStats {
        PluginHostStats {
            active_hosts: self.active_hosts.load(Ordering::Acquire),
            successful_starts: self.successful_starts.load(Ordering::Relaxed),
            failed_starts: self.failed_starts.load(Ordering::Relaxed),
        }
    }

    async fn invoke(
        &self,
        descriptor: &PluginDescriptor,
        request: InvokeRequest,
        request_timeout: Duration,
    ) -> Result<InvokeResponse, ControllerError> {
        let worker_key = WorkerKey::from(descriptor);
        let worker = self.worker_for(descriptor).await?;
        let deadline = Instant::now() + request_timeout;
        let result = {
            let Some(mut worker_guard) = lock_before_deadline(worker.as_ref(), deadline).await
            else {
                return Err(ControllerError::ExecutionLaneTimeout {
                    plugin_id: descriptor.plugin_id.clone(),
                    timeout: request_timeout,
                });
            };
            match timeout_at(deadline, worker_guard.invoke(request)).await {
                Ok(result) => result,
                Err(_) => {
                    worker_guard.kill().await;
                    Err(ControllerError::Timeout {
                        plugin_id: descriptor.plugin_id.clone(),
                        timeout: request_timeout,
                    })
                }
            }
        };

        if result.is_err() {
            self.evict(&worker_key, &worker).await;
        }
        result
    }

    async fn preflight(&self, descriptor: &PluginDescriptor) -> Result<(), ControllerError> {
        let mut worker = self.spawn_worker(descriptor).await?;
        worker.shutdown().await;
        Ok(())
    }

    async fn worker_for(
        &self,
        descriptor: &PluginDescriptor,
    ) -> Result<Arc<Mutex<PluginWorker>>, ControllerError> {
        let key = WorkerKey::from(descriptor);
        let slot = {
            let mut workers = self.workers.lock().await;
            Arc::clone(
                workers
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(WorkerSlot::vacant())),
            )
        };
        let mut state = slot.state.lock().await;
        loop {
            match &*state {
                WorkerSlotState::Ready(worker) => return Ok(Arc::clone(worker)),
                WorkerSlotState::Failed { retry_after } if Instant::now() < *retry_after => {
                    return Err(ControllerError::HostInitializationFailed(
                        descriptor.plugin_id.clone(),
                    ));
                }
                WorkerSlotState::Failed { .. } => {
                    *state = WorkerSlotState::Vacant;
                }
                WorkerSlotState::Vacant => match self.spawn_worker(descriptor).await {
                    Ok(worker) => {
                        let worker = Arc::new(Mutex::new(worker));
                        *state = WorkerSlotState::Ready(Arc::clone(&worker));
                        self.active_hosts.fetch_add(1, Ordering::AcqRel);
                        return Ok(worker);
                    }
                    Err(failure) => {
                        *state = WorkerSlotState::Failed {
                            retry_after: Instant::now() + HOST_RESTART_BACKOFF,
                        };
                        return Err(failure);
                    }
                },
            }
        }
    }

    async fn spawn_worker(
        &self,
        descriptor: &PluginDescriptor,
    ) -> Result<PluginWorker, ControllerError> {
        let executable = self.config.host_for(descriptor.architecture);
        match PluginWorker::spawn(descriptor.clone(), executable, &self.config.plugin_trust).await {
            Ok(worker) => {
                self.successful_starts.fetch_add(1, Ordering::Relaxed);
                Ok(worker)
            }
            Err(failure) => {
                self.failed_starts.fetch_add(1, Ordering::Relaxed);
                Err(failure)
            }
        }
    }

    async fn evict(&self, key: &WorkerKey, failed_worker: &Arc<Mutex<PluginWorker>>) {
        let slot = { self.workers.lock().await.get(key).cloned() };
        let Some(slot) = slot else {
            return;
        };
        let mut state = slot.state.lock().await;
        if matches!(
            &*state,
            WorkerSlotState::Ready(current) if Arc::ptr_eq(current, failed_worker)
        ) {
            *state = WorkerSlotState::Failed {
                retry_after: Instant::now() + HOST_RESTART_BACKOFF,
            };
            decrement_saturating(&self.active_hosts);
        }
    }

    async fn shutdown(&self) {
        let slots = {
            let mut workers = self.workers.lock().await;
            workers.drain().map(|(_, slot)| slot).collect::<Vec<_>>()
        };
        let mut workers = Vec::new();
        for slot in slots {
            let mut state = slot.state.lock().await;
            if let WorkerSlotState::Ready(worker) = &*state {
                workers.push(Arc::clone(worker));
            }
            *state = WorkerSlotState::Failed {
                retry_after: Instant::now() + HOST_RESTART_BACKOFF,
            };
        }
        self.active_hosts.store(0, Ordering::Release);
        for worker in workers {
            worker.lock().await.shutdown().await;
        }
    }

    async fn shutdown_plugin(&self, plugin_id: &str) {
        let slots = {
            let mut workers = self.workers.lock().await;
            let keys = workers
                .keys()
                .filter(|key| key.plugin_id == plugin_id)
                .cloned()
                .collect::<Vec<_>>();
            keys.into_iter()
                .filter_map(|key| workers.remove(&key))
                .collect::<Vec<_>>()
        };
        let mut workers = Vec::new();
        for slot in slots {
            let mut state = slot.state.lock().await;
            if let WorkerSlotState::Ready(worker) = &*state {
                workers.push(Arc::clone(worker));
                decrement_saturating(&self.active_hosts);
            }
            *state = WorkerSlotState::Failed {
                retry_after: Instant::now() + HOST_RESTART_BACKOFF,
            };
        }
        for worker in workers {
            worker.lock().await.shutdown().await;
        }
    }
}

fn decrement_saturating(counter: &AtomicUsize) {
    let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
        Some(value.saturating_sub(1))
    });
}

async fn lock_before_deadline<'a, T>(
    mutex: &'a Mutex<T>,
    deadline: Instant,
) -> Option<MutexGuard<'a, T>> {
    timeout_at(deadline, mutex.lock()).await.ok()
}

fn configured_timeout(seconds: u64) -> Option<Duration> {
    (seconds > 0).then(|| Duration::from_secs(seconds.min(300)))
}

fn public_host_failure(error: &ControllerError) -> String {
    format!("native plugin host failed ({})", error.diagnostic_code())
}

type HostReader = Box<dyn AsyncRead + Unpin + Send>;
type HostWriter = Box<dyn AsyncWrite + Unpin + Send>;

struct PluginWorker {
    descriptor: PluginDescriptor,
    child: Child,
    writer: HostWriter,
    reader: HostReader,
    next_request_id: u64,
    #[cfg(windows)]
    _job: WindowsJob,
}

impl PluginWorker {
    async fn spawn(
        descriptor: PluginDescriptor,
        executable: &Path,
        plugin_trust: &PluginTrust,
    ) -> Result<Self, ControllerError> {
        let resolved_executable = if executable.is_absolute() {
            executable.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|source| ControllerError::Spawn {
                    executable: executable.to_path_buf(),
                    source,
                })?
                .join(executable)
        };
        let mut command = Command::new(&resolved_executable);
        command
            .arg("--plugin-id")
            .arg(&descriptor.plugin_id)
            .arg("--plugin-dir")
            .arg(&descriptor.plugin_dir);
        match plugin_trust {
            PluginTrust::Strict { trust_store } => {
                command.arg("--trust-store").arg(trust_store);
            }
            PluginTrust::AllowUnsigned => {
                command.arg("--allow-unsigned");
            }
        }
        #[cfg(windows)]
        let (pipe_name, pipe_server) = create_host_pipe()?;
        #[cfg(windows)]
        command
            .arg("--ipc-pipe")
            .arg(&pipe_name)
            .arg("--controller-pid")
            .arg(std::process::id().to_string())
            .creation_flags(CREATE_NO_WINDOW);

        command
            .current_dir(&descriptor.plugin_dir)
            .kill_on_drop(true);
        #[cfg(windows)]
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(not(windows))]
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let mut child = command.spawn().map_err(|source| ControllerError::Spawn {
            executable: resolved_executable.clone(),
            source,
        })?;
        #[cfg(windows)]
        let job = WindowsJob::assign(&child).map_err(|error| {
            let _ = child.start_kill();
            ControllerError::WindowsJob(error)
        })?;

        #[cfg(windows)]
        let (reader, writer): (HostReader, HostWriter) = {
            let child_id = child.id().ok_or_else(|| ControllerError::HostTransport {
                operation: "identify-child",
                message: "spawned host exited before transport setup".into(),
            })?;
            let connection = timeout(HOST_CONNECT_TIMEOUT, pipe_server.connect()).await;
            let connection_error = match connection {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(ControllerError::HostTransport {
                    operation: "connect",
                    message: error.to_string(),
                }),
                Err(_) => Some(ControllerError::HostTransport {
                    operation: "connect",
                    message: "host did not connect before the deadline".into(),
                }),
            };
            if let Some(error) = connection_error {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(error);
            }
            if let Err(error) = verify_named_pipe_client(&pipe_server, child_id) {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(error);
            }
            let (reader, writer) = tokio::io::split(pipe_server);
            (Box::new(reader), Box::new(writer))
        };
        #[cfg(not(windows))]
        let (reader, writer): (HostReader, HostWriter) = {
            let writer = child
                .stdin
                .take()
                .ok_or(ControllerError::MissingPipe("stdin"))?;
            let reader = child
                .stdout
                .take()
                .ok_or(ControllerError::MissingPipe("stdout"))?;
            (Box::new(reader), Box::new(writer))
        };
        let mut worker = Self {
            descriptor,
            child,
            writer,
            reader,
            next_request_id: 1,
            #[cfg(windows)]
            _job: job,
        };
        let plugin_id = worker.descriptor.plugin_id.clone();
        match timeout(HOST_START_TIMEOUT, worker.health()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                worker.kill().await;
                return Err(error);
            }
            Err(_) => {
                worker.kill().await;
                return Err(ControllerError::Timeout {
                    plugin_id,
                    timeout: HOST_START_TIMEOUT,
                });
            }
        }
        info!(
            event_code = "plugin-host-started",
            plugin_id = worker.descriptor.plugin_id,
            architecture = ?worker.descriptor.architecture,
            "plugin host started"
        );
        Ok(worker)
    }

    async fn health(&mut self) -> Result<(), ControllerError> {
        let request_id = self.take_request_id();
        write_frame_async(
            &mut self.writer,
            &HostRequest::new(request_id, HostCommand::Health),
        )
        .await?;
        let response: HostResponse = read_frame_async(&mut self.reader)
            .await?
            .ok_or_else(|| ControllerError::HostExited(self.descriptor.plugin_id.clone()))?;
        match validate_payload(request_id, response)? {
            HostPayload::Health { plugin_id } if plugin_id == self.descriptor.plugin_id => Ok(()),
            payload => Err(ControllerError::UnexpectedPayload(format!("{payload:?}"))),
        }
    }

    async fn invoke(&mut self, request: InvokeRequest) -> Result<InvokeResponse, ControllerError> {
        let request_id = self.take_request_id();
        let message = HostRequest::new(
            request_id,
            HostCommand::Invoke {
                plugin_id: self.descriptor.plugin_id.clone(),
                request,
            },
        );
        write_frame_async(&mut self.writer, &message).await?;
        let response: HostResponse = read_frame_async(&mut self.reader)
            .await?
            .ok_or_else(|| ControllerError::HostExited(self.descriptor.plugin_id.clone()))?;
        validate_response(request_id, response)
    }

    fn take_request_id(&mut self) -> u64 {
        let current = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        current
    }

    async fn shutdown(&mut self) {
        let request_id = self.take_request_id();
        let _ = write_frame_async(
            &mut self.writer,
            &HostRequest::new(request_id, HostCommand::Shutdown),
        )
        .await;
        if !matches!(
            timeout(Duration::from_secs(2), self.child.wait()).await,
            Ok(Ok(_))
        ) {
            self.kill().await;
        }
    }

    async fn kill(&mut self) {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
    }
}

fn validate_response(
    expected_request_id: u64,
    response: HostResponse,
) -> Result<InvokeResponse, ControllerError> {
    match validate_payload(expected_request_id, response)? {
        HostPayload::Invoke { response } => Ok(response),
        payload => Err(ControllerError::UnexpectedPayload(format!("{payload:?}"))),
    }
}

fn validate_payload(
    expected_request_id: u64,
    response: HostResponse,
) -> Result<HostPayload, ControllerError> {
    if response.protocol_version != HOST_PROTOCOL_VERSION {
        return Err(ControllerError::ProtocolVersion {
            expected: HOST_PROTOCOL_VERSION,
            actual: response.protocol_version,
        });
    }
    if response.request_id != expected_request_id {
        return Err(ControllerError::RequestId {
            expected: expected_request_id,
            actual: response.request_id,
        });
    }
    match response.result {
        HostResult::Ok { payload } => Ok(payload),
        HostResult::Error { error } => Err(ControllerError::HostError {
            code: error.code,
            message: error.message,
        }),
    }
}

#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("max_in_flight_invocations must be between 1 and {maximum}, got {actual}")]
    InvalidInvocationLimit { actual: usize, maximum: usize },
    #[error("serviceId must not be empty")]
    EmptyServiceId,
    #[error("plugin ID must not be empty")]
    EmptyPluginId,
    #[error("service [{0}] is already routed to a different plugin")]
    DuplicateService(String),
    #[error("service [{0}] is not active for plugin host preflight")]
    PreflightRouteMismatch(String),
    #[error("plugin host candidate preflight is unavailable during reload or shutdown")]
    PreflightUnavailable,
    #[error("plugin maintenance is unavailable during global reload or shutdown")]
    MaintenanceUnavailable,
    #[error("plugin maintenance for [{expected}] cannot install manifest [{actual}]")]
    MaintenancePluginMismatch { expected: String, actual: String },
    #[error("plugin host [{0}] initialization failed in another concurrent request")]
    HostInitializationFailed(String),
    #[error("failed to spawn plugin host {executable:?}: {source}")]
    Spawn {
        executable: PathBuf,
        source: std::io::Error,
    },
    #[error("plugin host did not expose {0}")]
    MissingPipe(&'static str),
    #[error("plugin host [{0}] exited without a response")]
    HostExited(String),
    #[error("plugin host [{plugin_id}] timed out after {timeout:?}")]
    Timeout {
        plugin_id: String,
        timeout: Duration,
    },
    #[error("plugin host [{plugin_id}] execution lane stayed busy for {timeout:?}")]
    ExecutionLaneTimeout {
        plugin_id: String,
        timeout: Duration,
    },
    #[error("IPC framing failed: {0}")]
    Frame(#[from] FrameError),
    #[error("protocol version mismatch: expected {expected}, got {actual}")]
    ProtocolVersion { expected: u16, actual: u16 },
    #[error("request ID mismatch: expected {expected}, got {actual}")]
    RequestId { expected: u64, actual: u64 },
    #[error("plugin host returned unexpected payload: {0}")]
    UnexpectedPayload(String),
    #[error("plugin host error {code}: {message}")]
    HostError { code: String, message: String },
    #[cfg(windows)]
    #[error("failed to contain plugin host in a Windows Job Object: {0}")]
    WindowsJob(String),
    #[cfg(windows)]
    #[error("plugin host transport failed during {operation}: {message}")]
    HostTransport {
        operation: &'static str,
        message: String,
    },
}

impl ControllerError {
    pub fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::InvalidInvocationLimit { .. } => "invalid-invocation-limit",
            Self::EmptyServiceId => "empty-service-id",
            Self::EmptyPluginId => "empty-plugin-id",
            Self::DuplicateService(_) => "duplicate-service",
            Self::PreflightRouteMismatch(_) => "preflight-route-mismatch",
            Self::PreflightUnavailable => "preflight-unavailable",
            Self::MaintenanceUnavailable => "maintenance-unavailable",
            Self::MaintenancePluginMismatch { .. } => "maintenance-plugin-mismatch",
            Self::HostInitializationFailed(_) => "host-initialization-failed",
            Self::Spawn { .. } => "host-spawn-failed",
            Self::MissingPipe(_) => "host-pipe-missing",
            Self::HostExited(_) => "host-exited",
            Self::Timeout { .. } => "host-timeout",
            Self::ExecutionLaneTimeout { .. } => "execution-lane-timeout",
            Self::Frame(_) => "ipc-frame-failed",
            Self::ProtocolVersion { .. } => "protocol-version-mismatch",
            Self::RequestId { .. } => "request-id-mismatch",
            Self::UnexpectedPayload(_) => "unexpected-host-payload",
            Self::HostError { .. } => "native-host-error",
            #[cfg(windows)]
            Self::WindowsJob(_) => "windows-job-failed",
            #[cfg(windows)]
            Self::HostTransport { .. } => "host-transport-failed",
        }
    }
}

#[cfg(windows)]
fn create_host_pipe(
) -> Result<(String, tokio::net::windows::named_pipe::NamedPipeServer), ControllerError> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let name = format!(
        r"\\.\pipe\ssdev-webplus-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    );
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .max_instances(1)
        .create(&name)
        .map_err(|error| ControllerError::HostTransport {
            operation: "create",
            message: error.to_string(),
        })?;
    Ok((name, server))
}

#[cfg(windows)]
fn verify_named_pipe_client(
    server: &tokio::net::windows::named_pipe::NamedPipeServer,
    expected_process_id: u32,
) -> Result<(), ControllerError> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;

    let mut actual_process_id = 0;
    let handle = HANDLE(server.as_raw_handle());
    unsafe { GetNamedPipeClientProcessId(handle, &mut actual_process_id) }.map_err(|error| {
        ControllerError::HostTransport {
            operation: "authenticate-client",
            message: error.to_string(),
        }
    })?;
    if actual_process_id != expected_process_id {
        return Err(ControllerError::HostTransport {
            operation: "authenticate-client",
            message: "named-pipe client is not the spawned plugin host".into(),
        });
    }
    Ok(())
}

#[cfg(windows)]
struct WindowsJob {
    _handle: windows::core::Owned<windows::Win32::Foundation::HANDLE>,
}

// Windows Job Object handles are kernel handles and may be closed from any thread.
#[cfg(windows)]
unsafe impl Send for WindowsJob {}

#[cfg(windows)]
impl WindowsJob {
    fn assign(child: &Child) -> Result<Self, String> {
        use std::mem::size_of;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        let handle = unsafe { CreateJobObjectW(None, None) }.map_err(|error| error.to_string())?;
        let owned = unsafe { windows::core::Owned::new(handle) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        unsafe {
            SetInformationJobObject(
                *owned,
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        }
        .map_err(|error| error.to_string())?;
        let process = HANDLE(
            child
                .raw_handle()
                .ok_or_else(|| "spawned plugin host has no process handle".to_owned())?,
        );
        unsafe { AssignProcessToJobObject(*owned, process) }.map_err(|error| error.to_string())?;
        Ok(Self { _handle: owned })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Map;
    use std::fs;
    use tempfile::tempdir;

    fn config() -> SupervisorConfig {
        SupervisorConfig {
            x86_host: "missing-x86-host".into(),
            x64_host: "missing-x64-host".into(),
            request_timeout: Duration::from_secs(1),
            max_in_flight_invocations: DEFAULT_MAX_IN_FLIGHT_INVOCATIONS,
            plugin_trust: PluginTrust::AllowUnsigned,
        }
    }

    #[tokio::test]
    async fn missing_service_is_a_legacy_shaped_response() {
        let controller = Arc::new(PluginController::new(config()).unwrap());
        let response = controller
            .invoke(InvokeRequest {
                service_id: "missing".into(),
                method: "read".into(),
                parameters: Map::new(),
            })
            .await;

        assert_eq!(response.res_code, SERVICE_NOT_FOUND);
        assert!(response.res_data.as_str().unwrap().contains("missing"));
    }

    #[test]
    fn invocation_admission_limit_must_be_explicitly_bounded() {
        for invalid in [0, MAX_IN_FLIGHT_INVOCATIONS_LIMIT + 1] {
            let mut config = config();
            config.max_in_flight_invocations = invalid;
            assert!(matches!(
                PluginController::new(config),
                Err(ControllerError::InvalidInvocationLimit { actual, .. }) if actual == invalid
            ));
        }
    }

    #[tokio::test]
    async fn saturated_controller_rejects_without_queuing_more_work() {
        let mut config = config();
        config.max_in_flight_invocations = 1;
        let controller = Arc::new(PluginController::new(config).unwrap());
        let permit = controller.admission.try_acquire().unwrap();
        assert_eq!(
            controller.invocation_admission_stats(),
            InvocationAdmissionStats {
                max_in_flight: 1,
                in_flight: 1,
                rejected: 0,
                caller_detachments: 0,
                shutdown_rejections: 0,
                execution_lane_timeouts: 0,
                maintenance_rejections: 0,
                maintenance_active: false,
                global_maintenance_active: false,
                active_plugin_maintenances: 0,
                accepting: true,
            }
        );

        let response = controller
            .invoke(InvokeRequest {
                service_id: "missing".into(),
                method: "read".into(),
                parameters: Map::new(),
            })
            .await;
        assert_eq!(response.res_code, SERVER_BUSY);
        assert_eq!(
            response.res_data.as_str(),
            Some("native plugin invocation capacity is busy; retry later")
        );
        assert_eq!(controller.invocation_admission_stats().rejected, 1);

        drop(permit);
        let response = controller
            .invoke(InvokeRequest {
                service_id: "missing".into(),
                method: "read".into(),
                parameters: Map::new(),
            })
            .await;
        assert_eq!(response.res_code, SERVICE_NOT_FOUND);
        assert_eq!(controller.invocation_admission_stats().in_flight, 0);
    }

    #[tokio::test]
    async fn caller_cancellation_detaches_waiter_without_canceling_admitted_work() {
        let controller = Arc::new(PluginController::new(config()).unwrap());
        let invoke_controller = Arc::clone(&controller);
        let lifecycle = controller.lifecycle.write().await;
        let caller = tokio::spawn(async move {
            invoke_controller
                .invoke(InvokeRequest {
                    service_id: "missing".into(),
                    method: "read".into(),
                    parameters: Map::new(),
                })
                .await
        });

        timeout(Duration::from_secs(1), async {
            while controller.invocation_admission_stats().in_flight != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert_eq!(
            controller.invocation_admission_stats().caller_detachments,
            1
        );
        assert_eq!(controller.invocation_admission_stats().in_flight, 1);

        drop(lifecycle);
        timeout(Duration::from_secs(1), async {
            while controller.invocation_admission_stats().in_flight != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            controller.invocation_admission_stats().caller_detachments,
            1
        );
    }

    #[tokio::test]
    async fn shutdown_rejects_racing_work_before_it_reaches_a_plugin() {
        let controller = Arc::new(PluginController::new(config()).unwrap());
        let invoke_controller = Arc::clone(&controller);
        let lifecycle = controller.lifecycle.write().await;
        let caller = tokio::spawn(async move {
            invoke_controller
                .invoke(InvokeRequest {
                    service_id: "missing".into(),
                    method: "read".into(),
                    parameters: Map::new(),
                })
                .await
        });
        timeout(Duration::from_secs(1), async {
            while controller.invocation_admission_stats().in_flight != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let shutdown_controller = Arc::clone(&controller);
        let shutdown = tokio::spawn(async move { shutdown_controller.shutdown().await });
        timeout(Duration::from_secs(1), async {
            while controller.invocation_admission_stats().accepting {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(lifecycle);

        let response = caller.await.unwrap();
        assert_eq!(response.res_code, CONTROLLER_STOPPING);
        assert_eq!(
            response.res_data.as_str(),
            Some("native plugin controller is stopping; request was not executed")
        );
        shutdown.await.unwrap();
        let stats = controller.invocation_admission_stats();
        assert_eq!(stats.in_flight, 0);
        assert_eq!(stats.shutdown_rejections, 1);
        assert!(!stats.accepting);

        controller.resume_after_shutdown().await;
        assert!(controller.invocation_admission_stats().accepting);
        let response = controller
            .invoke(InvokeRequest {
                service_id: "missing".into(),
                method: "read".into(),
                parameters: Map::new(),
            })
            .await;
        assert_eq!(response.res_code, SERVICE_NOT_FOUND);
    }

    #[tokio::test]
    async fn maintenance_rejects_new_work_without_consuming_admission_capacity() {
        let controller = Arc::new(PluginController::new(config()).unwrap());
        let maintenance = controller.begin_maintenance().await;
        assert!(controller.invocation_admission_stats().maintenance_active);

        let response = controller
            .invoke(InvokeRequest {
                service_id: "missing".into(),
                method: "read".into(),
                parameters: Map::new(),
            })
            .await;

        assert_eq!(response.res_code, CONTROLLER_MAINTENANCE);
        assert_eq!(
            response.res_data.as_str(),
            Some("native plugin controller is reloading; request was not executed")
        );
        let stats = controller.invocation_admission_stats();
        assert_eq!(stats.in_flight, 0);
        assert_eq!(stats.maintenance_rejections, 1);

        drop(maintenance);
        assert!(!controller.invocation_admission_stats().maintenance_active);
        let response = controller
            .invoke(InvokeRequest {
                service_id: "missing".into(),
                method: "read".into(),
                parameters: Map::new(),
            })
            .await;
        assert_eq!(response.res_code, SERVICE_NOT_FOUND);
    }

    #[tokio::test]
    async fn pending_maintenance_rejects_immediately_and_cancellation_restores_running_state() {
        let controller = Arc::new(PluginController::new(config()).unwrap());
        let lifecycle_reader = controller.lifecycle.read().await;
        let maintenance_controller = Arc::clone(&controller);
        let maintenance = tokio::spawn(async move {
            let _maintenance = maintenance_controller.begin_maintenance().await;
            std::future::pending::<()>().await;
        });
        timeout(Duration::from_secs(1), async {
            while !controller.invocation_admission_stats().maintenance_active {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let response = controller
            .invoke(InvokeRequest {
                service_id: "missing".into(),
                method: "read".into(),
                parameters: Map::new(),
            })
            .await;
        assert_eq!(response.res_code, CONTROLLER_MAINTENANCE);
        assert_eq!(controller.invocation_admission_stats().in_flight, 0);

        maintenance.abort();
        assert!(maintenance.await.unwrap_err().is_cancelled());
        assert!(!controller.invocation_admission_stats().maintenance_active);
        drop(lifecycle_reader);

        let response = controller
            .invoke(InvokeRequest {
                service_id: "missing".into(),
                method: "read".into(),
                parameters: Map::new(),
            })
            .await;
        assert_eq!(response.res_code, SERVICE_NOT_FOUND);
    }

    #[tokio::test]
    async fn invocation_cannot_cross_a_maintenance_generation() {
        let controller = Arc::new(PluginController::new(config()).unwrap());
        let invoke_controller = Arc::clone(&controller);
        let lifecycle = controller.lifecycle.write().await;
        let caller = tokio::spawn(async move {
            invoke_controller
                .invoke(InvokeRequest {
                    service_id: "missing".into(),
                    method: "read".into(),
                    parameters: Map::new(),
                })
                .await
        });
        timeout(Duration::from_secs(1), async {
            while controller.invocation_admission_stats().in_flight != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        controller.lifecycle_epoch.fetch_add(1, Ordering::AcqRel);
        drop(lifecycle);

        let response = caller.await.unwrap();
        assert_eq!(response.res_code, CONTROLLER_MAINTENANCE);
        assert_eq!(controller.invocation_admission_stats().in_flight, 0);
        assert_eq!(
            controller
                .invocation_admission_stats()
                .maintenance_rejections,
            1
        );
    }

    #[test]
    fn manifest_timeouts_are_bounded_for_process_isolation() {
        assert_eq!(configured_timeout(0), None);
        assert_eq!(configured_timeout(15), Some(Duration::from_secs(15)));
        assert_eq!(configured_timeout(900), Some(Duration::from_secs(300)));
    }

    #[tokio::test]
    async fn execution_lane_wait_obeys_the_shared_request_deadline() {
        let lane = Mutex::new(());
        let held = lane.lock().await;

        assert!(
            lock_before_deadline(&lane, Instant::now() + Duration::from_millis(20))
                .await
                .is_none()
        );

        drop(held);
        assert!(
            lock_before_deadline(&lane, Instant::now() + Duration::from_secs(1))
                .await
                .is_some()
        );
    }

    #[test]
    fn execution_lane_timeout_is_distinct_and_guarantees_no_execution() {
        let controller = PluginController::new(config()).unwrap();
        let response = controller.host_failure_response(&ControllerError::ExecutionLaneTimeout {
            plugin_id: "busy-plugin".into(),
            timeout: Duration::from_secs(1),
        });

        assert_eq!(response.res_code, EXECUTION_LANE_TIMEOUT);
        assert_eq!(
            response.res_data.as_str(),
            Some("native plugin execution lane timed out; request was not executed")
        );
        assert_eq!(
            controller
                .invocation_admission_stats()
                .execution_lane_timeouts,
            1
        );
    }

    #[tokio::test]
    async fn conflicting_routes_are_rejected() {
        let controller = PluginController::new(config()).unwrap();
        controller
            .register_service(
                "reader",
                PluginDescriptor {
                    plugin_id: "plugin-a".into(),
                    plugin_dir: "plugins/plugin-a".into(),
                    architecture: PluginArchitecture::X86,
                },
            )
            .await
            .unwrap();
        let error = controller
            .register_service(
                "reader",
                PluginDescriptor {
                    plugin_id: "plugin-b".into(),
                    plugin_dir: "plugins/plugin-b".into(),
                    architecture: PluginArchitecture::X86,
                },
            )
            .await
            .unwrap_err();

        assert!(matches!(error, ControllerError::DuplicateService(_)));
    }

    #[test]
    fn response_correlation_is_enforced() {
        let error = validate_response(
            7,
            HostResponse::ok(
                8,
                HostPayload::Invoke {
                    response: InvokeResponse::success("ok"),
                },
            ),
        )
        .unwrap_err();

        assert!(matches!(error, ControllerError::RequestId { .. }));
    }

    #[test]
    fn diagnostic_codes_do_not_expose_native_host_details() {
        let error = ControllerError::HostError {
            code: "vendor-secret-code".into(),
            message: "patient-name-and-path".into(),
        };

        assert_eq!(error.diagnostic_code(), "native-host-error");
        assert!(!error.diagnostic_code().contains("vendor"));
        assert!(!error.diagnostic_code().contains("patient"));
        let public = public_host_failure(&error);
        assert_eq!(public, "native plugin host failed (native-host-error)");
        assert!(!public.contains("vendor"));
        assert!(!public.contains("patient"));
    }

    #[test]
    fn worker_identity_includes_architecture() {
        let x86 = WorkerKey::from(&PluginDescriptor {
            plugin_id: "mixed".into(),
            plugin_dir: "plugins/mixed".into(),
            architecture: PluginArchitecture::X86,
        });
        let x64 = WorkerKey::from(&PluginDescriptor {
            plugin_id: "mixed".into(),
            plugin_dir: "plugins/mixed".into(),
            architecture: PluginArchitecture::X64,
        });

        assert_ne!(x86, x64);
    }

    #[test]
    fn preflight_starts_one_host_per_plugin_architecture() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join("api.json"),
            r#"[
              {"serviceId":"x86-a","mainClass":"a.dll","architecture":"x86"},
              {"serviceId":"x86-b","mainClass":"b.dll","architecture":"x86"},
              {"serviceId":"x64-a","mainClass":"c.dll","architecture":"x64"}
            ]"#,
        )
        .unwrap();
        let manifest = PluginManifest::load("mixed-plugin", root.path()).unwrap();

        let descriptors = preflight_descriptors(&manifest);

        assert_eq!(descriptors.len(), 2);
        assert_eq!(descriptors[0].architecture, PluginArchitecture::X86);
        assert_eq!(descriptors[1].architecture, PluginArchitecture::X64);
    }

    #[tokio::test]
    async fn preflight_rejects_a_manifest_that_is_not_the_active_route_set() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join("api.json"),
            r#"{"serviceId":"candidate","mainClass":"reader.dll"}"#,
        )
        .unwrap();
        let manifest = PluginManifest::load("candidate-plugin", root.path()).unwrap();
        let controller = PluginController::new(config()).unwrap();
        let maintenance = controller.begin_maintenance().await;

        let failure = maintenance.preflight_manifest(&manifest).await.unwrap_err();

        assert!(matches!(
            failure,
            ControllerError::PreflightRouteMismatch(service) if service == "candidate"
        ));
    }

    #[tokio::test]
    async fn candidate_preflight_uses_staging_without_requiring_an_active_route() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join("api.json"),
            r#"{"serviceId":"candidate","mainClass":"reader.dll"}"#,
        )
        .unwrap();
        let manifest = PluginManifest::load("candidate-plugin", root.path()).unwrap();
        let controller = PluginController::new(config()).unwrap();

        let failure = controller
            .preflight_candidate_manifest(&manifest)
            .await
            .unwrap_err();

        assert!(matches!(failure, ControllerError::Spawn { .. }));
        assert_eq!(controller.service_count().await, 0);
        assert_eq!(controller.plugin_host_stats().failed_starts, 1);
    }

    #[tokio::test]
    async fn candidate_preflight_cannot_cross_an_active_maintenance_boundary() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join("api.json"),
            r#"{"serviceId":"candidate","mainClass":"reader.dll"}"#,
        )
        .unwrap();
        let manifest = PluginManifest::load("candidate-plugin", root.path()).unwrap();
        let controller = PluginController::new(config()).unwrap();
        let maintenance = controller.begin_maintenance().await;

        let failure = controller
            .preflight_candidate_manifest(&manifest)
            .await
            .unwrap_err();

        assert!(matches!(failure, ControllerError::PreflightUnavailable));
        assert_eq!(controller.plugin_host_stats().failed_starts, 0);
        drop(maintenance);
    }

    #[tokio::test]
    async fn scoped_maintenance_rejects_only_the_selected_plugin() {
        let root = tempdir().unwrap();
        let plugin_a = root.path().join("plugin-a");
        let plugin_b = root.path().join("plugin-b");
        fs::create_dir_all(&plugin_a).unwrap();
        fs::create_dir_all(&plugin_b).unwrap();
        fs::write(
            plugin_a.join("api.json"),
            r#"{"serviceId":"service-a","mainClass":"a.dll"}"#,
        )
        .unwrap();
        fs::write(
            plugin_b.join("api.json"),
            r#"{"serviceId":"service-b","mainClass":"b.dll"}"#,
        )
        .unwrap();
        let manifest_a = PluginManifest::load("plugin-a", &plugin_a).unwrap();
        let manifest_b = PluginManifest::load("plugin-b", &plugin_b).unwrap();
        let controller = Arc::new(PluginController::new(config()).unwrap());
        controller
            .replace_manifests(&[manifest_a, manifest_b])
            .await
            .unwrap();

        let maintenance = controller
            .begin_plugin_maintenance("plugin-a")
            .await
            .unwrap();
        assert!(controller.invocation_admission_stats().maintenance_active);

        let selected = controller
            .invoke(InvokeRequest {
                service_id: "service-a".into(),
                method: "read".into(),
                parameters: Map::new(),
            })
            .await;
        assert_eq!(selected.res_code, CONTROLLER_MAINTENANCE);
        assert_eq!(controller.invocation_admission_stats().in_flight, 0);

        let unrelated = controller
            .invoke(InvokeRequest {
                service_id: "service-b".into(),
                method: "read".into(),
                parameters: Map::new(),
            })
            .await;
        assert_eq!(unrelated.res_code, HOST_FAILURE);
        assert_eq!(controller.plugin_host_stats().failed_starts, 1);

        drop(maintenance);
        assert!(!controller.invocation_admission_stats().maintenance_active);
    }

    #[tokio::test]
    async fn scoped_maintenance_replaces_only_target_routes_atomically() {
        let root = tempdir().unwrap();
        let old_a = root.path().join("old-a");
        let new_a = root.path().join("new-a");
        let plugin_b = root.path().join("plugin-b");
        for directory in [&old_a, &new_a, &plugin_b] {
            fs::create_dir_all(directory).unwrap();
        }
        fs::write(
            old_a.join("api.json"),
            r#"{"serviceId":"old-a","mainClass":"old.dll"}"#,
        )
        .unwrap();
        fs::write(
            new_a.join("api.json"),
            r#"{"serviceId":"new-a","mainClass":"new.dll"}"#,
        )
        .unwrap();
        fs::write(
            plugin_b.join("api.json"),
            r#"{"serviceId":"service-b","mainClass":"b.dll"}"#,
        )
        .unwrap();
        let old_manifest = PluginManifest::load("plugin-a", old_a).unwrap();
        let new_manifest = PluginManifest::load("plugin-a", new_a.clone()).unwrap();
        let manifest_b = PluginManifest::load("plugin-b", plugin_b.clone()).unwrap();
        let controller = PluginController::new(config()).unwrap();
        controller
            .replace_manifests(&[old_manifest, manifest_b])
            .await
            .unwrap();

        let maintenance = controller
            .begin_plugin_maintenance("plugin-a")
            .await
            .unwrap();
        maintenance
            .replace_manifest(Some(&new_manifest))
            .await
            .unwrap();

        let routes = controller.routes.read().await;
        assert!(!routes.contains_key("old-a"));
        assert_eq!(routes["new-a"].descriptor.plugin_dir, new_a);
        assert_eq!(routes["service-b"].descriptor.plugin_dir, plugin_b);
        assert_eq!(routes.len(), 2);
        drop(routes);
        drop(maintenance);
    }

    #[tokio::test]
    async fn scoped_route_collision_preserves_the_previous_route_set() {
        let root = tempdir().unwrap();
        let plugin_a = root.path().join("plugin-a");
        let replacement_a = root.path().join("replacement-a");
        let plugin_b = root.path().join("plugin-b");
        for directory in [&plugin_a, &replacement_a, &plugin_b] {
            fs::create_dir_all(directory).unwrap();
        }
        fs::write(
            plugin_a.join("api.json"),
            r#"{"serviceId":"service-a","mainClass":"a.dll"}"#,
        )
        .unwrap();
        fs::write(
            replacement_a.join("api.json"),
            r#"{"serviceId":"service-b","mainClass":"collision.dll"}"#,
        )
        .unwrap();
        fs::write(
            plugin_b.join("api.json"),
            r#"{"serviceId":"service-b","mainClass":"b.dll"}"#,
        )
        .unwrap();
        let manifest_a = PluginManifest::load("plugin-a", plugin_a).unwrap();
        let replacement = PluginManifest::load("plugin-a", replacement_a).unwrap();
        let manifest_b = PluginManifest::load("plugin-b", plugin_b).unwrap();
        let controller = PluginController::new(config()).unwrap();
        controller
            .replace_manifests(&[manifest_a, manifest_b])
            .await
            .unwrap();
        let maintenance = controller
            .begin_plugin_maintenance("plugin-a")
            .await
            .unwrap();

        let failure = maintenance
            .replace_manifest(Some(&replacement))
            .await
            .unwrap_err();

        assert!(matches!(
            failure,
            ControllerError::DuplicateService(service) if service == "service-b"
        ));
        let routes = controller.routes.read().await;
        assert_eq!(routes["service-a"].descriptor.plugin_id, "plugin-a");
        assert_eq!(routes["service-b"].descriptor.plugin_id, "plugin-b");
        assert_eq!(routes.len(), 2);
    }

    #[tokio::test]
    async fn cancelled_scoped_maintenance_restores_target_admission() {
        let controller = Arc::new(PluginController::new(config()).unwrap());
        let plugin_lifecycle = controller.plugin_lifecycle("plugin-a").await;
        let lifecycle_reader = plugin_lifecycle.lifecycle.read().await;
        let maintenance_controller = Arc::clone(&controller);
        let maintenance = tokio::spawn(async move {
            let _maintenance = maintenance_controller
                .begin_plugin_maintenance("plugin-a")
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });
        timeout(Duration::from_secs(1), async {
            while !controller.invocation_admission_stats().maintenance_active {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        maintenance.abort();
        assert!(maintenance.await.unwrap_err().is_cancelled());
        assert!(!controller.invocation_admission_stats().maintenance_active);
        assert!(!plugin_lifecycle.maintenance_active.load(Ordering::Acquire));
        drop(lifecycle_reader);

        controller
            .begin_plugin_maintenance("plugin-a")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn invocation_cannot_cross_a_scoped_maintenance_generation() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join("api.json"),
            r#"{"serviceId":"service-a","mainClass":"a.dll"}"#,
        )
        .unwrap();
        let manifest = PluginManifest::load("plugin-a", root.path()).unwrap();
        let controller = Arc::new(PluginController::new(config()).unwrap());
        controller.replace_manifests(&[manifest]).await.unwrap();
        let plugin_lifecycle = controller.plugin_lifecycle("plugin-a").await;
        let lifecycle_writer = plugin_lifecycle.lifecycle.write().await;

        let invoke_controller = Arc::clone(&controller);
        let invocation = tokio::spawn(async move {
            invoke_controller
                .invoke(InvokeRequest {
                    service_id: "service-a".into(),
                    method: "read".into(),
                    parameters: Map::new(),
                })
                .await
        });
        timeout(Duration::from_secs(1), async {
            while controller.invocation_admission_stats().in_flight != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let maintenance_controller = Arc::clone(&controller);
        let maintenance = tokio::spawn(async move {
            let _maintenance = maintenance_controller
                .begin_plugin_maintenance("plugin-a")
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });
        timeout(Duration::from_secs(1), async {
            while !plugin_lifecycle.maintenance_active.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(lifecycle_writer);

        let response = invocation.await.unwrap();
        assert_eq!(response.res_code, CONTROLLER_MAINTENANCE);
        assert_eq!(controller.plugin_host_stats().failed_starts, 0);
        assert_eq!(controller.invocation_admission_stats().in_flight, 0);
        maintenance.abort();
        assert!(maintenance.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn candidate_preflight_is_scoped_to_the_plugin_maintenance_boundary() {
        let root = tempdir().unwrap();
        let plugin_a = root.path().join("plugin-a");
        let plugin_b = root.path().join("plugin-b");
        fs::create_dir_all(&plugin_a).unwrap();
        fs::create_dir_all(&plugin_b).unwrap();
        fs::write(
            plugin_a.join("api.json"),
            r#"{"serviceId":"service-a","mainClass":"a.dll"}"#,
        )
        .unwrap();
        fs::write(
            plugin_b.join("api.json"),
            r#"{"serviceId":"service-b","mainClass":"b.dll"}"#,
        )
        .unwrap();
        let manifest_a = PluginManifest::load("plugin-a", plugin_a).unwrap();
        let manifest_b = PluginManifest::load("plugin-b", plugin_b).unwrap();
        let controller = PluginController::new(config()).unwrap();
        let maintenance = controller
            .begin_plugin_maintenance("plugin-a")
            .await
            .unwrap();

        let selected = controller
            .preflight_candidate_manifest(&manifest_a)
            .await
            .unwrap_err();
        assert!(matches!(selected, ControllerError::PreflightUnavailable));
        assert_eq!(controller.plugin_host_stats().failed_starts, 0);

        let unrelated = controller
            .preflight_candidate_manifest(&manifest_b)
            .await
            .unwrap_err();
        assert!(matches!(unrelated, ControllerError::Spawn { .. }));
        assert_eq!(controller.plugin_host_stats().failed_starts, 1);
        drop(maintenance);
    }

    #[tokio::test]
    async fn failed_host_initialization_is_single_flight_and_backed_off() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join("api.json"),
            r#"{"serviceId":"unavailable","mainClass":"reader.dll","methods":[{"name":"probe"}]}"#,
        )
        .unwrap();
        let manifest = PluginManifest::load("unavailable-plugin", root.path()).unwrap();
        let controller = Arc::new(PluginController::new(config()).unwrap());
        controller
            .replace_manifests(std::slice::from_ref(&manifest))
            .await
            .unwrap();

        let mut calls = tokio::task::JoinSet::new();
        for _ in 0..DEFAULT_MAX_IN_FLIGHT_INVOCATIONS {
            let controller = Arc::clone(&controller);
            calls.spawn(async move {
                controller
                    .invoke(InvokeRequest {
                        service_id: "unavailable".into(),
                        method: "probe".into(),
                        parameters: Map::new(),
                    })
                    .await
            });
        }
        while let Some(response) = calls.join_next().await {
            assert_eq!(response.unwrap().res_code, HOST_FAILURE);
        }
        assert_eq!(controller.plugin_host_stats().failed_starts, 1);

        let immediate = controller
            .invoke(InvokeRequest {
                service_id: "unavailable".into(),
                method: "probe".into(),
                parameters: Map::new(),
            })
            .await;
        assert_eq!(immediate.res_code, HOST_FAILURE);
        assert_eq!(controller.plugin_host_stats().failed_starts, 1);

        tokio::time::sleep(HOST_RESTART_BACKOFF + Duration::from_millis(50)).await;
        let retried = controller
            .invoke(InvokeRequest {
                service_id: "unavailable".into(),
                method: "probe".into(),
                parameters: Map::new(),
            })
            .await;
        assert_eq!(retried.res_code, HOST_FAILURE);
        assert_eq!(controller.plugin_host_stats().failed_starts, 2);
        assert_eq!(controller.plugin_host_stats().active_hosts, 0);
    }

    #[test]
    fn replacement_manifest_set_rejects_cross_plugin_service_collisions() {
        let root = tempdir().unwrap();
        let mut manifests = Vec::new();
        for plugin_id in ["plugin-a", "plugin-b"] {
            let directory = root.path().join(plugin_id);
            fs::create_dir_all(&directory).unwrap();
            fs::write(
                directory.join("api.json"),
                r#"{"serviceId":"shared","mainClass":"reader.dll"}"#,
            )
            .unwrap();
            manifests.push(PluginManifest::load(plugin_id, directory).unwrap());
        }

        assert!(matches!(
            PluginController::validate_manifests(&manifests),
            Err(ControllerError::DuplicateService(service)) if service == "shared"
        ));
    }

    #[tokio::test]
    async fn maintenance_replaces_routes_as_one_set() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join("api.json"),
            r#"{"serviceId":"replacement","mainClass":"reader.dll"}"#,
        )
        .unwrap();
        let manifest = PluginManifest::load("replacement-plugin", root.path()).unwrap();
        let controller = PluginController::new(config()).unwrap();

        controller.replace_manifests(&[manifest]).await.unwrap();

        assert_eq!(controller.service_count().await, 1);
    }
}
