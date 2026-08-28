mod app_update;
#[cfg(any(windows, target_os = "macos"))]
mod capture;
#[cfg(not(any(windows, target_os = "macos")))]
#[path = "capture_unsupported.rs"]
mod capture;
mod com_discovery;
#[allow(dead_code)]
// The shared build/runtime ACL declaration intentionally has target-specific subsets.
mod command_permissions;
mod deployment_check;
mod desktop;
mod invocations;
mod local_mappings;
mod project_activation;
mod shortcuts;
mod sso;

/// Version of the public API injected into authorized business WebViews.
/// It must evolve independently from the private plugin-host wire protocol.
pub const BRIDGE_PROTOCOL_VERSION: u16 = 1;
const DESKTOP_CAPABILITIES_SCHEMA_VERSION: u16 = 1;

#[doc(hidden)]
pub use app_update::verify_update_artifact_files;

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use serde::Serialize;
use sha2::{Digest, Sha256};
use ssdev_config::ConfigStore;
use ssdev_diagnostics::{DiagnosticContext, DiagnosticsState, DiagnosticsStats};
use ssdev_invocation_ledger::{
    COMPLETED_OPERATION_RETENTION, INDETERMINATE_OPERATION_RETENTION, MAX_DURABLE_OPERATIONS,
    MAX_DURABLE_OPERATIONS_PER_SCOPE,
};
use ssdev_origin_policy::{OriginPolicy, OriginPolicySummary};
use ssdev_process_policy::ProcessPolicy;
use ssdev_project_bundle as project_bundle;
use tauri::{AppHandle, Manager, State, WebviewWindow};
use tauri_plugin_autostart::MacosLauncher;
use tauri_plugin_dialog::{DialogExt, MessageDialogKind};
use tauri_plugin_global_shortcut::Builder as ShortcutBuilder;
use tauri_plugin_opener::OpenerExt;
use webplus_controller::{
    PluginController, PluginTrust, SupervisorConfig, DEFAULT_MAX_IN_FLIGHT_INVOCATIONS,
};
use webplus_plugin_config::{discover_plugins, PluginManifest, ServiceDefinition};
use webplus_plugin_package::{prepare_plugin_removal, PluginActivation, PreparedPlugin};
use webplus_plugin_repository::{
    download_package, fetch_catalog, secure_http_client, CatalogEntry, CatalogWithdrawalReason,
    PluginCatalog,
};
use webplus_plugin_trust::{prepare_signing_material, read_identity, TrustStore};
use webplus_protocol::{InvokeRequest, InvokeResponse, PluginArchitecture, HOST_PROTOCOL_VERSION};

use invocations::{
    InvocationCoordinator, TrackedInvocationStatus, MAX_RETAINED_RESPONSE_BYTES,
    MAX_RUNTIME_OPERATIONS, RUNTIME_RESULT_RETENTION,
};

const FRONTEND_READY_TIMEOUT: Duration = Duration::from_secs(15);
const STARTUP_FAILURE_FILE_NAME: &str = "startup-failure.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum StartupStage {
    Bootstrap = 0,
    RuntimePaths = 1,
    Diagnostics = 2,
    LocalStorage = 3,
    TrustPolicy = 4,
    PluginRuntime = 5,
    CoreServices = 6,
    DesktopShell = 7,
    SetupComplete = 8,
}

impl StartupStage {
    fn current() -> Self {
        match STARTUP_STAGE.load(Ordering::Acquire) {
            1 => Self::RuntimePaths,
            2 => Self::Diagnostics,
            3 => Self::LocalStorage,
            4 => Self::TrustPolicy,
            5 => Self::PluginRuntime,
            6 => Self::CoreServices,
            7 => Self::DesktopShell,
            8 => Self::SetupComplete,
            _ => Self::Bootstrap,
        }
    }

    fn enter(self) {
        STARTUP_STAGE.store(self as u8, Ordering::Release);
    }

    fn failure(self) -> StartupFailure {
        match self {
            Self::RuntimePaths => StartupFailure {
                code: "startup-runtime-paths",
                summary: "无法确定当前用户的应用数据目录。",
                action: "请确认 Windows 用户配置文件可用，并尝试重新登录系统。",
            },
            Self::Diagnostics => StartupFailure {
                code: "startup-diagnostics",
                summary: "无法初始化本地诊断记录。",
                action: "请检查用户应用数据目录的写入权限和剩余磁盘空间。",
            },
            Self::LocalStorage => StartupFailure {
                code: "startup-local-storage",
                summary: "无法读取或恢复桌面配置及本地组件数据。",
                action: "请先保留应用数据目录，再检查目录权限、磁盘空间或联系实施人员。",
            },
            Self::TrustPolicy => StartupFailure {
                code: "startup-trust-policy",
                summary: "安装包中的签名信任或业务来源策略无效。",
                action: "请使用组织正式发布的完整安装包修复安装，不要手工替换策略文件。",
            },
            Self::PluginRuntime => StartupFailure {
                code: "startup-plugin-runtime",
                summary: "原生插件运行环境初始化失败。",
                action: "请修复 SSDEV Desktop 安装，并确认 x86/x64 插件宿主文件未被安全软件隔离。",
            },
            Self::CoreServices => StartupFailure {
                code: "startup-core-services",
                summary: "桌面核心服务初始化失败。",
                action: "请查看启动日志中的稳定错误码，并将诊断文件交给实施人员。",
            },
            Self::DesktopShell => StartupFailure {
                code: "startup-desktop-shell",
                summary: "控制窗口或系统桌面集成初始化失败。",
                action: "请修复 Microsoft Edge WebView2 Runtime 后重试；仍失败时修复 SSDEV Desktop 安装。",
            },
            Self::SetupComplete | Self::Bootstrap => StartupFailure {
                code: "startup-framework",
                summary: "桌面运行框架初始化失败。",
                action: "请重新启动；仍失败时修复 SSDEV Desktop 安装并查看启动日志。",
            },
        }
    }
}

#[derive(Clone, Copy)]
struct StartupFailure {
    code: &'static str,
    summary: &'static str,
    action: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartupFailureDocument {
    schema_version: u8,
    generated_at_unix_ms: u128,
    event_code: &'static str,
    error_code: &'static str,
    summary: &'static str,
    action: &'static str,
}

static STARTUP_STAGE: AtomicU8 = AtomicU8::new(StartupStage::Bootstrap as u8);
static STARTUP_COMPLETE: AtomicBool = AtomicBool::new(false);
static STARTUP_FAILURE_REPORTED: AtomicBool = AtomicBool::new(false);
static STARTUP_LOG_DIR: OnceLock<PathBuf> = OnceLock::new();

struct BridgeState {
    controller: Arc<PluginController>,
    desktop_version: semver::Version,
    invocation_coordinator: Option<Arc<InvocationCoordinator>>,
    invocation_coordinator_error: Option<&'static str>,
    plugin_load_failures: AtomicUsize,
    plugin_count: AtomicUsize,
    recovered_plugin_transactions: AtomicUsize,
    preflighted_plugin_hosts: AtomicUsize,
    plugin_preflight_failures: AtomicUsize,
    plugin_trust_mode: &'static str,
    x86_host: PathBuf,
    x64_host: PathBuf,
    plugin_root: PathBuf,
    local_mapping_root: PathBuf,
    project_transaction_root: PathBuf,
    config_path: PathBuf,
    trust_store: Option<Arc<TrustStore>>,
    install_lock: tokio::sync::Mutex<()>,
    process_policy_entries: usize,
    managed_process_failures: usize,
    repository_client: reqwest::Client,
}

struct DiagnosticsRuntime {
    state: Option<DiagnosticsState>,
    startup_error: Option<&'static str>,
    log_dir: PathBuf,
}

#[derive(Default)]
struct FrontendRuntime {
    ready: AtomicBool,
    timeout_reported: AtomicBool,
}

#[tauri::command]
fn frontend_ready(
    caller: WebviewWindow,
    app: AppHandle,
    frontend: State<'_, FrontendRuntime>,
) -> Result<(), String> {
    desktop::require_control(&caller)?;
    let was_ready = frontend.ready.swap(true, Ordering::AcqRel);
    tracing::info!(
        event_code = "frontend-ready",
        app_version = %app.package_info().version,
        recovered_after_timeout = frontend.timeout_reported.load(Ordering::Acquire),
        duplicate_signal = was_ready,
        "control frontend mounted and reached native IPC"
    );
    Ok(())
}

#[tauri::command]
fn open_diagnostics_directory(
    caller: WebviewWindow,
    app: AppHandle,
    diagnostics: State<'_, DiagnosticsRuntime>,
) -> Result<(), String> {
    desktop::require_control(&caller)?;
    fs::create_dir_all(&diagnostics.log_dir)
        .map_err(|_| "无法创建诊断日志目录，请检查应用数据目录权限".to_owned())?;
    app.opener()
        .open_path(
            diagnostics.log_dir.to_string_lossy().into_owned(),
            None::<&str>,
        )
        .map_err(|_| "无法使用系统文件管理器打开诊断日志目录".to_owned())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BridgeStatus {
    mode: &'static str,
    protocol_version: u16,
    plugin_host_protocol_version: u16,
    transport: &'static str,
    http_gateway_enabled: bool,
    service_count: usize,
    max_in_flight_invocations: usize,
    in_flight_invocations: usize,
    rejected_invocations: u64,
    caller_detachments: u64,
    shutdown_rejected_invocations: u64,
    execution_lane_timeouts: u64,
    maintenance_rejected_invocations: u64,
    plugin_maintenance_active: bool,
    global_plugin_maintenance_active: bool,
    active_plugin_maintenances: usize,
    accepting_plugin_invocations: bool,
    tracked_invocations_available: bool,
    tracked_invocations_accepting: bool,
    tracked_invocations_error: Option<&'static str>,
    tracked_runtime_operations: usize,
    tracked_pending_operations: usize,
    tracked_retained_results: usize,
    tracked_durable_operations: usize,
    tracked_persistence_failures: u64,
    active_plugin_hosts: usize,
    plugin_host_starts: u64,
    plugin_host_start_failures: u64,
    plugin_load_failures: usize,
    plugin_count: usize,
    recovered_plugin_transactions: usize,
    preflighted_plugin_hosts: usize,
    plugin_preflight_failures: usize,
    plugin_trust_mode: &'static str,
    trust_key_count: usize,
    active_trust_key_count: usize,
    retired_trust_key_count: usize,
    revoked_trust_key_count: usize,
    plugin_root: PathBuf,
    process_policy_entries: usize,
    managed_process_failures: usize,
    auto_start_enabled: Option<bool>,
    auto_start_error: Option<String>,
    app_update_configured: bool,
    app_update_error: Option<String>,
    sso_active: bool,
    sso_error: Option<&'static str>,
    origin_policy: OriginPolicySummary,
    origin_policy_error: Option<String>,
    diagnostics_available: bool,
    diagnostics_error: Option<&'static str>,
    diagnostics_log_dir: PathBuf,
    diagnostics: Option<DiagnosticsStats>,
}

#[tauri::command]
async fn bridge_status(
    caller: WebviewWindow,
    app: AppHandle,
    state: State<'_, BridgeState>,
    desktop_state: State<'_, desktop::DesktopState>,
    update_state: State<'_, app_update::AppUpdateState>,
    sso_state: State<'_, sso::SsoRuntimeState>,
    diagnostics: State<'_, DiagnosticsRuntime>,
) -> Result<BridgeStatus, String> {
    desktop::require_control(&caller)?;
    let (auto_start_enabled, auto_start_error) = desktop::autostart_status(&app);
    let app_update = update_state.status();
    let (sso_active, sso_error) = sso_state.status();
    let admission = state.controller.invocation_admission_stats();
    let hosts = state.controller.plugin_host_stats();
    let trust_keys = state
        .trust_store
        .as_deref()
        .map(TrustStore::stats)
        .unwrap_or_default();
    let tracked = match &state.invocation_coordinator {
        Some(coordinator) => Some(coordinator.stats().await),
        None => None,
    };
    Ok(BridgeStatus {
        mode: "native-ipc",
        protocol_version: BRIDGE_PROTOCOL_VERSION,
        plugin_host_protocol_version: HOST_PROTOCOL_VERSION,
        transport: "Tauri IPC",
        http_gateway_enabled: false,
        service_count: state.controller.service_count().await,
        max_in_flight_invocations: admission.max_in_flight,
        in_flight_invocations: admission.in_flight,
        rejected_invocations: admission.rejected,
        caller_detachments: admission.caller_detachments,
        shutdown_rejected_invocations: admission.shutdown_rejections,
        execution_lane_timeouts: admission.execution_lane_timeouts,
        maintenance_rejected_invocations: admission.maintenance_rejections,
        plugin_maintenance_active: admission.maintenance_active,
        global_plugin_maintenance_active: admission.global_maintenance_active,
        active_plugin_maintenances: admission.active_plugin_maintenances,
        accepting_plugin_invocations: admission.accepting,
        tracked_invocations_available: tracked.is_some(),
        tracked_invocations_accepting: tracked.is_some_and(|stats| stats.accepting),
        tracked_invocations_error: state.invocation_coordinator_error,
        tracked_runtime_operations: tracked.map_or(0, |stats| stats.runtime_operations),
        tracked_pending_operations: tracked.map_or(0, |stats| stats.pending_operations),
        tracked_retained_results: tracked.map_or(0, |stats| stats.retained_results),
        tracked_durable_operations: tracked.map_or(0, |stats| stats.durable_operations),
        tracked_persistence_failures: tracked.map_or(0, |stats| stats.persistence_failures),
        active_plugin_hosts: hosts.active_hosts,
        plugin_host_starts: hosts.successful_starts,
        plugin_host_start_failures: hosts.failed_starts,
        plugin_load_failures: state.plugin_load_failures.load(Ordering::Acquire),
        plugin_count: state.plugin_count.load(Ordering::Acquire),
        recovered_plugin_transactions: state.recovered_plugin_transactions.load(Ordering::Acquire),
        preflighted_plugin_hosts: state.preflighted_plugin_hosts.load(Ordering::Acquire),
        plugin_preflight_failures: state.plugin_preflight_failures.load(Ordering::Acquire),
        plugin_trust_mode: state.plugin_trust_mode,
        trust_key_count: trust_keys.total,
        active_trust_key_count: trust_keys.active,
        retired_trust_key_count: trust_keys.retired,
        revoked_trust_key_count: trust_keys.revoked,
        plugin_root: state.plugin_root.clone(),
        process_policy_entries: state.process_policy_entries,
        managed_process_failures: state.managed_process_failures,
        auto_start_enabled,
        auto_start_error,
        app_update_configured: app_update.configured,
        app_update_error: app_update.error,
        sso_active,
        sso_error,
        origin_policy: desktop_state.origin_policy_summary(),
        origin_policy_error: desktop_state.origin_policy_error(),
        diagnostics_available: diagnostics.state.is_some(),
        diagnostics_error: diagnostics.startup_error,
        diagnostics_log_dir: diagnostics.log_dir.clone(),
        diagnostics: diagnostics.state.as_ref().map(DiagnosticsState::stats),
    })
}

#[tauri::command]
async fn run_deployment_check(
    caller: WebviewWindow,
    state: State<'_, BridgeState>,
    desktop_state: State<'_, desktop::DesktopState>,
    update_state: State<'_, app_update::AppUpdateState>,
    diagnostics: State<'_, DiagnosticsRuntime>,
) -> Result<deployment_check::DeploymentCheckReport, String> {
    desktop::require_control(&caller)?;
    let _install = state.install_lock.lock().await;
    recover_plugin_store(&state)?;
    let config = desktop_state.config.snapshot();
    let config_error = config.validate().err().map(|error| error.to_string());
    let business_origin_count = config.business_origins().map_or(0, |origins| origins.len());
    let origin = desktop_state.origin_policy_summary();
    let origin_policy_error = desktop_state.origin_policy_error();
    let inspected = inspect_all_plugins(
        &state.plugin_root,
        &state.local_mapping_root,
        state.trust_store.as_deref(),
        &state.desktop_version,
    );
    let (manifests, plugin_load_failures, plugin_inventory_error) = match inspected {
        Ok(inspected) => (inspected.manifests, inspected.failures.len(), None),
        Err(error) => (Vec::new(), 0, Some(error)),
    };
    let plugin_count = manifests.len();
    let service_count = manifests
        .iter()
        .map(|manifest| manifest.services.len())
        .sum();
    let route_coverage = desktop_state.plugin_route_policy_coverage(&config, &manifests);
    let (
        plugin_route_count,
        evaluated_policy_grants,
        authorized_policy_grants,
        uncovered_business_origins,
        uncovered_plugin_routes,
        route_policy_error,
    ) = match route_coverage {
        Ok(coverage) => (
            coverage.route_count,
            coverage.evaluated_grant_count,
            coverage.authorized_grant_count,
            coverage.uncovered_origin_count,
            coverage.uncovered_route_count,
            None,
        ),
        Err(error) => (0, 0, 0, 0, 0, Some(error)),
    };
    let trust_keys = state
        .trust_store
        .as_deref()
        .map(TrustStore::stats)
        .unwrap_or_default();
    let tracked = match &state.invocation_coordinator {
        Some(coordinator) => Some(coordinator.stats().await),
        None => None,
    };
    let report = deployment_check::evaluate(&deployment_check::DeploymentCheckFacts {
        is_windows: cfg!(windows),
        config_error,
        business_origin_count,
        origin_policy_error,
        allow_insecure_http: origin.allow_insecure_http,
        plugin_trust_mode: state.plugin_trust_mode,
        active_trust_keys: trust_keys.active,
        plugin_count,
        service_count,
        active_service_count: state.controller.service_count().await,
        active_manifests_match: state
            .controller
            .manifests_match_active_routes(&manifests)
            .await
            .is_ok_and(|matches| matches),
        plugin_route_count,
        evaluated_policy_grants,
        authorized_policy_grants,
        uncovered_business_origins,
        uncovered_plugin_routes,
        route_policy_error,
        plugin_inventory_error,
        plugin_load_failures,
        plugin_preflight_failures: state.plugin_preflight_failures.load(Ordering::Acquire),
        x86_host_available: state.x86_host.is_file(),
        x64_host_available: state.x64_host.is_file(),
        tracked_invocations_available: tracked.is_some(),
        tracked_invocations_accepting: tracked.is_some_and(|stats| stats.accepting),
        tracked_persistence_failures: tracked.map_or(0, |stats| stats.persistence_failures),
        diagnostics_available: diagnostics.state.is_some(),
        managed_process_failures: state.managed_process_failures,
        app_update_configured: update_state.status().configured,
    });
    tracing::info!(
        event_code = "deployment-check-completed",
        ready = report.ready,
        passed = report.passed,
        warnings = report.warnings,
        failures = report.failures,
        "deployment self-check completed"
    );
    Ok(report)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticsExportResult {
    bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectBundleExportResult {
    bytes: u64,
    bundle_sha256: String,
    signed_plugins: usize,
    local_mappings: usize,
    service_count: usize,
    preflighted_hosts: usize,
}

struct StagedProjectExport {
    temporary: tempfile::TempDir,
    inputs: Vec<project_bundle::PreparedProjectBundleInput>,
    signed_plugins: usize,
    local_mappings: usize,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectBundlePreview {
    plan_id: String,
    schema_version: u8,
    created_by_version: String,
    signature_verified: bool,
    signature_key_id: Option<String>,
    business_origins: usize,
    signed_plugins: usize,
    local_mappings: usize,
    service_count: usize,
    preflighted_hosts: usize,
    config_preview: desktop::ConfigChangePreview,
    install_count: usize,
    upgrade_count: usize,
    replace_count: usize,
    retained_count: usize,
    components: Vec<ProjectBundleComponentPreview>,
    retained_components: Vec<ProjectBundleComponentPreview>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectBundleComponentPreview {
    plugin_id: String,
    version: Option<String>,
    desktop_version_requirement: Option<String>,
    source: &'static str,
    action: &'static str,
    service_count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectBundleImportResult {
    signed_plugins: usize,
    local_mappings: usize,
    service_count: usize,
    preflighted_hosts: usize,
}

enum PreparedProjectComponent {
    Signed(PreparedPlugin),
    Local(local_mappings::PreparedLocalMapping),
}

impl PreparedProjectComponent {
    fn manifest(&self) -> &PluginManifest {
        match self {
            Self::Signed(prepared) => prepared.manifest(),
            Self::Local(prepared) => prepared.manifest(),
        }
    }

    fn activation_member(&self) -> project_activation::ProjectActivationMember {
        let (plugin_id, kind) = match self {
            Self::Signed(prepared) => (
                prepared.identity().plugin_id.clone(),
                project_activation::ProjectActivationKind::SignedPlugin,
            ),
            Self::Local(prepared) => (
                prepared.plugin_id().to_owned(),
                project_activation::ProjectActivationKind::LocalMapping,
            ),
        };
        project_activation::ProjectActivationMember { plugin_id, kind }
    }
}

enum ActivatedProjectComponent {
    Signed(PluginActivation),
    Local(local_mappings::ActivatedLocalMapping),
}

impl ActivatedProjectComponent {
    fn rollback(self) -> Result<(), String> {
        match self {
            Self::Signed(activation) => activation.rollback().map_err(|error| error.to_string()),
            Self::Local(activation) => activation.rollback(),
        }
    }

    fn commit_grouped(self) -> Result<(), String> {
        match self {
            Self::Signed(activation) => activation
                .commit_grouped()
                .map_err(|error| error.to_string()),
            Self::Local(activation) => activation.commit_grouped().map(|_| ()),
        }
    }
}

fn rollback_project_components(
    transaction: project_activation::ProjectActivation,
    mut components: Vec<ActivatedProjectComponent>,
) -> Result<(), String> {
    let mut failures = Vec::new();
    while let Some(component) = components.pop() {
        if let Err(error) = component.rollback() {
            failures.push(error);
        }
    }
    if failures.is_empty() {
        transaction.abort()
    } else {
        Err(format!(
            "{} 个项目组件回滚失败；已保留恢复事务，请重新启动客户端",
            failures.len()
        ))
    }
}

struct PreparedProjectBundle {
    config: ssdev_config::DesktopConfig,
    components: Vec<PreparedProjectComponent>,
    preview: ProjectBundlePreview,
}

#[tauri::command]
async fn export_diagnostics(
    caller: WebviewWindow,
    app: AppHandle,
    destination: PathBuf,
    bridge_state: State<'_, BridgeState>,
    desktop_state: State<'_, desktop::DesktopState>,
    update_state: State<'_, app_update::AppUpdateState>,
    diagnostics: State<'_, DiagnosticsRuntime>,
) -> Result<DiagnosticsExportResult, String> {
    desktop::require_control(&caller)?;
    let state = diagnostics
        .state
        .as_ref()
        .cloned()
        .ok_or_else(|| "诊断日志不可用".to_owned())?;
    let origin = desktop_state.origin_policy_summary();
    let update = update_state.status();
    let admission = bridge_state.controller.invocation_admission_stats();
    let hosts = bridge_state.controller.plugin_host_stats();
    let trust_keys = bridge_state
        .trust_store
        .as_deref()
        .map(TrustStore::stats)
        .unwrap_or_default();
    let tracked = match &bridge_state.invocation_coordinator {
        Some(coordinator) => Some(coordinator.stats().await),
        None => None,
    };
    let (auto_start_enabled, _) = desktop::autostart_status(&app);
    let context = DiagnosticContext {
        app_version: app.package_info().version.to_string(),
        os: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        protocol_version: BRIDGE_PROTOCOL_VERSION,
        plugin_host_protocol_version: HOST_PROTOCOL_VERSION,
        service_count: bridge_state.controller.service_count().await,
        plugin_count: bridge_state.plugin_count.load(Ordering::Acquire),
        quarantined_plugin_count: bridge_state.plugin_load_failures.load(Ordering::Acquire),
        recovered_plugin_transaction_count: bridge_state
            .recovered_plugin_transactions
            .load(Ordering::Acquire),
        preflighted_plugin_host_count: bridge_state
            .preflighted_plugin_hosts
            .load(Ordering::Acquire),
        plugin_preflight_failure_count: bridge_state
            .plugin_preflight_failures
            .load(Ordering::Acquire),
        trust_key_count: trust_keys.total,
        active_trust_key_count: trust_keys.active,
        retired_trust_key_count: trust_keys.retired,
        revoked_trust_key_count: trust_keys.revoked,
        process_policy_entries: bridge_state.process_policy_entries,
        managed_process_failures: bridge_state.managed_process_failures,
        origin_policy_enforced: origin.enforced,
        business_origin_count: origin.business_origins,
        origin_service_grant_count: origin.service_grants,
        origin_method_grant_count: origin.method_grants,
        max_in_flight_invocations: admission.max_in_flight,
        in_flight_invocations: admission.in_flight,
        rejected_invocations: admission.rejected,
        caller_detachment_count: admission.caller_detachments,
        shutdown_rejected_invocation_count: admission.shutdown_rejections,
        execution_lane_timeout_count: admission.execution_lane_timeouts,
        maintenance_rejected_invocation_count: admission.maintenance_rejections,
        plugin_maintenance_active: admission.maintenance_active,
        global_plugin_maintenance_active: admission.global_maintenance_active,
        active_plugin_maintenance_count: admission.active_plugin_maintenances,
        accepting_plugin_invocations: admission.accepting,
        tracked_invocations_available: tracked.is_some(),
        tracked_invocations_accepting: tracked.is_some_and(|stats| stats.accepting),
        tracked_invocations_error: bridge_state.invocation_coordinator_error.map(str::to_owned),
        tracked_runtime_operation_count: tracked.map_or(0, |stats| stats.runtime_operations),
        tracked_pending_operation_count: tracked.map_or(0, |stats| stats.pending_operations),
        tracked_retained_result_count: tracked.map_or(0, |stats| stats.retained_results),
        tracked_durable_operation_count: tracked.map_or(0, |stats| stats.durable_operations),
        tracked_persistence_failure_count: tracked.map_or(0, |stats| stats.persistence_failures),
        active_plugin_host_count: hosts.active_hosts,
        plugin_host_start_count: hosts.successful_starts,
        plugin_host_start_failure_count: hosts.failed_starts,
        navigation_origin_count: origin.navigation_origins,
        external_origin_count: origin.external_origins,
        insecure_http_allowed: origin.allow_insecure_http,
        app_update_configured: update.configured,
        auto_start_enabled,
    };
    let bytes = tokio::task::spawn_blocking(move || state.export(&destination, &context))
        .await
        .map_err(|_| "诊断导出任务异常终止".to_owned())?
        .map_err(|error| error.to_string())?;
    tracing::info!(
        event_code = "diagnostics-exported",
        bytes,
        "diagnostics exported"
    );
    Ok(DiagnosticsExportResult { bytes })
}

#[tauri::command]
async fn export_project_bundle(
    caller: WebviewWindow,
    app: AppHandle,
    destination: PathBuf,
    state: State<'_, BridgeState>,
    desktop_state: State<'_, desktop::DesktopState>,
) -> Result<ProjectBundleExportResult, String> {
    desktop::require_control(&caller)?;
    let _install = state.install_lock.lock().await;
    recover_plugin_store(&state)?;
    let config = desktop_state.config.snapshot();
    desktop_state.authorize_config(&config)?;
    let inspected = inspect_all_plugins(
        &state.plugin_root,
        &state.local_mapping_root,
        state.trust_store.as_deref(),
        &state.desktop_version,
    )?;
    if !inspected.failures.is_empty() {
        return Err(format!(
            "当前有 {} 个插件或映射未通过校验，请先处理后再导出项目包",
            inspected.failures.len()
        ));
    }
    validate_project_delivery_routes(&desktop_state, &config, &inspected.manifests)?;
    let service_count = inspected
        .manifests
        .iter()
        .map(|manifest| manifest.services.len())
        .sum::<usize>();
    ensure_project_export_runtime_matches(service_count, state.controller.service_count().await)?;
    ensure_project_export_active_manifests_match(
        state
            .controller
            .manifests_match_active_routes(&inspected.manifests)
            .await
            .map_err(|error| error.to_string())?,
    )?;
    let trust_store = state.trust_store.clone();
    let local_mapping_root = state.local_mapping_root.clone();
    let staged_trust_store = trust_store.clone();
    let staged_local_mapping_root = local_mapping_root.clone();
    let staged = tokio::task::spawn_blocking(move || {
        stage_project_export_components(
            inspected.manifests,
            &staged_local_mapping_root,
            staged_trust_store.as_deref(),
        )
    })
    .await
    .map_err(|_| "项目组件封装任务异常终止".to_owned())??;

    let candidate_inputs = staged.inputs.clone();
    let candidate_plugin_root = state.plugin_root.clone();
    let candidate_local_mapping_root = state.local_mapping_root.clone();
    let candidate_trust_store = trust_store.clone();
    let candidate_desktop_version = state.desktop_version.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        prepare_project_export_candidates(
            candidate_inputs,
            &candidate_plugin_root,
            &candidate_local_mapping_root,
            candidate_trust_store.as_deref(),
            &candidate_desktop_version,
        )
    })
    .await
    .map_err(|_| "项目候选组件检查任务异常终止".to_owned())??;
    let candidates = prepared
        .iter()
        .map(|component| component.manifest().clone())
        .collect::<Vec<_>>();
    validate_project_delivery_routes(&desktop_state, &config, &candidates)?;
    let service_count = candidates
        .iter()
        .map(|manifest| manifest.services.len())
        .sum::<usize>();
    ensure_project_export_runtime_matches(service_count, state.controller.service_count().await)?;
    let preflighted_hosts = preflight_manifests(&state, &candidates, "项目组件").await?;
    drop(prepared);

    let version = app.package_info().version.to_string();
    let result = tokio::task::spawn_blocking(move || {
        let StagedProjectExport {
            temporary,
            inputs,
            signed_plugins,
            local_mappings,
        } = staged;
        let _temporary = temporary;
        let summary =
            project_bundle::create_from_prepared(&destination, &config, &version, inputs)?;
        if summary.signed_plugin_count != signed_plugins
            || summary.local_mapping_count != local_mappings
        {
            return Err("项目包复核后的组件计数不一致".to_owned());
        }
        Ok::<_, String>(ProjectBundleExportResult {
            bytes: summary.bundle_bytes,
            bundle_sha256: summary.bundle_sha256,
            signed_plugins,
            local_mappings,
            service_count,
            preflighted_hosts,
        })
    })
    .await
    .map_err(|_| "项目包导出任务异常终止".to_owned())??;
    tracing::info!(
        event_code = "project-bundle-exported",
        bytes = result.bytes,
        signed_plugins = result.signed_plugins,
        local_mappings = result.local_mappings,
        service_count = result.service_count,
        preflighted_hosts = result.preflighted_hosts,
        "project deployment bundle exported"
    );
    Ok(result)
}

#[tauri::command]
async fn inspect_project_bundle(
    caller: WebviewWindow,
    source: PathBuf,
    state: State<'_, BridgeState>,
    desktop_state: State<'_, desktop::DesktopState>,
) -> Result<ProjectBundlePreview, String> {
    desktop::require_control(&caller)?;
    let _install = state.install_lock.lock().await;
    recover_plugin_store(&state)?;
    let prepared = prepare_project_bundle(source, &state, &desktop_state).await?;
    tracing::info!(
        event_code = "project-bundle-inspected",
        signed_plugins = prepared.preview.signed_plugins,
        local_mappings = prepared.preview.local_mappings,
        service_count = prepared.preview.service_count,
        preflighted_hosts = prepared.preview.preflighted_hosts,
        config_changed = prepared.preview.config_preview.config_changed,
        installs = prepared.preview.install_count,
        upgrades = prepared.preview.upgrade_count,
        replacements = prepared.preview.replace_count,
        retained = prepared.preview.retained_count,
        "project deployment bundle inspected"
    );
    Ok(prepared.preview)
}

#[tauri::command]
async fn import_project_bundle(
    caller: WebviewWindow,
    app: AppHandle,
    source: PathBuf,
    expected_plan_id: String,
    state: State<'_, BridgeState>,
    desktop_state: State<'_, desktop::DesktopState>,
) -> Result<ProjectBundleImportResult, String> {
    desktop::require_control(&caller)?;
    let _install = state.install_lock.lock().await;
    recover_plugin_store(&state)?;
    if !is_lowercase_sha256(&expected_plan_id) {
        return Err("项目导入计划标识无效，请重新预检".into());
    }
    let prepared = prepare_project_bundle(source, &state, &desktop_state).await?;
    if prepared.preview.plan_id != expected_plan_id {
        return Err("项目包或当前机器状态已在预检后变化，请重新预检后确认导入".into());
    }
    let signed_plugins = prepared.preview.signed_plugins;
    let local_mappings = prepared.preview.local_mappings;
    let preflighted_hosts = prepared.preview.preflighted_hosts;
    let previous_config = desktop_state.config.snapshot();
    let previous_plugins = inspect_all_plugins(
        &state.plugin_root,
        &state.local_mapping_root,
        state.trust_store.as_deref(),
        &state.desktop_version,
    )?;
    if !previous_plugins.failures.is_empty() {
        return Err("当前插件清单在项目预检后发生变化，请处理隔离项后重试".into());
    }
    let members = prepared
        .components
        .iter()
        .map(PreparedProjectComponent::activation_member)
        .collect();
    let transaction = project_activation::ProjectActivation::begin(
        &state.project_transaction_root,
        &previous_config,
        &prepared.config,
        members,
    )?;
    let maintenance = state.controller.begin_maintenance().await;
    let mut activated = Vec::with_capacity(prepared.components.len());
    for component in prepared.components {
        let activation = match component {
            PreparedProjectComponent::Signed(plugin) => plugin
                .activate()
                .map(ActivatedProjectComponent::Signed)
                .map_err(|error| error.to_string()),
            PreparedProjectComponent::Local(mapping) => mapping
                .activate(&state.local_mapping_root)
                .map(ActivatedProjectComponent::Local),
        };
        match activation {
            Ok(activation) => activated.push(activation),
            Err(error) => {
                let rollback = rollback_project_components(transaction, activated);
                return Err(match rollback {
                    Ok(()) => format!("项目组件启用失败，已恢复导入前状态: {error}"),
                    Err(rollback) => format!("项目组件启用失败: {error}; {rollback}"),
                });
            }
        }
    }

    let installed = match inspect_all_plugins(
        &state.plugin_root,
        &state.local_mapping_root,
        state.trust_store.as_deref(),
        &state.desktop_version,
    ) {
        Ok(installed) if installed.failures.is_empty() => installed,
        Ok(installed) => {
            let error = format!("新项目产生 {} 个无效插件或映射", installed.failures.len());
            let rollback = rollback_project_components(transaction, activated);
            return Err(match rollback {
                Ok(()) => format!("{error}，已恢复导入前状态"),
                Err(rollback) => format!("{error}; {rollback}"),
            });
        }
        Err(error) => {
            let rollback = rollback_project_components(transaction, activated);
            return Err(match rollback {
                Ok(()) => format!("新项目清单读取失败，已恢复导入前状态: {error}"),
                Err(rollback) => format!("新项目清单读取失败: {error}; {rollback}"),
            });
        }
    };
    if let Err(error) = maintenance.replace_manifests(&installed.manifests).await {
        let rollback = rollback_project_components(transaction, activated);
        return Err(match rollback {
            Ok(()) => format!("新项目路由无效，已恢复导入前状态: {error}"),
            Err(rollback) => format!("新项目路由无效: {error}; {rollback}"),
        });
    }
    if let Err(error) = desktop::replace_desktop_config(&app, &desktop_state, prepared.config) {
        let route_restore = maintenance
            .replace_manifests(&previous_plugins.manifests)
            .await;
        let rollback = rollback_project_components(transaction, activated);
        return Err(match (route_restore, rollback) {
            (Ok(()), Ok(())) => {
                format!("项目配置切换失败，已恢复导入前状态: {error}")
            }
            (route_restore, rollback) => format!(
                "项目配置切换失败: {error}; 恢复旧路由结果: {}; 组件回滚结果: {}",
                route_restore
                    .err()
                    .map_or_else(|| "成功".to_owned(), |failure| failure.to_string()),
                rollback
                    .err()
                    .map_or_else(|| "成功".to_owned(), |failure| failure)
            ),
        });
    }
    if let Err(error) = transaction.mark_committed() {
        let config_restore = desktop::replace_desktop_config(&app, &desktop_state, previous_config);
        let route_restore = maintenance
            .replace_manifests(&previous_plugins.manifests)
            .await;
        let rollback = rollback_project_components(transaction, activated);
        return Err(format!(
            "项目提交点写入失败: {error}; 恢复旧配置结果: {}; 恢复旧路由结果: {}; 组件回滚结果: {}",
            config_restore
                .err()
                .map_or_else(|| "成功".to_owned(), |failure| failure),
            route_restore
                .err()
                .map_or_else(|| "成功".to_owned(), |failure| failure.to_string()),
            rollback
                .err()
                .map_or_else(|| "成功".to_owned(), |failure| failure)
        ));
    }

    let mut deferred_cleanup = 0_usize;
    for component in activated {
        if component.commit_grouped().is_err() {
            deferred_cleanup = deferred_cleanup.saturating_add(1);
        }
    }
    if deferred_cleanup == 0 {
        if transaction.finish().is_err() {
            deferred_cleanup = 1;
        }
    } else {
        drop(transaction);
    }
    let service_count = state.controller.service_count().await;
    state
        .plugin_load_failures
        .store(installed.failures.len(), Ordering::Release);
    state
        .plugin_count
        .store(installed.manifests.len(), Ordering::Release);
    tracing::info!(
        event_code = "project-bundle-imported",
        signed_plugins,
        local_mappings,
        service_count,
        preflighted_hosts,
        deferred_cleanup,
        "project deployment bundle imported"
    );
    Ok(ProjectBundleImportResult {
        signed_plugins,
        local_mappings,
        service_count,
        preflighted_hosts,
    })
}

async fn prepare_project_bundle(
    source: PathBuf,
    state: &BridgeState,
    desktop_state: &desktop::DesktopState,
) -> Result<PreparedProjectBundle, String> {
    let strict_signature = state.plugin_trust_mode != "debug-unsigned";
    let trust_store = state.trust_store.clone();
    let (opened, signature_verified, signature_key_id, bundle_sha256) =
        tokio::task::spawn_blocking(move || {
            open_project_bundle_for_mode(&source, trust_store.as_deref(), strict_signature)
        })
        .await
        .map_err(|_| "项目包读取任务异常终止".to_owned())??;
    desktop_state.authorize_config(&opened.config)?;
    let business_origins = opened
        .config
        .business_origins()
        .map_err(|error| error.to_string())?
        .len();
    let schema_version = opened.schema_version();
    let created_by_version = opened.created_by_version().to_owned();
    let specifications = opened
        .components()
        .map(|component| {
            (
                component.plugin_id.to_owned(),
                component.version.map(str::to_owned),
                component.kind,
                component.path,
            )
        })
        .collect::<Vec<_>>();
    let current = inspect_all_plugins(
        &state.plugin_root,
        &state.local_mapping_root,
        state.trust_store.as_deref(),
        &state.desktop_version,
    )?;
    if !current.failures.is_empty() {
        return Err(format!(
            "目标机器当前有 {} 个无效插件或映射，请先处理后再导入项目包",
            current.failures.len()
        ));
    }
    let current_config = desktop_state.config.snapshot();
    let config_preview = desktop::build_config_change_preview(&current_config, &opened.config)?;
    let current_state_manifests = current.manifests.clone();
    let current_state_local_root = state.local_mapping_root.clone();
    let current_state_digest = tokio::task::spawn_blocking(move || {
        project_import_state_digest(
            &current_config,
            &current_state_manifests,
            &current_state_local_root,
        )
    })
    .await
    .map_err(|_| "项目导入基线摘要任务异常终止".to_owned())??;
    let plan_id = project_import_plan_id(
        &bundle_sha256,
        &current_state_digest,
        &state.desktop_version,
    );
    let mut components = Vec::with_capacity(specifications.len());
    let mut previews = Vec::with_capacity(specifications.len());
    for (declared_id, declared_version, kind, path) in specifications {
        match kind {
            project_bundle::ProjectComponentKind::SignedPlugin => {
                if current.manifests.iter().any(|manifest| {
                    manifest.plugin_id == declared_id
                        && is_local_manifest(manifest, &state.local_mapping_root)
                }) {
                    return Err(format!(
                        "项目签名插件 [{declared_id}] 与目标机器的同名本地映射冲突，请先删除本地映射"
                    ));
                }
                let trust_store = state
                    .trust_store
                    .as_ref()
                    .cloned()
                    .ok_or_else(|| "正式项目包要求启用插件签名信任".to_owned())?;
                let plugin_root = state.plugin_root.clone();
                let prepared = tokio::task::spawn_blocking(move || {
                    PreparedPlugin::prepare(&path, &plugin_root, &trust_store)
                        .map_err(|error| error.to_string())
                })
                .await
                .map_err(|_| "签名插件准备任务异常终止".to_owned())??;
                let metadata = prepared.metadata();
                ensure_signed_plugin_compatible(prepared.manifest(), &state.desktop_version)?;
                let actual_version = metadata.version.to_string();
                if prepared.identity().plugin_id != declared_id
                    || declared_version.as_deref() != Some(actual_version.as_str())
                {
                    return Err(format!("项目组件 [{declared_id}] 身份或版本与清单不一致"));
                }
                let current_manifest = current.manifests.iter().find(|manifest| {
                    manifest.plugin_id == declared_id
                        && !is_local_manifest(manifest, &state.local_mapping_root)
                });
                let current_version = current_manifest
                    .and_then(|manifest| manifest.metadata.as_ref())
                    .map(|metadata| &metadata.version);
                ensure_upgrade_allowed(current_version, &metadata.version)?;
                let action = classify_project_component_action(
                    project_bundle::ProjectComponentKind::SignedPlugin,
                    current_manifest.is_some(),
                    current_version,
                    Some(&metadata.version),
                );
                previews.push(ProjectBundleComponentPreview {
                    plugin_id: declared_id,
                    version: Some(actual_version),
                    desktop_version_requirement: metadata
                        .desktop_version_requirement
                        .as_ref()
                        .map(ToString::to_string),
                    source: "signed-package",
                    action,
                    service_count: prepared.manifest().services.len(),
                });
                components.push(PreparedProjectComponent::Signed(prepared));
            }
            project_bundle::ProjectComponentKind::LocalMapping => {
                let current_mapping_exists = current.manifests.iter().any(|manifest| {
                    manifest.plugin_id == declared_id
                        && is_local_manifest(manifest, &state.local_mapping_root)
                });
                if current.manifests.iter().any(|manifest| {
                    manifest.plugin_id == declared_id
                        && !is_local_manifest(manifest, &state.local_mapping_root)
                }) {
                    return Err(format!(
                        "项目本地映射 [{declared_id}] 与目标机器的同名签名插件冲突，请先调整映射 ID"
                    ));
                }
                if declared_version.is_some() {
                    return Err(format!("本地映射 [{declared_id}] 不应声明发布版本"));
                }
                let local_root = state.local_mapping_root.clone();
                let prepared = tokio::task::spawn_blocking(move || {
                    local_mappings::prepare_import(&local_root, &path)
                })
                .await
                .map_err(|_| "本地映射准备任务异常终止".to_owned())??;
                if prepared.plugin_id() != declared_id {
                    return Err(format!("本地映射 [{declared_id}] 身份与清单不一致"));
                }
                previews.push(ProjectBundleComponentPreview {
                    plugin_id: declared_id,
                    version: None,
                    desktop_version_requirement: None,
                    source: "local-mapping",
                    action: classify_project_component_action(
                        project_bundle::ProjectComponentKind::LocalMapping,
                        current_mapping_exists,
                        None,
                        None,
                    ),
                    service_count: prepared.manifest().services.len(),
                });
                components.push(PreparedProjectComponent::Local(prepared));
            }
        }
    }

    let imported_ids = components
        .iter()
        .map(|component| component.manifest().plugin_id.clone())
        .collect::<std::collections::HashSet<_>>();
    let retained_components = current
        .manifests
        .iter()
        .filter(|manifest| !imported_ids.contains(&manifest.plugin_id))
        .map(|manifest| {
            let local = is_local_manifest(manifest, &state.local_mapping_root);
            ProjectBundleComponentPreview {
                plugin_id: manifest.plugin_id.clone(),
                version: manifest
                    .metadata
                    .as_ref()
                    .map(|metadata| metadata.version.to_string()),
                desktop_version_requirement: if local {
                    None
                } else {
                    manifest
                        .metadata
                        .as_ref()
                        .and_then(|metadata| metadata.desktop_version_requirement.as_ref())
                        .map(ToString::to_string)
                },
                source: if local {
                    "local-mapping"
                } else {
                    "signed-package"
                },
                action: "retain",
                service_count: manifest.services.len(),
            }
        })
        .collect::<Vec<_>>();
    let mut candidates = current
        .manifests
        .into_iter()
        .filter(|manifest| !imported_ids.contains(&manifest.plugin_id))
        .collect::<Vec<_>>();
    candidates.extend(
        components
            .iter()
            .map(|component| component.manifest().clone()),
    );
    validate_project_delivery_routes(desktop_state, &opened.config, &candidates)?;
    let project_manifests = components
        .iter()
        .map(|component| component.manifest().clone())
        .collect::<Vec<_>>();
    let preflighted_hosts = preflight_manifests(state, &project_manifests, "项目组件").await?;
    let signed_plugins = previews
        .iter()
        .filter(|component| component.source == "signed-package")
        .count();
    let local_mappings = previews.len().saturating_sub(signed_plugins);
    let service_count = previews
        .iter()
        .map(|component| component.service_count)
        .sum();
    let install_count = previews
        .iter()
        .filter(|component| component.action == "install")
        .count();
    let upgrade_count = previews
        .iter()
        .filter(|component| component.action == "upgrade")
        .count();
    let replace_count = previews
        .iter()
        .filter(|component| matches!(component.action, "reinstall" | "replace"))
        .count();
    let retained_count = retained_components.len();
    Ok(PreparedProjectBundle {
        config: opened.config,
        components,
        preview: ProjectBundlePreview {
            plan_id,
            schema_version,
            created_by_version,
            signature_verified,
            signature_key_id,
            business_origins,
            signed_plugins,
            local_mappings,
            service_count,
            preflighted_hosts,
            config_preview,
            install_count,
            upgrade_count,
            replace_count,
            retained_count,
            components: previews,
            retained_components,
        },
    })
}

fn stage_project_export_components(
    manifests: Vec<PluginManifest>,
    local_mapping_root: &std::path::Path,
    trust_store: Option<&TrustStore>,
) -> Result<StagedProjectExport, String> {
    let temporary =
        tempfile::tempdir().map_err(|error| format!("无法创建项目包组件暂存目录: {error}"))?;
    let mut inputs = Vec::with_capacity(manifests.len());
    let mut signed_plugins = 0_usize;
    let mut local_mappings = 0_usize;
    for manifest in manifests {
        let plugin_id = manifest.plugin_id.clone();
        if is_local_manifest(&manifest, local_mapping_root) {
            let path = temporary.path().join(format!("{plugin_id}.ssdev-mapping"));
            local_mappings::export_bundle(local_mapping_root, &plugin_id, &path)?;
            inputs.push(project_bundle::ProjectBundleInput {
                plugin_id,
                version: None,
                kind: project_bundle::ProjectComponentKind::LocalMapping,
                path,
            });
            local_mappings += 1;
        } else {
            let trust_store = trust_store.ok_or_else(|| {
                "开发态未签名插件不能进入项目部署包，请使用本地映射或正式签名插件".to_owned()
            })?;
            let metadata = manifest
                .metadata
                .as_ref()
                .ok_or_else(|| format!("签名插件 [{plugin_id}] 缺少版本元数据"))?;
            let path = temporary.path().join(format!("{plugin_id}.ssdev-plugin"));
            let identity = webplus_plugin_package::create_deterministic_package(
                &manifest.plugin_dir,
                &path,
                trust_store,
            )
            .map_err(|error| format!("无法导出签名插件 [{plugin_id}]: {error}"))?;
            if identity.plugin_id != plugin_id {
                return Err(format!("签名插件 [{plugin_id}] 封装后身份发生变化"));
            }
            inputs.push(project_bundle::ProjectBundleInput {
                plugin_id,
                version: Some(metadata.version.to_string()),
                kind: project_bundle::ProjectComponentKind::SignedPlugin,
                path,
            });
            signed_plugins += 1;
        }
    }
    let inputs = project_bundle::prepare_inputs(inputs)?;
    Ok(StagedProjectExport {
        temporary,
        inputs,
        signed_plugins,
        local_mappings,
    })
}

fn prepare_project_export_candidates(
    inputs: Vec<project_bundle::PreparedProjectBundleInput>,
    plugin_root: &std::path::Path,
    local_mapping_root: &std::path::Path,
    trust_store: Option<&TrustStore>,
    desktop_version: &semver::Version,
) -> Result<Vec<PreparedProjectComponent>, String> {
    let mut candidates = Vec::with_capacity(inputs.len());
    for input in inputs {
        match input.kind() {
            project_bundle::ProjectComponentKind::SignedPlugin => {
                let trust_store =
                    trust_store.ok_or_else(|| "正式项目导出要求启用插件签名信任".to_owned())?;
                let prepared = PreparedPlugin::prepare(input.path(), plugin_root, trust_store)
                    .map_err(|error| {
                        format!("无法复核待导出的签名插件 [{}]: {error}", input.plugin_id())
                    })?;
                ensure_signed_plugin_compatible(prepared.manifest(), desktop_version)?;
                let actual_version = prepared.metadata().version.to_string();
                if prepared.identity().plugin_id != input.plugin_id()
                    || input.version() != Some(actual_version.as_str())
                {
                    return Err(format!(
                        "待导出签名插件 [{}] 的封装身份或版本不一致",
                        input.plugin_id()
                    ));
                }
                candidates.push(PreparedProjectComponent::Signed(prepared));
            }
            project_bundle::ProjectComponentKind::LocalMapping => {
                if input.version().is_some() {
                    return Err(format!(
                        "待导出本地映射 [{}] 不应声明版本",
                        input.plugin_id()
                    ));
                }
                let prepared = local_mappings::prepare_import(local_mapping_root, input.path())?;
                if prepared.plugin_id() != input.plugin_id() {
                    return Err(format!(
                        "待导出本地映射 [{}] 的封装身份不一致",
                        input.plugin_id()
                    ));
                }
                candidates.push(PreparedProjectComponent::Local(prepared));
            }
        }
    }
    Ok(candidates)
}

fn validate_project_delivery_routes(
    desktop_state: &desktop::DesktopState,
    config: &ssdev_config::DesktopConfig,
    manifests: &[PluginManifest],
) -> Result<(), String> {
    PluginController::validate_manifests(manifests).map_err(|error| error.to_string())?;
    let coverage = desktop_state.plugin_route_policy_coverage(config, manifests)?;
    if coverage.uncovered_origin_count > 0 || coverage.uncovered_route_count > 0 {
        return Err(format!(
            "项目来源与插件能力授权不完整：{} 个来源无法访问任何能力，{} 条调用路由未被当前来源授权",
            coverage.uncovered_origin_count, coverage.uncovered_route_count
        ));
    }
    Ok(())
}

fn ensure_project_export_runtime_matches(
    declared_service_count: usize,
    active_service_count: usize,
) -> Result<(), String> {
    if declared_service_count != active_service_count {
        return Err(format!(
            "当前项目运行状态不一致：磁盘插件声明 {declared_service_count} 个服务，但控制器只有 {active_service_count} 个活动服务；请先重新加载插件或重启客户端"
        ));
    }
    Ok(())
}

fn ensure_project_export_active_manifests_match(matches: bool) -> Result<(), String> {
    if !matches {
        return Err(
            "当前项目运行状态不一致：磁盘插件完整清单与控制器活动清单存在漂移；请先执行安全重新扫描或重启客户端"
                .into(),
        );
    }
    Ok(())
}

async fn preflight_manifests(
    state: &BridgeState,
    manifests: &[PluginManifest],
    subject: &str,
) -> Result<usize, String> {
    let mut preflighted_hosts = 0_usize;
    for manifest in manifests {
        let report = state
            .controller
            .preflight_candidate_manifest(manifest)
            .await
            .map_err(|error| {
                state
                    .plugin_preflight_failures
                    .fetch_add(1, Ordering::AcqRel);
                format!(
                    "{subject} [{}] 宿主预检失败 ({})：{error}",
                    manifest.plugin_id,
                    error.diagnostic_code()
                )
            })?;
        preflighted_hosts = preflighted_hosts.saturating_add(report.hosts_started);
    }
    state
        .preflighted_plugin_hosts
        .fetch_add(preflighted_hosts, Ordering::AcqRel);
    Ok(preflighted_hosts)
}

fn classify_project_component_action(
    kind: project_bundle::ProjectComponentKind,
    current_exists: bool,
    current_version: Option<&semver::Version>,
    candidate_version: Option<&semver::Version>,
) -> &'static str {
    if !current_exists {
        return "install";
    }
    match kind {
        project_bundle::ProjectComponentKind::LocalMapping => "replace",
        project_bundle::ProjectComponentKind::SignedPlugin => {
            if current_version
                .zip(candidate_version)
                .is_some_and(|(current, candidate)| candidate > current)
            {
                "upgrade"
            } else {
                "reinstall"
            }
        }
    }
}

fn project_import_state_digest(
    config: &ssdev_config::DesktopConfig,
    manifests: &[PluginManifest],
    local_mapping_root: &std::path::Path,
) -> Result<String, String> {
    let mut hasher = Sha256::new();
    hasher.update(b"SSDEV-PROJECT-IMPORT-STATE\0");
    let config = serde_json::to_vec(config).map_err(|error| error.to_string())?;
    hash_plan_field(&mut hasher, &config);

    let mut manifests = manifests.iter().collect::<Vec<_>>();
    manifests.sort_by(|left, right| left.plugin_id.cmp(&right.plugin_id));
    let temporary =
        tempfile::tempdir().map_err(|error| format!("无法创建项目导入基线暂存目录: {error}"))?;
    for (index, manifest) in manifests.into_iter().enumerate() {
        hash_plan_field(&mut hasher, manifest.plugin_id.as_bytes());
        if is_local_manifest(manifest, local_mapping_root) {
            hash_plan_field(&mut hasher, b"local-mapping");
            let package = temporary
                .path()
                .join(format!("mapping-{index}.ssdev-mapping"));
            local_mappings::export_bundle(local_mapping_root, &manifest.plugin_id, &package)?;
            hash_plan_file(&mut hasher, &package)?;
        } else {
            hash_plan_field(&mut hasher, b"signed-package");
            let key_id = match read_identity(&manifest.plugin_dir) {
                Ok(identity) => identity.key_id,
                Err(_) if allow_unsigned_plugins() => "debug-unsigned".to_owned(),
                Err(error) => return Err(error.to_string()),
            };
            let material =
                prepare_signing_material(&manifest.plugin_dir, &manifest.plugin_id, &key_id)
                    .map_err(|error| error.to_string())?;
            hash_plan_field(&mut hasher, &material.payload);
        }
    }
    Ok(lowercase_hex(&hasher.finalize()))
}

fn project_import_plan_id(
    bundle_sha256: &str,
    current_state_sha256: &str,
    desktop_version: &semver::Version,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"SSDEV-PROJECT-IMPORT-PLAN\0");
    hash_plan_field(&mut hasher, bundle_sha256.as_bytes());
    hash_plan_field(&mut hasher, current_state_sha256.as_bytes());
    hash_plan_field(&mut hasher, desktop_version.to_string().as_bytes());
    lowercase_hex(&hasher.finalize())
}

fn hash_plan_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn hash_plan_file(hasher: &mut Sha256, path: &std::path::Path) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("无法读取项目导入基线文件: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("项目导入基线文件不是安全普通文件".into());
    }
    hasher.update(metadata.len().to_be_bytes());
    let mut file =
        fs::File::open(path).map_err(|error| format!("无法打开项目导入基线文件: {error}"))?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("无法计算项目导入基线摘要: {error}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(())
}

fn lowercase_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn open_project_bundle_for_mode(
    source: &std::path::Path,
    trust_store: Option<&TrustStore>,
    strict_signature: bool,
) -> Result<
    (
        project_bundle::OpenedProjectBundle,
        bool,
        Option<String>,
        String,
    ),
    String,
> {
    if strict_signature {
        let trust_store = trust_store.ok_or_else(|| "正式项目包要求启用组织签名信任".to_owned())?;
        let signature = project_bundle::signature_path(source)?;
        project_bundle::open_verified(source, &signature, trust_store).map(|(opened, verified)| {
            let bundle_sha256 = verified.summary.bundle_sha256;
            (opened, true, Some(verified.key_id), bundle_sha256)
        })
    } else {
        project_bundle::open_with_signing_material(source)
            .map(|(opened, material)| (opened, false, None, material.summary.bundle_sha256))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginInstallResult {
    plugin_id: String,
    plugin_version: String,
    service_count: usize,
    quarantined_plugins: usize,
    replaced_existing: bool,
    preflighted_hosts: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginReloadResult {
    service_count: usize,
    quarantined_plugins: usize,
    preflighted_hosts: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginInventoryResult {
    plugins: Vec<PluginInventoryItem>,
    quarantined: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginInventoryItem {
    plugin_id: String,
    version: Option<String>,
    desktop_version_requirement: Option<String>,
    display_name: String,
    source: &'static str,
    services: Vec<ServiceInventoryItem>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceInventoryItem {
    service_id: String,
    architecture: PluginArchitecture,
    main_type: String,
    main_class: String,
    calling_convention: String,
    charset: String,
    cacheable: bool,
    timeout_ms: u64,
    dependency_count: usize,
    method_count: usize,
    methods: Vec<MethodInventoryItem>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MethodInventoryItem {
    request_name: String,
    native_name: String,
    return_type: String,
    parameter_count: usize,
    timeout_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalMappingInventoryResult {
    mappings: Vec<local_mappings::LocalMappingDefinition>,
    failures: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalMappingSaveResult {
    plugin_id: String,
    service_count: usize,
    preflighted_hosts: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginDebugResult {
    elapsed_ms: u128,
    response: InvokeResponse,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DebugCaseRunResult {
    name: String,
    service_id: String,
    method: String,
    expected_res_code: i32,
    actual_res_code: i32,
    data_asserted: bool,
    data_passed: bool,
    data_mismatch_path: Option<String>,
    elapsed_ms: u128,
    passed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginUpdateCheckResult {
    catalog_issued_at: u64,
    catalog_expires_at: u64,
    updates: Vec<PluginUpdateItem>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginUpdateItem {
    plugin_id: String,
    installed_version: Option<String>,
    available_version: Option<String>,
    latest_catalog_version: Option<String>,
    install_plan_id: Option<String>,
    installed_version_withdrawn: bool,
    withdrawal_reason: Option<CatalogWithdrawalReason>,
    catalog_available: bool,
    compatibility_limited: bool,
    update_available: bool,
}

#[tauri::command]
async fn install_plugin_package(
    caller: WebviewWindow,
    state: State<'_, BridgeState>,
    package_path: PathBuf,
) -> Result<PluginInstallResult, String> {
    desktop::require_control(&caller)?;
    let _install = state.install_lock.lock().await;
    recover_plugin_store(&state)?;
    let trust_store = state
        .trust_store
        .as_ref()
        .cloned()
        .ok_or_else(|| "开发态未签名模式不允许使用插件安装器".to_owned())?;
    let prepared = prepare_local_package(
        package_path,
        state.plugin_root.clone(),
        Arc::clone(&trust_store),
    )
    .await?;
    activate_prepared_plugin(&state, &trust_store, prepared, None).await
}

#[tauri::command]
async fn install_plugin_from_catalog(
    caller: WebviewWindow,
    bridge_state: State<'_, BridgeState>,
    desktop_state: State<'_, desktop::DesktopState>,
    plugin_id: String,
    version: String,
    expected_plan_id: String,
) -> Result<PluginInstallResult, String> {
    desktop::require_control(&caller)?;
    if !is_lowercase_sha256(&expected_plan_id) {
        return Err("插件更新确认标识无效，请重新检查更新".to_owned());
    }
    let _install = bridge_state.install_lock.lock().await;
    recover_plugin_store(&bridge_state)?;
    let trust_store = bridge_state
        .trust_store
        .as_ref()
        .cloned()
        .ok_or_else(|| "开发态未签名模式不允许使用插件仓库".to_owned())?;
    let (catalog_url, signature_url) = desktop_state
        .config
        .snapshot()
        .plugin_catalog_urls()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "尚未配置签名插件仓库".to_owned())?;
    let requested_version = semver::Version::parse(&version)
        .map_err(|error| format!("请求的插件版本不是合法 SemVer: {error}"))?;
    let catalog = fetch_catalog(
        &bridge_state.repository_client,
        &catalog_url,
        &signature_url,
        &trust_store,
        SystemTime::now(),
    )
    .await
    .map_err(|error| error.to_string())?;
    let entry = catalog
        .select(&plugin_id, Some(&requested_version))
        .cloned()
        .ok_or_else(|| format!("签名仓库中没有插件 [{plugin_id}] 的匹配版本"))?;
    let catalog_signing_key_id = catalog
        .signing_key_id()
        .ok_or_else(|| "签名插件仓库没有已验证的目录签名身份".to_owned())?;
    let desktop_requirement = entry.desktop_version_requirement.as_ref().ok_or_else(|| {
        format!(
            "插件 [{} {}] 未声明支持的 SSDEV Desktop 版本",
            entry.plugin_id, entry.version
        )
    })?;
    if !desktop_requirement.matches(&bridge_state.desktop_version) {
        return Err(format!(
            "插件 [{} {}] 不支持当前 SSDEV Desktop {}；要求 {}",
            entry.plugin_id, entry.version, bridge_state.desktop_version, desktop_requirement
        ));
    }
    let installed = inspect_plugins(
        &bridge_state.plugin_root,
        Some(&trust_store),
        &bridge_state.desktop_version,
    )?;
    let installed_manifest = installed
        .manifests
        .iter()
        .find(|manifest| manifest.plugin_id == plugin_id);
    let current_state_sha256 = plugin_update_installed_state_digest(
        &bridge_state.plugin_root,
        &plugin_id,
        installed_manifest,
    )?;
    let actual_plan_id = plugin_update_plan_id(
        &entry,
        catalog_signing_key_id,
        &current_state_sha256,
        &bridge_state.desktop_version,
    )?;
    ensure_plugin_update_plan_matches(&expected_plan_id, &actual_plan_id)?;
    let temporary_directory = bridge_state.plugin_root.join(".downloads");
    let downloaded = download_package(
        &bridge_state.repository_client,
        &entry,
        &temporary_directory,
    )
    .await
    .map_err(|error| error.to_string())?;
    let prepared = prepare_local_package(
        downloaded.path().to_path_buf(),
        bridge_state.plugin_root.clone(),
        Arc::clone(&trust_store),
    )
    .await?;
    verify_catalog_identity(&entry, &prepared)?;
    activate_prepared_plugin(
        &bridge_state,
        &trust_store,
        prepared,
        Some(&current_state_sha256),
    )
    .await
}

#[tauri::command]
async fn check_plugin_updates(
    caller: WebviewWindow,
    bridge_state: State<'_, BridgeState>,
    desktop_state: State<'_, desktop::DesktopState>,
    plugin_id: Option<String>,
) -> Result<PluginUpdateCheckResult, String> {
    desktop::require_control(&caller)?;
    let requested_plugin_id = plugin_id
        .as_deref()
        .map(str::trim)
        .filter(|plugin_id| !plugin_id.is_empty());
    if plugin_id.is_some() && requested_plugin_id.is_none() {
        return Err("插件 ID 不能为空".to_owned());
    }

    let _install = bridge_state.install_lock.lock().await;
    recover_plugin_store(&bridge_state)?;
    let trust_store = bridge_state
        .trust_store
        .as_ref()
        .cloned()
        .ok_or_else(|| "开发态未签名模式不允许使用插件仓库".to_owned())?;
    let (catalog_url, signature_url) = desktop_state
        .config
        .snapshot()
        .plugin_catalog_urls()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "尚未配置签名插件仓库".to_owned())?;
    let catalog = fetch_catalog(
        &bridge_state.repository_client,
        &catalog_url,
        &signature_url,
        &trust_store,
        SystemTime::now(),
    )
    .await
    .map_err(|error| error.to_string())?;
    let installed = inspect_plugins(
        &bridge_state.plugin_root,
        Some(&trust_store),
        &bridge_state.desktop_version,
    )?;
    let catalog_signing_key_id = catalog
        .signing_key_id()
        .ok_or_else(|| "签名插件仓库没有已验证的目录签名身份".to_owned())?;
    let updates = collect_plugin_updates(
        &installed.manifests,
        &bridge_state.plugin_root,
        &catalog,
        catalog_signing_key_id,
        requested_plugin_id,
        &bridge_state.desktop_version,
    )?;
    Ok(PluginUpdateCheckResult {
        catalog_issued_at: catalog.issued_at(),
        catalog_expires_at: catalog.expires_at(),
        updates,
    })
}

fn collect_plugin_updates(
    installed: &[PluginManifest],
    plugin_root: &std::path::Path,
    catalog: &PluginCatalog,
    catalog_signing_key_id: &str,
    requested_plugin_id: Option<&str>,
    desktop_version: &semver::Version,
) -> Result<Vec<PluginUpdateItem>, String> {
    let mut plugin_ids = if let Some(plugin_id) = requested_plugin_id {
        vec![plugin_id.to_owned()]
    } else {
        installed
            .iter()
            .map(|manifest| manifest.plugin_id.clone())
            .collect()
    };
    plugin_ids.sort();
    plugin_ids.dedup();
    plugin_ids
        .into_iter()
        .map(|plugin_id| {
            let installed_manifest = installed
                .iter()
                .find(|manifest| manifest.plugin_id == plugin_id);
            let installed_version = installed_manifest
                .and_then(|manifest| manifest.metadata.as_ref())
                .map(|metadata| &metadata.version);
            let latest_catalog_version =
                catalog.select(&plugin_id, None).map(|entry| &entry.version);
            let withdrawal =
                installed_version.and_then(|version| catalog.withdrawal(&plugin_id, version));
            let available_entry = catalog.select_compatible(&plugin_id, None, desktop_version);
            let available_version = available_entry.map(|entry| &entry.version);
            let update_available = is_plugin_update_available(installed_version, available_version);
            let install_plan_id = if update_available {
                let entry = available_entry.expect("an available version must have an entry");
                let current_state_sha256 = plugin_update_installed_state_digest(
                    plugin_root,
                    &plugin_id,
                    installed_manifest,
                )?;
                Some(plugin_update_plan_id(
                    entry,
                    catalog_signing_key_id,
                    &current_state_sha256,
                    desktop_version,
                )?)
            } else {
                None
            };
            Ok(PluginUpdateItem {
                plugin_id,
                installed_version: installed_version.map(ToString::to_string),
                available_version: available_version.map(ToString::to_string),
                latest_catalog_version: latest_catalog_version.map(ToString::to_string),
                install_plan_id,
                installed_version_withdrawn: withdrawal.is_some(),
                withdrawal_reason: withdrawal.map(|withdrawal| withdrawal.reason),
                catalog_available: latest_catalog_version.is_some(),
                compatibility_limited: latest_catalog_version != available_version,
                update_available,
            })
        })
        .collect()
}

fn is_plugin_update_available(
    installed: Option<&semver::Version>,
    available: Option<&semver::Version>,
) -> bool {
    match (installed, available) {
        (Some(installed), Some(available)) => available > installed,
        (None, Some(_)) => true,
        (_, None) => false,
    }
}

fn plugin_update_installed_state_digest(
    plugin_root: &std::path::Path,
    plugin_id: &str,
    installed: Option<&PluginManifest>,
) -> Result<String, String> {
    let mut hasher = Sha256::new();
    hasher.update(b"SSDEV-PLUGIN-UPDATE-STATE\0");
    hash_plan_field(&mut hasher, plugin_id.as_bytes());
    match installed {
        Some(manifest) => {
            if manifest.plugin_id != plugin_id || !manifest.plugin_dir.starts_with(plugin_root) {
                return Err("插件更新基线不属于目标签名插件目录".to_owned());
            }
            let identity =
                read_identity(&manifest.plugin_dir).map_err(|error| error.to_string())?;
            if identity.plugin_id != plugin_id {
                return Err("插件更新基线签名身份与目标插件不一致".to_owned());
            }
            let material =
                prepare_signing_material(&manifest.plugin_dir, plugin_id, &identity.key_id)
                    .map_err(|error| error.to_string())?;
            hash_plan_field(&mut hasher, b"installed");
            hash_plan_field(&mut hasher, identity.key_id.as_bytes());
            hash_plan_field(&mut hasher, &material.payload);
        }
        None => {
            let target = plugin_root.join(plugin_id);
            match fs::symlink_metadata(&target) {
                Ok(_) => {
                    return Err(format!(
                        "插件 [{plugin_id}] 的本机目录存在但未通过签名或兼容性检查；请先处理隔离项再检查更新"
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    hash_plan_field(&mut hasher, b"not-installed");
                }
                Err(error) => {
                    return Err(format!("无法读取插件 [{plugin_id}] 的更新基线: {error}"));
                }
            }
        }
    }
    Ok(lowercase_hex(&hasher.finalize()))
}

fn plugin_update_plan_id(
    entry: &CatalogEntry,
    catalog_signing_key_id: &str,
    current_state_sha256: &str,
    desktop_version: &semver::Version,
) -> Result<String, String> {
    let entry =
        serde_json::to_vec(entry).map_err(|error| format!("无法生成插件更新确认标识: {error}"))?;
    let mut hasher = Sha256::new();
    hasher.update(b"SSDEV-PLUGIN-UPDATE-PLAN\0");
    hash_plan_field(&mut hasher, &entry);
    hash_plan_field(&mut hasher, catalog_signing_key_id.as_bytes());
    hash_plan_field(&mut hasher, current_state_sha256.as_bytes());
    hash_plan_field(&mut hasher, desktop_version.to_string().as_bytes());
    Ok(lowercase_hex(&hasher.finalize()))
}

fn ensure_plugin_update_plan_matches(expected: &str, actual: &str) -> Result<(), String> {
    if expected != actual {
        return Err(
            "签名仓库条目或当前插件状态在确认后发生变化，请重新检查更新并确认目标版本".to_owned(),
        );
    }
    Ok(())
}

async fn prepare_local_package(
    package_path: PathBuf,
    plugin_root: PathBuf,
    trust_store: Arc<TrustStore>,
) -> Result<PreparedPlugin, String> {
    tokio::task::spawn_blocking(move || {
        PreparedPlugin::prepare(&package_path, &plugin_root, &trust_store)
    })
    .await
    .map_err(|error| format!("插件安装任务异常终止: {error}"))?
    .map_err(|error| error.to_string())
}

fn verify_catalog_identity(entry: &CatalogEntry, prepared: &PreparedPlugin) -> Result<(), String> {
    if prepared.identity().plugin_id != entry.plugin_id
        || prepared.metadata().version != entry.version
        || prepared.metadata().desktop_version_requirement != entry.desktop_version_requirement
    {
        return Err(format!(
            "下载包身份或兼容范围与签名仓库不一致：期望 {} {} [{}]，实际 {} {} [{}]",
            entry.plugin_id,
            entry.version,
            entry
                .desktop_version_requirement
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "未声明".to_owned()),
            prepared.identity().plugin_id,
            prepared.metadata().version,
            prepared
                .metadata()
                .desktop_version_requirement
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "未声明".to_owned())
        ));
    }
    Ok(())
}

async fn activate_prepared_plugin(
    state: &BridgeState,
    trust_store: &TrustStore,
    prepared: PreparedPlugin,
    expected_current_state_sha256: Option<&str>,
) -> Result<PluginInstallResult, String> {
    let plugin_root = state.plugin_root.clone();

    ensure_signed_plugin_compatible(prepared.manifest(), &state.desktop_version)?;

    let plugin_id = prepared.identity().plugin_id.clone();
    let plugin_version = prepared.metadata().version.clone();
    let before = inspect_all_plugins(
        &plugin_root,
        &state.local_mapping_root,
        Some(trust_store),
        &state.desktop_version,
    )?;
    let previous_manifest = before
        .manifests
        .iter()
        .find(|manifest| {
            manifest.plugin_id == plugin_id
                && !is_local_manifest(manifest, &state.local_mapping_root)
        })
        .cloned();
    if let Some(expected) = expected_current_state_sha256 {
        let actual = plugin_update_installed_state_digest(
            &plugin_root,
            &plugin_id,
            previous_manifest.as_ref(),
        )?;
        ensure_plugin_update_plan_matches(expected, &actual)?;
    }
    if before.manifests.iter().any(|manifest| {
        manifest.plugin_id == plugin_id && is_local_manifest(manifest, &state.local_mapping_root)
    }) {
        return Err(format!(
            "签名插件 ID [{plugin_id}] 与现有本地映射冲突，请先删除或重命名本地映射"
        ));
    }
    let current_version = previous_manifest
        .as_ref()
        .and_then(|manifest| manifest.metadata.as_ref())
        .map(|metadata| &metadata.version);
    ensure_upgrade_allowed(current_version, &plugin_version)?;
    let replaced_existing = plugin_root.join(&plugin_id).exists();
    let mut candidates = before.manifests.clone();
    candidates.retain(|manifest| manifest.plugin_id != plugin_id);
    candidates.push(prepared.manifest().clone());
    PluginController::validate_manifests(&candidates).map_err(|error| error.to_string())?;

    let preflight = match state
        .controller
        .preflight_candidate_manifest(prepared.manifest())
        .await
    {
        Ok(preflight) => preflight,
        Err(error) => {
            state
                .plugin_preflight_failures
                .fetch_add(1, Ordering::AcqRel);
            let diagnostic_code = error.diagnostic_code();
            return Err(format!(
                "候选插件宿主预检失败 ({diagnostic_code})，未修改当前插件"
            ));
        }
    };

    let maintenance = state
        .controller
        .begin_plugin_maintenance(&plugin_id)
        .await
        .map_err(|error| {
            format!(
                "插件维护窗口不可用 ({})，未修改当前插件",
                error.diagnostic_code()
            )
        })?;
    let activation = prepared.activate().map_err(|error| error.to_string())?;
    let installed = match inspect_all_plugins(
        &plugin_root,
        &state.local_mapping_root,
        Some(trust_store),
        &state.desktop_version,
    ) {
        Ok(installed) => installed,
        Err(error) => {
            activation
                .rollback()
                .map_err(|rollback| format!("{error}; 插件回滚同时失败: {rollback}"))?;
            maintenance
                .replace_manifest(previous_manifest.as_ref())
                .await
                .map_err(|reload| format!("{error}; 恢复旧路由失败: {reload}"))?;
            return Err(error);
        }
    };
    let Some(installed_manifest) = installed
        .manifests
        .iter()
        .find(|manifest| {
            manifest.plugin_id == plugin_id
                && !is_local_manifest(manifest, &state.local_mapping_root)
        })
        .cloned()
    else {
        activation
            .rollback()
            .map_err(|rollback| format!("新插件未进入已验证清单；插件回滚同时失败: {rollback}"))?;
        maintenance
            .replace_manifest(previous_manifest.as_ref())
            .await
            .map_err(|reload| format!("新插件未进入已验证清单；恢复旧路由失败: {reload}"))?;
        return Err("新插件未进入已验证清单，已恢复旧插件".into());
    };
    if let Err(error) = maintenance
        .replace_manifest(Some(&installed_manifest))
        .await
    {
        activation
            .rollback()
            .map_err(|rollback| format!("新插件路由无效: {error}; 插件回滚同时失败: {rollback}"))?;
        maintenance
            .replace_manifest(previous_manifest.as_ref())
            .await
            .map_err(|reload| format!("新插件路由无效: {error}; 恢复旧路由失败: {reload}"))?;
        return Err(format!("新插件路由无效: {error}"));
    }
    if let Err(error) = activation.commit() {
        maintenance
            .replace_manifest(previous_manifest.as_ref())
            .await
            .map_err(|reload| format!("插件事务提交失败: {error}; 恢复旧路由失败: {reload}"))?;
        return Err(format!("插件事务提交失败，已恢复旧插件: {error}"));
    }
    state
        .plugin_load_failures
        .store(installed.failures.len(), Ordering::Release);
    state
        .plugin_count
        .store(installed.manifests.len(), Ordering::Release);
    state
        .preflighted_plugin_hosts
        .fetch_add(preflight.hosts_started, Ordering::AcqRel);
    tracing::info!(
        event_code = "plugin-activated",
        plugin_id,
        plugin_version = %plugin_version,
        replaced_existing,
        preflighted_hosts = preflight.hosts_started,
        "signed plugin activated"
    );
    Ok(PluginInstallResult {
        plugin_id,
        plugin_version: plugin_version.to_string(),
        service_count: installed
            .manifests
            .iter()
            .map(|item| item.services.len())
            .sum(),
        quarantined_plugins: installed.failures.len(),
        replaced_existing,
        preflighted_hosts: preflight.hosts_started,
    })
}

#[tauri::command]
async fn uninstall_signed_plugin(
    caller: WebviewWindow,
    state: State<'_, BridgeState>,
    plugin_id: String,
) -> Result<(), String> {
    desktop::require_control(&caller)?;
    let _install = state.install_lock.lock().await;
    recover_plugin_store(&state)?;
    let before = inspect_all_plugins(
        &state.plugin_root,
        &state.local_mapping_root,
        state.trust_store.as_deref(),
        &state.desktop_version,
    )?;
    let baseline_failures = before.failures.clone();
    let previous_manifest = before
        .manifests
        .iter()
        .find(|manifest| {
            manifest.plugin_id == plugin_id
                && !is_local_manifest(manifest, &state.local_mapping_root)
        })
        .cloned()
        .ok_or_else(|| format!("签名插件 [{plugin_id}] 不存在"))?;
    let maintenance = state
        .controller
        .begin_plugin_maintenance(&plugin_id)
        .await
        .map_err(|error| {
            format!(
                "插件维护窗口不可用 ({})，未修改当前插件",
                error.diagnostic_code()
            )
        })?;
    let root = state.plugin_root.clone();
    let removal = tokio::task::spawn_blocking({
        let plugin_id = plugin_id.clone();
        move || prepare_plugin_removal(&root, &plugin_id)
    })
    .await
    .map_err(|_| "插件卸载任务异常终止".to_owned())?
    .map_err(|error| error.to_string())?;
    let installed = match inspect_all_plugins(
        &state.plugin_root,
        &state.local_mapping_root,
        state.trust_store.as_deref(),
        &state.desktop_version,
    ) {
        Ok(installed) if same_plugin_failures(&baseline_failures, &installed.failures) => installed,
        Ok(_) => {
            removal.rollback().map_err(|rollback| {
                format!("卸载后插件隔离清单发生变化；恢复原插件同时失败: {rollback}")
            })?;
            return Err("卸载后插件隔离清单发生变化，已恢复原插件".into());
        }
        Err(error) => {
            removal
                .rollback()
                .map_err(|rollback| format!("{error}; 恢复原插件同时失败: {rollback}"))?;
            return Err(format!("无法验证卸载后的插件清单，已恢复原插件: {error}"));
        }
    };
    if let Err(error) = maintenance.replace_manifest(None).await {
        removal
            .rollback()
            .map_err(|rollback| format!("卸载路由失败: {error}; 恢复原插件同时失败: {rollback}"))?;
        maintenance
            .replace_manifest(Some(&previous_manifest))
            .await
            .map_err(|restore| format!("卸载路由失败: {error}; 恢复原路由失败: {restore}"))?;
        return Err(format!("卸载路由失败，已恢复原插件: {error}"));
    }
    if let Err(error) = removal.commit() {
        maintenance
            .replace_manifest(Some(&previous_manifest))
            .await
            .map_err(|restore| format!("卸载事务提交失败: {error}; 恢复原路由失败: {restore}"))?;
        return Err(format!("卸载事务提交失败，已恢复原插件: {error}"));
    }
    state
        .plugin_load_failures
        .store(installed.failures.len(), Ordering::Release);
    state
        .plugin_count
        .store(installed.manifests.len(), Ordering::Release);
    tracing::info!(
        event_code = "plugin-uninstalled",
        plugin_id,
        "signed plugin uninstalled"
    );
    Ok(())
}

#[tauri::command]
async fn reload_plugins(
    caller: WebviewWindow,
    state: State<'_, BridgeState>,
) -> Result<PluginReloadResult, String> {
    desktop::require_control(&caller)?;
    let _install = state.install_lock.lock().await;
    recover_plugin_store(&state)?;
    let plugins = inspect_all_plugins(
        &state.plugin_root,
        &state.local_mapping_root,
        state.trust_store.as_deref(),
        &state.desktop_version,
    )?;
    PluginController::validate_manifests(&plugins.manifests).map_err(|error| error.to_string())?;
    let preflighted_hosts =
        preflight_manifests(&state, &plugins.manifests, "待重载插件或映射").await?;
    state
        .controller
        .replace_manifests(&plugins.manifests)
        .await
        .map_err(|error| error.to_string())?;
    state
        .plugin_load_failures
        .store(plugins.failures.len(), Ordering::Release);
    state
        .plugin_count
        .store(plugins.manifests.len(), Ordering::Release);
    tracing::info!(
        event_code = "plugins-reloaded",
        plugin_count = plugins.manifests.len(),
        quarantined_count = plugins.failures.len(),
        preflighted_hosts,
        "plugin routes reloaded"
    );
    Ok(PluginReloadResult {
        service_count: plugins
            .manifests
            .iter()
            .map(|item| item.services.len())
            .sum(),
        quarantined_plugins: plugins.failures.len(),
        preflighted_hosts,
    })
}

#[tauri::command]
async fn plugin_inventory(
    caller: WebviewWindow,
    state: State<'_, BridgeState>,
) -> Result<PluginInventoryResult, String> {
    desktop::require_control(&caller)?;
    let _install = state.install_lock.lock().await;
    recover_plugin_store(&state)?;
    let inspected = inspect_all_plugins(
        &state.plugin_root,
        &state.local_mapping_root,
        state.trust_store.as_deref(),
        &state.desktop_version,
    )?;
    let plugins = inspected
        .manifests
        .into_iter()
        .map(|manifest| {
            let source = if is_local_manifest(&manifest, &state.local_mapping_root) {
                "local-mapping"
            } else {
                "signed-package"
            };
            let version = manifest
                .metadata
                .as_ref()
                .map(|metadata| metadata.version.to_string());
            let desktop_version_requirement = if source == "signed-package" {
                manifest
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.desktop_version_requirement.as_ref())
                    .map(ToString::to_string)
            } else {
                None
            };
            let display_name = manifest
                .metadata
                .as_ref()
                .map(|metadata| metadata.display_name.trim())
                .filter(|name| !name.is_empty())
                .unwrap_or(&manifest.plugin_id)
                .to_owned();
            let services = manifest
                .services
                .into_iter()
                .map(service_inventory_item)
                .collect();
            PluginInventoryItem {
                plugin_id: manifest.plugin_id,
                version,
                desktop_version_requirement,
                display_name,
                source,
                services,
            }
        })
        .collect();
    Ok(PluginInventoryResult {
        plugins,
        quarantined: inspected.failures,
    })
}

#[tauri::command]
fn inspect_native_component(
    caller: WebviewWindow,
    path: PathBuf,
) -> Result<local_mappings::NativeComponentInspection, String> {
    desktop::require_control(&caller)?;
    local_mappings::inspect_component(&path)
}

#[tauri::command]
async fn discover_registered_com_components(
    caller: WebviewWindow,
    query: String,
    architecture: PluginArchitecture,
) -> Result<com_discovery::ComDiscoveryResult, String> {
    desktop::require_control(&caller)?;
    tokio::task::spawn_blocking(move || com_discovery::discover(&query, architecture))
        .await
        .map_err(|_| "COM 注册发现任务异常终止".to_owned())?
}

#[tauri::command]
async fn local_mapping_inventory(
    caller: WebviewWindow,
    state: State<'_, BridgeState>,
) -> Result<LocalMappingInventoryResult, String> {
    desktop::require_control(&caller)?;
    let _install = state.install_lock.lock().await;
    let inspected = inspect_plugins(&state.local_mapping_root, None, &state.desktop_version)?;
    let mut mappings = Vec::new();
    let mut failures = inspected.failures;
    for manifest in inspected.manifests {
        match local_mappings::validate_installed_manifest(&manifest)
            .and_then(|()| local_mappings::load_definition(&manifest.plugin_dir))
        {
            Ok(definition) => mappings.push(definition),
            Err(error) => failures.push(format!("[{}] {error}", manifest.plugin_id)),
        }
    }
    mappings.sort_by(|left, right| left.plugin_id.cmp(&right.plugin_id));
    Ok(LocalMappingInventoryResult { mappings, failures })
}

#[tauri::command]
async fn save_local_mapping(
    caller: WebviewWindow,
    state: State<'_, BridgeState>,
    definition: local_mappings::LocalMappingDefinition,
) -> Result<LocalMappingSaveResult, String> {
    desktop::require_control(&caller)?;
    let _install = state.install_lock.lock().await;
    let plugin_id = definition.plugin_id.clone();
    if state.plugin_root.join(&plugin_id).exists() {
        return Err(format!(
            "映射 ID [{plugin_id}] 与签名插件冲突，请使用其他 ID"
        ));
    }
    let root = state.local_mapping_root.clone();
    let prepared = tokio::task::spawn_blocking(move || local_mappings::prepare(&root, definition))
        .await
        .map_err(|_| "本地映射准备任务异常终止".to_owned())??;
    activate_prepared_local_mapping(&state, prepared).await
}

#[tauri::command]
async fn export_local_mapping(
    caller: WebviewWindow,
    state: State<'_, BridgeState>,
    plugin_id: String,
    destination: PathBuf,
) -> Result<(), String> {
    desktop::require_control(&caller)?;
    let _install = state.install_lock.lock().await;
    let root = state.local_mapping_root.clone();
    tokio::task::spawn_blocking(move || {
        local_mappings::export_bundle(&root, &plugin_id, &destination)
    })
    .await
    .map_err(|_| "映射导出任务异常终止".to_owned())?
}

#[tauri::command]
async fn export_local_mapping_typescript(
    caller: WebviewWindow,
    state: State<'_, BridgeState>,
    plugin_id: String,
    destination: PathBuf,
) -> Result<(), String> {
    desktop::require_control(&caller)?;
    let _install = state.install_lock.lock().await;
    let root = state.local_mapping_root.clone();
    tokio::task::spawn_blocking(move || {
        local_mappings::export_typescript(&root, &plugin_id, &destination)
    })
    .await
    .map_err(|_| "TypeScript 导出任务异常终止".to_owned())?
}

#[tauri::command]
async fn export_local_mapping_release_source(
    caller: WebviewWindow,
    state: State<'_, BridgeState>,
    plugin_id: String,
    destination_parent: PathBuf,
) -> Result<local_mappings::ReleaseSourceExportResult, String> {
    desktop::require_control(&caller)?;
    let _install = state.install_lock.lock().await;
    let root = state.local_mapping_root.clone();
    tokio::task::spawn_blocking(move || {
        local_mappings::export_release_source(&root, &plugin_id, &destination_parent)
    })
    .await
    .map_err(|_| "发布源导出任务异常终止".to_owned())?
}

#[tauri::command]
async fn import_local_mapping(
    caller: WebviewWindow,
    state: State<'_, BridgeState>,
    source: PathBuf,
) -> Result<LocalMappingSaveResult, String> {
    desktop::require_control(&caller)?;
    let _install = state.install_lock.lock().await;
    let root = state.local_mapping_root.clone();
    let prepared =
        tokio::task::spawn_blocking(move || local_mappings::prepare_import(&root, &source))
            .await
            .map_err(|_| "映射导入任务异常终止".to_owned())??;
    if state.plugin_root.join(prepared.plugin_id()).exists() {
        return Err(format!(
            "映射 ID [{}] 与签名插件冲突，请先调整映射包",
            prepared.plugin_id()
        ));
    }
    activate_prepared_local_mapping(&state, prepared).await
}

async fn activate_prepared_local_mapping(
    state: &BridgeState,
    prepared: local_mappings::PreparedLocalMapping,
) -> Result<LocalMappingSaveResult, String> {
    let plugin_id = prepared.plugin_id().to_owned();
    let current = inspect_all_plugins(
        &state.plugin_root,
        &state.local_mapping_root,
        state.trust_store.as_deref(),
        &state.desktop_version,
    )?;
    let mut candidates = current.manifests.clone();
    candidates.retain(|manifest| manifest.plugin_id != plugin_id);
    candidates.push(prepared.manifest().clone());
    PluginController::validate_manifests(&candidates).map_err(|error| error.to_string())?;
    let preflight = state
        .controller
        .preflight_candidate_manifest(prepared.manifest())
        .await
        .map_err(|error| {
            state
                .plugin_preflight_failures
                .fetch_add(1, Ordering::AcqRel);
            format!(
                "本地映射宿主预检失败 ({})，未修改当前映射: {error}",
                error.diagnostic_code(),
            )
        })?;
    let maintenance = state.controller.begin_maintenance().await;
    let root = state.local_mapping_root.clone();
    let activated = tokio::task::spawn_blocking(move || prepared.activate(&root))
        .await
        .map_err(|_| "本地映射启用任务异常终止".to_owned())??;
    let installed = match inspect_all_plugins(
        &state.plugin_root,
        &state.local_mapping_root,
        state.trust_store.as_deref(),
        &state.desktop_version,
    ) {
        Ok(installed) => installed,
        Err(error) => {
            activated
                .rollback()
                .map_err(|rollback| format!("映射加载失败: {error}; 回滚同时失败: {rollback}"))?;
            maintenance
                .replace_manifests(&current.manifests)
                .await
                .map_err(|reload| format!("映射加载失败: {error}; 恢复旧路由失败: {reload}"))?;
            return Err(format!("映射加载失败，已恢复旧映射: {error}"));
        }
    };
    if let Err(error) = maintenance.replace_manifests(&installed.manifests).await {
        activated
            .rollback()
            .map_err(|rollback| format!("新映射路由无效: {error}; 回滚同时失败: {rollback}"))?;
        maintenance
            .replace_manifests(&current.manifests)
            .await
            .map_err(|reload| format!("新映射路由无效: {error}; 恢复旧路由失败: {reload}"))?;
        return Err(format!("新映射路由无效，已恢复旧映射: {error}"));
    }
    let activated = match activated.commit() {
        Ok(manifest) => manifest,
        Err(error) => {
            maintenance
                .replace_manifests(&current.manifests)
                .await
                .map_err(|reload| format!("映射事务提交失败: {error}; 恢复旧路由失败: {reload}"))?;
            return Err(format!("映射事务提交失败: {error}"));
        }
    };
    state
        .plugin_load_failures
        .store(installed.failures.len(), Ordering::Release);
    state
        .plugin_count
        .store(installed.manifests.len(), Ordering::Release);
    state
        .preflighted_plugin_hosts
        .fetch_add(preflight.hosts_started, Ordering::AcqRel);
    tracing::info!(
        event_code = "local-mapping-saved",
        plugin_id,
        service_count = activated.services.len(),
        preflighted_hosts = preflight.hosts_started,
        "local native mapping saved and hot loaded"
    );
    Ok(LocalMappingSaveResult {
        plugin_id,
        service_count: activated.services.len(),
        preflighted_hosts: preflight.hosts_started,
    })
}

#[tauri::command]
async fn delete_local_mapping(
    caller: WebviewWindow,
    state: State<'_, BridgeState>,
    plugin_id: String,
) -> Result<(), String> {
    desktop::require_control(&caller)?;
    let _install = state.install_lock.lock().await;
    recover_plugin_store(&state)?;
    let before = inspect_all_plugins(
        &state.plugin_root,
        &state.local_mapping_root,
        state.trust_store.as_deref(),
        &state.desktop_version,
    )?;
    let baseline_failures = before.failures.clone();
    let previous_manifest = before
        .manifests
        .iter()
        .find(|manifest| {
            manifest.plugin_id == plugin_id
                && is_local_manifest(manifest, &state.local_mapping_root)
        })
        .cloned()
        .ok_or_else(|| format!("本地映射 [{plugin_id}] 不存在"))?;
    let maintenance = state
        .controller
        .begin_plugin_maintenance(&plugin_id)
        .await
        .map_err(|error| {
            format!(
                "映射维护窗口不可用 ({})，未修改当前映射",
                error.diagnostic_code()
            )
        })?;
    let root = state.local_mapping_root.clone();
    let removal = tokio::task::spawn_blocking({
        let plugin_id = plugin_id.clone();
        move || local_mappings::prepare_removal(&root, &plugin_id)
    })
    .await
    .map_err(|_| "映射删除任务异常终止".to_owned())??;
    let installed = match inspect_all_plugins(
        &state.plugin_root,
        &state.local_mapping_root,
        state.trust_store.as_deref(),
        &state.desktop_version,
    ) {
        Ok(installed) if same_plugin_failures(&baseline_failures, &installed.failures) => installed,
        Ok(_) => {
            removal.rollback().map_err(|rollback| {
                format!("删除后插件隔离清单发生变化；恢复原映射同时失败: {rollback}")
            })?;
            return Err("删除后插件隔离清单发生变化，已恢复原映射".into());
        }
        Err(error) => {
            removal
                .rollback()
                .map_err(|rollback| format!("{error}; 恢复原映射同时失败: {rollback}"))?;
            return Err(format!("无法验证删除后的插件清单，已恢复原映射: {error}"));
        }
    };
    if let Err(error) = maintenance.replace_manifest(None).await {
        removal.rollback().map_err(|rollback| {
            format!("删除映射路由失败: {error}; 恢复映射同时失败: {rollback}")
        })?;
        maintenance
            .replace_manifest(Some(&previous_manifest))
            .await
            .map_err(|restore| format!("删除映射路由失败: {error}; 恢复原路由失败: {restore}"))?;
        return Err(format!("删除映射路由失败，已恢复原映射: {error}"));
    }
    if let Err(error) = removal.commit() {
        maintenance
            .replace_manifest(Some(&previous_manifest))
            .await
            .map_err(|restore| {
                format!("映射删除事务提交失败: {error}; 恢复原路由失败: {restore}")
            })?;
        return Err(format!("映射删除事务提交失败，已恢复原映射: {error}"));
    }
    state
        .plugin_load_failures
        .store(installed.failures.len(), Ordering::Release);
    state
        .plugin_count
        .store(installed.manifests.len(), Ordering::Release);
    tracing::info!(
        event_code = "local-mapping-deleted",
        plugin_id,
        "local native mapping deleted"
    );
    Ok(())
}

#[tauri::command]
async fn debug_plugin_invoke(
    caller: WebviewWindow,
    state: State<'_, BridgeState>,
    request: InvokeRequest,
) -> Result<PluginDebugResult, String> {
    desktop::require_control(&caller)?;
    request.validate().map_err(|error| error.to_string())?;
    let started = std::time::Instant::now();
    let response = state.controller.invoke(request).await;
    Ok(PluginDebugResult {
        elapsed_ms: started.elapsed().as_millis(),
        response,
    })
}

#[tauri::command]
async fn save_local_mapping_debug_case(
    caller: WebviewWindow,
    state: State<'_, BridgeState>,
    plugin_id: String,
    debug_case: local_mappings::DebugCaseDefinition,
) -> Result<Vec<local_mappings::DebugCaseDefinition>, String> {
    desktop::require_control(&caller)?;
    let _install = state.install_lock.lock().await;
    let root = state.local_mapping_root.clone();
    tokio::task::spawn_blocking(move || {
        local_mappings::upsert_debug_case(&root, &plugin_id, debug_case)
    })
    .await
    .map_err(|_| "调试用例保存任务异常终止".to_owned())?
}

#[tauri::command]
async fn delete_local_mapping_debug_case(
    caller: WebviewWindow,
    state: State<'_, BridgeState>,
    plugin_id: String,
    case_name: String,
) -> Result<Vec<local_mappings::DebugCaseDefinition>, String> {
    desktop::require_control(&caller)?;
    let _install = state.install_lock.lock().await;
    let root = state.local_mapping_root.clone();
    tokio::task::spawn_blocking(move || {
        local_mappings::delete_debug_case(&root, &plugin_id, &case_name)
    })
    .await
    .map_err(|_| "调试用例删除任务异常终止".to_owned())?
}

#[tauri::command]
async fn run_local_mapping_debug_cases(
    caller: WebviewWindow,
    state: State<'_, BridgeState>,
    plugin_id: String,
) -> Result<Vec<DebugCaseRunResult>, String> {
    desktop::require_control(&caller)?;
    let cases = {
        let _install = state.install_lock.lock().await;
        let root = state.local_mapping_root.clone();
        let plugin_id = plugin_id.clone();
        tokio::task::spawn_blocking(move || local_mappings::load_debug_cases(&root, &plugin_id))
            .await
            .map_err(|_| "调试用例读取任务异常终止".to_owned())??
    };
    let mut results = Vec::with_capacity(cases.len());
    for debug_case in cases {
        let started = std::time::Instant::now();
        let response = state
            .controller
            .invoke(InvokeRequest {
                service_id: debug_case.service_id.clone(),
                method: debug_case.method.clone(),
                parameters: debug_case.parameters,
            })
            .await;
        let data_mismatch_path = if debug_case.assert_res_data {
            local_mappings::res_data_mismatch_path(
                &debug_case.expected_res_data,
                &response.res_data,
            )
        } else {
            None
        };
        let data_passed = data_mismatch_path.is_none();
        results.push(DebugCaseRunResult {
            name: debug_case.name,
            service_id: debug_case.service_id,
            method: debug_case.method,
            expected_res_code: debug_case.expected_res_code,
            actual_res_code: response.res_code,
            data_asserted: debug_case.assert_res_data,
            data_passed,
            data_mismatch_path,
            elapsed_ms: started.elapsed().as_millis(),
            passed: response.res_code == debug_case.expected_res_code && data_passed,
        });
    }
    let passed = results.iter().filter(|result| result.passed).count();
    tracing::info!(
        event_code = "local-mapping-regression-completed",
        plugin_id,
        case_count = results.len(),
        passed_count = passed,
        "local mapping synthetic regression completed"
    );
    Ok(results)
}

fn service_inventory_item(service: ServiceDefinition) -> ServiceInventoryItem {
    let main_type = service.resolved_main_type().to_ascii_lowercase();
    let methods = service
        .methods
        .into_iter()
        .map(|method| MethodInventoryItem {
            request_name: method.alias.unwrap_or_else(|| method.name.clone()),
            native_name: method.name,
            return_type: method.return_type,
            parameter_count: method.parameters.len(),
            timeout_ms: method.timeout,
        })
        .collect::<Vec<_>>();
    ServiceInventoryItem {
        service_id: service.service_id,
        architecture: service.architecture,
        main_type,
        main_class: service.main_class,
        calling_convention: service.calling_convention,
        charset: service.charset,
        cacheable: service.cacheable,
        timeout_ms: service.timeout,
        dependency_count: service.deps.len(),
        method_count: methods.len(),
        methods,
    }
}

#[tauri::command]
async fn plugin_invoke(
    caller: WebviewWindow,
    desktop_state: State<'_, desktop::DesktopState>,
    state: State<'_, BridgeState>,
    request: InvokeRequest,
) -> Result<InvokeResponse, String> {
    let _origin = desktop::require_plugin_invocation(
        &caller,
        &desktop_state,
        &request.service_id,
        &request.method,
    )?;
    Ok(state.controller.invoke(request).await)
}

#[tauri::command]
async fn plugin_invoke_tracked(
    caller: WebviewWindow,
    desktop_state: State<'_, desktop::DesktopState>,
    state: State<'_, BridgeState>,
    operation_id: String,
    request: InvokeRequest,
) -> Result<TrackedInvocationStatus, String> {
    let origin = desktop::require_plugin_invocation(
        &caller,
        &desktop_state,
        &request.service_id,
        &request.method,
    )?;
    let coordinator = state.invocation_coordinator.as_ref().ok_or_else(|| {
        format!(
            "持久调用协调不可用 ({})",
            state
                .invocation_coordinator_error
                .unwrap_or("tracked-invocation-unavailable")
        )
    })?;
    coordinator
        .invoke(
            &origin,
            &operation_id,
            request,
            Arc::clone(&state.controller),
        )
        .await
        .map_err(|error| format!("持久调用协调失败 ({})", error.diagnostic_code()))
}

#[tauri::command]
async fn plugin_invocation_status(
    caller: WebviewWindow,
    desktop_state: State<'_, desktop::DesktopState>,
    state: State<'_, BridgeState>,
    operation_id: String,
    service_id: String,
    method: String,
) -> Result<TrackedInvocationStatus, String> {
    let origin = desktop::require_plugin_invocation(&caller, &desktop_state, &service_id, &method)?;
    let coordinator = state.invocation_coordinator.as_ref().ok_or_else(|| {
        format!(
            "持久调用协调不可用 ({})",
            state
                .invocation_coordinator_error
                .unwrap_or("tracked-invocation-unavailable")
        )
    })?;
    coordinator
        .status(&origin, &operation_id, &service_id, &method)
        .await
        .map_err(|error| format!("持久调用状态查询失败 ({})", error.diagnostic_code()))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemDeclaration {
    os: &'static str,
    architecture: &'static str,
    app_version: String,
    protocol_version: u16,
    capabilities: DesktopCapabilitiesDeclaration,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopCapabilitiesDeclaration {
    schema_version: u16,
    tracked_invocations: TrackedInvocationCapabilitiesDeclaration,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TrackedInvocationCapabilitiesDeclaration {
    supported: bool,
    available: bool,
    accepting: bool,
    error_code: Option<&'static str>,
    limits: TrackedInvocationLimitsDeclaration,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TrackedInvocationLimitsDeclaration {
    max_runtime_operations: usize,
    max_retained_response_bytes: usize,
    runtime_result_retention_seconds: u64,
    max_durable_operations: usize,
    max_durable_operations_per_scope: usize,
    completed_retention_seconds: u64,
    indeterminate_retention_seconds: u64,
}

fn desktop_capabilities(state: Option<&BridgeState>) -> DesktopCapabilitiesDeclaration {
    let coordinator = state.and_then(|state| state.invocation_coordinator.as_ref());
    DesktopCapabilitiesDeclaration {
        schema_version: DESKTOP_CAPABILITIES_SCHEMA_VERSION,
        tracked_invocations: TrackedInvocationCapabilitiesDeclaration {
            supported: true,
            available: coordinator.is_some(),
            accepting: coordinator.is_some_and(|coordinator| coordinator.is_accepting()),
            error_code: state
                .and_then(|state| state.invocation_coordinator_error)
                .or_else(|| {
                    state
                        .is_none()
                        .then_some("tracked-runtime-state-unavailable")
                }),
            limits: TrackedInvocationLimitsDeclaration {
                max_runtime_operations: MAX_RUNTIME_OPERATIONS,
                max_retained_response_bytes: MAX_RETAINED_RESPONSE_BYTES,
                runtime_result_retention_seconds: RUNTIME_RESULT_RETENTION.as_secs(),
                max_durable_operations: MAX_DURABLE_OPERATIONS,
                max_durable_operations_per_scope: MAX_DURABLE_OPERATIONS_PER_SCOPE,
                completed_retention_seconds: COMPLETED_OPERATION_RETENTION.as_secs(),
                indeterminate_retention_seconds: INDETERMINATE_OPERATION_RETENTION.as_secs(),
            },
        },
    }
}

#[tauri::command]
fn system_declaration<R: tauri::Runtime>(
    caller: WebviewWindow<R>,
    app: AppHandle<R>,
    desktop_state: State<'_, desktop::DesktopState>,
) -> Result<SystemDeclaration, String> {
    desktop::require_business(&caller, &desktop_state)?;
    let capabilities = app.try_state::<BridgeState>();
    Ok(SystemDeclaration {
        os: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        app_version: app.package_info().version.to_string(),
        protocol_version: BRIDGE_PROTOCOL_VERSION,
        capabilities: desktop_capabilities(capabilities.as_deref()),
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    StartupStage::Bootstrap.enter();
    install_safe_panic_hook();
    let shortcut_plugin = ShortcutBuilder::<tauri::Wry>::new().build();

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(
            tauri_plugin_opener::Builder::new()
                .open_js_links_on_click(false)
                .build(),
        )
        .plugin(tauri_plugin_single_instance::init(|app, arguments, _| {
            desktop::show_control(app);
            sso::start_from_arguments(app, arguments);
        }))
        .plugin(shortcut_plugin)
        .setup(|app| {
            StartupStage::RuntimePaths.enter();
            let resource_dir = app.path().resource_dir()?;
            let system_config_dir = app.path().config_dir()?;
            let config_dir = app.path().app_config_dir()?;
            let local_data_dir = app.path().app_local_data_dir()?;
            let log_dir = local_data_dir.join("logs");
            let _ = STARTUP_LOG_DIR.set(log_dir.clone());
            StartupStage::Diagnostics.enter();
            let diagnostics = match DiagnosticsState::initialize(&log_dir) {
                Ok(state) => DiagnosticsRuntime {
                    state: Some(state),
                    startup_error: None,
                    log_dir: log_dir.clone(),
                },
                Err(error) => {
                    eprintln!("diagnostics unavailable: {}", error.code());
                    DiagnosticsRuntime {
                        state: None,
                        startup_error: Some(error.code()),
                        log_dir: log_dir.clone(),
                    }
                }
            };
            app.manage(diagnostics);
            StartupStage::LocalStorage.enter();
            let config_path = select_runtime_path(
                config_dir.join("config.json"),
                development_path_override("SSDEV_CONFIG_PATH"),
                cfg!(debug_assertions),
            );
            let plugin_root = select_runtime_path(
                local_data_dir.join("plugins"),
                development_path_override("SSDEV_PLUGIN_DIR"),
                cfg!(debug_assertions),
            );
            std::fs::create_dir_all(&plugin_root)?;
            let local_mapping_root = local_data_dir.join("local-mappings");
            std::fs::create_dir_all(&local_mapping_root)?;
            let project_transaction_root = local_data_dir.join("project-activation");
            let recovery = project_activation::recover(
                &project_transaction_root,
                &config_path,
                &plugin_root,
                &local_mapping_root,
            )
            .map_err(std::io::Error::other)?;
            log_project_recovery(recovery);
            let config = ConfigStore::open(
                config_path.clone(),
                legacy_config_candidates(&system_config_dir),
            )?;
            if !config.migration_sources().is_empty() {
                tracing::info!(
                    event_code = "legacy-config-merged",
                    source_count = config.migration_sources().len(),
                    "legacy desktop configuration merged"
                );
            }
            if !config.migration_warnings().is_empty() {
                tracing::warn!(
                    event_code = "legacy-config-warning",
                    warning_count = config.migration_warnings().len(),
                    "legacy desktop configuration has unreadable sources"
                );
            }
            StartupStage::TrustPolicy.enter();
            let allow_unsigned_plugins = allow_unsigned_plugins();
            let trust_store_path = plugin_trust_store_path(&resource_dir);
            let (trust_store, plugin_trust) = if allow_unsigned_plugins {
                tracing::warn!(
                    event_code = "unsigned-plugin-debug-mode",
                    "unsigned plugins enabled in explicit debug mode"
                );
                (None, PluginTrust::AllowUnsigned)
            } else {
                (
                    Some(Arc::new(TrustStore::load(&trust_store_path)?)),
                    PluginTrust::StrictWithLocalMappings {
                        trust_store: trust_store_path.clone(),
                        local_mapping_root: local_mapping_root.clone(),
                    },
                )
            };
            let origin_policy = load_origin_policy(
                &resource_dir,
                &trust_store_path,
                trust_store.as_deref(),
                allow_unsigned_plugins,
            )?;
            StartupStage::PluginRuntime.enter();
            let x86_host = host_path(
                "SSDEV_PLUGIN_HOST_X86",
                &resource_dir,
                "windows/webplus-plugin-host-x86.exe",
            );
            let x64_host = host_path(
                "SSDEV_PLUGIN_HOST_X64",
                &resource_dir,
                "windows/webplus-plugin-host-x64.exe",
            );
            let controller = PluginController::new(SupervisorConfig {
                x86_host: x86_host.clone(),
                x64_host: x64_host.clone(),
                request_timeout: Duration::from_secs(30),
                max_in_flight_invocations: DEFAULT_MAX_IN_FLIGHT_INVOCATIONS,
                plugin_trust,
            })?;
            let desktop_version = semver::Version::parse(&app.package_info().version.to_string())
                .map_err(std::io::Error::other)?;
            let plugins = inspect_all_plugins(
                &plugin_root,
                &local_mapping_root,
                trust_store.as_deref(),
                &desktop_version,
            )
                .map_err(std::io::Error::other)?;
            if !plugins.failures.is_empty() {
                tracing::warn!(
                    event_code = "plugins-quarantined",
                    quarantined_count = plugins.failures.len(),
                    "plugins quarantined during startup"
                );
            }
            tauri::async_runtime::block_on(controller.replace_manifests(&plugins.manifests))?;
            StartupStage::CoreServices.enter();
            let initial_config = config.snapshot();
            let (process_policy_entries, managed_process_failures) = launch_managed_processes(
                &resource_dir,
                &trust_store_path,
                &initial_config.managed_processes,
            );
            let repository_client = secure_http_client().map_err(std::io::Error::other)?;
            let (invocation_coordinator, invocation_coordinator_error) =
                match InvocationCoordinator::open(local_data_dir.join("invocation-ledger")) {
                    Ok(coordinator) => (Some(Arc::new(coordinator)), None),
                    Err(error) => {
                        let code = error.diagnostic_code();
                        tracing::error!(
                            event_code = "tracked-invocation-ledger-unavailable",
                            error_code = code,
                            "durable tracked invocation ledger is unavailable"
                        );
                        (None, Some(code))
                    }
                };
            app.manage(app_update::AppUpdateState::load(
                &resource_dir,
                &local_data_dir,
                repository_client.clone(),
            ));
            app.manage(sso::SsoRuntimeState::default());
            app.manage(capture::RegionCaptureState::new());
            app.manage(BridgeState {
                controller: Arc::new(controller),
                desktop_version,
                invocation_coordinator,
                invocation_coordinator_error,
                plugin_load_failures: AtomicUsize::new(plugins.failures.len()),
                plugin_count: AtomicUsize::new(plugins.manifests.len()),
                recovered_plugin_transactions: AtomicUsize::new(recovery.total()),
                preflighted_plugin_hosts: AtomicUsize::new(0),
                plugin_preflight_failures: AtomicUsize::new(0),
                plugin_trust_mode: if allow_unsigned_plugins {
                    "debug-unsigned"
                } else {
                    "ed25519-strict"
                },
                x86_host,
                x64_host,
                plugin_root,
                local_mapping_root,
                project_transaction_root,
                config_path,
                trust_store,
                install_lock: tokio::sync::Mutex::new(()),
                process_policy_entries,
                managed_process_failures,
                repository_client,
            });
            StartupStage::DesktopShell.enter();
            let desktop_state = desktop::DesktopState::new(config, origin_policy);
            if let Err(_error) =
                desktop_state.ensure_business_ipc_capabilities(app.handle(), &initial_config)
            {
                tracing::warn!(
                    event_code = "startup-business-origin-unavailable",
                    error_code = "origin-policy-rejected-config",
                    "configured business origins are unavailable; the local control window will continue"
                );
            }
            app.manage(desktop_state);
            app.manage(FrontendRuntime::default());
            if let Err(_error) =
                shortcuts::replace(app.handle(), &initial_config.key_bindings, &[])
            {
                tracing::warn!(
                    event_code = "startup-shortcuts-unavailable",
                    error_code = "global-shortcut-registration-failed",
                    "global shortcuts are unavailable; the desktop will continue"
                );
            }
            if desktop::replace_autostart(app.handle(), initial_config.auto_start).is_err() {
                tracing::warn!(
                    event_code = "autostart-sync-failed",
                    "desktop autostart synchronization failed"
                );
            }
            desktop::setup_control_window(app)?;
            start_frontend_watchdog(app.handle());
            if let Err(_error) = desktop::setup_tray(app) {
                tracing::warn!(
                    event_code = "startup-tray-unavailable",
                    error_code = "tray-initialization-failed",
                    "system tray is unavailable; the control window will continue"
                );
            }
            sso::start_from_process_arguments(app.handle());
            tracing::info!(
                event_code = "app-started",
                app_version = %app.package_info().version,
                plugin_count = plugins.manifests.len(),
                quarantined_count = plugins.failures.len(),
                service_count = plugins.manifests.iter().map(|manifest| manifest.services.len()).sum::<usize>(),
                origin_policy_enforced = app.state::<desktop::DesktopState>().origin_policy_summary().enforced,
                "desktop startup completed"
            );
            StartupStage::SetupComplete.enter();
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            bridge_status,
            run_deployment_check,
            export_project_bundle,
            inspect_project_bundle,
            import_project_bundle,
            frontend_ready,
            open_diagnostics_directory,
            install_plugin_package,
            install_plugin_from_catalog,
            uninstall_signed_plugin,
            check_plugin_updates,
            reload_plugins,
            plugin_inventory,
            inspect_native_component,
            discover_registered_com_components,
            local_mapping_inventory,
            save_local_mapping,
            export_local_mapping,
            export_local_mapping_typescript,
            export_local_mapping_release_source,
            import_local_mapping,
            delete_local_mapping,
            debug_plugin_invoke,
            save_local_mapping_debug_case,
            delete_local_mapping_debug_case,
            run_local_mapping_debug_cases,
            plugin_invoke,
            plugin_invoke_tracked,
            plugin_invocation_status,
            system_declaration,
            desktop::desktop_config,
            desktop::save_desktop_config,
            desktop::inspect_desktop_config_import,
            desktop::import_desktop_config,
            desktop::export_desktop_config,
            desktop::open_business_window,
            desktop::open_external_url,
            desktop::open_secondary_window,
            desktop::show_floating_window,
            desktop::close_floating_window,
            desktop::resolve_floating_window,
            desktop::clear_business_data,
            desktop::reload_business_windows,
            capture::capture_business_window,
            capture::capture_region_snapshot,
            capture::complete_region_capture,
            capture::cancel_region_capture,
            app_update::check_app_update,
            app_update::install_app_update,
            export_diagnostics,
        ])
        .build(app_context());
    let app = match app {
        Ok(app) => app,
        Err(_error) => {
            report_fatal_startup_failure(StartupStage::current().failure());
            return;
        }
    };
    STARTUP_COMPLETE.store(true, Ordering::Release);
    app.run(|app, event| {
        if let tauri::RunEvent::ExitRequested { code, api, .. } = event {
            if desktop::intercept_exit_request(app, code.unwrap_or_default()) {
                api.prevent_exit();
            }
        }
    });
}

fn app_context<R: tauri::Runtime>() -> tauri::Context<R> {
    tauri::generate_context!()
}

struct InspectedPlugins {
    manifests: Vec<webplus_plugin_config::PluginManifest>,
    failures: Vec<String>,
}

fn same_plugin_failures(baseline: &[String], candidate: &[String]) -> bool {
    let mut baseline = baseline.to_vec();
    let mut candidate = candidate.to_vec();
    baseline.sort();
    candidate.sort();
    baseline == candidate
}

fn recover_plugin_store(
    state: &BridgeState,
) -> Result<project_activation::ProjectRecoveryReport, String> {
    let report = project_activation::recover_runtime(
        &state.project_transaction_root,
        &state.config_path,
        &state.plugin_root,
        &state.local_mapping_root,
    )?;
    let recovered = report.total();
    if recovered > 0 {
        state
            .recovered_plugin_transactions
            .fetch_add(recovered, Ordering::AcqRel);
        log_project_recovery(report);
    }
    Ok(report)
}

fn log_project_recovery(report: project_activation::ProjectRecoveryReport) {
    if report.total() > 0 {
        tracing::warn!(
            event_code = "plugin-transactions-recovered",
            project_transaction = report.recovered_project_transaction,
            plugin_rollbacks = report.plugin.rolled_back_activations,
            plugin_finalizations = report.plugin.finalized_activations,
            mapping_rollbacks = report.local_mapping.rolled_back_activations,
            mapping_finalizations = report.local_mapping.finalized_activations,
            recovered_items = report.total(),
            "incomplete project or plugin transactions recovered"
        );
    }
}

fn inspect_plugins(
    plugin_root: &std::path::Path,
    trust_store: Option<&TrustStore>,
    desktop_version: &semver::Version,
) -> Result<InspectedPlugins, String> {
    let report = discover_plugins(plugin_root).map_err(|error| error.to_string())?;
    let mut failures = report
        .failures
        .into_iter()
        .map(|failure| {
            format!(
                "[{}] at {:?}: {}",
                failure.plugin_id, failure.path, failure.error
            )
        })
        .collect::<Vec<_>>();
    let mut manifests = Vec::new();
    for manifest in report.manifests {
        if let Some(trust_store) = trust_store {
            if let Err(error) = trust_store.verify(&manifest) {
                failures.push(format!(
                    "[{}] at {:?}: {}",
                    manifest.plugin_id, manifest.plugin_dir, error
                ));
                continue;
            }
        }
        match manifest.metadata.as_ref() {
            Some(metadata) if !metadata.supports_desktop_version(desktop_version) => {
                failures.push(format!(
                    "[{}] does not support SSDEV Desktop {}; required {}",
                    manifest.plugin_id,
                    desktop_version,
                    metadata
                        .desktop_version_requirement
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "not declared".to_owned())
                ));
                continue;
            }
            None if trust_store.is_some() => {
                failures.push(format!(
                    "[{}] signed plugin is missing compatibility metadata",
                    manifest.plugin_id
                ));
                continue;
            }
            _ => {}
        }
        manifests.push(manifest);
    }
    Ok(InspectedPlugins {
        manifests,
        failures,
    })
}

fn inspect_all_plugins(
    plugin_root: &std::path::Path,
    local_mapping_root: &std::path::Path,
    trust_store: Option<&TrustStore>,
    desktop_version: &semver::Version,
) -> Result<InspectedPlugins, String> {
    let mut signed = inspect_plugins(plugin_root, trust_store, desktop_version)?;
    let local = inspect_plugins(local_mapping_root, None, desktop_version)?;
    let mut plugin_ids = signed
        .manifests
        .iter()
        .map(|manifest| manifest.plugin_id.clone())
        .collect::<std::collections::HashSet<_>>();
    for manifest in local.manifests {
        if let Err(error) = local_mappings::validate_installed_manifest(&manifest) {
            signed.failures.push(format!(
                "本地映射 [{}] 未通过本机定义校验: {error}",
                manifest.plugin_id
            ));
        } else if plugin_ids.insert(manifest.plugin_id.clone()) {
            signed.manifests.push(manifest);
        } else {
            signed.failures.push(format!(
                "本地映射 [{}] 与签名插件 ID 冲突",
                manifest.plugin_id
            ));
        }
    }
    signed.failures.extend(local.failures);
    signed
        .manifests
        .sort_by(|left, right| left.plugin_id.cmp(&right.plugin_id));
    Ok(signed)
}

fn is_local_manifest(manifest: &PluginManifest, root: &std::path::Path) -> bool {
    manifest.plugin_dir.starts_with(root)
}

fn ensure_upgrade_allowed(
    current: Option<&semver::Version>,
    candidate: &semver::Version,
) -> Result<(), String> {
    if let Some(current) = current {
        if candidate < current {
            return Err(format!(
                "默认禁止插件降级：当前版本 {current}，安装包版本 {candidate}"
            ));
        }
    }
    Ok(())
}

fn ensure_signed_plugin_compatible(
    manifest: &PluginManifest,
    desktop_version: &semver::Version,
) -> Result<(), String> {
    let metadata = manifest
        .metadata
        .as_ref()
        .ok_or_else(|| format!("签名插件 [{}] 缺少版本兼容元数据", manifest.plugin_id))?;
    if !metadata.supports_desktop_version(desktop_version) {
        return Err(format!(
            "签名插件 [{} {}] 不支持 SSDEV Desktop {}；要求 {}",
            manifest.plugin_id,
            metadata.version,
            desktop_version,
            metadata
                .desktop_version_requirement
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "未声明".to_owned())
        ));
    }
    Ok(())
}

fn allow_unsigned_plugins() -> bool {
    cfg!(debug_assertions)
        && std::env::var("SSDEV_ALLOW_UNSIGNED_PLUGINS")
            .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn install_safe_panic_hook() {
    let _previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        tracing::error!(event_code = "process-panic", "desktop process panicked");
        if !STARTUP_COMPLETE.load(Ordering::Acquire) {
            report_fatal_startup_failure(StartupStage::current().failure());
        }
        #[cfg(debug_assertions)]
        _previous(panic_info);
        #[cfg(not(debug_assertions))]
        let _ = panic_info;
    }));
}

fn start_frontend_watchdog(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(FRONTEND_READY_TIMEOUT).await;
        let frontend = app.state::<FrontendRuntime>();
        if frontend.ready.load(Ordering::Acquire)
            || frontend
                .timeout_reported
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return;
        }
        let failure = StartupFailure {
            code: "frontend-startup-timeout",
            summary: "控制窗口已经创建，但页面未能连接桌面核心服务。",
            action: "请修复 Microsoft Edge WebView2 Runtime 或 SSDEV Desktop 安装；随后查看日志并重新启动。",
        };
        tracing::error!(
            event_code = "frontend-startup-timeout",
            error_code = failure.code,
            timeout_seconds = FRONTEND_READY_TIMEOUT.as_secs(),
            "control frontend did not reach native IPC before the startup deadline"
        );
        write_startup_failure_document(failure);
        app.dialog()
            .message(startup_failure_message(failure))
            .title("SSDEV Desktop 启动异常")
            .kind(MessageDialogKind::Error)
            .show(|_| {});
    });
}

fn report_fatal_startup_failure(failure: StartupFailure) {
    if STARTUP_FAILURE_REPORTED.swap(true, Ordering::AcqRel) {
        return;
    }
    tracing::error!(
        event_code = "desktop-startup-failed",
        error_code = failure.code,
        "desktop initialization failed"
    );
    write_startup_failure_document(failure);
    show_native_startup_error(&startup_failure_message(failure));
}

fn write_startup_failure_document(failure: StartupFailure) {
    let Some(log_dir) = STARTUP_LOG_DIR.get() else {
        return;
    };
    let document = StartupFailureDocument {
        schema_version: 1,
        generated_at_unix_ms: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
        event_code: "desktop-startup-failed",
        error_code: failure.code,
        summary: failure.summary,
        action: failure.action,
    };
    let Ok(bytes) = serde_json::to_vec(&document) else {
        return;
    };
    if bytes.len() > 4 * 1024 {
        return;
    }
    let _ = persist_startup_failure_document(log_dir, &bytes);
}

fn persist_startup_failure_document(
    log_dir: &std::path::Path,
    bytes: &[u8],
) -> std::io::Result<()> {
    fs::create_dir_all(log_dir)?;
    let directory_metadata = fs::symlink_metadata(log_dir)?;
    if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
        return Err(std::io::Error::other(
            "startup diagnostics directory is unsafe",
        ));
    }
    let destination = log_dir.join(STARTUP_FAILURE_FILE_NAME);
    if let Ok(metadata) = fs::symlink_metadata(&destination) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(std::io::Error::other("startup failure marker is unsafe"));
        }
    }
    let mut temporary = tempfile::NamedTempFile::new_in(log_dir)?;
    temporary.write_all(bytes)?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist(destination)
        .map_err(|error| error.error)?;
    Ok(())
}

fn startup_failure_message(failure: StartupFailure) -> String {
    let log_location = STARTUP_LOG_DIR
        .get()
        .map(|directory| directory.display().to_string())
        .unwrap_or_else(|| "尚未建立（用户应用数据目录不可用）".to_owned());
    format!(
        "{}\n\n处理建议：{}\n\n错误码：{}\n日志目录：{}",
        failure.summary, failure.action, failure.code, log_location
    )
}

#[cfg(windows)]
fn show_native_startup_error(message: &str) {
    use windows::core::PCWSTR;
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

    let title = "SSDEV Desktop 启动失败\0"
        .encode_utf16()
        .collect::<Vec<_>>();
    let message = message
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    unsafe {
        let _ = MessageBoxW(
            None,
            PCWSTR(message.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }
}

#[cfg(not(windows))]
fn show_native_startup_error(message: &str) {
    eprintln!("SSDEV Desktop startup failed: {message}");
}

fn plugin_trust_store_path(resource_dir: &std::path::Path) -> PathBuf {
    let bundled = resource_dir.join("plugin-trust.json");
    let selected = select_runtime_path(
        bundled.clone(),
        development_path_override("SSDEV_PLUGIN_TRUST_STORE"),
        cfg!(debug_assertions),
    );
    if selected != bundled {
        return selected;
    }
    if bundled.is_file() || !cfg!(debug_assertions) {
        return bundled;
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/plugin-trust.json")
}

fn load_origin_policy(
    resource_dir: &std::path::Path,
    trust_store_path: &std::path::Path,
    trust_store: Option<&TrustStore>,
    allow_unsigned_plugins: bool,
) -> Result<OriginPolicy, Box<dyn std::error::Error>> {
    let policy_path = select_runtime_path(
        resource_dir.join("origin-policy.json"),
        development_path_override("SSDEV_ORIGIN_POLICY"),
        cfg!(debug_assertions),
    );
    let signature_path = select_runtime_path(
        resource_dir.join("origin-policy.sig.json"),
        development_path_override("SSDEV_ORIGIN_POLICY_SIGNATURE"),
        cfg!(debug_assertions),
    );
    match (policy_path.is_file(), signature_path.is_file()) {
        (true, true) => {
            let owned_trust;
            let trust = if let Some(trust) = trust_store {
                trust
            } else {
                owned_trust = TrustStore::load(trust_store_path)?;
                &owned_trust
            };
            Ok(OriginPolicy::load(&policy_path, &signature_path, trust)?)
        }
        (false, false) if cfg!(debug_assertions) && allow_unsigned_plugins => {
            tracing::warn!(
                event_code = "unsigned-origin-policy-debug-mode",
                "signed origin policy disabled in explicit debug mode"
            );
            Ok(OriginPolicy::development_unrestricted())
        }
        (false, false) => Err(
            "a signed origin-policy.json and origin-policy.sig.json are required to authorize business WebViews"
                .into(),
        ),
        _ => Err("origin policy and its signature must be installed together".into()),
    }
}

fn launch_managed_processes(
    resource_dir: &std::path::Path,
    trust_store_path: &std::path::Path,
    selected: &[String],
) -> (usize, usize) {
    let policy_path = select_runtime_path(
        resource_dir.join("process-policy.json"),
        development_path_override("SSDEV_PROCESS_POLICY"),
        cfg!(debug_assertions),
    );
    let signature_path = select_runtime_path(
        resource_dir.join("process-policy.sig.json"),
        development_path_override("SSDEV_PROCESS_POLICY_SIGNATURE"),
        cfg!(debug_assertions),
    );
    if !policy_path.is_file() && !signature_path.is_file() {
        if !selected.is_empty() {
            tracing::warn!(
                event_code = "process-policy-missing",
                selected_count = selected.len(),
                "managed processes selected without a signed process policy"
            );
        }
        return (0, selected.len());
    }
    let policy = TrustStore::load(trust_store_path)
        .map_err(|error| error.to_string())
        .and_then(|trust| {
            ProcessPolicy::load(&policy_path, &signature_path, &trust)
                .map_err(|error| error.to_string())
        });
    let policy = match policy {
        Ok(policy) => policy,
        Err(_) => {
            tracing::warn!(
                event_code = "process-policy-rejected",
                "signed managed process policy rejected"
            );
            return (0, selected.len().max(1));
        }
    };
    let entries = policy.len();
    let report = policy.launch_selected(selected);
    for failure in &report.failures {
        tracing::warn!(
            event_code = "managed-process-start-failed",
            process_id = failure.process_id,
            "managed process was not started"
        );
    }
    (entries, report.failures.len())
}

fn legacy_config_candidates(system_config_dir: &std::path::Path) -> Vec<PathBuf> {
    let mut candidates = development_legacy_config_candidates();
    candidates.push(system_config_dir.join("rbmh-desktop/config.json"));
    candidates.push(system_config_dir.join("ssdev-desktop/config.json"));
    candidates.push(system_config_dir.join("Electron/config.json"));
    candidates.push(PathBuf::from(
        r"C:\dir\bsoft\rbmh-desktop-config\config.json",
    ));
    candidates
}

#[cfg(debug_assertions)]
fn development_legacy_config_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(current_dir) = std::env::current_dir() {
        candidates.push(current_dir.join("config.json"));
    }
    if let Some(portable_dir) = std::env::var_os("PORTABLE_EXECUTABLE_DIR") {
        candidates.push(PathBuf::from(portable_dir).join("config.json"));
    }
    candidates
}

#[cfg(not(debug_assertions))]
fn development_legacy_config_candidates() -> Vec<PathBuf> {
    Vec::new()
}

fn host_path(environment_key: &str, resource_dir: &std::path::Path, filename: &str) -> PathBuf {
    select_runtime_path(
        resource_dir.join(filename),
        development_path_override(environment_key),
        cfg!(debug_assertions),
    )
}

#[cfg(debug_assertions)]
fn development_path_override(environment_key: &str) -> Option<PathBuf> {
    std::env::var_os(environment_key).map(PathBuf::from)
}

#[cfg(not(debug_assertions))]
fn development_path_override(_environment_key: &str) -> Option<PathBuf> {
    None
}

fn select_runtime_path(
    installed: PathBuf,
    development_override: Option<PathBuf>,
    allow_development_override: bool,
) -> PathBuf {
    if allow_development_override {
        development_override.unwrap_or(installed)
    } else {
        installed
    }
}

#[cfg(test)]
mod tests {
    use super::{
        classify_project_component_action, collect_plugin_updates, desktop,
        ensure_plugin_update_plan_matches, ensure_project_export_active_manifests_match,
        ensure_project_export_runtime_matches, ensure_signed_plugin_compatible,
        ensure_upgrade_allowed, is_lowercase_sha256, is_plugin_update_available,
        legacy_config_candidates, open_project_bundle_for_mode, persist_startup_failure_document,
        plugin_update_installed_state_digest, plugin_update_plan_id, project_bundle,
        project_import_plan_id, project_import_state_digest, select_runtime_path,
        service_inventory_item, startup_failure_message, CatalogWithdrawalReason, FrontendRuntime,
        ProjectBundlePreview, StartupFailureDocument, StartupStage, FRONTEND_READY_TIMEOUT,
    };
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use semver::Version;
    use std::{
        fs,
        path::PathBuf,
        time::{Duration, UNIX_EPOCH},
    };
    use webplus_plugin_config::{PluginManifest, ServiceDefinition, API_FILENAME};
    use webplus_plugin_repository::PluginCatalog;
    use webplus_plugin_trust::{
        encode_signature_document, prepare_signing_material, TrustStore, SIGNATURE_FILENAME,
    };

    #[test]
    fn startup_stages_have_stable_actionable_failure_codes() {
        for (stage, expected_code) in [
            (StartupStage::Bootstrap, "startup-framework"),
            (StartupStage::RuntimePaths, "startup-runtime-paths"),
            (StartupStage::Diagnostics, "startup-diagnostics"),
            (StartupStage::LocalStorage, "startup-local-storage"),
            (StartupStage::TrustPolicy, "startup-trust-policy"),
            (StartupStage::PluginRuntime, "startup-plugin-runtime"),
            (StartupStage::CoreServices, "startup-core-services"),
            (StartupStage::DesktopShell, "startup-desktop-shell"),
            (StartupStage::SetupComplete, "startup-framework"),
        ] {
            let failure = stage.failure();
            assert_eq!(failure.code, expected_code);
            assert!(!failure.summary.is_empty());
            assert!(!failure.action.is_empty());
            let message = startup_failure_message(failure);
            assert!(message.contains(expected_code));
            assert!(message.contains("处理建议"));
            assert!(message.contains("日志目录"));
        }
    }

    #[test]
    fn startup_failure_document_is_bounded_and_contains_no_raw_error() {
        let failure = StartupStage::DesktopShell.failure();
        let document = StartupFailureDocument {
            schema_version: 1,
            generated_at_unix_ms: 1,
            event_code: "desktop-startup-failed",
            error_code: failure.code,
            summary: failure.summary,
            action: failure.action,
        };
        let encoded = serde_json::to_vec(&document).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();

        assert!(encoded.len() < 4 * 1024);
        assert_eq!(value["errorCode"], "startup-desktop-shell");
        assert!(value.get("error").is_none());
        assert!(value.get("path").is_none());
        assert!(value.get("url").is_none());
    }

    #[test]
    fn frontend_readiness_timeout_is_bounded_and_reported_once() {
        let frontend = FrontendRuntime::default();

        assert!(FRONTEND_READY_TIMEOUT >= Duration::from_secs(5));
        assert!(FRONTEND_READY_TIMEOUT <= Duration::from_secs(60));
        assert!(!frontend.ready.load(std::sync::atomic::Ordering::Acquire));
        assert!(frontend
            .timeout_reported
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok());
        assert!(frontend
            .timeout_reported
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_err());
    }

    #[test]
    fn startup_failure_marker_replaces_only_its_fixed_regular_file() {
        let root = tempfile::tempdir().unwrap();
        let log_dir = root.path().join("logs");

        persist_startup_failure_document(&log_dir, br#"{"errorCode":"first"}"#).unwrap();
        persist_startup_failure_document(&log_dir, br#"{"errorCode":"second"}"#).unwrap();

        assert_eq!(
            fs::read(log_dir.join(super::STARTUP_FAILURE_FILE_NAME)).unwrap(),
            br#"{"errorCode":"second"}"#
        );
    }

    #[cfg(unix)]
    #[test]
    fn startup_failure_marker_refuses_a_symbolic_link() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let log_dir = root.path().join("logs");
        fs::create_dir(&log_dir).unwrap();
        let private = root.path().join("private.txt");
        fs::write(&private, b"keep").unwrap();
        symlink(&private, log_dir.join(super::STARTUP_FAILURE_FILE_NAME)).unwrap();

        assert!(persist_startup_failure_document(&log_dir, b"replacement").is_err());
        assert_eq!(fs::read(private).unwrap(), b"keep");
    }

    #[test]
    fn plugin_install_rejects_downgrade_but_allows_repair() {
        let current = Version::new(2, 4, 0);
        assert!(ensure_upgrade_allowed(Some(&current), &Version::new(2, 3, 9)).is_err());
        assert!(ensure_upgrade_allowed(Some(&current), &Version::new(2, 4, 0)).is_ok());
        assert!(ensure_upgrade_allowed(Some(&current), &Version::new(3, 0, 0)).is_ok());
        assert!(ensure_upgrade_allowed(None, &Version::new(1, 0, 0)).is_ok());
    }

    #[test]
    fn project_import_plan_classifies_only_actions_the_import_actually_performs() {
        use project_bundle::ProjectComponentKind::{LocalMapping, SignedPlugin};

        assert_eq!(
            classify_project_component_action(
                SignedPlugin,
                false,
                None,
                Some(&Version::new(1, 0, 0)),
            ),
            "install"
        );
        assert_eq!(
            classify_project_component_action(
                SignedPlugin,
                true,
                Some(&Version::new(1, 0, 0)),
                Some(&Version::new(1, 1, 0)),
            ),
            "upgrade"
        );
        assert_eq!(
            classify_project_component_action(
                SignedPlugin,
                true,
                Some(&Version::new(1, 0, 0)),
                Some(&Version::new(1, 0, 0)),
            ),
            "reinstall"
        );
        assert_eq!(
            classify_project_component_action(LocalMapping, true, None, None),
            "replace"
        );
    }

    #[test]
    fn project_import_preview_contains_the_shared_configuration_change_summary() {
        let current = ssdev_config::DesktopConfig {
            website: Some("https://current.example.test/app".into()),
            managed_processes: vec!["reader-agent".into()],
            ..ssdev_config::DesktopConfig::default()
        };
        let candidate = ssdev_config::DesktopConfig {
            website: Some("https://candidate.example.test/app".into()),
            environments: vec![ssdev_config::EnvironmentConfig {
                name: "生产环境".into(),
                url: "https://candidate.example.test/app".into(),
                extensions: Default::default(),
            }],
            auto_start: true,
            ..ssdev_config::DesktopConfig::default()
        };
        let preview = ProjectBundlePreview {
            plan_id: "a".repeat(64),
            schema_version: 1,
            created_by_version: "0.1.0".into(),
            signature_verified: true,
            signature_key_id: Some("project-key".into()),
            business_origins: 1,
            signed_plugins: 0,
            local_mappings: 0,
            service_count: 0,
            preflighted_hosts: 0,
            config_preview: desktop::build_config_change_preview(&current, &candidate).unwrap(),
            install_count: 0,
            upgrade_count: 0,
            replace_count: 0,
            retained_count: 0,
            components: Vec::new(),
            retained_components: Vec::new(),
        };
        let value = serde_json::to_value(preview).unwrap();

        assert!(value.get("configChanged").is_none());
        assert_eq!(value["configPreview"]["configChanged"], true);
        assert_eq!(
            value["configPreview"]["candidateDefaultWebsite"],
            "https://candidate.example.test/app"
        );
        assert_eq!(value["configPreview"]["currentManagedProcessCount"], 1);
        assert_eq!(value["configPreview"]["candidateManagedProcessCount"], 0);
        assert!(value["configPreview"].get("planId").is_none());
    }

    #[test]
    fn project_export_requires_disk_and_active_services_to_match() {
        assert!(ensure_project_export_runtime_matches(0, 0).is_ok());
        assert!(ensure_project_export_runtime_matches(4, 4).is_ok());
        let error = ensure_project_export_runtime_matches(4, 3).unwrap_err();
        assert!(error.contains("磁盘插件声明 4 个服务"));
        assert!(error.contains("3 个活动服务"));
        assert!(ensure_project_export_active_manifests_match(true).is_ok());
        assert!(ensure_project_export_active_manifests_match(false)
            .unwrap_err()
            .contains("完整清单"));
    }

    #[test]
    fn project_import_plan_id_binds_bundle_state_and_desktop_version() {
        let base =
            project_import_plan_id(&"11".repeat(32), &"22".repeat(32), &Version::new(0, 1, 0));
        assert!(is_lowercase_sha256(&base));
        assert_ne!(
            base,
            project_import_plan_id(&"33".repeat(32), &"22".repeat(32), &Version::new(0, 1, 0),)
        );
        assert_ne!(
            base,
            project_import_plan_id(&"11".repeat(32), &"44".repeat(32), &Version::new(0, 1, 0),)
        );
        assert_ne!(
            base,
            project_import_plan_id(&"11".repeat(32), &"22".repeat(32), &Version::new(0, 2, 0),)
        );
    }

    #[test]
    fn project_import_state_digest_changes_with_the_saved_configuration() {
        let root = tempfile::tempdir().unwrap();
        let baseline = ssdev_config::DesktopConfig::default();
        let mut changed = baseline.clone();
        changed.website = Some("http://project.internal".into());

        let baseline_digest = project_import_state_digest(&baseline, &[], root.path()).unwrap();
        let changed_digest = project_import_state_digest(&changed, &[], root.path()).unwrap();
        assert!(is_lowercase_sha256(&baseline_digest));
        assert_ne!(baseline_digest, changed_digest);
    }

    #[test]
    fn project_import_state_digest_binds_signed_plugin_file_content() {
        let root = tempfile::tempdir().unwrap();
        let plugin = root.path().join("reader");
        fs::create_dir(&plugin).unwrap();
        fs::write(
            plugin.join(API_FILENAME),
            r#"{"serviceId":"reader","mainClass":"reader.dll"}"#,
        )
        .unwrap();
        fs::write(
            plugin.join("plugin.json"),
            r#"{"schemaVersion":1,"pluginId":"reader","version":"1.0.0","desktopVersionRequirement":">=0.1.0, <0.2.0"}"#,
        )
        .unwrap();
        fs::write(plugin.join("reader.dll"), b"first signed payload").unwrap();
        let signing_key = SigningKey::from_bytes(&[73_u8; 32]);
        let material = prepare_signing_material(&plugin, "reader", "test-key").unwrap();
        let signature = BASE64.encode(signing_key.sign(&material.payload).to_bytes());
        fs::write(
            plugin.join(SIGNATURE_FILENAME),
            encode_signature_document(&material, &signature).unwrap(),
        )
        .unwrap();
        let manifest = PluginManifest::load("reader", &plugin).unwrap();
        let config = ssdev_config::DesktopConfig::default();
        let local_root = root.path().join("local-mappings");
        fs::create_dir(&local_root).unwrap();

        let before =
            project_import_state_digest(&config, std::slice::from_ref(&manifest), &local_root)
                .unwrap();
        fs::write(plugin.join("reader.dll"), b"changed signed payload").unwrap();
        let after =
            project_import_state_digest(&config, std::slice::from_ref(&manifest), &local_root)
                .unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn signed_plugin_compatibility_must_be_explicit_and_match_the_desktop() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join(API_FILENAME),
            r#"{"serviceId":"reader","mainClass":"reader.dll"}"#,
        )
        .unwrap();
        fs::write(
            root.path().join("plugin.json"),
            r#"{"schemaVersion":1,"pluginId":"reader","version":"1.0.0","desktopVersionRequirement":">=0.1.0, <0.2.0"}"#,
        )
        .unwrap();
        let manifest = PluginManifest::load("reader", root.path()).unwrap();
        assert!(ensure_signed_plugin_compatible(&manifest, &Version::new(0, 1, 5)).is_ok());
        assert!(ensure_signed_plugin_compatible(&manifest, &Version::new(0, 2, 0)).is_err());

        fs::write(
            root.path().join("plugin.json"),
            r#"{"schemaVersion":1,"pluginId":"reader","version":"1.0.0"}"#,
        )
        .unwrap();
        let legacy = PluginManifest::load("reader", root.path()).unwrap();
        assert!(ensure_signed_plugin_compatible(&legacy, &Version::new(0, 1, 5)).is_err());
    }

    #[test]
    fn plugin_update_check_only_marks_newer_or_uninstalled_versions() {
        let current = Version::new(2, 4, 0);
        let older = Version::new(2, 3, 9);
        let same = Version::new(2, 4, 0);
        let newer = Version::new(2, 5, 0);

        assert!(!is_plugin_update_available(Some(&current), Some(&older)));
        assert!(!is_plugin_update_available(Some(&current), Some(&same)));
        assert!(is_plugin_update_available(Some(&current), Some(&newer)));
        assert!(is_plugin_update_available(None, Some(&newer)));
        assert!(!is_plugin_update_available(Some(&current), None));
    }

    #[test]
    fn plugin_update_check_exposes_newer_incompatible_catalog_versions() {
        let root = tempfile::tempdir().unwrap();
        let plugin = root.path().join("reader");
        fs::create_dir(&plugin).unwrap();
        fs::write(
            plugin.join(API_FILENAME),
            r#"{"serviceId":"reader","mainClass":"reader.dll"}"#,
        )
        .unwrap();
        fs::write(
            plugin.join("plugin.json"),
            r#"{"schemaVersion":1,"pluginId":"reader","version":"1.0.0","desktopVersionRequirement":">=0.1.0, <0.2.0"}"#,
        )
        .unwrap();
        let signing_key = SigningKey::from_bytes(&[91_u8; 32]);
        let material = prepare_signing_material(&plugin, "reader", "test-key").unwrap();
        let signature = BASE64.encode(signing_key.sign(&material.payload).to_bytes());
        fs::write(
            plugin.join(SIGNATURE_FILENAME),
            encode_signature_document(&material, &signature).unwrap(),
        )
        .unwrap();
        let installed = PluginManifest::load("reader", &plugin).unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_100);
        let catalog = PluginCatalog::from_unsigned_bytes(
            &serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 1,
                "issuedAt": 1_700_000_000_u64,
                "expiresAt": 1_700_003_600_u64,
                "entries": [{
                    "pluginId": "reader",
                    "version": "1.1.0",
                    "desktopVersionRequirement": ">=0.1.0, <0.2.0",
                    "url": "https://plugins.example.test/reader-1.1.0.ssdev-plugin",
                    "sha256": "11".repeat(32),
                    "size": 10
                }, {
                    "pluginId": "reader",
                    "version": "2.0.0",
                    "desktopVersionRequirement": ">=0.2.0, <0.3.0",
                    "url": "https://plugins.example.test/reader-2.0.0.ssdev-plugin",
                    "sha256": "22".repeat(32),
                    "size": 10
                }],
                "withdrawals": [{
                    "pluginId": "reader",
                    "version": "1.0.0",
                    "reason": "security"
                }]
            }))
            .unwrap(),
            now,
        )
        .unwrap();

        let updates = collect_plugin_updates(
            &[installed],
            root.path(),
            &catalog,
            "catalog-key",
            None,
            &Version::new(0, 1, 5),
        )
        .unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].available_version.as_deref(), Some("1.1.0"));
        assert_eq!(updates[0].latest_catalog_version.as_deref(), Some("2.0.0"));
        assert!(updates[0]
            .install_plan_id
            .as_deref()
            .is_some_and(is_lowercase_sha256));
        assert!(updates[0].installed_version_withdrawn);
        assert_eq!(
            updates[0].withdrawal_reason,
            Some(CatalogWithdrawalReason::Security)
        );
        assert!(updates[0].compatibility_limited);
        assert!(updates[0].update_available);
    }

    #[test]
    fn plugin_update_plan_binds_entry_key_state_and_desktop_version() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_100);
        let catalog = PluginCatalog::from_unsigned_bytes(
            &serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 1,
                "issuedAt": 1_700_000_000_u64,
                "expiresAt": 1_700_003_600_u64,
                "entries": [{
                    "pluginId": "reader",
                    "version": "1.1.0",
                    "desktopVersionRequirement": ">=0.1.0, <0.2.0",
                    "url": "https://plugins.example.test/reader-1.1.0.ssdev-plugin",
                    "sha256": "11".repeat(32),
                    "size": 10
                }]
            }))
            .unwrap(),
            now,
        )
        .unwrap();
        let entry = catalog.select("reader", None).unwrap();
        let desktop = Version::new(0, 1, 5);
        let state = "22".repeat(32);
        let base = plugin_update_plan_id(entry, "catalog-key", &state, &desktop).unwrap();
        assert!(is_lowercase_sha256(&base));

        let mut changed_entry = entry.clone();
        changed_entry.sha256 = "33".repeat(32);
        assert_ne!(
            base,
            plugin_update_plan_id(&changed_entry, "catalog-key", &state, &desktop).unwrap()
        );
        assert_ne!(
            base,
            plugin_update_plan_id(entry, "rotated-key", &state, &desktop).unwrap()
        );
        assert_ne!(
            base,
            plugin_update_plan_id(entry, "catalog-key", &"44".repeat(32), &desktop).unwrap()
        );
        assert_ne!(
            base,
            plugin_update_plan_id(entry, "catalog-key", &state, &Version::new(0, 2, 0)).unwrap()
        );
        assert!(ensure_plugin_update_plan_matches(&base, &base).is_ok());
        assert!(ensure_plugin_update_plan_matches(&base, &"55".repeat(32)).is_err());
    }

    #[test]
    fn plugin_update_state_digest_binds_installed_content_and_absence() {
        let root = tempfile::tempdir().unwrap();
        let absent = plugin_update_installed_state_digest(root.path(), "reader", None).unwrap();
        let plugin = root.path().join("reader");
        fs::create_dir(&plugin).unwrap();
        fs::write(
            plugin.join(API_FILENAME),
            r#"{"serviceId":"reader","mainClass":"reader.dll"}"#,
        )
        .unwrap();
        fs::write(
            plugin.join("plugin.json"),
            r#"{"schemaVersion":1,"pluginId":"reader","version":"1.0.0","desktopVersionRequirement":">=0.1.0, <0.2.0"}"#,
        )
        .unwrap();
        fs::write(plugin.join("reader.dll"), b"first payload").unwrap();
        let signing_key = SigningKey::from_bytes(&[92_u8; 32]);
        let material = prepare_signing_material(&plugin, "reader", "test-key").unwrap();
        let signature = BASE64.encode(signing_key.sign(&material.payload).to_bytes());
        fs::write(
            plugin.join(SIGNATURE_FILENAME),
            encode_signature_document(&material, &signature).unwrap(),
        )
        .unwrap();
        let manifest = PluginManifest::load("reader", &plugin).unwrap();
        let before =
            plugin_update_installed_state_digest(root.path(), "reader", Some(&manifest)).unwrap();
        fs::write(plugin.join("reader.dll"), b"second payload").unwrap();
        let after =
            plugin_update_installed_state_digest(root.path(), "reader", Some(&manifest)).unwrap();
        assert_ne!(absent, before);
        assert_ne!(before, after);
        assert!(plugin_update_installed_state_digest(root.path(), "reader", None).is_err());
    }

    #[test]
    fn inventory_exposes_request_to_native_mapping_without_plugin_root() {
        let service: ServiceDefinition = serde_json::from_value(serde_json::json!({
            "serviceId": "reader",
            "mainClass": "native/reader.dll",
            "mainType": "dll",
            "architecture": "x86",
            "charset": "gbk",
            "callingConvention": "cdecl",
            "cacheable": true,
            "timeout": 2500,
            "deps": ["native/helper.dll"],
            "methods": [{
                "name": "ReadCardW",
                "alias": "readCard",
                "timeout": 1200,
                "returnType": "string",
                "parameters": ["port"]
            }]
        }))
        .expect("service fixture must be valid");

        let item = service_inventory_item(service);
        assert_eq!(item.main_class, "native/reader.dll");
        assert_eq!(item.calling_convention, "cdecl");
        assert_eq!(item.charset, "gbk");
        assert_eq!(item.dependency_count, 1);
        assert_eq!(item.methods.len(), 1);
        assert_eq!(item.methods[0].request_name, "readCard");
        assert_eq!(item.methods[0].native_name, "ReadCardW");
        assert_eq!(item.methods[0].parameter_count, 1);
        assert!(!item.main_class.contains("plugins/reader"));
    }

    #[test]
    fn release_mode_ignores_runtime_path_overrides() {
        let bundled = PathBuf::from("installed/plugin-trust.json");
        let injected = Some(PathBuf::from("attacker/plugin-trust.json"));

        assert_eq!(
            select_runtime_path(bundled.clone(), injected.clone(), false),
            bundled
        );
        assert_eq!(
            select_runtime_path(PathBuf::from("installed/host.exe"), injected, false),
            PathBuf::from("installed/host.exe")
        );
        assert_eq!(
            select_runtime_path(
                PathBuf::from("user/config.json"),
                Some(PathBuf::from("attacker/config.json")),
                false,
            ),
            PathBuf::from("user/config.json")
        );
        assert_eq!(
            select_runtime_path(
                PathBuf::from("user/plugins"),
                Some(PathBuf::from("attacker/plugins")),
                false,
            ),
            PathBuf::from("user/plugins")
        );
    }

    #[test]
    fn debug_mode_can_select_explicit_test_resources() {
        let override_path = PathBuf::from("fixtures/host.exe");
        assert_eq!(
            select_runtime_path(
                PathBuf::from("installed/host.exe"),
                Some(override_path.clone()),
                true,
            ),
            override_path
        );
    }

    #[test]
    fn known_legacy_config_locations_use_the_system_config_root() {
        let system_config = PathBuf::from("system-config");
        let candidates = legacy_config_candidates(&system_config);

        assert!(candidates.contains(&system_config.join("Electron/config.json")));
        assert!(candidates.contains(&PathBuf::from(
            r"C:\dir\bsoft\rbmh-desktop-config\config.json"
        )));
    }

    #[test]
    fn formal_project_import_requires_the_fixed_signature_sidecar() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("clinic.ssdev-project");
        project_bundle::create(
            &project,
            &ssdev_config::DesktopConfig::default(),
            "1.2.3",
            Vec::new(),
        )
        .unwrap();
        let trust_path = root.path().join("trust.json");
        fs::write(&trust_path, br#"{"schemaVersion":2,"keys":[]}"#).unwrap();
        let trust = TrustStore::load(&trust_path).unwrap();

        let error = open_project_bundle_for_mode(&project, Some(&trust), true)
            .err()
            .unwrap();
        assert!(error.contains("签名封套"));
        let (_, verified, key_id, bundle_sha256) =
            open_project_bundle_for_mode(&project, None, false).unwrap();
        assert!(!verified);
        assert!(key_id.is_none());
        assert!(is_lowercase_sha256(&bundle_sha256));
    }
}
