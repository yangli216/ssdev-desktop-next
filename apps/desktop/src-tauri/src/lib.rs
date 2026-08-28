mod app_update;
#[cfg(any(windows, target_os = "macos"))]
mod capture;
#[cfg(not(any(windows, target_os = "macos")))]
#[path = "capture_unsupported.rs"]
mod capture;
#[allow(dead_code)]
// The shared build/runtime ACL declaration intentionally has target-specific subsets.
mod command_permissions;
mod deployment_check;
mod desktop;
mod invocations;
mod local_mappings;
mod shortcuts;
mod sso;

/// Version of the public API injected into authorized business WebViews.
/// It must evolve independently from the private plugin-host wire protocol.
pub const BRIDGE_PROTOCOL_VERSION: u16 = 1;
const DESKTOP_CAPABILITIES_SCHEMA_VERSION: u16 = 1;

#[doc(hidden)]
pub use app_update::verify_update_artifact_files;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Serialize;
use ssdev_config::ConfigStore;
use ssdev_diagnostics::{DiagnosticContext, DiagnosticsState, DiagnosticsStats};
use ssdev_invocation_ledger::{
    COMPLETED_OPERATION_RETENTION, INDETERMINATE_OPERATION_RETENTION, MAX_DURABLE_OPERATIONS,
    MAX_DURABLE_OPERATIONS_PER_SCOPE,
};
use ssdev_origin_policy::{OriginPolicy, OriginPolicySummary};
use ssdev_process_policy::ProcessPolicy;
use tauri::{AppHandle, Manager, State, WebviewWindow};
use tauri_plugin_autostart::MacosLauncher;
use tauri_plugin_global_shortcut::Builder as ShortcutBuilder;
use webplus_controller::{
    PluginController, PluginTrust, SupervisorConfig, DEFAULT_MAX_IN_FLIGHT_INVOCATIONS,
};
use webplus_plugin_config::{discover_plugins, PluginManifest, ServiceDefinition};
use webplus_plugin_package::{recover_incomplete_activations, PreparedPlugin, RecoveryReport};
use webplus_plugin_repository::{
    download_package, fetch_catalog, secure_http_client, CatalogEntry, PluginCatalog,
};
use webplus_plugin_trust::TrustStore;
use webplus_protocol::{InvokeRequest, InvokeResponse, PluginArchitecture, HOST_PROTOCOL_VERSION};

use invocations::{
    InvocationCoordinator, TrackedInvocationStatus, MAX_RETAINED_RESPONSE_BYTES,
    MAX_RUNTIME_OPERATIONS, RUNTIME_RESULT_RETENTION,
};

struct BridgeState {
    controller: Arc<PluginController>,
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
    trust_store: Option<Arc<TrustStore>>,
    install_lock: tokio::sync::Mutex<()>,
    process_policy_entries: usize,
    managed_process_failures: usize,
    repository_client: reqwest::Client,
}

struct DiagnosticsRuntime {
    state: Option<DiagnosticsState>,
    startup_error: Option<&'static str>,
}

#[tauri::command]
fn frontend_ready(caller: WebviewWindow, app: AppHandle) -> Result<(), String> {
    desktop::require_control(&caller)?;
    tracing::info!(
        event_code = "frontend-ready",
        app_version = %app.package_info().version,
        "control frontend mounted and reached native IPC"
    );
    Ok(())
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
    let config = desktop_state.config.snapshot();
    let config_error = config.validate().err().map(|error| error.to_string());
    let business_origin_count = config.business_origins().map_or(0, |origins| origins.len());
    let origin = desktop_state.origin_policy_summary();
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
        origin_policy_error: desktop_state.origin_policy_error(),
        allow_insecure_http: origin.allow_insecure_http,
        plugin_trust_mode: state.plugin_trust_mode,
        active_trust_keys: trust_keys.active,
        plugin_count: state.plugin_count.load(Ordering::Acquire),
        service_count: state.controller.service_count().await,
        plugin_load_failures: state.plugin_load_failures.load(Ordering::Acquire),
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
    catalog_available: bool,
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
    activate_prepared_plugin(&state, &trust_store, prepared).await
}

#[tauri::command]
async fn install_plugin_from_catalog(
    caller: WebviewWindow,
    bridge_state: State<'_, BridgeState>,
    desktop_state: State<'_, desktop::DesktopState>,
    plugin_id: String,
    version: Option<String>,
) -> Result<PluginInstallResult, String> {
    desktop::require_control(&caller)?;
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
    let requested_version = version
        .as_deref()
        .map(semver::Version::parse)
        .transpose()
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
        .select(&plugin_id, requested_version.as_ref())
        .cloned()
        .ok_or_else(|| format!("签名仓库中没有插件 [{plugin_id}] 的匹配版本"))?;
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
    activate_prepared_plugin(&bridge_state, &trust_store, prepared).await
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
    let installed = inspect_plugins(&bridge_state.plugin_root, Some(&trust_store))?;
    let updates = collect_plugin_updates(&installed.manifests, &catalog, requested_plugin_id);
    Ok(PluginUpdateCheckResult {
        catalog_issued_at: catalog.issued_at(),
        catalog_expires_at: catalog.expires_at(),
        updates,
    })
}

fn collect_plugin_updates(
    installed: &[PluginManifest],
    catalog: &PluginCatalog,
    requested_plugin_id: Option<&str>,
) -> Vec<PluginUpdateItem> {
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
            let installed_version = installed
                .iter()
                .find(|manifest| manifest.plugin_id == plugin_id)
                .and_then(|manifest| manifest.metadata.as_ref())
                .map(|metadata| &metadata.version);
            let available_version = catalog.select(&plugin_id, None).map(|entry| &entry.version);
            PluginUpdateItem {
                plugin_id,
                installed_version: installed_version.map(ToString::to_string),
                available_version: available_version.map(ToString::to_string),
                catalog_available: available_version.is_some(),
                update_available: is_plugin_update_available(installed_version, available_version),
            }
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
    {
        return Err(format!(
            "下载包身份与签名仓库不一致：期望 {} {}，实际 {} {}",
            entry.plugin_id,
            entry.version,
            prepared.identity().plugin_id,
            prepared.metadata().version
        ));
    }
    Ok(())
}

async fn activate_prepared_plugin(
    state: &BridgeState,
    trust_store: &TrustStore,
    prepared: PreparedPlugin,
) -> Result<PluginInstallResult, String> {
    let plugin_root = state.plugin_root.clone();

    let plugin_id = prepared.identity().plugin_id.clone();
    let plugin_version = prepared.metadata().version.clone();
    let before = inspect_all_plugins(&plugin_root, &state.local_mapping_root, Some(trust_store))?;
    let previous_manifest = before
        .manifests
        .iter()
        .find(|manifest| {
            manifest.plugin_id == plugin_id
                && !is_local_manifest(manifest, &state.local_mapping_root)
        })
        .cloned();
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
    let installed =
        match inspect_all_plugins(&plugin_root, &state.local_mapping_root, Some(trust_store)) {
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
    )?;
    PluginController::validate_manifests(&plugins.manifests).map_err(|error| error.to_string())?;
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
        "plugin routes reloaded"
    );
    Ok(PluginReloadResult {
        service_count: plugins
            .manifests
            .iter()
            .map(|item| item.services.len())
            .sum(),
        quarantined_plugins: plugins.failures.len(),
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
async fn local_mapping_inventory(
    caller: WebviewWindow,
    state: State<'_, BridgeState>,
) -> Result<LocalMappingInventoryResult, String> {
    desktop::require_control(&caller)?;
    let _install = state.install_lock.lock().await;
    let inspected = inspect_plugins(&state.local_mapping_root, None)?;
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
    let target = local_mappings::bounded_plugin_target(&state.local_mapping_root, &plugin_id)?;
    if !target.is_dir() {
        return Err(format!("本地映射 [{plugin_id}] 不存在"));
    }
    let maintenance = state.controller.begin_maintenance().await;
    let backup = state
        .local_mapping_root
        .join(format!(".mapping-delete-{}", uuid::Uuid::new_v4()));
    std::fs::rename(&target, &backup).map_err(|error| format!("无法暂存待删除映射: {error}"))?;
    let installed = match inspect_all_plugins(
        &state.plugin_root,
        &state.local_mapping_root,
        state.trust_store.as_deref(),
    ) {
        Ok(installed) => installed,
        Err(error) => {
            let _ = std::fs::rename(&backup, &target);
            return Err(error);
        }
    };
    if let Err(error) = maintenance.replace_manifests(&installed.manifests).await {
        let _ = std::fs::rename(&backup, &target);
        return Err(error.to_string());
    }
    std::fs::remove_dir_all(&backup).map_err(|error| format!("无法清理已删除映射: {error}"))?;
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
            let resource_dir = app.path().resource_dir()?;
            let system_config_dir = app.path().config_dir()?;
            let config_dir = app.path().app_config_dir()?;
            let local_data_dir = app.path().app_local_data_dir()?;
            let diagnostics = match DiagnosticsState::initialize(&local_data_dir.join("logs")) {
                Ok(state) => DiagnosticsRuntime {
                    state: Some(state),
                    startup_error: None,
                },
                Err(error) => {
                    eprintln!("diagnostics unavailable: {}", error.code());
                    DiagnosticsRuntime {
                        state: None,
                        startup_error: Some(error.code()),
                    }
                }
            };
            app.manage(diagnostics);
            install_safe_panic_hook();
            let config_path = select_runtime_path(
                config_dir.join("config.json"),
                development_path_override("SSDEV_CONFIG_PATH"),
                cfg!(debug_assertions),
            );
            let config = ConfigStore::open(
                config_path,
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
            let plugin_root = select_runtime_path(
                local_data_dir.join("plugins"),
                development_path_override("SSDEV_PLUGIN_DIR"),
                cfg!(debug_assertions),
            );
            std::fs::create_dir_all(&plugin_root)?;
            let local_mapping_root = local_data_dir.join("local-mappings");
            std::fs::create_dir_all(&local_mapping_root)?;
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
            let recovery = recover_incomplete_activations(&plugin_root)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            log_plugin_recovery(recovery);
            let plugins = inspect_all_plugins(
                &plugin_root,
                &local_mapping_root,
                trust_store.as_deref(),
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
                invocation_coordinator,
                invocation_coordinator_error,
                plugin_load_failures: AtomicUsize::new(plugins.failures.len()),
                plugin_count: AtomicUsize::new(plugins.manifests.len()),
                recovered_plugin_transactions: AtomicUsize::new(recovery_total(recovery)),
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
                trust_store,
                install_lock: tokio::sync::Mutex::new(()),
                process_policy_entries,
                managed_process_failures,
                repository_client,
            });
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
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            bridge_status,
            run_deployment_check,
            frontend_ready,
            install_plugin_package,
            install_plugin_from_catalog,
            check_plugin_updates,
            reload_plugins,
            plugin_inventory,
            inspect_native_component,
            local_mapping_inventory,
            save_local_mapping,
            export_local_mapping,
            import_local_mapping,
            delete_local_mapping,
            debug_plugin_invoke,
            plugin_invoke,
            plugin_invoke_tracked,
            plugin_invocation_status,
            system_declaration,
            desktop::desktop_config,
            desktop::save_desktop_config,
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
            tracing::error!(
                event_code = "desktop-build-failed",
                error_code = "tauri-build-error",
                "desktop initialization failed"
            );
            return;
        }
    };
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

fn recover_plugin_store(state: &BridgeState) -> Result<RecoveryReport, String> {
    let report = recover_incomplete_activations(&state.plugin_root)
        .map_err(|error| format!("插件安装事务恢复失败: {error}"))?;
    let recovered = recovery_total(report);
    if recovered > 0 {
        state
            .recovered_plugin_transactions
            .fetch_add(recovered, Ordering::AcqRel);
        log_plugin_recovery(report);
    }
    Ok(report)
}

fn recovery_total(report: RecoveryReport) -> usize {
    report
        .rolled_back_activations
        .saturating_add(report.removed_committed_transactions)
        .saturating_add(report.removed_staging_directories)
}

fn log_plugin_recovery(report: RecoveryReport) {
    if report.recovered_anything() {
        tracing::warn!(
            event_code = "plugin-transactions-recovered",
            rolled_back_activations = report.rolled_back_activations,
            removed_committed_transactions = report.removed_committed_transactions,
            removed_staging_directories = report.removed_staging_directories,
            "incomplete plugin installation transactions recovered"
        );
    }
}

fn inspect_plugins(
    plugin_root: &std::path::Path,
    trust_store: Option<&TrustStore>,
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
) -> Result<InspectedPlugins, String> {
    let mut signed = inspect_plugins(plugin_root, trust_store)?;
    let local = inspect_plugins(local_mapping_root, None)?;
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

fn allow_unsigned_plugins() -> bool {
    cfg!(debug_assertions)
        && std::env::var("SSDEV_ALLOW_UNSIGNED_PLUGINS")
            .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn install_safe_panic_hook() {
    let _previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        tracing::error!(event_code = "process-panic", "desktop process panicked");
        #[cfg(debug_assertions)]
        _previous(panic_info);
        #[cfg(not(debug_assertions))]
        let _ = panic_info;
    }));
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
        ensure_upgrade_allowed, is_plugin_update_available, legacy_config_candidates,
        select_runtime_path, service_inventory_item,
    };
    use semver::Version;
    use std::path::PathBuf;
    use webplus_plugin_config::ServiceDefinition;

    #[test]
    fn plugin_install_rejects_downgrade_but_allows_repair() {
        let current = Version::new(2, 4, 0);
        assert!(ensure_upgrade_allowed(Some(&current), &Version::new(2, 3, 9)).is_err());
        assert!(ensure_upgrade_allowed(Some(&current), &Version::new(2, 4, 0)).is_ok());
        assert!(ensure_upgrade_allowed(Some(&current), &Version::new(3, 0, 0)).is_ok());
        assert!(ensure_upgrade_allowed(None, &Version::new(1, 0, 0)).is_ok());
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
}
