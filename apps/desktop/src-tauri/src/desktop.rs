use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use ssdev_config::{ConfigStore, DesktopConfig};
use ssdev_origin_policy::{InvocationPolicyCoverage, OriginPolicy, OriginPolicySummary};
use tauri::ipc::CapabilityBuilder;
use tauri::menu::{Menu, MenuBuilder, SubmenuBuilder};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::webview::{NewWindowResponse, PageLoadEvent};
use tauri::{
    AppHandle, Manager, Runtime, State, WebviewUrl, WebviewWindow, WebviewWindowBuilder,
    WindowEvent,
};
use tauri_plugin_autostart::ManagerExt as AutostartManagerExt;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tauri_plugin_opener::OpenerExt;
use url::Url;
use webplus_plugin_config::PluginManifest;

pub(crate) const BUSINESS_LABEL_PREFIX: &str = "business-";
const FLOATING_LABEL_PREFIX: &str = "floating-";
const FLOATING_ACTION_EVENT: &str = "ssdev-floating-action";
const CONTROL_PAGE: &str = "/index.html";
const APP_EXIT_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const BUSINESS_FRONTEND_READY_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_BUSINESS_WINDOWS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BusinessFrontendState {
    Loading,
    Navigating,
    Ready,
    TimedOut,
}

#[derive(Debug, Clone, Copy)]
struct BusinessWindowRuntime {
    state: BusinessFrontendState,
    generation: u64,
    recovering_from_timeout: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BusinessFrontendHealth {
    pub(crate) active_windows: usize,
    pub(crate) loading_windows: usize,
    pub(crate) navigating_windows: usize,
    pub(crate) ready_windows: usize,
    pub(crate) timed_out_windows: usize,
    pub(crate) total_timeouts: u64,
    pub(crate) recovered_after_timeout: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BusinessFrontendRetryResult {
    retried_windows: usize,
    failed_windows: usize,
    unavailable_windows: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BusinessDataClearPreview {
    plan_id: String,
    configured_business_origins: usize,
    business_windows: usize,
    floating_windows: usize,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BusinessWindowReloadResult {
    requested_windows: usize,
    reloaded_windows: usize,
    failed_windows: usize,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BusinessSurfaceCloseResult {
    pub(crate) reset_required: bool,
    pub(crate) requested_windows: usize,
    pub(crate) closed_windows: usize,
    pub(crate) failed_windows: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BusinessReadyTransition {
    recovered_after_timeout: bool,
    duplicate_signal: bool,
}

pub(crate) struct DesktopState {
    pub(crate) config: Arc<ConfigStore>,
    origin_policy: Arc<OriginPolicy>,
    started_managed_processes: BTreeSet<String>,
    next_window_id: AtomicU64,
    next_capability_id: AtomicU64,
    next_tray_action_id: AtomicU64,
    exit_lifecycle: ExitLifecycle,
    ipc_business_origins: Mutex<BTreeSet<String>>,
    business_windows: Mutex<HashMap<String, BusinessWindowRuntime>>,
    business_frontend_timeouts: AtomicU64,
    business_frontend_recoveries: AtomicU64,
    tray_environment_actions: Mutex<HashMap<String, String>>,
    floating_windows: Mutex<HashMap<String, FloatingEntry>>,
}

impl DesktopState {
    pub(crate) fn new(config: ConfigStore, origin_policy: OriginPolicy) -> Self {
        let started_managed_processes = config.snapshot().managed_processes.into_iter().collect();
        Self {
            config: Arc::new(config),
            origin_policy: Arc::new(origin_policy),
            started_managed_processes,
            next_window_id: AtomicU64::new(1),
            next_capability_id: AtomicU64::new(1),
            next_tray_action_id: AtomicU64::new(1),
            exit_lifecycle: ExitLifecycle::new(),
            ipc_business_origins: Mutex::new(BTreeSet::new()),
            business_windows: Mutex::new(HashMap::new()),
            business_frontend_timeouts: AtomicU64::new(0),
            business_frontend_recoveries: AtomicU64::new(0),
            tray_environment_actions: Mutex::new(HashMap::new()),
            floating_windows: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn origin_policy_summary(&self) -> OriginPolicySummary {
        self.origin_policy.summary()
    }

    pub(crate) fn origin_policy_error(&self) -> Option<String> {
        self.origin_policy
            .authorize(&self.config.snapshot())
            .err()
            .map(|error| error.to_string())
    }

    pub(crate) fn authorize_config(&self, config: &DesktopConfig) -> Result<(), String> {
        self.origin_policy
            .authorize(config)
            .map_err(|error| error.to_string())
    }

    pub(crate) fn managed_process_restart_required(&self) -> bool {
        self.config
            .snapshot()
            .managed_processes
            .into_iter()
            .collect::<BTreeSet<_>>()
            != self.started_managed_processes
    }

    pub(crate) fn require_current_managed_processes(&self) -> Result<(), String> {
        if self.managed_process_restart_required() {
            Err("受控辅助进程配置已变更，请重新启动客户端后继续；错误码：managed-process-restart-required".into())
        } else {
            Ok(())
        }
    }

    pub(crate) fn plugin_route_policy_coverage(
        &self,
        config: &DesktopConfig,
        manifests: &[PluginManifest],
    ) -> Result<InvocationPolicyCoverage, String> {
        self.authorize_config(config)?;
        let origins = config
            .business_origins()
            .map_err(|error| error.to_string())?;
        let mut routes = BTreeSet::new();
        for manifest in manifests {
            for service in &manifest.services {
                for method in &service.methods {
                    routes.insert((service.service_id.clone(), method.name.clone()));
                    if let Some(alias) = &method.alias {
                        routes.insert((service.service_id.clone(), alias.clone()));
                    }
                }
            }
        }
        self.origin_policy
            .invocation_coverage(&origins, &routes)
            .map_err(|error| error.to_string())
    }

    fn reserve_business_window_label(&self) -> Result<String, String> {
        let mut windows = self
            .business_windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if windows.len() >= MAX_BUSINESS_WINDOWS {
            return Err(format!("业务窗口数量已达到上限 [{MAX_BUSINESS_WINDOWS}]"));
        }
        loop {
            let id = self.next_window_id.fetch_add(1, Ordering::Relaxed);
            let label = format!("{BUSINESS_LABEL_PREFIX}{id}");
            if let std::collections::hash_map::Entry::Vacant(entry) = windows.entry(label.clone()) {
                entry.insert(BusinessWindowRuntime {
                    state: BusinessFrontendState::Loading,
                    generation: 0,
                    recovering_from_timeout: false,
                });
                return Ok(label);
            }
        }
    }

    fn release_business_window_label(&self, label: &str) {
        self.business_windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(label);
    }

    fn release_floating_window_label(&self, label: &str) {
        self.floating_windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|_, entry| entry.window_label != label);
    }

    fn mark_business_navigation(&self, label: &str, business_origin: bool) -> Option<u64> {
        let mut windows = self
            .business_windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let runtime = windows.get_mut(label)?;
        runtime.recovering_from_timeout =
            runtime.recovering_from_timeout || runtime.state == BusinessFrontendState::TimedOut;
        runtime.generation = runtime.generation.wrapping_add(1).max(1);
        runtime.state = if business_origin {
            BusinessFrontendState::Loading
        } else {
            BusinessFrontendState::Navigating
        };
        business_origin.then_some(runtime.generation)
    }

    fn mark_business_frontend_ready(&self, label: &str) -> Result<BusinessReadyTransition, String> {
        let mut windows = self
            .business_windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let runtime = windows
            .get_mut(label)
            .ok_or_else(|| "业务窗口就绪状态已失效".to_owned())?;
        let recovered_after_timeout =
            runtime.state == BusinessFrontendState::TimedOut || runtime.recovering_from_timeout;
        let duplicate_signal = runtime.state == BusinessFrontendState::Ready;
        runtime.state = BusinessFrontendState::Ready;
        runtime.recovering_from_timeout = false;
        if recovered_after_timeout {
            self.business_frontend_recoveries
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(BusinessReadyTransition {
            recovered_after_timeout,
            duplicate_signal,
        })
    }

    fn report_business_frontend_timeout(&self, label: &str, generation: u64) -> bool {
        let mut windows = self
            .business_windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(runtime) = windows.get_mut(label) else {
            return false;
        };
        if runtime.generation != generation || runtime.state != BusinessFrontendState::Loading {
            return false;
        }
        runtime.state = BusinessFrontendState::TimedOut;
        runtime.recovering_from_timeout = false;
        self.business_frontend_timeouts
            .fetch_add(1, Ordering::Relaxed);
        true
    }

    fn claim_timed_out_business_windows(&self) -> Vec<(String, u64)> {
        let mut windows = self
            .business_windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut claimed = windows
            .iter_mut()
            .filter_map(|(label, runtime)| {
                if runtime.state != BusinessFrontendState::TimedOut {
                    return None;
                }
                runtime.generation = runtime.generation.wrapping_add(1).max(1);
                runtime.state = BusinessFrontendState::Loading;
                runtime.recovering_from_timeout = true;
                Some((label.clone(), runtime.generation))
            })
            .collect::<Vec<_>>();
        claimed.sort_by(|left, right| left.0.cmp(&right.0));
        claimed
    }

    fn restore_business_frontend_timeout(&self, label: &str, generation: u64) -> bool {
        let mut windows = self
            .business_windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(runtime) = windows.get_mut(label) else {
            return false;
        };
        if runtime.generation != generation || runtime.state != BusinessFrontendState::Loading {
            return false;
        }
        runtime.state = BusinessFrontendState::TimedOut;
        runtime.recovering_from_timeout = false;
        true
    }

    pub(crate) fn business_frontend_health(&self) -> BusinessFrontendHealth {
        let windows = self
            .business_windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut health = BusinessFrontendHealth {
            active_windows: windows.len(),
            total_timeouts: self.business_frontend_timeouts.load(Ordering::Relaxed),
            recovered_after_timeout: self.business_frontend_recoveries.load(Ordering::Relaxed),
            ..BusinessFrontendHealth::default()
        };
        for runtime in windows.values() {
            match runtime.state {
                BusinessFrontendState::Loading => health.loading_windows += 1,
                BusinessFrontendState::Navigating => health.navigating_windows += 1,
                BusinessFrontendState::Ready => health.ready_windows += 1,
                BusinessFrontendState::TimedOut => health.timed_out_windows += 1,
            }
        }
        health
    }

    fn take_floating_label(&self) -> String {
        let id = self.next_window_id.fetch_add(1, Ordering::Relaxed);
        format!("{FLOATING_LABEL_PREFIX}{id}")
    }

    pub(crate) fn ensure_business_ipc_capabilities<R: tauri::Runtime>(
        &self,
        app: &AppHandle<R>,
        config: &DesktopConfig,
    ) -> Result<(), String> {
        self.authorize_config(config)?;
        let origins = config
            .business_origins()
            .map_err(|error| error.to_string())?;
        let mut registered = self
            .ipc_business_origins
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let pending = origins.difference(&registered).cloned().collect::<Vec<_>>();
        for origin in pending {
            let id = self.next_capability_id.fetch_add(1, Ordering::Relaxed);
            add_remote_command_capability(
                app,
                format!("business-origin-{id}"),
                BUSINESS_LABEL_PREFIX.to_owned() + "*",
                &origin,
                crate::command_permissions::BUSINESS_PERMISSIONS,
            )?;
            add_remote_command_capability(
                app,
                format!("floating-origin-{id}"),
                FLOATING_LABEL_PREFIX.to_owned() + "*",
                &origin,
                crate::command_permissions::FLOATING_PERMISSIONS,
            )?;
            registered.insert(origin);
        }
        Ok(())
    }
}

struct ExitLifecycle {
    drain_started: AtomicBool,
    ready: AtomicBool,
}

struct ExitDrainGuard<F: FnOnce()> {
    finalize: Option<F>,
}

impl<F: FnOnce()> ExitDrainGuard<F> {
    fn new(finalize: F) -> Self {
        Self {
            finalize: Some(finalize),
        }
    }

    fn complete(mut self) {
        if let Some(finalize) = self.finalize.take() {
            finalize();
        }
    }
}

impl<F: FnOnce()> Drop for ExitDrainGuard<F> {
    fn drop(&mut self) {
        let Some(finalize) = self.finalize.take() else {
            return;
        };
        tracing::error!(
            event_code = "app-exit-drain-task-failed",
            error_code = "app-exit-drain-task-failed",
            "application exit drain task terminated unexpectedly"
        );
        finalize();
    }
}

impl ExitLifecycle {
    fn new() -> Self {
        Self {
            drain_started: AtomicBool::new(false),
            ready: AtomicBool::new(false),
        }
    }

    fn begin_drain(&self) -> bool {
        self.drain_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    fn mark_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }
}

fn add_remote_command_capability<R: tauri::Runtime>(
    app: &AppHandle<R>,
    identifier: String,
    window: String,
    origin: &str,
    permissions: &[&str],
) -> Result<(), String> {
    let capability = permissions.iter().fold(
        CapabilityBuilder::new(identifier)
            .local(false)
            .remote(format!("{origin}/*"))
            .window(window),
        |capability, permission| capability.permission(*permission),
    );
    app.add_capability(capability)
        .map_err(|error| format!("无法为已授权业务来源注册窄 IPC 权限: {error}"))
}

#[derive(Clone)]
struct FloatingEntry {
    window_label: String,
    parent_label: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigSnapshot {
    config: DesktopConfig,
    path: PathBuf,
    migrated_from: Option<PathBuf>,
    migration_sources: Vec<PathBuf>,
    migration_warnings: Vec<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigImportEnvironmentPreview {
    name: String,
    url: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigChangePreview {
    pub(crate) config_changed: bool,
    pub(crate) business_surface_reset_required: bool,
    pub(crate) project_identity_changed: bool,
    pub(crate) default_website_changed: bool,
    pub(crate) tenant_changed: bool,
    pub(crate) allow_switch_changed: bool,
    pub(crate) auto_close_changed: bool,
    pub(crate) auto_start_changed: bool,
    pub(crate) plugin_catalog_changed: bool,
    pub(crate) current_project_id: String,
    pub(crate) current_project_name: String,
    pub(crate) candidate_project_id: String,
    pub(crate) candidate_project_name: String,
    pub(crate) candidate_default_website: Option<String>,
    pub(crate) candidate_allow_switch: bool,
    pub(crate) candidate_auto_close: bool,
    pub(crate) candidate_auto_start: bool,
    pub(crate) current_environment_count: usize,
    pub(crate) candidate_environment_count: usize,
    pub(crate) candidate_environments: Vec<ConfigImportEnvironmentPreview>,
    pub(crate) current_business_origin_count: usize,
    pub(crate) candidate_business_origin_count: usize,
    pub(crate) current_trusted_origin_count: usize,
    pub(crate) candidate_trusted_origin_count: usize,
    pub(crate) current_external_origin_count: usize,
    pub(crate) candidate_external_origin_count: usize,
    pub(crate) current_managed_process_count: usize,
    pub(crate) candidate_managed_process_count: usize,
    pub(crate) current_enabled_shortcut_count: usize,
    pub(crate) candidate_enabled_shortcut_count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigImportPreview {
    plan_id: String,
    #[serde(flatten)]
    change: ConfigChangePreview,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigImportResult {
    #[serde(flatten)]
    snapshot: ConfigSnapshot,
    #[serde(flatten)]
    closed_surfaces: BusinessSurfaceCloseResult,
}

#[tauri::command]
pub(crate) fn desktop_config<R: tauri::Runtime>(
    caller: WebviewWindow<R>,
    state: State<'_, DesktopState>,
) -> Result<ConfigSnapshot, String> {
    require_control(&caller)?;
    Ok(config_snapshot(&state))
}

fn config_snapshot(state: &DesktopState) -> ConfigSnapshot {
    ConfigSnapshot {
        config: state.config.snapshot(),
        path: state.config.path().to_path_buf(),
        migrated_from: state.config.migrated_from().map(Path::to_path_buf),
        migration_sources: state.config.migration_sources().to_vec(),
        migration_warnings: state.config.migration_warnings().to_vec(),
    }
}

#[tauri::command]
pub(crate) async fn save_desktop_config(
    caller: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
    bridge_state: State<'_, crate::BridgeState>,
    config: DesktopConfig,
) -> Result<BusinessSurfaceCloseResult, String> {
    require_control(&caller)?;
    let _install = bridge_state.install_lock.lock().await;
    crate::validate_config_signed_plugin_route_change(&state, &bridge_state, &config).await?;
    let reset_required = business_surface_reset_required(&state.config.snapshot(), &config);
    replace_desktop_config(&app, &state, config)?;
    Ok(if reset_required {
        force_close_business_surfaces(&app)
    } else {
        BusinessSurfaceCloseResult::default()
    })
}

#[tauri::command]
pub(crate) async fn inspect_desktop_config_import(
    caller: WebviewWindow,
    state: State<'_, DesktopState>,
    bridge_state: State<'_, crate::BridgeState>,
    source: PathBuf,
) -> Result<ConfigImportPreview, String> {
    require_control(&caller)?;
    let _install = bridge_state.install_lock.lock().await;
    let candidate = ssdev_config::load_config_file(&source).map_err(|error| error.to_string())?;
    crate::validate_config_signed_plugin_route_change(&state, &bridge_state, &candidate).await?;
    let preview = build_config_import_preview(&state.config.snapshot(), &candidate)?;
    tracing::info!(
        event_code = "desktop-config-import-inspected",
        config_changed = preview.change.config_changed,
        business_surface_reset_required = preview.change.business_surface_reset_required,
        business_origins = preview.change.candidate_business_origin_count,
        environments = preview.change.candidate_environment_count,
        managed_processes = preview.change.candidate_managed_process_count,
        enabled_shortcuts = preview.change.candidate_enabled_shortcut_count,
        "desktop config import inspected"
    );
    Ok(preview)
}

pub(crate) fn replace_desktop_config(
    app: &AppHandle,
    state: &DesktopState,
    config: DesktopConfig,
) -> Result<(), String> {
    state.authorize_config(&config)?;
    state.ensure_business_ipc_capabilities(app, &config)?;
    let previous = state.config.snapshot();
    crate::shortcuts::replace(app, &config.key_bindings, &previous.key_bindings)?;
    let previous_autostart = match current_autostart(app) {
        Ok(enabled) => enabled,
        Err(error) => {
            let restore = crate::shortcuts::replace(app, &previous.key_bindings, &[]);
            return Err(append_restore_error(error, "恢复原快捷键", restore));
        }
    };
    if let Err(error) = replace_autostart(app, config.auto_start) {
        let restore_autostart = replace_autostart(app, previous_autostart);
        let restore_shortcuts = crate::shortcuts::replace(app, &previous.key_bindings, &[]);
        return Err(append_desktop_restore_errors(
            error,
            restore_autostart,
            restore_shortcuts,
        ));
    }
    if let Err(error) = state.config.replace(config) {
        let restore_autostart = replace_autostart(app, previous_autostart);
        let restore_shortcuts = crate::shortcuts::replace(app, &previous.key_bindings, &[]);
        return Err(append_desktop_restore_errors(
            error.to_string(),
            restore_autostart,
            restore_shortcuts,
        ));
    }
    if refresh_tray_menu(app).is_err() {
        tracing::warn!(
            event_code = "tray-menu-refresh-failed",
            error_code = "tray-menu-unavailable",
            "tray menu refresh failed after desktop config replacement"
        );
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn import_desktop_config(
    caller: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
    bridge_state: State<'_, crate::BridgeState>,
    source: PathBuf,
    expected_plan_id: String,
) -> Result<ConfigImportResult, String> {
    require_control(&caller)?;
    let _install = bridge_state.install_lock.lock().await;
    if !crate::is_lowercase_sha256(&expected_plan_id) {
        return Err("配置导入计划标识无效，请重新预检".into());
    }
    let candidate = ssdev_config::load_config_file(&source).map_err(|error| error.to_string())?;
    crate::validate_config_signed_plugin_route_change(&state, &bridge_state, &candidate).await?;
    let preview = build_config_import_preview(&state.config.snapshot(), &candidate)?;
    if preview.plan_id != expected_plan_id {
        return Err("导入文件或当前配置已在预检后变化，请重新预检后确认导入".into());
    }
    if !preview.change.config_changed {
        tracing::info!(
            event_code = "desktop-config-import-unchanged",
            "desktop config import skipped because configuration is unchanged"
        );
        return Ok(ConfigImportResult {
            snapshot: config_snapshot(&state),
            closed_surfaces: BusinessSurfaceCloseResult::default(),
        });
    }
    replace_desktop_config(&app, &state, candidate)?;
    let closed_surfaces = if preview.change.business_surface_reset_required {
        force_close_business_surfaces(&app)
    } else {
        BusinessSurfaceCloseResult::default()
    };
    tracing::info!(
        event_code = "desktop-config-imported",
        config_changed = preview.change.config_changed,
        business_surface_reset_required = preview.change.business_surface_reset_required,
        business_origins = preview.change.candidate_business_origin_count,
        environments = preview.change.candidate_environment_count,
        managed_processes = preview.change.candidate_managed_process_count,
        enabled_shortcuts = preview.change.candidate_enabled_shortcut_count,
        "desktop config imported"
    );
    Ok(ConfigImportResult {
        snapshot: config_snapshot(&state),
        closed_surfaces,
    })
}

fn build_config_import_preview(
    current: &DesktopConfig,
    candidate: &DesktopConfig,
) -> Result<ConfigImportPreview, String> {
    Ok(ConfigImportPreview {
        plan_id: config_import_plan_id(current, candidate)?,
        change: build_config_change_preview(current, candidate)?,
    })
}

pub(crate) fn build_config_change_preview(
    current: &DesktopConfig,
    candidate: &DesktopConfig,
) -> Result<ConfigChangePreview, String> {
    let current_business_origin_count = current
        .business_origins()
        .map_err(|error| error.to_string())?
        .len();
    let candidate_business_origin_count = candidate
        .business_origins()
        .map_err(|error| error.to_string())?
        .len();
    Ok(ConfigChangePreview {
        config_changed: current != candidate,
        business_surface_reset_required: business_surface_reset_required(current, candidate),
        project_identity_changed: current.project_id != candidate.project_id
            || current.project_name != candidate.project_name,
        default_website_changed: current.website != candidate.website,
        tenant_changed: current.tenant_id != candidate.tenant_id,
        allow_switch_changed: current.allow_switch != candidate.allow_switch,
        auto_close_changed: current.auto_close != candidate.auto_close,
        auto_start_changed: current.auto_start != candidate.auto_start,
        plugin_catalog_changed: current.plugin_catalog_url != candidate.plugin_catalog_url
            || current.plugin_catalog_signature_url != candidate.plugin_catalog_signature_url,
        current_project_id: current.project_id.clone(),
        current_project_name: current.project_name.clone(),
        candidate_project_id: candidate.project_id.clone(),
        candidate_project_name: candidate.project_name.clone(),
        candidate_default_website: candidate.website.clone(),
        candidate_allow_switch: candidate.allow_switch,
        candidate_auto_close: candidate.auto_close,
        candidate_auto_start: candidate.auto_start,
        current_environment_count: current.environments.len(),
        candidate_environment_count: candidate.environments.len(),
        candidate_environments: candidate
            .environments
            .iter()
            .map(|environment| ConfigImportEnvironmentPreview {
                name: environment.name.clone(),
                url: environment.url.clone(),
            })
            .collect(),
        current_business_origin_count,
        candidate_business_origin_count,
        current_trusted_origin_count: current.trusted_origins.len(),
        candidate_trusted_origin_count: candidate.trusted_origins.len(),
        current_external_origin_count: current.external_origins.len(),
        candidate_external_origin_count: candidate.external_origins.len(),
        current_managed_process_count: current.managed_processes.len(),
        candidate_managed_process_count: candidate.managed_processes.len(),
        current_enabled_shortcut_count: enabled_shortcut_count(current),
        candidate_enabled_shortcut_count: enabled_shortcut_count(candidate),
    })
}

fn business_surface_reset_required(current: &DesktopConfig, candidate: &DesktopConfig) -> bool {
    let mut normalized_candidate = candidate.clone();
    normalized_candidate
        .project_id
        .clone_from(&current.project_id);
    normalized_candidate
        .project_name
        .clone_from(&current.project_name);
    normalized_candidate.allow_switch = current.allow_switch;
    normalized_candidate.auto_close = current.auto_close;
    normalized_candidate.auto_start = current.auto_start;
    normalized_candidate
        .processes
        .clone_from(&current.processes);
    normalized_candidate
        .key_bindings
        .clone_from(&current.key_bindings);
    normalized_candidate
        .plugin_catalog_url
        .clone_from(&current.plugin_catalog_url);
    normalized_candidate
        .plugin_catalog_signature_url
        .clone_from(&current.plugin_catalog_signature_url);
    normalized_candidate.feedback = current.feedback;
    normalized_candidate != *current
}

fn enabled_shortcut_count(config: &DesktopConfig) -> usize {
    config
        .key_bindings
        .iter()
        .filter(|binding| binding.enabled)
        .count()
}

fn config_import_plan_id(
    current: &DesktopConfig,
    candidate: &DesktopConfig,
) -> Result<String, String> {
    let current = serde_json::to_vec(current).map_err(|error| error.to_string())?;
    let candidate = serde_json::to_vec(candidate).map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(b"SSDEV-DESKTOP-CONFIG-IMPORT-PLAN\0");
    crate::hash_plan_field(&mut hasher, &current);
    crate::hash_plan_field(&mut hasher, &candidate);
    Ok(crate::lowercase_hex(&hasher.finalize()))
}

#[tauri::command]
pub(crate) fn export_desktop_config(
    caller: WebviewWindow,
    state: State<'_, DesktopState>,
    destination: PathBuf,
) -> Result<(), String> {
    require_control(&caller)?;
    let config = state.config.snapshot();
    state.authorize_config(&config)?;
    ssdev_config::export_config_file(&destination, &config).map_err(|error| error.to_string())
}

pub(crate) fn autostart_status(app: &AppHandle) -> (Option<bool>, Option<String>) {
    match current_autostart(app) {
        Ok(enabled) => (Some(enabled), None),
        Err(error) => (None, Some(error)),
    }
}

fn current_autostart(app: &AppHandle) -> Result<bool, String> {
    app.autolaunch()
        .is_enabled()
        .map_err(|error| format!("无法读取开机启动状态: {error}"))
}

pub(crate) fn replace_autostart(app: &AppHandle, enabled: bool) -> Result<(), String> {
    let manager = app.autolaunch();
    let current = manager
        .is_enabled()
        .map_err(|error| format!("无法读取开机启动状态: {error}"))?;
    if current == enabled {
        return Ok(());
    }
    if enabled {
        manager
            .enable()
            .map_err(|error| format!("启用开机启动失败: {error}"))?;
    } else {
        manager
            .disable()
            .map_err(|error| format!("关闭开机启动失败: {error}"))?;
    }
    let actual = manager
        .is_enabled()
        .map_err(|error| format!("无法确认开机启动状态: {error}"))?;
    if actual != enabled {
        return Err("操作系统未接受开机启动状态变更".into());
    }
    Ok(())
}

fn append_restore_error(error: String, label: &str, restore: Result<(), String>) -> String {
    match restore {
        Ok(()) => error,
        Err(restore) => format!("{error}; {label}失败: {restore}"),
    }
}

fn append_desktop_restore_errors(
    error: String,
    restore_autostart: Result<(), String>,
    restore_shortcuts: Result<(), String>,
) -> String {
    let error = append_restore_error(error, "恢复原开机启动状态", restore_autostart);
    append_restore_error(error, "恢复原快捷键", restore_shortcuts)
}

#[tauri::command]
pub(crate) fn open_business_window(
    caller: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
    environment: Option<String>,
) -> Result<String, String> {
    require_control(&caller)?;
    match environment {
        Some(environment) => open_configured_environment(&app, &state, &environment),
        None => open_configured_business(&app, &state),
    }
}

#[tauri::command]
pub(crate) fn open_external_url(
    caller: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
    url: String,
) -> Result<(), String> {
    require_business(&caller, &state)?;
    if url.len() > 4096 {
        return Err("外部地址过长".into());
    }
    let allowed = state
        .config
        .snapshot()
        .external_url_origins()
        .map_err(|error| error.to_string())?;
    let current = caller.url().map_err(|error| error.to_string())?;
    let url = validate_external_url(&current, &url, &allowed)?;
    app.opener()
        .open_url(url.as_str(), None::<&str>)
        .map_err(|error| error.to_string())
}

fn validate_external_url(
    current: &Url,
    candidate: &str,
    allowed_origins: &BTreeSet<String>,
) -> Result<Url, String> {
    let url = Url::parse(candidate)
        .or_else(|_| current.join(candidate))
        .map_err(|error| format!("无效的外部地址: {error}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("只允许打开 HTTP(S) 地址".into());
    }
    let origin = url.origin().ascii_serialization();
    if !allowed_origins.contains(&origin) {
        return Err(format!("外部地址来源 [{origin}] 未获授权"));
    }
    Ok(url)
}

pub(crate) fn open_configured_business(
    app: &AppHandle,
    state: &DesktopState,
) -> Result<String, String> {
    let config = state.config.snapshot();
    let url = config
        .website_url()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "尚未配置业务系统地址".to_owned())?;
    open_business_at(app, state, url)
}

fn open_configured_environment(
    app: &AppHandle,
    state: &DesktopState,
    requested_name: &str,
) -> Result<String, String> {
    let config = state.config.snapshot();
    state.authorize_config(&config)?;
    if !config.allow_switch {
        return Err("当前配置未启用环境切换".into());
    }
    let requested_name = requested_name.trim();
    let url = config
        .environment_url(requested_name)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("未找到环境 [{requested_name}]"))?;
    open_business_at(app, state, url)
}

pub(crate) fn open_business_at(
    app: &AppHandle,
    state: &DesktopState,
    url: Url,
) -> Result<String, String> {
    state.require_current_managed_processes()?;
    let config = state.config.snapshot();
    state.authorize_config(&config)?;
    let business_origins = config
        .business_origins()
        .map_err(|error| error.to_string())?;
    if !business_origins.contains(&url.origin().ascii_serialization()) {
        return Err(format!(
            "业务地址来源 [{}] 未在配置中授权",
            url.origin().ascii_serialization()
        ));
    }
    let navigation_origins = config
        .allowed_origins()
        .map_err(|error| error.to_string())?;
    let label = state.reserve_business_window_label()?;
    let result = build_business_window(
        app,
        &label,
        url,
        navigation_origins,
        business_origins,
        BusinessWindowOptions::default(),
    );
    match result {
        Ok(_) => {
            tracing::info!(
                event_code = "business-window-created",
                app_version = %app.package_info().version,
                "authorized business window created"
            );
            Ok(label)
        }
        Err(error) => {
            state.release_business_window_label(&label);
            Err(error)
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SecondaryWindowRequest {
    url: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    screen_index: Option<usize>,
    #[serde(default)]
    context: Option<Value>,
    #[serde(default)]
    width: Option<u32>,
    #[serde(default)]
    height: Option<u32>,
    #[serde(default)]
    left: Option<i32>,
    #[serde(default)]
    top: Option<i32>,
}

#[tauri::command]
pub(crate) fn open_secondary_window(
    caller: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
    request: SecondaryWindowRequest,
) -> Result<String, String> {
    require_business(&caller, &state)?;
    if request.url.len() > 4096 {
        return Err("窗口地址过长".into());
    }
    let url = match Url::parse(&request.url) {
        Ok(url) => url,
        Err(_) => caller
            .url()
            .map_err(|error| error.to_string())?
            .join(&request.url)
            .map_err(|error| format!("无效的窗口地址: {error}"))?,
    };
    let config = state.config.snapshot();
    let business_origins = config
        .business_origins()
        .map_err(|error| error.to_string())?;
    let navigation_origins = config
        .allowed_origins()
        .map_err(|error| error.to_string())?;
    if !matches!(url.scheme(), "http" | "https")
        || !business_origins.contains(&url.origin().ascii_serialization())
    {
        return Err(format!(
            "新窗口来源 [{}] 未在配置中授权",
            url.origin().ascii_serialization()
        ));
    }

    validate_secondary_window_request(&request)?;
    let title = request.title.unwrap_or_else(|| "SSDEV Desktop".into());
    if title.chars().count() > 128 {
        return Err("窗口标题不能超过 128 个字符".into());
    }
    if let Some(context) = &request.context {
        if !context.is_object() {
            return Err("窗口上下文必须是 JSON 对象".into());
        }
        if serde_json::to_vec(context)
            .map_err(|error| error.to_string())?
            .len()
            > 64 * 1024
        {
            return Err("窗口上下文不能超过 64 KiB".into());
        }
    }
    let position = match (request.left, request.top) {
        (Some(left), Some(top)) => Some((f64::from(left), f64::from(top))),
        _ => monitor_position(&app, request.screen_index.unwrap_or(1))?,
    };
    let inner_size = request
        .width
        .zip(request.height)
        .map(|(width, height)| (f64::from(width), f64::from(height)));
    let label = state.reserve_business_window_label()?;
    let result = build_business_window(
        &app,
        &label,
        url,
        navigation_origins,
        business_origins,
        BusinessWindowOptions {
            title,
            position,
            context: request.context,
            inner_size,
        },
    );
    match result {
        Ok(_) => Ok(label),
        Err(error) => {
            state.release_business_window_label(&label);
            Err(error)
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FloatingWindowRequest {
    id: String,
    url: String,
    #[serde(default = "default_floating_duration")]
    duration_ms: u64,
    #[serde(default = "default_floating_width")]
    width: u32,
    #[serde(default = "default_floating_height")]
    height: u32,
    #[serde(default)]
    context: Option<Value>,
}

#[tauri::command]
pub(crate) fn show_floating_window(
    caller: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
    request: FloatingWindowRequest,
) -> Result<String, String> {
    require_business(&caller, &state)?;
    validate_floating_request(&request)?;
    let url = match Url::parse(&request.url) {
        Ok(url) => url,
        Err(_) => caller
            .url()
            .map_err(|error| error.to_string())?
            .join(&request.url)
            .map_err(|error| format!("无效的悬浮窗地址: {error}"))?,
    };
    let origins = state
        .config
        .snapshot()
        .business_origins()
        .map_err(|error| error.to_string())?;
    if !matches!(url.scheme(), "http" | "https")
        || !origins.contains(&url.origin().ascii_serialization())
    {
        return Err(format!(
            "悬浮窗来源 [{}] 未在配置中授权",
            url.origin().ascii_serialization()
        ));
    }

    if let Some(previous) = state
        .floating_windows
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&request.id)
    {
        if let Some(window) = app.get_webview_window(&previous.window_label) {
            let _ = window.close();
        }
    }

    let label = state.take_floating_label();
    let position = floating_position(&app, request.width, request.height)?;
    let script = floating_initialization_script(&origins, &request.id, request.context.as_ref())?;
    let navigation_origins = origins;
    let builder = WebviewWindowBuilder::new(&app, &label, WebviewUrl::External(url))
        .title("SSDEV Desktop")
        .inner_size(f64::from(request.width), f64::from(request.height))
        .position(position.0, position.1)
        .decorations(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .visible(false)
        .initialization_script(script)
        .on_navigation(move |url| {
            matches!(url.scheme(), "http" | "https")
                && navigation_origins.contains(&url.origin().ascii_serialization())
        })
        .on_new_window(|_, _| NewWindowResponse::Deny);
    #[cfg(not(target_os = "macos"))]
    let builder = builder.transparent(true);
    let window = builder.build().map_err(|error| error.to_string())?;
    state
        .floating_windows
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(
            request.id.clone(),
            FloatingEntry {
                window_label: label.clone(),
                parent_label: caller.label().to_owned(),
            },
        );
    install_floating_cleanup(&app, &window, request.id.clone(), label.clone());
    window.show().map_err(|error| error.to_string())?;

    let app_after_timeout = app.clone();
    let id_after_timeout = request.id;
    let label_after_timeout = label.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(request.duration_ms)).await;
        close_floating_by_identity(&app_after_timeout, &id_after_timeout, &label_after_timeout);
    });
    Ok(label)
}

#[tauri::command]
pub(crate) fn close_floating_window(
    caller: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
    id: String,
) -> Result<(), String> {
    require_authorized_webview(&caller, &state)?;
    let entry = floating_entry(&state, &id).ok_or_else(|| "悬浮窗不存在".to_owned())?;
    if caller.label() != entry.parent_label && caller.label() != entry.window_label {
        return Err("当前窗口无权关闭该悬浮窗".into());
    }
    close_floating_by_identity(&app, &id, &entry.window_label);
    Ok(())
}

#[tauri::command]
pub(crate) fn resolve_floating_window(
    caller: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
    id: String,
    payload: Value,
) -> Result<(), String> {
    require_authorized_webview(&caller, &state)?;
    if serde_json::to_vec(&payload)
        .map_err(|error| error.to_string())?
        .len()
        > 64 * 1024
    {
        return Err("悬浮窗返回数据不能超过 64 KiB".into());
    }
    let entry = floating_entry(&state, &id).ok_or_else(|| "悬浮窗不存在".to_owned())?;
    if caller.label() != entry.window_label {
        return Err("只有对应悬浮窗可以提交处理结果".into());
    }
    if let Some(parent) = app.get_webview_window(&entry.parent_label) {
        let payload = serde_json::to_string(&payload).map_err(|error| error.to_string())?;
        parent
            .eval(format!(
                "window.dispatchEvent(new CustomEvent('{FLOATING_ACTION_EVENT}', {{ detail: {payload} }}));"
            ))
            .map_err(|error| error.to_string())?;
    }
    close_floating_by_identity(&app, &id, &entry.window_label);
    Ok(())
}

#[tauri::command]
pub(crate) fn inspect_business_data_clear(
    caller: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
) -> Result<BusinessDataClearPreview, String> {
    require_control(&caller)?;
    build_business_data_clear_preview(&app, &state)
}

#[tauri::command]
pub(crate) fn clear_business_data(
    caller: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
    expected_plan_id: String,
) -> Result<BusinessSurfaceCloseResult, String> {
    require_control(&caller)?;
    if !crate::is_lowercase_sha256(&expected_plan_id) {
        return Err("站点数据清理计划标识无效，请重新检查影响".into());
    }
    let preview = build_business_data_clear_preview(&app, &state)?;
    if preview.plan_id != expected_plan_id {
        return Err("业务窗口或项目来源在确认后发生变化，请重新检查清理影响".into());
    }

    caller.clear_all_browsing_data().map_err(|_| {
        tracing::warn!(
            event_code = "business-data-clear-failed",
            error_code = "webview-data-clear",
            "business browsing data clear request failed"
        );
        "无法提交站点数据清理请求，请关闭业务窗口后重试；错误码：webview-data-clear".to_owned()
    })?;

    let result = force_close_business_surfaces(&app);
    tracing::info!(
        event_code = "business-data-clear-requested",
        configured_business_origins = preview.configured_business_origins,
        business_windows = preview.business_windows,
        floating_windows = preview.floating_windows,
        close_requested_windows = result.requested_windows,
        closed_windows = result.closed_windows,
        failed_window_closures = result.failed_windows,
        "business browsing data clear request accepted"
    );
    Ok(result)
}

#[tauri::command]
pub(crate) fn reload_business_windows(
    caller: WebviewWindow,
    app: AppHandle,
) -> Result<BusinessWindowReloadResult, String> {
    require_control(&caller)?;
    Ok(reload_business_windows_internal(&app))
}

#[tauri::command]
pub(crate) fn retry_timed_out_business_windows(
    caller: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
) -> Result<BusinessFrontendRetryResult, String> {
    require_control(&caller)?;
    Ok(retry_timed_out_business_windows_internal(&app, &state))
}

pub(crate) fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    let menu = build_tray_menu(app.handle())?;
    let mut builder = TrayIconBuilder::with_id("ssdev-main")
        .menu(&menu)
        .tooltip("SSDEV Desktop")
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| {
            let event_id = event.id.as_ref();
            match event_id {
                "show-control" => show_control(app),
                "open-business" => {
                    let state = app.state::<DesktopState>();
                    if open_configured_business(app, &state).is_err() {
                        tracing::warn!(
                            event_code = "tray-open-business-failed",
                            "tray business window action failed"
                        );
                        show_control(app);
                    }
                }
                "reload-business" => {
                    let result = reload_business_windows_internal(app);
                    if result.failed_windows > 0 {
                        tracing::warn!(
                            event_code = "tray-reload-business-failed",
                            requested_windows = result.requested_windows,
                            reloaded_windows = result.reloaded_windows,
                            failed_windows = result.failed_windows,
                            "tray reload action failed"
                        );
                        show_control(app);
                    }
                }
                "quit" => request_graceful_exit(app, 0),
                _ => open_tray_environment(app, event_id),
            }
        })
        .on_tray_icon_event(|tray, event| {
            if matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }
            ) {
                focus_primary_surface(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    let tray = builder.build(app)?;
    app.manage(tray);
    Ok(())
}

fn build_tray_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let state = app.state::<DesktopState>();
    let config = state.config.snapshot();
    let mut environment_actions = HashMap::new();
    let mut builder = MenuBuilder::new(app)
        .text("show-control", "打开控制台")
        .text("open-business", "进入默认业务系统");
    if config.allow_switch && !config.environments.is_empty() {
        let mut environments = SubmenuBuilder::new(app, "切换环境");
        for environment in config.environments {
            let id = state.next_tray_action_id.fetch_add(1, Ordering::Relaxed);
            let id = format!("open-environment-{id}");
            environments = environments.text(&id, environment.name.trim());
            environment_actions.insert(id, environment.name);
        }
        let environments = environments.build()?;
        builder = builder.item(&environments);
    }
    *state
        .tray_environment_actions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = environment_actions;
    builder
        .separator()
        .text("reload-business", "刷新业务窗口")
        .separator()
        .text("quit", "退出程序")
        .build()
}

fn refresh_tray_menu(app: &AppHandle) -> Result<(), String> {
    let menu = build_tray_menu(app).map_err(|error| error.to_string())?;
    let tray = app
        .tray_by_id("ssdev-main")
        .ok_or_else(|| "系统托盘尚未初始化".to_owned())?;
    tray.set_menu(Some(menu)).map_err(|error| error.to_string())
}

fn open_tray_environment(app: &AppHandle, action_id: &str) {
    let state = app.state::<DesktopState>();
    let environment = state
        .tray_environment_actions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(action_id)
        .cloned();
    let Some(environment) = environment else {
        return;
    };
    if open_configured_environment(app, &state, &environment).is_err() {
        tracing::warn!(
            event_code = "tray-open-environment-failed",
            "tray environment action failed"
        );
        show_control(app);
    }
}

pub(crate) fn intercept_exit_request(app: &AppHandle, exit_code: i32) -> bool {
    if app.state::<DesktopState>().exit_lifecycle.is_ready() {
        return false;
    }
    request_graceful_exit(app, exit_code);
    true
}

pub(crate) fn mark_exit_ready<R: Runtime>(app: &AppHandle<R>) {
    if let Some(state) = app.try_state::<DesktopState>() {
        state.exit_lifecycle.mark_ready();
    }
}

fn finalize_exit<R: Runtime>(app: &AppHandle<R>, exit_code: i32) {
    mark_exit_ready(app);
    app.exit(exit_code);
}

fn request_graceful_exit(app: &AppHandle, exit_code: i32) {
    let state = app.state::<DesktopState>();
    if !state.exit_lifecycle.begin_drain() {
        return;
    }

    let closed = force_close_business_surfaces(app);
    if closed.failed_windows > 0 {
        tracing::warn!(
            event_code = "app-exit-business-close-failed",
            requested_windows = closed.requested_windows,
            closed_windows = closed.closed_windows,
            failed_windows = closed.failed_windows,
            "application exit could not destroy every business surface before drain"
        );
    }
    let app = app.clone();
    let (controller, invocation_coordinator) = {
        let bridge = app.state::<crate::BridgeState>();
        (
            Arc::clone(&bridge.controller),
            bridge.invocation_coordinator.clone(),
        )
    };
    let exit_app = app.clone();
    let exit = ExitDrainGuard::new(move || finalize_exit(&exit_app, exit_code));
    tauri::async_runtime::spawn(async move {
        let drain = async {
            if let Some(coordinator) = &invocation_coordinator {
                coordinator.stop_accepting().await;
            }
            controller.shutdown().await;
            if let Some(coordinator) = &invocation_coordinator {
                coordinator.drain().await;
            }
        };
        if tokio::time::timeout(APP_EXIT_DRAIN_TIMEOUT, drain)
            .await
            .is_err()
        {
            tracing::warn!(
                event_code = "app-exit-drain-timeout",
                timeout_seconds = APP_EXIT_DRAIN_TIMEOUT.as_secs(),
                "application exit forced after native invocation and durable ledger drain timeout"
            );
        }
        exit.complete();
    });
}

pub(crate) fn setup_control_window(app: &tauri::App) -> tauri::Result<()> {
    let window = WebviewWindowBuilder::new(app, "control", WebviewUrl::App("index.html".into()))
        .title("SSDEV Desktop")
        .inner_size(1120.0, 760.0)
        .min_inner_size(760.0, 600.0)
        .center()
        .resizable(true)
        .visible(false)
        .on_navigation(is_control_page)
        .on_new_window(|_, _| NewWindowResponse::Deny)
        .build()?;
    let control = window.clone();
    window.on_window_event(move |event| {
        let WindowEvent::CloseRequested { api, .. } = event else {
            return;
        };
        let exiting = control
            .try_state::<DesktopState>()
            .is_some_and(|state| state.exit_lifecycle.is_ready());
        if !exiting && control.app_handle().tray_by_id("ssdev-main").is_some() {
            api.prevent_close();
            let _ = control.hide();
        }
    });
    Ok(())
}

pub(crate) fn require_control<R: tauri::Runtime>(caller: &WebviewWindow<R>) -> Result<(), String> {
    if caller.label() != "control" {
        return Err("该命令只能由本地控制窗口调用".into());
    }
    let url = caller
        .url()
        .map_err(|_| "无法确认本地控制窗口来源".to_owned())?;
    if !is_control_page(&url) {
        return Err("当前控制窗口不是受信任的内置页面".into());
    }
    Ok(())
}

fn is_control_page(url: &Url) -> bool {
    is_bundled_page(url, CONTROL_PAGE) || is_bundled_page(url, "/")
}

pub(crate) fn is_bundled_page(url: &Url, expected_path: &str) -> bool {
    if url.path() != expected_path
        || url.query().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return false;
    }
    match (url.scheme(), url.host_str(), url.port()) {
        ("tauri", Some("localhost"), None) | ("http" | "https", Some("tauri.localhost"), None) => {
            true
        }
        #[cfg(debug_assertions)]
        ("http", Some("127.0.0.1"), Some(1420)) => true,
        _ => false,
    }
}

pub(crate) fn require_business<R: tauri::Runtime>(
    caller: &WebviewWindow<R>,
    state: &DesktopState,
) -> Result<(), String> {
    if !caller.label().starts_with(BUSINESS_LABEL_PREFIX) {
        return Err("插件命令只能由受控业务窗口调用".into());
    }
    let url = caller.url().map_err(|error| error.to_string())?;
    let origin = url.origin().ascii_serialization();
    let config = state.config.snapshot();
    state.authorize_config(&config)?;
    let allowed = config
        .business_origins()
        .map_err(|error| error.to_string())?;
    if allowed.contains(&origin) {
        Ok(())
    } else {
        Err(format!("页面来源 [{origin}] 未获授权调用本地插件"))
    }
}

#[tauri::command]
pub(crate) fn business_frontend_ready(
    caller: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
) -> Result<(), String> {
    require_business(&caller, &state)?;
    let transition = state.mark_business_frontend_ready(caller.label())?;
    if transition.recovered_after_timeout {
        tracing::info!(
            event_code = "business-frontend-recovered",
            app_version = %app.package_info().version,
            "business frontend reached native IPC after a readiness timeout"
        );
    } else if !transition.duplicate_signal {
        tracing::info!(
            event_code = "business-frontend-ready",
            app_version = %app.package_info().version,
            "business frontend reached native IPC"
        );
    }
    Ok(())
}

pub(crate) fn require_plugin_invocation<R: tauri::Runtime>(
    caller: &WebviewWindow<R>,
    state: &DesktopState,
    service_id: &str,
    method: &str,
) -> Result<String, String> {
    require_business(caller, state)?;
    let origin = caller
        .url()
        .map_err(|error| error.to_string())?
        .origin()
        .ascii_serialization();
    state
        .origin_policy
        .authorize_plugin_invocation(&origin, service_id, method)
        .map_err(|error| error.to_string())?;
    Ok(origin)
}

fn require_authorized_webview(caller: &WebviewWindow, state: &DesktopState) -> Result<(), String> {
    if !caller.label().starts_with(BUSINESS_LABEL_PREFIX)
        && !caller.label().starts_with(FLOATING_LABEL_PREFIX)
    {
        return Err("该命令只能由受控业务窗口调用".into());
    }
    let origin = caller
        .url()
        .map_err(|error| error.to_string())?
        .origin()
        .ascii_serialization();
    let config = state.config.snapshot();
    state.authorize_config(&config)?;
    let allowed = config
        .business_origins()
        .map_err(|error| error.to_string())?;
    if allowed.contains(&origin) {
        Ok(())
    } else {
        Err(format!("页面来源 [{origin}] 未获授权调用桌面能力"))
    }
}

fn build_business_window(
    app: &AppHandle,
    label: &str,
    url: Url,
    navigation_origins: BTreeSet<String>,
    business_origins: BTreeSet<String>,
    options: BusinessWindowOptions,
) -> Result<WebviewWindow, String> {
    let script = bridge_initialization_script(&business_origins, options.context.as_ref())?;
    let readiness_origins = business_origins;
    let mut builder = WebviewWindowBuilder::new(app, label, WebviewUrl::External(url))
        .title(options.title)
        .inner_size(1280.0, 800.0)
        .initialization_script(script)
        .on_navigation(move |url| {
            matches!(url.scheme(), "http" | "https")
                && navigation_origins.contains(&url.origin().ascii_serialization())
        })
        .on_new_window(|_, _| NewWindowResponse::Deny)
        .on_page_load(move |window, payload| {
            if payload.event() != PageLoadEvent::Started {
                return;
            }
            let is_business_origin =
                readiness_origins.contains(&payload.url().origin().ascii_serialization());
            let generation = window
                .state::<DesktopState>()
                .mark_business_navigation(window.label(), is_business_origin);
            if let Some(generation) = generation {
                start_business_frontend_watchdog(
                    window.app_handle().clone(),
                    window.label().to_owned(),
                    generation,
                );
            }
        })
        .on_document_title_changed(|window, title| {
            let _ = window.set_title(&title);
        });
    if let Some((width, height)) = options.inner_size {
        builder = builder.inner_size(width, height);
    } else {
        builder = builder.maximized(true);
    }
    if let Some((x, y)) = options.position {
        builder = builder.position(x, y);
    }
    let window = builder.build().map_err(|error| error.to_string())?;
    install_close_confirmation(app, &window);
    install_business_cleanup(app, &window, label.to_owned());
    Ok(window)
}

fn start_business_frontend_watchdog(app: AppHandle, label: String, generation: u64) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(BUSINESS_FRONTEND_READY_TIMEOUT).await;
        if !app
            .state::<DesktopState>()
            .report_business_frontend_timeout(&label, generation)
        {
            return;
        }
        tracing::error!(
            event_code = "business-frontend-timeout",
            error_code = "business-frontend-not-ready",
            app_version = %app.package_info().version,
            timeout_seconds = BUSINESS_FRONTEND_READY_TIMEOUT.as_secs(),
            "business frontend did not reach native IPC before the readiness deadline"
        );
        if let Some(window) = app.get_webview_window(&label) {
            let recovery_app = app.clone();
            app.dialog()
                .message(
                    "业务页面未在 30 秒内完成加载。请检查业务地址、网络和证书，并返回控制台选择“仅重试失败窗口”；如仍失败，请导出诊断包。错误码：business-frontend-not-ready",
                )
                .title("SSDEV Desktop")
                .kind(MessageDialogKind::Error)
                .buttons(MessageDialogButtons::Ok)
                .parent(&window)
                .show(move |_| show_control(&recovery_app));
        }
    });
}

struct BusinessWindowOptions {
    title: String,
    position: Option<(f64, f64)>,
    context: Option<Value>,
    inner_size: Option<(f64, f64)>,
}

impl Default for BusinessWindowOptions {
    fn default() -> Self {
        Self {
            title: "SSDEV Desktop".into(),
            position: None,
            context: None,
            inner_size: None,
        }
    }
}

fn validate_secondary_window_request(request: &SecondaryWindowRequest) -> Result<(), String> {
    match (request.width, request.height) {
        (None, None) => {}
        (Some(width), Some(height))
            if (320..=7680).contains(&width) && (240..=4320).contains(&height) => {}
        (Some(_), Some(_)) => return Err("业务窗口尺寸超出允许范围".into()),
        _ => return Err("业务窗口宽度和高度必须同时提供".into()),
    }
    match (request.left, request.top) {
        (None, None) => {}
        (Some(left), Some(top))
            if (-32_768..=32_767).contains(&left) && (-32_768..=32_767).contains(&top) => {}
        (Some(_), Some(_)) => return Err("业务窗口坐标超出允许范围".into()),
        _ => return Err("业务窗口横纵坐标必须同时提供".into()),
    }
    Ok(())
}

fn monitor_position(app: &AppHandle, requested_index: usize) -> Result<Option<(f64, f64)>, String> {
    let monitors = app
        .available_monitors()
        .map_err(|error| error.to_string())?;
    if monitors.is_empty() {
        return Ok(None);
    }
    let monitor = monitors
        .get(requested_index)
        .unwrap_or_else(|| &monitors[0]);
    let position = monitor.position();
    let scale = monitor.scale_factor();
    Ok(Some((
        f64::from(position.x) / scale,
        f64::from(position.y) / scale,
    )))
}

fn validate_floating_request(request: &FloatingWindowRequest) -> Result<(), String> {
    if request.id.trim().is_empty() || request.id.chars().count() > 128 {
        return Err("悬浮窗 ID 必须为 1 到 128 个字符".into());
    }
    if request.url.len() > 4096 {
        return Err("悬浮窗地址过长".into());
    }
    if !(200..=800).contains(&request.width) || !(80..=600).contains(&request.height) {
        return Err("悬浮窗尺寸超出允许范围".into());
    }
    if !(1_000..=60_000).contains(&request.duration_ms) {
        return Err("悬浮窗显示时长必须在 1 到 60 秒之间".into());
    }
    if let Some(context) = &request.context {
        if !context.is_object() {
            return Err("悬浮窗上下文必须是 JSON 对象".into());
        }
        if serde_json::to_vec(context)
            .map_err(|error| error.to_string())?
            .len()
            > 64 * 1024
        {
            return Err("悬浮窗上下文不能超过 64 KiB".into());
        }
    }
    Ok(())
}

fn default_floating_duration() -> u64 {
    5_000
}

fn default_floating_width() -> u32 {
    330
}

fn default_floating_height() -> u32 {
    150
}

fn floating_position(app: &AppHandle, width: u32, height: u32) -> Result<(f64, f64), String> {
    let monitor = app
        .primary_monitor()
        .map_err(|error| error.to_string())?
        .or_else(|| {
            app.available_monitors()
                .ok()
                .and_then(|monitors| monitors.into_iter().next())
        })
        .ok_or_else(|| "未检测到可用显示器".to_owned())?;
    let work_area = monitor.work_area();
    let scale = monitor.scale_factor();
    let margin = 10.0 * scale;
    Ok((
        (f64::from(work_area.position.x) + f64::from(work_area.size.width)
            - f64::from(width) * scale
            - margin)
            / scale,
        (f64::from(work_area.position.y) + f64::from(work_area.size.height)
            - f64::from(height) * scale
            - margin)
            / scale,
    ))
}

fn floating_initialization_script(
    origins: &BTreeSet<String>,
    id: &str,
    context: Option<&Value>,
) -> Result<String, String> {
    let origins = serde_json::to_string(origins).map_err(|error| error.to_string())?;
    let id = serde_json::to_string(id).map_err(|error| error.to_string())?;
    let context = context
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()));
    let context = serde_json::to_string(&context).map_err(|error| error.to_string())?;
    Ok(format!(
        r#"(() => {{
  const allowedOrigins = new Set({origins});
  if (!allowedOrigins.has(window.location.origin)) return;
  const invoke = window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke;
  if (typeof invoke !== 'function') return;
  const deepFreeze = (value) => {{
    if (value && typeof value === 'object' && !Object.isFrozen(value)) {{
      Object.freeze(value);
      for (const child of Object.values(value)) deepFreeze(child);
    }}
    return value;
  }};
  const id = {id};
  const api = Object.freeze({{
    close: () => invoke('close_floating_window', {{ id }}),
    resolve: (payload = null) => invoke('resolve_floating_window', {{ id, payload }})
  }});
  Object.defineProperty(window, 'ssdevFloating', {{ value: api, configurable: false }});
  Object.defineProperty(window, 'ssdevDesktopContext', {{ value: deepFreeze({context}), configurable: false }});
}})();"#
    ))
}

fn floating_entry(state: &DesktopState, id: &str) -> Option<FloatingEntry> {
    state
        .floating_windows
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(id)
        .cloned()
}

fn close_floating_by_identity(app: &AppHandle, id: &str, expected_label: &str) {
    let state = app.state::<DesktopState>();
    let removed = {
        let mut floating = state
            .floating_windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if floating
            .get(id)
            .is_some_and(|entry| entry.window_label == expected_label)
        {
            floating.remove(id)
        } else {
            None
        }
    };
    if let Some(entry) = removed {
        if let Some(window) = app.get_webview_window(&entry.window_label) {
            let _ = window.close();
        }
    }
}

fn install_floating_cleanup(app: &AppHandle, window: &WebviewWindow, id: String, label: String) {
    let app = app.clone();
    window.on_window_event(move |event| {
        if matches!(event, WindowEvent::Destroyed) {
            let state = app.state::<DesktopState>();
            let mut floating = state
                .floating_windows
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if floating
                .get(&id)
                .is_some_and(|entry| entry.window_label == label)
            {
                floating.remove(&id);
            }
        }
    });
}

fn install_business_cleanup(app: &AppHandle, window: &WebviewWindow, label: String) {
    let app = app.clone();
    window.on_window_event(move |event| {
        if matches!(event, WindowEvent::Destroyed) {
            app.state::<DesktopState>()
                .release_business_window_label(&label);
        }
    });
}

fn install_close_confirmation(app: &AppHandle, window: &WebviewWindow) {
    const IDLE: u8 = 0;
    const PROMPTING: u8 = 1;
    const ALLOW_CLOSE: u8 = 2;

    let app = app.clone();
    let window = window.clone();
    let close_state = Arc::new(AtomicU8::new(IDLE));
    window.clone().on_window_event(move |event| {
        let WindowEvent::CloseRequested { api, .. } = event else {
            return;
        };
        if close_state.load(Ordering::Acquire) == ALLOW_CLOSE {
            return;
        }
        if !app.state::<DesktopState>().config.snapshot().auto_close {
            return;
        }

        api.prevent_close();
        if close_state
            .compare_exchange(IDLE, PROMPTING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let close_state_after_dialog = Arc::clone(&close_state);
        let window_after_dialog = window.clone();
        app.dialog()
            .message("确认关闭当前业务窗口？")
            .title("提示")
            .kind(MessageDialogKind::Info)
            .buttons(MessageDialogButtons::OkCancelCustom(
                "确认".into(),
                "取消".into(),
            ))
            .parent(&window)
            .show(move |confirmed| {
                if confirmed {
                    close_state_after_dialog.store(ALLOW_CLOSE, Ordering::Release);
                    let _ = window_after_dialog.close();
                } else {
                    close_state_after_dialog.store(IDLE, Ordering::Release);
                }
            });
    });
}

fn bridge_initialization_script(
    origins: &BTreeSet<String>,
    context: Option<&Value>,
) -> Result<String, String> {
    let origins = serde_json::to_string(origins).map_err(|error| error.to_string())?;
    let context = context
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()));
    let context = serde_json::to_string(&context).map_err(|error| error.to_string())?;
    Ok(format!(
        r#"(() => {{
  const allowedOrigins = new Set({origins});
  if (!allowedOrigins.has(window.location.origin)) return;
  const invoke = window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke;
  if (typeof invoke !== 'function') return;
  const deepFreeze = (value) => {{
    if (value && typeof value === 'object' && !Object.isFrozen(value)) {{
      Object.freeze(value);
      for (const child of Object.values(value)) deepFreeze(child);
    }}
    return value;
  }};
  const invokePlugin = (serviceId, method, parameters = {{}}) =>
    invoke('plugin_invoke', {{ request: {{ serviceId, method, parameters }} }});
  const invokePluginTracked = (operationId, serviceId, method, parameters = {{}}) =>
    invoke('plugin_invoke_tracked', {{ operationId, request: {{ serviceId, method, parameters }} }});
  const getPluginInvocation = (operationId, serviceId, method) =>
    invoke('plugin_invocation_status', {{ operationId, serviceId, method }});
  const getSystemInfo = () => invoke('system_declaration');
  const captureWindow = () => invoke('capture_business_window');
  const openExternal = (url) => invoke('open_external_url', {{ url }});
  const openWindow = (request) => invoke('open_secondary_window', {{ request }});
  const showFloating = (request) => invoke('show_floating_window', {{ request }});
  const closeFloating = (id) => invoke('close_floating_window', {{ id }});
  const api = Object.freeze({{ invokePlugin, invokePluginTracked, getPluginInvocation, getSystemInfo, captureWindow, openExternal, openWindow, showFloating, closeFloating }});
  Object.defineProperty(window, 'ssdevDesktop', {{ value: api, configurable: false }});
  Object.defineProperty(window, 'webPlusInvoke', {{ value: invokePlugin, configurable: false }});
  Object.defineProperty(window, 'ssdevDesktopContext', {{ value: deepFreeze({context}), configurable: false }});
  const signalReady = () => invoke('business_frontend_ready').catch(() => {{}});
  if (document.readyState === 'loading') {{
    document.addEventListener('DOMContentLoaded', signalReady, {{ once: true }});
  }} else {{
    queueMicrotask(signalReady);
  }}
}})();"#
    ))
}

pub(crate) fn force_close_business_surfaces<R: Runtime>(
    app: &AppHandle<R>,
) -> BusinessSurfaceCloseResult {
    let state = app.state::<DesktopState>();
    let mut result = BusinessSurfaceCloseResult {
        reset_required: true,
        ..BusinessSurfaceCloseResult::default()
    };
    for (label, window) in app.webview_windows() {
        let business = label.starts_with(BUSINESS_LABEL_PREFIX);
        let floating = label.starts_with(FLOATING_LABEL_PREFIX);
        if !business && !floating {
            continue;
        }
        result.requested_windows += 1;
        if window.destroy().is_ok() {
            result.closed_windows += 1;
            if business {
                state.release_business_window_label(&label);
            } else {
                state.release_floating_window_label(&label);
            }
        } else {
            result.failed_windows += 1;
        }
    }
    result
}

fn build_business_data_clear_preview(
    app: &AppHandle,
    state: &DesktopState,
) -> Result<BusinessDataClearPreview, String> {
    let business_origins = state
        .config
        .snapshot()
        .business_origins()
        .map_err(|error| error.to_string())?;
    let mut business_window_labels = Vec::new();
    let mut floating_window_labels = Vec::new();
    for label in app.webview_windows().into_keys() {
        if label.starts_with(BUSINESS_LABEL_PREFIX) {
            business_window_labels.push(label);
        } else if label.starts_with(FLOATING_LABEL_PREFIX) {
            floating_window_labels.push(label);
        }
    }
    business_window_labels.sort();
    floating_window_labels.sort();
    Ok(BusinessDataClearPreview {
        plan_id: business_data_clear_plan_id(
            &business_origins,
            &business_window_labels,
            &floating_window_labels,
        ),
        configured_business_origins: business_origins.len(),
        business_windows: business_window_labels.len(),
        floating_windows: floating_window_labels.len(),
    })
}

fn business_data_clear_plan_id(
    business_origins: &BTreeSet<String>,
    business_window_labels: &[String],
    floating_window_labels: &[String],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"SSDEV-BUSINESS-DATA-CLEAR-PLAN\0");
    crate::hash_plan_field(&mut hasher, env!("CARGO_PKG_VERSION").as_bytes());
    for origin in business_origins {
        crate::hash_plan_field(&mut hasher, origin.as_bytes());
    }
    crate::hash_plan_field(&mut hasher, b"business-windows");
    for label in business_window_labels {
        crate::hash_plan_field(&mut hasher, label.as_bytes());
    }
    crate::hash_plan_field(&mut hasher, b"floating-windows");
    for label in floating_window_labels {
        crate::hash_plan_field(&mut hasher, label.as_bytes());
    }
    crate::lowercase_hex(&hasher.finalize())
}

fn reload_business_windows_internal(app: &AppHandle) -> BusinessWindowReloadResult {
    let mut result = BusinessWindowReloadResult::default();
    for (label, window) in app.webview_windows() {
        if label.starts_with(BUSINESS_LABEL_PREFIX) {
            result.requested_windows += 1;
            if window.reload().is_ok() {
                result.reloaded_windows += 1;
            } else {
                result.failed_windows += 1;
            }
        }
    }
    result
}

fn retry_timed_out_business_windows_internal(
    app: &AppHandle,
    state: &DesktopState,
) -> BusinessFrontendRetryResult {
    let mut result = BusinessFrontendRetryResult::default();
    for (label, generation) in state.claim_timed_out_business_windows() {
        let Some(window) = app.get_webview_window(&label) else {
            state.release_business_window_label(&label);
            result.unavailable_windows += 1;
            continue;
        };
        if window.reload().is_err() {
            let _ = state.restore_business_frontend_timeout(&label, generation);
            result.failed_windows += 1;
            tracing::warn!(
                event_code = "business-frontend-retry-failed",
                error_code = "business-window-reload",
                "timed out business frontend could not be reloaded"
            );
            continue;
        }
        result.retried_windows += 1;
        start_business_frontend_watchdog(app.clone(), label, generation);
    }
    result
}

pub(crate) fn show_control<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window("control") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

pub(crate) fn focus_primary_surface<R: Runtime>(app: &AppHandle<R>) {
    let mut business_windows = app
        .webview_windows()
        .into_iter()
        .filter(|(label, _)| label.starts_with(BUSINESS_LABEL_PREFIX))
        .collect::<Vec<_>>();
    business_windows.sort_by(|left, right| left.0.cmp(&right.0));
    let Some((_, window)) = business_windows.into_iter().next() else {
        show_control(app);
        return;
    };
    let _ = window.show();
    let _ = window.unminimize();
    let _ = window.set_focus();
}

pub(crate) fn reset_business_zoom(app: &AppHandle) {
    for (label, window) in app.webview_windows() {
        if label.starts_with(BUSINESS_LABEL_PREFIX) {
            let _ = window.set_zoom(1.0);
        }
    }
}

pub(crate) fn dispatch_find(app: &AppHandle) {
    for (label, window) in app.webview_windows() {
        if label.starts_with(BUSINESS_LABEL_PREFIX) {
            let _ =
                window.eval("window.dispatchEvent(new CustomEvent('ssdev-find', { detail: '' }));");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn business_data_clear_plan_binds_origins_and_open_window_set() {
        let origins = BTreeSet::from([
            "http://project-a.example.test".to_owned(),
            "https://project-b.example.test".to_owned(),
        ]);
        let business = vec!["business-1".to_owned(), "business-2".to_owned()];
        let floating = vec!["floating-3".to_owned()];
        let plan = business_data_clear_plan_id(&origins, &business, &floating);

        assert!(crate::is_lowercase_sha256(&plan));
        assert_eq!(
            plan,
            business_data_clear_plan_id(&origins, &business, &floating)
        );
        assert_ne!(
            plan,
            business_data_clear_plan_id(
                &BTreeSet::from(["https://changed.example.test".to_owned()]),
                &business,
                &floating,
            )
        );
        assert_ne!(
            plan,
            business_data_clear_plan_id(&origins, &["business-1".to_owned()], &floating)
        );
        assert_ne!(plan, business_data_clear_plan_id(&origins, &business, &[]));
    }

    #[test]
    fn business_data_clear_preview_exposes_only_aggregate_impact() {
        let value = serde_json::to_value(BusinessDataClearPreview {
            plan_id: "ab".repeat(32),
            configured_business_origins: 3,
            business_windows: 2,
            floating_windows: 1,
        })
        .unwrap();

        assert_eq!(
            value,
            serde_json::json!({
                "planId": "ab".repeat(32),
                "configuredBusinessOrigins": 3,
                "businessWindows": 2,
                "floatingWindows": 1,
            })
        );
        assert!(!value.to_string().contains("example.test"));
    }

    #[test]
    fn business_window_reload_result_exposes_only_aggregate_counts() {
        let value = serde_json::to_value(BusinessWindowReloadResult {
            requested_windows: 3,
            reloaded_windows: 2,
            failed_windows: 1,
        })
        .unwrap();

        assert_eq!(
            value,
            serde_json::json!({
                "requestedWindows": 3,
                "reloadedWindows": 2,
                "failedWindows": 1,
            })
        );
    }

    #[test]
    fn programmatic_project_close_destroys_business_and_floating_surfaces_without_stale_state() {
        let directory = tempfile::tempdir().unwrap();
        let store =
            ConfigStore::open(directory.path().join("config.json"), Vec::<PathBuf>::new()).unwrap();
        let state = DesktopState::new(store, OriginPolicy::development_unrestricted());
        let business_label = state.reserve_business_window_label().unwrap();
        let floating_label = state.take_floating_label();
        state
            .floating_windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                "notice-1".into(),
                FloatingEntry {
                    window_label: floating_label.clone(),
                    parent_label: business_label.clone(),
                },
            );
        let app = tauri::test::mock_builder()
            .manage(state)
            .build(crate::app_context())
            .unwrap();
        WebviewWindowBuilder::new(
            &app,
            &business_label,
            WebviewUrl::External(Url::parse("https://business.example.test/app").unwrap()),
        )
        .build()
        .unwrap();
        WebviewWindowBuilder::new(
            &app,
            &floating_label,
            WebviewUrl::External(Url::parse("https://business.example.test/notice").unwrap()),
        )
        .build()
        .unwrap();

        let closed = force_close_business_surfaces(app.handle());

        assert!(closed.reset_required);
        assert_eq!(closed.requested_windows, 2);
        assert_eq!(closed.closed_windows, 2);
        assert_eq!(closed.failed_windows, 0);
        assert_eq!(
            app.state::<DesktopState>()
                .business_frontend_health()
                .active_windows,
            0
        );
        assert!(app
            .state::<DesktopState>()
            .floating_windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty());
    }

    #[test]
    fn config_import_plan_binds_candidate_and_current_configuration() {
        let current = DesktopConfig {
            website: Some("https://current.example.test/app".into()),
            ..DesktopConfig::default()
        };
        let candidate = DesktopConfig {
            project_id: "hospital-a-outpatient".into(),
            project_name: "A 院门诊项目".into(),
            website: Some("https://candidate.example.test/app".into()),
            auto_start: true,
            ..DesktopConfig::default()
        };
        let plan = config_import_plan_id(&current, &candidate).unwrap();

        assert!(crate::is_lowercase_sha256(&plan));
        assert_eq!(plan, config_import_plan_id(&current, &candidate).unwrap());

        let changed_current = DesktopConfig {
            tenant_id: "changed-current".into(),
            ..current.clone()
        };
        let changed_candidate = DesktopConfig {
            tenant_id: "changed-candidate".into(),
            ..candidate.clone()
        };
        assert_ne!(
            plan,
            config_import_plan_id(&changed_current, &candidate).unwrap()
        );
        assert_ne!(
            plan,
            config_import_plan_id(&current, &changed_candidate).unwrap()
        );
    }

    #[test]
    fn config_import_preview_exposes_effects_without_applying_them() {
        let current = DesktopConfig {
            website: Some("https://current.example.test/app".into()),
            managed_processes: vec!["reader-agent".into()],
            ..DesktopConfig::default()
        };
        let candidate = DesktopConfig {
            project_id: "hospital-a-outpatient".into(),
            project_name: "A 院门诊项目".into(),
            website: Some("https://candidate.example.test/app".into()),
            environments: vec![ssdev_config::EnvironmentConfig {
                name: "验收环境".into(),
                url: "https://acceptance.example.test/app".into(),
                extensions: Default::default(),
            }],
            allow_switch: false,
            auto_close: true,
            auto_start: true,
            tenant_id: "tenant-a".into(),
            trusted_origins: vec!["https://sso.example.test".into()],
            external_origins: vec!["https://help.example.test".into()],
            ..DesktopConfig::default()
        };

        let preview = build_config_change_preview(&current, &candidate).unwrap();

        assert!(preview.config_changed);
        assert!(preview.business_surface_reset_required);
        assert!(preview.project_identity_changed);
        assert_eq!(preview.current_project_id, "");
        assert_eq!(preview.current_project_name, "");
        assert_eq!(preview.candidate_project_id, "hospital-a-outpatient");
        assert_eq!(preview.candidate_project_name, "A 院门诊项目");
        assert!(preview.default_website_changed);
        assert!(preview.tenant_changed);
        assert!(preview.allow_switch_changed);
        assert!(preview.auto_close_changed);
        assert!(preview.auto_start_changed);
        assert_eq!(preview.current_environment_count, 0);
        assert_eq!(preview.candidate_environment_count, 1);
        assert_eq!(preview.current_business_origin_count, 1);
        assert_eq!(preview.candidate_business_origin_count, 2);
        assert_eq!(preview.current_managed_process_count, 1);
        assert_eq!(preview.candidate_managed_process_count, 0);
        assert_eq!(preview.candidate_trusted_origin_count, 1);
        assert_eq!(preview.candidate_external_origin_count, 1);
        assert_eq!(preview.candidate_environments[0].name, "验收环境");
    }

    #[test]
    fn desktop_only_settings_do_not_interrupt_open_business_surfaces() {
        let current = DesktopConfig {
            website: Some("https://business.example.test/app".into()),
            tenant_id: "tenant-a".into(),
            ..DesktopConfig::default()
        };
        let desktop_only = DesktopConfig {
            allow_switch: false,
            auto_close: true,
            auto_start: true,
            plugin_catalog_url: Some("https://plugins.example.test/catalog.json".into()),
            plugin_catalog_signature_url: Some(
                "https://plugins.example.test/catalog.sig.json".into(),
            ),
            ..current.clone()
        };

        assert!(!business_surface_reset_required(&current, &desktop_only));

        let mut changed_identity = desktop_only.clone();
        changed_identity.project_id = "hospital-a-outpatient".into();
        changed_identity.project_name = "A 院门诊项目".into();
        assert!(!business_surface_reset_required(
            &current,
            &changed_identity
        ));

        let mut changed_entry = desktop_only.clone();
        changed_entry.website = Some("https://business.example.test/next".into());
        assert!(business_surface_reset_required(&current, &changed_entry));

        let mut changed_origin = desktop_only.clone();
        changed_origin
            .trusted_origins
            .push("https://sso.example.test".into());
        assert!(business_surface_reset_required(&current, &changed_origin));

        let mut changed_processes = desktop_only.clone();
        changed_processes
            .managed_processes
            .push("reader-agent".into());
        assert!(business_surface_reset_required(
            &current,
            &changed_processes
        ));

        let mut changed_extension = desktop_only;
        changed_extension
            .extensions
            .insert("futureBusinessMode".into(), serde_json::json!(true));
        assert!(business_surface_reset_required(
            &current,
            &changed_extension
        ));
    }

    #[test]
    fn managed_process_selection_drift_requires_restart_independent_of_order() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.json");
        let store = ConfigStore::open(&config_path, Vec::<PathBuf>::new()).unwrap();
        store
            .replace(DesktopConfig {
                managed_processes: vec!["reader-agent".into(), "device-agent".into()],
                ..DesktopConfig::default()
            })
            .unwrap();
        let state = DesktopState::new(store, OriginPolicy::development_unrestricted());

        assert!(!state.managed_process_restart_required());
        state
            .config
            .replace(DesktopConfig {
                managed_processes: vec!["device-agent".into(), "reader-agent".into()],
                ..DesktopConfig::default()
            })
            .unwrap();
        assert!(!state.managed_process_restart_required());

        state
            .config
            .replace(DesktopConfig {
                managed_processes: vec!["replacement-agent".into()],
                ..DesktopConfig::default()
            })
            .unwrap();
        assert!(state.managed_process_restart_required());
        assert!(state
            .require_current_managed_processes()
            .unwrap_err()
            .contains("managed-process-restart-required"));
    }

    #[test]
    fn exit_lifecycle_starts_one_drain_and_then_allows_the_final_exit() {
        let lifecycle = ExitLifecycle::new();

        assert!(!lifecycle.is_ready());
        assert!(lifecycle.begin_drain());
        assert!(!lifecycle.begin_drain());
        assert!(!lifecycle.is_ready());

        lifecycle.mark_ready();
        assert!(lifecycle.is_ready());
        assert!(!lifecycle.begin_drain());
    }

    #[test]
    fn terminated_exit_drain_task_still_allows_the_final_exit() {
        let lifecycle = Arc::new(ExitLifecycle::new());
        assert!(lifecycle.begin_drain());
        let finalizer_lifecycle = Arc::clone(&lifecycle);

        drop(ExitDrainGuard::new(move || {
            finalizer_lifecycle.mark_ready();
        }));

        assert!(lifecycle.is_ready());
    }

    #[test]
    fn business_window_reservations_are_bounded_and_recoverable() {
        let directory = tempfile::tempdir().unwrap();
        let store =
            ConfigStore::open(directory.path().join("config.json"), Vec::<PathBuf>::new()).unwrap();
        let state = DesktopState::new(store, OriginPolicy::development_unrestricted());
        let labels = (0..MAX_BUSINESS_WINDOWS)
            .map(|_| state.reserve_business_window_label().unwrap())
            .collect::<Vec<_>>();

        assert!(state.reserve_business_window_label().is_err());
        state.release_business_window_label(&labels[0]);
        assert!(state.reserve_business_window_label().is_ok());
    }

    #[test]
    fn business_frontend_health_tracks_navigation_timeout_and_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let store =
            ConfigStore::open(directory.path().join("config.json"), Vec::<PathBuf>::new()).unwrap();
        let state = DesktopState::new(store, OriginPolicy::development_unrestricted());
        let label = state.reserve_business_window_label().unwrap();

        let generation = state.mark_business_navigation(&label, true).unwrap();
        assert_eq!(state.business_frontend_health().loading_windows, 1);
        assert!(!state.report_business_frontend_timeout(&label, generation + 1));
        assert!(state.report_business_frontend_timeout(&label, generation));
        assert_eq!(state.business_frontend_health().timed_out_windows, 1);

        let transition = state.mark_business_frontend_ready(&label).unwrap();
        assert!(transition.recovered_after_timeout);
        let health = state.business_frontend_health();
        assert_eq!(health.ready_windows, 1);
        assert_eq!(health.total_timeouts, 1);
        assert_eq!(health.recovered_after_timeout, 1);

        assert!(state.mark_business_navigation(&label, false).is_none());
        assert_eq!(state.business_frontend_health().navigating_windows, 1);
        state.release_business_window_label(&label);
        assert_eq!(state.business_frontend_health().active_windows, 0);
    }

    #[test]
    fn business_frontend_retry_claims_only_timed_out_windows_and_can_restore_failures() {
        let directory = tempfile::tempdir().unwrap();
        let store =
            ConfigStore::open(directory.path().join("config.json"), Vec::<PathBuf>::new()).unwrap();
        let state = DesktopState::new(store, OriginPolicy::development_unrestricted());
        let timed_out = state.reserve_business_window_label().unwrap();
        let ready = state.reserve_business_window_label().unwrap();

        let timed_out_generation = state.mark_business_navigation(&timed_out, true).unwrap();
        assert!(state.report_business_frontend_timeout(&timed_out, timed_out_generation));
        state.mark_business_navigation(&ready, true).unwrap();
        state.mark_business_frontend_ready(&ready).unwrap();

        let claimed = state.claim_timed_out_business_windows();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].0, timed_out);
        assert!(claimed[0].1 > timed_out_generation);
        let health = state.business_frontend_health();
        assert_eq!(health.loading_windows, 1);
        assert_eq!(health.ready_windows, 1);
        assert_eq!(health.timed_out_windows, 0);

        assert!(!state.restore_business_frontend_timeout(&timed_out, claimed[0].1 + 1));
        assert!(state.restore_business_frontend_timeout(&timed_out, claimed[0].1));
        let health = state.business_frontend_health();
        assert_eq!(health.timed_out_windows, 1);
        assert_eq!(health.total_timeouts, 1);

        let claimed = state.claim_timed_out_business_windows();
        state.mark_business_navigation(&timed_out, true).unwrap();
        let transition = state.mark_business_frontend_ready(&timed_out).unwrap();
        assert!(transition.recovered_after_timeout);
        assert_eq!(state.business_frontend_health().recovered_after_timeout, 1);
        assert_eq!(claimed.len(), 1);
    }

    #[test]
    fn business_frontend_retry_result_exposes_only_aggregate_counts() {
        let value = serde_json::to_value(BusinessFrontendRetryResult {
            retried_windows: 2,
            failed_windows: 1,
            unavailable_windows: 3,
        })
        .unwrap();

        assert_eq!(
            value,
            serde_json::json!({
                "retriedWindows": 2,
                "failedWindows": 1,
                "unavailableWindows": 3,
            })
        );
    }

    #[test]
    fn bridge_script_contains_only_the_narrow_plugin_api() {
        let origins = BTreeSet::from(["https://example.test".into()]);
        let script = bridge_initialization_script(&origins, None).unwrap();

        assert!(script.contains("plugin_invoke"));
        assert!(script.contains("system_declaration"));
        assert!(script.contains("open_external_url"));
        assert!(script.contains("webPlusInvoke"));
        assert!(script.contains("open_secondary_window"));
        assert!(script.contains("deepFreeze"));
        assert!(script.contains("business_frontend_ready"));
        assert!(script.contains("DOMContentLoaded"));
        assert!(!script.contains("shell"));
        assert!(!script.contains("filesystem"));
    }

    #[test]
    fn business_bridge_matches_the_shared_sdk_contract() {
        let contract: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../packages/web-bridge/bridge-contract.json"
        ))
        .expect("bridge contract must be valid JSON");
        assert_eq!(contract["schemaVersion"], 4);
        assert_eq!(contract["protocolVersion"], crate::BRIDGE_PROTOCOL_VERSION);
        assert_eq!(
            contract["pluginInvocationControlCodes"]["capacityBusy"],
            webplus_protocol::INVOKE_CAPACITY_BUSY_CODE
        );
        assert_eq!(
            contract["pluginInvocationControlCodes"]["controllerStopping"],
            webplus_protocol::INVOKE_CONTROLLER_STOPPING_CODE
        );
        assert_eq!(
            contract["pluginInvocationControlCodes"]["executionLaneTimeout"],
            webplus_protocol::INVOKE_EXECUTION_LANE_TIMEOUT_CODE
        );
        assert_eq!(
            contract["pluginInvocationControlCodes"]["pluginReloading"],
            webplus_protocol::INVOKE_PLUGIN_RELOADING_CODE
        );

        let origins = BTreeSet::from(["https://example.test".into()]);
        let script = bridge_initialization_script(&origins, None).unwrap();
        for method in contract["methods"]
            .as_array()
            .expect("bridge methods must be an array")
        {
            let method = method.as_str().expect("bridge method must be a string");
            assert!(script.contains(method), "bridge script is missing {method}");
        }
        for method in contract["optionalMethods"]
            .as_array()
            .expect("optional bridge methods must be an array")
        {
            let method = method.as_str().expect("bridge method must be a string");
            assert!(script.contains(method), "bridge script is missing {method}");
        }
        assert!(contract["events"]
            .as_array()
            .expect("bridge events must be an array")
            .iter()
            .any(|event| event == FLOATING_ACTION_EVENT));

        let capabilities = crate::DesktopCapabilitiesDeclaration {
            schema_version: crate::DESKTOP_CAPABILITIES_SCHEMA_VERSION,
            tracked_invocations: crate::TrackedInvocationCapabilitiesDeclaration {
                supported: true,
                available: true,
                accepting: true,
                error_code: None,
                limits: crate::TrackedInvocationLimitsDeclaration {
                    max_runtime_operations: crate::invocations::MAX_RUNTIME_OPERATIONS,
                    max_retained_response_bytes: crate::invocations::MAX_RETAINED_RESPONSE_BYTES,
                    runtime_result_retention_seconds: crate::invocations::RUNTIME_RESULT_RETENTION
                        .as_secs(),
                    max_durable_operations: ssdev_invocation_ledger::MAX_DURABLE_OPERATIONS,
                    max_durable_operations_per_scope:
                        ssdev_invocation_ledger::MAX_DURABLE_OPERATIONS_PER_SCOPE,
                    completed_retention_seconds:
                        ssdev_invocation_ledger::COMPLETED_OPERATION_RETENTION.as_secs(),
                    indeterminate_retention_seconds:
                        ssdev_invocation_ledger::INDETERMINATE_OPERATION_RETENTION.as_secs(),
                },
            },
        };
        let capabilities = serde_json::to_value(capabilities)
            .expect("capability declaration must be serializable");
        assert_eq!(
            capabilities["schemaVersion"],
            contract["capabilities"]["schemaVersion"]
        );
        let declared = capabilities["trackedInvocations"]
            .as_object()
            .expect("tracked invocation capabilities must be an object")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let contracted = contract["capabilities"]["trackedInvocations"]
            .as_array()
            .expect("tracked invocation capability fields must be an array")
            .iter()
            .map(|field| field.as_str().expect("capability field must be a string"))
            .collect::<BTreeSet<_>>();
        assert_eq!(declared, contracted);
        let declared_limits = capabilities["trackedInvocations"]["limits"]
            .as_object()
            .expect("tracked invocation limits must be an object")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let contracted_limits = contract["capabilities"]["trackedInvocationLimits"]
            .as_array()
            .expect("tracked invocation limit fields must be an array")
            .iter()
            .map(|field| field.as_str().expect("limit field must be a string"))
            .collect::<BTreeSet<_>>();
        assert_eq!(declared_limits, contracted_limits);
    }

    #[test]
    fn floating_bridge_does_not_expose_plugins_or_generic_tauri_apis() {
        let origins = BTreeSet::from(["https://example.test".into()]);
        let script = floating_initialization_script(&origins, "notice-1", None).unwrap();

        assert!(script.contains("close_floating_window"));
        assert!(script.contains("resolve_floating_window"));
        assert!(!script.contains("plugin_invoke"));
        assert!(!script.contains("open_secondary_window"));
        assert!(script.contains("deepFreeze"));
    }

    #[test]
    fn floating_window_limits_are_bounded() {
        let mut request = FloatingWindowRequest {
            id: "notice-1".into(),
            url: "https://example.test/notice".into(),
            duration_ms: 5_000,
            width: 330,
            height: 150,
            context: Some(serde_json::json!({ "message": "hello" })),
        };
        assert!(validate_floating_request(&request).is_ok());

        request.duration_ms = 600_000;
        assert!(validate_floating_request(&request).is_err());
    }

    #[test]
    fn secondary_window_geometry_is_bounded_and_requires_complete_pairs() {
        let mut request = SecondaryWindowRequest {
            url: "https://example.test/detail".into(),
            title: Some("详情".into()),
            screen_index: Some(1),
            context: None,
            width: Some(1280),
            height: Some(800),
            left: Some(-1280),
            top: Some(0),
        };
        assert!(validate_secondary_window_request(&request).is_ok());

        request.height = None;
        assert!(validate_secondary_window_request(&request).is_err());
        request.height = Some(800);
        request.width = Some(100);
        assert!(validate_secondary_window_request(&request).is_err());
        request.width = Some(1280);
        request.top = None;
        assert!(validate_secondary_window_request(&request).is_err());
    }

    #[test]
    fn external_urls_require_http_and_an_explicit_origin() {
        let current = Url::parse("https://business.example.test/app/").unwrap();
        let allowed = BTreeSet::from([
            "https://business.example.test".into(),
            "https://help.example.test".into(),
        ]);

        assert_eq!(
            validate_external_url(&current, "guide", &allowed)
                .unwrap()
                .as_str(),
            "https://business.example.test/app/guide"
        );
        assert!(validate_external_url(&current, "https://help.example.test/a", &allowed).is_ok());
        assert!(validate_external_url(&current, "https://evil.example.test", &allowed).is_err());
        assert!(validate_external_url(&current, "file:///C:/Windows/win.ini", &allowed).is_err());
    }

    #[test]
    fn control_page_accepts_only_the_exact_bundled_document() {
        for allowed in [
            "tauri://localhost/",
            "tauri://localhost/index.html",
            "http://tauri.localhost/",
            "http://tauri.localhost/index.html",
            "https://tauri.localhost/",
            "https://tauri.localhost/index.html",
        ] {
            assert!(is_control_page(&Url::parse(allowed).unwrap()), "{allowed}");
        }
        #[cfg(debug_assertions)]
        assert!(is_control_page(
            &Url::parse("http://127.0.0.1:1420/index.html").unwrap()
        ));
        #[cfg(debug_assertions)]
        assert!(is_control_page(
            &Url::parse("http://127.0.0.1:1420/").unwrap()
        ));
        for rejected in [
            "https://attacker.example/index.html",
            "tauri://localhost/other.html",
            "tauri://localhost/index.html?redirect=https://attacker.example",
            "http://tauri.localhost/other/index.html",
            "http://user@tauri.localhost/index.html",
            "http://127.0.0.1:1421/index.html",
        ] {
            assert!(
                !is_control_page(&Url::parse(rejected).unwrap()),
                "{rejected}"
            );
        }
    }

    #[test]
    fn remote_acl_allows_only_narrow_business_commands_on_the_configured_origin() {
        use tauri::ipc::{CallbackFn, InvokeBody};
        use tauri::test::{get_ipc_response, mock_builder, INVOKE_KEY};
        use tauri::webview::InvokeRequest;

        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.json");
        let config = DesktopConfig {
            website: Some("https://business.example.test/app".into()),
            ..DesktopConfig::default()
        };
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        let store = ConfigStore::open(&config_path, Vec::<PathBuf>::new()).unwrap();
        let state = DesktopState::new(store, OriginPolicy::development_unrestricted());
        let app = mock_builder()
            .manage(state)
            .invoke_handler(tauri::generate_handler![
                crate::system_declaration,
                crate::desktop::desktop_config,
            ])
            .build(crate::app_context())
            .unwrap();
        app.state::<DesktopState>()
            .ensure_business_ipc_capabilities(app.handle(), &config)
            .unwrap();
        let webview = WebviewWindowBuilder::new(
            &app,
            "business-1",
            WebviewUrl::External(Url::parse("https://business.example.test/app").unwrap()),
        )
        .build()
        .unwrap();
        let request = |command: &str, url: &str| InvokeRequest {
            cmd: command.into(),
            callback: CallbackFn(0),
            error: CallbackFn(1),
            url: Url::parse(url).unwrap(),
            body: InvokeBody::default(),
            headers: Default::default(),
            invoke_key: INVOKE_KEY.into(),
        };

        let allowed = get_ipc_response(
            &webview,
            request("system_declaration", "https://business.example.test/app"),
        )
        .unwrap()
        .deserialize::<serde_json::Value>()
        .unwrap();
        assert_eq!(allowed["protocolVersion"], crate::BRIDGE_PROTOCOL_VERSION);
        assert_eq!(
            allowed["capabilities"]["schemaVersion"],
            crate::DESKTOP_CAPABILITIES_SCHEMA_VERSION
        );
        let tracked = &allowed["capabilities"]["trackedInvocations"];
        assert_eq!(tracked["supported"], true);
        assert_eq!(tracked["available"], false);
        assert_eq!(tracked["accepting"], false);
        assert_eq!(tracked["errorCode"], "tracked-runtime-state-unavailable");
        assert_eq!(
            tracked["limits"]["maxRuntimeOperations"],
            crate::invocations::MAX_RUNTIME_OPERATIONS
        );
        assert_eq!(
            tracked["limits"]["maxDurableOperations"],
            ssdev_invocation_ledger::MAX_DURABLE_OPERATIONS
        );
        assert_eq!(
            tracked["limits"]["maxDurableOperationsPerScope"],
            ssdev_invocation_ledger::MAX_DURABLE_OPERATIONS_PER_SCOPE
        );

        assert!(get_ipc_response(
            &webview,
            request("desktop_config", "https://business.example.test/app"),
        )
        .is_err());
        assert!(get_ipc_response(
            &webview,
            request("system_declaration", "https://attacker.example/app"),
        )
        .is_err());

        let replacement = DesktopConfig {
            website: Some("https://replacement.example.test/app".into()),
            ..DesktopConfig::default()
        };
        let state = app.state::<DesktopState>();
        state
            .ensure_business_ipc_capabilities(app.handle(), &replacement)
            .unwrap();
        state.config.replace(replacement).unwrap();
        let replacement_webview = WebviewWindowBuilder::new(
            &app,
            "business-2",
            WebviewUrl::External(Url::parse("https://replacement.example.test/app").unwrap()),
        )
        .build()
        .unwrap();
        assert!(get_ipc_response(
            &replacement_webview,
            request("system_declaration", "https://replacement.example.test/app",),
        )
        .is_ok());
        assert!(get_ipc_response(
            &webview,
            request("system_declaration", "https://business.example.test/app"),
        )
        .is_err());

        let control =
            WebviewWindowBuilder::new(&app, "control", WebviewUrl::App("index.html".into()))
                .build()
                .unwrap();
        let control_url = control.url().unwrap().to_string();
        let control_result = get_ipc_response(&control, request("desktop_config", &control_url));
        if cfg!(debug_assertions) {
            assert!(
                control_result.is_ok(),
                "local control URL {control_url} was denied: {control_result:?}"
            );
        } else {
            assert!(
                control_result.is_err(),
                "release code trusted the test runtime's Vite development URL {control_url}"
            );
        }
        assert!(get_ipc_response(
            &control,
            request("desktop_config", "https://attacker.example/index.html"),
        )
        .is_err());
    }

    #[test]
    fn compatibility_policy_limits_plugin_calls_to_the_configured_business_origin() {
        use webplus_plugin_trust::TrustStore;

        let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fixtures/ci");
        let trust = TrustStore::load(&fixture_root.join("plugin-trust.json")).unwrap();
        let policy = OriginPolicy::load(
            &fixture_root.join("origin-policy.json"),
            &fixture_root.join("origin-policy.sig.json"),
            &trust,
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.json");
        let config = DesktopConfig {
            website: Some("http://10.17.5.57/app".into()),
            ..DesktopConfig::default()
        };
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        let store = ConfigStore::open(&config_path, Vec::<PathBuf>::new()).unwrap();
        let state = DesktopState::new(store, policy);
        let app = tauri::test::mock_builder()
            .build(crate::app_context())
            .unwrap();
        let webview = WebviewWindowBuilder::new(
            &app,
            "business-1",
            WebviewUrl::External(Url::parse("http://10.17.5.57/app").unwrap()),
        )
        .build()
        .unwrap();

        require_plugin_invocation(&webview, &state, "ci.health", "probe").unwrap();
        require_plugin_invocation(&webview, &state, "project.reader", "read").unwrap();

        let attacker = WebviewWindowBuilder::new(
            &app,
            "business-2",
            WebviewUrl::External(Url::parse("http://10.17.5.58/app").unwrap()),
        )
        .build()
        .unwrap();
        assert!(require_plugin_invocation(&attacker, &state, "ci.health", "probe").is_err());
    }

    #[test]
    fn deployment_coverage_includes_canonical_and_alias_plugin_routes() {
        let policy = OriginPolicy::from_unsigned_bytes(
            &serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "businessGrants": [{
                    "origin": "https://business.example.test",
                    "services": [{"serviceId": "reader", "methods": ["read"]}]
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.json");
        let config = DesktopConfig {
            website: Some("https://business.example.test/app".into()),
            ..DesktopConfig::default()
        };
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        let store = ConfigStore::open(&config_path, Vec::<PathBuf>::new()).unwrap();
        let state = DesktopState::new(store, policy);
        let plugin = directory.path().join("reader-plugin");
        fs::create_dir(&plugin).unwrap();
        fs::write(
            plugin.join("api.json"),
            serde_json::to_vec(&serde_json::json!({
                "serviceId": "reader",
                "mainClass": "reader.dll",
                "methods": [{"name": "read", "alias": "readCard"}]
            }))
            .unwrap(),
        )
        .unwrap();
        let manifest = PluginManifest::load("reader-plugin", &plugin).unwrap();

        let coverage = state
            .plugin_route_policy_coverage(&config, &[manifest])
            .unwrap();
        assert_eq!(coverage.route_count, 2);
        assert_eq!(coverage.authorized_grant_count, 1);
        assert_eq!(coverage.uncovered_route_count, 1);
    }
}
