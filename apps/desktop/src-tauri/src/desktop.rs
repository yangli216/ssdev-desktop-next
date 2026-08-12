use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssdev_config::{ConfigStore, DesktopConfig};
use ssdev_origin_policy::{OriginPolicy, OriginPolicySummary};
use tauri::ipc::CapabilityBuilder;
use tauri::menu::{Menu, MenuBuilder, SubmenuBuilder};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::webview::NewWindowResponse;
use tauri::{
    AppHandle, Manager, State, WebviewUrl, WebviewWindow, WebviewWindowBuilder, WindowEvent,
};
use tauri_plugin_autostart::ManagerExt as AutostartManagerExt;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tauri_plugin_opener::OpenerExt;
use url::Url;

pub(crate) const BUSINESS_LABEL_PREFIX: &str = "business-";
const FLOATING_LABEL_PREFIX: &str = "floating-";
const FLOATING_ACTION_EVENT: &str = "ssdev-floating-action";
const CONTROL_PAGE: &str = "/index.html";
const APP_EXIT_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_BUSINESS_WINDOWS: usize = 16;

pub(crate) struct DesktopState {
    pub(crate) config: Arc<ConfigStore>,
    origin_policy: Arc<OriginPolicy>,
    next_window_id: AtomicU64,
    next_capability_id: AtomicU64,
    next_tray_action_id: AtomicU64,
    exit_lifecycle: ExitLifecycle,
    ipc_business_origins: Mutex<BTreeSet<String>>,
    business_windows: Mutex<BTreeSet<String>>,
    tray_environment_actions: Mutex<HashMap<String, String>>,
    floating_windows: Mutex<HashMap<String, FloatingEntry>>,
}

impl DesktopState {
    pub(crate) fn new(config: ConfigStore, origin_policy: OriginPolicy) -> Self {
        Self {
            config: Arc::new(config),
            origin_policy: Arc::new(origin_policy),
            next_window_id: AtomicU64::new(1),
            next_capability_id: AtomicU64::new(1),
            next_tray_action_id: AtomicU64::new(1),
            exit_lifecycle: ExitLifecycle::new(),
            ipc_business_origins: Mutex::new(BTreeSet::new()),
            business_windows: Mutex::new(BTreeSet::new()),
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

    fn authorize_config(&self, config: &DesktopConfig) -> Result<(), String> {
        self.origin_policy
            .authorize(config)
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
            if windows.insert(label.clone()) {
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
pub(crate) fn save_desktop_config(
    caller: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
    config: DesktopConfig,
) -> Result<(), String> {
    require_control(&caller)?;
    replace_desktop_config(&app, &state, config)
}

fn replace_desktop_config(
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
    close_business_windows(app);
    Ok(())
}

#[tauri::command]
pub(crate) fn import_desktop_config(
    caller: WebviewWindow,
    app: AppHandle,
    state: State<'_, DesktopState>,
    source: PathBuf,
) -> Result<ConfigSnapshot, String> {
    require_control(&caller)?;
    let config = ssdev_config::load_config_file(&source).map_err(|error| error.to_string())?;
    replace_desktop_config(&app, &state, config)?;
    Ok(config_snapshot(&state))
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
        Ok(_) => Ok(label),
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
pub(crate) fn clear_business_data(caller: WebviewWindow, app: AppHandle) -> Result<(), String> {
    require_control(&caller)?;
    clear_business_data_internal(&app)
}

#[tauri::command]
pub(crate) fn reload_business_windows(caller: WebviewWindow, app: AppHandle) -> Result<(), String> {
    require_control(&caller)?;
    reload_business_windows_internal(&app)
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
                    if reload_business_windows_internal(app).is_err() {
                        tracing::warn!(
                            event_code = "tray-reload-business-failed",
                            "tray reload action failed"
                        );
                    }
                }
                "clear-business-data" => {
                    if clear_business_data_internal(app).is_err() {
                        tracing::warn!(
                            event_code = "tray-clear-business-data-failed",
                            "tray clear business data action failed"
                        );
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
                show_control(tray.app_handle());
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
        .text("clear-business-data", "清理站点数据")
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

pub(crate) fn mark_exit_ready(app: &AppHandle) {
    app.state::<DesktopState>().exit_lifecycle.mark_ready();
}

fn request_graceful_exit(app: &AppHandle, exit_code: i32) {
    let state = app.state::<DesktopState>();
    if !state.exit_lifecycle.begin_drain() {
        return;
    }

    close_business_windows(app);
    let app = app.clone();
    let (controller, invocation_coordinator) = {
        let bridge = app.state::<crate::BridgeState>();
        (
            Arc::clone(&bridge.controller),
            bridge.invocation_coordinator.clone(),
        )
    };
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
        mark_exit_ready(&app);
        app.exit(exit_code);
    });
}

pub(crate) fn setup_control_window(app: &tauri::App) -> tauri::Result<()> {
    WebviewWindowBuilder::new(app, "control", WebviewUrl::App("index.html".into()))
        .title("SSDEV Desktop")
        .inner_size(1120.0, 760.0)
        .min_inner_size(760.0, 600.0)
        .center()
        .resizable(true)
        .on_navigation(is_control_page)
        .on_new_window(|_, _| NewWindowResponse::Deny)
        .build()?;
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
    let mut builder = WebviewWindowBuilder::new(app, label, WebviewUrl::External(url))
        .title(options.title)
        .inner_size(1280.0, 800.0)
        .initialization_script(script)
        .on_navigation(move |url| {
            matches!(url.scheme(), "http" | "https")
                && navigation_origins.contains(&url.origin().ascii_serialization())
        })
        .on_new_window(|_, _| NewWindowResponse::Deny)
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
}})();"#
    ))
}

pub(crate) fn close_business_windows(app: &AppHandle) {
    for (label, window) in app.webview_windows() {
        if label.starts_with(BUSINESS_LABEL_PREFIX) {
            let _ = window.close();
        }
    }
}

fn clear_business_data_internal(app: &AppHandle) -> Result<(), String> {
    for (label, window) in app.webview_windows() {
        if label.starts_with(BUSINESS_LABEL_PREFIX) {
            window
                .clear_all_browsing_data()
                .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn reload_business_windows_internal(app: &AppHandle) -> Result<(), String> {
    for (label, window) in app.webview_windows() {
        if label.starts_with(BUSINESS_LABEL_PREFIX) {
            window.reload().map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

pub(crate) fn show_control(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("control") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
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
    fn bridge_script_contains_only_the_narrow_plugin_api() {
        let origins = BTreeSet::from(["https://example.test".into()]);
        let script = bridge_initialization_script(&origins, None).unwrap();

        assert!(script.contains("plugin_invoke"));
        assert!(script.contains("system_declaration"));
        assert!(script.contains("open_external_url"));
        assert!(script.contains("webPlusInvoke"));
        assert!(script.contains("open_secondary_window"));
        assert!(script.contains("deepFreeze"));
        assert!(!script.contains("shell"));
        assert!(!script.contains("filesystem"));
    }

    #[test]
    fn business_bridge_matches_the_shared_sdk_contract() {
        let contract: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../packages/web-bridge/bridge-contract.json"
        ))
        .expect("bridge contract must be valid JSON");
        assert_eq!(contract["schemaVersion"], 3);
        assert_eq!(contract["protocolVersion"], crate::BRIDGE_PROTOCOL_VERSION);

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
    fn signed_policy_scopes_plugin_calls_to_exact_services_and_methods() {
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
            website: Some("https://business.invalid/app".into()),
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
            WebviewUrl::External(Url::parse("https://business.invalid/app").unwrap()),
        )
        .build()
        .unwrap();

        require_plugin_invocation(&webview, &state, "ci.health", "probe").unwrap();
        assert!(require_plugin_invocation(&webview, &state, "ci.health", "reset").is_err());
        assert!(require_plugin_invocation(&webview, &state, "admin", "probe").is_err());
    }
}
