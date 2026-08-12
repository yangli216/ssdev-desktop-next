use serde::Deserialize;
use tauri::{AppHandle, State, WebviewWindow};

use crate::desktop::{self, DesktopState};

const UNSUPPORTED_MESSAGE: &str = "当前平台不支持桌面截图";

pub(crate) struct RegionCaptureState;

impl RegionCaptureState {
    pub(crate) fn new() -> Self {
        Self
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RegionSelection {
    left: f64,
    top: f64,
    width: f64,
    height: f64,
}

#[tauri::command]
pub(crate) async fn capture_business_window(
    caller: WebviewWindow,
    state: State<'_, DesktopState>,
) -> Result<String, String> {
    desktop::require_business(&caller, &state)?;
    Err(UNSUPPORTED_MESSAGE.into())
}

pub(crate) fn start_user_capture(_app: &AppHandle) {
    tracing::warn!(
        event_code = "business-window-capture-unsupported",
        "business window capture is unsupported on this platform"
    );
}

pub(crate) fn start_region_capture(_app: &AppHandle) {
    tracing::warn!(
        event_code = "region-capture-unsupported",
        "region capture is unsupported on this platform"
    );
}

#[tauri::command]
pub(crate) fn capture_region_snapshot(
    _caller: WebviewWindow,
    _state: State<'_, RegionCaptureState>,
) -> Result<String, String> {
    Err(UNSUPPORTED_MESSAGE.into())
}

#[tauri::command]
pub(crate) async fn complete_region_capture(
    _caller: WebviewWindow,
    _app: AppHandle,
    _state: State<'_, RegionCaptureState>,
    _selection: RegionSelection,
) -> Result<(), String> {
    Err(UNSUPPORTED_MESSAGE.into())
}

#[tauri::command]
pub(crate) fn cancel_region_capture(
    _caller: WebviewWindow,
    _state: State<'_, RegionCaptureState>,
) -> Result<(), String> {
    Err(UNSUPPORTED_MESSAGE.into())
}
