use std::collections::HashMap;
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use image::codecs::png::PngEncoder;
use image::{ExtendedColorType, ImageEncoder, RgbaImage};
use serde::Deserialize;
use tauri::webview::NewWindowResponse;
use tauri::{
    AppHandle, Manager, State, WebviewUrl, WebviewWindow, WebviewWindowBuilder, WindowEvent,
};

use crate::desktop::{self, DesktopState, BUSINESS_LABEL_PREFIX};

const MAX_CAPTURE_BYTES: usize = 24 * 1024 * 1024;
const MAX_CAPTURE_PIXELS: u64 = 33_177_600;
const CAPTURE_OVERLAY_PREFIX: &str = "capture-overlay-";
const CAPTURE_EVENT: &str = "ssdev-capture";

pub(crate) struct RegionCaptureState {
    pending: Mutex<HashMap<String, PendingRegionCapture>>,
    next_id: AtomicU64,
}

impl RegionCaptureState {
    pub(crate) fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    fn take_label(&self) -> String {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        format!("{CAPTURE_OVERLAY_PREFIX}{id}")
    }
}

struct PendingRegionCapture {
    target_label: String,
    image: RgbaImage,
    snapshot_data_url: String,
}

struct CapturedMonitor {
    image: RgbaImage,
    snapshot_data_url: String,
    x: i32,
    y: i32,
    scale_factor: f64,
}

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
    if !caller.is_focused().map_err(|error| error.to_string())? {
        return Err("只有当前聚焦的业务窗口可以截图".into());
    }
    capture_own_focused_window().await
}

pub(crate) fn start_user_capture(app: &AppHandle) {
    let target = focused_business_window(app);
    let Some(target) = target else {
        return;
    };
    tauri::async_runtime::spawn(async move {
        match capture_own_focused_window().await {
            Ok(data_url) => dispatch_capture(&target, &data_url),
            Err(_) => tracing::warn!(
                event_code = "business-window-capture-failed",
                "business window capture failed"
            ),
        }
    });
}

pub(crate) fn start_region_capture(app: &AppHandle) {
    let Some(target) = focused_business_window(app) else {
        return;
    };
    close_existing_overlays(app, &app.state::<RegionCaptureState>());
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let captured =
            match tauri::async_runtime::spawn_blocking(capture_focused_monitor_blocking).await {
                Ok(Ok(captured)) => captured,
                Ok(Err(_)) => {
                    tracing::warn!(
                        event_code = "region-monitor-capture-failed",
                        "region monitor capture failed"
                    );
                    return;
                }
                Err(_) => {
                    tracing::warn!(
                        event_code = "region-capture-task-failed",
                        "region capture task terminated unexpectedly"
                    );
                    return;
                }
            };
        if open_capture_overlay(&app, target.label(), captured).is_err() {
            tracing::warn!(
                event_code = "region-overlay-open-failed",
                "region capture overlay failed to open"
            );
        }
    });
}

#[tauri::command]
pub(crate) fn capture_region_snapshot(
    caller: WebviewWindow,
    state: State<'_, RegionCaptureState>,
) -> Result<String, String> {
    require_capture_overlay(&caller)?;
    state
        .pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(caller.label())
        .map(|pending| pending.snapshot_data_url.clone())
        .ok_or_else(|| "区域截图会话不存在或已经结束".to_owned())
}

#[tauri::command]
pub(crate) async fn complete_region_capture(
    caller: WebviewWindow,
    app: AppHandle,
    state: State<'_, RegionCaptureState>,
    selection: RegionSelection,
) -> Result<(), String> {
    require_capture_overlay(&caller)?;
    validate_selection(&selection)?;
    let pending = state
        .pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(caller.label())
        .ok_or_else(|| "区域截图会话不存在或已经结束".to_owned())?;
    let _ = caller.close();
    let data_url =
        tauri::async_runtime::spawn_blocking(move || crop_and_encode(pending.image, &selection))
            .await
            .map_err(|error| format!("区域截图编码任务异常终止: {error}"))??;
    let target = app
        .get_webview_window(&pending.target_label)
        .ok_or_else(|| "原业务窗口已经关闭".to_owned())?;
    dispatch_capture(&target, &data_url);
    Ok(())
}

#[tauri::command]
pub(crate) fn cancel_region_capture(
    caller: WebviewWindow,
    state: State<'_, RegionCaptureState>,
) -> Result<(), String> {
    require_capture_overlay(&caller)?;
    state
        .pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(caller.label());
    caller.close().map_err(|error| error.to_string())
}

fn focused_business_window(app: &AppHandle) -> Option<WebviewWindow> {
    app.webview_windows()
        .into_iter()
        .find_map(|(label, window)| {
            (label.starts_with(BUSINESS_LABEL_PREFIX) && window.is_focused().unwrap_or(false))
                .then_some(window)
        })
}

fn open_capture_overlay(
    app: &AppHandle,
    target_label: &str,
    captured: CapturedMonitor,
) -> Result<(), String> {
    let state = app.state::<RegionCaptureState>();
    let label = state.take_label();
    let width = captured.image.width();
    let height = captured.image.height();
    let scale = captured.scale_factor.max(1.0);
    state
        .pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(
            label.clone(),
            PendingRegionCapture {
                target_label: target_label.to_owned(),
                image: captured.image,
                snapshot_data_url: captured.snapshot_data_url,
            },
        );

    let builder = WebviewWindowBuilder::new(app, &label, WebviewUrl::App("capture.html".into()))
        .title("选择截图区域")
        .inner_size(f64::from(width) / scale, f64::from(height) / scale)
        .position(f64::from(captured.x) / scale, f64::from(captured.y) / scale)
        .decorations(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .resizable(false)
        .visible(false)
        .on_navigation(is_capture_overlay_url)
        .on_new_window(|_, _| NewWindowResponse::Deny);
    let window = match builder.build() {
        Ok(window) => window,
        Err(error) => {
            state
                .pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&label);
            return Err(error.to_string());
        }
    };
    let cleanup_app = app.clone();
    let cleanup_label = label.clone();
    window.on_window_event(move |event| {
        if matches!(event, WindowEvent::Destroyed) {
            cleanup_app
                .state::<RegionCaptureState>()
                .pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&cleanup_label);
        }
    });
    window.show().map_err(|error| error.to_string())?;
    window.set_focus().map_err(|error| error.to_string())?;
    Ok(())
}

fn is_capture_overlay_url(url: &url::Url) -> bool {
    desktop::is_bundled_page(url, "/capture.html")
}

fn close_existing_overlays(app: &AppHandle, state: &RegionCaptureState) {
    let labels = state
        .pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .drain()
        .map(|(label, _)| label)
        .collect::<Vec<_>>();
    for label in labels {
        if let Some(window) = app.get_webview_window(&label) {
            let _ = window.close();
        }
    }
}

fn require_capture_overlay(caller: &WebviewWindow) -> Result<(), String> {
    if !caller.label().starts_with(CAPTURE_OVERLAY_PREFIX) {
        return Err("该命令只能由本地截图遮罩调用".into());
    }
    let url = caller
        .url()
        .map_err(|_| "无法确认本地截图遮罩来源".to_owned())?;
    if !is_capture_overlay_url(&url) {
        return Err("当前截图遮罩不是受信任的内置页面".into());
    }
    Ok(())
}

fn validate_selection(selection: &RegionSelection) -> Result<(), String> {
    let values = [
        selection.left,
        selection.top,
        selection.width,
        selection.height,
    ];
    if values.iter().any(|value| !value.is_finite())
        || selection.left < 0.0
        || selection.top < 0.0
        || selection.width <= 0.0
        || selection.height <= 0.0
        || selection.left + selection.width > 1.000_001
        || selection.top + selection.height > 1.000_001
    {
        return Err("截图区域必须位于当前显示器范围内".into());
    }
    Ok(())
}

fn crop_and_encode(image: RgbaImage, selection: &RegionSelection) -> Result<String, String> {
    let image_width = image.width();
    let image_height = image.height();
    let left = (selection.left * f64::from(image_width)).floor() as u32;
    let top = (selection.top * f64::from(image_height)).floor() as u32;
    let right = ((selection.left + selection.width) * f64::from(image_width))
        .ceil()
        .min(f64::from(image_width)) as u32;
    let bottom = ((selection.top + selection.height) * f64::from(image_height))
        .ceil()
        .min(f64::from(image_height)) as u32;
    let width = right.saturating_sub(left);
    let height = bottom.saturating_sub(top);
    if width < 2 || height < 2 {
        return Err("截图区域过小".into());
    }
    let cropped = image::imageops::crop_imm(&image, left, top, width, height).to_image();
    encode_png_data_url(&cropped)
}

async fn capture_own_focused_window() -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(capture_own_focused_window_blocking)
        .await
        .map_err(|error| format!("截图任务异常终止: {error}"))?
}

fn capture_own_focused_window_blocking() -> Result<String, String> {
    let window = focused_native_window()?;
    let image = window.capture_image().map_err(|error| error.to_string())?;
    encode_png_data_url(&image)
}

fn capture_focused_monitor_blocking() -> Result<CapturedMonitor, String> {
    let window = focused_native_window()?;
    let monitor = window
        .current_monitor()
        .map_err(|error| error.to_string())?;
    let image = monitor.capture_image().map_err(|error| error.to_string())?;
    let snapshot_data_url = encode_png_data_url(&image)?;
    Ok(CapturedMonitor {
        image,
        snapshot_data_url,
        x: monitor.x().map_err(|error| error.to_string())?,
        y: monitor.y().map_err(|error| error.to_string())?,
        scale_factor: f64::from(monitor.scale_factor().map_err(|error| error.to_string())?),
    })
}

fn focused_native_window() -> Result<xcap::Window, String> {
    let process_id = std::process::id();
    xcap::Window::all()
        .map_err(|error| error.to_string())?
        .into_iter()
        .find(|window| {
            window.pid().ok() == Some(process_id) && window.is_focused().unwrap_or(false)
        })
        .ok_or_else(|| "未找到当前应用内聚焦的可截图窗口".to_owned())
}

fn encode_png_data_url(image: &RgbaImage) -> Result<String, String> {
    let pixels = u64::from(image.width()) * u64::from(image.height());
    if pixels > MAX_CAPTURE_PIXELS {
        return Err(format!(
            "截图像素数 {pixels} 超过安全上限 {MAX_CAPTURE_PIXELS}"
        ));
    }
    let mut bytes = Cursor::new(Vec::new());
    PngEncoder::new(&mut bytes)
        .write_image(
            image.as_raw(),
            image.width(),
            image.height(),
            ExtendedColorType::Rgba8,
        )
        .map_err(|error| error.to_string())?;
    let bytes = bytes.into_inner();
    if bytes.len() > MAX_CAPTURE_BYTES {
        return Err(format!(
            "截图大小 {} MiB 超过安全上限 {} MiB",
            bytes.len() / (1024 * 1024),
            MAX_CAPTURE_BYTES / (1024 * 1024)
        ));
    }
    Ok(format!("data:image/png;base64,{}", STANDARD.encode(bytes)))
}

fn dispatch_capture(target: &WebviewWindow, data_url: &str) {
    if let Ok(payload) = serde_json::to_string(data_url) {
        let _ = target.eval(format!(
            "window.dispatchEvent(new CustomEvent('{CAPTURE_EVENT}', {{ detail: {payload} }}));"
        ));
    }
}

#[cfg(test)]
mod tests {
    use image::Rgba;

    use super::*;

    #[test]
    fn normalized_region_is_bounded_and_cropped() {
        let image = RgbaImage::from_pixel(100, 80, Rgba([1, 2, 3, 255]));
        let selection = RegionSelection {
            left: 0.25,
            top: 0.25,
            width: 0.5,
            height: 0.5,
        };
        validate_selection(&selection).unwrap();
        let encoded = crop_and_encode(image, &selection).unwrap();
        assert!(encoded.starts_with("data:image/png;base64,"));
    }

    #[test]
    fn invalid_or_tiny_regions_are_rejected() {
        let outside = RegionSelection {
            left: 0.8,
            top: 0.0,
            width: 0.3,
            height: 0.5,
        };
        assert!(validate_selection(&outside).is_err());

        let tiny = RegionSelection {
            left: 0.0,
            top: 0.0,
            width: 0.001,
            height: 0.001,
        };
        assert!(crop_and_encode(RgbaImage::new(100, 100), &tiny).is_err());
    }

    #[test]
    fn capture_overlay_navigation_stays_on_the_bundled_page() {
        assert!(is_capture_overlay_url(
            &url::Url::parse("tauri://localhost/capture.html").unwrap()
        ));
        assert_eq!(
            is_capture_overlay_url(&url::Url::parse("http://127.0.0.1:1420/capture.html").unwrap()),
            cfg!(debug_assertions),
            "the Vite development origin must never be trusted by a release build"
        );
        assert!(!is_capture_overlay_url(
            &url::Url::parse("https://attacker.example/capture.html").unwrap()
        ));
        assert!(!is_capture_overlay_url(
            &url::Url::parse("tauri://localhost/index.html").unwrap()
        ));
        assert!(!is_capture_overlay_url(
            &url::Url::parse("https://tauri.localhost/other/capture.html").unwrap()
        ));
        assert!(!is_capture_overlay_url(
            &url::Url::parse("tauri://localhost/capture.html?source=remote").unwrap()
        ));
    }

    #[test]
    fn capture_event_matches_the_shared_sdk_contract() {
        let contract: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../packages/web-bridge/bridge-contract.json"
        ))
        .expect("bridge contract must be valid JSON");
        assert!(contract["events"]
            .as_array()
            .expect("bridge events must be an array")
            .iter()
            .any(|event| event == CAPTURE_EVENT));
    }
}
