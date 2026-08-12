use ssdev_config::{DesktopAction, KeyBindingConfig};
use tauri::{AppHandle, Manager};
use tauri_plugin_global_shortcut::{GlobalShortcutExt, ShortcutState};

use crate::{capture, desktop};

pub(crate) fn replace(
    app: &AppHandle,
    bindings: &[KeyBindingConfig],
    fallback: &[KeyBindingConfig],
) -> Result<(), String> {
    if let Err(error) = register_set(app, bindings) {
        if let Err(restore_error) = register_set(app, fallback) {
            return Err(format!(
                "快捷键注册失败: {error}; 恢复原快捷键同时失败: {restore_error}"
            ));
        }
        return Err(format!("快捷键注册失败: {error}"));
    }
    Ok(())
}

fn register_set(app: &AppHandle, bindings: &[KeyBindingConfig]) -> Result<(), String> {
    app.global_shortcut()
        .unregister_all()
        .map_err(|error| error.to_string())?;
    for binding in bindings.iter().filter(|binding| binding.enabled) {
        let action = binding.action;
        app.global_shortcut()
            .on_shortcut(binding.shortcut.trim(), move |app, _, event| {
                if event.state == ShortcutState::Pressed {
                    execute(app, action);
                }
            })
            .map_err(|error| format!("[{}]: {error}", binding.shortcut))?;
    }
    Ok(())
}

fn execute(app: &AppHandle, action: DesktopAction) {
    match action {
        DesktopAction::OpenBusinessWindow => {
            let state = app.state::<desktop::DesktopState>();
            if desktop::open_configured_business(app, &state).is_err() {
                tracing::warn!(
                    event_code = "shortcut-open-business-failed",
                    "shortcut business window action failed"
                );
                desktop::show_control(app);
            }
        }
        DesktopAction::CaptureBusinessWindow => capture::start_user_capture(app),
        DesktopAction::CaptureRegion => capture::start_region_capture(app),
        DesktopAction::ResetBusinessZoom => desktop::reset_business_zoom(app),
        DesktopAction::FindInBusinessWindow => desktop::dispatch_find(app),
    }
}
