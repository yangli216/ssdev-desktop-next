import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const appVue = new URL('../../apps/desktop/src/App.vue', import.meta.url)
const desktopRust = new URL('../../apps/desktop/src-tauri/src/desktop.rs', import.meta.url)
const desktopLib = new URL('../../apps/desktop/src-tauri/src/lib.rs', import.meta.url)

function sourceBetween(source, startText, endText) {
  const start = source.indexOf(startText)
  const end = source.indexOf(endText, start + 1)
  assert.notEqual(start, -1, `${startText} must exist`)
  assert.notEqual(end, -1, `${endText} must follow ${startText}`)
  return source.slice(start, end)
}

test('committed project transitions force-close both business and floating surfaces', async () => {
  const desktop = await readFile(desktopRust, 'utf8')
  const forceClose = sourceBetween(desktop, 'pub(crate) fn force_close_business_surfaces', 'fn build_business_data_clear_preview')
  const replaceConfig = sourceBetween(desktop, 'pub(crate) fn replace_desktop_config', '#[tauri::command]\npub(crate) async fn import_desktop_config')
  const userClose = sourceBetween(desktop, 'fn install_close_confirmation', 'fn bridge_initialization_script')

  assert.match(forceClose, /label\.starts_with\(BUSINESS_LABEL_PREFIX\)/)
  assert.match(forceClose, /label\.starts_with\(FLOATING_LABEL_PREFIX\)/)
  assert.match(forceClose, /window\.destroy\(\)/)
  assert.doesNotMatch(forceClose, /window\.close\(\)/)
  assert.match(forceClose, /reset_required: true/)
  assert.match(forceClose, /release_business_window_label/)
  assert.match(forceClose, /release_floating_window_label/)
  assert.doesNotMatch(replaceConfig, /force_close_business_surfaces/)
  assert.match(userClose, /WindowEvent::CloseRequested/)
  assert.match(userClose, /api\.prevent_close\(\)/)
  assert.match(userClose, /window_after_dialog\.close\(\)/)
})

test('configuration and project commands report close outcome after the primary commit', async () => {
  const [app, desktop, lib] = await Promise.all([
    readFile(appVue, 'utf8'),
    readFile(desktopRust, 'utf8'),
    readFile(desktopLib, 'utf8'),
  ])

  assert.match(desktop, /save_desktop_config[\s\S]+Result<BusinessSurfaceCloseResult, String>/)
  assert.match(desktop, /replace_desktop_config\(&app, &state, config\)\?;[\s\S]+force_close_business_surfaces\(&app\)/)
  assert.match(desktop, /struct ConfigImportResult[\s\S]+closed_surfaces: BusinessSurfaceCloseResult/)
  assert.match(lib, /struct ProjectBundleImportResult[\s\S]+reset_required: bool[\s\S]+requested_windows: usize[\s\S]+closed_windows: usize[\s\S]+failed_windows: usize/)
  assert.match(lib, /transaction\.mark_committed\(\)[\s\S]+baseline_transition\.commit\(\);[\s\S]+force_close_business_surfaces\(&app\)/)
  assert.match(app, /invoke<BusinessSurfaceCloseResult>\('save_desktop_config'/)
  assert.match(app, /invoke<ConfigImportResult>\('import_desktop_config'/)
  assert.match(app, /businessSurfaceCloseSummary\(result\)/)
  assert.match(app, /if \(!result\.resetRequired\) return '本次变更不影响当前业务页面，已保持打开。'/)
  assert.doesNotMatch(app, /已有业务窗口已关闭/)
})

test('desktop-only configuration changes preserve the current business workspace', async () => {
  const [app, desktop] = await Promise.all([
    readFile(appVue, 'utf8'),
    readFile(desktopRust, 'utf8'),
  ])
  const resetPolicy = sourceBetween(desktop, 'fn business_surface_reset_required', 'fn enabled_shortcut_count')

  assert.match(resetPolicy, /normalized_candidate\.allow_switch = current\.allow_switch/)
  assert.match(resetPolicy, /normalized_candidate\.auto_close = current\.auto_close/)
  assert.match(resetPolicy, /normalized_candidate\.auto_start = current\.auto_start/)
  assert.match(resetPolicy, /plugin_catalog_url[\s\S]+clone_from/)
  assert.match(resetPolicy, /normalized_candidate != \*current/)
  assert.match(desktop, /let reset_required = business_surface_reset_required\(&state\.config\.snapshot\(\), &config\)/)
  assert.match(desktop, /preview\.change\.business_surface_reset_required[\s\S]+force_close_business_surfaces/)
  assert.match(app, /businessSurfaceResetRequired: boolean/)
  assert.match(app, /业务页面：\{\{ configImportPreview\.businessSurfaceResetRequired \? '应用后关闭' : '保持打开' \}\}/)
  assert.match(app, /业务页面：切换后关闭/)
})
