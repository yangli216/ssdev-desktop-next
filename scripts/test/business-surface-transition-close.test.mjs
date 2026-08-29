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
  assert.match(lib, /struct ProjectBundleImportResult[\s\S]+requested_windows: usize[\s\S]+closed_windows: usize[\s\S]+failed_windows: usize/)
  assert.match(lib, /transaction\.mark_committed\(\)[\s\S]+baseline_transition\.commit\(\);[\s\S]+force_close_business_surfaces\(&app\)/)
  assert.match(app, /invoke<BusinessSurfaceCloseResult>\('save_desktop_config'/)
  assert.match(app, /invoke<ConfigImportResult>\('import_desktop_config'/)
  assert.match(app, /businessSurfaceCloseSummary\(result\)/)
  assert.doesNotMatch(app, /已有业务窗口已关闭/)
})
