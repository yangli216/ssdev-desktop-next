import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const desktopRust = new URL('../../apps/desktop/src-tauri/src/desktop.rs', import.meta.url)
const libRust = new URL('../../apps/desktop/src-tauri/src/lib.rs', import.meta.url)
const ssoRust = new URL('../../apps/desktop/src-tauri/src/sso.rs', import.meta.url)

function functionSource(source, signature, nextSignature) {
  const start = source.indexOf(signature)
  const end = source.indexOf(nextSignature, start + 1)
  assert.notEqual(start, -1, `${signature} must exist`)
  assert.notEqual(end, -1, `${nextSignature} must follow ${signature}`)
  return source.slice(start, end)
}

test('normal startup opens the configured business surface and falls back to control', async () => {
  const [desktop, lib, sso] = await Promise.all([
    readFile(desktopRust, 'utf8'),
    readFile(libRust, 'utf8'),
    readFile(ssoRust, 'utf8'),
  ])
  const setup = functionSource(lib, 'desktop::setup_control_window(app)?', 'tracing::info!(')
  const control = functionSource(desktop, 'pub(crate) fn setup_control_window', 'pub(crate) fn require_control')

  assert.match(control, /\.visible\(false\)/)
  assert.match(setup, /SsoLaunchOutcome::NotRequested/)
  assert.match(setup, /initial_config\.website_url\(\)\?\.is_some\(\)/)
  assert.match(setup, /desktop::open_configured_business\(app\.handle\(\), &desktop_state\)/)
  assert.match(setup, /startup-business-window-unavailable/)
  assert.match(setup, /desktop::show_control\(app\.handle\(\)\)/)
  assert.match(setup, /else if !tray_available/)
  assert.match(sso, /Err\(_\) => \{[\s\S]*desktop::show_control\(&app\)/)
})

test('single-instance and tray activation restore business before administration', async () => {
  const [desktop, lib] = await Promise.all([
    readFile(desktopRust, 'utf8'),
    readFile(libRust, 'utf8'),
  ])
  const singleInstance = functionSource(
    lib,
    '.plugin(tauri_plugin_single_instance::init',
    '.plugin(shortcut_plugin)',
  )
  const primarySurface = functionSource(
    desktop,
    'pub(crate) fn focus_primary_surface',
    'pub(crate) fn reset_business_zoom',
  )

  assert.match(singleInstance, /SsoLaunchOutcome::NotRequested => desktop::focus_primary_surface\(app\)/)
  assert.match(singleInstance, /SsoLaunchOutcome::Rejected => desktop::show_control\(app\)/)
  assert.match(desktop, /TrayIconEvent::Click[\s\S]*focus_primary_surface\(tray\.app_handle\(\)\)/)
  assert.match(primarySurface, /label\.starts_with\(BUSINESS_LABEL_PREFIX\)/)
  assert.match(primarySurface, /business_windows\.sort_by/)
  assert.match(primarySurface, /show_control\(app\)/)
  assert.match(primarySurface, /window\.set_focus\(\)/)
})

test('closing control hides it only when the tray can reopen it', async () => {
  const desktop = await readFile(desktopRust, 'utf8')
  const control = functionSource(desktop, 'pub(crate) fn setup_control_window', 'pub(crate) fn require_control')

  assert.match(control, /WindowEvent::CloseRequested/)
  assert.match(control, /state\.exit_lifecycle\.is_ready\(\)/)
  assert.match(control, /control\.app_handle\(\)\.tray_by_id\("ssdev-main"\)\.is_some\(\)/)
  assert.match(control, /api\.prevent_close\(\)/)
  assert.match(control, /control\.hide\(\)/)
})
