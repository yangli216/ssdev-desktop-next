import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const appVue = new URL('../../apps/desktop/src/App.vue', import.meta.url)
const desktopRust = new URL('../../apps/desktop/src-tauri/src/lib.rs', import.meta.url)
const commandPermissions = new URL('../../apps/desktop/src-tauri/src/command_permissions.rs', import.meta.url)

function functionSource(source, name, nextName) {
  const start = source.indexOf(`async function ${name}`)
  const end = source.indexOf(`async function ${nextName}`, start + 1)
  assert.notEqual(start, -1, `${name} must exist`)
  assert.notEqual(end, -1, `${nextName} must follow ${name}`)
  return source.slice(start, end)
}

function rustFunctionSource(source, name, nextName) {
  const start = source.indexOf(`async fn ${name}`)
  const end = source.indexOf(`async fn ${nextName}`, start + 1)
  assert.notEqual(start, -1, `${name} must exist`)
  assert.notEqual(end, -1, `${nextName} must follow ${name}`)
  return source.slice(start, end)
}

test('signed plugin uninstall previews exact version and impact before one confirmation', async () => {
  const source = await readFile(appVue, 'utf8')
  const uninstall = functionSource(source, 'uninstallSignedPlugin', 'reloadPlugins')
  const inspect = uninstall.indexOf("'inspect_signed_plugin_uninstall'")
  const confirm = uninstall.indexOf('window.confirm')
  const remove = uninstall.indexOf("'uninstall_signed_plugin'")

  assert.ok(inspect >= 0 && confirm > inspect && remove > confirm)
  assert.equal(uninstall.match(/window\.confirm/g)?.length, 1)
  assert.match(uninstall, /confirmed\.pluginVersion/)
  assert.match(uninstall, /confirmed\.serviceCount[^`]+confirmed\.methodCount/)
  assert.match(uninstall, /expectedPlanId: confirmed\.planId/)
})

test('signed plugin uninstall is rebound under install, maintenance, and moved-byte boundaries', async () => {
  const source = await readFile(desktopRust, 'utf8')
  const uninstall = rustFunctionSource(source, 'uninstall_signed_plugin', 'reload_plugins')
  const installLock = uninstall.indexOf('install_lock.lock().await')
  const firstContext = uninstall.indexOf('signed_plugin_uninstall_context')
  const firstCheck = uninstall.indexOf('ensure_signed_plugin_uninstall_plan_matches')
  const maintenance = uninstall.indexOf('begin_plugin_maintenance')
  const secondContext = uninstall.indexOf('signed_plugin_uninstall_context', firstContext + 1)
  const secondCheck = uninstall.indexOf('ensure_signed_plugin_uninstall_plan_matches', firstCheck + 1)
  const removal = uninstall.indexOf('prepare_plugin_removal')
  const movedState = uninstall.indexOf('signed_plugin_directory_state_digest', removal)
  const finalCheck = uninstall.indexOf('ensure_signed_plugin_uninstall_plan_matches', secondCheck + 1)

  assert.ok(installLock >= 0 && firstContext > installLock && firstCheck > firstContext)
  assert.ok(maintenance > firstCheck && secondContext > maintenance && secondCheck > secondContext)
  assert.ok(removal > secondCheck && movedState > removal && finalCheck > movedState)
  assert.match(source, /SSDEV-SIGNED-PLUGIN-UNINSTALL-PLAN/)
  assert.match(source, /签名插件状态在卸载确认后发生变化，请重新检查卸载影响/)
})

test('signed plugin uninstall preview remains a local control permission', async () => {
  const source = await readFile(commandPermissions, 'utf8')
  const controlStart = source.indexOf('pub const CONTROL_PERMISSIONS')
  const businessStart = source.indexOf('pub const BUSINESS_PERMISSIONS')
  const floatingStart = source.indexOf('pub const FLOATING_PERMISSIONS')
  const control = source.slice(controlStart, businessStart)
  const business = source.slice(businessStart, floatingStart)

  assert.match(control, /allow-inspect-signed-plugin-uninstall/)
  assert.match(control, /allow-uninstall-signed-plugin/)
  assert.doesNotMatch(business, /signed-plugin-uninstall|uninstall-signed-plugin/)
})
