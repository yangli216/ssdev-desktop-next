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

test('full plugin reload previews bounded route impact before one confirmation', async () => {
  const source = await readFile(appVue, 'utf8')
  const reload = functionSource(source, 'reloadPlugins', 'refreshPluginsAfterMapping')
  const inspect = reload.indexOf("'inspect_plugin_reload'")
  const confirm = reload.indexOf('window.confirm')
  const replace = reload.indexOf("'reload_plugins'")

  assert.ok(inspect >= 0 && confirm > inspect && replace > confirm)
  assert.equal(reload.match(/window\.confirm/g)?.length, 1)
  assert.match(reload, /confirmed\.signedPluginCount[^`]+confirmed\.localMappingCount/)
  assert.match(reload, /confirmed\.serviceCount[^`]+confirmed\.methodCount/)
  assert.match(reload, /confirmed\.removedLocalMappingCount/)
  assert.match(reload, /expectedPlanId: confirmed\.planId/)
})

test('full plugin reload rebinds candidates after preflight and inside global maintenance', async () => {
  const source = await readFile(desktopRust, 'utf8')
  const reload = rustFunctionSource(source, 'reload_plugins', 'plugin_inventory')
  const installLock = reload.indexOf('install_lock.lock().await')
  const firstContext = reload.indexOf('plugin_reload_context(&')
  const firstCheck = reload.indexOf('ensure_plugin_reload_plan_matches')
  const preflight = reload.indexOf('preflight_manifests')
  const secondContext = reload.indexOf('plugin_reload_context(&', firstContext + 1)
  const secondCheck = reload.indexOf('ensure_plugin_reload_plan_matches', firstCheck + 1)
  const maintenance = reload.indexOf('begin_maintenance')
  const thirdContext = reload.indexOf('plugin_reload_context(&', secondContext + 1)
  const thirdCheck = reload.indexOf('ensure_plugin_reload_plan_matches', secondCheck + 1)
  const replace = reload.indexOf('replace_manifests(&candidate_manifests)')
  const finalDigest = reload.indexOf('plugin_reload_candidate_state_digest', replace)
  const finalCheck = reload.indexOf('ensure_plugin_reload_candidate_state_matches', finalDigest)
  const restore = reload.indexOf('replace_manifests(&previous_manifests)', finalCheck)

  assert.ok(installLock >= 0 && firstContext > installLock && firstCheck > firstContext)
  assert.ok(preflight > firstCheck && secondContext > preflight && secondCheck > secondContext)
  assert.ok(maintenance > secondCheck && thirdContext > maintenance && thirdCheck > thirdContext)
  assert.ok(replace > thirdCheck && finalDigest > replace && finalCheck > finalDigest && restore > finalCheck)
  assert.match(source, /SSDEV-PLUGIN-RELOAD-PLAN/)
  assert.match(source, /插件目录或活动路由在重新扫描确认后发生变化，请重新检查扫描影响/)
})

test('plugin reload preview and mutation stay in the local control ACL', async () => {
  const source = await readFile(commandPermissions, 'utf8')
  const controlStart = source.indexOf('pub const CONTROL_PERMISSIONS')
  const businessStart = source.indexOf('pub const BUSINESS_PERMISSIONS')
  const floatingStart = source.indexOf('pub const FLOATING_PERMISSIONS')
  const control = source.slice(controlStart, businessStart)
  const business = source.slice(businessStart, floatingStart)

  assert.match(control, /allow-inspect-plugin-reload/)
  assert.match(control, /allow-reload-plugins/)
  assert.doesNotMatch(business, /plugin-reload|reload-plugins/)
})
