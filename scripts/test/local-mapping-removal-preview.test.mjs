import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const studioVue = new URL('../../apps/desktop/src/LocalMappingStudio.vue', import.meta.url)
const desktopRust = new URL('../../apps/desktop/src-tauri/src/lib.rs', import.meta.url)

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

test('mapping deletion previews exact bounded impact before one confirmation', async () => {
  const source = await readFile(studioVue, 'utf8')
  const deletion = functionSource(source, 'deleteMapping', 'exportMapping')
  const inspect = deletion.indexOf("'inspect_local_mapping_removal'")
  const confirm = deletion.indexOf('window.confirm')
  const remove = deletion.indexOf("'delete_local_mapping'")

  assert.ok(inspect >= 0 && confirm > inspect && remove > confirm)
  assert.equal(deletion.match(/window\.confirm/g)?.length, 1)
  assert.match(deletion, /preview\.serviceCount[^`]+preview\.methodCount[^`]+preview\.debugCaseCount/)
  assert.match(deletion, /expectedPlanId: preview\.planId/)
  assert.match(deletion, /deletionDiscardsCurrentDraft\(pluginId\)/)
})

test('mapping deletion is rebound under the install and maintenance boundaries', async () => {
  const source = await readFile(desktopRust, 'utf8')
  const deletion = rustFunctionSource(source, 'delete_local_mapping', 'debug_plugin_invoke')
  const installLock = deletion.indexOf('install_lock.lock().await')
  const firstContext = deletion.indexOf('local_mapping_removal_context')
  const firstCheck = deletion.indexOf('ensure_local_mapping_removal_plan_matches')
  const maintenance = deletion.indexOf('begin_plugin_maintenance')
  const secondContext = deletion.indexOf('local_mapping_removal_context', firstContext + 1)
  const secondCheck = deletion.indexOf('ensure_local_mapping_removal_plan_matches', firstCheck + 1)
  const removal = deletion.indexOf('prepare_removal')
  const movedState = deletion.indexOf('local_mapping_directory_state_digest', removal)
  const finalCheck = deletion.indexOf('ensure_local_mapping_removal_plan_matches', secondCheck + 1)

  assert.ok(installLock >= 0 && firstContext > installLock && firstCheck > firstContext)
  assert.ok(maintenance > firstCheck && secondContext > maintenance && secondCheck > secondContext && removal > secondCheck)
  assert.ok(movedState > removal && finalCheck > movedState)
  assert.match(source, /SSDEV-LOCAL-MAPPING-REMOVAL-PLAN/)
  assert.match(source, /本地映射状态在删除确认后发生变化，请重新检查删除影响/)
})
