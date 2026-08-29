import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const studioVue = new URL('../../apps/desktop/src/LocalMappingStudio.vue', import.meta.url)
const appVue = new URL('../../apps/desktop/src/App.vue', import.meta.url)

function functionSource(source, name, nextName) {
  const start = source.indexOf(`function ${name}`)
  const end = source.indexOf(`function ${nextName}`, start + 1)
  assert.notEqual(start, -1, `${name} must exist`)
  assert.notEqual(end, -1, `${nextName} must follow ${name}`)
  return source.slice(start, end)
}

test('committed mapping actions are not reported as failed by a follow-up inventory read', async () => {
  const source = await readFile(studioVue, 'utf8')
  const committed = functionSource(source, 'runCommittedMappingAction', 'retryMappingInventory')
  const primary = committed.indexOf('result = await action()')
  const changed = committed.indexOf("emit('changed')")
  const refresh = committed.indexOf('await refreshCommittedMapping(plan)')

  assert.ok(primary >= 0 && changed > primary && refresh > changed)
  assert.match(source, /async function refreshCommittedMapping[\s\S]+操作已经完成，请勿重复执行，重新读取后再继续/)
  assert.match(source, /pendingInventoryRefresh\.value = plan[\s\S]+inventoryUnverified\.value = true/)
  assert.match(source, /MAPPING_INVENTORY_REFRESH_TIMEOUT_MS = 15_000/)
  assert.match(source, /const inventoryUnverified = ref\(true\)/)
  assert.match(source, /onMounted\(async \(\) => \{[\s\S]+busy\.value = true[\s\S]+await loadInventory\(\)[\s\S]+inventoryUnverified\.value = false[\s\S]+finally \{[\s\S]+busy\.value = false/)
  assert.match(source, /@click="retryMappingInventory">重新读取映射/)
  assert.match(source, /class="studio-copy" :inert="busy \|\| inventoryUnverified"/)
  assert.match(source, /class="mapping-editor" :inert="busy \|\| inventoryUnverified"/)

  for (const [name, nextName] of [
    ['saveMapping', 'deleteMapping'],
    ['deleteMapping', 'exportMapping'],
    ['confirmMappingImport', 'mappingImportActionLabel'],
  ]) {
    const action = functionSource(source, name, nextName)
    assert.match(action, /runCommittedMappingAction\(/)
    assert.doesNotMatch(action, /await loadInventory\(\)/)
  }
})

test('an unverified mapping workspace blocks global project actions but keeps its own retry reachable', async () => {
  const source = await readFile(appVue, 'utf8')

  assert.match(source, /const mappingWorkspaceUnverified = ref\(false\)/)
  assert.match(source, /const controlStateUnverified = computed\(\(\) => \([\s\S]+controlLoadFailed\.value \|\| controlRefreshIncomplete\.value \|\| runtimeStatusStale\.value/)
  assert.match(source, /const projectStateUnverified = computed\(\(\) => \([\s\S]+controlStateUnverified\.value \|\| mappingWorkspaceUnverified\.value/)
  assert.match(source, /原生映射工作台清单尚未复核，相关项目操作已暂停/)
  assert.match(source, /function requireVerifiedControlState\(action: string\): boolean[\s\S]+原生映射清单尚未复核/)
  assert.match(source, /requireVerifiedControlState\(action\) && requireSavedConfig\(action\) && requireSavedMapping\(action\)/)
  assert.match(source, /if \(!requireVerifiedControlState\('导入项目部署包'\)\) return/)
  assert.match(source, /:disabled="busy \|\| controlStateUnverified \|\| configDraftDirty"/)
  assert.match(source, /:inert="projectStateUnverified \|\| projectDeliveryDraftDirty"/)
  assert.match(source, /@state-unverified="mappingWorkspaceUnverified = \$event"/)
  assert.match(source, /controlRefreshIncomplete \|\| runtimeStatusStale \|\| mappingWorkspaceUnverified \? 'STATUS UNKNOWN'/)
})
