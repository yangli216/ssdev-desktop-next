import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import {
  mappingDeletionDiscardsDraft,
  mappingDraftTargetsPlugin,
} from '../../apps/desktop/src/local-mapping-draft.js'

const studioVue = new URL('../../apps/desktop/src/LocalMappingStudio.vue', import.meta.url)

test('native mapping operations cannot silently use an older activated mapping', async () => {
  const source = await readFile(studioVue, 'utf8')

  assert.match(source, /const savedMappingPluginId = computed/)
  assert.match(source, /mappingDraftTargetsPlugin\(\{[\s\S]+savedPluginId: savedMappingPluginId\.value[\s\S]+currentPluginId: draft\.value\.pluginId/)
  assert.match(source, /mappingDeletionDiscardsDraft\(\{[\s\S]+currentPluginId: draft\.value\.pluginId/)
  assert.match(source, /function requireSavedTargetMapping\(pluginId: string, action: string\): boolean/)
  assert.match(source, /function requireActiveMappingSnapshot\(action: string\): boolean/)
  assert.match(source, /async function exportMapping[\s\S]+requireSavedTargetMapping\(pluginId, '导出迁移包'\)[\s\S]+await save\(/)
  assert.match(source, /async function exportTypescript[\s\S]+requireSavedTargetMapping\(pluginId, '导出 TypeScript 客户端'\)[\s\S]+await save\(/)
  assert.match(source, /async function exportReleaseSource[\s\S]+requireSavedTargetMapping\(pluginId, '导出发布源'\)[\s\S]+await open\(/)
  assert.match(source, /async function invokeDebug[\s\S]+requireActiveMappingSnapshot\('运行现场测试'\)[\s\S]+debug_plugin_invoke/)
  assert.match(source, /async function saveDebugCase[\s\S]+requireActiveMappingSnapshot\('保存调试用例'\)[\s\S]+save_local_mapping_debug_case/)
  assert.match(source, /async function runDebugCases[\s\S]+requireActiveMappingSnapshot\('运行回归用例'\)[\s\S]+run_local_mapping_debug_cases/)
  assert.match(source, /deletionDiscardsCurrentDraft\(pluginId\)[\s\S]+本地映射「\$\{pluginId\}」有未保存更改。删除成功后这些草稿也会丢失/)
  assert.match(source, /当前草稿有未保存更改；当前映射的调试、回归和导出已暂停/)
  assert.match(source, /function discardDraftChanges\(\)[\s\S]+replaceDraft\(savedDraft\.value, '已放弃未保存更改，恢复到最近保存状态。'\)/)
  assert.match(source, /v-if="draftDirty" type="button" :disabled="busy \|\| disabled" @click="discardDraftChanges">放弃更改/)
  assert.match(source, /:disabled="busy \|\| disabled \|\| targetHasUnsavedDraft\(mapping\.pluginId\)"/)
  assert.match(source, /:disabled="busy \|\| disabled \|\| draftDirty \|\| !mappingIsInstalled" @click="invokeDebug"/)
})

test('draft identity guards both the saved and edited plugin IDs without overblocking unrelated mappings', () => {
  const renamedDraft = { dirty: true, savedPluginId: 'device-a', currentPluginId: 'device-b' }

  assert.equal(mappingDraftTargetsPlugin(renamedDraft, 'device-a'), true)
  assert.equal(mappingDraftTargetsPlugin(renamedDraft, 'device-b'), true)
  assert.equal(mappingDraftTargetsPlugin(renamedDraft, 'device-c'), false)
  assert.equal(mappingDraftTargetsPlugin({ ...renamedDraft, dirty: false }, 'device-a'), false)
  assert.equal(mappingDraftTargetsPlugin({ dirty: true, savedPluginId: '', currentPluginId: ' device-b ' }, 'device-b'), true)
  assert.equal(mappingDraftTargetsPlugin(renamedDraft, ''), false)

  assert.equal(mappingDeletionDiscardsDraft(renamedDraft, 'device-a'), false)
  assert.equal(mappingDeletionDiscardsDraft(renamedDraft, 'device-b'), true)
  assert.equal(mappingDeletionDiscardsDraft({ ...renamedDraft, dirty: false }, 'device-b'), false)
})

test('editing a mapping invalidates results produced by the previous activated snapshot', async () => {
  const source = await readFile(studioVue, 'utf8')

  assert.match(source, /watch\(draftDirty, \(value\) => \{[\s\S]+debugResult\.value = null[\s\S]+suggestedExpectedDataText\.value = ''[\s\S]+regressionResults\.value = \[\]/)
  assert.match(source, /v-if="debugResult && !draftDirty"/)
  assert.match(source, /v-if="regressionResults\.length && !draftDirty"/)
})
