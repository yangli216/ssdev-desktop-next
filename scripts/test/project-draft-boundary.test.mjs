import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const appVue = new URL('../../apps/desktop/src/App.vue', import.meta.url)

test('unsaved native mappings cannot be omitted from project-changing operations', async () => {
  const source = await readFile(appVue, 'utf8')

  assert.match(source, /const projectDeliveryDraftDirty = computed\(\(\) => configDraftDirty\.value \|\| mappingDraftDirty\.value\)/)
  assert.match(source, /function requireSavedMapping\(action: string\): boolean/)
  assert.match(source, /function requireCleanProjectDrafts\(action: string\): boolean/)
  assert.match(source, /if \(!requireCleanProjectDrafts\('导出项目部署包'\)\) return/)
  assert.match(source, /if \(!requireCleanProjectDrafts\('预检项目部署包'\)\) return/)
  assert.match(source, /if \(!requireCleanProjectDrafts\('安装签名插件'\)\) return/)
  assert.match(source, /if \(!requireCleanProjectDrafts\('卸载签名插件'\)\) return/)
  assert.match(source, /if \(!requireCleanProjectDrafts\('重新扫描插件目录'\)\) return/)
  assert.match(source, /if \(!requireCleanProjectDrafts\('变更签名插件版本'\)\) return/)
  assert.match(source, /if \(!requireCleanProjectDrafts\('安装应用更新'\)\) return/)
  assert.match(source, /if \(!requireCleanProjectDrafts\('执行深度部署自检'\)\) return/)
  assert.match(source, /if \(!requireCleanProjectDrafts\('导出深度部署自检记录'\)\) return/)
  assert.match(source, /原生映射工作台有未保存更改，插件变更、应用更新和项目交付操作已暂停/)
  assert.match(source, /:inert="projectStateUnverified \|\| projectDeliveryDraftDirty"/)
  assert.match(source, /mappingDraftDirty \? '原生映射草稿尚未保存，当前结论只对应已激活映射'/)
  assert.match(source, /projectDeliveryDraftDirty \? 'DRAFT NOT CHECKED'/)
})
