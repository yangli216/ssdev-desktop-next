import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import { cloneConfig, configFingerprint } from '../../apps/desktop/src/config-draft.js'

const appVue = new URL('../../apps/desktop/src/App.vue', import.meta.url)

test('configuration fingerprints ignore object key order but preserve meaningful changes', () => {
  const first = {
    website: 'http://project.internal',
    environments: [{ name: '生产', url: 'http://project.internal' }],
    policy: { methods: ['read', 'write'], enabled: true },
  }
  const reordered = {
    policy: { enabled: true, methods: ['read', 'write'] },
    environments: [{ url: 'http://project.internal', name: '生产' }],
    website: 'http://project.internal',
  }
  assert.equal(configFingerprint(first), configFingerprint(reordered))

  reordered.environments[0].url = 'http://another.internal'
  assert.notEqual(configFingerprint(first), configFingerprint(reordered))
  reordered.environments[0].url = 'http://project.internal'
  reordered.policy.methods.reverse()
  assert.notEqual(configFingerprint(first), configFingerprint(reordered))
})

test('configuration clone is detached from the editable form', () => {
  const editable = { website: 'http://project.internal', environments: [{ name: '生产' }] }
  const candidate = cloneConfig(editable)
  editable.environments[0].name = '测试'
  assert.equal(candidate.environments[0].name, '生产')
})

test('unsaved configuration cannot silently launch, export, or enter a project plan', async () => {
  const source = await readFile(appVue, 'utf8')

  assert.match(source, /const configDraftDirty = computed/)
  assert.match(source, /function applyConfigSnapshot\(next: ConfigSnapshot\)/)
  assert.match(source, /savedConfigFingerprint\.value = configFingerprint\(next\.config\)/)
  assert.match(source, /const candidate = cloneConfig\(snapshot\.value\.config\)/)
  assert.match(source, /savedConfigFingerprint\.value = configFingerprint\(candidate\)/)
  assert.match(source, /if \(!requireSavedConfig\('启动业务系统'\)\) return/)
  assert.match(source, /if \(!requireSavedConfig\(`打开环境「\$\{environment\.name\}」`\)\) return/)
  assert.match(source, /if \(!requireSavedConfig\('导出当前有效配置'\)\) return/)
  assert.match(source, /if \(!requireSavedConfig\('导出项目部署包'\)\) return/)
  assert.match(source, /if \(!requireSavedConfig\('预检项目部署包'\)\) return/)
  assert.match(source, /当前项目配置有未保存更改。导入项目会以项目包中的配置替换这些草稿/)
  assert.match(source, /window\.addEventListener\('beforeunload', preventConfigDraftUnload\)/)
  assert.match(source, /@click="discardConfigChanges"/)
  assert.match(source, /项目配置有未保存更改，业务启动、原生能力变更和项目交付操作已暂停/)
  assert.match(source, /:disabled="busy \|\| controlStateUnverified \|\| configDraftDirty"/)
  assert.match(source, /:inert="controlStateUnverified \|\| configDraftDirty"/)
  assert.match(source, /configDraftDirty \? 'DRAFT NOT CHECKED'/)
})
