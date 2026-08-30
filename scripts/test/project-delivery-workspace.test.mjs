import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const controlFrontendUrl = new URL('../../apps/desktop/src/App.vue', import.meta.url)

test('project packaging and deep validation live in one task-based workspace', async () => {
  const source = await readFile(controlFrontendUrl, 'utf8')
  const sharedProjectPage = source.indexOf(
    `<section v-show="activeSection === 'configuration' || activeSection === 'delivery'"`,
  )
  const nativePage = source.indexOf(`<section v-show="activeSection === 'native'"`)
  const securityPage = source.indexOf(`<section v-show="activeSection === 'security'"`)

  assert.match(source, /type ConsoleSection =[^\n]+'delivery'/)
  assert.match(source, /id: 'delivery', label: '项目交付', description: '项目包与深度自检'/)
  assert.match(source, /class="module-delivery"[^>]+activeSection = 'delivery'/)
  assert.ok(sharedProjectPage >= 0 && nativePage > sharedProjectPage)
  assert.ok(securityPage > nativePage)

  const projectWorkspace = source.slice(sharedProjectPage, nativePage)
  assert.match(projectWorkspace, /id="delivery-title">项目交付/)
  assert.match(projectWorkspace, /class="delivery-steps" aria-label="项目交付步骤"/)
  assert.ok(
    projectWorkspace.indexOf('源机导出交付草稿') < projectWorkspace.indexOf('目标机导入已签项目包'),
  )
  assert.ok(
    projectWorkspace.indexOf('目标机导入已签项目包') < projectWorkspace.indexOf('目标机完成深度验证'),
  )
  assert.match(projectWorkspace, /v-show="activeSection === 'delivery'" class="project-bundle-panel"/)
  assert.match(projectWorkspace, /v-show="activeSection === 'delivery'" v-if="deploymentCheck"/)
  assert.match(projectWorkspace, /导出项目包草稿/)
  assert.match(projectWorkspace, /选择已签项目包并预检/)
  assert.match(projectWorkspace, /deploymentCheck\?\.deepAvailable === false/)
  assert.match(projectWorkspace, /@click="runDeploymentCheck">/)
  assert.match(projectWorkspace, /@click="exportDeploymentCheck">导出深度自检记录/)

  const securityWorkspace = source.slice(securityPage)
  assert.doesNotMatch(securityWorkspace, /@click="runDeploymentCheck"/)
  assert.doesNotMatch(securityWorkspace, /@click="exportDeploymentCheck"/)
  assert.match(securityWorkspace, /@click="openDiagnosticsDirectory">打开日志目录/)
  assert.match(securityWorkspace, /@click="exportDiagnostics">导出脱敏诊断包/)
})
