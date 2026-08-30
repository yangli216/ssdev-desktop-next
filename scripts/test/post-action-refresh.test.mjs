import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const appVue = new URL('../../apps/desktop/src/App.vue', import.meta.url)

test('committed control actions are not reported as failed by follow-up reads', async () => {
  const source = await readFile(appVue, 'utf8')

  assert.match(source, /async function runPrimaryThenRefresh\(/)
  assert.match(source, /await action\(\)[\s\S]+const refreshed = await refreshControlState\(fields\)/)
  assert.match(source, /操作已经完成，请勿重复执行，刷新状态后再继续/)
  assert.match(source, /上一项操作已经完成，但部分页面状态尚未重新读取/)
  assert.match(source, /@click="retryControlStateRefresh"/)
  assert.match(source, /controlRefreshMissing\.value = \[\.\.\.new Set\(/)
  assert.match(source, /pendingControlRefreshFields/)
  assert.match(source, /runPrimaryThenRefresh\([\s\S]+invoke<BusinessSurfaceCloseResult>\('save_desktop_config'/)
  assert.match(source, /runPrimaryThenRefresh\([\s\S]+invoke<ProjectBundleImportResult>\('import_project_bundle'/)
  assert.match(source, /runPrimaryThenRefresh\([\s\S]+invoke<PluginInstallResult>\('install_plugin_package'/)
  assert.match(source, /runPrimaryThenRefresh\([\s\S]+invoke\('uninstall_signed_plugin'/)
  assert.match(source, /runPrimaryThenRefresh\([\s\S]+invoke<DeploymentCheckReport>\('run_deployment_check', \{ deep: true \}\)/)
  assert.match(source, /if \(!requireSavedConfig\('启动业务系统'\)\) return/)
})

test('post-action refresh is bounded, field-isolated, and does not expose read errors', async () => {
  const source = await readFile(appVue, 'utf8')

  assert.match(source, /const CONTROL_POST_ACTION_REFRESH_TIMEOUT_MS = 15_000/)
  assert.match(source, /Promise\.all\(targets\.map\(async \(field\) =>/)
  assert.match(source, /if \(field === 'deployment'\) deploymentCheckUnavailable\.value = true/)
  assert.match(source, /if \(field === 'status'\) recordRuntimeStatusEvent\('failure'\)/)
  assert.doesNotMatch(source, /页面状态未完全刷新[^\n]+\$\{reason/)
  assert.match(source, /controlRefreshIncomplete \|\| runtimeStatusStale \|\| mappingWorkspaceUnverified \? 'STATUS UNKNOWN'/)
  assert.match(source, /const controlStateUnverified = computed/)
  assert.match(source, /type="submit" :disabled="busy \|\| controlStateUnverified \|\| Boolean\(projectIdentityError\) \|\| Boolean\(shortcutConfigError\) \|\| !configDraftDirty">保存配置/)
  assert.match(source, /:disabled="busy \|\| projectStateUnverified" @click="confirmPluginPackageInstall"/)
  assert.match(source, /:disabled="busy \|\| projectStateUnverified \|\| projectDeliveryDraftDirty \|\| !appUpdate\?\.available/)
  assert.match(source, /pluginUpdates\.value = null\s+appUpdate\.value = null/)
  assert.match(source, /runPrimaryThenRefresh\([\s\S]+invoke\('retry_plugin_host'/)
})
