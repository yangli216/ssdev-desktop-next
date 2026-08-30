import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const appVue = new URL('../../apps/desktop/src/App.vue', import.meta.url)
const desktopRust = new URL('../../apps/desktop/src-tauri/src/desktop.rs', import.meta.url)
const desktopLib = new URL('../../apps/desktop/src-tauri/src/lib.rs', import.meta.url)
const deploymentCheck = new URL('../../apps/desktop/src-tauri/src/deployment_check.rs', import.meta.url)
const diagnostics = new URL('../../crates/ssdev-diagnostics/src/lib.rs', import.meta.url)

function sourceBetween(source, startText, endText) {
  const start = source.indexOf(startText)
  const end = source.indexOf(endText, start + 1)
  assert.notEqual(start, -1, `${startText} must exist`)
  assert.notEqual(end, -1, `${endText} must follow ${startText}`)
  return source.slice(start, end)
}

test('managed process selection drift is a restart-bound runtime boundary', async () => {
  const [app, desktop, lib, check, diagnostic] = await Promise.all([
    readFile(appVue, 'utf8'),
    readFile(desktopRust, 'utf8'),
    readFile(desktopLib, 'utf8'),
    readFile(deploymentCheck, 'utf8'),
    readFile(diagnostics, 'utf8'),
  ])

  const openBusiness = sourceBetween(desktop, 'pub(crate) fn open_business_at', '#[derive(Debug, Deserialize)]')
  const invokePlugin = sourceBetween(lib, 'async fn plugin_invoke(', '#[tauri::command]\nasync fn plugin_invoke_tracked')
  const invokeTracked = sourceBetween(lib, 'async fn plugin_invoke_tracked(', '#[tauri::command]\nasync fn plugin_invocation_status')
  const operationStatus = sourceBetween(lib, 'async fn plugin_invocation_status(', '#[derive(Serialize)]\n#[serde(rename_all = "camelCase")]\nstruct SystemDeclaration')

  assert.match(desktop, /started_managed_processes: BTreeSet<String>/)
  assert.match(desktop, /managed_process_restart_required[\s\S]+BTreeSet<_>>\(\)[\s\S]+started_managed_processes/)
  assert.match(desktop, /managed-process-restart-required/)
  assert.match(openBusiness, /require_current_managed_processes\(\)\?/)
  assert.match(invokePlugin, /require_current_managed_processes\(\)\?/)
  assert.match(invokeTracked, /require_current_managed_processes\(\)[\s\S]+TrackedInvocationErrorPhase::Runtime/)
  assert.doesNotMatch(operationStatus, /require_current_managed_processes/)

  assert.match(lib, /struct BridgeStatus[\s\S]+managed_process_restart_required: bool/)
  assert.match(diagnostic, /pub managed_process_restart_required: bool/)
  assert.match(check, /if facts\.managed_process_restart_required[\s\S]+"managed-processes"[\s\S]+DeploymentCheckStatus::Fail/)

  assert.match(app, /managedProcessRestartRequired: boolean/)
  assert.match(app, /function requireCurrentManagedProcesses/)
  assert.match(app, /受控辅助进程配置已变更。请退出并重新启动客户端/)
  assert.match(app, /managedProcessRestartRequired \|\| configDraftDirty/)
  assert.match(app, /新业务窗口和新原生调用已暂停/)
})
