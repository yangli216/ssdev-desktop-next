import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const appVue = new URL('../../apps/desktop/src/App.vue', import.meta.url)
const desktopRust = new URL('../../apps/desktop/src-tauri/src/lib.rs', import.meta.url)
const deploymentRust = new URL('../../apps/desktop/src-tauri/src/deployment_check.rs', import.meta.url)

function sourceBetween(source, startText, endText) {
  const start = source.indexOf(startText)
  const end = source.indexOf(endText, start + 1)
  assert.notEqual(start, -1, `${startText} must exist`)
  assert.notEqual(end, -1, `${endText} must follow ${startText}`)
  return source.slice(start, end)
}

test('an unavailable durable ledger degrades tracked calls without killing the desktop', async () => {
  const [app, desktop, deployment] = await Promise.all([
    readFile(appVue, 'utf8'),
    readFile(desktopRust, 'utf8'),
    readFile(deploymentRust, 'utf8'),
  ])
  const startup = sourceBetween(
    desktop,
    'match InvocationCoordinator::open(local_data_dir.join("invocation-ledger"))',
    'app.manage(app_update::AppUpdateState::load',
  )
  const bridgeState = sourceBetween(desktop, 'app.manage(BridgeState {', 'StartupStage::DesktopShell.enter()')
  const guidance = sourceBetween(app, 'function trackedInvocationGuidance', 'function shortcutActionDetail')
  const attention = sourceBetween(app, '<section v-if="controlLoadFailed', '</section>\n      </section>')

  assert.match(startup, /Ok\(coordinator\) => \(Some\(Arc::new\(coordinator\)\), None\)/)
  assert.match(startup, /Err\(error\)[\s\S]+\(None, Some\(code\)\)/)
  assert.doesNotMatch(startup, /\?|return Err|panic!|expect\(|unwrap\(/)
  assert.match(bridgeState, /invocation_coordinator,\s+invocation_coordinator_error,/)
  assert.match(desktop, /StartupStage::SetupComplete\.enter\(\)/)
  assert.match(desktop, /tracked_invocations_available: tracked\.is_some\(\)/)
  assert.match(desktop, /tracked_invocations_error: state\.invocation_coordinator_error/)

  for (const code of [
    'operation-ledger-path',
    'operation-ledger-corrupt',
    'operation-ledger-json',
    'operation-ledger-size',
    'operation-ledger-capacity',
    'operation-ledger-scope-capacity',
    'operation-ledger-io',
  ]) {
    assert.match(guidance, new RegExp(`'${code}'`))
  }
  assert.doesNotMatch(guidance, /trackedInvocationsError|diagnosticsLogDir|pluginRoot/)
  assert.match(app, /const trackedInvocationsUnavailable = computed/)
  assert.match(attention, /持久原生操作防重放不可用/)
  assert.match(attention, /activeSection = 'security'/)
  assert.match(app, /trackedInvocationGuidance\(status\.trackedInvocationsError\)/)
  assert.match(deployment, /"tracked-invocations",\s+"持久调用账本",\s+DeploymentCheckStatus::Fail/)
})
