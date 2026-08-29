import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const appVue = new URL('../../apps/desktop/src/App.vue', import.meta.url)
const desktopLib = new URL('../../apps/desktop/src-tauri/src/lib.rs', import.meta.url)
const processPolicy = new URL('../../crates/ssdev-process-policy/src/lib.rs', import.meta.url)
const commandPermissions = new URL('../../apps/desktop/src-tauri/src/command_permissions.rs', import.meta.url)

function sourceBetween(source, startText, endText) {
  const start = source.indexOf(startText)
  const end = source.indexOf(endText, start + 1)
  assert.notEqual(start, -1, `${startText} must exist`)
  assert.notEqual(end, -1, `${endText} must follow ${startText}`)
  return source.slice(start, end)
}

test('signed managed process choices are visual but keep launch details native-only', async () => {
  const [app, lib, policy, permissions] = await Promise.all([
    readFile(appVue, 'utf8'),
    readFile(desktopLib, 'utf8'),
    readFile(processPolicy, 'utf8'),
    readFile(commandPermissions, 'utf8'),
  ])
  const publicSummary = sourceBetween(policy, 'pub struct ProcessPolicyEntrySummary', '#[derive(Debug, Clone, PartialEq, Eq)]\npub struct LaunchFailure')
  const bridgeEntry = sourceBetween(lib, 'struct ManagedProcessCatalogEntry', 'struct ManagedProcessStartup')
  const bridgeStatus = sourceBetween(lib, 'struct BridgeStatus', 'struct BridgePluginHostHealth')
  const businessPermissions = sourceBetween(permissions, 'pub const BUSINESS_PERMISSIONS', 'pub const FLOATING_PERMISSIONS')

  assert.match(publicSummary, /pub id: String/)
  assert.match(publicSummary, /pub singleton: bool/)
  assert.doesNotMatch(publicSummary, /executable|arguments|working_directory|sha256/)
  assert.match(policy, /entries\.sort_by\(\|left, right\| left\.id\.cmp\(&right\.id\)\)/)
  assert.match(bridgeEntry, /id: String[\s\S]+singleton: bool/)
  assert.doesNotMatch(bridgeEntry, /executable|arguments|working_directory|sha256/)
  assert.match(bridgeStatus, /process_policy_error: Option<&'static str>/)
  assert.match(bridgeStatus, /managed_process_catalog: Vec<ManagedProcessCatalogEntry>/)
  assert.match(lib, /process-policy-not-installed/)
  assert.match(lib, /process-policy-invalid/)
  assert.doesNotMatch(businessPermissions, /allow-bridge-status/)

  assert.match(app, /managedProcessCatalog: Array/)
  assert.match(app, /const managedProcessOptions = computed/)
  assert.match(app, /\.filter\(\(id\) => !known\.has\(id\)\)/)
  assert.match(app, /v-model="snapshot\.config\.managedProcesses"/)
  assert.match(app, /当前签名策略中不存在；取消后不能重新选择/)
  assert.match(app, /不展示程序路径或启动参数/)
  assert.match(app, /保存后客户端会暂停新业务和原生调用，直到完成重启/)
})
