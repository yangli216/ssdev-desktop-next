<script setup lang="ts">
import { Channel, invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import { open, save } from '@tauri-apps/plugin-dialog'
import { onMounted, onUnmounted, ref } from 'vue'
import LocalMappingStudio from './LocalMappingStudio.vue'

type BridgeStatus = {
  mode: string
  protocolVersion: number
  pluginHostProtocolVersion: number
  transport: string
  httpGatewayEnabled: boolean
  serviceCount: number
  maxInFlightInvocations: number
  inFlightInvocations: number
  rejectedInvocations: number
  callerDetachments: number
  shutdownRejectedInvocations: number
  executionLaneTimeouts: number
  maintenanceRejectedInvocations: number
  pluginMaintenanceActive: boolean
  globalPluginMaintenanceActive: boolean
  activePluginMaintenances: number
  acceptingPluginInvocations: boolean
  trackedInvocationsAvailable: boolean
  trackedInvocationsAccepting: boolean
  trackedInvocationsError?: string
  trackedRuntimeOperations: number
  trackedPendingOperations: number
  trackedRetainedResults: number
  trackedDurableOperations: number
  trackedPersistenceFailures: number
  activePluginHosts: number
  pluginHostStarts: number
  pluginHostStartFailures: number
  pluginLoadFailures: number
  pluginCount: number
  recoveredPluginTransactions: number
  preflightedPluginHosts: number
  pluginPreflightFailures: number
  pluginTrustMode: string
  trustKeyCount: number
  activeTrustKeyCount: number
  retiredTrustKeyCount: number
  revokedTrustKeyCount: number
  pluginRoot: string
  processPolicyEntries: number
  managedProcessFailures: number
  autoStartEnabled?: boolean
  autoStartError?: string
  appUpdateConfigured: boolean
  appUpdateError?: string
  ssoActive: boolean
  ssoError?: string
  originPolicy: {
    enforced: boolean
    allowConfiguredBusinessOrigins: boolean
    businessOrigins: number
    serviceGrants: number
    methodGrants: number
    navigationOrigins: number
    externalOrigins: number
    allowInsecureHttp: boolean
  }
  originPolicyError?: string
  diagnosticsAvailable: boolean
  diagnosticsError?: string
  diagnosticsLogDir: string
  diagnostics?: {
    logFiles: number
    logBytes: number
    oversizedEvents: number
    writeFailures: number
  }
}

type DeploymentCheckReport = {
  ready: boolean
  passed: number
  warnings: number
  failures: number
  items: Array<{
    id: string
    label: string
    status: 'pass' | 'warning' | 'fail' | 'info'
    summary: string
    action?: string
  }>
}

type ProjectBundlePreview = {
  planId: string
  schemaVersion: number
  createdByVersion: string
  signatureVerified: boolean
  signatureKeyId?: string
  businessOrigins: number
  signedPlugins: number
  localMappings: number
  serviceCount: number
  preflightedHosts: number
  configPreview: ConfigChangePreview
  installCount: number
  upgradeCount: number
  replaceCount: number
  retainedCount: number
  components: Array<{
    pluginId: string
    version?: string
    desktopVersionRequirement?: string
    source: 'signed-package' | 'local-mapping'
    action: 'install' | 'upgrade' | 'reinstall' | 'replace'
    serviceCount: number
  }>
  retainedComponents: Array<{
    pluginId: string
    version?: string
    desktopVersionRequirement?: string
    source: 'signed-package' | 'local-mapping'
    action: 'retain'
    serviceCount: number
  }>
}

type ProjectBundleImportResult = {
  signedPlugins: number
  localMappings: number
  serviceCount: number
  preflightedHosts: number
}

type EnvironmentConfig = {
  name: string
  url: string
  [key: string]: unknown
}

type DesktopConfig = {
  website?: string
  environments: EnvironmentConfig[]
  allowSwitch: boolean
  autoClose: boolean
  autoStart: boolean
  tenantId: string
  processes: string[]
  managedProcesses: string[]
  trustedOrigins: string[]
  externalOrigins: string[]
  pluginCatalogUrl?: string
  pluginCatalogSignatureUrl?: string
  feedback: boolean
  [key: string]: unknown
}

type ConfigSnapshot = {
  config: DesktopConfig
  path: string
  migratedFrom?: string
  migrationSources: string[]
  migrationWarnings: string[]
}

type ConfigChangePreview = {
  configChanged: boolean
  defaultWebsiteChanged: boolean
  tenantChanged: boolean
  allowSwitchChanged: boolean
  autoCloseChanged: boolean
  autoStartChanged: boolean
  pluginCatalogChanged: boolean
  candidateDefaultWebsite?: string
  candidateAllowSwitch: boolean
  candidateAutoClose: boolean
  candidateAutoStart: boolean
  currentEnvironmentCount: number
  candidateEnvironmentCount: number
  candidateEnvironments: EnvironmentConfig[]
  currentBusinessOriginCount: number
  candidateBusinessOriginCount: number
  currentTrustedOriginCount: number
  candidateTrustedOriginCount: number
  currentExternalOriginCount: number
  candidateExternalOriginCount: number
  currentManagedProcessCount: number
  candidateManagedProcessCount: number
  currentEnabledShortcutCount: number
  candidateEnabledShortcutCount: number
}

type ConfigImportPreview = ConfigChangePreview & {
  planId: string
}

type PluginInstallResult = {
  pluginId: string
  pluginVersion: string
  serviceCount: number
  replacedExisting: boolean
  quarantinedPlugins: number
  preflightedHosts: number
}

type PluginInventory = {
  plugins: Array<{
    pluginId: string
    version?: string
    desktopVersionRequirement?: string
    displayName: string
    source: 'signed-package' | 'local-mapping'
    services: Array<{
      serviceId: string
      architecture: 'x86' | 'x64'
      mainType: string
      mainClass: string
      callingConvention: string
      charset: string
      cacheable: boolean
      timeoutMs: number
      dependencyCount: number
      methodCount: number
      methods: Array<{
        requestName: string
        nativeName: string
        returnType: string
        parameterCount: number
        timeoutMs: number
      }>
    }>
  }>
  quarantined: string[]
}

type PluginUpdateCheck = {
  catalogIssuedAt: number
  catalogExpiresAt: number
  updates: Array<{
    pluginId: string
    installedVersion?: string
    availableVersion?: string
    latestCatalogVersion?: string
    installPlanId?: string
    installedVersionWithdrawn: boolean
    withdrawalReason?: 'security' | 'defective' | 'publisher-withdrawn'
    catalogAvailable: boolean
    compatibilityLimited: boolean
    updateAvailable: boolean
  }>
}

type AppUpdateCheck = {
  configured: boolean
  currentVersion: string
  available: boolean
  compatible: boolean
  pluginBlockers: number
  installPlanId?: string
  version?: string
  date?: string
  notes?: string
}

type AppUpdateEvent =
  | { event: 'started'; data: { contentLength?: number; maxDownloadBytes: number } }
  | { event: 'progress'; data: { downloadedBytes: number } }
  | { event: 'verified' }
  | { event: 'installing' }

type SsoStatusEvent = {
  code: string
  active: boolean
}

const status = ref<BridgeStatus | null>(null)
const deploymentCheck = ref<DeploymentCheckReport | null>(null)
const projectBundlePreview = ref<ProjectBundlePreview | null>(null)
const selectedProjectBundle = ref('')
const configImportPreview = ref<ConfigImportPreview | null>(null)
const selectedConfigImport = ref('')
const snapshot = ref<ConfigSnapshot | null>(null)
const inventory = ref<PluginInventory | null>(null)
const catalogPluginId = ref('')
const pluginUpdates = ref<PluginUpdateCheck | null>(null)
const appUpdate = ref<AppUpdateCheck | null>(null)
const updateProgress = ref('')
const error = ref('')
const ssoActive = ref(false)
const ssoError = ref('')
const notice = ref('')
const busy = ref(false)
type ConsoleSection = 'overview' | 'configuration' | 'native' | 'plugins' | 'security'
const activeSection = ref<ConsoleSection>('overview')
const sections: Array<{ id: ConsoleSection; label: string; description: string }> = [
  { id: 'overview', label: '运行概览', description: '状态与常用操作' },
  { id: 'configuration', label: '项目配置', description: '环境、来源与启动项' },
  { id: 'native', label: '原生映射', description: 'DLL / COM 可视化调试' },
  { id: 'plugins', label: '插件管理', description: '安装、签名与更新' },
  { id: 'security', label: '安全与诊断', description: '策略、运行指标与日志' },
]
const projectActionLabels = {
  install: '新增',
  upgrade: '升级',
  reinstall: '同版本修复',
  replace: '替换映射',
  retain: '保留',
} as const
const withdrawalReasonLabels = {
  security: '安全原因',
  defective: '发布缺陷',
  'publisher-withdrawn': '发布方撤回',
} as const
let unlistenSsoStatus: UnlistenFn | undefined
let ssoStatusEventSeen = false

function applySsoStatus(code?: string, active = false) {
  ssoActive.value = active
  if (!code || code === 'sso-login-started' || code === 'sso-login-succeeded') {
    ssoError.value = ''
  } else if (code === 'sso-arguments-invalid') {
    ssoError.value = 'SSO 启动参数无效，已在联网前拒绝。请检查启动器参数是否缺失或重复。'
  } else if (code === 'sso-already-running') {
    ssoError.value = '已有一项 SSO 登录正在处理，新的重复启动已拒绝。'
  } else {
    ssoError.value = 'SSO 登录失败。请检查 HTTPS 地址、院内证书、网络和服务状态。'
  }
}

onMounted(async () => {
  try {
    await invoke('frontend_ready')
    unlistenSsoStatus = await listen<SsoStatusEvent>('desktop://sso-status', (event) => {
      ssoStatusEventSeen = true
      applySsoStatus(event.payload.code, event.payload.active)
    })
    const deploymentPromise = invoke<DeploymentCheckReport>('run_deployment_check').catch((reason) => {
      error.value = `部署自检不可用：${reason instanceof Error ? reason.message : String(reason)}`
      return null
    })
    const [bridge, config, plugins, deployment] = await Promise.all([
      invoke<BridgeStatus>('bridge_status'),
      invoke<ConfigSnapshot>('desktop_config'),
      invoke<PluginInventory>('plugin_inventory'),
      deploymentPromise,
    ])
    status.value = bridge
    snapshot.value = config
    inventory.value = plugins
    deploymentCheck.value = deployment
    if (!ssoStatusEventSeen) applySsoStatus(bridge.ssoError, bridge.ssoActive)
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : String(reason)
  }
})

onUnmounted(() => unlistenSsoStatus?.())

async function run(action: () => Promise<unknown>, success: string) {
  busy.value = true
  error.value = ''
  notice.value = ''
  try {
    await action()
    notice.value = success
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : String(reason)
  } finally {
    busy.value = false
  }
}

async function saveConfig() {
  if (!snapshot.value) return
  await run(
    async () => {
      await invoke('save_desktop_config', { config: snapshot.value?.config })
      deploymentCheck.value = await invoke<DeploymentCheckReport>('run_deployment_check')
      configImportPreview.value = null
      selectedConfigImport.value = ''
    },
    '配置已安全保存；已有业务窗口已关闭，请重新进入。',
  )
}

async function importConfig() {
  const source = await open({
    multiple: false,
    directory: false,
    filters: [{ name: 'SSDEV 桌面配置', extensions: ['json'] }],
  })
  if (typeof source !== 'string') return
  await run(async () => {
    configImportPreview.value = null
    selectedConfigImport.value = ''
    configImportPreview.value = await invoke<ConfigImportPreview>('inspect_desktop_config_import', { source })
    selectedConfigImport.value = source
  }, '配置预检已完成；计划已绑定导入文件和当前已保存配置，请核对后确认。')
}

async function confirmConfigImport() {
  if (!selectedConfigImport.value || !configImportPreview.value) {
    error.value = '请先选择并预检桌面配置。'
    return
  }
  const source = selectedConfigImport.value
  const expectedPlanId = configImportPreview.value.planId
  const changed = configImportPreview.value.configChanged
  await run(async () => {
    snapshot.value = await invoke<ConfigSnapshot>('import_desktop_config', {
      source,
      expectedPlanId,
    })
    deploymentCheck.value = await invoke<DeploymentCheckReport>('run_deployment_check')
    configImportPreview.value = null
    selectedConfigImport.value = ''
  }, changed ? '配置已按确认计划导入；已有业务窗口已关闭。' : '导入配置与当前配置一致，未执行替换。')
}

function cancelConfigImport() {
  configImportPreview.value = null
  selectedConfigImport.value = ''
  notice.value = '已取消配置导入。'
}

async function exportConfig() {
  const destination = await save({
    defaultPath: 'ssdev-desktop-config.json',
    filters: [{ name: 'SSDEV 桌面配置', extensions: ['json'] }],
  })
  if (typeof destination !== 'string') return
  await run(
    () => invoke('export_desktop_config', { destination }),
    '当前有效配置已原子导出。',
  )
}

async function exportProjectBundle() {
  const destination = await save({
    defaultPath: 'ssdev-project.ssdev-project',
    filters: [{ name: 'SSDEV 项目部署包', extensions: ['ssdev-project'] }],
  })
  if (typeof destination !== 'string') return
  let result: { bytes: number; bundleSha256: string; signedPlugins: number; localMappings: number; serviceCount: number; preflightedHosts: number } | undefined
  await run(async () => {
    result = await invoke<{ bytes: number; bundleSha256: string; signedPlugins: number; localMappings: number; serviceCount: number; preflightedHosts: number }>('export_project_bundle', { destination })
  }, '')
  if (result) {
    notice.value = `项目部署包草稿已导出（${(result.bytes / 1024 / 1024).toFixed(1)} MiB）：${result.signedPlugins} 个签名插件，${result.localMappings} 个本地映射，共 ${result.serviceCount} 个原生服务；${result.preflightedHosts} 个架构宿主已按封装候选预检。SHA-256：${result.bundleSha256}。正式交付前请核对签名请求中的同一摘要，并使用组织签名工具生成同目录旁签文件。`
  }
}

async function inspectProjectBundle() {
  const source = await open({
    multiple: false,
    directory: false,
    filters: [{ name: 'SSDEV 项目部署包', extensions: ['ssdev-project'] }],
  })
  if (typeof source !== 'string') return
  await run(async () => {
    projectBundlePreview.value = null
    selectedProjectBundle.value = ''
    projectBundlePreview.value = await invoke<ProjectBundlePreview>('inspect_project_bundle', { source })
    selectedProjectBundle.value = source
  }, '项目包预检已完成；导入计划已绑定项目包和当前机器状态，请核对变更后确认。')
}

async function importSelectedProjectBundle() {
  if (!selectedProjectBundle.value || !projectBundlePreview.value) {
    error.value = '请先选择并预检项目部署包。'
    return
  }
  const source = selectedProjectBundle.value
  const expectedPlanId = projectBundlePreview.value.planId
  let result: ProjectBundleImportResult | undefined
  await run(async () => {
    result = await invoke<ProjectBundleImportResult>('import_project_bundle', {
      source,
      expectedPlanId,
    })
    ;[status.value, snapshot.value, inventory.value, deploymentCheck.value] = await Promise.all([
      invoke<BridgeStatus>('bridge_status'),
      invoke<ConfigSnapshot>('desktop_config'),
      invoke<PluginInventory>('plugin_inventory'),
      invoke<DeploymentCheckReport>('run_deployment_check'),
    ])
    selectedProjectBundle.value = ''
    projectBundlePreview.value = null
    selectedConfigImport.value = ''
    configImportPreview.value = null
  }, '')
  if (result) {
    notice.value = `项目已导入：${result.signedPlugins} 个签名插件、${result.localMappings} 个本地映射、${result.serviceCount} 个原生服务；已有业务窗口已关闭。`
  }
}

async function openBusiness() {
  await run(() => invoke('open_business_window'), '业务窗口已启动。')
}

async function openEnvironment(environment: EnvironmentConfig) {
  if (!snapshot.value) return
  await run(async () => {
    await invoke('save_desktop_config', { config: snapshot.value?.config })
    selectedConfigImport.value = ''
    configImportPreview.value = null
    await invoke('open_business_window', { environment: environment.name })
  }, `已保存配置并打开环境「${environment.name}」。`)
}

function addEnvironment() {
  snapshot.value?.config.environments.push({ name: '', url: '' })
}

function removeEnvironment(index: number) {
  if (!snapshot.value) return
  const [removed] = snapshot.value.config.environments.splice(index, 1)
  if (removed && snapshot.value.config.website === removed.url) {
    snapshot.value.config.website = snapshot.value.config.environments[0]?.url
  }
}

function changeEnvironmentUrl(environment: EnvironmentConfig, value: string) {
  if (!snapshot.value) return
  const previous = environment.url
  environment.url = value
  if (snapshot.value.config.website === previous) {
    snapshot.value.config.website = value
  }
}

async function clearBusinessData() {
  await run(() => invoke('clear_business_data'), '业务窗口缓存与站点数据已清理。')
}

async function reloadBusiness() {
  await run(() => invoke('reload_business_windows'), '业务窗口已刷新。')
}

async function installPlugin() {
  const selected = await open({
    multiple: false,
    directory: false,
    filters: [{ name: 'SSDEV 签名插件包', extensions: ['ssdev-plugin', 'zip'] }],
  })
  if (typeof selected !== 'string') return

  let result: PluginInstallResult | undefined
  await run(async () => {
    result = await invoke<PluginInstallResult>('install_plugin_package', { packagePath: selected })
    ;[status.value, inventory.value, deploymentCheck.value] = await Promise.all([
      invoke<BridgeStatus>('bridge_status'),
      invoke<PluginInventory>('plugin_inventory'),
      invoke<DeploymentCheckReport>('run_deployment_check'),
    ])
  }, '')

  if (result) {
    const action = result.replacedExisting ? '升级' : '安装'
    notice.value = `${result.pluginId} ${result.pluginVersion} 已${action}，${result.preflightedHosts} 个架构宿主预检通过，当前共 ${result.serviceCount} 个服务已热加载。`
  }
}

async function uninstallSignedPlugin(pluginId: string, displayName: string) {
  if (!window.confirm(`确定卸载签名插件「${displayName}」(${pluginId}) 吗？对应原生服务将立即停止。`)) return
  await run(async () => {
    await invoke('uninstall_signed_plugin', { pluginId })
    pluginUpdates.value = null
    ;[status.value, inventory.value, deploymentCheck.value] = await Promise.all([
      invoke<BridgeStatus>('bridge_status'),
      invoke<PluginInventory>('plugin_inventory'),
      invoke<DeploymentCheckReport>('run_deployment_check'),
    ])
  }, `签名插件 ${pluginId} 已卸载并从路由移除。`)
}

async function reloadPlugins() {
  await run(async () => {
    await invoke('reload_plugins')
    ;[status.value, inventory.value, deploymentCheck.value] = await Promise.all([
      invoke<BridgeStatus>('bridge_status'),
      invoke<PluginInventory>('plugin_inventory'),
      invoke<DeploymentCheckReport>('run_deployment_check'),
    ])
  }, '插件目录已重新验签，候选宿主预检通过并热加载。')
}

async function refreshPluginsAfterMapping() {
  try {
    ;[status.value, inventory.value, deploymentCheck.value] = await Promise.all([
      invoke<BridgeStatus>('bridge_status'),
      invoke<PluginInventory>('plugin_inventory'),
      invoke<DeploymentCheckReport>('run_deployment_check'),
    ])
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : String(reason)
  }
}

async function checkPluginUpdates(requestedPluginId?: string) {
  const pluginId = requestedPluginId?.trim()
  if (requestedPluginId !== undefined && !pluginId) {
    error.value = '请先填写要查询的插件 ID。'
    return
  }
  let result: PluginUpdateCheck | undefined
  await run(async () => {
    result = await invoke<PluginUpdateCheck>('check_plugin_updates', {
      pluginId: pluginId || null,
    })
    pluginUpdates.value = result
  }, '')
  if (!result) return
  const available = result.updates.filter((item) => item.updateAvailable)
  const withdrawn = result.updates.filter((item) => item.installedVersionWithdrawn)
  if (result.updates.length === 0) {
    notice.value = '当前没有已安装插件可检查。'
  } else if (withdrawn.length > 0) {
    notice.value = `发现 ${withdrawn.length} 个已安装插件版本已被签名仓库撤回，请优先升级或卸载。`
  } else if (available.length === 0) {
    notice.value = '签名仓库中未发现可安装的新版本。'
  } else {
    notice.value = `发现 ${available.length} 个可安装的插件版本，请确认目标版本后安装。`
  }
}

async function installFromCatalog(pluginId: string, version?: string, installPlanId?: string) {
  if (!pluginId.trim() || !version || !installPlanId) {
    error.value = '请先检查仓库并选择明确的插件版本。'
    return
  }
  let result: PluginInstallResult | undefined
  await run(async () => {
    result = await invoke<PluginInstallResult>('install_plugin_from_catalog', {
      pluginId,
      version,
      expectedPlanId: installPlanId,
    })
    ;[status.value, inventory.value, pluginUpdates.value, deploymentCheck.value] = await Promise.all([
      invoke<BridgeStatus>('bridge_status'),
      invoke<PluginInventory>('plugin_inventory'),
      invoke<PluginUpdateCheck>('check_plugin_updates', { pluginId }),
      invoke<DeploymentCheckReport>('run_deployment_check'),
    ])
  }, '')
  if (result) {
    const action = result.replacedExisting ? '更新' : '安装'
    notice.value = `${result.pluginId} ${result.pluginVersion} 已从签名仓库${action}，${result.preflightedHosts} 个架构宿主预检通过并热加载。`
  }
}

async function checkAppUpdate() {
  let result: AppUpdateCheck | undefined
  appUpdate.value = null
  updateProgress.value = ''
  await run(async () => {
    result = await invoke<AppUpdateCheck>('check_app_update')
    appUpdate.value = result
  }, '')
  if (!result) return
  if (!result.configured) {
    notice.value = '当前构建未配置生产更新端点与公钥。'
  } else if (result.available && !result.compatible) {
    notice.value = `发现签名更新 ${result.version}，但有 ${result.pluginBlockers} 个插件未声明兼容或未通过完整性检查。`
  } else if (result.available) {
    notice.value = `发现签名更新 ${result.version}，安装前可以查看发布说明。`
  } else {
    notice.value = `当前 ${result.currentVersion} 已是最新版本。`
  }
}

async function installAppUpdate() {
  if (!appUpdate.value?.available || !appUpdate.value.compatible || !appUpdate.value.installPlanId) {
    error.value = appUpdate.value?.available
      ? appUpdate.value.compatible
        ? '应用更新确认状态已失效，请重新检查更新。'
        : '当前插件集合与目标 Desktop 版本不兼容，请先安装兼容插件版本。'
      : '请先检查并确认存在可用更新。'
    return
  }
  const expectedPlanId = appUpdate.value.installPlanId
  const onEvent = new Channel<AppUpdateEvent>()
  onEvent.onmessage = (event) => {
    if (event.event === 'started') {
      const total = event.data.contentLength
      updateProgress.value = total ? `开始下载，共 ${(total / 1024 / 1024).toFixed(1)} MiB` : '开始下载更新包'
    } else if (event.event === 'progress') {
      updateProgress.value = `已下载 ${(event.data.downloadedBytes / 1024 / 1024).toFixed(1)} MiB`
    } else if (event.event === 'verified') {
      updateProgress.value = '更新包签名已验证'
    } else {
      updateProgress.value = '正在启动系统安装程序…'
    }
  }
  await run(
    () => invoke('install_app_update', { expectedPlanId, onEvent }),
    '更新已安装，客户端即将重新启动。',
  )
}

async function exportDiagnostics() {
  const destination = await save({
    defaultPath: `ssdev-diagnostics-${new Date().toISOString().slice(0, 10)}.zip`,
    filters: [{ name: 'SSDEV 诊断包', extensions: ['zip'] }],
  })
  if (typeof destination !== 'string') return
  let result: { bytes: number } | undefined
  await run(async () => {
    result = await invoke<{ bytes: number }>('export_diagnostics', { destination })
  }, '')
  if (result) {
    notice.value = `诊断包已导出（${(result.bytes / 1024).toFixed(1)} KiB）；不包含业务参数、响应、SSO 参数或业务地址。`
  }
}

async function openDiagnosticsDirectory() {
  await run(
    () => invoke('open_diagnostics_directory'),
    '已使用系统文件管理器打开诊断日志目录。',
  )
}

async function runDeploymentCheck() {
  let result: DeploymentCheckReport | undefined
  await run(async () => {
    result = await invoke<DeploymentCheckReport>('run_deployment_check')
    deploymentCheck.value = result
  }, '')
  if (result) {
    notice.value = result.ready
      ? `部署自检通过：${result.passed} 项正常，${result.warnings} 项提醒。`
      : `部署自检发现 ${result.failures} 项阻塞问题，请按建议处理后重新检查。`
  }
}
</script>

<template>
  <div class="app-shell">
    <aside class="sidebar">
      <div class="brand">
        <span class="brand-mark">S</span>
        <span><strong>SSDEV</strong><small>Desktop Next</small></span>
      </div>
      <nav aria-label="控制台导航">
        <button
          v-for="(section, index) in sections"
          :key="section.id"
          type="button"
          :class="{ active: activeSection === section.id }"
          :aria-current="activeSection === section.id ? 'page' : undefined"
          @click="activeSection = section.id"
        >
          <span class="nav-index">0{{ index + 1 }}</span>
          <span><strong>{{ section.label }}</strong><small>{{ section.description }}</small></span>
          <i v-if="section.id === 'plugins' && inventory?.quarantined.length" class="nav-alert">{{ inventory.quarantined.length }}</i>
        </button>
      </nav>
      <div class="sidebar-status">
        <span :class="['status-dot', { ready: Boolean(status), warning: Boolean(error || ssoError) }]" />
        <span><strong>{{ error || ssoError ? '需要处理' : status ? '桌面服务正常' : '正在连接' }}</strong><small>{{ status?.serviceCount ?? '—' }} 个原生服务可用</small></span>
      </div>
    </aside>

    <main class="workspace">
      <div v-if="notice || ssoError || error" class="message-stack" aria-live="polite">
        <p v-if="notice" class="notice" role="status">{{ notice }}</p>
        <p v-if="ssoError" class="error" role="alert">{{ ssoError }}</p>
        <p v-if="error" class="error" role="alert">操作失败：{{ error }}</p>
      </div>

      <section v-show="activeSection === 'overview'" class="page page-overview" aria-labelledby="overview-title">
        <header class="page-hero">
          <div>
            <p class="eyebrow">WORKSPACE OVERVIEW</p>
            <h1 id="overview-title">本地能力控制台</h1>
            <p class="lede">集中查看运行状态，并快速进入当前项目或专业配置工作区。</p>
          </div>
          <span class="phase">{{ status?.acceptingPluginInvocations ? '服务就绪' : '正在初始化' }}</span>
        </header>

        <section class="summary-grid" aria-label="关键运行状态">
          <article><span>桌面通信</span><strong>{{ status?.transport ?? '连接中' }}</strong><small>不开放 localhost 端口</small></article>
          <article><span>原生服务</span><strong>{{ status?.serviceCount ?? '—' }}</strong><small>{{ status?.pluginCount ?? '—' }} 个插件 · x86 / x64 隔离</small></article>
          <article><span>当前调用</span><strong>{{ status ? `${status.inFlightInvocations} / ${status.maxInFlightInvocations}` : '—' }}</strong><small>{{ status?.acceptingPluginInvocations ? '正在接受新调用' : '暂不接受新调用' }}</small></article>
          <article><span>部署状态</span><strong>{{ deploymentCheck ? deploymentCheck.ready ? '可以交付' : '需要处理' : '检查中' }}</strong><small>{{ deploymentCheck ? `${deploymentCheck.failures} 项阻塞 · ${deploymentCheck.warnings} 项提醒` : '正在执行环境自检' }}</small></article>
        </section>

        <div class="overview-layout">
          <section class="launch-panel">
            <div>
              <p class="eyebrow">QUICK START</p>
              <h2>进入业务系统</h2>
              <p>{{ snapshot?.config.website || '尚未配置默认业务地址' }}</p>
            </div>
            <button class="primary large" type="button" :disabled="busy || !snapshot?.config.website" @click="openBusiness">启动默认环境</button>
            <div v-if="snapshot?.config.allowSwitch && snapshot.config.environments.length" class="environment-shortcuts">
              <button
                v-for="environment in snapshot.config.environments"
                :key="`${environment.name}:${environment.url}`"
                type="button"
                :disabled="busy || !environment.name || !environment.url"
                @click="openEnvironment(environment)"
              >{{ environment.name || '未命名环境' }}</button>
            </div>
          </section>

          <section class="module-panel" aria-label="能力工作区">
            <header><div><p class="eyebrow">CAPABILITIES</p><h2>能力工作区</h2></div><small>按任务进入，避免在首页堆叠低频配置。</small></header>
            <div class="module-grid">
              <button type="button" @click="activeSection = 'configuration'"><span>项目配置</span><small>{{ snapshot?.config.environments.length ?? 0 }} 个业务环境</small><b>→</b></button>
              <button type="button" @click="activeSection = 'native'"><span>原生映射</span><small>DLL / COM 配置与调试</small><b>→</b></button>
              <button type="button" @click="activeSection = 'plugins'"><span>插件管理</span><small>{{ inventory?.plugins.length ?? 0 }} 个已验证插件</small><b>→</b></button>
              <button type="button" @click="activeSection = 'security'"><span>安全与诊断</span><small>策略、日志和应用维护</small><b>→</b></button>
            </div>
          </section>
        </div>

        <section v-if="deploymentCheck?.failures || status?.pluginPreflightFailures || inventory?.quarantined.length || ssoError" class="attention-panel">
          <div><p class="eyebrow">ATTENTION</p><h2>待处理事项</h2></div>
          <ul>
            <li v-if="deploymentCheck?.failures"><strong>部署自检存在 {{ deploymentCheck.failures }} 项阻塞问题</strong><button type="button" @click="activeSection = 'security'">查看自检</button></li>
            <li v-if="inventory?.quarantined.length"><strong>{{ inventory.quarantined.length }} 个插件已隔离</strong><button type="button" @click="activeSection = 'plugins'">查看插件</button></li>
            <li v-if="status?.pluginPreflightFailures"><strong>{{ status.pluginPreflightFailures }} 次宿主预检失败</strong><button type="button" @click="activeSection = 'security'">查看诊断</button></li>
            <li v-if="ssoError"><strong>最近一次 SSO 登录失败</strong><button type="button" @click="activeSection = 'security'">查看详情</button></li>
          </ul>
        </section>
      </section>

      <section v-show="activeSection === 'configuration'" class="page" aria-labelledby="configuration-title">
        <header class="section-header"><div><p class="eyebrow">PROJECT CONFIGURATION</p><h1 id="configuration-title">项目配置</h1><p>管理业务环境、来源边界和桌面启动行为。</p></div><div class="header-actions"><button type="button" :disabled="busy" @click="importConfig">导入配置</button><button type="button" :disabled="busy" @click="exportConfig">导出配置</button></div></header>
        <section v-if="configImportPreview" class="config-import-preview" aria-label="配置导入变更预览">
          <header>
            <div><p class="eyebrow">CONFIG IMPORT PLAN</p><h2>{{ configImportPreview.configChanged ? '核对配置变更' : '配置内容没有变化' }}</h2><p>确认时会重新读取文件并核对当前已保存配置；任一变化都会要求重新预检。</p></div>
            <div class="config-import-actions"><button type="button" :disabled="busy" @click="cancelConfigImport">取消</button><button class="primary" type="button" :disabled="busy" @click="confirmConfigImport">{{ configImportPreview.configChanged ? '确认并应用配置' : '确认无须替换' }}</button></div>
          </header>
          <div class="config-import-target"><span>目标默认入口</span><strong>{{ configImportPreview.candidateDefaultWebsite || '未配置' }}</strong></div>
          <div class="config-import-counts">
            <span><small>业务环境</small><strong>{{ configImportPreview.currentEnvironmentCount }} → {{ configImportPreview.candidateEnvironmentCount }}</strong></span>
            <span><small>业务来源</small><strong>{{ configImportPreview.currentBusinessOriginCount }} → {{ configImportPreview.candidateBusinessOriginCount }}</strong></span>
            <span><small>SSO 来源</small><strong>{{ configImportPreview.currentTrustedOriginCount }} → {{ configImportPreview.candidateTrustedOriginCount }}</strong></span>
            <span><small>外链来源</small><strong>{{ configImportPreview.currentExternalOriginCount }} → {{ configImportPreview.candidateExternalOriginCount }}</strong></span>
            <span><small>受控进程</small><strong>{{ configImportPreview.currentManagedProcessCount }} → {{ configImportPreview.candidateManagedProcessCount }}</strong></span>
            <span><small>启用快捷键</small><strong>{{ configImportPreview.currentEnabledShortcutCount }} → {{ configImportPreview.candidateEnabledShortcutCount }}</strong></span>
          </div>
          <div class="project-change-summary">
            <span :class="{ changed: configImportPreview.defaultWebsiteChanged }">默认入口{{ configImportPreview.defaultWebsiteChanged ? '变更' : '不变' }}</span>
            <span :class="{ changed: configImportPreview.tenantChanged }">租户{{ configImportPreview.tenantChanged ? '变更' : '不变' }}</span>
            <span :class="{ changed: configImportPreview.allowSwitchChanged }">环境切换：{{ configImportPreview.candidateAllowSwitch ? '启用' : '关闭' }}</span>
            <span :class="{ changed: configImportPreview.autoCloseChanged }">关闭确认：{{ configImportPreview.candidateAutoClose ? '启用' : '关闭' }}</span>
            <span :class="{ changed: configImportPreview.autoStartChanged }">开机启动：{{ configImportPreview.candidateAutoStart ? '启用' : '关闭' }}</span>
            <span :class="{ changed: configImportPreview.pluginCatalogChanged }">插件仓库{{ configImportPreview.pluginCatalogChanged ? '变更' : '不变' }}</span>
          </div>
          <details v-if="configImportPreview.candidateEnvironments.length" class="config-import-environments"><summary>查看目标业务环境（{{ configImportPreview.candidateEnvironments.length }}）</summary><ul><li v-for="environment in configImportPreview.candidateEnvironments" :key="`${environment.name}:${environment.url}`"><strong>{{ environment.name }}</strong><code>{{ environment.url }}</code></li></ul></details>
        </section>
        <section class="project-bundle-panel">
          <div class="project-bundle-copy"><p class="eyebrow">PROJECT DELIVERY</p><h2>项目部署包</h2><p>将当前配置、签名插件和本地映射作为一个交付单元迁移到目标 Windows 机器；正式导入要求同目录组织签名旁签。</p></div>
          <div class="project-bundle-actions"><button type="button" :disabled="busy" @click="exportProjectBundle">导出当前项目</button><button class="primary" type="button" :disabled="busy" @click="inspectProjectBundle">选择项目包并预检</button></div>
          <div v-if="projectBundlePreview" class="project-bundle-preview">
            <header><div><strong>变更计划已验证，可以导入</strong><small>由客户端 {{ projectBundlePreview.createdByVersion }} 创建 · schema {{ projectBundlePreview.schemaVersion }} · {{ projectBundlePreview.signatureVerified ? `组织签名 ${projectBundlePreview.signatureKeyId}` : '调试态未签名' }}</small></div><button class="primary" type="button" :disabled="busy" @click="importSelectedProjectBundle">确认计划并切换项目</button></header>
            <div class="bundle-summary"><span><strong>{{ projectBundlePreview.businessOrigins }}</strong>业务来源</span><span><strong>{{ projectBundlePreview.signedPlugins }}</strong>签名插件</span><span><strong>{{ projectBundlePreview.localMappings }}</strong>本地映射</span><span><strong>{{ projectBundlePreview.serviceCount }}</strong>原生服务</span><span><strong>{{ projectBundlePreview.preflightedHosts }}</strong>宿主预检</span></div>
            <div class="project-change-summary"><span :class="{ changed: projectBundlePreview.configPreview.configChanged }">配置{{ projectBundlePreview.configPreview.configChanged ? '更新' : '不变' }}</span><span>新增 {{ projectBundlePreview.installCount }}</span><span>升级 {{ projectBundlePreview.upgradeCount }}</span><span>修复/替换 {{ projectBundlePreview.replaceCount }}</span><span>保留本机 {{ projectBundlePreview.retainedCount }}</span></div>
            <h3>目标项目配置</h3>
            <div class="config-import-target"><span>默认业务入口</span><strong>{{ projectBundlePreview.configPreview.candidateDefaultWebsite || '未配置' }}</strong></div>
            <div class="config-import-counts">
              <span><small>业务环境</small><strong>{{ projectBundlePreview.configPreview.currentEnvironmentCount }} → {{ projectBundlePreview.configPreview.candidateEnvironmentCount }}</strong></span>
              <span><small>业务来源</small><strong>{{ projectBundlePreview.configPreview.currentBusinessOriginCount }} → {{ projectBundlePreview.configPreview.candidateBusinessOriginCount }}</strong></span>
              <span><small>SSO 来源</small><strong>{{ projectBundlePreview.configPreview.currentTrustedOriginCount }} → {{ projectBundlePreview.configPreview.candidateTrustedOriginCount }}</strong></span>
              <span><small>外链来源</small><strong>{{ projectBundlePreview.configPreview.currentExternalOriginCount }} → {{ projectBundlePreview.configPreview.candidateExternalOriginCount }}</strong></span>
              <span><small>受控进程</small><strong>{{ projectBundlePreview.configPreview.currentManagedProcessCount }} → {{ projectBundlePreview.configPreview.candidateManagedProcessCount }}</strong></span>
              <span><small>启用快捷键</small><strong>{{ projectBundlePreview.configPreview.currentEnabledShortcutCount }} → {{ projectBundlePreview.configPreview.candidateEnabledShortcutCount }}</strong></span>
            </div>
            <div class="project-change-summary">
              <span :class="{ changed: projectBundlePreview.configPreview.defaultWebsiteChanged }">默认入口{{ projectBundlePreview.configPreview.defaultWebsiteChanged ? '变更' : '不变' }}</span>
              <span :class="{ changed: projectBundlePreview.configPreview.tenantChanged }">租户{{ projectBundlePreview.configPreview.tenantChanged ? '变更' : '不变' }}</span>
              <span :class="{ changed: projectBundlePreview.configPreview.allowSwitchChanged }">环境切换：{{ projectBundlePreview.configPreview.candidateAllowSwitch ? '启用' : '关闭' }}</span>
              <span :class="{ changed: projectBundlePreview.configPreview.autoCloseChanged }">关闭确认：{{ projectBundlePreview.configPreview.candidateAutoClose ? '启用' : '关闭' }}</span>
              <span :class="{ changed: projectBundlePreview.configPreview.autoStartChanged }">开机启动：{{ projectBundlePreview.configPreview.candidateAutoStart ? '启用' : '关闭' }}</span>
              <span :class="{ changed: projectBundlePreview.configPreview.pluginCatalogChanged }">插件仓库{{ projectBundlePreview.configPreview.pluginCatalogChanged ? '变更' : '不变' }}</span>
            </div>
            <details v-if="projectBundlePreview.configPreview.candidateEnvironments.length" class="config-import-environments"><summary>查看目标业务环境（{{ projectBundlePreview.configPreview.candidateEnvironments.length }}）</summary><ul><li v-for="environment in projectBundlePreview.configPreview.candidateEnvironments" :key="`${environment.name}:${environment.url}`"><strong>{{ environment.name }}</strong><code>{{ environment.url }}</code></li></ul></details>
            <h3>项目包变更</h3>
            <ul><li v-for="component in projectBundlePreview.components" :key="component.pluginId"><span><strong>{{ component.pluginId }}</strong><small>{{ component.source === 'signed-package' ? `签名插件 ${component.version ?? ''} · Desktop ${component.desktopVersionRequirement ?? '未声明'}` : '本地动态映射' }}</small></span><em><b :class="`plan-action ${component.action}`">{{ projectActionLabels[component.action] }}</b>{{ component.serviceCount }} 个服务</em></li></ul>
            <details v-if="projectBundlePreview.retainedComponents.length" class="retained-components"><summary>不会删除的本机现有能力（{{ projectBundlePreview.retainedCount }}）</summary><ul><li v-for="component in projectBundlePreview.retainedComponents" :key="component.pluginId"><span><strong>{{ component.pluginId }}</strong><small>{{ component.source === 'signed-package' ? `签名插件 ${component.version ?? ''}` : '本地动态映射' }}</small></span><em><b class="plan-action retain">保留</b>{{ component.serviceCount }} 个服务</em></li></ul></details>
          </div>
        </section>
        <section class="operations" aria-label="桌面配置">
          <div class="operation-copy">
            <p class="eyebrow">BUSINESS ENTRY</p><h2>受控业务入口</h2>
            <p>配置的项目地址将直接成为该项目允许访问原生能力的来源。</p>
            <p v-if="snapshot?.migratedFrom" class="migration">已合并 {{ snapshot.migrationSources.length }} 个旧配置来源；首选来源：{{ snapshot.migratedFrom }}</p>
            <p v-if="snapshot?.migrationWarnings.length" class="migration warning">有 {{ snapshot.migrationWarnings.length }} 项旧配置未能自动读取，请查看运行日志并人工核对。</p>
          </div>
          <form v-if="snapshot" @submit.prevent="saveConfig">
            <label><span>业务系统地址</span><input v-model.trim="snapshot.config.website" type="url" maxlength="4096" placeholder="http://project.internal" /></label>
            <label><span>默认租户</span><input v-model.trim="snapshot.config.tenantId" type="text" placeholder="可选" /></label>
            <fieldset class="environments">
              <legend>业务环境</legend><p>默认项用于首页快捷启动；启用切换后，可直接打开任一环境。</p>
              <div v-for="(environment, index) in snapshot.config.environments" :key="index" class="environment-row">
                <label class="environment-default" title="设为默认环境"><input v-model="snapshot.config.website" type="radio" :value="environment.url" /><span>默认</span></label>
                <input v-model.trim="environment.name" type="text" maxlength="128" placeholder="环境名称" />
                <input :value="environment.url" type="url" maxlength="4096" placeholder="http://project.internal" @input="changeEnvironmentUrl(environment, ($event.target as HTMLInputElement).value)" />
                <button type="button" :disabled="busy || !snapshot.config.allowSwitch || !environment.name || !environment.url" @click="openEnvironment(environment)">打开</button>
                <button type="button" :disabled="busy" aria-label="删除环境" @click="removeEnvironment(index)">删除</button>
              </div>
              <button class="environment-add" type="button" :disabled="busy || snapshot.config.environments.length >= 32" @click="addEnvironment">新增环境</button>
            </fieldset>
            <div class="form-columns">
              <label><span>SSO 额外可信来源</span><textarea :value="snapshot.config.trustedOrigins.join('\n')" placeholder="每行一个来源，例如 https://sso.example.internal" @input="snapshot.config.trustedOrigins = ($event.target as HTMLTextAreaElement).value.split(/\s+/).filter(Boolean)" /></label>
              <label><span>系统浏览器允许来源</span><textarea :value="snapshot.config.externalOrigins.join('\n')" placeholder="每行一个来源" @input="snapshot.config.externalOrigins = ($event.target as HTMLTextAreaElement).value.split(/\s+/).filter(Boolean)" /></label>
            </div>
            <details class="advanced-settings">
              <summary>插件仓库高级配置</summary>
              <label><span>签名插件仓库索引</span><input v-model.trim="snapshot.config.pluginCatalogUrl" type="url" placeholder="https://plugins.example/catalog.json" /></label>
              <label><span>仓库索引签名</span><input v-model.trim="snapshot.config.pluginCatalogSignatureUrl" type="url" placeholder="https://plugins.example/catalog.sig.json" /></label>
            </details>
            <div class="toggles"><label><input v-model="snapshot.config.allowSwitch" type="checkbox" />允许环境切换</label><label><input v-model="snapshot.config.autoClose" type="checkbox" />关闭前确认</label><label><input v-model="snapshot.config.autoStart" type="checkbox" />开机自动启动</label></div>
            <div class="actions"><button class="primary" type="submit" :disabled="busy">保存配置</button><button type="button" :disabled="busy" @click="openBusiness">进入业务系统</button></div>
            <small class="config-path">配置位置：{{ snapshot.path }}</small>
          </form>
        </section>
        <section class="compact-panel"><div><h2>业务窗口维护</h2><p>仅在页面显示异常或需要清除登录状态时使用。</p></div><div class="actions"><button type="button" :disabled="busy" @click="reloadBusiness">刷新业务窗口</button><button type="button" :disabled="busy" @click="clearBusinessData">清理站点数据</button></div></section>
      </section>

      <section v-show="activeSection === 'native'" class="page page-native" aria-labelledby="native-title">
        <header class="section-header"><div><p class="eyebrow">NATIVE MAPPING STUDIO</p><h1 id="native-title">原生映射</h1><p>发现本机组件、配置调用映射，并在发布前完成受控调试。</p></div><span class="section-chip">本机管理员能力</span></header>
        <LocalMappingStudio :disabled="busy" @changed="refreshPluginsAfterMapping" />
      </section>

      <section v-show="activeSection === 'plugins'" class="page" aria-labelledby="plugins-title">
        <header class="section-header"><div><p class="eyebrow">PLUGIN MANAGEMENT</p><h1 id="plugins-title">插件管理</h1><p>管理签名插件包、本机动态映射和仓库更新。</p></div><div class="header-actions"><button type="button" :disabled="busy" @click="installPlugin">安装签名插件</button><button type="button" :disabled="busy" @click="reloadPlugins">重新扫描</button></div></header>
        <section class="plugin-inventory" aria-label="已安装插件">
          <div><p class="eyebrow">VERIFIED INVENTORY</p><h2>已验证插件</h2><p>无效项不会进入服务路由；动态映射始终与主进程隔离。</p><div class="inventory-count"><strong>{{ inventory?.plugins.length ?? '—' }}</strong><span>个可用插件</span></div></div>
          <div class="plugin-list">
            <form class="catalog-install" @submit.prevent="checkPluginUpdates(catalogPluginId)"><input v-model.trim="catalogPluginId" type="text" placeholder="输入签名仓库中的插件 ID" /><button type="submit" :disabled="busy">查询版本</button><button type="button" :disabled="busy" @click="checkPluginUpdates()">检查全部更新</button></form>
            <div v-if="pluginUpdates" class="plugin-update-results" aria-live="polite">
              <div v-for="update in pluginUpdates.updates" :key="update.pluginId"><span><strong>{{ update.pluginId }}</strong><small>已安装 {{ update.installedVersion ?? '无' }} · 当前客户端可用 {{ update.availableVersion ?? '无' }}<template v-if="update.installedVersionWithdrawn"> · 当前版本已撤回（{{ update.withdrawalReason ? withdrawalReasonLabels[update.withdrawalReason] : '原因未分类' }}）</template><template v-if="update.compatibilityLimited"> · 仓库最新 {{ update.latestCatalogVersion }} 需要其他 Desktop 版本</template></small></span><button v-if="update.updateAvailable && update.availableVersion && update.installPlanId" type="button" :disabled="busy" @click="installFromCatalog(update.pluginId, update.availableVersion, update.installPlanId)">{{ update.installedVersion ? `安装更新 ${update.availableVersion}` : `安装 ${update.availableVersion}` }}</button><em v-else>{{ update.installedVersionWithdrawn ? '当前版本已撤回，请升级或卸载' : update.catalogAvailable ? (update.compatibilityLimited ? '新版本与当前客户端不兼容' : '已是最新版本') : '仓库未收录' }}</em></div>
            </div>
            <article v-for="plugin in inventory?.plugins ?? []" :key="plugin.pluginId">
              <header><span><strong>{{ plugin.displayName }}</strong><small>{{ plugin.pluginId }} · {{ plugin.source === 'local-mapping' ? '本机动态映射' : `${plugin.version ?? '未知版本'} · Desktop ${plugin.desktopVersionRequirement ?? '未声明'}` }}</small></span><div v-if="plugin.source === 'signed-package'" class="plugin-actions"><button type="button" :disabled="busy" @click="checkPluginUpdates(plugin.pluginId)">检查更新</button><button class="danger-link" type="button" :disabled="busy" @click="uninstallSignedPlugin(plugin.pluginId, plugin.displayName)">卸载</button></div></header>
              <details v-for="service in plugin.services" :key="service.serviceId" class="service-mapping"><summary><code>{{ service.serviceId }}</code><span>{{ service.architecture }} / {{ service.mainType }} / {{ service.methodCount }} 个方法</span></summary><dl><div><dt>原生目标</dt><dd><code>{{ service.mainClass }}</code></dd></div><div><dt>调用约定</dt><dd>{{ service.callingConvention || '默认' }} · {{ service.charset || '默认字符集' }}</dd></div><div><dt>服务策略</dt><dd>{{ service.timeoutMs || '默认' }} ms · {{ service.cacheable ? '缓存实例' : '按需实例' }} · {{ service.dependencyCount }} 个依赖</dd></div></dl><div v-for="method in service.methods" :key="`${service.serviceId}:${method.requestName}`" class="method-mapping"><code>{{ method.requestName }}</code><span aria-hidden="true">→</span><code>{{ method.nativeName }}</code><small>{{ method.returnType || '默认返回类型' }} · {{ method.parameterCount }} 参数 · {{ method.timeoutMs || '默认' }} ms</small></div></details>
            </article>
            <p v-if="inventory && inventory.plugins.length === 0" class="empty">尚未安装通过验签的插件。</p>
            <details v-if="inventory?.quarantined.length" class="quarantined" open><summary>{{ inventory.quarantined.length }} 个插件已隔离</summary><ul><li v-for="failure in inventory.quarantined" :key="failure">{{ failure }}</li></ul></details>
          </div>
        </section>
      </section>

      <section v-show="activeSection === 'security'" class="page" aria-labelledby="security-title">
        <header class="section-header"><div><p class="eyebrow">SECURITY & DIAGNOSTICS</p><h1 id="security-title">安全与诊断</h1><p>先执行部署自检，再按需查看详细指标和导出诊断。</p></div><div class="header-actions"><button class="primary" type="button" :disabled="busy" @click="runDeploymentCheck">重新自检</button><button type="button" :disabled="busy" @click="openDiagnosticsDirectory">打开日志目录</button><button type="button" :disabled="busy || !status?.diagnosticsAvailable" @click="exportDiagnostics">导出脱敏诊断包</button></div></header>
        <section v-if="deploymentCheck" :class="['deployment-check', { ready: deploymentCheck.ready }]" aria-label="部署自检结果">
          <header>
            <div><p class="eyebrow">DEPLOYMENT CHECK</p><h2>{{ deploymentCheck.ready ? '当前机器可以交付' : '部署条件尚未满足' }}</h2><p>{{ deploymentCheck.passed }} 项正常 · {{ deploymentCheck.warnings }} 项提醒 · {{ deploymentCheck.failures }} 项阻塞</p></div>
            <span>{{ deploymentCheck.ready ? 'READY' : 'ACTION REQUIRED' }}</span>
          </header>
          <div class="check-list">
            <article v-for="item in deploymentCheck.items" :key="item.id" :class="`check-${item.status}`">
              <i>{{ item.status === 'pass' ? '✓' : item.status === 'fail' ? '!' : item.status === 'warning' ? '△' : 'i' }}</i>
              <div><strong>{{ item.label }}</strong><p>{{ item.summary }}</p><small v-if="item.action">建议：{{ item.action }}</small></div>
            </article>
          </div>
        </section>
        <section class="diagnostic-grid" aria-label="详细运行状态">
          <article><span>插件调用背压</span><strong v-if="status?.globalPluginMaintenanceActive">全局维护中</strong><strong v-else>{{ status ? `${status.inFlightInvocations} / ${status.maxInFlightInvocations}` : '—' }}</strong><small>容量拒绝 {{ status?.rejectedInvocations ?? '—' }} · 槽超时 {{ status?.executionLaneTimeouts ?? '—' }} · 维护拒绝 {{ status?.maintenanceRejectedInvocations ?? '—' }}</small></article>
          <article><span>隔离宿主监督</span><strong>{{ status?.activePluginHosts ?? '—' }} 个活动宿主</strong><small>累计启动 {{ status?.pluginHostStarts ?? '—' }} · 失败 {{ status?.pluginHostStartFailures ?? '—' }}</small></article>
          <article><span>原生操作防重放</span><strong>{{ status?.trackedInvocationsAvailable ? (status.trackedInvocationsAccepting ? '持久协调可用' : '正在排空') : '不可用' }}</strong><small>{{ status?.trackedInvocationsAvailable ? `等待 ${status.trackedPendingOperations} · 可找回 ${status.trackedRetainedResults} · 落盘异常 ${status.trackedPersistenceFailures}` : status?.trackedInvocationsError ?? '状态尚未加载' }}</small></article>
          <article><span>插件信任</span><strong>{{ status?.pluginTrustMode === 'ed25519-strict' ? '严格签名' : '开发模式' }}</strong><small :title="status?.pluginRoot">{{ status ? `${status.trustKeyCount} 把密钥 · 启用 ${status.activeTrustKeyCount} · 吊销 ${status.revokedTrustKeyCount}` : '完整清单与 SHA-256 校验' }}</small></article>
          <article><span>安装事务</span><strong>{{ status?.recoveredPluginTransactions ? '已自动恢复' : '状态正常' }}</strong><small>已清理或回滚 {{ status?.recoveredPluginTransactions ?? '—' }} 项</small></article>
          <article><span>宿主预检</span><strong>{{ status?.pluginPreflightFailures ? '存在失败' : '状态正常' }}</strong><small>通过 {{ status?.preflightedPluginHosts ?? '—' }} · 失败 {{ status?.pluginPreflightFailures ?? '—' }}</small></article>
          <article><span>受控进程策略</span><strong>{{ status?.processPolicyEntries ?? '—' }} 项</strong><small>启动失败 {{ status?.managedProcessFailures ?? '—' }} · 不经过 Shell</small></article>
          <article><span>开机启动</span><strong>{{ status?.autoStartEnabled == null ? '状态未知' : status.autoStartEnabled ? '已启用' : '未启用' }}</strong><small :title="status?.autoStartError">{{ status?.autoStartError ?? '由本机系统机制管理' }}</small></article>
          <article><span>SSO 传输</span><strong>{{ ssoActive ? '登录处理中' : ssoError ? '最近失败' : 'HTTPS-only' }}</strong><small>禁止重定向 · 请求与响应均有上限</small></article>
          <article><span>业务来源策略</span><strong>{{ status?.originPolicy.allowConfiguredBusinessOrigins ? '项目地址兼容' : status?.originPolicy.enforced ? '发布方签名' : '开发模式' }}</strong><small :title="status?.originPolicyError">{{ status?.originPolicyError ?? `${status?.originPolicy.businessOrigins ?? '—'} 个来源 · HTTP ${status?.originPolicy.allowInsecureHttp ? '允许' : '禁止'}` }}</small></article>
          <article><span>隐私诊断日志</span><strong>{{ status?.diagnosticsAvailable ? '可用' : '不可用' }}</strong><small :title="status?.diagnosticsLogDir">{{ status?.diagnosticsError ?? `${status?.diagnostics?.logFiles ?? '—'} 个文件 · ${((status?.diagnostics?.logBytes ?? 0) / 1024).toFixed(1)} KiB` }}</small></article>
          <article><span>协议与兼容网关</span><strong>v{{ status?.protocolVersion ?? '—' }}</strong><small>宿主 v{{ status?.pluginHostProtocolVersion ?? '—' }} · HTTP 网关{{ status?.httpGatewayEnabled ? '已启用' : '关闭' }}</small></article>
        </section>
        <section class="maintenance-panel"><div><p class="eyebrow">CLIENT MAINTENANCE</p><h2>客户端维护</h2><p>{{ status?.appUpdateError ?? (status?.appUpdateConfigured ? '应用更新包必须通过签名验证，并与当前插件兼容。' : '当前构建未配置生产更新端点。') }}</p></div><div class="maintenance-actions"><button type="button" :disabled="busy || !status?.appUpdateConfigured" @click="checkAppUpdate">检查应用更新</button><button class="primary" type="button" :disabled="busy || !appUpdate?.available || !appUpdate.compatible || !appUpdate.installPlanId" @click="installAppUpdate">安装签名更新</button></div><details v-if="appUpdate?.available" class="update-details" open><summary>版本 {{ appUpdate.version }}{{ appUpdate.date ? ` · ${appUpdate.date}` : '' }}</summary><p v-if="!appUpdate.compatible">{{ appUpdate.pluginBlockers }} 个插件阻止升级；请先从签名仓库安装兼容版本。</p><p>{{ appUpdate.notes || '此版本未提供发布说明。' }}</p><small v-if="updateProgress">{{ updateProgress }}</small></details></section>
        <section class="boundary"><div><p class="eyebrow">TRUST BOUNDARY</p><h2>第三方 DLL 永不进入主进程</h2></div><ol><li><b>业务 WebView</b><span>只调用受限的业务命令</span></li><li><b>Rust Controller</b><span>执行路由、策略、超时和监督</span></li><li><b>Plugin Host</b><span>加载 DLL、COM、OCX、EXE 或 BAT</span></li></ol></section>
      </section>
    </main>
  </div>
</template>
