<script setup lang="ts">
import { Channel, invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import { open, save } from '@tauri-apps/plugin-dialog'
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { cloneConfig, configFingerprint } from './config-draft.js'
import LocalMappingStudio from './LocalMappingStudio.vue'
import {
  initialRuntimeStatusHealth,
  updateRuntimeStatusHealth,
  withBoundedTimeout,
  type RuntimeStatusHealthEvent,
} from './runtime-status.js'

const CONTROL_BOOTSTRAP_TIMEOUT_MS = 15_000
const CONTROL_POST_ACTION_REFRESH_TIMEOUT_MS = 15_000

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
  pluginHosts: Array<{
    pluginId: string
    architecture: 'x86' | 'x64'
    serviceCount: number
    state: 'idle' | 'ready' | 'restart-backoff' | 'retry-ready'
    failureCount: number
    lastFailureCode?: string
  }>
  pluginLoadFailures: number
  pluginCount: number
  recoveredPluginTransactions: number
  preflightedPluginHosts: number
  pluginPreflightFailures: number
  pluginTrustMode: string
  pluginApiBaselineCount: number
  pluginApiBaselineFailures: number
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
  businessWindowCount: number
  businessLoadingWindows: number
  businessNavigatingWindows: number
  businessReadyWindows: number
  businessTimedOutWindows: number
  businessFrontendTimeouts: number
  businessFrontendRecoveries: number
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

type PluginHostStatus = BridgeStatus['pluginHosts'][number]

type DeploymentCheckReport = {
  deep: boolean
  deepAvailable: boolean
  ready: boolean
  deliveryReady: boolean
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
    apiAdditionCount: number
    apiReviewChangeCount: number
  }>
  retainedComponents: Array<{
    pluginId: string
    version?: string
    desktopVersionRequirement?: string
    source: 'signed-package' | 'local-mapping'
    action: 'retain'
    serviceCount: number
    apiAdditionCount: number
    apiReviewChangeCount: number
  }>
}

type ProjectBundleImportResult = {
  signedPlugins: number
  localMappings: number
  serviceCount: number
  preflightedHosts: number
  resetRequired: boolean
  requestedWindows: number
  closedWindows: number
  failedWindows: number
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

type BusinessSurfaceCloseResult = {
  resetRequired: boolean
  requestedWindows: number
  closedWindows: number
  failedWindows: number
}

type ConfigImportResult = ConfigSnapshot & BusinessSurfaceCloseResult

type ConfigChangePreview = {
  configChanged: boolean
  businessSurfaceResetRequired: boolean
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

type PluginPackagePreview = {
  planId: string
  pluginId: string
  displayName: string
  pluginVersion: string
  desktopVersionRequirement: string
  currentVersion?: string
  action: 'install' | 'upgrade' | 'reinstall'
  serviceCount: number
  methodCount: number
  apiAdditionCount: number
  apiReviewChangeCount: number
  services: Array<{
    serviceId: string
    architecture: 'x86' | 'x64'
    methodCount: number
  }>
  preflightedHosts: number
}

type SignedPluginUninstallPreview = {
  planId: string
  pluginId: string
  displayName: string
  pluginVersion: string
  serviceCount: number
  methodCount: number
}

type PluginReloadPreview = {
  planId: string
  pluginCount: number
  signedPluginCount: number
  localMappingCount: number
  serviceCount: number
  methodCount: number
  addedPluginCount: number
  changedRoutePluginCount: number
  removedLocalMappingCount: number
  quarantinedPlugins: number
  preflightedHosts: number
}

type PluginReloadResult = {
  serviceCount: number
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
    installBlocker?: 'local-mapping-conflict' | 'invalid-target-state'
    rollbackVersionCount: number
    rollbackVersions: Array<{
      version: string
      desktopVersionRequirement: string
      installPlanId: string
    }>
  }>
}

type CatalogInstallAction = 'install' | 'upgrade' | 'rollback'

type AppUpdateCheck = {
  configured: boolean
  currentVersion: string
  available: boolean
  compatible: boolean
  capabilityBlockers: number
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

type BusinessFrontendRetryResult = {
  retriedWindows: number
  failedWindows: number
  unavailableWindows: number
}

type BusinessDataClearPreview = {
  planId: string
  configuredBusinessOrigins: number
  businessWindows: number
  floatingWindows: number
}

type BusinessWindowReloadResult = {
  requestedWindows: number
  reloadedWindows: number
  failedWindows: number
}

type ControlRefreshField = 'status' | 'config' | 'inventory' | 'deployment'
type PrimaryActionOutcome = {
  succeeded: boolean
  refreshed: boolean
}

const ALL_CONTROL_REFRESH_FIELDS: ControlRefreshField[] = ['status', 'config', 'inventory', 'deployment']

const status = ref<BridgeStatus | null>(null)
const deploymentCheck = ref<DeploymentCheckReport | null>(null)
const projectBundlePreview = ref<ProjectBundlePreview | null>(null)
const selectedProjectBundle = ref('')
const configImportPreview = ref<ConfigImportPreview | null>(null)
const selectedConfigImport = ref('')
const snapshot = ref<ConfigSnapshot | null>(null)
const savedConfigFingerprint = ref('')
const inventory = ref<PluginInventory | null>(null)
const pluginPackagePreview = ref<PluginPackagePreview | null>(null)
const selectedPluginPackage = ref('')
const catalogPluginId = ref('')
const pluginUpdates = ref<PluginUpdateCheck | null>(null)
const appUpdate = ref<AppUpdateCheck | null>(null)
const businessDataClearPreview = ref<BusinessDataClearPreview | null>(null)
const updateProgress = ref('')
const error = ref('')
const ssoActive = ref(false)
const ssoError = ref('')
const notice = ref('')
const busy = ref(false)
const controlLoadActive = ref(false)
const controlLoadFailed = ref(false)
const controlRefreshActive = ref(false)
const controlRefreshMissing = ref<ControlRefreshField[]>([])
const deploymentCheckUnavailable = ref(false)
const runtimeStatusHealth = ref(initialRuntimeStatusHealth())
const runtimeStatusRecovered = ref(false)
const mappingDraftDirty = ref(false)
const mappingWorkspaceUnverified = ref(false)
const mappingWorkspaceRevision = ref(0)
type ConsoleSection = 'overview' | 'configuration' | 'native' | 'plugins' | 'security'
const activeSection = ref<ConsoleSection>('overview')
const runtimeStatusStale = computed(() => runtimeStatusHealth.value.stale)
const controlRefreshIncomplete = computed(() => controlRefreshMissing.value.length > 0)
const configDraftDirty = computed(() => (
  snapshot.value != null
  && configFingerprint(snapshot.value.config) !== savedConfigFingerprint.value
))
const projectDeliveryDraftDirty = computed(() => configDraftDirty.value || mappingDraftDirty.value)
const controlStateUnverified = computed(() => (
  controlLoadFailed.value || controlRefreshIncomplete.value || runtimeStatusStale.value
))
const projectStateUnverified = computed(() => (
  controlStateUnverified.value || mappingWorkspaceUnverified.value
))
const deploymentReadiness = computed(() => {
  if (controlLoadFailed.value) {
    return {
      label: '初始化失败',
      detail: '控制台尚未取得完整项目状态，请重新加载',
    }
  }
  if (controlRefreshIncomplete.value) {
    return {
      label: '状态待刷新',
      detail: '操作已完成，但部分页面状态尚未重新读取',
    }
  }
  if (mappingWorkspaceUnverified.value) {
    return {
      label: '映射状态待刷新',
      detail: '请在原生映射页重新读取当前清单',
    }
  }
  if (configDraftDirty.value) {
    return {
      label: '配置未保存',
      detail: '当前自检结论仅对应磁盘中的有效配置',
    }
  }
  if (mappingDraftDirty.value) {
    return {
      label: '映射未保存',
      detail: '当前自检结论不包含原生映射工作台草稿',
    }
  }
  if (runtimeStatusStale.value) {
    return {
      label: '状态未知',
      detail: '桌面核心通信中断，部署状态无法确认',
    }
  }
  const report = deploymentCheck.value
  if (deploymentCheckUnavailable.value) {
    return {
      label: '检查不可用',
      detail: '控制台已加载；请在安全与诊断中重新检查',
    }
  }
  if (!report) {
    return {
      label: '检查中',
      detail: '正在执行环境快速检查',
    }
  }
  if (!report.ready) {
    return {
      label: '需要处理',
      detail: `${report.failures} 项阻塞 · ${report.warnings} 项提醒`,
    }
  }
  if (report.deliveryReady) {
    return {
      label: '可以交付',
      detail: `${report.passed} 项深度检查通过 · ${report.warnings} 项提醒`,
    }
  }
  if (report.deepAvailable) {
    return {
      label: '待深度检查',
      detail: `${report.passed} 项快速检查通过 · 正式交付前需验证宿主`,
    }
  }
  return {
    label: '开发预览',
    detail: '当前平台不提供 Windows 宿主交付检查',
  }
})
const needsDeepDeploymentCheck = computed(() => (
  deploymentCheck.value?.ready === true
  && deploymentCheck.value.deepAvailable
  && !deploymentCheck.value.deliveryReady
))
const businessFrontendReadiness = computed(() => {
  if (controlLoadFailed.value) return { label: '状态未知', detail: '控制台初始化失败，无法确认业务页面状态' }
  if (controlRefreshIncomplete.value) return { label: '状态未知', detail: '操作后的页面状态尚未完整刷新' }
  if (runtimeStatusStale.value) return { label: '状态未知', detail: '桌面核心通信中断，无法确认业务页面状态' }
  const current = status.value
  if (!current) return { label: '检查中', detail: '正在读取业务窗口状态' }
  if (current.businessTimedOutWindows > 0) {
    return { label: '加载失败', detail: `${current.businessTimedOutWindows} 个窗口未到达原生 IPC` }
  }
  if (current.businessReadyWindows > 0) {
    return { label: '已连接', detail: `${current.businessReadyWindows} / ${current.businessWindowCount} 个窗口就绪` }
  }
  if (current.businessNavigatingWindows > 0) {
    return { label: '登录跳转中', detail: `${current.businessNavigatingWindows} 个窗口等待返回业务页面` }
  }
  if (current.businessLoadingWindows > 0) {
    return { label: '正在加载', detail: '页面加载完成后将自动验证原生 IPC' }
  }
  return { label: '未启动', detail: '启动业务环境后自动校验' }
})
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
let ssoStatusListenerPromise: Promise<void> | undefined
let controlConsoleMounted = false
let ssoStatusEventSeen = false
let statusRefreshTimer: number | undefined
let runtimeStatusRecoveryTimer: number | undefined
let statusRefreshActive = false
let controlRefreshQueue: Promise<void> = Promise.resolve()
let controlRefreshRequests = 0
const pendingControlRefreshFields = new Set<ControlRefreshField>()

function pluginHostNeedsAttention(host: PluginHostStatus) {
  return host.state === 'restart-backoff' || host.state === 'retry-ready'
}

function pluginHostAdvice(host: PluginHostStatus) {
  switch (host.lastFailureCode) {
    case 'native-component-missing':
      return '重新验签或安装插件，并确认入口及依赖文件完整。'
    case 'native-path-escape':
      return '原生路径越过插件目录；请修正映射或重新打包，重复重试不会修复。'
    case 'native-dll-preflight-failed':
      return '核对 DLL 位数、依赖文件和声明导出，并在原生映射工作台重新预检。'
    case 'native-com-preflight-failed':
      return '核对对应位数的 COM/OCX 注册，以及类和成员声明。'
    case 'native-process-preflight-failed':
      return '核对 EXE/BAT 入口完整性；文件发生变化时应重新打包或安装。'
    case 'native-operation-unsupported':
      return '检查组件类型、目标架构和静态 ABI 声明。'
    case 'host-architecture-mismatch':
      return '服务架构与宿主不一致；请修正 x86/x64 映射并重新发布。'
    case 'host-protocol-version-mismatch':
    case 'protocol-version-mismatch':
      return '客户端与插件宿主版本不一致；请修复或重新安装当前 Desktop。'
    case 'host-spawn-failed':
      return '确认客户端安装完整，并检查终端防护是否阻止插件宿主启动。'
    case 'host-exited':
    case 'host-pipe-missing':
    case 'host-transport-failed':
    case 'windows-job-failed':
    case 'native-worker-unavailable':
      return '可先恢复宿主；若重复失败，请执行深度自检并导出脱敏诊断包。'
    default:
      return '可先恢复宿主；若重复失败，请执行深度自检并查看稳定错误码。'
  }
}

async function retryPluginHost(host: PluginHostStatus) {
  const outcome = await runPrimaryThenRefresh(
    () => invoke('retry_plugin_host', {
      pluginId: host.pluginId,
      architecture: host.architecture,
    }),
    ['status'],
  )
  if (outcome.succeeded) {
    showPrimaryActionSuccess(
      `${host.pluginId} ${host.architecture.toUpperCase()} 宿主 Health 已恢复；未调用业务方法。`,
      outcome.refreshed,
    )
  }
}

async function refreshRuntimeStatus(force = false) {
  if (busy.value || controlRefreshActive.value || statusRefreshActive || (runtimeStatusStale.value && !force)) return
  statusRefreshActive = true
  try {
    const next = await withBoundedTimeout(invoke<BridgeStatus>('bridge_status'))
    status.value = next
    if (!ssoStatusEventSeen) applySsoStatus(next.ssoError, next.ssoActive)
    controlRefreshMissing.value = controlRefreshMissing.value.filter((field) => field !== 'status')
    recordRuntimeStatusEvent('success')
  } catch {
    recordRuntimeStatusEvent('failure')
  } finally {
    statusRefreshActive = false
  }
}

function retryRuntimeStatus() {
  void refreshRuntimeStatus(true)
}

function recordRuntimeStatusEvent(event: RuntimeStatusHealthEvent) {
  const transition = updateRuntimeStatusHealth(runtimeStatusHealth.value, event)
  runtimeStatusHealth.value = transition.health
  if (event === 'failure') {
    runtimeStatusRecovered.value = false
    if (runtimeStatusRecoveryTimer != null) window.clearTimeout(runtimeStatusRecoveryTimer)
    runtimeStatusRecoveryTimer = undefined
    return
  }
  if (!transition.recovered) return
  runtimeStatusRecovered.value = true
  if (runtimeStatusRecoveryTimer != null) window.clearTimeout(runtimeStatusRecoveryTimer)
  runtimeStatusRecoveryTimer = window.setTimeout(() => {
    runtimeStatusRecovered.value = false
    runtimeStatusRecoveryTimer = undefined
  }, 8_000)
}

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

function applyConfigSnapshot(next: ConfigSnapshot) {
  snapshot.value = next
  savedConfigFingerprint.value = configFingerprint(next.config)
}

function requireSavedConfig(action: string): boolean {
  if (!configDraftDirty.value) return true
  notice.value = ''
  error.value = `项目配置有未保存更改。请先保存或放弃更改，再${action}。`
  activeSection.value = 'configuration'
  return false
}

function requireSavedMapping(action: string): boolean {
  if (!mappingDraftDirty.value) return true
  notice.value = ''
  error.value = `原生映射工作台有未保存更改。请先保存或放弃映射草稿，再${action}。`
  activeSection.value = 'native'
  return false
}

function requireVerifiedControlState(action: string): boolean {
  if (!projectStateUnverified.value) return true
  notice.value = ''
  if (mappingWorkspaceUnverified.value) {
    error.value = `原生映射清单尚未复核。请先在原生映射页重新读取，再${action}。`
    activeSection.value = 'native'
  } else {
    error.value = `当前项目状态尚未完整验证。请先恢复或刷新状态，再${action}。`
  }
  return false
}

function requireCleanProjectDrafts(action: string): boolean {
  return requireVerifiedControlState(action) && requireSavedConfig(action) && requireSavedMapping(action)
}

function businessSurfaceCloseSummary(result: BusinessSurfaceCloseResult): string {
  if (!result.resetRequired) return '本次变更不影响当前业务页面，已保持打开。'
  if (result.requestedWindows === 0) return '当前没有打开的业务或悬浮页面。'
  if (result.failedWindows > 0) {
    return `已关闭 ${result.closedWindows} / ${result.requestedWindows} 个业务或悬浮页面；${result.failedWindows} 个页面未能自动关闭，请手动关闭后再继续。`
  }
  return `已关闭 ${result.closedWindows} 个业务或悬浮页面。`
}

function preventConfigDraftUnload(event: BeforeUnloadEvent) {
  if (!configDraftDirty.value) return
  event.preventDefault()
  event.returnValue = ''
}

async function ensureSsoStatusListener() {
  if (unlistenSsoStatus) return
  if (ssoStatusListenerPromise) return ssoStatusListenerPromise
  ssoStatusListenerPromise = (async () => {
    try {
      const unlisten = await listen<SsoStatusEvent>('desktop://sso-status', (event) => {
        ssoStatusEventSeen = true
        applySsoStatus(event.payload.code, event.payload.active)
      })
      if (controlConsoleMounted) unlistenSsoStatus = unlisten
      else unlisten()
    } catch {
      // bridge_status polling remains the bounded fallback for SSO status.
    } finally {
      ssoStatusListenerPromise = undefined
    }
  })()
  return ssoStatusListenerPromise
}

async function loadControlConsole() {
  if (controlLoadActive.value) return
  controlLoadActive.value = true
  try {
    const bootstrap = (async () => {
      await invoke('frontend_ready')
      void ensureSsoStatusListener()
      const deploymentPromise = withBoundedTimeout(
        invoke<DeploymentCheckReport>('run_deployment_check', { deep: false }),
      ).catch(() => {
        deploymentCheckUnavailable.value = true
        return null
      })
      return Promise.all([
        invoke<BridgeStatus>('bridge_status'),
        invoke<ConfigSnapshot>('desktop_config'),
        invoke<PluginInventory>('plugin_inventory'),
        deploymentPromise,
      ])
    })()
    const [bridge, config, plugins, deployment] = await withBoundedTimeout(
      bootstrap,
      CONTROL_BOOTSTRAP_TIMEOUT_MS,
    )
    if (!controlConsoleMounted) return
    status.value = bridge
    applyConfigSnapshot(config)
    inventory.value = plugins
    deploymentCheck.value = deployment
    if (deployment) deploymentCheckUnavailable.value = false
    if (!ssoStatusEventSeen) applySsoStatus(bridge.ssoError, bridge.ssoActive)
    controlLoadFailed.value = false
    controlRefreshMissing.value = []
    recordRuntimeStatusEvent('success')
    if (statusRefreshTimer == null) {
      statusRefreshTimer = window.setInterval(() => void refreshRuntimeStatus(), 5_000)
    }
  } catch {
    if (controlConsoleMounted) controlLoadFailed.value = true
  } finally {
    controlLoadActive.value = false
  }
}

function retryControlLoad() {
  void loadControlConsole()
}

onMounted(() => {
  controlConsoleMounted = true
  window.addEventListener('beforeunload', preventConfigDraftUnload)
  void loadControlConsole()
})

onUnmounted(() => {
  controlConsoleMounted = false
  window.removeEventListener('beforeunload', preventConfigDraftUnload)
  unlistenSsoStatus?.()
  if (statusRefreshTimer != null) window.clearInterval(statusRefreshTimer)
  if (runtimeStatusRecoveryTimer != null) window.clearTimeout(runtimeStatusRecoveryTimer)
})

async function run(action: () => Promise<unknown>, success: string): Promise<boolean> {
  busy.value = true
  error.value = ''
  notice.value = ''
  try {
    await action()
    notice.value = success
    return true
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : String(reason)
    return false
  } finally {
    busy.value = false
  }
}

async function refreshControlState(fields: ControlRefreshField[]): Promise<boolean> {
  for (const field of fields) pendingControlRefreshFields.add(field)
  controlRefreshRequests += 1
  controlRefreshActive.value = true
  let refreshed = false
  const execute = async () => {
    const targets = [...new Set([...controlRefreshMissing.value, ...pendingControlRefreshFields])]
    for (const field of targets) pendingControlRefreshFields.delete(field)
    let failures: Array<ControlRefreshField | null>
    try {
      failures = await Promise.all(targets.map(async (field) => {
        try {
          if (field === 'status') {
            const next = await withBoundedTimeout(
              invoke<BridgeStatus>('bridge_status'),
              CONTROL_POST_ACTION_REFRESH_TIMEOUT_MS,
            )
            status.value = next
            if (!ssoStatusEventSeen) applySsoStatus(next.ssoError, next.ssoActive)
            recordRuntimeStatusEvent('success')
          } else if (field === 'config') {
            const next = await withBoundedTimeout(
              invoke<ConfigSnapshot>('desktop_config'),
              CONTROL_POST_ACTION_REFRESH_TIMEOUT_MS,
            )
            applyConfigSnapshot(next)
          } else if (field === 'inventory') {
            inventory.value = await withBoundedTimeout(
              invoke<PluginInventory>('plugin_inventory'),
              CONTROL_POST_ACTION_REFRESH_TIMEOUT_MS,
            )
          } else {
            deploymentCheck.value = await withBoundedTimeout(
              invoke<DeploymentCheckReport>('run_deployment_check', { deep: false }),
              CONTROL_POST_ACTION_REFRESH_TIMEOUT_MS,
            )
            deploymentCheckUnavailable.value = false
          }
          return null
        } catch {
          if (field === 'status') recordRuntimeStatusEvent('failure')
          if (field === 'deployment') deploymentCheckUnavailable.value = true
          return field
        }
      }))
    } catch {
      failures = targets
    }
    controlRefreshMissing.value = [...new Set([
      ...failures.filter((field): field is ControlRefreshField => field !== null),
      ...pendingControlRefreshFields,
    ])]
    refreshed = controlRefreshMissing.value.length === 0
  }
  const scheduled = controlRefreshQueue.then(execute, execute)
  controlRefreshQueue = scheduled.then(() => undefined, () => undefined)
  try {
    await scheduled
    return refreshed
  } finally {
    controlRefreshRequests = Math.max(0, controlRefreshRequests - 1)
    controlRefreshActive.value = controlRefreshRequests > 0
  }
}

async function runPrimaryThenRefresh(
  action: () => Promise<unknown>,
  fields: ControlRefreshField[],
): Promise<PrimaryActionOutcome> {
  busy.value = true
  error.value = ''
  notice.value = ''
  try {
    try {
      await action()
    } catch (reason) {
      error.value = reason instanceof Error ? reason.message : String(reason)
      return { succeeded: false, refreshed: false }
    }
    const refreshed = await refreshControlState(fields)
    return { succeeded: true, refreshed }
  } finally {
    busy.value = false
  }
}

function showPrimaryActionSuccess(message: string, refreshed: boolean) {
  notice.value = refreshed
    ? message
    : `${message} 页面状态未完全刷新；操作已经完成，请勿重复执行，刷新状态后再继续。`
}

async function retryControlStateRefresh() {
  if (controlRefreshActive.value) return
  busy.value = true
  error.value = ''
  notice.value = ''
  try {
    const refreshed = await refreshControlState(ALL_CONTROL_REFRESH_FIELDS)
    if (refreshed) notice.value = '操作后的项目、插件和运行状态已经重新验证。'
  } finally {
    busy.value = false
  }
}

async function discardConfigChanges() {
  if (!configDraftDirty.value || busy.value || controlStateUnverified.value) return
  busy.value = true
  error.value = ''
  notice.value = ''
  try {
    const next = await withBoundedTimeout(
      invoke<ConfigSnapshot>('desktop_config'),
      CONTROL_POST_ACTION_REFRESH_TIMEOUT_MS,
    )
    applyConfigSnapshot(next)
    notice.value = '未保存的项目配置更改已放弃，页面已恢复为当前有效配置。'
  } catch {
    error.value = '未能重新读取当前有效配置。请刷新状态；仍失败时重启客户端并查看日志。'
  } finally {
    busy.value = false
  }
}

async function saveConfig() {
  if (!snapshot.value) return
  const candidate = cloneConfig(snapshot.value.config)
  let closedSurfaces: BusinessSurfaceCloseResult | undefined
  const outcome = await runPrimaryThenRefresh(
    async () => {
      closedSurfaces = await invoke<BusinessSurfaceCloseResult>('save_desktop_config', { config: candidate })
      savedConfigFingerprint.value = configFingerprint(candidate)
      configImportPreview.value = null
      selectedConfigImport.value = ''
    },
    ['status', 'config', 'deployment'],
  )
  if (outcome.succeeded && closedSurfaces) {
    showPrimaryActionSuccess(`配置已安全保存；${businessSurfaceCloseSummary(closedSurfaces)}`, outcome.refreshed)
  }
}

async function importConfig() {
  const source = await open({
    multiple: false,
    directory: false,
    filters: [{ name: 'SSDEV 桌面配置', extensions: ['json'] }],
  })
  if (typeof source !== 'string') return
  if (configDraftDirty.value && !window.confirm('当前项目配置有未保存更改。继续预检不会立即丢弃草稿，但确认导入后将以文件内容替换草稿和当前有效配置。确定继续吗？')) return
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
  let imported: ConfigImportResult | undefined
  const outcome = await runPrimaryThenRefresh(async () => {
    imported = await invoke<ConfigImportResult>('import_desktop_config', {
      source,
      expectedPlanId,
    })
    applyConfigSnapshot(imported)
    configImportPreview.value = null
    selectedConfigImport.value = ''
  }, ['status', 'config', 'deployment'])
  if (outcome.succeeded) {
    showPrimaryActionSuccess(
      changed && imported
        ? `配置已按确认计划导入；${businessSurfaceCloseSummary(imported)}`
        : '导入配置与当前配置一致，未执行替换。',
      outcome.refreshed,
    )
  }
}

function cancelConfigImport() {
  configImportPreview.value = null
  selectedConfigImport.value = ''
  notice.value = '已取消配置导入。'
}

async function exportConfig() {
  if (!requireSavedConfig('导出当前有效配置')) return
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
  if (!requireCleanProjectDrafts('导出项目部署包')) return
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
  if (!requireCleanProjectDrafts('预检项目部署包')) return
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
  if (!requireVerifiedControlState('导入项目部署包')) return
  if (!selectedProjectBundle.value || !projectBundlePreview.value) {
    error.value = '请先选择并预检项目部署包。'
    return
  }
  if (configDraftDirty.value && !window.confirm('当前项目配置有未保存更改。导入项目会以项目包中的配置替换这些草稿，确定继续吗？')) return
  if (mappingDraftDirty.value && !window.confirm('当前原生映射工作台有未保存更改。导入项目会刷新工作台并丢弃这些更改，确定继续吗？')) return
  const source = selectedProjectBundle.value
  const expectedPlanId = projectBundlePreview.value.planId
  let result: ProjectBundleImportResult | undefined
  const outcome = await runPrimaryThenRefresh(async () => {
    result = await invoke<ProjectBundleImportResult>('import_project_bundle', {
      source,
      expectedPlanId,
    })
    mappingWorkspaceRevision.value += 1
    mappingDraftDirty.value = false
    pluginUpdates.value = null
    appUpdate.value = null
    selectedProjectBundle.value = ''
    projectBundlePreview.value = null
    selectedConfigImport.value = ''
    configImportPreview.value = null
  }, ALL_CONTROL_REFRESH_FIELDS)
  if (result) {
    showPrimaryActionSuccess(
      `项目已导入：${result.signedPlugins} 个签名插件、${result.localMappings} 个本地映射、${result.serviceCount} 个原生服务；${businessSurfaceCloseSummary(result)}`,
      outcome.refreshed,
    )
  }
}

async function openBusiness() {
  if (!requireSavedConfig('启动业务系统')) return
  await run(() => invoke('open_business_window'), '业务窗口已创建；页面完成加载后首页将显示“已连接”。')
}

async function openEnvironment(environment: EnvironmentConfig) {
  if (!requireSavedConfig(`打开环境「${environment.name}」`)) return
  await run(
    () => invoke('open_business_window', { environment: environment.name }),
    `环境「${environment.name}」窗口已创建；页面完成加载后首页将显示“已连接”。`,
  )
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

async function inspectBusinessDataClear() {
  let preview: BusinessDataClearPreview | undefined
  const succeeded = await run(async () => {
    preview = await invoke<BusinessDataClearPreview>('inspect_business_data_clear')
  }, '已读取当前站点数据清理影响；确认前不会修改任何数据。')
  if (succeeded && preview) businessDataClearPreview.value = preview
}

function cancelBusinessDataClear() {
  businessDataClearPreview.value = null
}

async function confirmBusinessDataClear() {
  const preview = businessDataClearPreview.value
  if (!preview) return
  let result: BusinessSurfaceCloseResult | undefined
  const outcome = await runPrimaryThenRefresh(async () => {
    result = await invoke<BusinessSurfaceCloseResult>('clear_business_data', {
      expectedPlanId: preview.planId,
    })
    businessDataClearPreview.value = null
  }, ['status'])
  if (!outcome.succeeded || !result) {
    businessDataClearPreview.value = null
    return
  }
  showPrimaryActionSuccess(
    `站点数据清理已提交，Cookie、登录状态、缓存和本地存储不可恢复；${businessSurfaceCloseSummary(result)}`,
    outcome.refreshed,
  )
}

async function reloadBusiness() {
  let result: BusinessWindowReloadResult | undefined
  const outcome = await runPrimaryThenRefresh(async () => {
    result = await invoke<BusinessWindowReloadResult>('reload_business_windows')
  }, ['status'])
  if (!outcome.succeeded || !result) return
  if (result.requestedWindows === 0) {
    showPrimaryActionSuccess('当前没有打开的业务窗口，无需刷新。', outcome.refreshed)
  } else if (result.failedWindows > 0) {
    showPrimaryActionSuccess(
      `已刷新 ${result.reloadedWindows} / ${result.requestedWindows} 个业务窗口；${result.failedWindows} 个窗口无法刷新，请关闭后重新进入。`,
      outcome.refreshed,
    )
  } else {
    showPrimaryActionSuccess(`已刷新 ${result.reloadedWindows} 个业务窗口。`, outcome.refreshed)
  }
}

async function retryTimedOutBusinessWindows() {
  let result: BusinessFrontendRetryResult | undefined
  const outcome = await runPrimaryThenRefresh(async () => {
    result = await invoke<BusinessFrontendRetryResult>('retry_timed_out_business_windows')
  }, ['status'])
  if (!outcome.succeeded || !result) return
  if (result.retriedWindows > 0) {
    showPrimaryActionSuccess(
      `已重新加载 ${result.retriedWindows} 个超时业务窗口；页面完成加载后将自动复核原生连接。`,
      outcome.refreshed,
    )
  } else if (result.unavailableWindows > 0) {
    showPrimaryActionSuccess('超时业务窗口已经关闭，无需继续重试。', outcome.refreshed)
  } else {
    showPrimaryActionSuccess('当前没有仍处于超时状态的业务窗口。', outcome.refreshed)
  }
  if (result.failedWindows > 0) {
    error.value = `${result.failedWindows} 个超时业务窗口无法重新加载；请关闭后重新进入业务系统。`
  }
}

async function selectPluginPackage() {
  const selected = await open({
    multiple: false,
    directory: false,
    filters: [{ name: 'SSDEV 签名插件包', extensions: ['ssdev-plugin', 'zip'] }],
  })
  if (typeof selected !== 'string') return

  const outcome = await runPrimaryThenRefresh(async () => {
    pluginPackagePreview.value = null
    selectedPluginPackage.value = ''
    pluginPackagePreview.value = await invoke<PluginPackagePreview>('inspect_plugin_package', {
      packagePath: selected,
    })
    selectedPluginPackage.value = selected
  }, ['status'])
  if (outcome.succeeded) {
    showPrimaryActionSuccess('插件包验签和候选宿主预检已通过；请核对变更后确认安装。', outcome.refreshed)
  }
}

async function confirmPluginPackageInstall() {
  if (!requireCleanProjectDrafts('安装签名插件')) return
  if (!pluginPackagePreview.value || !selectedPluginPackage.value) {
    error.value = '请先选择并预检签名插件包。'
    return
  }
  const packagePath = selectedPluginPackage.value
  const preview = pluginPackagePreview.value

  let result: PluginInstallResult | undefined
  const outcome = await runPrimaryThenRefresh(async () => {
    result = await invoke<PluginInstallResult>('install_plugin_package', {
      packagePath,
      expectedPlanId: preview.planId,
    })
    pluginPackagePreview.value = null
    selectedPluginPackage.value = ''
    pluginUpdates.value = null
    appUpdate.value = null
  }, ['status', 'inventory', 'deployment'])

  if (result) {
    const action = projectActionLabels[preview.action]
    showPrimaryActionSuccess(
      `${result.pluginId} ${result.pluginVersion} 已${action}，${result.preflightedHosts} 个架构宿主预检通过，当前共 ${result.serviceCount} 个服务已热加载。`,
      outcome.refreshed,
    )
  }
}

function cancelPluginPackageInstall() {
  pluginPackagePreview.value = null
  selectedPluginPackage.value = ''
  notice.value = '已取消签名插件安装。'
}

async function uninstallSignedPlugin(pluginId: string) {
  if (!requireCleanProjectDrafts('卸载签名插件')) return
  let preview: SignedPluginUninstallPreview | undefined
  const inspected = await run(async () => {
    preview = await invoke<SignedPluginUninstallPreview>('inspect_signed_plugin_uninstall', { pluginId })
  }, '')
  if (!inspected || !preview) return
  const confirmed = preview
  if (!window.confirm(
    `确定卸载签名插件「${confirmed.displayName}」(${confirmed.pluginId} ${confirmed.pluginVersion}) 吗？` +
    `将停止 ${confirmed.serviceCount} 个服务、${confirmed.methodCount} 个方法。` +
    '插件程序会被删除，但不会恢复已经发生的设备操作或业务数据。',
  )) return
  const outcome = await runPrimaryThenRefresh(async () => {
    await invoke('uninstall_signed_plugin', {
      pluginId: confirmed.pluginId,
      expectedPlanId: confirmed.planId,
    })
    pluginUpdates.value = null
    appUpdate.value = null
  }, ['status', 'inventory', 'deployment'])
  if (outcome.succeeded) {
    showPrimaryActionSuccess(
      `签名插件 ${confirmed.pluginId} ${confirmed.pluginVersion} 已卸载并从路由移除。`,
      outcome.refreshed,
    )
  }
}

async function reloadPlugins() {
  if (!requireCleanProjectDrafts('重新扫描插件目录')) return
  let preview: PluginReloadPreview | undefined
  const inspected = await run(async () => {
    preview = await invoke<PluginReloadPreview>('inspect_plugin_reload')
  }, '')
  if (!inspected || !preview) return
  const confirmed = preview
  if (!window.confirm(
    `重新扫描候选包含 ${confirmed.signedPluginCount} 个签名插件、${confirmed.localMappingCount} 个本地映射，` +
    `共 ${confirmed.serviceCount} 个服务、${confirmed.methodCount} 个方法；` +
    `将新增 ${confirmed.addedPluginCount} 个插件、变更 ${confirmed.changedRoutePluginCount} 个插件的路由，` +
    `移除 ${confirmed.removedLocalMappingCount} 个未进入候选清单的本地映射，并保留 ${confirmed.quarantinedPlugins} 个隔离项。` +
    `${confirmed.preflightedHosts} 个候选架构宿主已完成无业务调用预检。确定进入全局维护并替换活动路由吗？`,
  )) return
  let result: PluginReloadResult | undefined
  const outcome = await runPrimaryThenRefresh(async () => {
    result = await invoke<PluginReloadResult>('reload_plugins', { expectedPlanId: confirmed.planId })
    pluginUpdates.value = null
    appUpdate.value = null
  }, ['status', 'inventory', 'deployment'])
  if (outcome.succeeded && result) {
    showPrimaryActionSuccess(
      `插件目录已重新验签，${result.preflightedHosts} 个架构宿主预检通过，当前路由包含 ${result.serviceCount} 个服务；${result.quarantinedPlugins} 个无效项保持隔离。`,
      outcome.refreshed,
    )
  }
}

async function refreshPluginsAfterMapping() {
  pluginUpdates.value = null
  appUpdate.value = null
  await refreshControlState(['status', 'inventory', 'deployment'])
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
  const newPlugins = available.filter((item) => !item.installedVersion)
  const upgrades = available.filter((item) => item.installedVersion)
  const withdrawn = result.updates.filter((item) => item.installedVersionWithdrawn)
  const blocked = result.updates.filter((item) => item.installBlocker)
  const rollbackVersions = result.updates.reduce((count, item) => count + item.rollbackVersionCount, 0)
  if (result.updates.length === 0) {
    notice.value = '签名仓库当前没有可展示的插件。'
  } else if (withdrawn.length > 0) {
    notice.value = `发现 ${withdrawn.length} 个已安装插件版本已被签名仓库撤回，请精确检查后升级、受控回退或卸载。`
  } else if (available.length === 0) {
    notice.value = blocked.length
      ? `仓库目录已验证，但有 ${blocked.length} 个候选被本机同名能力或异常目录阻止。`
      : rollbackVersions > 0
        ? `当前插件已是最新版本；精确查询中有 ${rollbackVersions} 个受控回退版本可选。`
        : '仓库目录已验证，当前没有与本机 Desktop 兼容的新插件或更新。'
  } else {
    notice.value = `仓库目录已验证：${newPlugins.length} 个新插件、${upgrades.length} 个更新可安装，请确认明确版本后继续。`
  }
}

async function installFromCatalog(pluginId: string, version?: string, installPlanId?: string, action: CatalogInstallAction = 'upgrade') {
  if (!requireCleanProjectDrafts('变更签名插件版本')) return
  if (!pluginId.trim() || !version || !installPlanId) {
    error.value = '请先检查仓库并选择明确的插件版本。'
    return
  }
  if (action === 'rollback' && !window.confirm(`确定将插件「${pluginId}」回退到 ${version} 吗？这只替换插件程序，不会恢复设备状态或业务数据。`)) return
  let result: PluginInstallResult | undefined
  const outcome = await runPrimaryThenRefresh(async () => {
    result = await invoke<PluginInstallResult>('install_plugin_from_catalog', {
      pluginId,
      version,
      expectedPlanId: installPlanId,
    })
    pluginUpdates.value = null
    appUpdate.value = null
  }, ['status', 'inventory', 'deployment'])
  if (result) {
    const actionLabel = action === 'rollback' ? '回退到' : result.replacedExisting ? '更新到' : '安装为'
    showPrimaryActionSuccess(
      `${result.pluginId} 已从签名仓库${actionLabel} ${result.pluginVersion}，${result.preflightedHosts} 个架构宿主预检通过并热加载。`,
      outcome.refreshed,
    )
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
    notice.value = `发现签名更新 ${result.version}，但有 ${result.capabilityBlockers} 个插件或本地映射未声明兼容，或未通过完整性检查。`
  } else if (result.available) {
    notice.value = `发现签名更新 ${result.version}，安装前可以查看发布说明。`
  } else {
    notice.value = `当前 ${result.currentVersion} 已是最新版本。`
  }
}

async function installAppUpdate() {
  if (!requireCleanProjectDrafts('安装应用更新')) return
  if (!appUpdate.value?.available || !appUpdate.value.compatible || !appUpdate.value.installPlanId) {
    error.value = appUpdate.value?.available
      ? appUpdate.value.compatible
        ? '应用更新确认状态已失效，请重新检查更新。'
        : '当前插件或本地映射集合与目标 Desktop 版本不兼容，请先修复对应能力。'
      : '请先检查并确认存在可用更新。'
    return
  }
  const expectedPlanId = appUpdate.value.installPlanId
  let installHandoffStarted = false
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
      installHandoffStarted = true
      updateProgress.value = '正在启动系统安装程序…'
    }
  }
  const completed = await run(
    () => invoke('install_app_update', { expectedPlanId, onEvent }),
    '更新已安装，客户端即将重新启动。',
  )
  if (!completed) {
    if (appUpdate.value?.installPlanId === expectedPlanId) {
      appUpdate.value.installPlanId = undefined
    }
    updateProgress.value = installHandoffStarted
      ? '系统安装程序未能启动；当前版本与业务窗口已恢复，请重新检查更新后重试。'
      : '更新安装未完成；请根据错误提示重新检查更新后重试。'
    await refreshRuntimeStatus()
  }
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
  if (!requireCleanProjectDrafts('执行深度部署自检')) return
  let result: DeploymentCheckReport | undefined
  const outcome = await runPrimaryThenRefresh(async () => {
    result = await invoke<DeploymentCheckReport>('run_deployment_check', { deep: true })
    deploymentCheck.value = result
    deploymentCheckUnavailable.value = false
  }, ['status'])
  if (result) {
    const message = result.ready
      ? `${result.deep ? '深度' : '快速'}自检通过：${result.passed} 项正常，${result.warnings} 项提醒。`
      : `${result.deep ? '深度' : '快速'}自检发现 ${result.failures} 项阻塞问题，请按建议处理后重新检查。`
    showPrimaryActionSuccess(message, outcome.refreshed)
  }
}

async function exportDeploymentCheck() {
  if (!requireCleanProjectDrafts('导出深度部署自检记录')) return
  const destination = await save({
    defaultPath: `ssdev-deployment-check-${new Date().toISOString().slice(0, 10)}.json`,
    filters: [{ name: 'SSDEV 部署自检记录', extensions: ['json'] }],
  })
  if (typeof destination !== 'string') return
  let result: { bytes: number; report: DeploymentCheckReport } | undefined
  const outcome = await runPrimaryThenRefresh(async () => {
    result = await invoke<{ bytes: number; report: DeploymentCheckReport }>('export_deployment_check', { destination })
    deploymentCheck.value = result.report
    deploymentCheckUnavailable.value = false
  }, ['status'])
  if (result) {
    showPrimaryActionSuccess(
      `${result.report.deep ? '深度' : '快速'}部署自检已重新执行并导出（${(result.bytes / 1024).toFixed(1)} KiB）；这是脱敏的未签名现场记录，不替代生产切换证据。`,
      outcome.refreshed,
    )
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
        <span :class="['status-dot', { ready: Boolean(status) && !controlLoadFailed && !controlRefreshIncomplete && !runtimeStatusStale && !mappingWorkspaceUnverified, warning: Boolean(controlLoadFailed || controlRefreshIncomplete || error || ssoError || runtimeStatusStale || mappingWorkspaceUnverified) }]" />
        <span><strong>{{ controlLoadFailed ? '控制台初始化失败' : runtimeStatusStale ? '桌面通信中断' : controlRefreshIncomplete ? '操作已完成，状态待刷新' : mappingWorkspaceUnverified ? '映射清单待复核' : error || ssoError ? '需要处理' : status ? '桌面服务正常' : '正在连接' }}</strong><small>{{ controlLoadFailed ? '请重新加载核心项目状态' : runtimeStatusStale ? `状态连续 ${runtimeStatusHealth.consecutiveFailures} 次刷新失败` : controlRefreshIncomplete ? `${controlRefreshMissing.length} 类状态等待重新读取` : mappingWorkspaceUnverified ? '请在原生映射页重新读取当前清单' : `${status?.serviceCount ?? '—'} 个原生服务可用` }}</small></span>
      </div>
    </aside>

    <main class="workspace">
      <div v-if="notice || ssoError || error || controlLoadFailed || controlRefreshIncomplete || runtimeStatusStale || runtimeStatusRecovered" class="message-stack" aria-live="polite">
        <p v-if="notice" class="notice" role="status">{{ notice }}</p>
        <p v-if="runtimeStatusRecovered" class="notice" role="status">桌面核心通信已经恢复，运行状态已重新验证。</p>
        <div v-if="controlLoadFailed" class="runtime-status-alert" role="alert"><span>控制台未能读取完整项目状态。请重新加载；仍失败时重启客户端并查看日志。</span><button type="button" :disabled="controlLoadActive" @click="retryControlLoad">{{ controlLoadActive ? '正在加载…' : '重新加载' }}</button></div>
        <div v-if="controlRefreshIncomplete" class="runtime-status-alert" role="alert"><span>上一项操作已经完成，但部分页面状态尚未重新读取。请勿重复执行该操作，刷新状态后再继续。</span><button type="button" :disabled="busy || controlRefreshActive" @click="retryControlStateRefresh">{{ controlRefreshActive ? '正在刷新…' : '刷新状态' }}</button></div>
        <div v-if="runtimeStatusStale" class="runtime-status-alert" role="alert"><span>桌面核心状态连续刷新失败，当前页面显示的数据可能已经过期。请立即重试；仍失败时重启客户端并查看日志。</span><button type="button" :disabled="busy || statusRefreshActive" @click="retryRuntimeStatus">立即重试</button></div>
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
          <span class="phase">{{ controlLoadFailed ? '初始化失败' : runtimeStatusStale ? '状态不可用' : controlRefreshIncomplete ? '状态待刷新' : mappingWorkspaceUnverified ? '映射待复核' : status?.acceptingPluginInvocations ? '服务就绪' : '正在初始化' }}</span>
        </header>

        <section class="summary-grid" aria-label="关键运行状态">
          <article><span>桌面通信</span><strong>{{ runtimeStatusStale ? '连接中断' : status?.transport ?? '连接中' }}</strong><small>{{ runtimeStatusStale ? '无法确认本地能力状态；请立即重试' : '不开放 localhost 端口' }}</small></article>
          <article><span>原生服务</span><strong>{{ status?.serviceCount ?? '—' }}</strong><small>{{ status?.pluginCount ?? '—' }} 个插件 · x86 / x64 隔离</small></article>
          <article><span>业务页面</span><strong>{{ businessFrontendReadiness.label }}</strong><small>{{ businessFrontendReadiness.detail }}</small></article>
          <article><span>部署状态</span><strong>{{ deploymentReadiness.label }}</strong><small>{{ runtimeStatusStale ? '桌面通信中断，部署状态无法确认' : deploymentReadiness.detail }}</small></article>
        </section>

        <div class="overview-layout">
          <section class="launch-panel">
            <div>
              <p class="eyebrow">QUICK START</p>
              <h2>进入业务系统</h2>
              <p>{{ snapshot?.config.website || '尚未配置默认业务地址' }}</p>
            </div>
            <button class="primary large" type="button" :disabled="busy || controlLoadFailed || controlRefreshIncomplete || runtimeStatusStale || configDraftDirty || !snapshot?.config.website" @click="openBusiness">启动默认环境</button>
            <div v-if="snapshot?.config.allowSwitch && snapshot.config.environments.length" class="environment-shortcuts">
              <button
                v-for="environment in snapshot.config.environments"
                :key="`${environment.name}:${environment.url}`"
                type="button"
                :disabled="busy || controlLoadFailed || controlRefreshIncomplete || runtimeStatusStale || configDraftDirty || !environment.name || !environment.url"
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

        <section v-if="controlLoadFailed || controlRefreshIncomplete || runtimeStatusStale || mappingWorkspaceUnverified || projectDeliveryDraftDirty || needsDeepDeploymentCheck || deploymentCheck?.failures || status?.businessTimedOutWindows || status?.pluginPreflightFailures || status?.pluginApiBaselineFailures || status?.pluginHosts.some(pluginHostNeedsAttention) || inventory?.quarantined.length || ssoError" class="attention-panel">
          <div><p class="eyebrow">ATTENTION</p><h2>待处理事项</h2></div>
          <ul>
            <li v-if="controlLoadFailed"><strong>控制台初始化未完成，不能确认当前项目和原生能力状态</strong><button type="button" :disabled="controlLoadActive" @click="retryControlLoad">重新加载</button></li>
            <li v-if="controlRefreshIncomplete"><strong>已完成的操作仍有 {{ controlRefreshMissing.length }} 类页面状态待刷新，请勿重复执行</strong><button type="button" :disabled="busy || controlRefreshActive" @click="retryControlStateRefresh">刷新状态</button></li>
            <li v-if="runtimeStatusStale"><strong>桌面核心通信中断，所有运行状态和部署结论均已标记为未知</strong><button type="button" :disabled="busy || statusRefreshActive" @click="retryRuntimeStatus">重新连接</button></li>
            <li v-if="mappingWorkspaceUnverified"><strong>原生映射工作台清单尚未复核，相关项目操作已暂停</strong><button type="button" @click="activeSection = 'native'">重新读取映射</button></li>
            <li v-if="configDraftDirty"><strong>项目配置有未保存更改，业务启动、原生能力变更和项目交付操作已暂停</strong><button type="button" @click="activeSection = 'configuration'">处理配置</button></li>
            <li v-if="mappingDraftDirty"><strong>原生映射工作台有未保存更改，插件变更、应用更新和项目交付操作已暂停</strong><button type="button" @click="activeSection = 'native'">处理映射</button></li>
            <li v-if="needsDeepDeploymentCheck"><strong>快速检查已通过，正式交付前还需验证当前 x86/x64 插件宿主</strong><button type="button" :disabled="busy || projectStateUnverified || projectDeliveryDraftDirty" @click="runDeploymentCheck">立即深度自检</button></li>
            <li v-if="deploymentCheck?.failures"><strong>部署自检存在 {{ deploymentCheck.failures }} 项阻塞问题</strong><button type="button" @click="activeSection = 'security'">查看自检</button></li>
            <li v-if="status?.businessTimedOutWindows"><strong>{{ status.businessTimedOutWindows }} 个业务页面加载失败或未到达原生 IPC</strong><button type="button" :disabled="busy || controlStateUnverified" @click="retryTimedOutBusinessWindows">仅重试失败窗口</button></li>
            <li v-if="inventory?.quarantined.length"><strong>{{ inventory.quarantined.length }} 个插件已隔离</strong><button type="button" @click="activeSection = 'plugins'">查看插件</button></li>
            <li v-if="status?.pluginPreflightFailures"><strong>{{ status.pluginPreflightFailures }} 次宿主预检失败</strong><button type="button" @click="activeSection = 'security'">查看诊断</button></li>
            <li v-if="status?.pluginApiBaselineFailures"><strong>签名插件契约基线有 {{ status.pluginApiBaselineFailures }} 次持久化失败</strong><button type="button" @click="activeSection = 'security'">查看诊断</button></li>
            <li v-if="status?.pluginHosts.some(pluginHostNeedsAttention)"><strong>{{ status.pluginHosts.filter(pluginHostNeedsAttention).length }} 个插件宿主等待恢复</strong><button type="button" @click="activeSection = 'security'">定位宿主</button></li>
            <li v-if="ssoError"><strong>最近一次 SSO 登录失败</strong><button type="button" @click="activeSection = 'security'">查看详情</button></li>
          </ul>
        </section>
      </section>

      <section v-show="activeSection === 'configuration'" class="page" aria-labelledby="configuration-title">
        <header class="section-header"><div><p class="eyebrow">PROJECT CONFIGURATION</p><h1 id="configuration-title">项目配置</h1><p>管理业务环境、来源边界和桌面启动行为。</p></div><div class="header-actions"><span v-if="configDraftDirty" class="section-chip">配置未保存</span><button type="button" :disabled="busy" @click="importConfig">导入配置</button><button type="button" :disabled="busy || controlStateUnverified || configDraftDirty" @click="exportConfig">导出配置</button></div></header>
        <section v-if="configImportPreview" class="config-import-preview" aria-label="配置导入变更预览">
          <header>
            <div><p class="eyebrow">CONFIG IMPORT PLAN</p><h2>{{ configImportPreview.configChanged ? '核对配置变更' : '配置内容没有变化' }}</h2><p>确认时会重新读取文件并核对当前已保存配置；任一变化都会要求重新预检。</p></div>
            <div class="config-import-actions"><button type="button" :disabled="busy" @click="cancelConfigImport">取消</button><button class="primary" type="button" :disabled="busy || controlStateUnverified" @click="confirmConfigImport">{{ configImportPreview.configChanged ? '确认并应用配置' : '确认无须替换' }}</button></div>
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
            <span :class="{ changed: configImportPreview.businessSurfaceResetRequired }">业务页面：{{ configImportPreview.businessSurfaceResetRequired ? '应用后关闭' : '保持打开' }}</span>
          </div>
          <details v-if="configImportPreview.candidateEnvironments.length" class="config-import-environments"><summary>查看目标业务环境（{{ configImportPreview.candidateEnvironments.length }}）</summary><ul><li v-for="environment in configImportPreview.candidateEnvironments" :key="`${environment.name}:${environment.url}`"><strong>{{ environment.name }}</strong><code>{{ environment.url }}</code></li></ul></details>
        </section>
        <section class="project-bundle-panel">
          <div class="project-bundle-copy"><p class="eyebrow">PROJECT DELIVERY</p><h2>项目部署包</h2><p>将当前配置、签名插件和本地映射作为一个交付单元迁移到目标 Windows 机器；正式导入要求同目录组织签名旁签。</p></div>
          <div class="project-bundle-actions"><button type="button" :disabled="busy || projectStateUnverified || projectDeliveryDraftDirty" @click="exportProjectBundle">导出当前项目</button><button class="primary" type="button" :disabled="busy || projectStateUnverified || projectDeliveryDraftDirty" @click="inspectProjectBundle">选择项目包并预检</button></div>
          <div v-if="projectBundlePreview" class="project-bundle-preview">
            <header><div><strong>变更计划已验证，可以导入</strong><small>由客户端 {{ projectBundlePreview.createdByVersion }} 创建 · schema {{ projectBundlePreview.schemaVersion }} · {{ projectBundlePreview.signatureVerified ? `组织签名 ${projectBundlePreview.signatureKeyId}` : '调试态未签名' }}</small></div><button class="primary" type="button" :disabled="busy || projectStateUnverified" @click="importSelectedProjectBundle">确认计划并切换项目</button></header>
            <div class="bundle-summary"><span><strong>{{ projectBundlePreview.businessOrigins }}</strong>业务来源</span><span><strong>{{ projectBundlePreview.signedPlugins }}</strong>签名插件</span><span><strong>{{ projectBundlePreview.localMappings }}</strong>本地映射</span><span><strong>{{ projectBundlePreview.serviceCount }}</strong>原生服务</span><span><strong>{{ projectBundlePreview.preflightedHosts }}</strong>宿主预检</span></div>
            <div class="project-change-summary"><span :class="{ changed: projectBundlePreview.configPreview.configChanged }">配置{{ projectBundlePreview.configPreview.configChanged ? '更新' : '不变' }}</span><span>新增 {{ projectBundlePreview.installCount }}</span><span>升级 {{ projectBundlePreview.upgradeCount }}</span><span>修复/替换 {{ projectBundlePreview.replaceCount }}</span><span>保留本机 {{ projectBundlePreview.retainedCount }}</span><span class="changed">业务页面：切换后关闭</span></div>
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
            <ul><li v-for="component in projectBundlePreview.components" :key="component.pluginId"><span><strong>{{ component.pluginId }}</strong><small>{{ component.source === 'signed-package' ? `签名插件 ${component.version ?? ''} · Desktop ${component.desktopVersionRequirement ?? '未声明'}${component.action === 'install' ? '' : ` · API 新增 ${component.apiAdditionCount} / 原生复核 ${component.apiReviewChangeCount}`}` : '本地动态映射' }}</small></span><em><b :class="`plan-action ${component.action}`">{{ projectActionLabels[component.action] }}</b>{{ component.serviceCount }} 个服务</em></li></ul>
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
          <form v-if="snapshot" :inert="busy || controlStateUnverified || Boolean(configImportPreview)" @submit.prevent="saveConfig">
            <label><span>业务系统地址</span><input v-model.trim="snapshot.config.website" type="url" maxlength="4096" placeholder="http://project.internal" /></label>
            <label><span>默认租户</span><input v-model.trim="snapshot.config.tenantId" type="text" placeholder="可选" /></label>
            <fieldset class="environments">
              <legend>业务环境</legend><p>默认项用于首页快捷启动；启用切换后，可直接打开任一环境。</p>
              <div v-for="(environment, index) in snapshot.config.environments" :key="index" class="environment-row">
                <label class="environment-default" title="设为默认环境"><input v-model="snapshot.config.website" type="radio" :value="environment.url" /><span>默认</span></label>
                <input v-model.trim="environment.name" type="text" maxlength="128" placeholder="环境名称" />
                <input :value="environment.url" type="url" maxlength="4096" placeholder="http://project.internal" @input="changeEnvironmentUrl(environment, ($event.target as HTMLInputElement).value)" />
                <button type="button" :disabled="busy || controlLoadFailed || controlRefreshIncomplete || runtimeStatusStale || configDraftDirty || !snapshot.config.allowSwitch || !environment.name || !environment.url" @click="openEnvironment(environment)">打开</button>
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
            <div class="actions"><button class="primary" type="submit" :disabled="busy || controlStateUnverified || !configDraftDirty">保存配置</button><button v-if="configDraftDirty" type="button" :disabled="busy || controlStateUnverified" @click="discardConfigChanges">放弃更改</button><button type="button" :disabled="busy || controlStateUnverified || configDraftDirty" @click="openBusiness">进入业务系统</button></div>
            <small class="config-path">配置位置：{{ snapshot.path }}</small>
          </form>
        </section>
        <section class="compact-panel"><div><h2>业务窗口维护</h2><p>刷新不会清除登录状态；站点数据清理必须先检查影响并单独确认。</p></div><div class="actions"><button type="button" :disabled="busy" @click="reloadBusiness">刷新业务窗口</button><button type="button" :disabled="busy" @click="inspectBusinessDataClear">检查清理影响</button></div></section>
        <section v-if="businessDataClearPreview" class="business-data-clear-preview" aria-label="站点数据清理影响">
          <header><div><p class="eyebrow">DESTRUCTIVE MAINTENANCE</p><h2>确认清理全部 WebView 站点数据</h2><p>确认时会重新核对项目来源和窗口集合；发生变化则停止操作并要求重新检查。</p></div><div class="business-data-clear-actions"><button type="button" :disabled="busy" @click="cancelBusinessDataClear">取消</button><button class="danger-link" type="button" :disabled="busy" @click="confirmBusinessDataClear">确认清理且不可恢复</button></div></header>
          <div class="business-data-clear-impact"><span><small>当前配置来源</small><strong>{{ businessDataClearPreview.configuredBusinessOrigins }}</strong></span><span><small>业务窗口</small><strong>{{ businessDataClearPreview.businessWindows }}</strong></span><span><small>悬浮页面</small><strong>{{ businessDataClearPreview.floatingWindows }}</strong></span></div>
          <p>该操作清除应用 WebView 配置文件中的 Cookie、登录状态、缓存和本地存储，并关闭所有业务窗口与悬浮页面；设备操作和业务系统中的服务端数据不会回退。</p>
        </section>
      </section>

      <section v-show="activeSection === 'native'" class="page page-native" aria-labelledby="native-title">
        <header class="section-header"><div><p class="eyebrow">NATIVE MAPPING STUDIO</p><h1 id="native-title">原生映射</h1><p>发现本机组件、配置调用映射，并在发布前完成受控调试。</p></div><span class="section-chip">本机管理员能力</span></header>
        <LocalMappingStudio
          :key="mappingWorkspaceRevision"
          :disabled="busy || controlStateUnverified || configDraftDirty"
          @changed="refreshPluginsAfterMapping"
          @dirty="mappingDraftDirty = $event"
          @state-unverified="mappingWorkspaceUnverified = $event"
        />
      </section>

      <section v-show="activeSection === 'plugins'" class="page" aria-labelledby="plugins-title" :inert="projectStateUnverified || projectDeliveryDraftDirty">
        <header class="section-header"><div><p class="eyebrow">PLUGIN MANAGEMENT</p><h1 id="plugins-title">插件管理</h1><p>管理签名插件包、本机动态映射和仓库更新。</p></div><div class="header-actions"><button type="button" :disabled="busy" @click="selectPluginPackage">选择签名插件</button><button type="button" :disabled="busy || controlStateUnverified" @click="reloadPlugins">重新扫描</button></div></header>
        <section v-if="pluginPackagePreview" class="plugin-package-preview" aria-label="签名插件安装预览">
          <header>
            <div><p class="eyebrow">SIGNED PLUGIN PLAN</p><h2>核对{{ projectActionLabels[pluginPackagePreview.action] }}计划</h2><p>确认时会重新读取和验签安装包，并复核当前插件状态；任一变化都会停止安装。</p></div>
            <div class="plugin-package-actions"><button type="button" :disabled="busy" @click="cancelPluginPackageInstall">取消</button><button class="primary" type="button" :disabled="busy || projectStateUnverified" @click="confirmPluginPackageInstall">确认并{{ projectActionLabels[pluginPackagePreview.action] }}</button></div>
          </header>
          <div class="plugin-package-identity"><span><small>插件</small><strong>{{ pluginPackagePreview.displayName }}</strong><code>{{ pluginPackagePreview.pluginId }}</code></span><span><small>版本变化</small><strong>{{ pluginPackagePreview.currentVersion ?? '未安装' }} → {{ pluginPackagePreview.pluginVersion }}</strong><b :class="`plan-action ${pluginPackagePreview.action}`">{{ projectActionLabels[pluginPackagePreview.action] }}</b></span><span><small>Desktop 兼容范围</small><strong>{{ pluginPackagePreview.desktopVersionRequirement }}</strong></span></div>
          <div class="plugin-package-summary"><span><strong>{{ pluginPackagePreview.serviceCount }}</strong>个服务</span><span><strong>{{ pluginPackagePreview.methodCount }}</strong>个方法</span><span v-if="pluginPackagePreview.currentVersion"><strong>{{ pluginPackagePreview.apiAdditionCount }}</strong>项 API 兼容新增</span><span v-if="pluginPackagePreview.currentVersion"><strong>{{ pluginPackagePreview.apiReviewChangeCount }}</strong>项原生复核</span><span><strong>{{ pluginPackagePreview.preflightedHosts }}</strong>个宿主已预检</span></div>
          <ul><li v-for="service in pluginPackagePreview.services" :key="service.serviceId"><code>{{ service.serviceId }}</code><span>{{ service.architecture }} · {{ service.methodCount }} 个方法</span></li></ul>
        </section>
        <section class="plugin-inventory" aria-label="已安装插件">
          <div><p class="eyebrow">VERIFIED INVENTORY</p><h2>已验证插件</h2><p>无效项不会进入服务路由；动态映射始终与主进程隔离。</p><div class="inventory-count"><strong>{{ inventory?.plugins.length ?? '—' }}</strong><span>个可用插件</span></div></div>
          <div class="plugin-list">
            <form class="catalog-install" @submit.prevent="checkPluginUpdates(catalogPluginId)"><input v-model.trim="catalogPluginId" type="text" placeholder="按插件 ID 精确查询（可选）" /><button type="submit" :disabled="busy">查询版本</button><button type="button" :disabled="busy" @click="checkPluginUpdates()">浏览仓库并检查更新</button></form>
            <div v-if="pluginUpdates" class="plugin-update-results" aria-live="polite">
              <header><strong>已验证签名目录</strong><small>{{ pluginUpdates.updates.length }} 个插件 · 目录有效期至 {{ new Date(pluginUpdates.catalogExpiresAt * 1000).toLocaleString() }}</small></header>
              <div v-for="update in pluginUpdates.updates" :key="update.pluginId"><span><strong>{{ update.pluginId }}<b v-if="!update.installedVersion && update.catalogAvailable" class="catalog-new">新插件</b></strong><small>已安装 {{ update.installedVersion ?? '无' }} · 当前客户端可用 {{ update.availableVersion ?? '无' }}<template v-if="update.installedVersionWithdrawn"> · 当前版本已撤回（{{ update.withdrawalReason ? withdrawalReasonLabels[update.withdrawalReason] : '原因未分类' }}）</template><template v-if="update.compatibilityLimited"> · 仓库最新 {{ update.latestCatalogVersion }} 需要其他 Desktop 版本</template></small></span><button v-if="update.updateAvailable && update.availableVersion && update.installPlanId" type="button" :disabled="busy" @click="installFromCatalog(update.pluginId, update.availableVersion, update.installPlanId, update.installedVersion ? 'upgrade' : 'install')">{{ update.installedVersion ? `安装更新 ${update.availableVersion}` : `安装 ${update.availableVersion}` }}</button><em v-else>{{ update.installBlocker === 'local-mapping-conflict' ? '同名本地映射占用，请先调整' : update.installBlocker === 'invalid-target-state' ? '本机同名插件目录异常，请先处理隔离项' : update.installedVersionWithdrawn ? '当前版本已撤回，请升级、受控回退或卸载' : update.catalogAvailable ? (update.compatibilityLimited ? '新版本与当前客户端不兼容' : '已是最新版本') : '仓库未收录' }}</em><details v-if="update.rollbackVersions.length" class="plugin-rollback-options"><summary>受控回退版本（{{ update.rollbackVersionCount }}）</summary><p>仅列出当前 Desktop 兼容且仍可安装的签名版本；回退前仍会重新验签、预检宿主并核对本机状态。</p><ul><li v-for="rollback in update.rollbackVersions" :key="rollback.version"><span><strong>{{ rollback.version }}</strong><small>Desktop {{ rollback.desktopVersionRequirement }}</small></span><button class="danger-link" type="button" :disabled="busy" @click="installFromCatalog(update.pluginId, rollback.version, rollback.installPlanId, 'rollback')">回退到此版本</button></li></ul><small v-if="update.rollbackVersionCount > update.rollbackVersions.length">仅显示最近 {{ update.rollbackVersions.length }} 个版本。</small></details></div>
            </div>
            <article v-for="plugin in inventory?.plugins ?? []" :key="plugin.pluginId">
              <header><span><strong>{{ plugin.displayName }}</strong><small>{{ plugin.pluginId }} · {{ plugin.source === 'local-mapping' ? '本机动态映射' : `${plugin.version ?? '未知版本'} · Desktop ${plugin.desktopVersionRequirement ?? '未声明'}` }}</small></span><div v-if="plugin.source === 'signed-package'" class="plugin-actions"><button type="button" :disabled="busy" @click="checkPluginUpdates(plugin.pluginId)">检查更新</button><button class="danger-link" type="button" :disabled="busy" @click="uninstallSignedPlugin(plugin.pluginId)">卸载</button></div></header>
              <details v-for="service in plugin.services" :key="service.serviceId" class="service-mapping"><summary><code>{{ service.serviceId }}</code><span>{{ service.architecture }} / {{ service.mainType }} / {{ service.methodCount }} 个方法</span></summary><dl><div><dt>原生目标</dt><dd><code>{{ service.mainClass }}</code></dd></div><div><dt>调用约定</dt><dd>{{ service.callingConvention || '默认' }} · {{ service.charset || '默认字符集' }}</dd></div><div><dt>服务策略</dt><dd>{{ service.timeoutMs || '默认' }} ms · {{ service.cacheable ? '缓存实例' : '按需实例' }} · {{ service.dependencyCount }} 个依赖</dd></div></dl><div v-for="method in service.methods" :key="`${service.serviceId}:${method.requestName}`" class="method-mapping"><code>{{ method.requestName }}</code><span aria-hidden="true">→</span><code>{{ method.nativeName }}</code><small>{{ method.returnType || '默认返回类型' }} · {{ method.parameterCount }} 参数 · {{ method.timeoutMs || '默认' }} ms</small></div></details>
            </article>
            <p v-if="inventory && inventory.plugins.length === 0" class="empty">尚未安装通过验签的插件。</p>
            <details v-if="inventory?.quarantined.length" class="quarantined" open><summary>{{ inventory.quarantined.length }} 个插件已隔离</summary><ul><li v-for="failure in inventory.quarantined" :key="failure">{{ failure }}</li></ul></details>
          </div>
        </section>
      </section>

      <section v-show="activeSection === 'security'" class="page" aria-labelledby="security-title">
        <header class="section-header"><div><p class="eyebrow">SECURITY & DIAGNOSTICS</p><h1 id="security-title">安全与诊断</h1><p>快速检查用于日常状态刷新；正式交付前执行深度自检，实际启动当前插件宿主完成 Health 验证。</p></div><div class="header-actions"><button class="primary" type="button" :disabled="busy || projectStateUnverified || projectDeliveryDraftDirty" @click="runDeploymentCheck">深度自检</button><button type="button" :disabled="busy || projectStateUnverified || projectDeliveryDraftDirty" @click="exportDeploymentCheck">导出深度自检记录</button><button type="button" :disabled="busy" @click="openDiagnosticsDirectory">打开日志目录</button><button type="button" :disabled="busy || !status?.diagnosticsAvailable" @click="exportDiagnostics">导出脱敏诊断包</button></div></header>
        <section v-if="deploymentCheck" :class="['deployment-check', { ready: deploymentCheck.ready && !controlLoadFailed && !controlRefreshIncomplete && !runtimeStatusStale && !mappingWorkspaceUnverified && !projectDeliveryDraftDirty }]" aria-label="部署自检结果">
          <header>
            <div><p class="eyebrow">{{ deploymentCheck.deep ? 'DEEP DEPLOYMENT CHECK' : 'QUICK DEPLOYMENT CHECK' }}</p><h2>{{ controlRefreshIncomplete ? '操作后的项目状态尚未完整刷新' : runtimeStatusStale ? '桌面核心通信中断，当前自检结论已过期' : mappingWorkspaceUnverified ? '原生映射工作台清单尚未复核' : configDraftDirty ? '项目配置草稿尚未保存，当前结论只对应有效配置' : mappingDraftDirty ? '原生映射草稿尚未保存，当前结论只对应已激活映射' : deploymentCheck.ready ? (deploymentCheck.deep ? '当前机器通过深度交付检查' : '快速检查未发现阻塞') : '部署条件尚未满足' }}</h2><p>{{ deploymentCheck.passed }} 项正常 · {{ deploymentCheck.warnings }} 项提醒 · {{ deploymentCheck.failures }} 项阻塞</p></div>
            <span>{{ controlRefreshIncomplete || runtimeStatusStale || mappingWorkspaceUnverified ? 'STATUS UNKNOWN' : projectDeliveryDraftDirty ? 'DRAFT NOT CHECKED' : deploymentCheck.ready ? (deploymentCheck.deep ? 'READY' : 'QUICK PASS') : 'ACTION REQUIRED' }}</span>
          </header>
          <div class="check-list">
            <article v-for="item in deploymentCheck.items" :key="item.id" :class="`check-${item.status}`">
              <i>{{ item.status === 'pass' ? '✓' : item.status === 'fail' ? '!' : item.status === 'warning' ? '△' : 'i' }}</i>
              <div><strong>{{ item.label }}</strong><p>{{ item.summary }}</p><small v-if="item.action">建议：{{ item.action }}</small></div>
            </article>
          </div>
        </section>
        <p v-if="controlRefreshIncomplete || runtimeStatusStale" class="stale-status-note">以下明细尚未在最近操作后全部复核，仅供定位，不代表当前完整运行状态。</p>
        <section :class="['diagnostic-grid', { stale: controlRefreshIncomplete || runtimeStatusStale }]" aria-label="详细运行状态">
          <article><span>插件调用背压</span><strong v-if="status?.globalPluginMaintenanceActive">全局维护中</strong><strong v-else>{{ status ? `${status.inFlightInvocations} / ${status.maxInFlightInvocations}` : '—' }}</strong><small>容量拒绝 {{ status?.rejectedInvocations ?? '—' }} · 槽超时 {{ status?.executionLaneTimeouts ?? '—' }} · 维护拒绝 {{ status?.maintenanceRejectedInvocations ?? '—' }}</small></article>
          <article><span>隔离宿主监督</span><strong>{{ status?.activePluginHosts ?? '—' }} 个活动宿主</strong><small>累计启动 {{ status?.pluginHostStarts ?? '—' }} · 失败 {{ status?.pluginHostStartFailures ?? '—' }}</small></article>
          <article><span>原生操作防重放</span><strong>{{ status?.trackedInvocationsAvailable ? (status.trackedInvocationsAccepting ? '持久协调可用' : '正在排空') : '不可用' }}</strong><small>{{ status?.trackedInvocationsAvailable ? `等待 ${status.trackedPendingOperations} · 可找回 ${status.trackedRetainedResults} · 落盘异常 ${status.trackedPersistenceFailures}` : status?.trackedInvocationsError ?? '状态尚未加载' }}</small></article>
          <article><span>插件信任</span><strong>{{ status?.pluginTrustMode === 'ed25519-strict' ? '严格签名' : '开发模式' }}</strong><small :title="status?.pluginRoot">{{ status ? `${status.trustKeyCount} 把密钥 · ${status.pluginApiBaselineCount} 个契约基线 · 基线写入失败 ${status.pluginApiBaselineFailures}` : '完整清单与 SHA-256 校验' }}</small></article>
          <article><span>安装事务</span><strong>{{ status?.recoveredPluginTransactions ? '已自动恢复' : '状态正常' }}</strong><small>已清理或回滚 {{ status?.recoveredPluginTransactions ?? '—' }} 项</small></article>
          <article><span>宿主预检</span><strong>{{ status?.pluginPreflightFailures ? '存在失败' : '状态正常' }}</strong><small>通过 {{ status?.preflightedPluginHosts ?? '—' }} · 失败 {{ status?.pluginPreflightFailures ?? '—' }}</small></article>
          <article><span>受控进程策略</span><strong>{{ status?.processPolicyEntries ?? '—' }} 项</strong><small>启动失败 {{ status?.managedProcessFailures ?? '—' }} · 不经过 Shell</small></article>
          <article><span>开机启动</span><strong>{{ status?.autoStartEnabled == null ? '状态未知' : status.autoStartEnabled ? '已启用' : '未启用' }}</strong><small :title="status?.autoStartError">{{ status?.autoStartError ?? '由本机系统机制管理' }}</small></article>
          <article><span>SSO 传输</span><strong>{{ ssoActive ? '登录处理中' : ssoError ? '最近失败' : 'HTTPS-only' }}</strong><small>禁止重定向 · 请求与响应均有上限</small></article>
          <article><span>业务来源策略</span><strong>{{ status?.originPolicy.allowConfiguredBusinessOrigins ? '项目地址兼容' : status?.originPolicy.enforced ? '发布方签名' : '开发模式' }}</strong><small :title="status?.originPolicyError">{{ status?.originPolicyError ?? `${status?.originPolicy.businessOrigins ?? '—'} 个来源 · HTTP ${status?.originPolicy.allowInsecureHttp ? '允许' : '禁止'}` }}</small></article>
          <article><span>隐私诊断日志</span><strong>{{ status?.diagnosticsAvailable ? '可用' : '不可用' }}</strong><small :title="status?.diagnosticsLogDir">{{ status?.diagnosticsError ?? `${status?.diagnostics?.logFiles ?? '—'} 个文件 · ${((status?.diagnostics?.logBytes ?? 0) / 1024).toFixed(1)} KiB` }}</small></article>
          <article><span>协议与兼容网关</span><strong>v{{ status?.protocolVersion ?? '—' }}</strong><small>宿主 v{{ status?.pluginHostProtocolVersion ?? '—' }} · HTTP 网关{{ status?.httpGatewayEnabled ? '已启用' : '关闭' }}</small></article>
        </section>
        <details v-if="status?.pluginHosts.length" class="host-health-panel" :open="status.pluginHosts.some(pluginHostNeedsAttention)">
          <summary><span><strong>插件宿主明细</strong><small>{{ status.pluginHosts.length }} 个插件/架构运行单元 · {{ status.pluginHosts.filter(pluginHostNeedsAttention).length }} 个等待恢复</small></span><em>仅显示稳定诊断码，不包含路径、调用参数或厂商错误</em></summary>
          <div class="host-health-list">
            <article v-for="host in status.pluginHosts" :key="`${host.pluginId}:${host.architecture}`" :class="`host-${host.state}`">
              <span><strong>{{ host.pluginId }}</strong><small>{{ host.architecture.toUpperCase() }} · {{ host.serviceCount }} 个服务</small></span>
              <div class="host-health-runtime"><span><b>{{ host.state === 'ready' ? '运行中' : host.state === 'restart-backoff' ? '启动退避' : host.state === 'retry-ready' ? '等待重试' : '按需待机' }}</b><small>累计失败 {{ host.failureCount }}<template v-if="host.lastFailureCode"> · {{ host.lastFailureCode }}</template></small><small v-if="pluginHostNeedsAttention(host)" class="host-health-advice">建议：{{ pluginHostAdvice(host) }}</small></span><button v-if="pluginHostNeedsAttention(host)" type="button" :disabled="busy" title="只重新启动隔离宿主并完成 Health，不调用 DLL、COM 或进程业务方法" @click="retryPluginHost(host)">恢复宿主</button></div>
            </article>
          </div>
        </details>
        <section class="maintenance-panel"><div><p class="eyebrow">CLIENT MAINTENANCE</p><h2>客户端维护</h2><p>{{ status?.appUpdateError ?? (status?.appUpdateConfigured ? '应用更新包必须通过签名验证，并与当前插件及本地映射兼容。' : '当前构建未配置生产更新端点。') }}</p></div><div class="maintenance-actions"><button type="button" :disabled="busy || !status?.appUpdateConfigured" @click="checkAppUpdate">检查应用更新</button><button class="primary" type="button" :disabled="busy || projectStateUnverified || projectDeliveryDraftDirty || !appUpdate?.available || !appUpdate.compatible || !appUpdate.installPlanId" @click="installAppUpdate">安装签名更新</button></div><details v-if="appUpdate?.available" class="update-details" open><summary>版本 {{ appUpdate.version }}{{ appUpdate.date ? ` · ${appUpdate.date}` : '' }}</summary><p v-if="!appUpdate.compatible">{{ appUpdate.capabilityBlockers }} 个插件或本地映射阻止升级；请先修复对应能力。</p><p>{{ appUpdate.notes || '此版本未提供发布说明。' }}</p><small v-if="updateProgress">{{ updateProgress }}</small></details></section>
        <section class="boundary"><div><p class="eyebrow">TRUST BOUNDARY</p><h2>第三方 DLL 永不进入主进程</h2></div><ol><li><b>业务 WebView</b><span>只调用受限的业务命令</span></li><li><b>Rust Controller</b><span>执行路由、策略、超时和监督</span></li><li><b>Plugin Host</b><span>加载 DLL、COM、OCX、EXE 或 BAT</span></li></ol></section>
      </section>
    </main>
  </div>
</template>
