<script setup lang="ts">
import { Channel, invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import { open, save } from '@tauri-apps/plugin-dialog'
import { onMounted, onUnmounted, ref } from 'vue'

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
  diagnostics?: {
    logFiles: number
    logBytes: number
    oversizedEvents: number
    writeFailures: number
  }
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
    displayName: string
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
    catalogAvailable: boolean
    updateAvailable: boolean
  }>
}

type AppUpdateCheck = {
  configured: boolean
  currentVersion: string
  available: boolean
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
    const [bridge, config, plugins] = await Promise.all([
      invoke<BridgeStatus>('bridge_status'),
      invoke<ConfigSnapshot>('desktop_config'),
      invoke<PluginInventory>('plugin_inventory'),
    ])
    status.value = bridge
    snapshot.value = config
    inventory.value = plugins
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
    () => invoke('save_desktop_config', { config: snapshot.value?.config }),
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
    snapshot.value = await invoke<ConfigSnapshot>('import_desktop_config', { source })
  }, '配置已校验并导入；已有业务窗口已关闭。')
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

async function openBusiness() {
  await run(() => invoke('open_business_window'), '业务窗口已启动。')
}

async function openEnvironment(environment: EnvironmentConfig) {
  if (!snapshot.value) return
  await run(async () => {
    await invoke('save_desktop_config', { config: snapshot.value?.config })
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
    ;[status.value, inventory.value] = await Promise.all([
      invoke<BridgeStatus>('bridge_status'),
      invoke<PluginInventory>('plugin_inventory'),
    ])
  }, '')

  if (result) {
    const action = result.replacedExisting ? '升级' : '安装'
    notice.value = `${result.pluginId} ${result.pluginVersion} 已${action}，${result.preflightedHosts} 个架构宿主预检通过，当前共 ${result.serviceCount} 个服务已热加载。`
  }
}

async function reloadPlugins() {
  await run(async () => {
    await invoke('reload_plugins')
    ;[status.value, inventory.value] = await Promise.all([
      invoke<BridgeStatus>('bridge_status'),
      invoke<PluginInventory>('plugin_inventory'),
    ])
  }, '插件目录已重新校验并热加载。')
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
  if (result.updates.length === 0) {
    notice.value = '当前没有已安装插件可检查。'
  } else if (available.length === 0) {
    notice.value = '签名仓库中未发现可安装的新版本。'
  } else {
    notice.value = `发现 ${available.length} 个可安装的插件版本，请确认目标版本后安装。`
  }
}

async function installFromCatalog(pluginId: string, version?: string) {
  if (!pluginId.trim() || !version) {
    error.value = '请先检查仓库并选择明确的插件版本。'
    return
  }
  let result: PluginInstallResult | undefined
  await run(async () => {
    result = await invoke<PluginInstallResult>('install_plugin_from_catalog', {
      pluginId,
      version,
    })
    ;[status.value, inventory.value, pluginUpdates.value] = await Promise.all([
      invoke<BridgeStatus>('bridge_status'),
      invoke<PluginInventory>('plugin_inventory'),
      invoke<PluginUpdateCheck>('check_plugin_updates', { pluginId }),
    ])
  }, '')
  if (result) {
    const action = result.replacedExisting ? '更新' : '安装'
    notice.value = `${result.pluginId} ${result.pluginVersion} 已从签名仓库${action}，${result.preflightedHosts} 个架构宿主预检通过并热加载。`
  }
}

async function checkAppUpdate() {
  let result: AppUpdateCheck | undefined
  await run(async () => {
    result = await invoke<AppUpdateCheck>('check_app_update')
    appUpdate.value = result
  }, '')
  if (!result) return
  if (!result.configured) {
    notice.value = '当前构建未配置生产更新端点与公钥。'
  } else if (result.available) {
    notice.value = `发现签名更新 ${result.version}，安装前可以查看发布说明。`
  } else {
    notice.value = `当前 ${result.currentVersion} 已是最新版本。`
  }
}

async function installAppUpdate() {
  if (!appUpdate.value?.available) {
    error.value = '请先检查并确认存在可用更新。'
    return
  }
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
    () => invoke('install_app_update', { onEvent }),
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
</script>

<template>
  <main class="shell">
    <header class="hero">
      <div>
        <p class="eyebrow">SSDEV DESKTOP · NEXT</p>
        <h1>本地能力控制台</h1>
        <p class="lede">Tauri 只负责可信桌面边界，业务插件在隔离进程中运行。</p>
      </div>
      <span class="phase">等待外部验收</span>
    </header>

    <section class="status-grid" aria-label="运行状态">
      <article>
        <span>桌面通信</span>
        <strong>{{ status?.transport ?? '正在连接…' }}</strong>
        <small>无 localhost 端口</small>
      </article>
      <article>
        <span>插件隔离</span>
        <strong>x86 / x64</strong>
        <small>每个插件独立宿主</small>
      </article>
      <article>
        <span>协议版本</span>
        <strong>v{{ status?.protocolVersion ?? '—' }}</strong>
        <small>业务桥接；内部宿主协议 v{{ status?.pluginHostProtocolVersion ?? '—' }}</small>
      </article>
      <article>
        <span>HTTP 兼容网关</span>
        <strong>{{ status?.httpGatewayEnabled ? '已启用' : '默认关闭' }}</strong>
        <small>仅为外部浏览器保留</small>
      </article>
      <article>
        <span>已注册服务</span>
        <strong>{{ status?.serviceCount ?? '—' }}</strong>
        <small>隔离 {{ status?.pluginLoadFailures ?? '—' }} 个无效插件</small>
      </article>
      <article>
        <span>插件调用背压</span>
        <strong v-if="status?.globalPluginMaintenanceActive">正在全局维护</strong>
        <strong v-else-if="status?.activePluginMaintenances">{{ status.activePluginMaintenances }} 个插件正在安全热更新</strong>
        <strong v-else-if="status?.acceptingPluginInvocations">{{ status.inFlightInvocations }} / {{ status.maxInFlightInvocations }}</strong>
        <strong v-else>{{ status ? '正在安全退出' : '—' }}</strong>
        <small>容量拒绝 {{ status?.rejectedInvocations ?? '—' }} 次；执行槽超时 {{ status?.executionLaneTimeouts ?? '—' }} 次；热更新拒绝 {{ status?.maintenanceRejectedInvocations ?? '—' }} 次；退出期拒绝 {{ status?.shutdownRejectedInvocations ?? '—' }} 次；等待者脱离 {{ status?.callerDetachments ?? '—' }} 次</small>
      </article>
      <article>
        <span>隔离宿主监督</span>
        <strong>{{ status?.activePluginHosts ?? '—' }} 个活动宿主</strong>
        <small>累计启动 {{ status?.pluginHostStarts ?? '—' }} 次；失败 {{ status?.pluginHostStartFailures ?? '—' }} 次</small>
      </article>
      <article>
        <span>原生操作防重放</span>
        <strong>{{ status?.trackedInvocationsAvailable ? (status.trackedInvocationsAccepting ? '持久协调可用' : '正在排空') : '不可用' }}</strong>
        <small v-if="status?.trackedInvocationsAvailable">等待 {{ status.trackedPendingOperations }} 项；可找回 {{ status.trackedRetainedResults }} 项结果；账本 {{ status.trackedDurableOperations }} 项；落盘异常 {{ status.trackedPersistenceFailures }} 次</small>
        <small v-else>{{ status?.trackedInvocationsError ?? '状态尚未加载' }}</small>
      </article>
      <article>
        <span>插件信任</span>
        <strong>{{ status?.pluginTrustMode === 'ed25519-strict' ? '严格签名' : '开发模式' }}</strong>
        <small :title="status?.pluginRoot">{{ status ? `${status.trustKeyCount} 把密钥：启用 ${status.activeTrustKeyCount}，退役 ${status.retiredTrustKeyCount}，吊销 ${status.revokedTrustKeyCount}` : '完整文件清单与 SHA-256 校验' }}</small>
      </article>
      <article>
        <span>插件安装事务</span>
        <strong>{{ status?.recoveredPluginTransactions ? '已自动恢复' : '状态正常' }}</strong>
        <small>本次运行累计清理或回滚 {{ status?.recoveredPluginTransactions ?? '—' }} 项</small>
      </article>
      <article>
        <span>安装前宿主预检</span>
        <strong>{{ status?.pluginPreflightFailures ? '存在失败' : '状态正常' }}</strong>
        <small>通过 {{ status?.preflightedPluginHosts ?? '—' }} 个架构宿主；失败 {{ status?.pluginPreflightFailures ?? '—' }} 次</small>
      </article>
      <article>
        <span>受控进程策略</span>
        <strong>{{ status?.processPolicyEntries ?? '—' }} 项</strong>
        <small>启动失败 {{ status?.managedProcessFailures ?? '—' }} 项；不经过 Shell</small>
      </article>
      <article>
        <span>开机启动</span>
        <strong>{{ status?.autoStartEnabled == null ? '状态未知' : status.autoStartEnabled ? '已启用' : '未启用' }}</strong>
        <small :title="status?.autoStartError">{{ status?.autoStartError ?? '由本机系统机制管理' }}</small>
      </article>
      <article>
        <span>应用更新</span>
        <strong>{{ status?.appUpdateConfigured ? '严格签名' : '未配置' }}</strong>
        <small :title="status?.appUpdateError">{{ status?.appUpdateError ?? '仅本地控制台可触发' }}</small>
      </article>
      <article>
        <span>SSO 传输</span>
        <strong>{{ ssoActive ? '登录处理中' : ssoError ? '最近失败' : 'HTTPS-only' }}</strong>
        <small>禁止重定向；请求和响应均有上限</small>
      </article>
      <article>
        <span>业务来源策略</span>
        <strong>{{ status?.originPolicy.enforced ? '发布方签名' : '开发模式' }}</strong>
        <small :title="status?.originPolicyError">
          {{ status?.originPolicyError ?? `${status?.originPolicy.businessOrigins ?? '—'} 个业务来源，${status?.originPolicy.serviceGrants ?? '—'} 个服务授权，${status?.originPolicy.methodGrants ?? '—'} 个方法授权；HTTP ${status?.originPolicy.allowInsecureHttp ? '已例外放行' : '禁止'}` }}
        </small>
      </article>
      <article>
        <span>隐私诊断日志</span>
        <strong>{{ status?.diagnosticsAvailable ? '可用' : '不可用' }}</strong>
        <small :title="status?.diagnosticsError">
          {{ status?.diagnosticsError ?? `${status?.diagnostics?.logFiles ?? '—'} 个文件 · ${((status?.diagnostics?.logBytes ?? 0) / 1024).toFixed(1)} KiB` }}
        </small>
      </article>
    </section>

    <section class="operations" aria-label="桌面配置">
      <div class="operation-copy">
        <p class="eyebrow">BUSINESS ENTRY</p>
        <h2>受控业务入口</h2>
        <p>业务页面只能访问发布方签名策略批准的来源，并且只获得插件调用能力。</p>
        <p v-if="snapshot?.migratedFrom" class="migration">
          已合并 {{ snapshot.migrationSources.length }} 个旧配置来源；首选来源：{{ snapshot.migratedFrom }}
        </p>
        <p v-if="snapshot?.migrationWarnings.length" class="migration warning">
          有 {{ snapshot.migrationWarnings.length }} 项旧配置未能自动读取，请查看运行日志并人工核对。
        </p>
      </div>
      <form v-if="snapshot" @submit.prevent="saveConfig">
        <label>
          <span>业务系统地址</span>
          <input v-model.trim="snapshot.config.website" type="url" maxlength="4096" placeholder="https://example.internal" />
        </label>
        <label>
          <span>默认租户</span>
          <input v-model.trim="snapshot.config.tenantId" type="text" placeholder="可选" />
        </label>
        <fieldset class="environments">
          <legend>业务环境</legend>
          <p>默认项用于“进入业务系统”；启用切换后，可保存并直接打开任一已授权环境。</p>
          <div v-for="(environment, index) in snapshot.config.environments" :key="index" class="environment-row">
            <label class="environment-default" title="设为默认环境">
              <input v-model="snapshot.config.website" type="radio" :value="environment.url" />
              <span>默认</span>
            </label>
            <input v-model.trim="environment.name" type="text" maxlength="128" placeholder="环境名称" />
            <input
              :value="environment.url"
              type="url"
              maxlength="4096"
              placeholder="https://example.internal"
              @input="changeEnvironmentUrl(environment, ($event.target as HTMLInputElement).value)"
            />
            <button
              type="button"
              :disabled="busy || !snapshot.config.allowSwitch || !environment.name || !environment.url"
              @click="openEnvironment(environment)"
            >打开</button>
            <button type="button" :disabled="busy" aria-label="删除环境" @click="removeEnvironment(index)">删除</button>
          </div>
          <button class="environment-add" type="button" :disabled="busy || snapshot.config.environments.length >= 32" @click="addEnvironment">新增环境</button>
        </fieldset>
        <label>
          <span>SSO 额外可信来源</span>
          <textarea
            :value="snapshot.config.trustedOrigins.join('\n')"
            placeholder="每行一个来源，例如 https://sso.example.internal"
            @input="snapshot.config.trustedOrigins = ($event.target as HTMLTextAreaElement).value.split(/\s+/).filter(Boolean)"
          />
        </label>
        <label>
          <span>允许在系统浏览器打开的来源</span>
          <textarea
            :value="snapshot.config.externalOrigins.join('\n')"
            placeholder="默认只允许业务来源；每行可追加一个 https:// 来源"
            @input="snapshot.config.externalOrigins = ($event.target as HTMLTextAreaElement).value.split(/\s+/).filter(Boolean)"
          />
        </label>
        <label>
          <span>签名插件仓库索引</span>
          <input v-model.trim="snapshot.config.pluginCatalogUrl" type="url" placeholder="https://plugins.example/catalog.json" />
        </label>
        <label>
          <span>仓库索引签名</span>
          <input v-model.trim="snapshot.config.pluginCatalogSignatureUrl" type="url" placeholder="https://plugins.example/catalog.sig.json" />
        </label>
        <div class="toggles">
          <label><input v-model="snapshot.config.allowSwitch" type="checkbox" />允许环境切换</label>
          <label><input v-model="snapshot.config.autoClose" type="checkbox" />关闭前确认</label>
          <label><input v-model="snapshot.config.autoStart" type="checkbox" />开机自动启动</label>
        </div>
        <div class="actions">
          <button class="primary" type="submit" :disabled="busy">保存配置</button>
          <button type="button" :disabled="busy" @click="importConfig">导入配置</button>
          <button type="button" :disabled="busy" @click="exportConfig">导出配置</button>
          <button type="button" :disabled="busy" @click="openBusiness">进入业务系统</button>
          <button type="button" :disabled="busy" @click="reloadBusiness">刷新业务窗口</button>
          <button type="button" :disabled="busy" @click="clearBusinessData">清理站点数据</button>
          <button type="button" :disabled="busy" @click="installPlugin">安装签名插件</button>
          <button type="button" :disabled="busy" @click="reloadPlugins">重新扫描插件</button>
          <button type="button" :disabled="busy || !status?.appUpdateConfigured" @click="checkAppUpdate">检查应用更新</button>
          <button type="button" :disabled="busy || !appUpdate?.available" @click="installAppUpdate">安装签名更新</button>
          <button type="button" :disabled="busy || !status?.diagnosticsAvailable" @click="exportDiagnostics">导出脱敏诊断包</button>
        </div>
        <details v-if="appUpdate?.available" class="update-details" open>
          <summary>版本 {{ appUpdate.version }}{{ appUpdate.date ? ` · ${appUpdate.date}` : '' }}</summary>
          <p>{{ appUpdate.notes || '此版本未提供发布说明。' }}</p>
          <small v-if="updateProgress">{{ updateProgress }}</small>
        </details>
        <small class="config-path">配置位置：{{ snapshot.path }}</small>
      </form>
    </section>

    <section class="plugin-inventory" aria-label="已安装插件">
      <div>
        <p class="eyebrow">PLUGIN INVENTORY</p>
        <h2>已验证插件</h2>
        <p>只展示重新发现并通过当前信任库验签的插件；隔离项不会进入服务路由。</p>
      </div>
      <div class="plugin-list">
        <form class="catalog-install" @submit.prevent="checkPluginUpdates(catalogPluginId)">
          <input v-model.trim="catalogPluginId" type="text" placeholder="输入签名仓库中的插件 ID" />
          <button type="submit" :disabled="busy">查询仓库版本</button>
          <button type="button" :disabled="busy" @click="checkPluginUpdates()">检查全部已安装插件</button>
        </form>
        <div v-if="pluginUpdates" class="plugin-update-results" aria-live="polite">
          <div v-for="update in pluginUpdates.updates" :key="update.pluginId">
            <span>
              <strong>{{ update.pluginId }}</strong>
              <small>已安装 {{ update.installedVersion ?? '无' }} · 仓库 {{ update.availableVersion ?? '无匹配版本' }}</small>
            </span>
            <button
              v-if="update.updateAvailable && update.availableVersion"
              type="button"
              :disabled="busy"
              @click="installFromCatalog(update.pluginId, update.availableVersion)"
            >
              {{ update.installedVersion ? `安装更新 ${update.availableVersion}` : `安装 ${update.availableVersion}` }}
            </button>
            <em v-else>{{ update.catalogAvailable ? '已是最新版本' : '仓库未收录' }}</em>
          </div>
        </div>
        <article v-for="plugin in inventory?.plugins ?? []" :key="plugin.pluginId">
          <header>
            <span><strong>{{ plugin.displayName }}</strong><small>{{ plugin.pluginId }} · {{ plugin.version ?? '旧版未知版本' }}</small></span>
            <button type="button" :disabled="busy" @click="checkPluginUpdates(plugin.pluginId)">检查更新</button>
          </header>
          <details v-for="service in plugin.services" :key="service.serviceId" class="service-mapping">
            <summary>
              <code>{{ service.serviceId }}</code>
              <span>{{ service.architecture }} / {{ service.mainType }} / {{ service.methodCount }} 个方法</span>
            </summary>
            <dl>
              <div><dt>原生目标</dt><dd><code>{{ service.mainClass }}</code></dd></div>
              <div><dt>调用约定</dt><dd>{{ service.callingConvention || '默认' }} · {{ service.charset || '默认字符集' }}</dd></div>
              <div><dt>服务策略</dt><dd>{{ service.timeoutMs || '默认' }} ms · {{ service.cacheable ? '缓存实例' : '按需实例' }} · {{ service.dependencyCount }} 个依赖</dd></div>
            </dl>
            <div class="method-mapping" v-for="method in service.methods" :key="`${service.serviceId}:${method.requestName}`">
              <code>{{ method.requestName }}</code>
              <span aria-hidden="true">→</span>
              <code>{{ method.nativeName }}</code>
              <small>{{ method.returnType || '默认返回类型' }} · {{ method.parameterCount }} 参数 · {{ method.timeoutMs || '默认' }} ms</small>
            </div>
          </details>
        </article>
        <p v-if="inventory && inventory.plugins.length === 0" class="empty">尚未安装通过验签的插件。</p>
        <details v-if="inventory?.quarantined.length" class="quarantined">
          <summary>{{ inventory.quarantined.length }} 个插件已隔离</summary>
          <ul><li v-for="failure in inventory.quarantined" :key="failure">{{ failure }}</li></ul>
        </details>
      </div>
    </section>

    <section class="boundary">
      <div>
        <p class="eyebrow">TRUST BOUNDARY</p>
        <h2>第三方 DLL 永不进入主进程</h2>
      </div>
      <ol>
        <li><b>业务 WebView</b><span>只调用受限的业务命令</span></li>
        <li><b>Rust Controller</b><span>执行路由、策略、超时和监督</span></li>
        <li><b>Plugin Host</b><span>加载 DLL、COM、OCX、EXE 或 BAT</span></li>
      </ol>
    </section>

    <p v-if="notice" class="notice" role="status">{{ notice }}</p>
    <p v-if="ssoError" class="error" role="alert">{{ ssoError }}</p>
    <p v-if="error" class="error" role="alert">操作失败：{{ error }}</p>
  </main>
</template>
