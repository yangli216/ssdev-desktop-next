<script setup lang="ts">
import { invoke } from '@tauri-apps/api/core'
import { open, save } from '@tauri-apps/plugin-dialog'
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { mappingDeletionDiscardsDraft, mappingDraftTargetsPlugin, sameMappingPluginId } from './local-mapping-draft.js'

type Architecture = 'x86' | 'x64'
type MainType = 'dll' | 'com' | 'ocx' | 'exe' | 'bat'

type ParameterDefinition = {
  name: string
  type: string
  len: number
  charset?: string
  decode?: string
}

type MethodDefinition = {
  name: string
  alias?: string
  timeout: number
  returnType: string
  parameters: Array<ParameterDefinition | string>
  props: string[]
}

type ServiceDefinition = {
  serviceId: string
  mainClass: string
  mainType: MainType
  architecture: Architecture
  charset: string
  callingConvention: string
  cacheable: boolean
  timeout: number
  deps: string[]
  methods: MethodDefinition[]
}

type LocalMappingDefinition = {
  schemaVersion: number
  pluginId: string
  displayName: string
  services: ServiceDefinition[]
  debugCases: DebugCaseDefinition[]
}

type DebugCaseDefinition = {
  name: string
  serviceId: string
  method: string
  parameters: Record<string, unknown>
  expectedResCode: number
  assertResData: boolean
  expectedResData: unknown
}

type MappingInventory = {
  mappings: LocalMappingDefinition[]
  failures: string[]
}

type LocalMappingImportPreview = {
  planId: string
  pluginId: string
  displayName: string
  action: 'install' | 'replace'
  serviceCount: number
  methodCount: number
  debugCaseCount: number
  services: Array<{
    serviceId: string
    architecture: Architecture
    mainType: string
    methodCount: number
  }>
}

type NativeInspection = {
  fileName: string
  fileBytes: number
  componentType: string
  architecture?: Architecture
  exports: string[]
  warnings: string[]
}

type ComComponent = {
  clsid: string
  progId?: string
  versionIndependentProgId?: string
  displayName: string
  architecture: Architecture
  componentType: 'com' | 'ocx'
  serverType: 'in-process' | 'local-process' | 'unknown'
}

type ComDiscoveryResult = {
  components: ComComponent[]
  scanned: number
  truncated: boolean
}

type DebugResult = {
  elapsedMs: number
  response: {
    ResCode: number
    ResData: unknown
    [key: string]: unknown
  }
}

type DebugCaseRunResult = {
  name: string
  serviceId: string
  method: string
  expectedResCode: number
  actualResCode: number
  dataAsserted: boolean
  dataPassed: boolean
  dataMismatchPath: string | null
  elapsedMs: number
  passed: boolean
}

type MappingInventoryRefreshPlan = {
  action: 'upsert' | 'delete'
  pluginId: string
  successMessage: string
}

const props = defineProps<{ disabled?: boolean }>()
const emit = defineEmits<{
  changed: []
  dirty: [value: boolean]
  stateUnverified: [value: boolean]
}>()

const inventory = ref<MappingInventory>({ mappings: [], failures: [] })
const mappingImportPreview = ref<LocalMappingImportPreview | null>(null)
const selectedMappingImport = ref('')
const draft = ref<LocalMappingDefinition>(newMapping())
const serviceIndex = ref(0)
const methodIndex = ref(0)
const inspection = ref<NativeInspection | null>(null)
const comQuery = ref('')
const comDiscovery = ref<ComDiscoveryResult | null>(null)
const debugValues = ref<Record<string, string | boolean | number>>({})
const debugResult = ref<DebugResult | null>(null)
const debugCaseName = ref('')
const expectedResCode = ref(0)
const assertResData = ref(false)
const expectedResDataText = ref('')
const suggestedExpectedDataText = ref('')
const regressionResults = ref<DebugCaseRunResult[]>([])
const busy = ref(false)
const error = ref('')
const notice = ref('')
const inventoryUnverified = ref(true)
const pendingInventoryRefresh = ref<MappingInventoryRefreshPlan | null>(null)

const MAPPING_INVENTORY_REFRESH_TIMEOUT_MS = 15_000

const service = computed(() => draft.value.services[serviceIndex.value])
const method = computed(() => service.value?.methods[methodIndex.value])
const isComService = computed(() => service.value?.mainType === 'com' || service.value?.mainType === 'ocx')
const callableParameters = computed(() => (method.value?.parameters ?? []).filter((item): item is ParameterDefinition => typeof item !== 'string' && !item.name.startsWith('$')))
const returnTypeOptions = computed(() => service.value?.mainType === 'dll'
  ? ['void', 'string', 'bool', 'int', 'uint', 'pointer']
  : ['void', 'string', 'bool', 'int', 'uint', 'pointer', 'float', 'double'])
const editingStoredCase = computed(() => draft.value.debugCases.some((item) => item.name === debugCaseName.value.trim()))

function newMethod(name = ''): MethodDefinition {
  return { name, alias: '', timeout: 0, returnType: 'string', parameters: [], props: [] }
}

function newService(): ServiceDefinition {
  return {
    serviceId: '',
    mainClass: '',
    mainType: 'dll',
    architecture: 'x64',
    charset: 'utf8',
    callingConvention: 'system',
    cacheable: true,
    timeout: 30000,
    deps: [],
    methods: [newMethod()],
  }
}

function newMapping(): LocalMappingDefinition {
  return { schemaVersion: 1, pluginId: '', displayName: '', services: [newService()], debugCases: [] }
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}

function normalizeDebugCases(cases: DebugCaseDefinition[]): DebugCaseDefinition[] {
  return cases.map((item) => ({
    ...item,
    assertResData: item.assertResData ?? false,
    expectedResData: item.expectedResData ?? null,
  }))
}

function normalizeMapping(mapping: LocalMappingDefinition): LocalMappingDefinition {
  const normalized = clone(mapping)
  normalized.debugCases = normalizeDebugCases(normalized.debugCases ?? [])
  for (const item of normalized.services) {
    item.mainType = (item.mainType || 'dll').toLowerCase() as MainType
    item.charset ||= 'utf8'
    item.callingConvention ||= 'system'
    for (const mappedMethod of item.methods) {
      mappedMethod.props ??= []
      mappedMethod.parameters = mappedMethod.parameters.map((parameter) =>
        typeof parameter === 'string'
          ? { name: parameter, type: 'string', len: 1024 }
          : { ...parameter, type: parameter.type || 'string', len: parameter.len ?? 1024 },
      )
    }
  }
  return normalized
}

function mappingForSave(): LocalMappingDefinition {
  const payload = clone(draft.value)
  for (const item of payload.services) {
    for (const mappedMethod of item.methods) {
      if (!mappedMethod.alias?.trim()) delete mappedMethod.alias
      for (const parameter of mappedMethod.parameters) {
        if (typeof parameter === 'string') continue
        if (!parameter.charset?.trim()) delete parameter.charset
        if (!parameter.decode?.trim()) delete parameter.decode
      }
    }
  }
  return payload
}

const savedDraft = ref<LocalMappingDefinition>(clone(mappingForSave()))
const draftDirty = computed(() => JSON.stringify(mappingForSave()) !== JSON.stringify(savedDraft.value))
const savedMappingPluginId = computed(() => savedDraft.value.pluginId.trim())
const mappingIsInstalled = computed(() => inventory.value.mappings.some((item) => sameMappingPluginId(item.pluginId, draft.value.pluginId)))
const editingInstalledMapping = computed(() => (
  savedMappingPluginId.value !== ''
  && inventory.value.mappings.some((item) => sameMappingPluginId(item.pluginId, savedMappingPluginId.value))
))

watch(draftDirty, (value) => {
  emit('dirty', value)
  if (!value) return
  debugResult.value = null
  suggestedExpectedDataText.value = ''
  regressionResults.value = []
}, { immediate: true })
watch(inventoryUnverified, (value) => emit('stateUnverified', value), { immediate: true })

function markDraftSaved() {
  savedDraft.value = clone(mappingForSave())
}

function markDebugCasesSaved(debugCases: DebugCaseDefinition[]) {
  savedDraft.value = {
    ...clone(savedDraft.value),
    debugCases: clone(debugCases),
  }
}

function confirmDiscardDraft(): boolean {
  return !draftDirty.value || window.confirm('当前映射有未保存更改，继续将丢弃这些更改。确定继续吗？')
}

function targetHasUnsavedDraft(pluginId: string): boolean {
  return mappingDraftTargetsPlugin({
    dirty: draftDirty.value,
    savedPluginId: savedMappingPluginId.value,
    currentPluginId: draft.value.pluginId,
  }, pluginId)
}

function deletionDiscardsCurrentDraft(pluginId: string): boolean {
  return mappingDeletionDiscardsDraft({
    dirty: draftDirty.value,
    savedPluginId: savedMappingPluginId.value,
    currentPluginId: draft.value.pluginId,
  }, pluginId)
}

function requireSavedTargetMapping(pluginId: string, action: string): boolean {
  if (!targetHasUnsavedDraft(pluginId)) return true
  notice.value = ''
  error.value = `当前映射有未保存更改。请先保存或放弃草稿，再${action}。`
  return false
}

function requireActiveMappingSnapshot(action: string): boolean {
  if (draftDirty.value) {
    notice.value = ''
    error.value = `当前映射有未保存更改。请先保存并热加载，再${action}。`
    return false
  }
  if (mappingIsInstalled.value) return true
  notice.value = ''
  error.value = `请先保存并热加载映射，再${action}。`
  return false
}

function beforeUnload(event: BeforeUnloadEvent) {
  if (!draftDirty.value) return
  event.preventDefault()
  event.returnValue = ''
}

function reasonText(reason: unknown): string {
  return reason instanceof Error ? reason.message : String(reason)
}

async function run(action: () => Promise<void>) {
  busy.value = true
  error.value = ''
  notice.value = ''
  try {
    await action()
  } catch (reason) {
    error.value = reasonText(reason)
  } finally {
    busy.value = false
  }
}

async function withMappingInventoryTimeout<T>(promise: Promise<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = window.setTimeout(
      () => reject(new Error('mapping-inventory-refresh-timeout')),
      MAPPING_INVENTORY_REFRESH_TIMEOUT_MS,
    )
    promise.then(
      (value) => {
        window.clearTimeout(timer)
        resolve(value)
      },
      (reason) => {
        window.clearTimeout(timer)
        reject(reason)
      },
    )
  })
}

async function readInventory(): Promise<MappingInventory> {
  return withMappingInventoryTimeout(invoke<MappingInventory>('local_mapping_inventory'))
}

async function loadInventory() {
  inventory.value = await readInventory()
}

onMounted(async () => {
  window.addEventListener('beforeunload', beforeUnload)
  busy.value = true
  try {
    await loadInventory()
    inventoryUnverified.value = false
  } catch {
    inventoryUnverified.value = true
    error.value = '原生映射清单未能读取。请重新读取后再编辑、调试或交付映射。'
  } finally {
    busy.value = false
  }
})

onBeforeUnmount(() => {
  window.removeEventListener('beforeunload', beforeUnload)
  emit('dirty', false)
  emit('stateUnverified', false)
})

function replaceDraft(mapping: LocalMappingDefinition, editNotice = '') {
  draft.value = normalizeMapping(mapping)
  serviceIndex.value = 0
  methodIndex.value = 0
  inspection.value = null
  comQuery.value = ''
  comDiscovery.value = null
  debugResult.value = null
  debugValues.value = {}
  debugCaseName.value = ''
  expectedResCode.value = 0
  assertResData.value = false
  expectedResDataText.value = ''
  suggestedExpectedDataText.value = ''
  regressionResults.value = []
  error.value = ''
  notice.value = editNotice
  markDraftSaved()
}

function applyRefreshedInventory(next: MappingInventory, plan: MappingInventoryRefreshPlan) {
  if (plan.action === 'upsert') {
    const saved = next.mappings.find((item) => item.pluginId === plan.pluginId)
    if (!saved) throw new Error('committed-mapping-missing-from-inventory')
    replaceDraft(saved)
  } else if (draft.value.pluginId.trim() === plan.pluginId) {
    resetEditor(true)
  } else if (savedMappingPluginId.value === plan.pluginId) {
    savedDraft.value = clone(newMapping())
  }
  inventory.value = next
}

async function refreshCommittedMapping(plan: MappingInventoryRefreshPlan): Promise<boolean> {
  try {
    const next = await readInventory()
    applyRefreshedInventory(next, plan)
    pendingInventoryRefresh.value = null
    inventoryUnverified.value = false
    error.value = ''
    notice.value = plan.successMessage
    return true
  } catch {
    pendingInventoryRefresh.value = plan
    inventoryUnverified.value = true
    error.value = ''
    notice.value = `${plan.successMessage} 工作台清单未重新读取；操作已经完成，请勿重复执行，重新读取后再继续。`
    return false
  }
}

async function runCommittedMappingAction<T>(
  action: () => Promise<T>,
  refreshPlan: (result: T) => MappingInventoryRefreshPlan,
) {
  busy.value = true
  error.value = ''
  notice.value = ''
  let result: T
  try {
    result = await action()
  } catch (reason) {
    error.value = reasonText(reason)
    busy.value = false
    return
  }
  const plan = refreshPlan(result)
  pendingInventoryRefresh.value = plan
  emit('changed')
  await refreshCommittedMapping(plan)
  busy.value = false
}

async function retryMappingInventory() {
  if (busy.value) return
  busy.value = true
  error.value = ''
  notice.value = ''
  const pending = pendingInventoryRefresh.value
  if (pending) {
    await refreshCommittedMapping(pending)
  } else {
    try {
      inventory.value = await readInventory()
      inventoryUnverified.value = false
      notice.value = '原生映射清单已重新读取，可以继续操作。'
    } catch {
      inventoryUnverified.value = true
      error.value = '原生映射清单仍无法读取。请检查桌面核心状态后重试。'
    }
  }
  busy.value = false
}

function resetEditor(force = false) {
  if (!force && !confirmDiscardDraft()) return
  replaceDraft(newMapping())
}

function discardDraftChanges() {
  if (!draftDirty.value) return
  if (!window.confirm('确定放弃当前映射的全部未保存更改，并恢复到最近保存状态吗？')) return
  replaceDraft(savedDraft.value, '已放弃未保存更改，恢复到最近保存状态。')
}

function editMapping(mapping: LocalMappingDefinition) {
  if (!confirmDiscardDraft()) return
  replaceDraft(mapping, `正在编辑 ${mapping.displayName || mapping.pluginId}`)
}

function selectService(index: number) {
  serviceIndex.value = index
  methodIndex.value = 0
  inspection.value = null
  comQuery.value = ''
  comDiscovery.value = null
  debugResult.value = null
  debugValues.value = {}
  debugCaseName.value = ''
  expectedResCode.value = 0
  assertResData.value = false
  expectedResDataText.value = ''
  suggestedExpectedDataText.value = ''
  regressionResults.value = []
}

function addService() {
  draft.value.services.push(newService())
  selectService(draft.value.services.length - 1)
}

function removeService(index: number) {
  if (draft.value.services.length === 1) {
    error.value = '一个映射至少需要一个服务。'
    return
  }
  draft.value.services.splice(index, 1)
  selectService(Math.min(serviceIndex.value, draft.value.services.length - 1))
}

function addMethod(name = '') {
  if (!service.value) return
  service.value.methods.push(newMethod(name))
  methodIndex.value = service.value.methods.length - 1
  debugValues.value = {}
}

function removeMethod(index: number) {
  if (!service.value) return
  service.value.methods.splice(index, 1)
  if (service.value.methods.length === 0) service.value.methods.push(newMethod())
  methodIndex.value = Math.min(methodIndex.value, service.value.methods.length - 1)
  debugValues.value = {}
}

function addParameter() {
  method.value?.parameters.push({ name: '', type: 'string', len: 1024 })
}

function parameterTypeOptions(parameter: ParameterDefinition): string[] {
  if (service.value?.mainType !== 'dll') return ['string', 'bool', 'int', 'uint', 'float', 'double', 'buffer']
  return parameter.name.startsWith('$') ? ['string', 'int', 'buffer'] : ['string', 'bool', 'int', 'uint']
}

function removeParameter(index: number) {
  method.value?.parameters.splice(index, 1)
}

function addComProperty() {
  method.value?.props.push('')
}

function removeComProperty(index: number) {
  method.value?.props.splice(index, 1)
}

function parameterAt(index: number): ParameterDefinition {
  const parameter = method.value?.parameters[index]
  if (!parameter || typeof parameter === 'string') {
    throw new Error('参数定义尚未规范化')
  }
  return parameter
}

function addDependency() {
  service.value?.deps.push('')
}

function removeDependency(index: number) {
  service.value?.deps.splice(index, 1)
}

async function selectComponent() {
  const selected = await open({
    multiple: false,
    directory: false,
    filters: [{ name: 'Windows 原生组件', extensions: ['dll', 'exe', 'bat'] }],
  })
  if (typeof selected !== 'string' || !service.value) return
  service.value.mainClass = selected
  const extension = selected.split('.').pop()?.toLowerCase()
  if (extension === 'dll' || extension === 'ocx' || extension === 'exe' || extension === 'bat') {
    service.value.mainType = extension
  }
  await inspectCurrentComponent()
}

async function inspectCurrentComponent() {
  if (!service.value?.mainClass || service.value.mainType === 'com') return
  await run(async () => {
    inspection.value = await invoke<NativeInspection>('inspect_native_component', { path: service.value?.mainClass })
    if (inspection.value.architecture && service.value) service.value.architecture = inspection.value.architecture
    notice.value = inspection.value.exports.length
      ? `已识别 ${inspection.value.exports.length} 个导出函数。`
      : '组件已读取，但没有自动识别到可调用的导出函数。'
  })
}

async function discoverCom() {
  if (!service.value || !['com', 'ocx'].includes(service.value.mainType)) return
  const query = comQuery.value.trim()
  if (query.length < 2) {
    error.value = '请输入至少 2 个字符搜索 ProgID、CLSID 或组件名称。'
    return
  }
  await run(async () => {
    comDiscovery.value = await invoke<ComDiscoveryResult>('discover_registered_com_components', {
      query,
      architecture: service.value?.architecture,
    })
    notice.value = comDiscovery.value.components.length
      ? `已在 ${service.value?.architecture} 注册视图找到 ${comDiscovery.value.components.length} 项${comDiscovery.value.truncated ? '（结果已截断，请缩小搜索范围）' : ''}。`
      : `已扫描 ${comDiscovery.value.scanned} 项注册信息，没有找到匹配组件。`
  })
}

function useComComponent(component: ComComponent) {
  if (!service.value) return
  service.value.mainClass = component.progId || component.versionIndependentProgId || component.clsid
  service.value.architecture = component.architecture
  service.value.mainType = component.componentType
  notice.value = `已选择 ${service.value.mainClass}；方法和参数仍需依据厂商接口文档配置。`
}

function comServerLabel(serverType: ComComponent['serverType']): string {
  if (serverType === 'in-process') return '进程内服务器'
  if (serverType === 'local-process') return '本地进程服务器'
  return '服务器类型未知'
}

function useExport(name: string) {
  const existing = service.value?.methods.findIndex((item) => item.name === name) ?? -1
  if (existing >= 0) {
    methodIndex.value = existing
  } else {
    addMethod(name)
  }
}

async function saveMapping() {
  const definition = mappingForSave()
  const existingTarget = inventory.value.mappings.find((item) => sameMappingPluginId(item.pluginId, definition.pluginId))
  const editingTarget = sameMappingPluginId(savedMappingPluginId.value, definition.pluginId)
  if (existingTarget && !editingTarget && !window.confirm(`映射 ID「${definition.pluginId}」已经属于「${existingTarget.displayName || existingTarget.pluginId}」。继续将替换其原生组件、服务、方法和调试用例，确定继续吗？`)) return
  if (existingTarget) definition.pluginId = existingTarget.pluginId
  await runCommittedMappingAction(
    () => invoke<{ pluginId: string; serviceCount: number; preflightedHosts: number }>('save_local_mapping', {
      definition,
      expectedExisting: Boolean(existingTarget),
    }),
    (result) => ({
      action: 'upsert',
      pluginId: result.pluginId,
      successMessage: `映射已保存并热加载：${result.serviceCount} 个服务，${result.preflightedHosts} 个宿主预检通过。`,
    }),
  )
}

async function deleteMapping(pluginId: string) {
  if (deletionDiscardsCurrentDraft(pluginId) && !window.confirm(`本地映射「${pluginId}」有未保存更改。删除成功后这些草稿也会丢失，确定继续吗？`)) return
  if (!window.confirm(`确定删除本地映射「${pluginId}」吗？签名插件不会受影响。`)) return
  await runCommittedMappingAction(
    () => invoke('delete_local_mapping', { pluginId }),
    () => ({
      action: 'delete',
      pluginId,
      successMessage: `本地映射 ${pluginId} 已删除并从路由卸载。`,
    }),
  )
}

async function exportMapping(pluginId: string) {
  if (!requireSavedTargetMapping(pluginId, '导出迁移包')) return
  const destination = await save({
    defaultPath: `${pluginId}.ssdev-mapping`,
    filters: [{ name: 'SSDEV 本地映射包', extensions: ['ssdev-mapping'] }],
  })
  if (typeof destination !== 'string') return
  await run(async () => {
    await invoke('export_local_mapping', { pluginId, destination })
    notice.value = `映射包已导出：${destination}`
  })
}

async function exportTypescript(pluginId: string) {
  if (!requireSavedTargetMapping(pluginId, '导出 TypeScript 客户端')) return
  const destination = await save({
    defaultPath: `${pluginId}.client.ts`,
    filters: [{ name: 'TypeScript 客户端', extensions: ['ts'] }],
  })
  if (typeof destination !== 'string') return
  await run(async () => {
    await invoke('export_local_mapping_typescript', { pluginId, destination })
    notice.value = `类型化调用代码已导出：${destination}`
  })
}

async function exportReleaseSource(pluginId: string) {
  if (!requireSavedTargetMapping(pluginId, '导出发布源')) return
  const destinationParent = await open({
    multiple: false,
    directory: true,
    title: '选择发布源父目录',
  })
  if (typeof destinationParent !== 'string') return
  await run(async () => {
    const result = await invoke<{ destination: string; matrixSeed: string; fileCount: number; bytes: number; seededCaseCount: number; placeholderCaseCount: number; reviewRequiredCaseCount: number }>('export_local_mapping_release_source', {
      pluginId,
      destinationParent,
    })
    notice.value = `最小发布源已导出：${result.destination}（${result.fileCount} 个文件，${(result.bytes / 1024 / 1024).toFixed(1)} MiB）；矩阵种子：${result.matrixSeed}（现场用例 ${result.seededCaseCount} 个，占位待补 ${result.placeholderCaseCount} 个，正式复核 ${result.reviewRequiredCaseCount} 个）。下一步由 ssdev-plugin-tool prepare --matrix-seed 生成签名请求。`
  })
}

async function inspectMappingImport() {
  const source = await open({
    multiple: false,
    directory: false,
    filters: [{ name: 'SSDEV 本地映射包', extensions: ['ssdev-mapping'] }],
  })
  if (typeof source !== 'string') return
  mappingImportPreview.value = null
  selectedMappingImport.value = ''
  await run(async () => {
    mappingImportPreview.value = await invoke<LocalMappingImportPreview>('inspect_local_mapping_import', { source })
    selectedMappingImport.value = source
    notice.value = '映射包已完成只读结构校验，尚未加载原生代码；请核对服务范围后再确认。'
  })
}

async function confirmMappingImport() {
  const preview = mappingImportPreview.value
  const source = selectedMappingImport.value
  if (!preview || !source) {
    error.value = '请先选择并预检映射包。'
    return
  }
  if (!window.confirm(`映射包「${preview.displayName || preview.pluginId}」不验证发布者签名，确认信任其原生代码并${preview.action === 'replace' ? '替换现有映射' : '安装'}吗？`)) return
  if (!confirmDiscardDraft()) return
  await runCommittedMappingAction(
    () => invoke<{ pluginId: string; serviceCount: number; preflightedHosts: number }>('import_local_mapping', {
      source,
      expectedPlanId: preview.planId,
    }),
    (result) => {
      mappingImportPreview.value = null
      selectedMappingImport.value = ''
      return {
        action: 'upsert',
        pluginId: result.pluginId,
        successMessage: `映射包已复核并热加载：${result.serviceCount} 个服务，${result.preflightedHosts} 个宿主预检通过。`,
      }
    },
  )
}

function mappingImportActionLabel(action: LocalMappingImportPreview['action']): string {
  return action === 'replace' ? '替换现有映射' : '安装新映射'
}

function debugInputType(type: string): string {
  const normalized = type.toLowerCase()
  if (normalized === 'bool' || normalized === 'boolean') return 'checkbox'
  if (['int', 'int32', 'long', 'uint', 'uint32', 'dword', 'float', 'double'].includes(normalized)) return 'number'
  return 'text'
}

function convertedValue(parameter: ParameterDefinition): unknown {
  const raw = debugValues.value[parameter.name]
  const normalized = parameter.type.toLowerCase()
  if (normalized === 'bool' || normalized === 'boolean') return Boolean(raw)
  if (['int', 'int32', 'long', 'uint', 'uint32', 'dword', 'float', 'double'].includes(normalized)) {
    return raw === '' || raw === undefined ? 0 : Number(raw)
  }
  return raw === undefined ? '' : String(raw)
}

function currentDebugParameters(): Record<string, unknown> {
  return Object.fromEntries(callableParameters.value.map((item) => [item.name, convertedValue(item)]))
}

function returnValueAssertionSuggestion(data: unknown): string {
  if (!data || typeof data !== 'object' || Array.isArray(data) || !('ReturnValue' in data)) return ''
  const value = (data as Record<string, unknown>).ReturnValue
  if (value !== null && typeof value !== 'number' && typeof value !== 'boolean') return ''
  return JSON.stringify({ ReturnValue: value }, null, 2)
}

function useSuggestedExpectedData() {
  if (!suggestedExpectedDataText.value) return
  assertResData.value = true
  expectedResDataText.value = suggestedExpectedDataText.value
}

function parsedExpectedResData(): unknown {
  if (!assertResData.value) return null
  const text = expectedResDataText.value.trim()
  if (!text) throw new Error('启用 ResData 断言后必须填写有效 JSON。')
  try {
    return JSON.parse(text) as unknown
  } catch (reason) {
    throw new Error(`期望 ResData 不是有效 JSON：${reasonText(reason)}`)
  }
}

async function invokeDebug() {
  if (!requireActiveMappingSnapshot('运行现场测试')) return
  if (!service.value || !method.value) return
  const serviceId = service.value.serviceId.trim()
  const methodName = (method.value.alias || method.value.name).trim()
  if (!serviceId || !methodName) {
    error.value = '请先保存有效的服务 ID 和方法名称。'
    return
  }
  await run(async () => {
    debugResult.value = await invoke<DebugResult>('debug_plugin_invoke', {
      request: { serviceId, method: methodName, parameters: currentDebugParameters() },
    })
    if (!editingStoredCase.value) expectedResCode.value = debugResult.value.response.ResCode
    suggestedExpectedDataText.value = debugResult.value.response.ResCode === 0
      ? returnValueAssertionSuggestion(debugResult.value.response.ResData)
      : ''
    notice.value = suggestedExpectedDataText.value
      ? `调用完成，用时 ${debugResult.value.elapsedMs} ms；可采用本次 ReturnValue 作为断言。`
      : `调用完成，用时 ${debugResult.value.elapsedMs} ms。`
  })
}

async function saveDebugCase() {
  if (!requireActiveMappingSnapshot('保存调试用例')) return
  if (!service.value || !method.value) return
  const name = debugCaseName.value.trim()
  if (!name) {
    error.value = '请输入调试用例名称。'
    return
  }
  const methodName = (method.value.alias || method.value.name).trim()
  let expectedResData: unknown
  try {
    expectedResData = parsedExpectedResData()
  } catch (reason) {
    error.value = reasonText(reason)
    return
  }
  await run(async () => {
    const debugCases = await invoke<DebugCaseDefinition[]>('save_local_mapping_debug_case', {
      pluginId: draft.value.pluginId,
      debugCase: {
        name,
        serviceId: service.value?.serviceId.trim(),
        method: methodName,
        parameters: currentDebugParameters(),
        expectedResCode: Number(expectedResCode.value),
        assertResData: assertResData.value,
        expectedResData,
      },
    })
    draft.value.debugCases = normalizeDebugCases(debugCases)
    markDebugCasesSaved(draft.value.debugCases)
    const stored = inventory.value.mappings.find((item) => item.pluginId === draft.value.pluginId)
    if (stored) stored.debugCases = clone(draft.value.debugCases)
    regressionResults.value = []
    notice.value = `已保存合成调试用例「${name}」。`
  })
}

function loadDebugCase(debugCase: DebugCaseDefinition) {
  const targetServiceIndex = draft.value.services.findIndex((item) => item.serviceId === debugCase.serviceId)
  if (targetServiceIndex < 0) return
  serviceIndex.value = targetServiceIndex
  const targetService = draft.value.services[targetServiceIndex]
  const targetMethodIndex = targetService.methods.findIndex((item) => item.name === debugCase.method || item.alias === debugCase.method)
  if (targetMethodIndex < 0) return
  methodIndex.value = targetMethodIndex
  debugValues.value = Object.fromEntries(Object.entries(debugCase.parameters).map(([name, value]) => {
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return [name, value]
    return [name, JSON.stringify(value)]
  }))
  debugCaseName.value = debugCase.name
  expectedResCode.value = debugCase.expectedResCode
  assertResData.value = debugCase.assertResData
  expectedResDataText.value = debugCase.assertResData ? JSON.stringify(debugCase.expectedResData, null, 2) : ''
  suggestedExpectedDataText.value = ''
  debugResult.value = null
  notice.value = `已载入调试用例「${debugCase.name}」。`
}

async function deleteDebugCase(caseName: string) {
  await run(async () => {
    const debugCases = await invoke<DebugCaseDefinition[]>('delete_local_mapping_debug_case', {
      pluginId: draft.value.pluginId,
      caseName,
    })
    draft.value.debugCases = normalizeDebugCases(debugCases)
    markDebugCasesSaved(draft.value.debugCases)
    const stored = inventory.value.mappings.find((item) => item.pluginId === draft.value.pluginId)
    if (stored) stored.debugCases = clone(draft.value.debugCases)
    regressionResults.value = []
    notice.value = `已删除调试用例「${caseName}」。`
  })
}

async function runDebugCases() {
  if (!requireActiveMappingSnapshot('运行回归用例')) return
  if (draft.value.debugCases.length === 0) return
  await run(async () => {
    regressionResults.value = await invoke<DebugCaseRunResult[]>('run_local_mapping_debug_cases', {
      pluginId: draft.value.pluginId,
    })
    const passed = regressionResults.value.filter((item) => item.passed).length
    notice.value = `回归执行完成：${passed}/${regressionResults.value.length} 通过。`
  })
}

function regressionDataSummary(item: DebugCaseRunResult): string {
  if (!item.dataAsserted) return 'ResData 未断言'
  if (item.dataPassed) return 'ResData 匹配'
  return `ResData 不匹配：${item.dataMismatchPath || '$'}`
}
</script>

<template>
  <section class="mapping-studio" aria-label="DLL 动态映射工作台">
    <div v-if="inventoryUnverified" class="mapping-state-warning" role="alert">
      <span><strong>{{ pendingInventoryRefresh ? '映射操作已经完成，但工作台清单尚未复核' : '映射工作台清单尚未读取' }}</strong><small>{{ pendingInventoryRefresh ? '请勿重复保存、导入或删除；重新读取成功后会恢复当前编辑器和项目门禁。' : '重新读取成功前，映射编辑、调试和项目交付均保持暂停。' }}</small></span>
      <button type="button" :disabled="busy" @click="retryMappingInventory">重新读取映射</button>
    </div>
    <div class="studio-copy" :inert="busy || inventoryUnverified">
      <p class="eyebrow">NATIVE MAPPING STUDIO</p>
      <h2>DLL 动态映射与调试</h2>
      <p>选择 DLL/EXE/BAT，或填写 COM/OCX 标识；配置服务和方法后即可热加载，无需重新打包客户端。</p>
      <button type="button" :disabled="busy || disabled" @click="resetEditor()">新建映射</button>
      <button type="button" :disabled="busy || disabled" @click="inspectMappingImport">选择并预检映射包</button>
      <section v-if="mappingImportPreview" class="mapping-import-preview" aria-label="映射包导入计划">
        <strong>{{ mappingImportPreview.displayName || mappingImportPreview.pluginId }}</strong>
        <small>{{ mappingImportPreview.pluginId }} · {{ mappingImportActionLabel(mappingImportPreview.action) }}</small>
        <p>{{ mappingImportPreview.serviceCount }} 个服务 · {{ mappingImportPreview.methodCount }} 个方法 · {{ mappingImportPreview.debugCaseCount }} 个合成用例</p>
        <ul>
          <li v-for="item in mappingImportPreview.services" :key="item.serviceId">
            <span>{{ item.serviceId }}</span><small>{{ item.architecture }} · {{ item.mainType.toUpperCase() }} · {{ item.methodCount }} 个方法</small>
          </li>
        </ul>
        <p class="mapping-import-warning">本地映射包不提供发布者签名；确认后才会在隔离宿主加载并预检原生代码。仅导入来源可信且已核对摘要的项目文件。</p>
        <button class="primary" type="button" :disabled="busy || disabled" @click="confirmMappingImport">确认计划并热加载</button>
      </section>
      <div class="mapping-cards">
        <article v-for="mapping in inventory.mappings" :key="mapping.pluginId">
          <button type="button" :disabled="busy || disabled" @click="editMapping(mapping)">
            <strong>{{ mapping.displayName || mapping.pluginId }}</strong>
            <small>{{ mapping.pluginId }} · {{ mapping.services.length }} 个服务</small>
          </button>
          <span><button type="button" :disabled="busy || disabled || targetHasUnsavedDraft(mapping.pluginId)" @click="exportTypescript(mapping.pluginId)">TS</button><button type="button" :disabled="busy || disabled || targetHasUnsavedDraft(mapping.pluginId)" @click="exportReleaseSource(mapping.pluginId)">发布源</button><button type="button" :disabled="busy || disabled || targetHasUnsavedDraft(mapping.pluginId)" @click="exportMapping(mapping.pluginId)">迁移包</button><button class="danger-link" type="button" :disabled="busy || disabled" @click="deleteMapping(mapping.pluginId)">删除</button></span>
        </article>
        <p v-if="inventory.mappings.length === 0" class="empty">尚未创建本地映射。</p>
      </div>
      <details v-if="inventory.failures.length" class="mapping-failures">
        <summary>{{ inventory.failures.length }} 项本地映射未加载</summary>
        <ul><li v-for="failure in inventory.failures" :key="failure">{{ failure }}</li></ul>
      </details>
    </div>

    <form class="mapping-editor" :inert="busy || inventoryUnverified" @submit.prevent="saveMapping">
      <div v-if="draftDirty" class="draft-dirty" role="status">当前草稿有未保存更改；当前映射的调试、回归和导出已暂停</div>
      <div class="mapping-heading">
        <label><span>映射 ID</span><input v-model.trim="draft.pluginId" :disabled="editingInstalledMapping" required pattern="[A-Za-z0-9._-]+" placeholder="hospital-device" /></label>
        <label><span>显示名称</span><input v-model.trim="draft.displayName" required placeholder="院内设备接口" /></label>
      </div>
      <p v-if="editingInstalledMapping" class="field-hint">已保存映射的 ID 是稳定路由身份，不能直接改名；需要新身份时请新建映射，验证后再单独删除旧映射。</p>

      <div class="service-tabs">
        <button
          v-for="(item, index) in draft.services"
          :key="index"
          type="button"
          :class="{ active: serviceIndex === index }"
          @click="selectService(index)"
        >{{ item.serviceId || `服务 ${index + 1}` }}</button>
        <button type="button" @click="addService">＋ 服务</button>
      </div>

      <template v-if="service">
        <fieldset>
          <legend>原生组件</legend>
          <div class="field-grid three">
            <label><span>服务 ID</span><input v-model.trim="service.serviceId" required placeholder="DeviceService" /></label>
            <label><span>组件类型</span>
              <select v-model="service.mainType"><option value="dll">DLL</option><option value="com">COM</option><option value="ocx">OCX</option><option value="exe">EXE</option><option value="bat">BAT</option></select>
            </label>
            <label><span>架构</span><select v-model="service.architecture"><option value="x64">x64</option><option value="x86">x86 (32 位)</option></select></label>
          </div>
          <label class="component-path">
            <span>{{ service.mainType === 'com' || service.mainType === 'ocx' ? 'ProgID / CLSID' : '组件文件' }}</span>
            <span><input v-model.trim="service.mainClass" required :placeholder="service.mainType === 'com' || service.mainType === 'ocx' ? 'Vendor.Device.1' : '选择本机文件'" /><button v-if="service.mainType !== 'com' && service.mainType !== 'ocx'" type="button" @click="selectComponent">选择并识别</button></span>
          </label>
          <div v-if="service.mainType === 'com' || service.mainType === 'ocx'" class="com-discovery">
            <div class="com-search">
              <label><span>搜索 Windows 已注册组件（{{ service.architecture }}）</span><input v-model.trim="comQuery" maxlength="128" placeholder="输入 ProgID、CLSID 或组件名称" @keydown.enter.prevent="discoverCom" /></label>
              <button type="button" :disabled="busy || disabled || comQuery.trim().length < 2" @click="discoverCom">搜索注册表</button>
            </div>
            <p>仅只读查询当前架构的 COM 注册视图，不创建组件实例；方法、参数和副作用不会自动推断。</p>
            <div v-if="comDiscovery" class="com-results">
              <button v-for="item in comDiscovery.components" :key="`${item.architecture}:${item.clsid}`" type="button" @click="useComComponent(item)">
                <strong>{{ item.progId || item.versionIndependentProgId || item.clsid }}</strong>
                <span>{{ item.displayName || '未提供组件名称' }}</span>
                <small>{{ item.architecture }} · {{ item.componentType.toUpperCase() }} · {{ comServerLabel(item.serverType) }} · {{ item.clsid }}</small>
              </button>
              <p v-if="comDiscovery.components.length === 0" class="empty">没有匹配的注册组件；请核对架构或缩短厂商名称。</p>
            </div>
          </div>
          <div class="field-grid four">
            <label><span>调用约定</span><select v-model="service.callingConvention"><option value="system">system</option><option value="cdecl">cdecl</option><option value="stdcall">stdcall</option></select></label>
            <label><span>字符集</span><select v-model="service.charset"><option value="utf8">UTF-8</option><option value="gbk">GBK</option></select></label>
            <label><span>超时 (ms)</span><input v-model.number="service.timeout" type="number" min="1" /></label>
            <label class="check"><input v-model="service.cacheable" type="checkbox" /><span>复用组件实例</span></label>
          </div>
          <div class="dependency-list">
            <span>依赖文件</span>
            <div v-for="(_dependency, index) in service.deps" :key="index"><input v-model.trim="service.deps[index]" placeholder="依赖 DLL 的绝对路径" /><button type="button" @click="removeDependency(index)">移除</button></div>
            <button type="button" @click="addDependency">＋ 添加依赖</button>
          </div>
          <div v-if="inspection" class="inspection">
            <strong>{{ inspection.fileName }}</strong><small>{{ (inspection.fileBytes / 1024).toFixed(1) }} KiB · {{ inspection.componentType }} · {{ inspection.architecture || '架构未知' }}</small>
            <p v-for="warning in inspection.warnings" :key="warning">{{ warning }}</p>
            <details v-if="inspection.exports.length" open><summary>{{ inspection.exports.length }} 个导出函数（点击加入方法）</summary><div><button v-for="item in inspection.exports" :key="item" type="button" @click="useExport(item)">{{ item }}</button></div></details>
          </div>
        </fieldset>

        <fieldset>
          <legend>方法映射</legend>
          <div class="method-layout">
            <nav>
              <button v-for="(item, index) in service.methods" :key="index" type="button" :class="{ active: methodIndex === index }" @click="methodIndex = index; debugValues = {}; debugResult = null">{{ item.alias || item.name || `方法 ${index + 1}` }}</button>
              <button type="button" @click="addMethod()">＋ 方法</button>
            </nav>
            <div v-if="method" class="method-editor">
              <div class="field-grid four">
                <label><span>原生函数名</span><input v-model.trim="method.name" required /></label>
                <label><span>网页调用名（可选）</span><input v-model.trim="method.alias" /></label>
                <label><span>返回类型</span><select v-model="method.returnType"><option v-for="item in returnTypeOptions" :key="item">{{ item }}</option></select></label>
                <label><span>超时覆盖 (ms)</span><input v-model.number="method.timeout" type="number" min="0" /></label>
              </div>
              <div class="parameter-table">
                <div class="parameter-head"><span>参数名</span><span>类型</span><span>长度</span><span>字符集</span><span></span></div>
                <div v-for="(_parameter, index) in method.parameters" :key="index" class="parameter-row">
                  <input v-model.trim="parameterAt(index).name" required placeholder="$name 表示输出参数" />
                  <select v-model="parameterAt(index).type"><option v-for="item in parameterTypeOptions(parameterAt(index))" :key="item">{{ item }}</option></select>
                  <input v-model.number="parameterAt(index).len" type="number" min="0" placeholder="0" />
                  <select v-model="parameterAt(index).charset"><option value="">继承</option><option value="utf8">UTF-8</option><option value="gbk">GBK</option></select>
                  <button type="button" @click="removeParameter(index)">移除</button>
                </div>
                <button type="button" @click="addParameter">＋ 添加参数</button>
              </div>
              <div v-if="isComService || method.props.length" class="com-property-list">
                <strong>调用后读取属性</strong>
                <p v-if="isComService">方法执行成功后以 <code>PROPERTYGET</code> 读取，结果与 <code>ReturnValue</code>、输出参数一起进入 <code>ResData</code>；属性类型在生成客户端中保持为 <code>JsonValue</code>。</p>
                <p v-else class="mapping-import-warning">当前组件不是 COM/OCX，请移除已有属性后再保存。</p>
                <div v-for="(_property, index) in method.props" :key="index"><input v-model.trim="method.props[index]" required maxlength="256" placeholder="例如 Count" /><button type="button" @click="removeComProperty(index)">移除</button></div>
                <button v-if="isComService" type="button" @click="addComProperty">＋ 添加返回属性</button>
              </div>
              <p v-if="service.mainType === 'dll'" class="field-hint">DLL 使用最多 12 个机器字参数的受限 ABI：输入支持字符串、布尔和整数，输出支持字符串缓冲区和 32 位整数；浮点、结构体与回调需要专用 Rust 适配器。</p>
              <button class="danger-link" type="button" @click="removeMethod(methodIndex)">删除当前方法</button>
            </div>
          </div>
        </fieldset>

        <fieldset v-if="method" class="debug-panel">
          <legend>现场调试</legend>
          <p>请先保存映射，再输入测试参数。以 <code>$</code> 开头的输出参数无需输入；保存用例时只使用合成数据，不要录入患者、账号或生产密钥。</p>
          <div class="debug-inputs">
            <label v-for="parameter in callableParameters" :key="parameter.name"><span>{{ parameter.name || '未命名参数' }} <small>{{ parameter.type }}</small></span><input v-model="debugValues[parameter.name]" :type="debugInputType(parameter.type)" /></label>
            <p v-if="callableParameters.length === 0">此方法没有输入参数。</p>
          </div>
          <button type="button" :disabled="busy || disabled || draftDirty || !mappingIsInstalled" @click="invokeDebug">运行测试</button>
          <div v-if="debugResult && !draftDirty" class="debug-result" :class="{ failed: debugResult.response.ResCode !== 0 }">
            <strong>ResCode: {{ debugResult.response.ResCode }}</strong><small>{{ debugResult.elapsedMs }} ms</small>
            <pre>{{ JSON.stringify(debugResult.response.ResData, null, 2) }}</pre>
          </div>
          <div class="debug-case-editor">
            <label><span>用例名称</span><input v-model.trim="debugCaseName" maxlength="128" placeholder="例如：模拟设备正常返回" /></label>
            <label><span>期望 ResCode</span><input v-model.number="expectedResCode" type="number" /></label>
            <button type="button" :disabled="busy || disabled || draftDirty || !mappingIsInstalled" @click="saveDebugCase">保存为回归用例</button>
          </div>
          <div class="data-assertion-editor">
            <div>
              <label class="check"><input v-model="assertResData" type="checkbox" /><span>断言期望 ResData 子集</span></label>
              <button v-if="suggestedExpectedDataText" type="button" :disabled="busy || disabled" @click="useSuggestedExpectedData">采用本次 ReturnValue</button>
            </div>
            <label><span>期望 JSON；对象只比较填写的字段，数组和基础值精确比较</span><textarea v-model="expectedResDataText" :disabled="!assertResData" rows="5" placeholder="{ &quot;ReturnValue&quot;: 0 }"></textarea></label>
          </div>
          <div class="debug-case-list">
            <div class="debug-case-heading">
              <strong>已保存回归用例（{{ draft.debugCases.length }}/32）</strong>
              <button type="button" :disabled="busy || disabled || draftDirty || !mappingIsInstalled || draft.debugCases.length === 0" @click="runDebugCases">顺序运行全部</button>
            </div>
            <article v-for="item in draft.debugCases" :key="item.name">
              <button type="button" :disabled="busy || disabled" @click="loadDebugCase(item)">
                <strong>{{ item.name }}</strong><small>{{ item.serviceId }} / {{ item.method }} · ResCode {{ item.expectedResCode }}{{ item.assertResData ? ' · 含 ResData 断言' : '' }}</small>
              </button>
              <button class="danger-link" type="button" :disabled="busy || disabled" @click="deleteDebugCase(item.name)">删除</button>
            </article>
            <p v-if="draft.debugCases.length === 0" class="empty">尚未保存合成回归用例。</p>
          </div>
          <div v-if="regressionResults.length && !draftDirty" class="regression-results">
            <div v-for="item in regressionResults" :key="item.name" :class="{ failed: !item.passed }">
              <strong>{{ item.passed ? '通过' : '失败' }} · {{ item.name }}</strong>
              <small>{{ item.serviceId }} / {{ item.method }} · ResCode {{ item.actualResCode }} / {{ item.expectedResCode }} · {{ regressionDataSummary(item) }} · {{ item.elapsedMs }} ms</small>
            </div>
          </div>
        </fieldset>

        <div class="editor-actions">
          <button class="primary" type="submit" :disabled="busy || disabled">保存、校验并热加载</button>
          <button v-if="draftDirty" type="button" :disabled="busy || disabled" @click="discardDraftChanges">放弃更改</button>
          <button type="button" :disabled="busy || disabled" @click="removeService(serviceIndex)">删除当前服务</button>
        </div>
      </template>
      <p v-if="notice" class="mapping-notice" role="status">{{ notice }}</p>
      <p v-if="error" class="mapping-error" role="alert">操作失败：{{ error }}</p>
    </form>
  </section>
</template>

<style scoped>
.mapping-studio { display: grid; grid-template-columns: minmax(230px, .55fr) 1.45fr; gap: 42px; margin-top: 28px; padding: 42px; border: 1px solid #c9d0c9; border-radius: 18px; background: rgba(255,255,251,.9); }
.mapping-state-warning { grid-column: 1 / -1; display: flex; align-items: center; justify-content: space-between; gap: 18px; margin-bottom: -18px; padding: 14px 16px; border: 1px solid #d5b36a; border-radius: 10px; background: #fff6dd; color: #644b18; }
.mapping-state-warning span { display: grid; gap: 4px; }
.mapping-state-warning small { color: #795f29; }
.studio-copy h2 { margin: 0; font: 500 34px Georgia, "Songti SC", serif; }
.studio-copy > p:not(.eyebrow) { color: #66736b; line-height: 1.7; }
button { padding: 8px 11px; border: 1px solid #9eaaa2; border-radius: 8px; background: #fff; color: #274735; cursor: pointer; }
button:disabled { cursor: wait; opacity: .55; }
.mapping-cards { display: grid; gap: 8px; margin-top: 18px; }
.studio-copy > button + button { margin-left: 6px; }
.mapping-import-preview { display: grid; gap: 7px; margin-top: 14px; padding: 13px; border: 1px solid #d5b36a; border-radius: 10px; background: #fffaf0; }
.mapping-import-preview > strong, .mapping-import-preview > small { overflow-wrap: anywhere; }
.mapping-import-preview > small { color: #718078; }
.mapping-import-preview > p { margin: 0; color: #58665e; font-size: 12px; line-height: 1.5; }
.mapping-import-preview ul { display: grid; gap: 5px; max-height: 180px; margin: 2px 0; padding: 0; overflow: auto; list-style: none; }
.mapping-import-preview li { display: grid; gap: 2px; padding: 7px 8px; border-radius: 7px; background: rgba(255,255,255,.8); font-size: 12px; }
.mapping-import-preview li small { color: #718078; }
.mapping-import-preview .mapping-import-warning { color: #8b5b22; }
.mapping-import-preview .primary { justify-self: start; border-color: #173e2d; background: #173e2d; color: #fff; }
.mapping-cards article { display: grid; grid-template-columns: 1fr auto; gap: 6px; align-items: stretch; }
.mapping-cards article > button:first-child { display: grid; gap: 4px; text-align: left; }
.mapping-cards article > span { display: flex; gap: 5px; }
.mapping-cards small { color: #718078; }
.danger-link { color: #8b3c31; }
.empty { padding: 14px; border: 1px dashed #b9c4bb; border-radius: 10px; color: #718078; }
.mapping-failures { margin-top: 14px; color: #8b3c31; font-size: 12px; }
.mapping-failures li { margin: 8px 0; overflow-wrap: anywhere; }
.mapping-editor { display: grid; min-width: 0; gap: 16px; }
.draft-dirty { justify-self: start; padding: 5px 9px; border: 1px solid #d5b36a; border-radius: 999px; background: #fff6dd; color: #795718; font-size: 12px; font-weight: 800; }
.mapping-heading, .field-grid { display: grid; gap: 12px; }
.mapping-heading { grid-template-columns: .8fr 1.2fr; }
.field-grid.three { grid-template-columns: repeat(3, 1fr); }
.field-grid.four { grid-template-columns: repeat(4, 1fr); }
label { display: grid; gap: 6px; color: #4c5d53; font-size: 12px; font-weight: 700; }
input, select { min-width: 0; width: 100%; padding: 9px 10px; border: 1px solid #bfc9c1; border-radius: 8px; background: #fff; color: #13231c; }
input:focus, select:focus { outline: none; border-color: #2f654b; box-shadow: 0 0 0 3px rgba(47,101,75,.12); }
.service-tabs { display: flex; flex-wrap: wrap; gap: 7px; }
.service-tabs .active, .method-layout nav .active { border-color: #173e2d; background: #173e2d; color: #fff; }
fieldset { min-width: 0; margin: 0; padding: 18px; border: 1px solid #c8d1c9; border-radius: 12px; }
legend { padding: 0 7px; color: #355746; font-size: 13px; font-weight: 800; }
.component-path { margin: 13px 0; }
.component-path > span:last-child { display: grid; grid-template-columns: 1fr auto; gap: 8px; }
.com-discovery { display: grid; gap: 8px; margin: -3px 0 14px; padding: 12px; border: 1px solid #d1d9d2; border-radius: 9px; background: #f6f8f5; }
.com-search { display: grid; grid-template-columns: 1fr auto; gap: 8px; align-items: end; }
.com-discovery > p { margin: 0; color: #718078; font-size: 11px; }
.com-results { display: grid; gap: 6px; max-height: 260px; overflow: auto; }
.com-results > button { display: grid; gap: 3px; text-align: left; }
.com-results > button span { color: #4f6156; font-size: 12px; }
.com-results > button small { overflow-wrap: anywhere; color: #7b8980; font: 10px ui-monospace, monospace; }
.check { display: flex; align-items: center; gap: 7px; padding-top: 22px; }
.check input { width: auto; }
.dependency-list { display: grid; gap: 7px; margin-top: 14px; color: #4c5d53; font-size: 12px; font-weight: 700; }
.dependency-list > div { display: grid; grid-template-columns: 1fr auto; gap: 7px; }
.dependency-list > button { justify-self: start; }
.inspection { margin-top: 14px; padding: 13px; border-radius: 9px; background: #edf3ed; }
.inspection > strong, .inspection > small { display: block; }
.inspection > small { margin-top: 3px; color: #718078; }
.inspection p { color: #8b5b22; font-size: 12px; }
.inspection summary { margin: 10px 0 7px; cursor: pointer; font-size: 12px; font-weight: 700; }
.inspection details div { display: flex; flex-wrap: wrap; gap: 5px; max-height: 180px; overflow: auto; }
.inspection details button { padding: 5px 7px; font: 11px ui-monospace, monospace; }
.method-layout { display: grid; grid-template-columns: 145px 1fr; gap: 14px; }
.method-layout nav { display: grid; align-content: start; gap: 6px; }
.method-layout nav button { overflow: hidden; text-align: left; text-overflow: ellipsis; }
.method-editor { min-width: 0; }
.parameter-table { display: grid; gap: 6px; margin: 14px 0; }
.parameter-head, .parameter-row { display: grid; grid-template-columns: 1.1fr .75fr .55fr .7fr auto; gap: 6px; align-items: center; }
.parameter-head { color: #718078; font-size: 11px; }
.parameter-table > button { justify-self: start; }
.com-property-list { display: grid; gap: 7px; margin: 14px 0; padding: 12px; border: 1px solid #d1d9d2; border-radius: 9px; background: #f6f8f5; color: #4c5d53; font-size: 12px; }
.com-property-list > p { margin: 0; color: #718078; line-height: 1.5; }
.com-property-list > div { display: grid; grid-template-columns: 1fr auto; gap: 7px; }
.com-property-list > button { justify-self: start; }
.com-property-list .mapping-import-warning { color: #8b5b22; }
.debug-panel > p { margin-top: 0; color: #66736b; font-size: 12px; }
.debug-inputs { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 12px 0; }
.debug-inputs label span small { color: #89958d; font-weight: 500; }
.debug-inputs input[type="checkbox"] { width: 18px; }
.debug-result { display: grid; grid-template-columns: 1fr auto; gap: 8px; margin-top: 12px; padding: 12px; border-radius: 9px; background: #e1efe5; }
.debug-result.failed { background: #f8e1dc; color: #8b2e22; }
.debug-result pre { grid-column: 1 / -1; max-height: 230px; margin: 0; padding: 10px; overflow: auto; border-radius: 7px; background: rgba(255,255,255,.7); white-space: pre-wrap; overflow-wrap: anywhere; font-size: 11px; }
.debug-case-editor { display: grid; grid-template-columns: 1fr 150px auto; gap: 9px; align-items: end; margin-top: 14px; padding-top: 14px; border-top: 1px solid #d1d9d2; }
.data-assertion-editor { display: grid; grid-template-columns: 210px 1fr; gap: 10px; align-items: start; margin-top: 10px; }
.data-assertion-editor > div { display: grid; gap: 8px; }
.data-assertion-editor .check { padding-top: 8px; }
.data-assertion-editor textarea { min-width: 0; width: 100%; resize: vertical; padding: 9px 10px; border: 1px solid #bfc9c1; border-radius: 8px; background: #fff; color: #13231c; font: 12px ui-monospace, monospace; }
.data-assertion-editor textarea:disabled { background: #edf0ed; color: #7a857e; }
.debug-case-list { display: grid; gap: 7px; margin-top: 16px; }
.debug-case-heading { display: flex; align-items: center; justify-content: space-between; gap: 10px; color: #355746; font-size: 12px; }
.debug-case-list article { display: grid; grid-template-columns: 1fr auto; gap: 7px; }
.debug-case-list article > button:first-child { display: grid; gap: 3px; text-align: left; }
.debug-case-list article small { color: #718078; }
.regression-results { display: grid; gap: 6px; margin-top: 12px; }
.regression-results div { display: flex; justify-content: space-between; gap: 10px; padding: 9px 11px; border-radius: 8px; background: #e1efe5; }
.regression-results div.failed { background: #f8e1dc; color: #8b2e22; }
.regression-results small { text-align: right; }
.editor-actions { display: flex; gap: 9px; }
.editor-actions .primary { border-color: #173e2d; background: #173e2d; color: #fff; }
.mapping-notice, .mapping-error { margin: 0; padding: 12px; border-radius: 9px; }
.mapping-notice { background: #dfeee4; color: #245338; }
.mapping-error { background: #f8e1dc; color: #8b2e22; }
@media (max-width: 1100px) {
  .mapping-studio { grid-template-columns: 1fr; }
  .field-grid.four { grid-template-columns: repeat(2, 1fr); }
  .debug-case-editor { grid-template-columns: 1fr 150px; }
  .debug-case-editor button { grid-column: 1 / -1; }
  .data-assertion-editor { grid-template-columns: 1fr; }
}
</style>
