<script setup lang="ts">
import { invoke } from '@tauri-apps/api/core'
import { open, save } from '@tauri-apps/plugin-dialog'
import { computed, onMounted, ref } from 'vue'

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
  props: unknown[]
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
}

type MappingInventory = {
  mappings: LocalMappingDefinition[]
  failures: string[]
}

type NativeInspection = {
  fileName: string
  fileBytes: number
  componentType: string
  architecture?: Architecture
  exports: string[]
  warnings: string[]
}

type DebugResult = {
  elapsedMs: number
  response: {
    ResCode: number
    ResData: unknown
    [key: string]: unknown
  }
}

const props = defineProps<{ disabled?: boolean }>()
const emit = defineEmits<{ changed: [] }>()

const inventory = ref<MappingInventory>({ mappings: [], failures: [] })
const draft = ref<LocalMappingDefinition>(newMapping())
const serviceIndex = ref(0)
const methodIndex = ref(0)
const inspection = ref<NativeInspection | null>(null)
const debugValues = ref<Record<string, string | boolean | number>>({})
const debugResult = ref<DebugResult | null>(null)
const busy = ref(false)
const error = ref('')
const notice = ref('')

const service = computed(() => draft.value.services[serviceIndex.value])
const method = computed(() => service.value?.methods[methodIndex.value])
const callableParameters = computed(() => (method.value?.parameters ?? []).filter((item): item is ParameterDefinition => typeof item !== 'string' && !item.name.startsWith('$')))

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
  return { schemaVersion: 1, pluginId: '', displayName: '', services: [newService()] }
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}

function normalizeMapping(mapping: LocalMappingDefinition): LocalMappingDefinition {
  const normalized = clone(mapping)
  for (const item of normalized.services) {
    item.mainType = (item.mainType || 'dll').toLowerCase() as MainType
    item.charset ||= 'utf8'
    item.callingConvention ||= 'system'
    for (const mappedMethod of item.methods) {
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

async function loadInventory() {
  inventory.value = await invoke<MappingInventory>('local_mapping_inventory')
}

onMounted(async () => {
  try {
    await loadInventory()
  } catch (reason) {
    error.value = reasonText(reason)
  }
})

function resetEditor() {
  draft.value = newMapping()
  serviceIndex.value = 0
  methodIndex.value = 0
  inspection.value = null
  debugResult.value = null
  debugValues.value = {}
  error.value = ''
  notice.value = ''
}

function editMapping(mapping: LocalMappingDefinition) {
  draft.value = normalizeMapping(mapping)
  serviceIndex.value = 0
  methodIndex.value = 0
  inspection.value = null
  debugResult.value = null
  debugValues.value = {}
  error.value = ''
  notice.value = `正在编辑 ${mapping.displayName || mapping.pluginId}`
}

function selectService(index: number) {
  serviceIndex.value = index
  methodIndex.value = 0
  inspection.value = null
  debugResult.value = null
  debugValues.value = {}
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

function removeParameter(index: number) {
  method.value?.parameters.splice(index, 1)
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

function useExport(name: string) {
  const existing = service.value?.methods.findIndex((item) => item.name === name) ?? -1
  if (existing >= 0) {
    methodIndex.value = existing
  } else {
    addMethod(name)
  }
}

async function saveMapping() {
  await run(async () => {
    const result = await invoke<{ pluginId: string; serviceCount: number; preflightedHosts: number }>('save_local_mapping', {
      definition: mappingForSave(),
    })
    await loadInventory()
    const saved = inventory.value.mappings.find((item) => item.pluginId === result.pluginId)
    if (saved) editMapping(saved)
    notice.value = `映射已保存并热加载：${result.serviceCount} 个服务，${result.preflightedHosts} 个宿主预检通过。`
    emit('changed')
  })
}

async function deleteMapping(pluginId: string) {
  if (!window.confirm(`确定删除本地映射「${pluginId}」吗？签名插件不会受影响。`)) return
  await run(async () => {
    await invoke('delete_local_mapping', { pluginId })
    await loadInventory()
    if (draft.value.pluginId === pluginId) resetEditor()
    notice.value = `本地映射 ${pluginId} 已删除并从路由卸载。`
    emit('changed')
  })
}

async function exportMapping(pluginId: string) {
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

async function importMapping() {
  const source = await open({
    multiple: false,
    directory: false,
    filters: [{ name: 'SSDEV 本地映射包', extensions: ['ssdev-mapping'] }],
  })
  if (typeof source !== 'string') return
  await run(async () => {
    const result = await invoke<{ pluginId: string; serviceCount: number; preflightedHosts: number }>('import_local_mapping', { source })
    await loadInventory()
    const imported = inventory.value.mappings.find((item) => item.pluginId === result.pluginId)
    if (imported) editMapping(imported)
    notice.value = `映射包已导入并热加载：${result.serviceCount} 个服务。`
    emit('changed')
  })
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

async function invokeDebug() {
  if (!service.value || !method.value) return
  const serviceId = service.value.serviceId.trim()
  const methodName = (method.value.alias || method.value.name).trim()
  if (!serviceId || !methodName) {
    error.value = '请先保存有效的服务 ID 和方法名称。'
    return
  }
  await run(async () => {
    const parameters = Object.fromEntries(callableParameters.value.map((item) => [item.name, convertedValue(item)]))
    debugResult.value = await invoke<DebugResult>('debug_plugin_invoke', {
      request: { serviceId, method: methodName, parameters },
    })
    notice.value = `调用完成，用时 ${debugResult.value.elapsedMs} ms。`
  })
}
</script>

<template>
  <section class="mapping-studio" aria-label="DLL 动态映射工作台">
    <div class="studio-copy">
      <p class="eyebrow">NATIVE MAPPING STUDIO</p>
      <h2>DLL 动态映射与调试</h2>
      <p>选择 DLL/EXE/BAT，或填写 COM/OCX 标识；配置服务和方法后即可热加载，无需重新打包客户端。</p>
      <button type="button" :disabled="busy || disabled" @click="resetEditor">新建映射</button>
      <button type="button" :disabled="busy || disabled" @click="importMapping">导入映射包</button>
      <div class="mapping-cards">
        <article v-for="mapping in inventory.mappings" :key="mapping.pluginId">
          <button type="button" :disabled="busy || disabled" @click="editMapping(mapping)">
            <strong>{{ mapping.displayName || mapping.pluginId }}</strong>
            <small>{{ mapping.pluginId }} · {{ mapping.services.length }} 个服务</small>
          </button>
          <span><button type="button" :disabled="busy || disabled" @click="exportMapping(mapping.pluginId)">导出</button><button class="danger-link" type="button" :disabled="busy || disabled" @click="deleteMapping(mapping.pluginId)">删除</button></span>
        </article>
        <p v-if="inventory.mappings.length === 0" class="empty">尚未创建本地映射。</p>
      </div>
      <details v-if="inventory.failures.length" class="mapping-failures">
        <summary>{{ inventory.failures.length }} 项本地映射未加载</summary>
        <ul><li v-for="failure in inventory.failures" :key="failure">{{ failure }}</li></ul>
      </details>
    </div>

    <form class="mapping-editor" @submit.prevent="saveMapping">
      <div class="mapping-heading">
        <label><span>映射 ID</span><input v-model.trim="draft.pluginId" required pattern="[A-Za-z0-9._-]+" placeholder="hospital-device" /></label>
        <label><span>显示名称</span><input v-model.trim="draft.displayName" required placeholder="院内设备接口" /></label>
      </div>

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
                <label><span>返回类型</span><select v-model="method.returnType"><option>void</option><option>string</option><option>bool</option><option>int</option><option>uint</option><option>pointer</option><option>float</option><option>double</option></select></label>
                <label><span>超时覆盖 (ms)</span><input v-model.number="method.timeout" type="number" min="0" /></label>
              </div>
              <div class="parameter-table">
                <div class="parameter-head"><span>参数名</span><span>类型</span><span>长度</span><span>字符集</span><span></span></div>
                <div v-for="(_parameter, index) in method.parameters" :key="index" class="parameter-row">
                  <input v-model.trim="parameterAt(index).name" required placeholder="$name 表示输出参数" />
                  <select v-model="parameterAt(index).type"><option>string</option><option>bool</option><option>int</option><option>uint</option><option>float</option><option>double</option><option>buffer</option></select>
                  <input v-model.number="parameterAt(index).len" type="number" min="0" placeholder="0" />
                  <select v-model="parameterAt(index).charset"><option value="">继承</option><option value="utf8">UTF-8</option><option value="gbk">GBK</option></select>
                  <button type="button" @click="removeParameter(index)">移除</button>
                </div>
                <button type="button" @click="addParameter">＋ 添加参数</button>
              </div>
              <button class="danger-link" type="button" @click="removeMethod(methodIndex)">删除当前方法</button>
            </div>
          </div>
        </fieldset>

        <fieldset v-if="method" class="debug-panel">
          <legend>现场调试</legend>
          <p>请先保存映射，再在这里输入测试参数。以 <code>$</code> 开头的输出参数无需输入。</p>
          <div class="debug-inputs">
            <label v-for="parameter in callableParameters" :key="parameter.name"><span>{{ parameter.name || '未命名参数' }} <small>{{ parameter.type }}</small></span><input v-model="debugValues[parameter.name]" :type="debugInputType(parameter.type)" /></label>
            <p v-if="callableParameters.length === 0">此方法没有输入参数。</p>
          </div>
          <button type="button" :disabled="busy || disabled" @click="invokeDebug">运行测试</button>
          <div v-if="debugResult" class="debug-result" :class="{ failed: debugResult.response.ResCode !== 0 }">
            <strong>ResCode: {{ debugResult.response.ResCode }}</strong><small>{{ debugResult.elapsedMs }} ms</small>
            <pre>{{ JSON.stringify(debugResult.response.ResData, null, 2) }}</pre>
          </div>
        </fieldset>

        <div class="editor-actions">
          <button class="primary" type="submit" :disabled="busy || disabled">保存、校验并热加载</button>
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
.studio-copy h2 { margin: 0; font: 500 34px Georgia, "Songti SC", serif; }
.studio-copy > p:not(.eyebrow) { color: #66736b; line-height: 1.7; }
button { padding: 8px 11px; border: 1px solid #9eaaa2; border-radius: 8px; background: #fff; color: #274735; cursor: pointer; }
button:disabled { cursor: wait; opacity: .55; }
.mapping-cards { display: grid; gap: 8px; margin-top: 18px; }
.studio-copy > button + button { margin-left: 6px; }
.mapping-cards article { display: grid; grid-template-columns: 1fr auto; gap: 6px; align-items: stretch; }
.mapping-cards article > button:first-child { display: grid; gap: 4px; text-align: left; }
.mapping-cards article > span { display: flex; gap: 5px; }
.mapping-cards small { color: #718078; }
.danger-link { color: #8b3c31; }
.empty { padding: 14px; border: 1px dashed #b9c4bb; border-radius: 10px; color: #718078; }
.mapping-failures { margin-top: 14px; color: #8b3c31; font-size: 12px; }
.mapping-failures li { margin: 8px 0; overflow-wrap: anywhere; }
.mapping-editor { display: grid; min-width: 0; gap: 16px; }
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
.debug-panel > p { margin-top: 0; color: #66736b; font-size: 12px; }
.debug-inputs { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 12px 0; }
.debug-inputs label span small { color: #89958d; font-weight: 500; }
.debug-inputs input[type="checkbox"] { width: 18px; }
.debug-result { display: grid; grid-template-columns: 1fr auto; gap: 8px; margin-top: 12px; padding: 12px; border-radius: 9px; background: #e1efe5; }
.debug-result.failed { background: #f8e1dc; color: #8b2e22; }
.debug-result pre { grid-column: 1 / -1; max-height: 230px; margin: 0; padding: 10px; overflow: auto; border-radius: 7px; background: rgba(255,255,255,.7); white-space: pre-wrap; overflow-wrap: anywhere; font-size: 11px; }
.editor-actions { display: flex; gap: 9px; }
.editor-actions .primary { border-color: #173e2d; background: #173e2d; color: #fff; }
.mapping-notice, .mapping-error { margin: 0; padding: 12px; border-radius: 9px; }
.mapping-notice { background: #dfeee4; color: #245338; }
.mapping-error { background: #f8e1dc; color: #8b2e22; }
@media (max-width: 1100px) {
  .mapping-studio { grid-template-columns: 1fr; }
  .field-grid.four { grid-template-columns: repeat(2, 1fr); }
}
</style>
