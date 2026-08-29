export const CURRENT_BRIDGE_PROTOCOL_VERSION = 1 as const
// Backward-compatible export for existing business applications.
export const CURRENT_PROTOCOL_VERSION = CURRENT_BRIDGE_PROTOCOL_VERSION
export const CURRENT_DESKTOP_CAPABILITIES_SCHEMA_VERSION = 1 as const

export type JsonPrimitive = string | number | boolean | null
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue }
export type JsonObject = { [key: string]: JsonValue }

export interface InvokeResponse<T = JsonValue> {
  ResCode: number
  ResData: T
}

export const PLUGIN_INVOCATION_CONTROL_CODES = Object.freeze({
  capacityBusy: -32001,
  controllerStopping: -32002,
  executionLaneTimeout: -32003,
  pluginReloading: -32010,
} as const)

export type PluginInvocationDisposition = Readonly<
  | {
      kind: 'capacity-busy' | 'execution-lane-timeout' | 'plugin-reloading'
      execution: 'not-executed'
      retry: 'bounded-backoff'
    }
  | {
      kind: 'controller-stopping'
      execution: 'not-executed'
      retry: 'after-restart'
    }
  | {
      kind: 'other'
      execution: 'not-classified'
      retry: 'never-automatically'
    }
>

const PLUGIN_INVOCATION_DISPOSITIONS = Object.freeze({
  capacityBusy: Object.freeze({
    kind: 'capacity-busy',
    execution: 'not-executed',
    retry: 'bounded-backoff',
  }),
  controllerStopping: Object.freeze({
    kind: 'controller-stopping',
    execution: 'not-executed',
    retry: 'after-restart',
  }),
  executionLaneTimeout: Object.freeze({
    kind: 'execution-lane-timeout',
    execution: 'not-executed',
    retry: 'bounded-backoff',
  }),
  pluginReloading: Object.freeze({
    kind: 'plugin-reloading',
    execution: 'not-executed',
    retry: 'bounded-backoff',
  }),
  other: Object.freeze({
    kind: 'other',
    execution: 'not-classified',
    retry: 'never-automatically',
  }),
} as const satisfies Record<string, PluginInvocationDisposition>)

export function classifyPluginInvocationResponse(
  response: Pick<InvokeResponse, 'ResCode'>,
): PluginInvocationDisposition {
  switch (response.ResCode) {
    case PLUGIN_INVOCATION_CONTROL_CODES.capacityBusy:
      return PLUGIN_INVOCATION_DISPOSITIONS.capacityBusy
    case PLUGIN_INVOCATION_CONTROL_CODES.controllerStopping:
      return PLUGIN_INVOCATION_DISPOSITIONS.controllerStopping
    case PLUGIN_INVOCATION_CONTROL_CODES.executionLaneTimeout:
      return PLUGIN_INVOCATION_DISPOSITIONS.executionLaneTimeout
    case PLUGIN_INVOCATION_CONTROL_CODES.pluginReloading:
      return PLUGIN_INVOCATION_DISPOSITIONS.pluginReloading
    default:
      return PLUGIN_INVOCATION_DISPOSITIONS.other
  }
}

export function wasPluginInvocationGuaranteedNotExecuted(
  response: Pick<InvokeResponse, 'ResCode'>,
): boolean {
  return classifyPluginInvocationResponse(response).execution === 'not-executed'
}

export function canRetryPluginInvocationWithBackoff(
  response: Pick<InvokeResponse, 'ResCode'>,
): boolean {
  return classifyPluginInvocationResponse(response).retry === 'bounded-backoff'
}

export interface PluginInvoker {
  invokePlugin<T = JsonValue>(
    serviceId: string,
    method: string,
    parameters?: JsonObject,
  ): Promise<InvokeResponse<T>>
}

export interface PluginInvocationFixture<T = JsonValue> {
  serviceId: string
  method: string
  parameters?: JsonObject
  response: InvokeResponse<T>
}

export type InvalidPluginFixtureReason =
  | 'fixtures-not-array'
  | 'too-many-fixtures'
  | 'invalid-fixture'
  | 'invalid-route'
  | 'invalid-parameters'
  | 'invalid-response'
  | 'duplicate-invocation'

export class InvalidPluginFixtureError extends Error {
  override readonly name = 'InvalidPluginFixtureError'
  readonly reason: InvalidPluginFixtureReason
  readonly fixtureIndex: number | null

  constructor(reason: InvalidPluginFixtureReason, fixtureIndex: number | null = null) {
    super(fixtureIndex === null
      ? `SSDEV plugin fixtures are invalid (${reason})`
      : `SSDEV plugin fixture ${fixtureIndex} is invalid (${reason})`)
    this.reason = reason
    this.fixtureIndex = fixtureIndex
  }
}

export class UnexpectedPluginInvocationError extends Error {
  override readonly name = 'UnexpectedPluginInvocationError'
  readonly serviceId: string
  readonly method: string

  constructor(serviceId: string, method: string) {
    super(`No SSDEV plugin fixture matches route [${serviceId}/${method}] and the supplied parameters`)
    this.serviceId = serviceId
    this.method = method
  }
}

const MAX_PLUGIN_FIXTURES = 1024
const MAX_FIXTURE_ROUTE_LENGTH = 256
const MAX_FIXTURE_JSON_DEPTH = 64

/**
 * Creates a deterministic PluginInvoker for business-frontend unit tests.
 * It never installs a global desktop bridge and intentionally does not model
 * tracked invocations, timing, retries, or native hardware side effects.
 */
export function createPluginFixtureInvoker(
  fixtures: readonly PluginInvocationFixture[],
): PluginInvoker {
  if (!Array.isArray(fixtures)) {
    throw new InvalidPluginFixtureError('fixtures-not-array')
  }
  if (fixtures.length > MAX_PLUGIN_FIXTURES) {
    throw new InvalidPluginFixtureError('too-many-fixtures')
  }

  const responses = new Map<string, string>()
  for (const [index, fixture] of fixtures.entries()) {
    if (!isRecord(fixture) || !hasOnlyFixtureFields(fixture)) {
      throw new InvalidPluginFixtureError('invalid-fixture', index)
    }
    if (!isFixtureRoute(fixture.serviceId) || !isFixtureRoute(fixture.method)) {
      throw new InvalidPluginFixtureError('invalid-route', index)
    }
    const parameters = fixture.parameters ?? {}
    if (!isRecord(parameters)) {
      throw new InvalidPluginFixtureError('invalid-parameters', index)
    }
    let parameterJson: string
    try {
      parameterJson = canonicalFixtureJson(parameters)
    } catch {
      throw new InvalidPluginFixtureError('invalid-parameters', index)
    }
    if (!isFixtureResponse(fixture.response)) {
      throw new InvalidPluginFixtureError('invalid-response', index)
    }
    let responseJson: string
    try {
      responseJson = canonicalFixtureJson(fixture.response)
    } catch {
      throw new InvalidPluginFixtureError('invalid-response', index)
    }
    const key = fixtureInvocationKey(fixture.serviceId, fixture.method, parameterJson)
    if (responses.has(key)) {
      throw new InvalidPluginFixtureError('duplicate-invocation', index)
    }
    responses.set(key, responseJson)
  }

  return Object.freeze({
    async invokePlugin<T = JsonValue>(
      serviceId: string,
      method: string,
      parameters: JsonObject = {},
    ): Promise<InvokeResponse<T>> {
      let parameterJson: string
      try {
        if (!isFixtureRoute(serviceId) || !isFixtureRoute(method) || !isRecord(parameters)) {
          throw new Error('invalid invocation')
        }
        parameterJson = canonicalFixtureJson(parameters)
      } catch {
        throw new UnexpectedPluginInvocationError(serviceId, method)
      }
      const responseJson = responses.get(fixtureInvocationKey(serviceId, method, parameterJson))
      if (responseJson === undefined) {
        throw new UnexpectedPluginInvocationError(serviceId, method)
      }
      return JSON.parse(responseJson) as InvokeResponse<T>
    },
  })
}

export type TrackedInvocationStatus<T = JsonValue> =
  | { state: 'unknown' }
  | { state: 'pending' }
  | { state: 'completed'; response: InvokeResponse<T>; durable: boolean }
  | { state: 'indeterminate' }
  | { state: 'completedWithoutResult' }

export interface TrackedInvocationLimits {
  maxRuntimeOperations: number
  maxRetainedResponseBytes: number
  runtimeResultRetentionSeconds: number
  maxDurableOperations: number
  maxDurableOperationsPerScope: number
  completedRetentionSeconds: number
  indeterminateRetentionSeconds: number
}

export interface TrackedInvocationCapabilities {
  supported: boolean
  available: boolean
  accepting: boolean
  errorCode: string | null
  limits: TrackedInvocationLimits
}

export interface DesktopCapabilities {
  schemaVersion: typeof CURRENT_DESKTOP_CAPABILITIES_SCHEMA_VERSION
  trackedInvocations: TrackedInvocationCapabilities
}

export interface UnknownDesktopCapabilities {
  schemaVersion: number
  [capability: string]: unknown
}

export type DesktopCapabilitiesDeclaration =
  | DesktopCapabilities
  | UnknownDesktopCapabilities

export interface SystemDeclaration {
  os: string
  architecture: string
  appVersion: string
  protocolVersion: number
  /** Absent on desktop clients released before explicit capability negotiation. */
  capabilities?: DesktopCapabilitiesDeclaration
}

export interface SecondaryWindowRequest {
  url: string
  title?: string
  screenIndex?: number
  context?: JsonObject
  /** Must be provided together with height. Supplying a size opens a non-maximized window. */
  width?: number
  /** Must be provided together with width. */
  height?: number
  /** Desktop logical coordinate; must be provided together with top. */
  left?: number
  /** Desktop logical coordinate; must be provided together with left. */
  top?: number
}

export interface FloatingWindowRequest {
  id: string
  url: string
  durationMs?: number
  width?: number
  height?: number
  context?: JsonObject
}

export interface SsdevDesktopBridge extends PluginInvoker {
  invokePluginTracked?<T = JsonValue>(
    operationId: string,
    serviceId: string,
    method: string,
    parameters?: JsonObject,
  ): Promise<TrackedInvocationStatus<T>>
  getPluginInvocation?<T = JsonValue>(
    operationId: string,
    serviceId: string,
    method: string,
  ): Promise<TrackedInvocationStatus<T>>
  getSystemInfo(): Promise<SystemDeclaration>
  captureWindow(): Promise<string>
  openExternal(url: string): Promise<void>
  openWindow(request: SecondaryWindowRequest): Promise<string>
  showFloating(request: FloatingWindowRequest): Promise<string>
  closeFloating(id: string): Promise<void>
}

export const BRIDGE_METHODS = [
  'invokePlugin',
  'getSystemInfo',
  'captureWindow',
  'openExternal',
  'openWindow',
  'showFloating',
  'closeFloating',
] as const satisfies readonly (keyof SsdevDesktopBridge)[]

export const TRACKED_INVOCATION_METHODS = [
  'invokePluginTracked',
  'getPluginInvocation',
] as const satisfies readonly (keyof SsdevDesktopBridge)[]

export const BRIDGE_EVENTS = [
  'ssdev-capture',
  'ssdev-floating-action',
] as const

export type DesktopBridgeEvent = (typeof BRIDGE_EVENTS)[number]

export interface DesktopConnection {
  readonly bridge: SsdevDesktopBridge
  readonly system: Readonly<SystemDeclaration>
  readonly context: Readonly<JsonObject>
}

export interface ConnectOptions {
  supportedProtocolVersions?: readonly number[]
}

export class DesktopBridgeUnavailableError extends Error {
  override readonly name = 'DesktopBridgeUnavailableError'

  constructor() {
    super('SSDEV Desktop bridge is unavailable; open this page inside an authorized desktop business window')
  }
}

export class UnsupportedDesktopProtocolError extends Error {
  override readonly name = 'UnsupportedDesktopProtocolError'
  readonly actualVersion: number
  readonly supportedVersions: readonly number[]

  constructor(actualVersion: number, supportedVersions: readonly number[]) {
    super(`SSDEV Desktop protocol ${actualVersion} is not supported; expected one of [${supportedVersions.join(', ')}]`)
    this.actualVersion = actualVersion
    this.supportedVersions = supportedVersions
  }
}

export type InvalidDesktopDeclarationReason =
  | 'declaration-not-object'
  | 'invalid-os'
  | 'invalid-architecture'
  | 'invalid-app-version'
  | 'invalid-protocol-version'
  | 'invalid-capabilities'
  | 'invalid-tracked-invocations'

export class InvalidDesktopDeclarationError extends Error {
  override readonly name = 'InvalidDesktopDeclarationError'
  readonly reason: InvalidDesktopDeclarationReason

  constructor(reason: InvalidDesktopDeclarationReason) {
    super(`SSDEV Desktop returned an invalid system declaration (${reason})`)
    this.reason = reason
  }
}

export class TrackedInvocationsUnavailableError extends Error {
  override readonly name = 'TrackedInvocationsUnavailableError'
  readonly errorCode: string | undefined

  constructor(errorCode?: string) {
    super(errorCode
      ? `SSDEV Desktop tracked plugin invocations are unavailable (${errorCode})`
      : 'SSDEV Desktop tracked plugin invocations are unavailable; update the desktop client before using operation IDs')
    this.errorCode = errorCode
  }
}

export type TrackedInvocationBridge = SsdevDesktopBridge & {
  invokePluginTracked: NonNullable<SsdevDesktopBridge['invokePluginTracked']>
  getPluginInvocation: NonNullable<SsdevDesktopBridge['getPluginInvocation']>
}

type DesktopGlobals = typeof globalThis & {
  ssdevDesktop?: SsdevDesktopBridge
  webPlusInvoke?: SsdevDesktopBridge['invokePlugin']
  ssdevDesktopContext?: JsonObject
}

function globals(): DesktopGlobals {
  return globalThis as DesktopGlobals
}

function isCompleteBridge(value: unknown): value is SsdevDesktopBridge {
  if (typeof value !== 'object' || value === null) return false
  const bridge = value as Record<string, unknown>
  return BRIDGE_METHODS.every((method) => typeof bridge[method] === 'function')
}

export function isDesktopBridgeAvailable(): boolean {
  return isCompleteBridge(globals().ssdevDesktop)
}

export function requireDesktopBridge(): SsdevDesktopBridge {
  const bridge = globals().ssdevDesktop
  if (!isCompleteBridge(bridge)) {
    throw new DesktopBridgeUnavailableError()
  }
  return bridge
}

export function supportsTrackedPluginInvocations(
  bridge: SsdevDesktopBridge = requireDesktopBridge(),
  system?: SystemDeclaration,
): bridge is TrackedInvocationBridge {
  const candidate = bridge as unknown as Record<string, unknown>
  if (!TRACKED_INVOCATION_METHODS.every((method) => typeof candidate[method] === 'function')) {
    return false
  }
  if (system === undefined) {
    return true
  }
  const capability = getTrackedInvocationCapabilities(system)
  return capability?.supported === true
    && capability.available
    && capability.accepting
}

export function requireTrackedPluginInvocations(
  bridge: SsdevDesktopBridge = requireDesktopBridge(),
  system?: SystemDeclaration,
): TrackedInvocationBridge {
  if (!supportsTrackedPluginInvocations(bridge, system)) {
    const capability = system === undefined
      ? null
      : getTrackedInvocationCapabilities(system)
    const errorCode = capability === null
      ? (system === undefined ? undefined : 'tracked-capability-undeclared')
      : capability.errorCode
        ?? (!capability.supported
          ? 'tracked-invocation-unsupported'
          : !capability.available
            ? 'tracked-invocation-unavailable'
            : 'tracked-invocation-stopping')
    throw new TrackedInvocationsUnavailableError(errorCode)
  }
  return bridge
}

export function getTrackedInvocationCapabilities(
  system: SystemDeclaration,
): Readonly<TrackedInvocationCapabilities> | null {
  const capabilities = system.capabilities
  return isCurrentDesktopCapabilities(capabilities)
    ? capabilities.trackedInvocations
    : null
}

export function createPluginOperationId(): string {
  const randomUUID = globalThis.crypto?.randomUUID
  if (typeof randomUUID !== 'function') {
    throw new TrackedInvocationsUnavailableError()
  }
  return randomUUID.call(globalThis.crypto)
}

type UnknownRecord = Record<string, unknown>

const TRACKED_INVOCATION_LIMIT_FIELDS = [
  'maxRuntimeOperations',
  'maxRetainedResponseBytes',
  'runtimeResultRetentionSeconds',
  'maxDurableOperations',
  'maxDurableOperationsPerScope',
  'completedRetentionSeconds',
  'indeterminateRetentionSeconds',
] as const satisfies readonly (keyof TrackedInvocationLimits)[]

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasOnlyFixtureFields(value: UnknownRecord): boolean {
  return Object.keys(value).every((key) => (
    key === 'serviceId'
    || key === 'method'
    || key === 'parameters'
    || key === 'response'
  ))
    && Object.hasOwn(value, 'serviceId')
    && Object.hasOwn(value, 'method')
    && Object.hasOwn(value, 'response')
}

function isFixtureRoute(value: unknown): value is string {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= MAX_FIXTURE_ROUTE_LENGTH
    && value.trim() === value
    && ![...value].some((character) => {
      const code = character.charCodeAt(0)
      return code <= 0x1f || code === 0x7f
    })
}

function isFixtureResponse(value: unknown): value is InvokeResponse {
  if (!isRecord(value)) return false
  const keys = Object.keys(value).sort()
  return keys.length === 2
    && keys[0] === 'ResCode'
    && keys[1] === 'ResData'
    && Number.isSafeInteger(value.ResCode)
}

function fixtureInvocationKey(serviceId: string, method: string, parameterJson: string): string {
  return JSON.stringify([serviceId, method, parameterJson])
}

function canonicalFixtureJson(
  value: unknown,
  depth = 0,
  ancestors = new Set<object>(),
): string {
  if (depth > MAX_FIXTURE_JSON_DEPTH) {
    throw new Error('fixture JSON is too deeply nested')
  }
  if (value === null) return 'null'
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return JSON.stringify(value)
    case 'number':
      if (!Number.isFinite(value)) throw new Error('fixture JSON number is not finite')
      if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
        throw new Error('fixture JSON integer is outside the JavaScript safe range')
      }
      return JSON.stringify(value)
    case 'object': {
      if (ancestors.has(value)) throw new Error('fixture JSON is cyclic')
      ancestors.add(value)
      try {
        if (Array.isArray(value)) {
          const entries = []
          for (let index = 0; index < value.length; index += 1) {
            if (!Object.hasOwn(value, index)) {
              throw new Error('fixture JSON array is sparse')
            }
            entries.push(canonicalFixtureJson(value[index], depth + 1, ancestors))
          }
          return `[${entries.join(',')}]`
        }
        const prototype = Object.getPrototypeOf(value)
        if (prototype !== Object.prototype && prototype !== null) {
          throw new Error('fixture JSON object is not plain')
        }
        const record = value as UnknownRecord
        return `{${Object.keys(record)
          .sort()
          .map((key) => `${JSON.stringify(key)}:${canonicalFixtureJson(record[key], depth + 1, ancestors)}`)
          .join(',')}}`
      } finally {
        ancestors.delete(value)
      }
    }
    default:
      throw new Error('fixture value is not JSON')
  }
}

function isBoundedIdentifier(value: unknown, maximumLength: number): value is string {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= maximumLength
    && !value.includes('\0')
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

function isTrackedInvocationLimits(value: unknown): value is TrackedInvocationLimits {
  if (!isRecord(value)) return false
  return TRACKED_INVOCATION_LIMIT_FIELDS.every((field) => isNonNegativeSafeInteger(value[field]))
}

function isTrackedInvocationCapabilities(value: unknown): value is TrackedInvocationCapabilities {
  if (!isRecord(value)) return false
  if (typeof value.supported !== 'boolean'
    || typeof value.available !== 'boolean'
    || typeof value.accepting !== 'boolean') {
    return false
  }
  if (value.available && !value.supported) return false
  if (value.accepting && !value.available) return false
  if (value.errorCode !== null && !isBoundedIdentifier(value.errorCode, 128)) return false
  return isTrackedInvocationLimits(value.limits)
}

function isCurrentDesktopCapabilities(value: unknown): value is DesktopCapabilities {
  return isRecord(value)
    && value.schemaVersion === CURRENT_DESKTOP_CAPABILITIES_SCHEMA_VERSION
    && isTrackedInvocationCapabilities(value.trackedInvocations)
}

function validateSystemDeclaration(value: unknown): SystemDeclaration {
  if (!isRecord(value)) {
    throw new InvalidDesktopDeclarationError('declaration-not-object')
  }
  if (!isBoundedIdentifier(value.os, 64)) {
    throw new InvalidDesktopDeclarationError('invalid-os')
  }
  if (!isBoundedIdentifier(value.architecture, 64)) {
    throw new InvalidDesktopDeclarationError('invalid-architecture')
  }
  if (!isBoundedIdentifier(value.appVersion, 128)) {
    throw new InvalidDesktopDeclarationError('invalid-app-version')
  }
  if (!isNonNegativeSafeInteger(value.protocolVersion)
    || value.protocolVersion === 0
    || value.protocolVersion > 65_535) {
    throw new InvalidDesktopDeclarationError('invalid-protocol-version')
  }
  if (value.capabilities === undefined) {
    return value as unknown as SystemDeclaration
  }
  if (!isRecord(value.capabilities)
    || !isNonNegativeSafeInteger(value.capabilities.schemaVersion)
    || value.capabilities.schemaVersion === 0
    || value.capabilities.schemaVersion > 65_535) {
    throw new InvalidDesktopDeclarationError('invalid-capabilities')
  }
  if (value.capabilities.schemaVersion === CURRENT_DESKTOP_CAPABILITIES_SCHEMA_VERSION
    && !isTrackedInvocationCapabilities(value.capabilities.trackedInvocations)) {
    throw new InvalidDesktopDeclarationError('invalid-tracked-invocations')
  }
  return value as unknown as SystemDeclaration
}

function freezeSystemDeclaration(system: SystemDeclaration): Readonly<SystemDeclaration> {
  const capabilities = system.capabilities
  if (capabilities === undefined) {
    return Object.freeze({ ...system })
  }
  if (!isCurrentDesktopCapabilities(capabilities)) {
    return Object.freeze({
      ...system,
      capabilities: Object.freeze({ ...capabilities }),
    })
  }
  return Object.freeze({
    ...system,
    capabilities: Object.freeze({
      ...capabilities,
      trackedInvocations: Object.freeze({
        ...capabilities.trackedInvocations,
        limits: Object.freeze({ ...capabilities.trackedInvocations.limits }),
      }),
    }),
  })
}

export async function connectDesktop(options: ConnectOptions = {}): Promise<DesktopConnection> {
  const bridge = requireDesktopBridge()
  const system = validateSystemDeclaration(await bridge.getSystemInfo())
  const supported = options.supportedProtocolVersions ?? [CURRENT_BRIDGE_PROTOCOL_VERSION]
  if (!supported.includes(system.protocolVersion)) {
    throw new UnsupportedDesktopProtocolError(system.protocolVersion, supported)
  }
  const context = globals().ssdevDesktopContext ?? {}
  return Object.freeze({
    bridge,
    system: freezeSystemDeclaration(system),
    context: Object.freeze({ ...context }),
  })
}

declare global {
  interface Window {
    readonly ssdevDesktop?: SsdevDesktopBridge
    readonly webPlusInvoke?: SsdevDesktopBridge['invokePlugin']
    readonly ssdevDesktopContext?: Readonly<JsonObject>
  }
}
