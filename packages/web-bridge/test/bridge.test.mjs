import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import test from 'node:test'

import {
  BRIDGE_METHODS,
  BRIDGE_EVENTS,
  CURRENT_DESKTOP_CAPABILITIES_SCHEMA_VERSION,
  CURRENT_BRIDGE_PROTOCOL_VERSION,
  CURRENT_PROTOCOL_VERSION,
  CURRENT_TRACKED_INVOCATION_ERROR_SCHEMA_VERSION,
  DesktopBridgeUnavailableError,
  InvalidTrackedInvocationStatusError,
  InvalidPluginOperationIdError,
  InvalidPluginFixtureError,
  InvalidDesktopDeclarationError,
  PLUGIN_INVOCATION_CONTROL_CODES,
  UnsupportedDesktopProtocolError,
  TRACKED_INVOCATION_METHODS,
  TRACKED_INVOCATION_ERROR_PHASES,
  TRACKED_INVOCATION_STATES,
  TrackedInvocationsUnavailableError,
  UnexpectedPluginInvocationError,
  canRetryPluginInvocationWithBackoff,
  classifyPluginInvocationResponse,
  classifyTrackedInvocationFailure,
  classifyTrackedInvocationStatus,
  connectDesktop,
  createPluginFixtureInvoker,
  createPluginOperationId,
  getTrackedInvocationCapabilities,
  isPluginOperationId,
  isTrackedInvocationCommandError,
  isTrackedInvocationStatus,
  isDesktopBridgeAvailable,
  parsePluginOperationId,
  parseTrackedInvocationStatus,
  requireDesktopBridge,
  requireTrackedPluginInvocations,
  settleTrackedInvocation,
  supportsTrackedPluginInvocations,
  wasPluginInvocationGuaranteedNotExecuted,
} from '../dist/index.js'

const contract = JSON.parse(
  await readFile(new URL('../bridge-contract.json', import.meta.url), 'utf8'),
)
const packageManifest = JSON.parse(
  await readFile(new URL('../package.json', import.meta.url), 'utf8'),
)
const execFileAsync = promisify(execFile)

function clearBridge() {
  delete globalThis.ssdevDesktop
  delete globalThis.webPlusInvoke
  delete globalThis.ssdevDesktopContext
}

test.afterEach(clearBridge)

test('matches the shared desktop bridge contract', () => {
  assert.equal(contract.schemaVersion, 7)
  assert.equal(CURRENT_BRIDGE_PROTOCOL_VERSION, contract.protocolVersion)
  assert.equal(CURRENT_PROTOCOL_VERSION, contract.protocolVersion)
  assert.equal(CURRENT_DESKTOP_CAPABILITIES_SCHEMA_VERSION, contract.capabilities.schemaVersion)
  assert.deepEqual(BRIDGE_METHODS, contract.methods)
  assert.deepEqual(TRACKED_INVOCATION_METHODS, contract.optionalMethods)
  assert.deepEqual(BRIDGE_EVENTS, contract.events)
  assert.deepEqual(PLUGIN_INVOCATION_CONTROL_CODES, contract.pluginInvocationControlCodes)
  assert.equal(
    CURRENT_TRACKED_INVOCATION_ERROR_SCHEMA_VERSION,
    contract.trackedInvocationError.schemaVersion,
  )
  assert.deepEqual(TRACKED_INVOCATION_ERROR_PHASES, contract.trackedInvocationError.phases)
  assert.equal(Object.isFrozen(TRACKED_INVOCATION_ERROR_PHASES), true)
  assert.deepEqual(contract.trackedInvocationError.fields, [
    'schemaVersion',
    'kind',
    'phase',
    'code',
  ])
  assert.deepEqual(TRACKED_INVOCATION_STATES, contract.trackedInvocationStatus.states)
  assert.equal(Object.isFrozen(TRACKED_INVOCATION_STATES), true)
  assert.deepEqual(contract.trackedInvocationStatus.stateFields, {
    unknown: ['state'],
    pending: ['state'],
    completed: ['state', 'response', 'durable'],
    indeterminate: ['state'],
    completedWithoutResult: ['state'],
  })
  assert.deepEqual(contract.trackedInvocationStatus.responseFields, ['ResCode', 'ResData'])
})

test('classifies only controller rejections that prove native execution never started', () => {
  const expected = [
    [-32001, 'capacity-busy', 'bounded-backoff'],
    [-32002, 'controller-stopping', 'after-restart'],
    [-32003, 'execution-lane-timeout', 'bounded-backoff'],
    [-32004, 'tracked-invocation-required', 'use-tracked-invocation'],
    [-32010, 'plugin-reloading', 'bounded-backoff'],
  ]
  for (const [ResCode, kind, retry] of expected) {
    const response = { ResCode }
    assert.deepEqual(classifyPluginInvocationResponse(response), {
      kind,
      execution: 'not-executed',
      retry,
    })
    assert.equal(wasPluginInvocationGuaranteedNotExecuted(response), true)
    assert.equal(canRetryPluginInvocationWithBackoff(response), retry === 'bounded-backoff')
  }

  for (const ResCode of [0, 1, -32000, -32601]) {
    const response = { ResCode }
    assert.deepEqual(classifyPluginInvocationResponse(response), {
      kind: 'other',
      execution: 'not-classified',
      retry: 'never-automatically',
    })
    assert.equal(wasPluginInvocationGuaranteedNotExecuted(response), false)
    assert.equal(canRetryPluginInvocationWithBackoff(response), false)
  }
})

test('distinguishes tracked API support from current runtime availability', () => {
  const bridge = {
    invokePlugin: async () => ({ ResCode: 0, ResData: null }),
    invokePluginTracked: async () => ({ state: 'completed', response: { ResCode: 0, ResData: null }, durable: true }),
    getPluginInvocation: async () => ({ state: 'unknown' }),
    getSystemInfo: async () => unavailableSystem,
    captureWindow: async () => '',
    openExternal: async () => {},
    openWindow: async () => 'business-2',
    showFloating: async () => 'floating-3',
    closeFloating: async () => {},
  }
  const limits = {
    maxRuntimeOperations: 64,
    maxRetainedResponseBytes: 524288,
    runtimeResultRetentionSeconds: 600,
    maxDurableOperations: 65536,
    maxDurableOperationsPerScope: 16384,
    completedRetentionSeconds: 86400,
    indeterminateRetentionSeconds: 2592000,
  }
  const unavailableSystem = {
    os: 'windows',
    architecture: 'x86_64',
    appVersion: '1.0.0',
    protocolVersion: 1,
    capabilities: {
      schemaVersion: 1,
      trackedInvocations: {
        supported: true,
        available: false,
        accepting: false,
        errorCode: 'operation-ledger-io',
        limits,
      },
    },
  }
  assert.deepEqual(
    Object.keys(unavailableSystem.capabilities.trackedInvocations),
    contract.capabilities.trackedInvocations,
  )
  assert.deepEqual(Object.keys(limits), contract.capabilities.trackedInvocationLimits)

  assert.equal(supportsTrackedPluginInvocations(bridge), true)
  assert.equal(supportsTrackedPluginInvocations(bridge, unavailableSystem), false)
  assert.throws(
    () => requireTrackedPluginInvocations(bridge, unavailableSystem),
    (error) => error instanceof TrackedInvocationsUnavailableError
      && error.errorCode === 'operation-ledger-io',
  )

  const availableSystem = structuredClone(unavailableSystem)
  availableSystem.capabilities.trackedInvocations.available = true
  availableSystem.capabilities.trackedInvocations.accepting = true
  availableSystem.capabilities.trackedInvocations.errorCode = null
  assert.equal(supportsTrackedPluginInvocations(bridge, availableSystem), true)
  assert.equal(
    getTrackedInvocationCapabilities(availableSystem).limits.maxDurableOperations,
    65536,
  )

  availableSystem.capabilities.trackedInvocations.accepting = false
  assert.throws(
    () => requireTrackedPluginInvocations(bridge, availableSystem),
    (error) => error instanceof TrackedInvocationsUnavailableError
      && error.errorCode === 'tracked-invocation-stopping',
  )
})

test('keeps tracked invocations additive for older desktop clients', () => {
  globalThis.ssdevDesktop = {
    invokePlugin: async () => ({ ResCode: 0, ResData: null }),
    getSystemInfo: async () => ({ os: 'windows', architecture: 'x86_64', appVersion: '1.0.0', protocolVersion: 1 }),
    captureWindow: async () => '',
    openExternal: async () => {},
    openWindow: async () => 'business-2',
    showFloating: async () => 'floating-3',
    closeFloating: async () => {},
  }

  assert.equal(isDesktopBridgeAvailable(), true)
  assert.equal(supportsTrackedPluginInvocations(globalThis.ssdevDesktop), false)
  assert.throws(
    () => requireTrackedPluginInvocations(globalThis.ssdevDesktop),
    TrackedInvocationsUnavailableError,
  )
})

test('creates canonical random operation IDs when tracked calls are available', () => {
  const operationId = createPluginOperationId()
  assert.match(operationId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
  assert.equal(isPluginOperationId(operationId), true)
  assert.equal(parsePluginOperationId(operationId), operationId)
})

test('accepts only canonical UUID v4 operation IDs recovered from storage', () => {
  const canonical = '123e4567-e89b-42d3-a456-426614174000'
  assert.equal(isPluginOperationId(canonical), true)
  assert.equal(parsePluginOperationId(canonical), canonical)

  const invalid = [
    null,
    1,
    '',
    canonical.toUpperCase(),
    canonical.replaceAll('-', ''),
    '123e4567-e89b-12d3-a456-426614174000',
    '123e4567-e89b-42d3-7456-426614174000',
    `${canonical}-secret-suffix`,
  ]
  for (const value of invalid) {
    assert.equal(isPluginOperationId(value), false)
    assert.throws(
      () => parsePluginOperationId(value),
      (error) => error instanceof InvalidPluginOperationIdError
        && error.message === 'SSDEV plugin operation ID must be a canonical UUID v4'
        && !error.message.includes('secret-suffix'),
    )
  }
})

test('validates every tracked outcome and preserves completion durability', () => {
  const cases = [
    [
      { state: 'unknown' },
      { kind: 'unknown', execution: 'unknown', next: 'apply-business-recovery-policy', automaticReplay: 'forbidden' },
    ],
    [
      { state: 'pending' },
      { kind: 'pending', execution: 'in-progress', next: 'query-same-operation', automaticReplay: 'forbidden' },
    ],
    [
      { state: 'completed', response: { ResCode: 0, ResData: { ReturnValue: 0 } }, durable: true },
      { kind: 'completed', execution: 'completed', durability: 'confirmed', next: 'handle-response', automaticReplay: 'forbidden' },
    ],
    [
      { state: 'completed', response: { ResCode: 0, ResData: { ReturnValue: 0 } }, durable: false },
      { kind: 'completed', execution: 'completed', durability: 'not-confirmed', next: 'handle-response-and-record-recovery-risk', automaticReplay: 'forbidden' },
    ],
    [
      { state: 'indeterminate' },
      { kind: 'indeterminate', execution: 'possibly-executed', next: 'reconcile-before-new-operation', automaticReplay: 'forbidden' },
    ],
    [
      { state: 'completedWithoutResult' },
      { kind: 'completedWithoutResult', execution: 'possibly-executed', next: 'reconcile-before-new-operation', automaticReplay: 'forbidden' },
    ],
  ]

  for (const [status, expected] of cases) {
    assert.equal(isTrackedInvocationStatus(status), true)
    assert.equal(parseTrackedInvocationStatus(status), status)
    const disposition = classifyTrackedInvocationStatus(status)
    assert.deepEqual(disposition, expected)
    assert.equal(Object.isFrozen(disposition), true)
  }

  const cyclic = { ReturnValue: 0 }
  cyclic.self = cyclic
  const invalid = [
    null,
    {},
    { state: 'completed-without-result' },
    { state: 1 },
    { state: 'pending', detail: 'secret' },
    { state: 'completed', durable: true },
    { state: 'completed', response: { ResCode: 0, ResData: null }, durable: 'true' },
    { state: 'completed', response: { ResCode: 0.5, ResData: null }, durable: true },
    { state: 'completed', response: { ResCode: 2_147_483_648, ResData: null }, durable: true },
    { state: 'completed', response: { ResCode: 0, ResData: undefined }, durable: true },
    { state: 'completed', response: { ResCode: 0, ResData: cyclic }, durable: true },
    { state: 'completed', response: { ResCode: 0, ResData: null, detail: 'secret' }, durable: true },
  ]
  for (const status of invalid) {
    assert.equal(isTrackedInvocationStatus(status), false)
    assert.throws(
      () => parseTrackedInvocationStatus(status),
      (error) => error instanceof InvalidTrackedInvocationStatusError
        && error instanceof TypeError
        && error.message === 'SSDEV tracked invocation status is invalid',
    )
    assert.throws(
      () => classifyTrackedInvocationStatus(status),
      (error) => error instanceof InvalidTrackedInvocationStatusError
        && error.message === 'SSDEV tracked invocation status is invalid',
    )
  }
})

test('classifies only the versioned tracked command error without replaying failures', () => {
  for (const phase of TRACKED_INVOCATION_ERROR_PHASES) {
    const commandError = {
      schemaVersion: 1,
      kind: 'trackedInvocationError',
      phase,
      code: 'operation-ledger-io',
    }
    assert.equal(isTrackedInvocationCommandError(commandError), true)
    const disposition = classifyTrackedInvocationFailure(commandError)
    assert.deepEqual(disposition, {
      kind: 'desktop-rejection',
      phase,
      code: 'operation-ledger-io',
      execution: 'not-confirmed',
      next: 'query-same-operation-or-reconcile',
      automaticReplay: 'forbidden',
    })
    assert.equal(Object.isFrozen(disposition), true)
  }

  const malformed = [
    null,
    '持久调用协调失败 (operation-ledger-io)',
    new Error('operation-ledger-io'),
    {},
    { schemaVersion: 2, kind: 'trackedInvocationError', phase: 'invoke', code: 'operation-ledger-io' },
    { schemaVersion: 1, kind: 'trackedInvocationError', phase: 'unknown', code: 'operation-ledger-io' },
    { schemaVersion: 1, kind: 'trackedInvocationError', phase: 'invoke', code: 'INVALID secret' },
    {
      schemaVersion: 1,
      kind: 'trackedInvocationError',
      phase: 'invoke',
      code: 'operation-ledger-io',
      detail: 'secret-path',
    },
  ]
  for (const error of malformed) {
    assert.equal(isTrackedInvocationCommandError(error), false)
    assert.deepEqual(classifyTrackedInvocationFailure(error), {
      kind: 'unknown-error',
      phase: null,
      code: null,
      execution: 'unknown',
      next: 'treat-as-possibly-executed',
      automaticReplay: 'forbidden',
    })
  }
})

test('settles a direct tracked promise without exposing errors or replay authority', async () => {
  const nondurable = {
    state: 'completed',
    response: { ResCode: 0, ResData: { ReturnValue: 0 } },
    durable: false,
  }
  const completed = await settleTrackedInvocation(Promise.resolve(nondurable))
  assert.deepEqual(completed, {
    kind: 'status',
    status: nondurable,
    disposition: {
      kind: 'completed',
      execution: 'completed',
      durability: 'not-confirmed',
      next: 'handle-response-and-record-recovery-risk',
      automaticReplay: 'forbidden',
    },
  })
  assert.equal(Object.isFrozen(completed), true)
  assert.equal(Object.isFrozen(completed.disposition), true)

  const commandError = {
    schemaVersion: 1,
    kind: 'trackedInvocationError',
    phase: 'invoke',
    code: 'operation-ledger-io',
  }
  const rejected = await settleTrackedInvocation(Promise.reject(commandError))
  assert.deepEqual(rejected, {
    kind: 'failure',
    disposition: {
      kind: 'desktop-rejection',
      phase: 'invoke',
      code: 'operation-ledger-io',
      execution: 'not-confirmed',
      next: 'query-same-operation-or-reconcile',
      automaticReplay: 'forbidden',
    },
  })
  assert.equal(Object.isFrozen(rejected), true)

  const malformed = {
    state: 'completed',
    durable: true,
    detail: 'secret-path',
  }
  const unknownCases = [
    settleTrackedInvocation(Promise.resolve(malformed)),
    settleTrackedInvocation(Promise.reject(new Error('secret-error'))),
    settleTrackedInvocation(Promise.reject('legacy localized secret')),
  ]
  for (const settlement of await Promise.all(unknownCases)) {
    assert.deepEqual(settlement, {
      kind: 'failure',
      disposition: {
        kind: 'unknown-error',
        phase: null,
        code: null,
        execution: 'unknown',
        next: 'treat-as-possibly-executed',
        automaticReplay: 'forbidden',
      },
    })
    assert.equal(JSON.stringify(settlement).includes('secret'), false)
    assert.equal(Object.hasOwn(settlement, 'error'), false)
  }
})

test('fixture invoker matches exact routes and canonical JSON parameters', async () => {
  const invoker = createPluginFixtureInvoker([
    {
      serviceId: 'card.reader',
      method: 'readCard',
      parameters: { options: { retries: 1, audible: true }, timeout: 30 },
      response: {
        ResCode: 0,
        ResData: { ReturnValue: 0, cardNumber: 'TEST-001' },
      },
    },
    {
      serviceId: 'card.reader',
      method: 'status',
      response: { ResCode: 0, ResData: { ReturnValue: 1 } },
    },
  ])

  assert.equal(Object.isFrozen(invoker), true)
  assert.equal(globalThis.ssdevDesktop, undefined)
  const first = await invoker.invokePlugin('card.reader', 'readCard', {
    timeout: 30,
    options: { audible: true, retries: 1 },
  })
  assert.deepEqual(first, {
    ResCode: 0,
    ResData: { ReturnValue: 0, cardNumber: 'TEST-001' },
  })
  first.ResData.cardNumber = 'mutated-by-test'
  assert.deepEqual(
    await invoker.invokePlugin('card.reader', 'readCard', {
      options: { retries: 1, audible: true },
      timeout: 30,
    }),
    {
      ResCode: 0,
      ResData: { ReturnValue: 0, cardNumber: 'TEST-001' },
    },
  )
  assert.deepEqual(
    await invoker.invokePlugin('card.reader', 'status'),
    { ResCode: 0, ResData: { ReturnValue: 1 } },
  )
})

test('fixture invoker rejects ambiguous definitions and unexpected calls without logging parameters', async () => {
  const duplicate = {
    serviceId: 'card.reader',
    method: 'readCard',
    parameters: { token: 'fixture-secret' },
    response: { ResCode: 0, ResData: null },
  }
  assert.throws(
    () => createPluginFixtureInvoker([duplicate, structuredClone(duplicate)]),
    (error) => error instanceof InvalidPluginFixtureError
      && error.reason === 'duplicate-invocation'
      && error.fixtureIndex === 1,
  )
  assert.throws(
    () => createPluginFixtureInvoker([{
      serviceId: 'card.reader',
      method: 'readCard',
      response: { ResCode: 0, ResData: null, debug: true },
    }]),
    (error) => error instanceof InvalidPluginFixtureError
      && error.reason === 'invalid-response',
  )
  assert.throws(
    () => createPluginFixtureInvoker([{
      serviceId: 'card.reader',
      method: 'readCard',
      parameters: { sequence: 9_007_199_254_740_992 },
      response: { ResCode: 0, ResData: null },
    }]),
    (error) => error instanceof InvalidPluginFixtureError
      && error.reason === 'invalid-parameters',
  )

  const cyclicParameters = {}
  cyclicParameters.self = cyclicParameters
  assert.throws(
    () => createPluginFixtureInvoker([{
      serviceId: 'card.reader',
      method: 'readCard',
      parameters: cyclicParameters,
      response: { ResCode: 0, ResData: null },
    }]),
    (error) => error instanceof InvalidPluginFixtureError
      && error.reason === 'invalid-parameters',
  )

  const invoker = createPluginFixtureInvoker([duplicate])
  await assert.rejects(
    invoker.invokePlugin('card.reader', 'readCard', { token: 'different-secret' }),
    (error) => error instanceof UnexpectedPluginInvocationError
      && error.serviceId === 'card.reader'
      && error.method === 'readCard'
      && !error.message.includes('different-secret'),
  )
})

test('fails explicitly outside an authorized desktop window', () => {
  clearBridge()
  assert.equal(isDesktopBridgeAvailable(), false)
  assert.throws(() => requireDesktopBridge(), DesktopBridgeUnavailableError)
})

test('connects only to an explicitly supported protocol', async () => {
  globalThis.ssdevDesktopContext = { encounterId: '123' }
  globalThis.ssdevDesktop = {
    invokePlugin: async () => ({ ResCode: 0, ResData: null }),
    getSystemInfo: async () => ({
      os: 'windows',
      architecture: 'x86_64',
      appVersion: '1.2.3',
      protocolVersion: 1,
      capabilities: {
        schemaVersion: 1,
        trackedInvocations: {
          supported: true,
          available: true,
          accepting: true,
          errorCode: null,
          limits: {
            maxRuntimeOperations: 64,
            maxRetainedResponseBytes: 524288,
            runtimeResultRetentionSeconds: 600,
            maxDurableOperations: 65536,
            maxDurableOperationsPerScope: 16384,
            completedRetentionSeconds: 86400,
            indeterminateRetentionSeconds: 2592000,
          },
        },
      },
    }),
    captureWindow: async () => '',
    openExternal: async () => {},
    openWindow: async () => 'business-2',
    showFloating: async () => 'floating-3',
    closeFloating: async () => {},
  }

  const connection = await connectDesktop()
  assert.equal(connection.system.protocolVersion, 1)
  assert.equal(connection.context.encounterId, '123')
  assert.equal(Object.isFrozen(connection), true)
  assert.equal(Object.isFrozen(connection.system.capabilities), true)
  assert.equal(Object.isFrozen(connection.system.capabilities.trackedInvocations), true)
  assert.equal(Object.isFrozen(connection.system.capabilities.trackedInvocations.limits), true)
  await assert.rejects(
    connectDesktop({ supportedProtocolVersions: [2] }),
    UnsupportedDesktopProtocolError,
  )
})

test('rejects malformed desktop declarations with stable reasons', async () => {
  const bridge = {
    invokePlugin: async () => ({ ResCode: 0, ResData: null }),
    getSystemInfo: async () => null,
    captureWindow: async () => '',
    openExternal: async () => {},
    openWindow: async () => 'business-2',
    showFloating: async () => 'floating-3',
    closeFloating: async () => {},
  }
  globalThis.ssdevDesktop = bridge
  await assert.rejects(
    connectDesktop(),
    (error) => error instanceof InvalidDesktopDeclarationError
      && error.reason === 'declaration-not-object',
  )

  bridge.getSystemInfo = async () => ({
    os: 'windows',
    architecture: 'x86_64',
    appVersion: '1.2.3',
    protocolVersion: Number.NaN,
  })
  await assert.rejects(
    connectDesktop(),
    (error) => error instanceof InvalidDesktopDeclarationError
      && error.reason === 'invalid-protocol-version',
  )

  bridge.getSystemInfo = async () => ({
    os: 'windows',
    architecture: 'x86_64',
    appVersion: '1.2.3',
    protocolVersion: 1,
    capabilities: {
      schemaVersion: 1,
      trackedInvocations: {
        supported: true,
        available: true,
        accepting: true,
        errorCode: null,
      },
    },
  })
  await assert.rejects(
    connectDesktop(),
    (error) => error instanceof InvalidDesktopDeclarationError
      && error.reason === 'invalid-tracked-invocations',
  )
})

test('preserves unknown future capability schemas without claiming tracked support', async () => {
  globalThis.ssdevDesktop = {
    invokePlugin: async () => ({ ResCode: 0, ResData: null }),
    invokePluginTracked: async () => ({ state: 'unknown' }),
    getPluginInvocation: async () => ({ state: 'unknown' }),
    getSystemInfo: async () => ({
      os: 'windows',
      architecture: 'x86_64',
      appVersion: '2.0.0',
      protocolVersion: 1,
      capabilities: {
        schemaVersion: 2,
        futureCapability: { enabled: true },
      },
    }),
    captureWindow: async () => '',
    openExternal: async () => {},
    openWindow: async () => 'business-2',
    showFloating: async () => 'floating-3',
    closeFloating: async () => {},
  }

  const connection = await connectDesktop()
  assert.equal(connection.system.capabilities.schemaVersion, 2)
  assert.deepEqual(connection.system.capabilities.futureCapability, { enabled: true })
  assert.equal(getTrackedInvocationCapabilities(connection.system), null)
  assert.equal(supportsTrackedPluginInvocations(connection.bridge, connection.system), false)
  assert.equal(Object.isFrozen(connection.system.capabilities), true)
})

test('packs only the installable bridge contract and compiled SDK', async () => {
  const packageRoot = fileURLToPath(new URL('..', import.meta.url))
  const npmCli = process.env.npm_execpath
  assert.equal(typeof npmCli, 'string')
  const { stdout } = await execFileAsync(
    process.execPath,
    [npmCli, 'pack', '--dry-run', '--json'],
    { cwd: packageRoot, maxBuffer: 1024 * 1024 },
  )
  const [packed] = JSON.parse(stdout)
  assert.equal(packed.name, packageManifest.name)
  assert.equal(packed.version, packageManifest.version)
  assert.equal(packed.entryCount, 6)
  assert.equal(packed.unpackedSize < 128 * 1024, true)
  assert.deepEqual(
    packed.files.map((file) => file.path).sort(),
    [
      'README.md',
      'bridge-contract.json',
      'dist/index.d.ts',
      'dist/index.d.ts.map',
      'dist/index.js',
      'package.json',
    ],
  )
  assert.deepEqual(packed.bundled, [])
})
