import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import {
  BRIDGE_METHODS,
  BRIDGE_EVENTS,
  CURRENT_DESKTOP_CAPABILITIES_SCHEMA_VERSION,
  CURRENT_BRIDGE_PROTOCOL_VERSION,
  CURRENT_PROTOCOL_VERSION,
  DesktopBridgeUnavailableError,
  UnsupportedDesktopProtocolError,
  TRACKED_INVOCATION_METHODS,
  TrackedInvocationsUnavailableError,
  connectDesktop,
  createPluginOperationId,
  getTrackedInvocationCapabilities,
  isDesktopBridgeAvailable,
  requireDesktopBridge,
  requireTrackedPluginInvocations,
  supportsTrackedPluginInvocations,
} from '../dist/index.js'

const contract = JSON.parse(
  await readFile(new URL('../bridge-contract.json', import.meta.url), 'utf8'),
)

function clearBridge() {
  delete globalThis.ssdevDesktop
  delete globalThis.webPlusInvoke
  delete globalThis.ssdevDesktopContext
}

test.afterEach(clearBridge)

test('matches the shared desktop bridge contract', () => {
  assert.equal(contract.schemaVersion, 3)
  assert.equal(CURRENT_BRIDGE_PROTOCOL_VERSION, contract.protocolVersion)
  assert.equal(CURRENT_PROTOCOL_VERSION, contract.protocolVersion)
  assert.equal(CURRENT_DESKTOP_CAPABILITIES_SCHEMA_VERSION, contract.capabilities.schemaVersion)
  assert.deepEqual(BRIDGE_METHODS, contract.methods)
  assert.deepEqual(TRACKED_INVOCATION_METHODS, contract.optionalMethods)
  assert.deepEqual(BRIDGE_EVENTS, contract.events)
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
