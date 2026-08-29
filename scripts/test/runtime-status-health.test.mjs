import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import {
  initialRuntimeStatusHealth,
  RUNTIME_STATUS_FAILURE_THRESHOLD,
  updateRuntimeStatusHealth,
  withBoundedTimeout,
} from '../../apps/desktop/src/runtime-status.js'

const appVue = new URL('../../apps/desktop/src/App.vue', import.meta.url)

test('runtime status becomes stale only after bounded consecutive failures and recovers', () => {
  let health = initialRuntimeStatusHealth()
  for (let index = 1; index < RUNTIME_STATUS_FAILURE_THRESHOLD; index += 1) {
    const transition = updateRuntimeStatusHealth(health, 'failure')
    health = transition.health
    assert.equal(health.consecutiveFailures, index)
    assert.equal(health.stale, false)
    assert.equal(transition.recovered, false)
  }

  const stale = updateRuntimeStatusHealth(health, 'failure')
  assert.equal(stale.health.consecutiveFailures, RUNTIME_STATUS_FAILURE_THRESHOLD)
  assert.equal(stale.health.stale, true)

  const stillBounded = updateRuntimeStatusHealth(stale.health, 'failure')
  assert.equal(stillBounded.health.consecutiveFailures, RUNTIME_STATUS_FAILURE_THRESHOLD)
  assert.equal(stillBounded.health.stale, true)

  const recovered = updateRuntimeStatusHealth(stillBounded.health, 'success')
  assert.deepEqual(recovered.health, initialRuntimeStatusHealth())
  assert.equal(recovered.recovered, true)
})

test('runtime status request timeout is bounded and does not expose a lower-level error', async () => {
  await assert.rejects(
    withBoundedTimeout(new Promise(() => {}), 5),
    (error) => error instanceof Error && error.message === 'runtime-status-timeout',
  )
  assert.equal(
    await withBoundedTimeout(Promise.resolve('healthy'), 50),
    'healthy',
  )
})

test('control console exposes stale status and blocks new business launches', async () => {
  const source = await readFile(appVue, 'utf8')
  assert.match(source, /recordRuntimeStatusEvent\('failure'\)/)
  assert.match(source, /runtimeStatusStale[^\n]+桌面通信中断/)
  assert.match(source, /runtimeStatusStale[^\n]+状态不可用/)
  assert.match(source, /runtimeStatusStale[^\n]+部署状态无法确认/)
  assert.match(source, /busy \|\| controlLoadFailed \|\| runtimeStatusStale \|\| !snapshot\?\.config\.website/)
  assert.match(source, /桌面核心状态连续刷新失败/)
  assert.match(source, /ready: deploymentCheck\.ready && !controlLoadFailed && !runtimeStatusStale/)
  assert.match(source, /runtimeStatusStale \? 'STATUS UNKNOWN'/)
  assert.match(source, /以下明细来自最后一次成功刷新，仅供定位/)
  assert.match(source, /withBoundedTimeout\(invoke<BridgeStatus>\('bridge_status'\)\)/)
  assert.match(source, /@click="retryRuntimeStatus"/)
})

test('control console bootstrap is bounded, retryable, and degrades SSO events to polling', async () => {
  const source = await readFile(appVue, 'utf8')
  assert.match(source, /const CONTROL_BOOTSTRAP_TIMEOUT_MS = 15_000/)
  assert.match(source, /async function loadControlConsole\(\)/)
  assert.match(source, /withBoundedTimeout\(\s*bootstrap,\s*CONTROL_BOOTSTRAP_TIMEOUT_MS/)
  assert.match(source, /if \(controlLoadActive\.value\) return/)
  assert.match(source, /if \(statusRefreshTimer == null\)/)
  assert.match(source, /if \(!controlConsoleMounted\) return/)
  assert.match(source, /controlLoadFailed\.value = true/)
  assert.match(source, /@click="retryControlLoad"/)
  assert.match(source, /void ensureSsoStatusListener\(\)/)
  assert.match(source, /const deploymentPromise = withBoundedTimeout\(/)
  assert.match(source, /if \(!ssoStatusEventSeen\) applySsoStatus\(next\.ssoError, next\.ssoActive\)/)
  assert.doesNotMatch(source, /部署自检不可用：\$\{reason/)
})
