import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import {
  initialRuntimeStatusHealth,
  RUNTIME_STATUS_FAILURE_THRESHOLD,
  updateRuntimeStatusHealth,
  withRuntimeStatusTimeout,
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
    withRuntimeStatusTimeout(new Promise(() => {}), 5),
    (error) => error instanceof Error && error.message === 'runtime-status-timeout',
  )
  assert.equal(
    await withRuntimeStatusTimeout(Promise.resolve('healthy'), 50),
    'healthy',
  )
})

test('control console exposes stale status and blocks new business launches', async () => {
  const source = await readFile(appVue, 'utf8')
  assert.match(source, /recordRuntimeStatusEvent\('failure'\)/)
  assert.match(source, /runtimeStatusStale[^\n]+桌面通信中断/)
  assert.match(source, /runtimeStatusStale[^\n]+状态不可用/)
  assert.match(source, /runtimeStatusStale[^\n]+部署状态无法确认/)
  assert.match(source, /busy \|\| runtimeStatusStale \|\| !snapshot\?\.config\.website/)
  assert.match(source, /桌面核心状态连续刷新失败/)
  assert.match(source, /ready: deploymentCheck\.ready && !runtimeStatusStale/)
  assert.match(source, /runtimeStatusStale \? 'STATUS UNKNOWN'/)
  assert.match(source, /以下明细来自最后一次成功刷新，仅供定位/)
  assert.match(source, /withRuntimeStatusTimeout\(invoke<BridgeStatus>\('bridge_status'\)\)/)
  assert.match(source, /@click="retryRuntimeStatus"/)
})
