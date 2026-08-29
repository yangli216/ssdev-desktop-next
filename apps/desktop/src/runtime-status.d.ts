export const RUNTIME_STATUS_FAILURE_THRESHOLD: 3
export const RUNTIME_STATUS_REQUEST_TIMEOUT_MS: 4000

export type RuntimeStatusHealth = {
  consecutiveFailures: number
  stale: boolean
}

export type RuntimeStatusHealthEvent = 'success' | 'failure'

export type RuntimeStatusHealthTransition = {
  health: RuntimeStatusHealth
  recovered: boolean
}

export function initialRuntimeStatusHealth(): RuntimeStatusHealth

export function updateRuntimeStatusHealth(
  current: RuntimeStatusHealth,
  event: RuntimeStatusHealthEvent,
): RuntimeStatusHealthTransition

export function withBoundedTimeout<T>(
  request: Promise<T>,
  timeoutMs?: number,
): Promise<T>
