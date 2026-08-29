export const RUNTIME_STATUS_FAILURE_THRESHOLD = 3
export const RUNTIME_STATUS_REQUEST_TIMEOUT_MS = 4_000

export function initialRuntimeStatusHealth() {
  return {
    consecutiveFailures: 0,
    stale: false,
  }
}

export function updateRuntimeStatusHealth(current, event) {
  if (event === 'success') {
    return {
      health: initialRuntimeStatusHealth(),
      recovered: current.stale,
    }
  }
  const consecutiveFailures = Math.min(
    current.consecutiveFailures + 1,
    RUNTIME_STATUS_FAILURE_THRESHOLD,
  )
  return {
    health: {
      consecutiveFailures,
      stale: consecutiveFailures >= RUNTIME_STATUS_FAILURE_THRESHOLD,
    },
    recovered: false,
  }
}

export async function withBoundedTimeout(
  request,
  timeoutMs = RUNTIME_STATUS_REQUEST_TIMEOUT_MS,
) {
  let timeout
  try {
    return await Promise.race([
      request,
      new Promise((_, reject) => {
        timeout = globalThis.setTimeout(
          () => reject(new Error('runtime-status-timeout')),
          timeoutMs,
        )
      }),
    ])
  } finally {
    if (timeout != null) globalThis.clearTimeout(timeout)
  }
}
