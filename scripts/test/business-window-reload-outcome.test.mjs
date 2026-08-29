import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const appVue = new URL('../../apps/desktop/src/App.vue', import.meta.url)
const desktopRust = new URL('../../apps/desktop/src-tauri/src/desktop.rs', import.meta.url)

function functionSource(source, signature, nextSignature) {
  const start = source.indexOf(signature)
  const end = source.indexOf(nextSignature, start + 1)
  assert.notEqual(start, -1, `${signature} must exist`)
  assert.notEqual(end, -1, `${nextSignature} must follow ${signature}`)
  return source.slice(start, end)
}

test('business window reload reports no-op, full, and partial outcomes without early exit', async () => {
  const [app, desktop] = await Promise.all([
    readFile(appVue, 'utf8'),
    readFile(desktopRust, 'utf8'),
  ])
  const frontend = functionSource(app, 'async function reloadBusiness()', 'async function retryTimedOutBusinessWindows()')
  const backend = functionSource(desktop, 'fn reload_business_windows_internal', 'fn retry_timed_out_business_windows_internal')

  assert.match(frontend, /invoke<BusinessWindowReloadResult>\('reload_business_windows'\)/)
  assert.match(frontend, /result\.requestedWindows === 0/)
  assert.match(frontend, /result\.failedWindows > 0/)
  assert.match(frontend, /result\.reloadedWindows/)
  assert.match(backend, /result\.requested_windows \+= 1/)
  assert.match(backend, /result\.reloaded_windows \+= 1/)
  assert.match(backend, /result\.failed_windows \+= 1/)
  assert.doesNotMatch(backend, /\?;/)
  assert.doesNotMatch(backend, /map_err/)
})

test('tray refresh logs only stable aggregate counts and returns the operator to control on failure', async () => {
  const desktop = await readFile(desktopRust, 'utf8')
  const tray = functionSource(desktop, '"reload-business" =>', '"quit" =>')

  assert.match(tray, /result\.failed_windows > 0/)
  assert.match(tray, /requested_windows = result\.requested_windows/)
  assert.match(tray, /reloaded_windows = result\.reloaded_windows/)
  assert.match(tray, /failed_windows = result\.failed_windows/)
  assert.match(tray, /show_control\(app\)/)
  assert.doesNotMatch(tray, /error\s*=/)
})
