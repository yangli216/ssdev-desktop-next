import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const appVue = new URL('../../apps/desktop/src/App.vue', import.meta.url)
const configRust = new URL('../../crates/ssdev-config/src/lib.rs', import.meta.url)
const shortcutsRust = new URL('../../apps/desktop/src-tauri/src/shortcuts.rs', import.meta.url)
const desktopRust = new URL('../../apps/desktop/src-tauri/src/desktop.rs', import.meta.url)

function sourceBetween(source, startText, endText) {
  const start = source.indexOf(startText)
  const end = source.indexOf(endText, start + 1)
  assert.notEqual(start, -1, `${startText} must exist`)
  assert.notEqual(end, -1, `${endText} must follow ${startText}`)
  return source.slice(start, end)
}

test('shortcut editor exposes only fixed actions and preserves atomic registration rollback', async () => {
  const [app, config, shortcuts, desktop] = await Promise.all([
    readFile(appVue, 'utf8'),
    readFile(configRust, 'utf8'),
    readFile(shortcutsRust, 'utf8'),
    readFile(desktopRust, 'utf8'),
  ])
  const actionType = sourceBetween(app, 'type DesktopAction =', 'type KeyBindingConfig')
  const actionCatalog = sourceBetween(app, 'const shortcutActions:', 'const status = ref')
  const editor = sourceBetween(app, '<fieldset class="shortcut-editor">', '<details class="advanced-settings">')
  const validation = sourceBetween(config, 'if self.key_bindings.len() > 32', 'if self.managed_processes.len() > 64')
  const replacement = sourceBetween(shortcuts, 'pub(crate) fn replace(', 'fn register_set')
  const configCommit = sourceBetween(desktop, 'pub(crate) fn replace_desktop_config', '#[tauri::command]\npub(crate) async fn import_desktop_config')

  for (const action of [
    'open-business-window',
    'capture-business-window',
    'capture-region',
    'reset-business-zoom',
    'find-in-business-window',
  ]) {
    assert.match(actionType, new RegExp(`'${action}'`))
    assert.match(actionCatalog, new RegExp(`id: '${action}'`))
  }
  assert.doesNotMatch(actionType, /script|command|snippet|eval/)
  assert.match(app, /keyBindings: KeyBindingConfig\[\]/)
  assert.match(app, /const shortcutConfigError = computed/)
  assert.match(app, /enabled\.has\(normalized\)/)
  assert.match(app, /function addKeyBinding/)
  assert.match(app, /function removeKeyBinding/)
  assert.match(editor, /v-model\.trim="binding\.shortcut"/)
  assert.match(editor, /v-model="binding\.action"/)
  assert.match(editor, /v-model="binding\.enabled"/)
  assert.match(editor, /不接受脚本、命令行或自定义代码/)
  assert.match(app, /Boolean\(shortcutConfigError\) \|\| !configDraftDirty/)

  assert.match(validation, /for binding in &self\.key_bindings/)
  assert.match(validation, /byte\.is_ascii_graphic\(\)/)
  assert.match(validation, /binding\.enabled && !shortcuts\.insert/)
  assert.match(config, /deny_unknown_fields[\s\S]+pub struct KeyBindingConfig/)
  assert.match(replacement, /register_set\(app, bindings\)/)
  assert.match(replacement, /register_set\(app, fallback\)/)
  assert.match(configCommit, /shortcuts::replace\(app, &config\.key_bindings, &previous\.key_bindings\)/)
  assert.match(configCommit, /state\.config\.replace\(config\)/)
})
