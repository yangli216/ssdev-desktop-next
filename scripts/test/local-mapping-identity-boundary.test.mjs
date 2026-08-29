import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const studioVue = new URL('../../apps/desktop/src/LocalMappingStudio.vue', import.meta.url)
const desktopRust = new URL('../../apps/desktop/src-tauri/src/lib.rs', import.meta.url)

test('installed mapping identity is locked and replacement requires explicit confirmation', async () => {
  const source = await readFile(studioVue, 'utf8')

  assert.match(source, /const editingInstalledMapping = computed/)
  assert.match(source, /映射 ID<\/span><input[^>]+:disabled="editingInstalledMapping"/)
  assert.match(source, /已保存映射的 ID 是稳定路由身份，不能直接改名/)
  assert.match(source, /const existingTarget = inventory\.value\.mappings\.find\([^\n]+sameMappingPluginId/)
  assert.match(source, /existingTarget && !editingTarget && !window\.confirm\(`映射 ID/)
  assert.match(source, /if \(existingTarget\) definition\.pluginId = existingTarget\.pluginId/)
  assert.match(source, /expectedExisting: Boolean\(existingTarget\)/)
})

test('backend binds each save to the target state observed by the editor', async () => {
  const source = await readFile(desktopRust, 'utf8')

  assert.match(source, /async fn save_local_mapping\([\s\S]+expected_existing: bool/)
  assert.match(source, /let _install = state\.install_lock\.lock\(\)\.await;[\s\S]+mapping_target_exists/)
  assert.match(source, /if existing != expected_existing \{[\s\S]+映射目标状态已变化，请重新读取映射清单后再保存/)
})
