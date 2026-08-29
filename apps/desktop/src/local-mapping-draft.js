function normalizedPluginId(value) {
  return typeof value === 'string' ? value.trim() : ''
}

export function mappingDraftTargetsPlugin(state, targetPluginId) {
  if (!state.dirty) return false
  const target = normalizedPluginId(targetPluginId)
  if (!target) return false
  return normalizedPluginId(state.savedPluginId) === target
    || normalizedPluginId(state.currentPluginId) === target
}

export function mappingDeletionDiscardsDraft(state, targetPluginId) {
  if (!state.dirty) return false
  const target = normalizedPluginId(targetPluginId)
  return target !== '' && normalizedPluginId(state.currentPluginId) === target
}
