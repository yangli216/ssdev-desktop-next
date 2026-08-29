function normalizedPluginId(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : ''
}

export function sameMappingPluginId(left, right) {
  const normalizedLeft = normalizedPluginId(left)
  return normalizedLeft !== '' && normalizedLeft === normalizedPluginId(right)
}

export function mappingDraftTargetsPlugin(state, targetPluginId) {
  if (!state.dirty) return false
  const target = normalizedPluginId(targetPluginId)
  if (!target) return false
  return sameMappingPluginId(state.savedPluginId, target)
    || sameMappingPluginId(state.currentPluginId, target)
}

export function mappingDeletionDiscardsDraft(state, targetPluginId) {
  if (!state.dirty) return false
  const target = normalizedPluginId(targetPluginId)
  return target !== '' && sameMappingPluginId(state.currentPluginId, target)
}
