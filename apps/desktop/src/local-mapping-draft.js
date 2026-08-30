function normalizedPluginId(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : ''
}

export function isPortableMappingPluginId(value) {
  if (typeof value !== 'string'
    || value.length === 0
    || value.length > 128
    || value.startsWith('.')
    || value.endsWith('.')
    || !/^[A-Za-z0-9._-]+$/.test(value)) return false
  const stem = value.split('.', 1)[0].toUpperCase()
  return !['CON', 'PRN', 'AUX', 'NUL'].includes(stem)
    && !/^COM[1-9]$/.test(stem)
    && !/^LPT[1-9]$/.test(stem)
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
