export type MappingDraftIdentity = {
  dirty: boolean
  savedPluginId: string
  currentPluginId: string
}

export function mappingDraftTargetsPlugin(state: MappingDraftIdentity, targetPluginId: string): boolean
export function mappingDeletionDiscardsDraft(state: MappingDraftIdentity, targetPluginId: string): boolean
