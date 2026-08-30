export type MappingDraftIdentity = {
  dirty: boolean
  savedPluginId: string
  currentPluginId: string
}

export function isPortableMappingPluginId(value: string): boolean
export function sameMappingPluginId(left: string, right: string): boolean
export function mappingDraftTargetsPlugin(state: MappingDraftIdentity, targetPluginId: string): boolean
export function mappingDeletionDiscardsDraft(state: MappingDraftIdentity, targetPluginId: string): boolean
