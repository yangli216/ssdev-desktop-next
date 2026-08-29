function canonicalizeJson(value) {
  if (Array.isArray(value)) return value.map(canonicalizeJson)
  if (value == null || typeof value !== 'object') return value

  const keys = Object.keys(value).sort((left, right) => (
    left < right ? -1 : left > right ? 1 : 0
  ))
  const result = {}
  for (const key of keys) {
    if (value[key] !== undefined) result[key] = canonicalizeJson(value[key])
  }
  return result
}

export function configFingerprint(config) {
  return JSON.stringify(canonicalizeJson(config)) ?? 'null'
}

export function cloneConfig(config) {
  return JSON.parse(JSON.stringify(config))
}
