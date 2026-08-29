#!/usr/bin/env node

import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'
import { constants, lstat, open, readFile } from 'node:fs/promises'
import { pathToFileURL } from 'node:url'

const MAX_REQUEST_BYTES = 4 * 1024 * 1024
const TEST_KEY_ID = 'ci-rfc8032-test-only'
const TEST_PLUGIN_PREFIX = 'ci.'

// RFC 8032 test vector 1. This is public test material, not an organization key.
const TEST_SEED = Buffer.from(
  '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
  'hex',
)
const TEST_PUBLIC_KEY = Buffer.from(
  'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
  'hex',
)
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

function requireExactKeys(value, expected, role) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${role} must be a JSON object`)
  }
  const actual = Object.keys(value).sort()
  const required = [...expected].sort()
  if (actual.length !== required.length || actual.some((key, index) => key !== required[index])) {
    throw new Error(`${role} contains an unexpected or missing field`)
  }
}

function decodeCanonicalBase64(value, role) {
  if (typeof value !== 'string' || value.length === 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error(`${role} must be canonical Base64`)
  }
  const decoded = Buffer.from(value, 'base64')
  if (decoded.toString('base64') !== value) {
    throw new Error(`${role} must be canonical Base64`)
  }
  return decoded
}

export function signCiPluginRequestDocument(document) {
  requireExactKeys(document, [
    'schemaVersion',
    'pluginId',
    'version',
    'desktopVersionRequirement',
    'keyId',
    'algorithm',
    'files',
    'payloadBase64',
    'payloadSha256',
  ], 'plugin signing request')
  if (document.schemaVersion !== 1 || document.algorithm !== 'ed25519') {
    throw new Error('CI signer accepts only schema 1 Ed25519 plugin requests')
  }
  if (document.keyId !== TEST_KEY_ID || typeof document.pluginId !== 'string' || !document.pluginId.startsWith(TEST_PLUGIN_PREFIX)) {
    throw new Error('CI signer is restricted to the test-only key and ci.* plugin IDs')
  }
  if (typeof document.version !== 'string' || typeof document.desktopVersionRequirement !== 'string') {
    throw new Error('CI plugin request identity is incomplete')
  }
  if (!document.files || typeof document.files !== 'object' || Array.isArray(document.files) || Object.keys(document.files).length === 0) {
    throw new Error('CI plugin request must bind at least one staged file')
  }
  const payload = decodeCanonicalBase64(document.payloadBase64, 'payloadBase64')
  const payloadSha256 = createHash('sha256').update(payload).digest('hex')
  if (document.payloadSha256 !== payloadSha256) {
    throw new Error('CI plugin request payload digest does not match payloadBase64')
  }

  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, TEST_SEED]),
    format: 'der',
    type: 'pkcs8',
  })
  const publicKey = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, TEST_PUBLIC_KEY]),
    format: 'der',
    type: 'spki',
  })
  const signature = sign(null, payload, privateKey)
  if (signature.length !== 64 || !verify(null, payload, publicKey, signature)) {
    throw new Error('CI test signature did not verify against the fixture public key')
  }
  return `${signature.toString('base64')}\n`
}

export async function signCiPluginRequestFile(requestPath, signaturePath) {
  const requestMetadata = await lstat(requestPath)
  if (!requestMetadata.isFile() || requestMetadata.isSymbolicLink() || requestMetadata.size > MAX_REQUEST_BYTES) {
    throw new Error('CI signing request must be a bounded regular file')
  }
  const raw = await readFile(requestPath)
  let document
  try {
    document = JSON.parse(raw.toString('utf8'))
  } catch {
    throw new Error('CI signing request must contain valid UTF-8 JSON')
  }
  const signature = signCiPluginRequestDocument(document)
  const handle = await open(signaturePath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600)
  try {
    await handle.writeFile(signature, 'utf8')
  } finally {
    await handle.close()
  }
}

async function main() {
  if (process.argv.length !== 4) {
    throw new Error('usage: sign-ci-plugin-request.mjs REQUEST.json NEW_SIGNATURE.txt')
  }
  await signCiPluginRequestFile(process.argv[2], process.argv[3])
  process.stdout.write('Created RFC 8032 test-only CI plugin signature. Never use it for production.\n')
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`)
    process.exitCode = 1
  })
}
