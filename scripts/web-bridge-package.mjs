import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const packageDirectory = join(repositoryRoot, 'packages', 'web-bridge')
const packageManifestPath = join(packageDirectory, 'package.json')
const artifactManifestName = 'ssdev-web-bridge-sdk.json'
const expectedPackageName = '@bsoft/ssdev-web-bridge'
const maxArchiveBytes = 32 * 1024 * 1024
const maxSourceInputBytes = 4 * 1024 * 1024
const sourceFiles = Object.freeze([
  'README.md',
  'bridge-contract.json',
  'package-lock.json',
  'package.json',
  'src/index.ts',
  'tsconfig.json',
])

function usage() {
  return 'usage: node scripts/web-bridge-package.mjs build --output NEW_DIR | verify --directory DIR'
}

function parseArguments(argv) {
  const [command, flag, value, ...extra] = argv
  if (extra.length !== 0 || !value) throw new Error(usage())
  if (command === 'build' && flag === '--output') {
    return { command, directory: resolve(value) }
  }
  if (command === 'verify' && flag === '--directory') {
    return { command, directory: resolve(value) }
  }
  throw new Error(usage())
}

function npmExecutable() {
  return process.platform === 'win32' ? 'npm.cmd' : 'npm'
}

function runNpm(arguments_, options = {}) {
  const result = spawnSync(npmExecutable(), arguments_, {
    cwd: packageDirectory,
    encoding: 'utf8',
    ...options,
  })
  if (result.error) throw result.error
  if (result.status !== 0) {
    throw new Error(`npm ${arguments_[0]} failed with exit code ${result.status}: ${(result.stderr ?? '').trim()}`)
  }
  return result
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function isLowercaseSha256(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)
}

function isCanonicalSemver(value) {
  return typeof value === 'string'
    && /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.test(value)
}

function archiveName(packageName, version) {
  return `${packageName.replace(/^@/, '').replaceAll('/', '-')}-${version}.tgz`
}

async function realDirectory(path, role) {
  const metadata = await lstat(path)
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`${role} must be a real directory`)
  }
}

async function ensureFreshDirectoryTarget(path) {
  await realDirectory(dirname(path), 'SDK output parent')
  try {
    await lstat(path)
  } catch (error) {
    if (error?.code === 'ENOENT') return
    throw error
  }
  throw new Error('SDK output directory already exists')
}

async function regularFile(path, limit, role) {
  const metadata = await lstat(path)
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size < 1 || metadata.size > limit) {
    throw new Error(`${role} must be a bounded regular file`)
  }
  return metadata
}

async function sourceDigest() {
  const hash = createHash('sha256')
  for (const relative of sourceFiles) {
    const path = join(packageDirectory, relative)
    await regularFile(path, maxSourceInputBytes, `SDK source input [${relative}]`)
    const bytes = await readFile(path)
    hash.update(relative)
    hash.update('\0')
    hash.update(bytes)
    hash.update('\0')
  }
  return hash.digest('hex')
}

function hasExactKeys(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const actual = Object.keys(value).sort()
  const expected = [...keys].sort()
  return actual.length === expected.length && actual.every((key, index) => key === expected[index])
}

async function readPackageIdentity() {
  await regularFile(packageManifestPath, maxSourceInputBytes, 'Web Bridge package manifest')
  const document = JSON.parse(await readFile(packageManifestPath, 'utf8'))
  if (document.name !== expectedPackageName || !isCanonicalSemver(document.version)) {
    throw new Error('Web Bridge package identity is invalid')
  }
  if (document.private !== true) {
    throw new Error('Web Bridge package must remain private until an approved registry release exists')
  }
  return { name: document.name, version: document.version }
}

async function verifyArtifactDirectory(directory) {
  await realDirectory(directory, 'SDK artifact directory')
  const entries = (await readdir(directory)).sort()
  if (entries.length !== 2 || !entries.includes(artifactManifestName)) {
    throw new Error('SDK artifact directory must contain exactly one tgz and its fixed manifest')
  }

  const manifestPath = join(directory, artifactManifestName)
  await regularFile(manifestPath, 64 * 1024, 'SDK artifact manifest')
  const manifestBytes = await readFile(manifestPath)
  const manifest = JSON.parse(manifestBytes.toString('utf8'))
  const fields = [
    'schemaVersion',
    'packageName',
    'packageVersion',
    'archive',
    'bytes',
    'sha256',
    'sourceFileCount',
    'sourceSha256',
  ]
  if (!hasExactKeys(manifest, fields) || manifest.schemaVersion !== 1) {
    throw new Error('SDK artifact manifest schema is invalid')
  }
  const identity = await readPackageIdentity()
  const expectedArchive = archiveName(identity.name, identity.version)
  if (manifest.packageName !== identity.name
      || manifest.packageVersion !== identity.version
      || manifest.archive !== expectedArchive
      || entries[0] !== expectedArchive
      || entries[1] !== artifactManifestName
      || !Number.isSafeInteger(manifest.bytes)
      || manifest.bytes < 1
      || manifest.bytes > maxArchiveBytes
      || manifest.sourceFileCount !== sourceFiles.length
      || !isLowercaseSha256(manifest.sha256)
      || !isLowercaseSha256(manifest.sourceSha256)) {
    throw new Error('SDK artifact identity or bounded metadata is invalid')
  }

  const archivePath = join(directory, expectedArchive)
  const archiveMetadata = await regularFile(archivePath, maxArchiveBytes, 'SDK archive')
  const archiveBytes = await readFile(archivePath)
  if (archiveMetadata.size !== manifest.bytes || sha256(archiveBytes) !== manifest.sha256) {
    throw new Error('SDK archive does not match its manifest')
  }
  if (await sourceDigest() !== manifest.sourceSha256) {
    throw new Error('SDK artifact does not match the current locked Web Bridge sources')
  }

  return Object.freeze({ ...manifest, manifestSha256: sha256(manifestBytes), verified: true })
}

async function buildArtifactDirectory(output) {
  await ensureFreshDirectoryTarget(output)
  const identity = await readPackageIdentity()
  runNpm(['run', 'build'], { stdio: 'inherit' })

  const temporary = await mkdtemp(join(dirname(output), '.ssdev-web-bridge-sdk-'))
  let completed = false
  try {
    const packed = runNpm(['pack', '--json', '--pack-destination', temporary])
    const results = JSON.parse(packed.stdout)
    if (!Array.isArray(results) || results.length !== 1 || typeof results[0]?.filename !== 'string') {
      throw new Error('npm pack did not report exactly one archive')
    }
    const expectedArchive = archiveName(identity.name, identity.version)
    if (results[0].filename !== expectedArchive) {
      throw new Error('npm pack archive name does not match the package identity')
    }
    const archivePath = join(temporary, expectedArchive)
    const metadata = await regularFile(archivePath, maxArchiveBytes, 'SDK archive')
    const archiveBytes = await readFile(archivePath)
    const manifest = {
      schemaVersion: 1,
      packageName: identity.name,
      packageVersion: identity.version,
      archive: expectedArchive,
      bytes: metadata.size,
      sha256: sha256(archiveBytes),
      sourceFileCount: sourceFiles.length,
      sourceSha256: await sourceDigest(),
    }
    await writeFile(
      join(temporary, artifactManifestName),
      `${JSON.stringify(manifest, null, 2)}\n`,
      { encoding: 'utf8', flag: 'wx' },
    )
    const verified = await verifyArtifactDirectory(temporary)
    await rename(temporary, output)
    completed = true
    return Object.freeze({ ...verified, output })
  } finally {
    if (!completed) await rm(temporary, { recursive: true, force: true })
  }
}

async function main() {
  const options = parseArguments(process.argv.slice(2))
  const report = options.command === 'build'
    ? await buildArtifactDirectory(options.directory)
    : await verifyArtifactDirectory(options.directory)
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`)
  process.exitCode = 1
})
