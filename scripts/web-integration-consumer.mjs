import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  lstat,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { verifyArtifactDirectory } from './web-bridge-package.mjs'

const kitManifestName = 'ssdev-web-kit.json'
const kitClientName = 'client.ts'
const kitFixturesName = 'fixtures.ts'
const expectedSdkPackage = '@bsoft/ssdev-web-bridge'
const maxKitManifestBytes = 64 * 1024
const maxKitTypescriptBytes = 4 * 1024 * 1024
const maxCombinedTypescriptBytes = 32 * 1024 * 1024
const maxCoverageCount = 1024 * 1024
const maxCombinedFixtureCount = 1024
const maxKitCount = 64
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function usage() {
  return 'usage: node scripts/web-integration-consumer.mjs verify --kit DIR --sdk-directory DIR | verify-set --kit DIR --kit DIR... --sdk-directory DIR'
}

function parseArguments(argv) {
  const [command, ...arguments_] = argv
  if (command !== 'verify' && command !== 'verify-set') throw new Error(usage())
  const kits = []
  let sdkDirectory
  for (let index = 0; index < arguments_.length; index += 2) {
    const flag = arguments_[index]
    const value = arguments_[index + 1]
    if (!value) throw new Error(usage())
    if (flag === '--kit' && sdkDirectory === undefined) {
      kits.push(resolve(value))
    } else if (flag === '--sdk-directory' && sdkDirectory === undefined
        && index + 2 === arguments_.length) {
      sdkDirectory = resolve(value)
    } else {
      throw new Error(usage())
    }
  }
  const expectedKitMinimum = command === 'verify-set' ? 2 : 1
  const expectedKitMaximum = command === 'verify-set' ? maxKitCount : 1
  if (kits.length < expectedKitMinimum
      || kits.length > expectedKitMaximum
      || !sdkDirectory
      || new Set(kits).size !== kits.length) {
    throw new Error(usage())
  }
  return { command, kits, sdkDirectory }
}

function npmExecutable() {
  return process.platform === 'win32' ? 'npm.cmd' : 'npm'
}

function runProcess(executable, arguments_, options) {
  const { role, ...spawnOptions } = options
  const result = spawnSync(executable, arguments_, {
    encoding: 'utf8',
    ...spawnOptions,
  })
  if (result.error) throw result.error
  if (result.status !== 0) {
    const detail = `${result.stderr ?? ''}\n${result.stdout ?? ''}`.trim()
    throw new Error(`${role} failed with exit code ${result.status}: ${detail}`)
  }
  return result
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function asciiFold(value) {
  return value.replace(/[A-Z]/g, (character) => character.toLowerCase())
}

function isLowercaseSha256(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)
}

function isCanonicalSemver(value) {
  return typeof value === 'string'
    && /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.test(value)
}

function hasExactKeys(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const actual = Object.keys(value).sort()
  const expected = [...keys].sort()
  return actual.length === expected.length && actual.every((key, index) => key === expected[index])
}

async function realDirectory(path, role) {
  const metadata = await lstat(path)
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`${role} must be a real directory`)
  }
}

async function regularFile(path, limit, role) {
  const metadata = await lstat(path)
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size < 1 || metadata.size > limit) {
    throw new Error(`${role} must be a bounded regular file`)
  }
  return metadata
}

async function readWebKit(kit) {
  await realDirectory(kit, 'Web kit')
  const expectedFiles = [kitClientName, kitFixturesName, kitManifestName].sort()
  const actualFiles = (await readdir(kit)).sort()
  if (actualFiles.length !== expectedFiles.length
      || actualFiles.some((entry, index) => entry !== expectedFiles[index])) {
    throw new Error('Web kit must contain exactly client.ts, fixtures.ts, and ssdev-web-kit.json')
  }

  const manifestPath = join(kit, kitManifestName)
  await regularFile(manifestPath, maxKitManifestBytes, 'Web kit manifest')
  const manifestBytes = await readFile(manifestPath)
  const manifest = JSON.parse(manifestBytes.toString('utf8'))
  const manifestFields = [
    'schemaVersion',
    'pluginId',
    'pluginVersion',
    'displayName',
    'apiSha256',
    'pluginMetadataSha256',
    'matrixSha256',
    'serviceCount',
    'methodCount',
    'fixtureCount',
    'files',
  ]
  if (!hasExactKeys(manifest, manifestFields)
      || !hasExactKeys(manifest.files, ['client', 'fixtures'])
      || !hasExactKeys(manifest.files.client, ['path', 'sha256'])
      || !hasExactKeys(manifest.files.fixtures, ['path', 'sha256'])
      || manifest.schemaVersion !== 1) {
    throw new Error('Web kit manifest schema is invalid')
  }
  if (typeof manifest.pluginId !== 'string'
      || manifest.pluginId.length < 1
      || manifest.pluginId.length > 128
      || manifest.pluginId.trim() !== manifest.pluginId
      || /[\\/\u0000-\u001f\u007f]/.test(manifest.pluginId)
      || !isCanonicalSemver(manifest.pluginVersion)
      || typeof manifest.displayName !== 'string'
      || manifest.displayName.length < 1
      || [...manifest.displayName].length > 128
      || manifest.displayName.trim() !== manifest.displayName
      || /[\u0000-\u001f\u007f]/.test(manifest.displayName)) {
    throw new Error('Web kit identity is invalid')
  }
  if (!Number.isSafeInteger(manifest.serviceCount)
      || !Number.isSafeInteger(manifest.methodCount)
      || !Number.isSafeInteger(manifest.fixtureCount)
      || manifest.serviceCount < 1
      || manifest.serviceCount > manifest.methodCount
      || manifest.methodCount > manifest.fixtureCount
      || manifest.fixtureCount > maxCoverageCount) {
    throw new Error('Web kit coverage counts are invalid')
  }
  const digests = [
    manifest.apiSha256,
    manifest.pluginMetadataSha256,
    manifest.matrixSha256,
    manifest.files.client.sha256,
    manifest.files.fixtures.sha256,
  ]
  if (digests.some((digest) => !isLowercaseSha256(digest))
      || manifest.files.client.path !== kitClientName
      || manifest.files.fixtures.path !== kitFixturesName) {
    throw new Error('Web kit file declarations are invalid')
  }

  const clientPath = join(kit, kitClientName)
  const fixturesPath = join(kit, kitFixturesName)
  await regularFile(clientPath, maxKitTypescriptBytes, 'Web kit client')
  await regularFile(fixturesPath, maxKitTypescriptBytes, 'Web kit fixtures')
  const clientBytes = await readFile(clientPath)
  const fixturesBytes = await readFile(fixturesPath)
  if (sha256(clientBytes) !== manifest.files.client.sha256
      || sha256(fixturesBytes) !== manifest.files.fixtures.sha256) {
    throw new Error('Web kit TypeScript content does not match its manifest digests')
  }
  const expectedClientHeader = `// Web kit plugin: ${manifest.pluginId}@${manifest.pluginVersion}\n// API SHA-256: ${manifest.apiSha256}\n`
  const expectedFixturesHeader = `// Generated from a structurally valid SSDEV executable matrix.\n// Matrix SHA-256: ${manifest.matrixSha256}\n`
  if (!clientBytes.toString('utf8').startsWith(expectedClientHeader)
      || !fixturesBytes.toString('utf8').startsWith(expectedFixturesHeader)) {
    throw new Error('Web kit TypeScript headers do not match its manifest')
  }
  return Object.freeze({
    manifest,
    manifestSha256: sha256(manifestBytes),
    clientBytes,
    fixturesBytes,
  })
}

async function verifyConsumers(options) {
  const [sdk, ...kits] = await Promise.all([
    verifyArtifactDirectory(options.sdkDirectory),
    ...options.kits.map(readWebKit),
  ])
  if (sdk.packageName !== expectedSdkPackage || sdk.consumerSmokeVerified !== true) {
    throw new Error('Web Bridge SDK artifact is not an approved consumer-smoked package')
  }
  kits.sort((left, right) => {
    const leftIdentity = asciiFold(left.manifest.pluginId)
    const rightIdentity = asciiFold(right.manifest.pluginId)
    if (leftIdentity < rightIdentity) return -1
    if (leftIdentity > rightIdentity) return 1
    if (left.manifest.pluginVersion < right.manifest.pluginVersion) return -1
    if (left.manifest.pluginVersion > right.manifest.pluginVersion) return 1
    return 0
  })
  const pluginIdentities = new Set()
  let serviceCount = 0
  let methodCount = 0
  let fixtureCount = 0
  let typescriptBytes = 0
  for (const kit of kits) {
    const identity = asciiFold(kit.manifest.pluginId)
    if (pluginIdentities.has(identity)) {
      throw new Error(`Web kit set contains duplicate plugin identity [${kit.manifest.pluginId}]`)
    }
    pluginIdentities.add(identity)
    serviceCount += kit.manifest.serviceCount
    methodCount += kit.manifest.methodCount
    fixtureCount += kit.manifest.fixtureCount
    typescriptBytes += kit.clientBytes.length + kit.fixturesBytes.length
  }
  if (!Number.isSafeInteger(serviceCount)
      || !Number.isSafeInteger(methodCount)
      || !Number.isSafeInteger(fixtureCount)
      || serviceCount > maxCoverageCount
      || methodCount > maxCoverageCount
      || fixtureCount > maxCombinedFixtureCount
      || typescriptBytes > maxCombinedTypescriptBytes) {
    throw new Error('Web kit set exceeds the combined consumer bounds')
  }
  const kitSummaries = kits.map((kit) => Object.freeze({
    pluginId: kit.manifest.pluginId,
    pluginVersion: kit.manifest.pluginVersion,
    manifestSha256: kit.manifestSha256,
  }))
  const kitSetSha256 = sha256(Buffer.from(
    kitSummaries.map((kit) => JSON.stringify(kit)).join('\n'),
    'utf8',
  ))

  const typescriptCompiler = join(
    repositoryRoot,
    'packages',
    'web-bridge',
    'node_modules',
    'typescript',
    'bin',
    'tsc',
  )
  await regularFile(typescriptCompiler, maxKitTypescriptBytes, 'pinned TypeScript compiler')
  const consumer = await mkdtemp(join(tmpdir(), 'ssdev-web-integration-consumer-'))
  try {
    await writeFile(join(consumer, 'package.json'), `${JSON.stringify({
      private: true,
      type: 'module',
    }, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' })
    const sdkArchiveSource = join(options.sdkDirectory, sdk.archive)
    await regularFile(sdkArchiveSource, 32 * 1024 * 1024, 'verified Web Bridge SDK archive')
    const sdkArchiveBytes = await readFile(sdkArchiveSource)
    if (sha256(sdkArchiveBytes) !== sdk.sha256) {
      throw new Error('Web Bridge SDK archive changed after verification')
    }
    const sdkArchiveSnapshot = join(consumer, sdk.archive)
    await writeFile(sdkArchiveSnapshot, sdkArchiveBytes, { flag: 'wx' })
    runProcess(npmExecutable(), [
      'install',
      '--offline',
      '--ignore-scripts',
      '--no-audit',
      '--no-fund',
      '--package-lock=false',
      sdkArchiveSnapshot,
    ], { cwd: consumer, role: 'offline Web integration SDK install' })
    const kitFiles = kits.map((kit, index) => {
      const prefix = `kit-${String(index).padStart(2, '0')}`
      return Object.freeze({
        kit,
        clientName: `${prefix}-client.ts`,
        fixturesName: `${prefix}-fixtures.ts`,
      })
    })
    for (const entry of kitFiles) {
      await writeFile(join(consumer, entry.clientName), entry.kit.clientBytes, { flag: 'wx' })
      await writeFile(join(consumer, entry.fixturesName), entry.kit.fixturesBytes, { flag: 'wx' })
    }
    await writeFile(join(consumer, 'tsconfig.json'), `${JSON.stringify({
      compilerOptions: {
        target: 'ES2022',
        module: 'NodeNext',
        moduleResolution: 'NodeNext',
        lib: ['ES2022', 'DOM'],
        outDir: 'dist',
        rootDir: '.',
        strict: true,
        exactOptionalPropertyTypes: true,
        noUncheckedIndexedAccess: true,
        skipLibCheck: false,
      },
      files: kitFiles.flatMap((entry) => [entry.clientName, entry.fixturesName]),
    }, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' })
    runProcess(process.execPath, [typescriptCompiler, '--project', join(consumer, 'tsconfig.json')], {
      cwd: consumer,
      role: 'Web kit and SDK TypeScript consumer compile',
    })

    const runtimeImports = kitFiles.map((entry, index) => `import * as clientModule${index} from './dist/${entry.clientName.replace(/\.ts$/, '.js')}'\nimport { pluginFixtures as pluginFixtures${index} } from './dist/${entry.fixturesName.replace(/\.ts$/, '.js')}'`).join('\n')
    const runtimeIntegrations = kitFiles.map((entry, index) => `  {
    pluginId: ${JSON.stringify(entry.kit.manifest.pluginId)},
    methodCount: ${entry.kit.manifest.methodCount},
    fixtureCount: ${entry.kit.manifest.fixtureCount},
    clientModule: clientModule${index},
    fixtures: pluginFixtures${index},
  }`).join(',\n')
    const runtimePath = join(consumer, 'runtime-smoke.mjs')
    await writeFile(runtimePath, `import {
  UnexpectedPluginInvocationError,
  createPluginFixtureInvoker,
} from '@bsoft/ssdev-web-bridge'

${runtimeImports}

const integrations = [
${runtimeIntegrations}
]
const routeKey = (fixture) => JSON.stringify([fixture.serviceId, fixture.method])
const routeOwners = new Map()
const allFixtures = []
for (const integration of integrations) {
  if (!Array.isArray(integration.fixtures)
      || integration.fixtures.length !== integration.fixtureCount) {
    throw new Error(\`Web kit [\${integration.pluginId}] fixture count does not match its manifest\`)
  }
  const fixtureRoutes = new Set(integration.fixtures.map(routeKey))
  if (fixtureRoutes.size !== integration.methodCount) {
    throw new Error(\`Web kit [\${integration.pluginId}] routes do not match its manifest method coverage\`)
  }
  for (const route of fixtureRoutes) {
    const owner = routeOwners.get(route)
    if (owner !== undefined) {
      throw new Error(\`duplicate public route across Web kits [\${owner}] and [\${integration.pluginId}]\`)
    }
    routeOwners.set(route, integration.pluginId)
  }
  allFixtures.push(...integration.fixtures)
}
const invoker = createPluginFixtureInvoker(allFixtures)
for (const fixture of allFixtures) {
  const response = await invoker.invokePlugin(
    fixture.serviceId,
    fixture.method,
    fixture.parameters ?? {},
  )
  if (JSON.stringify(response) !== JSON.stringify(fixture.response)) {
    throw new Error('fixture invoker changed an expected response')
  }
}
for (const integration of integrations) {
  const clientExports = Object.entries(integration.clientModule)
    .filter(([name, value]) => name.endsWith('Client') && typeof value === 'function')
  if (clientExports.length !== 1) {
    throw new Error(\`Web kit [\${integration.pluginId}] must export exactly one generated client\`)
  }
  const Client = clientExports[0][1]
  const client = new Client(invoker)
  const methods = Object.getOwnPropertyNames(Client.prototype)
    .filter((name) => name !== 'constructor' && typeof client[name] === 'function')
  const fixtureRoutes = new Set(integration.fixtures.map(routeKey))
  if (methods.length !== integration.methodCount) {
    throw new Error(\`Web kit [\${integration.pluginId}] client method count does not match its manifest\`)
  }
  const matchedRoutes = new Set()
  for (const method of methods) {
    let matched = false
    for (const fixture of integration.fixtures) {
      try {
        const response = await client[method](fixture.parameters ?? {})
        if (JSON.stringify(response) !== JSON.stringify(fixture.response)) {
          throw new Error('generated client returned an unexpected fixture response')
        }
        matchedRoutes.add(routeKey(fixture))
        matched = true
        break
      } catch (error) {
        if (!(error instanceof UnexpectedPluginInvocationError)) throw error
      }
    }
    if (!matched) throw new Error(\`generated client method [\${method}] has no matching fixture\`)
  }
  if (matchedRoutes.size !== fixtureRoutes.size) {
    throw new Error(\`Web kit [\${integration.pluginId}] client does not cover every fixture route\`)
  }
}
`, { encoding: 'utf8', flag: 'wx' })
    runProcess(process.execPath, [runtimePath], {
      cwd: consumer,
      role: 'Web kit and SDK runtime consumer smoke',
    })
  } finally {
    await rm(consumer, { recursive: true, force: true })
  }

  const sharedReport = {
    schemaVersion: 1,
    kitCount: kits.length,
    serviceCount,
    methodCount,
    fixtureCount,
    kitSetSha256,
    sdkPackageName: sdk.packageName,
    sdkPackageVersion: sdk.packageVersion,
    sdkArchiveSha256: sdk.sha256,
    sdkSourceSha256: sdk.sourceSha256,
    offlineInstallVerified: true,
    typescriptCompileVerified: true,
    runtimeRoutesVerified: true,
    verified: true,
  }
  if (options.command === 'verify') {
    return Object.freeze({
      ...sharedReport,
      pluginId: kitSummaries[0].pluginId,
      pluginVersion: kitSummaries[0].pluginVersion,
      kitManifestSha256: kitSummaries[0].manifestSha256,
    })
  }
  return Object.freeze({
    ...sharedReport,
    pluginCount: kitSummaries.length,
    kits: kitSummaries,
  })
}

async function main() {
  const report = await verifyConsumers(parseArguments(process.argv.slice(2)))
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`)
  process.exitCode = 1
})
