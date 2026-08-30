import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
const script = join(repositoryRoot, 'scripts', 'web-bridge-package.mjs')
const consumerScript = join(repositoryRoot, 'scripts', 'web-integration-consumer.mjs')
const artifactManifestName = 'ssdev-web-bridge-sdk.json'
const workflow = join(repositoryRoot, '.github', 'workflows', 'ci.yml')

function run(...arguments_) {
  return spawnSync(process.execPath, [script, ...arguments_], {
    cwd: repositoryRoot,
    encoding: 'utf8',
  })
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function x86PeWithExport(name) {
  const bytes = Buffer.alloc(1536)
  bytes.write('MZ', 0, 'ascii')
  const peOffset = 0x80
  bytes.writeUInt32LE(peOffset, 0x3c)
  bytes.write('PE\0\0', peOffset, 'binary')
  const coff = peOffset + 4
  bytes.writeUInt16LE(0x014c, coff)
  bytes.writeUInt16LE(1, coff + 2)
  const optionalSize = 224
  bytes.writeUInt16LE(optionalSize, coff + 16)
  const optional = coff + 20
  bytes.writeUInt16LE(0x10b, optional)
  bytes.writeUInt32LE(1, optional + 92)
  bytes.writeUInt32LE(0x1000, optional + 96)
  const section = optional + optionalSize
  bytes.writeUInt32LE(0x1000, section + 8)
  bytes.writeUInt32LE(0x1000, section + 12)
  bytes.writeUInt32LE(0x400, section + 16)
  bytes.writeUInt32LE(0x200, section + 20)
  const exportDirectory = 0x200
  bytes.writeUInt32LE(1, exportDirectory + 24)
  bytes.writeUInt32LE(0x1040, exportDirectory + 32)
  bytes.writeUInt32LE(0x1080, 0x240)
  bytes.write(name, 0x280, 'ascii')
  return bytes
}

async function createGeneratedWebKit(root, options = {}) {
  const {
    fixtureName = 'reader',
    pluginId = 'reader-plugin',
    pluginVersion = '2.3.1',
    displayName = 'Patient Reader',
    serviceId = 'reader',
    nativeMethod = 'read',
    publicMethod = 'readCard',
    trackedInvocationRequired = false,
  } = options
  const plugin = join(root, `${fixtureName}-plugin-source`)
  const kit = join(root, `${fixtureName}-web-kit`)
  const matrix = join(root, `${fixtureName}-matrix.json`)
  const nativeLibrary = `${fixtureName}.dll`
  await mkdir(plugin)
  await writeFile(
    join(plugin, 'api.json'),
    JSON.stringify({
      serviceId,
      mainClass: nativeLibrary,
      architecture: 'x86',
      methods: [{
        name: nativeMethod,
        alias: publicMethod,
        parameters: ['timeout'],
        trackedInvocationRequired,
      }],
    }),
  )
  await writeFile(join(plugin, nativeLibrary), x86PeWithExport(nativeMethod))
  await writeFile(join(plugin, 'plugin.json'), JSON.stringify({
    schemaVersion: 1,
    pluginId,
    version: pluginVersion,
    displayName,
  }))
  await writeFile(matrix, JSON.stringify({
    schemaVersion: 1,
    draft: false,
    plugins: [{ pluginId, version: pluginVersion }],
    cases: [{
      name: `reviewed-${nativeMethod}`,
      request: {
        serviceId,
        method: nativeMethod,
        parameters: { timeout: 5 },
      },
      expected: {
        ResCode: 0,
        ResData: { ReturnValue: 0, fixture: fixtureName },
      },
    }],
  }))
  const generated = spawnSync('cargo', [
    'run',
    '--quiet',
    '--locked',
    '-p',
    'ssdev-plugin-tool',
    '--',
    'web-kit',
    '--plugin-dir',
    plugin,
    '--matrix',
    matrix,
    '--destination',
    kit,
  ], { cwd: repositoryRoot, encoding: 'utf8' })
  assert.equal(generated.status, 0, generated.stderr)
  return kit
}

function runConsumer(kit, sdkDirectory) {
  return spawnSync(process.execPath, [
    consumerScript,
    'verify',
    '--kit',
    kit,
    '--sdk-directory',
    sdkDirectory,
  ], { cwd: repositoryRoot, encoding: 'utf8' })
}

function runConsumerSet(kits, sdkDirectory) {
  return spawnSync(process.execPath, [
    consumerScript,
    'verify-set',
    ...kits.flatMap((kit) => ['--kit', kit]),
    '--sdk-directory',
    sdkDirectory,
  ], { cwd: repositoryRoot, encoding: 'utf8' })
}

test('builds and verifies a reproducible bounded Web Bridge SDK artifact', async (context) => {
  const root = await mkdtemp(join(tmpdir(), 'ssdev-web-bridge-package-'))
  context.after(() => rm(root, { recursive: true, force: true }))
  const first = join(root, 'first')
  const second = join(root, 'second')

  const firstBuild = run('build', '--output', first)
  assert.equal(firstBuild.status, 0, firstBuild.stderr)
  const secondBuild = run('build', '--output', second)
  assert.equal(secondBuild.status, 0, secondBuild.stderr)

  const firstManifest = JSON.parse(await readFile(join(first, artifactManifestName), 'utf8'))
  const secondManifest = JSON.parse(await readFile(join(second, artifactManifestName), 'utf8'))
  assert.deepEqual(firstManifest, secondManifest)
  assert.equal(firstManifest.packageName, '@bsoft/ssdev-web-bridge')
  assert.equal(firstManifest.packageVersion, '0.1.0')
  assert.equal(firstManifest.sourceFileCount, 6)
  assert.equal(firstManifest.consumerSmokeVerified, true)
  assert.match(firstManifest.sha256, /^[0-9a-f]{64}$/)
  assert.match(firstManifest.sourceSha256, /^[0-9a-f]{64}$/)

  const verification = run('verify', '--directory', first)
  assert.equal(verification.status, 0, verification.stderr)
  const report = JSON.parse(verification.stdout)
  assert.equal(report.verified, true)
  assert.equal(report.consumerSmokeVerified, true)
  assert.equal(report.sha256, firstManifest.sha256)
  assert.equal(Object.hasOwn(report, 'directory'), false)
  assert.equal(Object.hasOwn(report, 'output'), false)

  const kit = await createGeneratedWebKit(root)
  const consumed = runConsumer(kit, first)
  assert.equal(consumed.status, 0, consumed.stderr)
  const consumerReport = JSON.parse(consumed.stdout)
  assert.equal(consumerReport.pluginId, 'reader-plugin')
  assert.equal(consumerReport.pluginVersion, '2.3.1')
  assert.equal(consumerReport.sdkPackageName, '@bsoft/ssdev-web-bridge')
  assert.equal(consumerReport.sdkPackageVersion, '0.1.0')
  assert.equal(consumerReport.ordinaryMethodCount, 1)
  assert.equal(consumerReport.sdkArchiveSha256, firstManifest.sha256)
  assert.equal(consumerReport.offlineInstallVerified, true)
  assert.equal(consumerReport.typescriptCompileVerified, true)
  assert.equal(consumerReport.runtimeRoutesVerified, true)
  assert.equal(consumerReport.verified, true)
  assert.equal(Object.hasOwn(consumerReport, 'kit'), false)
  assert.equal(Object.hasOwn(consumerReport, 'sdkDirectory'), false)

  const writerKit = await createGeneratedWebKit(root, {
    fixtureName: 'writer',
    pluginId: 'writer-plugin',
    pluginVersion: '1.4.0',
    displayName: 'Patient Writer',
    serviceId: 'writer',
    nativeMethod: 'write',
    publicMethod: 'writeCard',
    trackedInvocationRequired: true,
  })
  const consumedSet = runConsumerSet([writerKit, kit], first)
  assert.equal(consumedSet.status, 0, consumedSet.stderr)
  const setReport = JSON.parse(consumedSet.stdout)
  assert.equal(setReport.kitCount, 2)
  assert.equal(setReport.pluginCount, 2)
  assert.equal(setReport.serviceCount, 2)
  assert.equal(setReport.methodCount, 2)
  assert.equal(setReport.ordinaryMethodCount, 1)
  assert.equal(setReport.fixtureCount, 2)
  assert.deepEqual(setReport.kits.map((entry) => entry.pluginId), [
    'reader-plugin',
    'writer-plugin',
  ])
  assert.match(setReport.kitSetSha256, /^[0-9a-f]{64}$/)
  assert.equal(setReport.sdkArchiveSha256, firstManifest.sha256)
  assert.equal(setReport.runtimeRoutesVerified, true)
  assert.equal(setReport.verified, true)
  assert.equal(Object.hasOwn(setReport, 'sdkDirectory'), false)

  const duplicateIdentityKit = await createGeneratedWebKit(root, {
    fixtureName: 'reader-duplicate',
    pluginId: 'READER-PLUGIN',
    pluginVersion: '2.4.0',
    displayName: 'Duplicate Reader',
    serviceId: 'duplicate-reader',
    nativeMethod: 'readDuplicate',
    publicMethod: 'readDuplicateCard',
  })
  const duplicateIdentity = runConsumerSet([kit, duplicateIdentityKit], first)
  assert.notEqual(duplicateIdentity.status, 0)
  assert.match(duplicateIdentity.stderr, /duplicate plugin identity/)

  const conflictingRouteKit = await createGeneratedWebKit(root, {
    fixtureName: 'reader-route-conflict',
    pluginId: 'reader-route-conflict-plugin',
    pluginVersion: '1.0.0',
    displayName: 'Reader Route Conflict',
    serviceId: 'reader',
    nativeMethod: 'read',
    publicMethod: 'readCard',
  })
  const conflictingRoute = runConsumerSet([kit, conflictingRouteKit], first)
  assert.notEqual(conflictingRoute.status, 0)
  assert.match(conflictingRoute.stderr, /duplicate public route across Web kits/)

  const kitClientPath = join(kit, 'client.ts')
  const kitManifestPath = join(kit, 'ssdev-web-kit.json')
  const kitClient = await readFile(kitClientPath, 'utf8')
  const incompatibleClient = `${kitClient}\nexport type MissingSdkContract = import('@bsoft/ssdev-web-bridge').DefinitelyMissingSdkType\n`
  await writeFile(kitClientPath, incompatibleClient)
  const kitManifest = JSON.parse(await readFile(kitManifestPath, 'utf8'))
  kitManifest.files.client.sha256 = sha256(incompatibleClient)
  await writeFile(kitManifestPath, `${JSON.stringify(kitManifest, null, 2)}\n`)
  const incompatible = runConsumer(kit, first)
  assert.notEqual(incompatible.status, 0)
  assert.match(incompatible.stderr, /TypeScript consumer compile failed/)

  const existingTarget = run('build', '--output', second)
  assert.notEqual(existingTarget.status, 0)
  assert.match(existingTarget.stderr, /already exists/)

  await appendFile(join(first, firstManifest.archive), 'tamper')
  const tampered = run('verify', '--directory', first)
  assert.notEqual(tampered.status, 0)
  assert.match(tampered.stderr, /does not match its manifest/)

  await writeFile(join(second, 'notes.txt'), 'unreviewed')
  const extraFile = run('verify', '--directory', second)
  assert.notEqual(extraFile.status, 0)
  assert.match(extraFile.stderr, /exactly one tgz/)

  await rm(join(second, 'notes.txt'))
  const manifestPath = join(second, artifactManifestName)
  const invalidManifest = { ...secondManifest, unexpected: true }
  await writeFile(manifestPath, `${JSON.stringify(invalidManifest, null, 2)}\n`)
  const unknownField = run('verify', '--directory', second)
  assert.notEqual(unknownField.status, 0)
  assert.match(unknownField.stderr, /schema is invalid/)

  await writeFile(manifestPath, `${JSON.stringify({
    ...secondManifest,
    consumerSmokeVerified: false,
  }, null, 2)}\n`)
  const missingConsumerSmoke = run('verify', '--directory', second)
  assert.notEqual(missingConsumerSmoke.status, 0)
  assert.match(missingConsumerSmoke.stderr, /identity or bounded metadata is invalid/)
})

test('default CI uploads only a successfully verified platform-neutral SDK handoff', async () => {
  const document = await readFile(workflow, 'utf8')
  const build = document.indexOf('node scripts/web-bridge-package.mjs build')
  const verify = document.indexOf('node scripts/web-bridge-package.mjs verify')
  const toolingTests = document.indexOf('run: node --test scripts/test/*.test.mjs')
  const upload = document.indexOf('name: ssdev-web-bridge-sdk')

  assert.ok(build >= 0)
  assert.ok(verify > build)
  assert.ok(toolingTests > verify)
  assert.ok(upload > toolingTests)
  assert.match(document.slice(verify, upload), /github\.event_name != 'pull_request'/)
  assert.match(document.slice(upload), /retention-days: 14/)
  assert.doesNotMatch(document.slice(build, upload), /npm publish/)
})
