import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { appendFile, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
const script = join(repositoryRoot, 'scripts', 'web-bridge-package.mjs')
const artifactManifestName = 'ssdev-web-bridge-sdk.json'
const workflow = join(repositoryRoot, '.github', 'workflows', 'ci.yml')

function run(...arguments_) {
  return spawnSync(process.execPath, [script, ...arguments_], {
    cwd: repositoryRoot,
    encoding: 'utf8',
  })
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
