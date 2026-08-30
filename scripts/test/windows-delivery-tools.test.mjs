import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const buildScriptUrl = new URL('../build-windows-delivery-tools.ps1', import.meta.url)
const matrixWrapperUrl = new URL('../test-plugin-matrix.ps1', import.meta.url)
const workflowUrl = new URL('../../.github/workflows/ci.yml', import.meta.url)
const documentationUrl = new URL('../../docs/windows-delivery-tools.md', import.meta.url)
const desktopBuildUrl = new URL('../build-windows.ps1', import.meta.url)

test('Windows delivery tools stay separate from the ordinary desktop installer', async () => {
  const [buildScript, desktopBuild] = await Promise.all([
    readFile(buildScriptUrl, 'utf8'),
    readFile(desktopBuildUrl, 'utf8'),
  ])

  assert.match(buildScript, /\[ValidateSet\("x86_64-pc-windows-msvc"\)\]/)
  assert.doesNotMatch(buildScript, /i686-pc-windows-msvc/)
  for (const binary of [
    'ssdev-desktop-doctor',
    'ssdev-pilot-readiness',
    'ssdev-migration-audit',
    'ssdev-plugin-tool',
    'ssdev-release-signing',
    'ssdev-cutover-evidence',
    'ssdev-release-manifest',
  ]) {
    assert.match(buildScript, new RegExp(`"${binary}"`))
  }
  assert.match(buildScript, /--example plugin_matrix/)
  assert.match(buildScript, /"ssdev-plugin-matrix\.exe"/)
  assert.match(buildScript, /cargo-cyclonedx 0\.5\.9/)
  assert.match(buildScript, /"ssdev-plugin-matrix\.cdx\.json"/)
  assert.match(buildScript, /"ssdev-desktop-doctor\.cdx\.json"/)
  assert.match(buildScript, /scripts\/normalize-cyclonedx\.mjs/)
  assert.match(buildScript, /sbomCount = \$sboms\.Count/)
  assert.doesNotMatch(
    desktopBuild,
    /windows-delivery-tools|ssdev-plugin-matrix\.exe|ssdev-desktop-doctor/,
  )
})

test('Windows delivery toolkit is source-bound, signed in production, and fully inventoried', async () => {
  const buildScript = await readFile(buildScriptUrl, 'utf8')

  assert.match(buildScript, /OutputDirectory already exists; delivery toolkits are never overwritten/)
  assert.match(buildScript, /OutputDirectory must stay outside the source workspace/)
  assert.match(buildScript, /\$env:CI -ne "true"/)
  assert.match(buildScript, /Production delivery tools require -WindowsSignCommand/)
  assert.match(buildScript, /Windows sign command must contain the %1 file placeholder/)
  assert.match(buildScript, /Delivery tools require a clean source workspace/)
  assert.match(buildScript, /Delivery tool SBOM source outputs must not exist before the build/)
  assert.match(buildScript, /\$generatedSbomsOwned = \$true/)
  assert.match(buildScript, /if \(\$generatedSbomsOwned\)/)
  assert.match(buildScript, /Delivery toolkit source changed while the build was running/)
  assert.match(buildScript, /Get-AuthenticodeSignature/)
  assert.match(buildScript, /SignerCertificate\.Subject/)
  assert.match(buildScript, /sourceRevision = \$revision/)
  assert.match(buildScript, /sourceDirty = \$false/)
  assert.match(buildScript, /authenticodeVerified = \$hasSigning/)
  assert.match(buildScript, /& \$manifestTool create \$staging "artifacts\.json"/)
  assert.match(buildScript, /& \$manifestTool verify \$staging "artifacts\.json"/)
  assert.match(buildScript, /Move-Item -LiteralPath \$staging -Destination \$outputPath/)
})

test('packaged matrix wrapper uses the verified adjacent runner but still binds clean source', async () => {
  const wrapper = await readFile(matrixWrapperUrl, 'utf8')

  assert.match(wrapper, /\[string\]\$Workspace/)
  assert.match(wrapper, /\[string\]\$MatrixRunner/)
  assert.match(wrapper, /Join-Path \$PSScriptRoot "ssdev-plugin-matrix\.exe"/)
  assert.match(wrapper, /Join-Path \$PSScriptRoot "ssdev-release-manifest\.exe"/)
  assert.match(wrapper, /& \$manifestVerifier verify \$PSScriptRoot "artifacts\.json" \| Out-Null/)
  assert.match(wrapper, /Supply -Workspace with the clean source workspace/)
  assert.match(wrapper, /cargo build --locked --release -p webplus-controller --example plugin_matrix/)
  assert.match(wrapper, /\$matrixPath \$sourceWorkspace \$evidenceOutputPath \$EvidenceEnvironment/)
})

test('Windows CI publishes one x64 delivery toolkit without changing platform package defaults', async () => {
  const workflow = await readFile(workflowUrl, 'utf8')

  assert.equal((workflow.match(/Build unsigned Windows x64 delivery toolkit/g) ?? []).length, 1)
  assert.equal((workflow.match(/Upload unsigned Windows x64 delivery toolkit/g) ?? []).length, 1)
  assert.equal((workflow.match(/ssdev-windows-delivery-tools-x64-unsigned/g) ?? []).length, 1)
  assert.match(workflow, /build-windows-delivery-tools\.ps1[\s\S]*?-AllowUnsignedTestBuild/)
  assert.match(workflow, /cargo install cargo-cyclonedx --version 0\.5\.9 --locked/)
  assert.match(workflow, /workflow_dispatch:[\s\S]*?default: windows/)
})

test('delivery toolkit documentation keeps unsigned CI output out of production', async () => {
  const documentation = await readFile(documentationUrl, 'utf8')

  assert.match(documentation, /不会增加在线轻量版体积/)
  assert.match(documentation, /名称带 `unsigned` 的短期制品只用于验证构建链，不能进入生产交付/)
  assert.match(documentation, /验证机无需安装 Rust/)
  assert.match(documentation, /仍必须提供与候选版本完全一致的干净源码工作区/)
  assert.match(documentation, /工具包不含私钥、令牌、业务材料/)
  assert.match(documentation, /8 个可执行入口对应的.*Windows x64 CycloneDX 1\.5 JSON/)
  assert.match(documentation, /`artifacts\.json` 覆盖.*全部可执行文件和 SBOM/)
  assert.match(documentation, /预装精确版本 `cargo-cyclonedx 0\.5\.9`/)
  assert.match(documentation, /ssdev-desktop-doctor\.exe inspect/)
  assert.match(documentation, /只读取当前用户应用数据目录下固定的 `logs\/ssdev\.log\*`/)
  assert.match(documentation, /不读取配置、插件、账本或业务缓存/)
  assert.match(documentation, /最多 16 种最新 WARN\/ERROR/)
  assert.match(documentation, /日志 `message`、其他字段.*都不进入控制台摘要/)
  assert.match(documentation, /聚合结果和 ZIP 内日志来自同一次有界读取/)
})
