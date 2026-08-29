param(
  [Parameter(Mandatory = $true)]
  [string]$X86Host,
  [Parameter(Mandatory = $true)]
  [string]$X64Host
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
$trustStore = Join-Path $workspace "fixtures/ci/plugin-trust.json"
$ciSigner = Join-Path $PSScriptRoot "sign-ci-plugin-request.mjs"
$x86HostPath = (Resolve-Path -LiteralPath $X86Host).Path
$x64HostPath = (Resolve-Path -LiteralPath $X64Host).Path

function Assert-ExternalCommand([string]$Context) {
  if ($LASTEXITCODE -ne 0) {
    throw "$Context failed with exit code $LASTEXITCODE"
  }
}

function Write-NewJson([string]$Path, [object]$Value) {
  if (Test-Path -LiteralPath $Path) {
    throw "Refusing to overwrite CI fixture output [$Path]."
  }
  $json = $Value | ConvertTo-Json -Depth 32
  [System.IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
}

if (-not [Environment]::Is64BitOperatingSystem) {
  throw "The synthetic dual-architecture plugin matrix requires a 64-bit Windows runner."
}
foreach ($requiredFile in @($trustStore, $ciSigner, $x86HostPath, $x64HostPath)) {
  if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
    throw "Required CI matrix input is missing: [$requiredFile]"
  }
}

$root = Join-Path ([System.IO.Path]::GetTempPath()) ("ssdev-plugin-matrix-ci-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $root | Out-Null

Push-Location $workspace
try {
  $matrixTargets = @(
    [pscustomobject]@{
      Architecture = "x86"
      Target = "i686-pc-windows-msvc"
      PluginId = "ci.echo-x86"
      ServiceId = "ci.echo-x86"
    },
    [pscustomobject]@{
      Architecture = "x64"
      Target = "x86_64-pc-windows-msvc"
      PluginId = "ci.echo-x64"
      ServiceId = "ci.echo-x64"
    }
  )
  $matrixPlugins = @()
  $matrixCases = @()
  $packageNames = @()

  foreach ($entry in $matrixTargets) {
    $scaffold = Join-Path $root $entry.PluginId
    $staging = Join-Path $root ("staging-" + $entry.Architecture)
    $request = Join-Path $root ("request-" + $entry.Architecture + ".json")
    $matrixTemplate = Join-Path $root ("matrix-" + $entry.Architecture + ".json")
    $signature = Join-Path $root ("signature-" + $entry.Architecture + ".txt")
    $packageName = $entry.PluginId + "-0.0.1.ssdev-plugin"
    $package = Join-Path $root $packageName

    cargo run --locked -p ssdev-plugin-tool -- init `
      --destination $scaffold `
      --plugin-id $entry.PluginId `
      --service-id $entry.ServiceId `
      --display-name ("CI Echo " + $entry.Architecture) `
      --architecture $entry.Architecture
    Assert-ExternalCommand "plugin scaffold generation for $($entry.Architecture)"

    & (Join-Path $scaffold "build.ps1")
    Assert-ExternalCommand "plugin scaffold build for $($entry.Architecture)"

    cargo run --locked -p ssdev-plugin-tool -- source-check `
      --source (Join-Path $scaffold "release-source") `
      --plugin-id $entry.PluginId
    Assert-ExternalCommand "plugin source check for $($entry.Architecture)"

    cargo run --locked -p webplus-native --example scaffold_roundtrip --target $entry.Target -- `
      (Join-Path $scaffold "release-source") $entry.PluginId
    Assert-ExternalCommand "direct scaffold round-trip for $($entry.Architecture)"

    cargo run --locked -p ssdev-plugin-tool -- prepare `
      --source (Join-Path $scaffold "release-source") `
      --staging $staging `
      --request $request `
      --matrix-template $matrixTemplate `
      --plugin-id $entry.PluginId `
      --version "0.0.1" `
      --desktop-version-requirement ">=0.1.0, <0.2.0" `
      --display-name ("CI Echo " + $entry.Architecture) `
      --key-id "ci-rfc8032-test-only" `
      --trust-store $trustStore `
      --matrix-seed (Join-Path $scaffold "matrix-seed.json")
    Assert-ExternalCommand "plugin release preparation for $($entry.Architecture)"

    node $ciSigner $request $signature
    Assert-ExternalCommand "test-only plugin signing for $($entry.Architecture)"

    cargo run --locked -p ssdev-plugin-tool -- finalize `
      --staging $staging `
      --request $request `
      --signature $signature `
      --trust-store $trustStore `
      --package $package
    Assert-ExternalCommand "plugin finalization for $($entry.Architecture)"

    $preparedMatrix = Get-Content -LiteralPath $matrixTemplate -Raw | ConvertFrom-Json
    if ($preparedMatrix.schemaVersion -ne 1 -or -not $preparedMatrix.draft -or $preparedMatrix.plugins.Count -ne 1 -or $preparedMatrix.cases.Count -ne 1) {
      throw "Prepared $($entry.Architecture) matrix did not preserve the expected bounded scaffold shape."
    }
    $case = $preparedMatrix.cases[0]
    $case.reviewRequired = $false
    $matrixPlugins += $preparedMatrix.plugins[0]
    $matrixCases += $case
    $packageNames += $packageName
  }

  $matrix = Join-Path $root "golden-matrix.json"
  Write-NewJson $matrix ([ordered]@{
    schemaVersion = 1
    draft = $false
    plugins = @($matrixPlugins)
    cases = @($matrixCases)
  })

  $releaseSet = Join-Path $root "release-set.json"
  Write-NewJson $releaseSet ([ordered]@{
    schemaVersion = 1
    packages = @($packageNames)
  })

  cargo run --locked -p ssdev-plugin-tool -- release-set-check `
    --spec $releaseSet `
    --trust-store $trustStore `
    --matrix $matrix
  Assert-ExternalCommand "synthetic release set check"

  $pluginRoot = Join-Path $root "plugin-root"
  cargo run --locked -p ssdev-plugin-tool -- release-set-materialize `
    --spec $releaseSet `
    --trust-store $trustStore `
    --matrix $matrix `
    --plugin-root $pluginRoot
  Assert-ExternalCommand "synthetic release set materialization"

  $sourceStatus = @(git -C $workspace status --porcelain=v1 --untracked-files=normal -- .)
  Assert-ExternalCommand "source cleanliness check before plugin evidence"
  if ($sourceStatus.Count -ne 0) {
    throw "Synthetic plugin evidence requires a clean source workspace; changed paths: $($sourceStatus -join ', ')"
  }

  $evidence = Join-Path $root "plugin-matrix-evidence.json"
  & (Join-Path $PSScriptRoot "test-plugin-matrix.ps1") `
    -PluginRoot $pluginRoot `
    -ReleaseSetSpec $releaseSet `
    -TrustStore $trustStore `
    -Matrix $matrix `
    -X86Host $x86HostPath `
    -X64Host $x64HostPath `
    -EvidenceOutput $evidence `
    -EvidenceEnvironment "ci-windows-native"

  $report = Get-Content -LiteralPath $evidence -Raw | ConvertFrom-Json
  $expectedX86HostSha256 = (Get-FileHash -LiteralPath $x86HostPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $expectedX64HostSha256 = (Get-FileHash -LiteralPath $x64HostPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $mismatches = @()
  if ([int]$report.schemaVersion -ne 2) { $mismatches += "schemaVersion" }
  if (-not [String]::Equals([string]$report.evidenceType, "plugin-matrix", [StringComparison]::Ordinal)) { $mismatches += "evidenceType" }
  if (-not [String]::Equals([string]$report.environment, "ci-windows-native", [StringComparison]::Ordinal)) { $mismatches += "environment" }
  if (-not [String]::Equals([string]$report.runnerOs, "windows", [StringComparison]::Ordinal)) { $mismatches += "runnerOs" }
  if (-not [String]::Equals([string]$report.runnerArchitecture, "x86_64", [StringComparison]::Ordinal)) { $mismatches += "runnerArchitecture" }
  if ([bool]$report.sourceDirty) { $mismatches += "sourceDirty" }
  if ([int]$report.pluginCount -ne 2) { $mismatches += "pluginCount" }
  if ([int]$report.serviceCount -ne 2) { $mismatches += "serviceCount" }
  if ([int]$report.methodCount -ne 2) { $mismatches += "methodCount" }
  if ([int]$report.enabledCaseCount -ne 2) { $mismatches += "enabledCaseCount" }
  if (-not [bool]$report.passed) { $mismatches += "passed" }
  if (-not [String]::Equals([string]$report.x86HostSha256, $expectedX86HostSha256, [StringComparison]::Ordinal)) { $mismatches += "x86HostSha256" }
  if (-not [String]::Equals([string]$report.x64HostSha256, $expectedX64HostSha256, [StringComparison]::Ordinal)) { $mismatches += "x64HostSha256" }
  if ($mismatches.Count -ne 0) {
    throw "Synthetic dual-architecture plugin matrix evidence mismatch: $($mismatches -join ', ')."
  }

  Write-Host "Synthetic signed x86/x64 plugin release set passed through the production matrix wrapper."
} finally {
  Pop-Location
  if (Test-Path -LiteralPath $root -PathType Container) {
    Remove-Item -LiteralPath $root -Recurse -Force
  }
}
