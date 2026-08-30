param(
  [Parameter(Mandatory = $true)]
  [string]$PluginRoot,
  [Parameter(Mandatory = $true)]
  [string]$ReleaseSetSpec,
  [Parameter(Mandatory = $true)]
  [string]$TrustStore,
  [Parameter(Mandatory = $true)]
  [string]$Matrix,
  [Parameter(Mandatory = $true)]
  [string]$X86Host,
  [Parameter(Mandatory = $true)]
  [string]$X64Host,
  [Parameter(Mandatory = $true)]
  [string]$EvidenceOutput,
  [Parameter(Mandatory = $true)]
  [string]$EvidenceEnvironment
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Stop-Matrix([string]$Code, [string]$Action) {
  [Console]::Error.WriteLine("plugin matrix: BLOCKED")
  [Console]::Error.WriteLine("blocker: $Code")
  [Console]::Error.WriteLine("action: $Action")
  [Console]::Error.WriteLine("evidence: not produced")
  exit 1
}

function Resolve-MatrixInput([string]$Value, [string]$Kind, [string]$Code, [string]$Action) {
  try {
    $resolved = (Resolve-Path -LiteralPath $Value -ErrorAction Stop).Path
  } catch {
    Stop-Matrix $Code $Action
  }
  if (-not (Test-Path -LiteralPath $resolved -PathType $Kind)) {
    Stop-Matrix $Code $Action
  }
  return $resolved
}

$workspace = Split-Path -Parent $PSScriptRoot
$pluginRootPath = Resolve-MatrixInput $PluginRoot Container "matrix-release-inputs-invalid" "Re-materialize the approved release set into a new plugin root."
$releaseSetSpecPath = Resolve-MatrixInput $ReleaseSetSpec Leaf "matrix-release-inputs-invalid" "Restore the approved release-set specification and repeat release-set-check."
$trustStorePath = Resolve-MatrixInput $TrustStore Leaf "matrix-trust-store-invalid" "Restore the approved active plugin trust store, then repeat release-set-check."
$matrixPath = Resolve-MatrixInput $Matrix Leaf "matrix-definition-invalid" "Run matrix-check and approve a fully covered non-draft matrix."
$x86HostPath = Resolve-MatrixInput $X86Host Leaf "matrix-host-preflight-failed" "Restore the exact signed x86 delivery host from the candidate bundle."
$x64HostPath = Resolve-MatrixInput $X64Host Leaf "matrix-host-preflight-failed" "Restore the exact signed x64 delivery host from the candidate bundle."
try {
  $evidenceOutputPath = [System.IO.Path]::GetFullPath($EvidenceOutput)
} catch {
  Stop-Matrix "matrix-evidence-output-invalid" "Choose a new evidence file under an existing controlled directory."
}
$evidenceParent = Split-Path -Parent $evidenceOutputPath
if (-not (Test-Path -LiteralPath $evidenceParent -PathType Container)) {
  Stop-Matrix "matrix-evidence-output-invalid" "Choose a new evidence file under an existing controlled directory."
}
if (Test-Path -LiteralPath $evidenceOutputPath) {
  Stop-Matrix "matrix-evidence-output-invalid" "Choose a new evidence file; prior evidence is never overwritten."
}
if ($EvidenceEnvironment -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
  Stop-Matrix "matrix-arguments-invalid" "Use a portable evidence environment identifier of 1 to 128 characters."
}

Push-Location $workspace
try {
  $matrixRunnerTargetRoot = Join-Path $workspace "target"
  cargo build --locked --release -p webplus-controller --example plugin_matrix --target x86_64-pc-windows-msvc --target-dir $matrixRunnerTargetRoot
  if ($LASTEXITCODE -ne 0) {
    Stop-Matrix "matrix-runner-build-failed" "Restore the locked Rust toolchain and source workspace, then rebuild the formal matrix runner."
  }
  $matrixRunner = Join-Path $matrixRunnerTargetRoot "x86_64-pc-windows-msvc\release\examples\plugin_matrix.exe"
  if (-not (Test-Path -LiteralPath $matrixRunner -PathType Leaf)) {
    Stop-Matrix "matrix-runner-build-failed" "Restore the locked Rust toolchain and source workspace, then rebuild the formal matrix runner."
  }
  & $matrixRunner `
    $x86HostPath $x64HostPath $pluginRootPath $releaseSetSpecPath $trustStorePath $matrixPath $workspace $evidenceOutputPath $EvidenceEnvironment
  if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
  }
  if (-not (Test-Path -LiteralPath $evidenceOutputPath -PathType Leaf)) {
    Stop-Matrix "matrix-evidence-write-failed" "Use a new writable evidence destination and rerun the complete matrix."
  }
} finally {
  Pop-Location
}
