param(
  [Parameter(Mandatory = $true)]
  [string]$PluginRoot,
  [Parameter(Mandatory = $true)]
  [string]$TrustStore,
  [Parameter(Mandatory = $true)]
  [string]$Matrix,
  [Parameter(Mandatory = $true)]
  [string]$EvidenceOutput,
  [Parameter(Mandatory = $true)]
  [string]$EvidenceEnvironment
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
$pluginRootPath = (Resolve-Path $PluginRoot).Path
$trustStorePath = (Resolve-Path $TrustStore).Path
$matrixPath = (Resolve-Path $Matrix).Path
$evidenceOutputPath = [System.IO.Path]::GetFullPath($EvidenceOutput)
$evidenceParent = Split-Path -Parent $evidenceOutputPath
if (-not (Test-Path -LiteralPath $evidenceParent -PathType Container)) {
  throw "Evidence output parent must be an existing directory."
}
if (Test-Path -LiteralPath $evidenceOutputPath) {
  throw "Evidence output already exists; refusing to overwrite prior test evidence."
}
if ($EvidenceEnvironment -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
  throw "EvidenceEnvironment must be a portable identifier of 1 to 128 characters."
}

Push-Location $workspace
try {
  cargo build --locked -p webplus-plugin-host --target i686-pc-windows-msvc
  cargo build --locked -p webplus-plugin-host --target x86_64-pc-windows-msvc

  $x86Host = Join-Path $workspace "target/i686-pc-windows-msvc/debug/webplus-plugin-host.exe"
  $x64Host = Join-Path $workspace "target/x86_64-pc-windows-msvc/debug/webplus-plugin-host.exe"
  cargo run --locked -p webplus-controller --example plugin_matrix --target x86_64-pc-windows-msvc -- `
    $x86Host $x64Host $pluginRootPath $trustStorePath $matrixPath $workspace $evidenceOutputPath $EvidenceEnvironment
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $evidenceOutputPath -PathType Leaf)) {
    throw "Real plugin matrix failed or did not produce cutover evidence."
  }
} finally {
  Pop-Location
}
