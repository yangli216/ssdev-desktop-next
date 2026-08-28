param(
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$TrustStore,
  [Parameter(Mandatory = $true)][string]$Signature,
  [Parameter(Mandatory = $true)][string]$OutputRoot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$output = [System.IO.Path]::GetFullPath($OutputRoot)
$trust = [System.IO.Path]::GetFullPath($TrustStore)
$signatureInput = [System.IO.Path]::GetFullPath($Signature)
$staging = Join-Path $output "staging"
$request = Join-Path $output "plugin-signing-request.json"

foreach ($required in @($staging, $request, $trust, $signatureInput)) {
  if (-not (Test-Path -LiteralPath $required)) {
    throw "Required signing input does not exist: $required"
  }
}
$metadata = Get-Content -LiteralPath (Join-Path $staging "plugin.json") -Raw | ConvertFrom-Json
if (-not [String]::Equals([string]$metadata.version, $Version, [StringComparison]::Ordinal)) {
  throw "Requested version [$Version] does not match prepared plugin version [$($metadata.version)]"
}
$package = Join-Path $output "$($metadata.pluginId)-$Version.ssdev-plugin"
if (Test-Path -LiteralPath $package) {
  throw "Package output already exists: $package"
}

Push-Location $workspace
try {
  cargo run --locked -p ssdev-plugin-tool -- finalize `
    --staging $staging `
    --request $request `
    --signature $signatureInput `
    --trust-store $trust `
    --package $package
  if ($LASTEXITCODE -ne 0) { throw "plugin finalize failed with exit code $LASTEXITCODE" }
} finally {
  Pop-Location
}

Write-Host "Verified plugin package: $package"
