param(
  [ValidateSet("x86", "x64")]
  [string]$Architecture = "x64",
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$DesktopVersionRequirement,
  [Parameter(Mandatory = $true)][string]$KeyId,
  [Parameter(Mandatory = $true)][string]$TrustStore,
  [Parameter(Mandatory = $true)][string]$OutputRoot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$output = [System.IO.Path]::GetFullPath($OutputRoot)
$trust = [System.IO.Path]::GetFullPath($TrustStore)
if (Test-Path -LiteralPath $output) {
  throw "OutputRoot must not already exist: $output"
}
if (-not (Test-Path -LiteralPath $trust -PathType Leaf)) {
  throw "TrustStore does not exist: $trust"
}

$target = if ($Architecture -eq "x86") { "i686-pc-windows-msvc" } else { "x86_64-pc-windows-msvc" }
$source = Join-Path $output "source"
$sourceBin = Join-Path $source "bin"
$staging = Join-Path $output "staging"
$request = Join-Path $output "plugin-signing-request.json"
$matrix = Join-Path $output "plugin-matrix.json"

New-Item -ItemType Directory -Path $sourceBin | Out-Null

Push-Location $workspace
try {
  rustup target add $target
  if ($LASTEXITCODE -ne 0) { throw "rustup failed with exit code $LASTEXITCODE" }
  cargo build --locked --release -p ssdev-windows-system-example --target $target
  if ($LASTEXITCODE -ne 0) { throw "example DLL build failed with exit code $LASTEXITCODE" }
  Copy-Item -LiteralPath (Join-Path $workspace "target/$target/release/ssdev_windows_system_example.dll") `
    -Destination (Join-Path $sourceBin "ssdev_windows_system_example.dll")
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot "api.$Architecture.json") `
    -Destination (Join-Path $source "api.json")

  cargo run --locked -p ssdev-plugin-tool -- source-check `
    --source $source `
    --plugin-id "windows-system-example-$Architecture"
  if ($LASTEXITCODE -ne 0) { throw "plugin source check failed with exit code $LASTEXITCODE" }

  cargo run --locked -p ssdev-plugin-tool -- prepare `
    --source $source `
    --staging $staging `
    --request $request `
    --matrix-template $matrix `
    --plugin-id "windows-system-example-$Architecture" `
    --version $Version `
    --desktop-version-requirement $DesktopVersionRequirement `
    --display-name "Windows System Capability Example ($Architecture)" `
    --key-id $KeyId `
    --trust-store $trust
  if ($LASTEXITCODE -ne 0) { throw "plugin prepare failed with exit code $LASTEXITCODE" }
} finally {
  Pop-Location
}

Write-Host "Prepared plugin staging: $staging"
Write-Host "Send payloadBase64 from $request to the approved Ed25519 signer."
