param(
  [Parameter(Mandatory = $true)]
  [string]$OutputDirectory,
  [ValidateSet("x86_64-pc-windows-msvc")]
  [string]$Target = "x86_64-pc-windows-msvc",
  [string]$WindowsSignCommand = $env:SSDEV_WINDOWS_SIGN_COMMAND,
  [string]$ExpectedSignerSubject = $env:SSDEV_WINDOWS_SIGNER_SUBJECT,
  [switch]$AllowUnsignedTestBuild
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
$toolPackages = @(
  "ssdev-desktop-doctor",
  "ssdev-pilot-readiness",
  "ssdev-migration-audit",
  "ssdev-plugin-tool",
  "ssdev-release-signing",
  "ssdev-cutover-evidence",
  "ssdev-release-manifest"
)
$sbomRoots = @(
  (Join-Path $workspace "apps"),
  (Join-Path $workspace "crates")
)
$sbomPattern = "*_$Target.cdx.json"
$generatedSbomsOwned = $false
$outputPath = [System.IO.Path]::GetFullPath($OutputDirectory)
$outputParent = Split-Path -Parent $outputPath
if (-not $outputParent -or -not (Test-Path -LiteralPath $outputParent -PathType Container)) {
  throw "OutputDirectory parent must be an existing directory."
}
if (Test-Path -LiteralPath $outputPath) {
  throw "OutputDirectory already exists; delivery toolkits are never overwritten."
}
$workspacePath = (Resolve-Path -LiteralPath $workspace).Path.TrimEnd([char[]]@(
  [System.IO.Path]::DirectorySeparatorChar,
  [System.IO.Path]::AltDirectorySeparatorChar
))
$workspacePrefix = $workspacePath + [System.IO.Path]::DirectorySeparatorChar
if (
  [String]::Equals($outputPath, $workspacePath, [StringComparison]::OrdinalIgnoreCase) -or
  $outputPath.StartsWith($workspacePrefix, [StringComparison]::OrdinalIgnoreCase)
) {
  throw "OutputDirectory must stay outside the source workspace."
}

$hasSigning = [bool]$WindowsSignCommand
if (-not $hasSigning) {
  if (-not $AllowUnsignedTestBuild -or $env:CI -ne "true") {
    throw "Production delivery tools require -WindowsSignCommand. Unsigned output is restricted to explicit CI test builds."
  }
} else {
  if ($WindowsSignCommand.IndexOf("%1", [StringComparison]::Ordinal) -lt 0) {
    throw "Windows sign command must contain the %1 file placeholder."
  }
  if (-not $ExpectedSignerSubject) {
    throw "Signed delivery tools require -ExpectedSignerSubject."
  }
}

function Invoke-DeliveryToolSigning {
  param([Parameter(Mandatory = $true)][string]$Path)
  $quotedPath = '"' + $Path.Replace('"', '""') + '"'
  $command = $WindowsSignCommand.Replace("%1", $quotedPath)
  & $env:ComSpec /d /s /c $command
  if ($LASTEXITCODE -ne 0) {
    throw "Windows signing command failed for delivery tool [$Path] with exit code $LASTEXITCODE."
  }
  $signature = Get-AuthenticodeSignature -FilePath $Path
  if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw "Authenticode signature is not valid for delivery tool [$Path]."
  }
  if (-not [String]::Equals($signature.SignerCertificate.Subject, $ExpectedSignerSubject, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Authenticode signer for delivery tool [$Path] does not match the required subject."
  }
}

function Assert-CycloneDxTool {
  $version = (& cargo cyclonedx --version | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $version -notmatch " 0\.5\.9$") {
    throw "Windows delivery tools require cargo-cyclonedx 0.5.9."
  }
}

function Remove-GeneratedSboms {
  foreach ($generatedSbom in @(Get-ChildItem -Path $sbomRoots -Filter $sbomPattern -Recurse -File -ErrorAction SilentlyContinue)) {
    Remove-Item -LiteralPath $generatedSbom.FullName -Force
  }
}

Push-Location $workspace
try {
  $revision = (& git rev-parse HEAD | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $revision -notmatch '^[0-9a-f]{40}$') {
    throw "A full Git source revision is required for the delivery toolkit."
  }
  $sourceChanges = @(& git status --porcelain --untracked-files=normal)
  if ($LASTEXITCODE -ne 0) {
    throw "Unable to inspect the source workspace state."
  }
  if ($sourceChanges.Count -gt 0) {
    throw "Delivery tools require a clean source workspace."
  }
  if (@(Get-ChildItem -Path $sbomRoots -Filter $sbomPattern -Recurse -File -ErrorAction SilentlyContinue).Count -gt 0) {
    throw "Delivery tool SBOM source outputs must not exist before the build."
  }

  $cargoMetadataText = (& cargo metadata --locked --format-version 1 | Out-String)
  if ($LASTEXITCODE -ne 0) {
    throw "Unable to read locked Cargo workspace metadata."
  }
  $cargoMetadata = $cargoMetadataText | ConvertFrom-Json
  $versionEntry = @($cargoMetadata.packages | Where-Object { $_.name -eq "ssdev-pilot-readiness" })
  if ($versionEntry.Count -ne 1 -or [string]$versionEntry[0].version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
    throw "Unable to resolve the delivery toolkit semantic version."
  }
  $toolkitVersion = [string]$versionEntry[0].version
  $webView2LoaderPackage = @($cargoMetadata.packages | Where-Object { $_.name -eq "webview2-com-sys" })
  if ($webView2LoaderPackage.Count -ne 1 -or -not ([string]$webView2LoaderPackage[0].source)) {
    throw "Unable to resolve the locked WebView2 Loader package."
  }
  $webView2LoaderSource = Join-Path `
    (Split-Path -Parent ([string]$webView2LoaderPackage[0].manifest_path)) `
    "x64/WebView2Loader.dll"
  if (-not (Test-Path -LiteralPath $webView2LoaderSource -PathType Leaf)) {
    throw "The locked WebView2 Loader binary is missing."
  }
  $webView2LoaderSignature = Get-AuthenticodeSignature -FilePath $webView2LoaderSource
  if (
    $webView2LoaderSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
    $webView2LoaderSignature.SignerCertificate.Subject -notmatch "Microsoft Corporation"
  ) {
    throw "The locked WebView2 Loader does not have a valid Microsoft Authenticode signature."
  }
  $webView2LoaderSourceHash = (Get-FileHash -LiteralPath $webView2LoaderSource -Algorithm SHA256).Hash

  Assert-CycloneDxTool
  & rustup target add $Target
  if ($LASTEXITCODE -ne 0) {
    throw "Unable to install the pinned Windows x64 Rust target."
  }
  & cargo build --locked --release --target $Target `
    -p ssdev-desktop-doctor `
    -p ssdev-pilot-readiness `
    -p ssdev-migration-audit `
    -p ssdev-plugin-tool `
    -p ssdev-release-signing `
    -p ssdev-cutover-evidence `
    -p ssdev-release-manifest
  if ($LASTEXITCODE -ne 0) {
    throw "Unable to build the Windows delivery command-line tools."
  }
  & cargo build --locked --release --target $Target -p webplus-controller --example plugin_matrix
  if ($LASTEXITCODE -ne 0) {
    throw "Unable to build the formal Windows plugin matrix runner."
  }

  $staging = Join-Path $outputParent (".ssdev-windows-delivery-tools-" + [Guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Path $staging | Out-Null
  try {
    $executables = @()
    foreach ($package in $toolPackages) {
      $source = Join-Path $workspace "target/$Target/release/$package.exe"
      if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Expected delivery tool executable is missing for [$package]."
      }
      $destination = Join-Path $staging "$package.exe"
      Copy-Item -LiteralPath $source -Destination $destination
      $executables += $destination
    }
    $matrixRunnerSource = Join-Path $workspace "target/$Target/release/examples/plugin_matrix.exe"
    if (-not (Test-Path -LiteralPath $matrixRunnerSource -PathType Leaf)) {
      throw "Expected formal plugin matrix runner is missing."
    }
    $matrixRunnerDestination = Join-Path $staging "ssdev-plugin-matrix.exe"
    Copy-Item -LiteralPath $matrixRunnerSource -Destination $matrixRunnerDestination
    $executables += $matrixRunnerDestination

    $webView2LoaderDestination = Join-Path $staging "WebView2Loader.dll"
    Copy-Item -LiteralPath $webView2LoaderSource -Destination $webView2LoaderDestination
    $copiedLoaderSignature = Get-AuthenticodeSignature -FilePath $webView2LoaderDestination
    $copiedLoaderHash = (Get-FileHash -LiteralPath $webView2LoaderDestination -Algorithm SHA256).Hash
    if (
      $copiedLoaderHash -ne $webView2LoaderSourceHash -or
      $copiedLoaderSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
      $copiedLoaderSignature.SignerCertificate.Thumbprint -ne $webView2LoaderSignature.SignerCertificate.Thumbprint
    ) {
      throw "The staged WebView2 Loader signature does not match the locked Microsoft source."
    }

    $doctorProbePath = Join-Path $staging "ssdev-desktop-doctor.exe"
    $doctorProbeOutput = (& $doctorProbePath inspect --data-root $staging 2>&1 | Out-String)
    $doctorProbeExitCode = $LASTEXITCODE
    if ($doctorProbeExitCode -ne 3 -or $doctorProbeOutput -notmatch '(?m)^webView2Status: available\r?$') {
      throw "The delivery doctor could not discover the current-user WebView2 Runtime through the staged Loader."
    }

    Copy-Item -LiteralPath (Join-Path $workspace "scripts/test-plugin-matrix.ps1") -Destination (Join-Path $staging "run-plugin-matrix.ps1")
    Copy-Item -LiteralPath (Join-Path $workspace "scripts/test-windows-package.ps1") -Destination (Join-Path $staging "run-windows-package.ps1")
    Copy-Item -LiteralPath (Join-Path $workspace "scripts/business-page-probe-server.mjs") -Destination (Join-Path $staging "business-page-probe-server.mjs")
    Copy-Item -LiteralPath (Join-Path $workspace "docs/windows-delivery-tools.md") -Destination (Join-Path $staging "README.md")

    $generatedSbomsOwned = $true
    & cargo cyclonedx `
      --manifest-path (Join-Path $workspace "Cargo.toml") `
      --format json `
      --target $Target `
      --target-in-filename `
      --spec-version 1.5
    if ($LASTEXITCODE -ne 0) {
      throw "Unable to generate the Windows delivery toolkit CycloneDX inputs."
    }
    $sbomDirectory = Join-Path $staging "sbom"
    New-Item -ItemType Directory -Path $sbomDirectory | Out-Null
    $sboms = [ordered]@{
      "ssdev-desktop-doctor.cdx.json" = (Join-Path $workspace "crates/ssdev-desktop-doctor/ssdev-desktop-doctor_$Target.cdx.json")
      "ssdev-pilot-readiness.cdx.json" = (Join-Path $workspace "crates/ssdev-pilot-readiness/ssdev-pilot-readiness_$Target.cdx.json")
      "ssdev-migration-audit.cdx.json" = (Join-Path $workspace "crates/ssdev-migration-audit/ssdev-migration-audit_$Target.cdx.json")
      "ssdev-plugin-tool.cdx.json" = (Join-Path $workspace "crates/ssdev-plugin-tool/ssdev-plugin-tool_$Target.cdx.json")
      "ssdev-release-signing.cdx.json" = (Join-Path $workspace "crates/ssdev-release-signing/ssdev-release-signing_$Target.cdx.json")
      "ssdev-cutover-evidence.cdx.json" = (Join-Path $workspace "crates/ssdev-cutover-evidence/ssdev-cutover-evidence_$Target.cdx.json")
      "ssdev-release-manifest.cdx.json" = (Join-Path $workspace "crates/ssdev-release-manifest/ssdev-release-manifest_$Target.cdx.json")
      "ssdev-plugin-matrix.cdx.json" = (Join-Path $workspace "crates/webplus-controller/webplus-controller_$Target.cdx.json")
    }
    foreach ($sbomName in $sboms.Keys) {
      $rawSbom = $sboms[$sbomName]
      if (-not (Test-Path -LiteralPath $rawSbom -PathType Leaf)) {
        throw "Expected delivery toolkit SBOM input is missing for [$sbomName]."
      }
      $normalizedSbom = Join-Path $sbomDirectory $sbomName
      & node (Join-Path $workspace "scripts/normalize-cyclonedx.mjs") $rawSbom $normalizedSbom $workspace
      if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $normalizedSbom -PathType Leaf)) {
        throw "Unable to normalize delivery toolkit SBOM [$sbomName]."
      }
      $bom = Get-Content -Raw -LiteralPath $normalizedSbom | ConvertFrom-Json
      $targetProperty = @($bom.metadata.properties | Where-Object { $_.name -eq "cdx:rustc:sbom:target:triple" })
      if (
        $bom.bomFormat -ne "CycloneDX" -or
        $bom.specVersion -ne "1.5" -or
        [int]$bom.version -ne 1 -or
        $targetProperty.Count -ne 1 -or
        $targetProperty[0].value -ne $Target -or
        @($bom.components).Count -lt 1 -or
        @($bom.dependencies).Count -lt 1
      ) {
        throw "Delivery toolkit SBOM [$sbomName] is incomplete or targets the wrong platform."
      }
    }
    Remove-GeneratedSboms
    $generatedSbomsOwned = $false

    $currentRevision = (& git rev-parse HEAD | Out-String).Trim()
    $currentSourceChanges = @(& git status --porcelain --untracked-files=normal)
    if (
      $LASTEXITCODE -ne 0 -or
      -not [String]::Equals($currentRevision, $revision, [StringComparison]::Ordinal) -or
      $currentSourceChanges.Count -gt 0
    ) {
      throw "Delivery toolkit source changed while the build was running."
    }

    if ($hasSigning) {
      foreach ($executable in $executables) {
        Invoke-DeliveryToolSigning $executable
      }
    }

    $release = [ordered]@{
      schemaVersion = 1
      productName = "SSDEV Windows Delivery Tools"
      version = $toolkitVersion
      sourceRevision = $revision
      sourceDirty = $false
      target = $Target
      executableCount = $executables.Count
      runtimeLoaderCount = 1
      webView2LoaderPackageVersion = [string]($webView2LoaderPackage[0].version)
      sbomCount = $sboms.Count
      authenticodeVerified = $hasSigning
      webView2LoaderAuthenticodeVerified = $true
    }
    [System.IO.File]::WriteAllText(
      (Join-Path $staging "release.json"),
      ($release | ConvertTo-Json),
      [System.Text.UTF8Encoding]::new($false)
    )

    $manifestTool = Join-Path $staging "ssdev-release-manifest.exe"
    & $manifestTool create $staging "artifacts.json"
    if ($LASTEXITCODE -ne 0) {
      throw "Unable to create the delivery toolkit artifact manifest."
    }
    & $manifestTool verify $staging "artifacts.json"
    if ($LASTEXITCODE -ne 0) {
      throw "The completed delivery toolkit does not match its artifact manifest."
    }

    Move-Item -LiteralPath $staging -Destination $outputPath
    $staging = $null
  } finally {
    if ($staging -and (Test-Path -LiteralPath $staging)) {
      Remove-Item -LiteralPath $staging -Recurse -Force
    }
  }
} finally {
  if ($generatedSbomsOwned) {
    Remove-GeneratedSboms
  }
  Pop-Location
}

Write-Host "PASS Windows x64 delivery toolkit created at [$outputPath]"
