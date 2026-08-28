param(
  [string]$PluginTrustStore = $env:SSDEV_PLUGIN_TRUST_STORE_SOURCE,
  [string]$ProcessPolicy = $env:SSDEV_PROCESS_POLICY_SOURCE,
  [string]$ProcessPolicySignature = $env:SSDEV_PROCESS_POLICY_SIGNATURE_SOURCE,
  [string]$OriginPolicy = $env:SSDEV_ORIGIN_POLICY_SOURCE,
  [string]$OriginPolicySignature = $env:SSDEV_ORIGIN_POLICY_SIGNATURE_SOURCE,
  [string]$AppUpdatePublicKey = $env:SSDEV_APP_UPDATE_PUBLIC_KEY_SOURCE,
  [string]$AppUpdateEndpoint = $env:SSDEV_APP_UPDATE_ENDPOINT,
  [string]$Publisher = $env:SSDEV_WINDOWS_PUBLISHER,
  [string]$WindowsCertificateThumbprint = $env:SSDEV_WINDOWS_CERTIFICATE_THUMBPRINT,
  [string]$WindowsTimestampUrl = $env:SSDEV_WINDOWS_TIMESTAMP_URL,
  [string]$WindowsSignCommand = $env:SSDEV_WINDOWS_SIGN_COMMAND,
  [string]$ExpectedSignerSubject = $env:SSDEV_WINDOWS_SIGNER_SUBJECT,
  [ValidateSet("x86_64-pc-windows-msvc", "i686-pc-windows-msvc")]
  [string]$DesktopTarget = "x86_64-pc-windows-msvc",
  [ValidateSet("OfflineInstaller", "DownloadBootstrapper")]
  [string]$WebViewInstallMode = "OfflineInstaller",
  [string]$AppVersion,
  [switch]$AllowUnsignedTestBuild,
  [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
$resourceDir = Join-Path $workspace "apps/desktop/src-tauri/resources/windows"
$bundledTrustStore = Join-Path $workspace "apps/desktop/src-tauri/resources/plugin-trust.json"
$bundledProcessPolicy = Join-Path $workspace "apps/desktop/src-tauri/resources/process-policy.json"
$bundledProcessPolicySignature = Join-Path $workspace "apps/desktop/src-tauri/resources/process-policy.sig.json"
$bundledOriginPolicy = Join-Path $workspace "apps/desktop/src-tauri/resources/origin-policy.json"
$bundledOriginPolicySignature = Join-Path $workspace "apps/desktop/src-tauri/resources/origin-policy.sig.json"
$bundledAppUpdatePolicy = Join-Path $workspace "apps/desktop/src-tauri/resources/app-update.json"
$bundledX86Host = Join-Path $workspace "apps/desktop/src-tauri/resources/windows/webplus-plugin-host-x86.exe"
$bundledX64Host = Join-Path $workspace "apps/desktop/src-tauri/resources/windows/webplus-plugin-host-x64.exe"
$desktopDir = Join-Path $workspace "apps/desktop"
$updateBuildConfig = Join-Path ([System.IO.Path]::GetTempPath()) ("ssdev-update-build-" + [System.IO.Path]::GetRandomFileName() + ".json")
$rawNpmSbom = Join-Path ([System.IO.Path]::GetTempPath()) ("ssdev-npm-sbom-" + [System.IO.Path]::GetRandomFileName() + ".json")
$releaseMetadataTemp = Join-Path ([System.IO.Path]::GetTempPath()) ("ssdev-release-metadata-" + [System.IO.Path]::GetRandomFileName() + ".json")
$desktopArchitecture = if ($DesktopTarget -eq "i686-pc-windows-msvc") { "x86" } else { "x64" }
$bundleRoot = Join-Path $workspace "target/$DesktopTarget/release/bundle"
$script:SigningCertificateStore = $null

function Get-SignTool {
  $fromPath = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if ($fromPath) {
    return $fromPath.Source
  }
  $programFilesX86 = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
  if (-not $programFilesX86) {
    throw "ProgramFiles(x86) is not available on this Windows host."
  }
  $candidates = Get-ChildItem `
    -Path (Join-Path $programFilesX86 "Windows Kits/10/bin/*/x64/signtool.exe") `
    -ErrorAction SilentlyContinue | Sort-Object FullName -Descending
  if (@($candidates).Count -lt 1) {
    throw "signtool.exe was not found in PATH or the Windows 10 SDK."
  }
  return $candidates[0].FullName
}

function Assert-CodeSignature {
  param([Parameter(Mandatory = $true)][string]$Path)
  $signature = Get-AuthenticodeSignature -FilePath $Path
  if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw "Authenticode signature is not valid for [$Path]: $($signature.StatusMessage)"
  }
  if ($ExpectedSignerSubject -and -not [String]::Equals($signature.SignerCertificate.Subject, $ExpectedSignerSubject, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Authenticode signer for [$Path] does not exactly match the required subject [$ExpectedSignerSubject]."
  }
}

function Invoke-CodeSigning {
  param([Parameter(Mandatory = $true)][string]$Path)
  if ($WindowsSignCommand) {
    $quotedPath = '"' + $Path.Replace('"', '""') + '"'
    $command = $WindowsSignCommand.Replace("%1", $quotedPath)
    & $env:ComSpec /d /s /c $command
    if ($LASTEXITCODE -ne 0) {
      throw "Custom Windows signing command failed for [$Path] with exit code $LASTEXITCODE."
    }
  } else {
    $arguments = @("sign", "/fd", "SHA256", "/sha1", $WindowsCertificateThumbprint)
    if ($script:SigningCertificateStore -eq "LocalMachine") {
      $arguments += "/sm"
    }
    $arguments += @("/tr", $WindowsTimestampUrl, "/td", "SHA256", $Path)
    & (Get-SignTool) @arguments
    if ($LASTEXITCODE -ne 0) {
      throw "signtool failed for [$Path] with exit code $LASTEXITCODE."
    }
  }
  Assert-CodeSignature $Path
}

function Save-ResourceState {
  param([string]$Path)
  $exists = Test-Path $Path
  [pscustomobject]@{
    Path = $Path
    Exists = $exists
    Bytes = if ($exists) { [System.IO.File]::ReadAllBytes($Path) } else { $null }
  }
}

function Restore-ResourceState {
  param($State)
  if ($State.Exists) {
    [System.IO.File]::WriteAllBytes($State.Path, $State.Bytes)
  } elseif (Test-Path $State.Path) {
    Remove-Item -Force $State.Path
  }
}

function Assert-CycloneDxTool {
  $version = (& cargo cyclonedx --version | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $version -notmatch " 0\.5\.9$") {
    throw "Windows release builds require cargo-cyclonedx 0.5.9. Install it with cargo install cargo-cyclonedx --version 0.5.9 --locked."
  }
}

$resourceStates = @(
  (Save-ResourceState $bundledTrustStore),
  (Save-ResourceState $bundledProcessPolicy),
  (Save-ResourceState $bundledProcessPolicySignature),
  (Save-ResourceState $bundledOriginPolicy),
  (Save-ResourceState $bundledOriginPolicySignature),
  (Save-ResourceState $bundledAppUpdatePolicy),
  (Save-ResourceState $bundledX86Host),
  (Save-ResourceState $bundledX64Host)
)
$sbomSourceRoots = @(
  (Join-Path $workspace "apps"),
  (Join-Path $workspace "crates")
)
$sourceSbomStates = @(
  Get-ChildItem -Path $sbomSourceRoots -Filter "*.cdx.json" -Recurse -File -ErrorAction SilentlyContinue |
    ForEach-Object { Save-ResourceState $_.FullName }
)
$pushedWorkspace = $false

try {
  New-Item -ItemType Directory -Force -Path $resourceDir | Out-Null

  if ($AppVersion -and $AppVersion -notmatch "^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$") {
    throw "-AppVersion must be a three-part numeric semantic version such as 1.2.3."
  }

  $hasCertificateSigning = [bool]$WindowsCertificateThumbprint
  $hasCustomSigning = [bool]$WindowsSignCommand
  if ($hasCertificateSigning -and $hasCustomSigning) {
    throw "Choose either -WindowsCertificateThumbprint or -WindowsSignCommand, not both."
  }
  if (-not $hasCertificateSigning -and -not $hasCustomSigning) {
    if (-not $AllowUnsignedTestBuild -or $env:CI -ne "true") {
      throw "Production builds require Authenticode signing. Supply -WindowsCertificateThumbprint or -WindowsSignCommand. Unsigned builds are restricted to explicit CI smoke jobs."
    }
  } else {
    if (-not $Publisher) {
      throw "Signed production builds require -Publisher (or SSDEV_WINDOWS_PUBLISHER)."
    }
    if (-not $ExpectedSignerSubject) {
      throw "Signed production builds require -ExpectedSignerSubject (or SSDEV_WINDOWS_SIGNER_SUBJECT)."
    }
  }
  if ($hasCertificateSigning) {
    $normalizedThumbprint = ($WindowsCertificateThumbprint -replace "\s", "").ToUpperInvariant()
    if ($normalizedThumbprint -notmatch "^[0-9A-F]{40}$") {
      throw "Windows certificate thumbprint must contain exactly 40 hexadecimal characters."
    }
    $WindowsCertificateThumbprint = $normalizedThumbprint
    if (-not $WindowsTimestampUrl) {
      throw "Certificate signing requires -WindowsTimestampUrl."
    }
    try {
      $timestampUri = [System.Uri]$WindowsTimestampUrl
    } catch {
      throw "Windows timestamp URL is invalid."
    }
    if ($timestampUri.Scheme -notin @("http", "https") -or -not $timestampUri.Host -or $timestampUri.UserInfo -or $timestampUri.Fragment) {
      throw "Windows timestamp URL must be HTTP(S) without credentials or a fragment."
    }
    $certificates = @(
      @("Cert:\CurrentUser\My", "Cert:\LocalMachine\My") |
        ForEach-Object { Get-ChildItem $_ } |
        Where-Object { $_.Thumbprint -eq $WindowsCertificateThumbprint }
    )
    if ($certificates.Count -ne 1) {
      throw "Expected exactly one installed signing certificate with thumbprint [$WindowsCertificateThumbprint], found $($certificates.Count)."
    }
    $certificate = $certificates[0]
    if (-not $certificate.HasPrivateKey -or $certificate.NotAfter -le [DateTime]::UtcNow) {
      throw "Windows signing certificate must have an accessible private key and must not be expired."
    }
    if (-not [String]::Equals($certificate.Subject, $ExpectedSignerSubject, [StringComparison]::OrdinalIgnoreCase)) {
      throw "Installed signing certificate subject does not exactly match [$ExpectedSignerSubject]."
    }
    $enhancedKeyUsageOids = @($certificate.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId.Value })
    if ($enhancedKeyUsageOids -notcontains "1.3.6.1.5.5.7.3.3") {
      throw "Windows signing certificate is not valid for code signing."
    }
    $script:SigningCertificateStore = if ($certificate.PSPath.IndexOf("LocalMachine", [StringComparison]::OrdinalIgnoreCase) -ge 0) { "LocalMachine" } else { "CurrentUser" }
  }
  if ($hasCustomSigning -and $WindowsSignCommand.IndexOf("%1", [StringComparison]::Ordinal) -lt 0) {
    throw "Windows sign command must contain the %1 file placeholder required by Tauri."
  }

  Assert-CycloneDxTool
  $baseTauriConfig = Get-Content -Raw (Join-Path $workspace "apps/desktop/src-tauri/tauri.conf.json") | ConvertFrom-Json
  $bundleTargets = @("nsis")
  $webViewInstallModeType = switch ($WebViewInstallMode) {
    "OfflineInstaller" { "offlineInstaller" }
    "DownloadBootstrapper" { "downloadBootstrapper" }
  }
  $releaseAppVersion = if ($AppVersion) { $AppVersion } else { [string]$baseTauriConfig.version }
  $authenticodeRequiredText = if ($hasCertificateSigning -or $hasCustomSigning) { "true" } else { "false" }
  $syntheticVersionOverrideText = if ($AppVersion) { "true" } else { "false" }
  $allowDirtySourceText = if ($AllowUnsignedTestBuild) { "true" } else { "false" }
  & cargo run --quiet --locked --manifest-path (Join-Path $workspace "Cargo.toml") `
    -p ssdev-release-manifest -- metadata-create `
    $workspace `
    $releaseMetadataTemp `
    $releaseAppVersion `
    ([string]$baseTauriConfig.productName) `
    ([string]$baseTauriConfig.identifier) `
    $authenticodeRequiredText `
    $syntheticVersionOverrideText `
    $allowDirtySourceText
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $releaseMetadataTemp -PathType Leaf)) {
    throw "Failed to create source-bound release provenance before injecting build resources."
  }

  if ($PluginTrustStore) {
    Copy-Item -Force (Resolve-Path $PluginTrustStore).Path $bundledTrustStore
  }

  if ([bool]$ProcessPolicy -ne [bool]$ProcessPolicySignature) {
    throw "Process policy and its signature must be supplied together."
  }
  if ($ProcessPolicy) {
    Copy-Item -Force (Resolve-Path $ProcessPolicy).Path $bundledProcessPolicy
    Copy-Item -Force (Resolve-Path $ProcessPolicySignature).Path $bundledProcessPolicySignature
  }

  if (-not $OriginPolicy -or -not $OriginPolicySignature) {
    throw "Production builds require -OriginPolicy and -OriginPolicySignature (or their SSDEV_ORIGIN_POLICY_* environment variables)."
  }
  Copy-Item -Force (Resolve-Path $OriginPolicy).Path $bundledOriginPolicy
  Copy-Item -Force (Resolve-Path $OriginPolicySignature).Path $bundledOriginPolicySignature

  Push-Location $workspace
  try {
    cargo run --locked -p ssdev-release-signing -- verify-trust-store `
      --trust-store $bundledTrustStore `
      --required-purposes plugin,origin-policy,project-bundle
    if ($LASTEXITCODE -ne 0) {
      throw "Production trust store is not ready for plugin, origin-policy, and project-bundle issuance."
    }
  } finally {
    Pop-Location
  }

  $hasProcessPolicy = Test-Path $bundledProcessPolicy
  $hasProcessPolicySignature = Test-Path $bundledProcessPolicySignature
  if ($hasProcessPolicy -ne $hasProcessPolicySignature) {
    throw "Bundled process policy and signature must either both exist or both be absent."
  }
  if ($hasProcessPolicy) {
    Push-Location $workspace
    try {
      cargo run --locked -p ssdev-release-signing -- verify `
        --kind process-policy `
        --document $bundledProcessPolicy `
        --envelope $bundledProcessPolicySignature `
        --trust-store $bundledTrustStore
      if ($LASTEXITCODE -ne 0) {
        throw "Bundled process policy signature verification failed."
      }
    } finally {
      Pop-Location
    }
  }

  Push-Location $workspace
  try {
    cargo run --locked -p ssdev-release-signing -- verify `
      --kind origin-policy `
      --document $bundledOriginPolicy `
      --envelope $bundledOriginPolicySignature `
      --trust-store $bundledTrustStore
    if ($LASTEXITCODE -ne 0) {
      throw "Bundled origin policy signature verification failed."
    }
  } finally {
    Pop-Location
  }

  if (-not $AppUpdatePublicKey -or -not $AppUpdateEndpoint) {
    throw "Production builds require -AppUpdatePublicKey and -AppUpdateEndpoint (or their SSDEV_APP_UPDATE_* environment variables)."
  }
  if (-not $env:TAURI_SIGNING_PRIVATE_KEY -and -not $env:TAURI_SIGNING_PRIVATE_KEY_PATH) {
    throw "Production builds require TAURI_SIGNING_PRIVATE_KEY or TAURI_SIGNING_PRIVATE_KEY_PATH so updater artifacts are signed."
  }
  $resolvedUpdatePublicKey = (Resolve-Path $AppUpdatePublicKey).Path
  $updatePublicKeyText = (Get-Content -Raw $resolvedUpdatePublicKey).Trim()
  try {
    $decodedUpdatePublicKey = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($updatePublicKeyText))
  } catch {
    throw "App update public key must be the Base64 text generated by the Tauri signer."
  }
  if (-not $decodedUpdatePublicKey.StartsWith("untrusted comment:") -or $decodedUpdatePublicKey.Split("`n").Count -lt 2) {
    throw "App update public key does not contain a valid Minisign public key envelope."
  }
  try {
    $updateUri = [System.Uri]$AppUpdateEndpoint
  } catch {
    throw "App update endpoint is not a valid URL."
  }
  if ($updateUri.Scheme -ne "https" -or -not $updateUri.Host -or $updateUri.UserInfo -or $updateUri.Fragment) {
    throw "App update endpoint must be an HTTPS URL without credentials or a fragment."
  }
  if ($AllowUnsignedTestBuild -and -not $updateUri.Host.EndsWith(".invalid", [StringComparison]::OrdinalIgnoreCase)) {
    throw "Unsigned CI test builds must use a reserved .invalid update host."
  }

  $appUpdatePolicy = [ordered]@{
    schemaVersion = 1
    enabled = $true
    endpoints = @($AppUpdateEndpoint)
    pubkey = $updatePublicKeyText
    maxDownloadBytes = 268435456
  }
  $windowsBundleConfig = [ordered]@{}
  $windowsBundleConfig["webviewInstallMode"] = [ordered]@{
    type = $webViewInstallModeType
    silent = $true
  }
  if ($hasCertificateSigning) {
    $windowsBundleConfig["certificateThumbprint"] = $WindowsCertificateThumbprint
    $windowsBundleConfig["digestAlgorithm"] = "sha256"
    $windowsBundleConfig["timestampUrl"] = $WindowsTimestampUrl
  } elseif ($hasCustomSigning) {
    $windowsBundleConfig["signCommand"] = $WindowsSignCommand
  }
  $tauriUpdateConfig = [ordered]@{
    bundle = [ordered]@{
      createUpdaterArtifacts = $true
      publisher = if ($Publisher) { $Publisher } else { "BSOFT CI Test Build" }
      targets = @($bundleTargets)
      windows = $windowsBundleConfig
    }
    plugins = [ordered]@{
      updater = [ordered]@{
        pubkey = $updatePublicKeyText
        endpoints = @($AppUpdateEndpoint)
        windows = [ordered]@{ installMode = "passive" }
      }
    }
  }
  if ($AppVersion) {
    $tauriUpdateConfig["version"] = $AppVersion
  }
  [System.IO.File]::WriteAllText(
    $bundledAppUpdatePolicy,
    ($appUpdatePolicy | ConvertTo-Json -Depth 5),
    [System.Text.UTF8Encoding]::new($false)
  )
  [System.IO.File]::WriteAllText(
    $updateBuildConfig,
    ($tauriUpdateConfig | ConvertTo-Json -Depth 8),
    [System.Text.UTF8Encoding]::new($false)
  )

  if (-not $SkipTests) {
    & (Join-Path $PSScriptRoot "test-windows.ps1")
  }

  Push-Location $workspace
  $pushedWorkspace = $true
  cargo build --locked --release -p webplus-plugin-host --target i686-pc-windows-msvc
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to build the x86 native plugin host."
  }
  cargo build --locked --release -p webplus-plugin-host --target x86_64-pc-windows-msvc
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to build the x64 native plugin host."
  }

  $x86Host = Join-Path $workspace "target/i686-pc-windows-msvc/release/webplus-plugin-host.exe"
  $x64Host = Join-Path $workspace "target/x86_64-pc-windows-msvc/release/webplus-plugin-host.exe"
  if ($hasCertificateSigning -or $hasCustomSigning) {
    Invoke-CodeSigning $x86Host
    Invoke-CodeSigning $x64Host
  }
  Copy-Item -Force $x86Host $bundledX86Host
  Copy-Item -Force $x64Host $bundledX64Host

  $expectedReleaseRoot = [System.IO.Path]::GetFullPath((Join-Path $workspace "target/$DesktopTarget/release"))
  $resolvedBundleRoot = [System.IO.Path]::GetFullPath($bundleRoot)
  if (-not $resolvedBundleRoot.StartsWith($expectedReleaseRoot + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to clean an unexpected bundle output path [$resolvedBundleRoot]."
  }
  if (Test-Path -LiteralPath $resolvedBundleRoot) {
    Remove-Item -LiteralPath $resolvedBundleRoot -Recurse -Force
  }

  npm ci --prefix $desktopDir
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to install the desktop frontend dependencies."
  }
  npm run build --prefix $desktopDir
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to build the desktop frontend."
  }

  # Tauri's bundle updater reads private-key contents from TAURI_SIGNING_PRIVATE_KEY.
  # The signer subcommand also supports a file-backed key, so expand that path only
  # for the bundle command and restore the caller's environment immediately after it.
  $originalTauriSigningPrivateKey = $env:TAURI_SIGNING_PRIVATE_KEY
  try {
    if (-not $originalTauriSigningPrivateKey -and $env:TAURI_SIGNING_PRIVATE_KEY_PATH) {
      if (-not (Test-Path -LiteralPath $env:TAURI_SIGNING_PRIVATE_KEY_PATH -PathType Leaf)) {
        throw "TAURI_SIGNING_PRIVATE_KEY_PATH does not reference a regular file."
      }
      $env:TAURI_SIGNING_PRIVATE_KEY = [System.IO.File]::ReadAllText($env:TAURI_SIGNING_PRIVATE_KEY_PATH)
    }
    npm run tauri --prefix $desktopDir -- build --target $DesktopTarget --config $updateBuildConfig
    if ($LASTEXITCODE -ne 0) {
      throw "Failed to build the Tauri Windows bundles."
    }
  }
  finally {
    $env:TAURI_SIGNING_PRIVATE_KEY = $originalTauriSigningPrivateKey
  }

  $nsisBundles = @(Get-ChildItem -Path (Join-Path $bundleRoot "nsis") -Filter "*-setup.exe" -File -ErrorAction SilentlyContinue)
  if ($nsisBundles.Count -ne 1) {
    throw "Expected exactly one NSIS installer, found $($nsisBundles.Count)."
  }
  $expectedBundleArtifacts = @($nsisBundles[0])
  if ($WebViewInstallMode -eq "DownloadBootstrapper") {
    $onlineLightweightMaxInstallerBytes = 128MB
    foreach ($bundle in $expectedBundleArtifacts) {
      if ($bundle.Length -gt $onlineLightweightMaxInstallerBytes) {
        throw "Online-light installer [$($bundle.Name)] is larger than 128 MiB; the offline WebView2 payload may still be embedded."
      }
    }
  }

  $metadataDirectory = Join-Path $bundleRoot "metadata"
  New-Item -ItemType Directory -Force -Path $metadataDirectory | Out-Null
  $packageProfile = [ordered]@{
    schemaVersion = 1
    desktopTarget = $DesktopTarget
    installerKind = "Nsis"
    webviewInstallMode = $WebViewInstallMode
  }
  [System.IO.File]::WriteAllText(
    (Join-Path $metadataDirectory "package-profile.json"),
    ($packageProfile | ConvertTo-Json -Depth 3),
    [System.Text.UTF8Encoding]::new($false)
  )
  $publicReleaseInputs = @(
    $bundledTrustStore,
    $bundledOriginPolicy,
    $bundledOriginPolicySignature,
    $bundledAppUpdatePolicy,
    $bundledProcessPolicy,
    $bundledProcessPolicySignature
  )
  foreach ($releaseInput in $publicReleaseInputs) {
    $metadataTarget = Join-Path $metadataDirectory (Split-Path -Leaf $releaseInput)
    if (Test-Path $releaseInput) {
      Copy-Item -Force $releaseInput $metadataTarget
    } elseif (Test-Path $metadataTarget) {
      Remove-Item -LiteralPath $metadataTarget -Force
    }
  }

  foreach ($sbomTarget in @("x86_64-pc-windows-msvc", "i686-pc-windows-msvc")) {
    & cargo cyclonedx `
      --manifest-path (Join-Path $workspace "apps/desktop/src-tauri/Cargo.toml") `
      --format json `
      --describe binaries `
      --target $sbomTarget `
      --target-in-filename `
      --spec-version 1.5
    if ($LASTEXITCODE -ne 0) {
      throw "cargo-cyclonedx failed for target [$sbomTarget]."
    }
  }
  $rustSboms = [ordered]@{
    "desktop-rust-$desktopArchitecture.cdx.json" = (Join-Path $workspace "apps/desktop/src-tauri/ssdev-desktop-core_bin_$DesktopTarget.cdx.json")
    "plugin-host-rust-x64.cdx.json" = (Join-Path $workspace "crates/webplus-plugin-host/webplus-plugin-host_bin_x86_64-pc-windows-msvc.cdx.json")
    "plugin-host-rust-x86.cdx.json" = (Join-Path $workspace "crates/webplus-plugin-host/webplus-plugin-host_bin_i686-pc-windows-msvc.cdx.json")
  }
  foreach ($sbomName in $rustSboms.Keys) {
    $sourceSbom = $rustSboms[$sbomName]
    if (-not (Test-Path -LiteralPath $sourceSbom -PathType Leaf)) {
      throw "cargo-cyclonedx did not produce expected SBOM [$sourceSbom]."
    }
    & node `
      (Join-Path $workspace "scripts/normalize-cyclonedx.mjs") `
      $sourceSbom `
      (Join-Path $metadataDirectory $sbomName) `
      $workspace
    if ($LASTEXITCODE -ne 0) {
      throw "CycloneDX normalization failed for [$sourceSbom]."
    }
  }

  $npmSbomOutput = (& npm sbom --prefix $desktopDir --package-lock-only --sbom-format cyclonedx --sbom-type application | Out-String)
  if ($LASTEXITCODE -ne 0 -or -not $npmSbomOutput.Trim()) {
    throw "npm failed to generate the desktop CycloneDX SBOM."
  }
  [System.IO.File]::WriteAllText(
    $rawNpmSbom,
    $npmSbomOutput,
    [System.Text.UTF8Encoding]::new($false)
  )
  & node `
    (Join-Path $workspace "scripts/normalize-cyclonedx.mjs") `
    $rawNpmSbom `
    (Join-Path $metadataDirectory "desktop-npm.cdx.json") `
    $workspace
  if ($LASTEXITCODE -ne 0) {
    throw "CycloneDX normalization failed for the desktop npm SBOM."
  }

  Copy-Item -LiteralPath $releaseMetadataTemp -Destination (Join-Path $metadataDirectory "release.json")

  $artifactManifestRelative = "metadata/artifacts.json"
  $artifactManifest = Join-Path $bundleRoot $artifactManifestRelative
  $artifactManifestSignature = "$artifactManifest.sig"
  & cargo run --quiet --locked -p ssdev-release-manifest -- create $bundleRoot $artifactManifestRelative
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $artifactManifest -PathType Leaf)) {
    throw "Failed to create the release artifact manifest."
  }
  if ($env:TAURI_SIGNING_PRIVATE_KEY -and (Test-Path -LiteralPath $env:TAURI_SIGNING_PRIVATE_KEY -PathType Leaf)) {
    $privateKeyPath = $env:TAURI_SIGNING_PRIVATE_KEY
    $env:TAURI_SIGNING_PRIVATE_KEY = $null
    try {
      & npm run tauri --prefix $desktopDir -- signer sign --private-key-path $privateKeyPath $artifactManifest
    }
    finally {
      $env:TAURI_SIGNING_PRIVATE_KEY = $privateKeyPath
    }
  }
  else {
    & npm run tauri --prefix $desktopDir -- signer sign $artifactManifest
  }
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $artifactManifestSignature -PathType Leaf)) {
    throw "Failed to sign the release artifact manifest."
  }
  & cargo run --quiet --locked -p ssdev-desktop-core --example verify_update_artifact -- `
    (Join-Path $metadataDirectory "app-update.json") $artifactManifest $artifactManifestSignature
  if ($LASTEXITCODE -ne 0) {
    throw "Release artifact manifest signature verification failed."
  }
  & cargo run --quiet --locked -p ssdev-release-manifest -- verify $bundleRoot $artifactManifestRelative
  if ($LASTEXITCODE -ne 0) {
    throw "Release artifact manifest inventory verification failed."
  }

  if ($hasCertificateSigning -or $hasCustomSigning) {
    foreach ($bundle in $expectedBundleArtifacts) {
      Assert-CodeSignature $bundle.FullName
    }
  }
} finally {
  if ($pushedWorkspace) {
    Pop-Location
  }
  foreach ($generatedSbom in @(Get-ChildItem -Path $sbomSourceRoots -Filter "*.cdx.json" -Recurse -File -ErrorAction SilentlyContinue)) {
    Remove-Item -LiteralPath $generatedSbom.FullName -Force
  }
  foreach ($sourceSbomState in $sourceSbomStates) {
    Restore-ResourceState $sourceSbomState
  }
  foreach ($resourceState in $resourceStates) {
    Restore-ResourceState $resourceState
  }
  if (Test-Path $updateBuildConfig) {
    Remove-Item -Force $updateBuildConfig
  }
  if (Test-Path $rawNpmSbom) {
    Remove-Item -Force $rawNpmSbom
  }
  if (Test-Path $releaseMetadataTemp) {
    Remove-Item -Force $releaseMetadataTemp
  }
}

$finalReleaseMetadata = Join-Path $bundleRoot "metadata/release.json"
if ($AllowUnsignedTestBuild) {
  # Synthetic CI packages may intentionally inject a version and unsigned test
  # resources. Validate the embedded provenance structure, while reserving the
  # exact post-build workspace comparison for production artifacts.
  & cargo run --quiet --locked --manifest-path (Join-Path $workspace "Cargo.toml") `
    -p ssdev-release-manifest -- metadata-verify `
    $finalReleaseMetadata
}
else {
  & cargo run --quiet --locked --manifest-path (Join-Path $workspace "Cargo.toml") `
    -p ssdev-release-manifest -- metadata-verify `
    $finalReleaseMetadata `
    $workspace
}
if ($LASTEXITCODE -ne 0) {
  throw "Release provenance changed while the Windows bundle was being built."
}
