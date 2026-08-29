param(
  [string]$BundleRoot,
  [string]$PreviousBundleRoot,
  [ValidateSet("x86_64-pc-windows-msvc", "i686-pc-windows-msvc")]
  [string]$DesktopTarget = "x86_64-pc-windows-msvc",
  [ValidateSet("OfflineInstaller", "DownloadBootstrapper")]
  [string]$ExpectedWebViewInstallMode = "OfflineInstaller",
  [ValidateSet("OfflineInstaller", "DownloadBootstrapper")]
  [string]$PreviousExpectedWebViewInstallMode,
  [string]$ProductName = "SSDEV Desktop",
  [string]$MainExecutableName = "ssdev-desktop-core.exe",
  [string]$ApplicationIdentifier = "com.bsoft.ssdev.desktop",
  [string]$ExpectedSignerSubject = $env:SSDEV_WINDOWS_SIGNER_SUBJECT,
  [string]$PreviousExpectedSignerSubject,
  [string]$ExpectedAppUpdatePublicKey = $env:SSDEV_APP_UPDATE_PUBLIC_KEY_SOURCE,
  [string]$PreviousExpectedAppUpdatePublicKey,
  [Parameter(Mandatory = $true)]
  [string]$EvidenceOutput,
  [Parameter(Mandatory = $true)]
  [string]$EvidenceEnvironment,
  [string]$DeploymentCheckRecord,
  [switch]$RequireAuthenticode,
  [switch]$SkipLaunch
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $PreviousExpectedWebViewInstallMode) {
  $PreviousExpectedWebViewInstallMode = $ExpectedWebViewInstallMode
}

$workspace = Split-Path -Parent $PSScriptRoot
if (-not $BundleRoot) {
  $BundleRoot = Join-Path $workspace "target/$DesktopTarget/release/bundle"
}
$BundleRoot = (Resolve-Path $BundleRoot).Path
$metadataDirectory = Join-Path $BundleRoot "metadata"
if ($PreviousBundleRoot) {
  $PreviousBundleRoot = (Resolve-Path $PreviousBundleRoot).Path
}
if (
  -not $EvidenceEnvironment -or
  $EvidenceEnvironment.Length -gt 128 -or
  $EvidenceEnvironment.StartsWith(".") -or
  $EvidenceEnvironment -notmatch '^[A-Za-z0-9_.-]+$'
) {
  throw "EvidenceEnvironment must be a portable identifier up to 128 characters."
}
$evidenceParent = Split-Path -Parent ([System.IO.Path]::GetFullPath($EvidenceOutput))
if (-not $evidenceParent -or -not (Test-Path -LiteralPath $evidenceParent -PathType Container)) {
  throw "EvidenceOutput parent must be an existing directory."
}
$EvidenceOutput = Join-Path (Resolve-Path -LiteralPath $evidenceParent).Path (Split-Path -Leaf $EvidenceOutput)
if (Test-Path -LiteralPath $EvidenceOutput) {
  throw "EvidenceOutput already exists; package evidence is never overwritten."
}
if ($DeploymentCheckRecord) {
  if (-not (Test-Path -LiteralPath $DeploymentCheckRecord -PathType Leaf)) {
    throw "DeploymentCheckRecord must be an existing deep deployment-check JSON file."
  }
  $DeploymentCheckRecord = (Resolve-Path -LiteralPath $DeploymentCheckRecord).Path
}

function Read-ExpectedUpdatePublicKey {
  param([Parameter(Mandatory = $true)][string]$Path)
  $resolved = (Resolve-Path -LiteralPath $Path).Path
  $text = (Get-Content -Raw -LiteralPath $resolved).Trim()
  try {
    $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($text))
  } catch {
    throw "Expected application update public key is not valid Base64 text."
  }
  if (-not $decoded.StartsWith("untrusted comment:") -or $decoded.Split("`n").Count -lt 2) {
    throw "Expected application update public key is not a valid Minisign public key envelope."
  }
  return $text
}

if (-not $ExpectedAppUpdatePublicKey) {
  throw "Package verification requires -ExpectedAppUpdatePublicKey or SSDEV_APP_UPDATE_PUBLIC_KEY_SOURCE."
}
$script:ExpectedUpdatePublicKeyText = Read-ExpectedUpdatePublicKey $ExpectedAppUpdatePublicKey
$script:PreviousExpectedUpdatePublicKeyText = if ($PreviousExpectedAppUpdatePublicKey) {
  Read-ExpectedUpdatePublicKey $PreviousExpectedAppUpdatePublicKey
} else {
  $script:ExpectedUpdatePublicKeyText
}

function Get-SingleArtifact {
  param(
    [Parameter(Mandatory = $true)][string]$Directory,
    [Parameter(Mandatory = $true)][string]$Filter,
    [Parameter(Mandatory = $true)][string]$Label
  )
  $artifacts = @(Get-ChildItem -Path $Directory -Filter $Filter -File -ErrorAction SilentlyContinue)
  if ($artifacts.Count -ne 1) {
    throw "Expected exactly one $Label artifact in [$Directory], found $($artifacts.Count)."
  }
  return $artifacts[0].FullName
}

function Assert-ExitCode {
  param(
    [Parameter(Mandatory = $true)]$Process,
    [Parameter(Mandatory = $true)][string]$Operation
  )
  if ($Process.ExitCode -notin @(0, 3010)) {
    throw "$Operation failed with exit code $($Process.ExitCode)."
  }
}

function Assert-Authenticode {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string]$SignerSubject = $ExpectedSignerSubject
  )
  if (-not $RequireAuthenticode) {
    return
  }
  $signature = Get-AuthenticodeSignature -FilePath $Path
  if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw "Authenticode signature is not valid for [$Path]: $($signature.StatusMessage)"
  }
  if (-not $SignerSubject) {
    throw "Authenticode verification requires an expected signer subject."
  }
  if (-not [String]::Equals($signature.SignerCertificate.Subject, $SignerSubject, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Authenticode signer for [$Path] does not exactly match [$SignerSubject]."
  }
}

function Get-PeMachine {
  param([Parameter(Mandatory = $true)][string]$Path)
  $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
  $reader = [System.IO.BinaryReader]::new($stream)
  try {
    if ($reader.ReadUInt16() -ne 0x5A4D) {
      throw "[$Path] does not contain an MZ header."
    }
    $stream.Position = 0x3C
    $peOffset = $reader.ReadInt32()
    if ($peOffset -lt 64 -or $peOffset -gt ($stream.Length - 6)) {
      throw "[$Path] contains an invalid PE offset."
    }
    $stream.Position = $peOffset
    if ($reader.ReadUInt32() -ne 0x00004550) {
      throw "[$Path] does not contain a PE signature."
    }
    return $reader.ReadUInt16()
  } finally {
    $reader.Dispose()
    $stream.Dispose()
  }
}

function Assert-PeArchitecture {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][ValidateSet("x86", "x64")][string]$Architecture
  )
  $expectedMachine = if ($Architecture -eq "x86") { 0x014C } else { 0x8664 }
  $actualMachine = Get-PeMachine $Path
  if ($actualMachine -ne $expectedMachine) {
    throw "[$Path] has PE machine 0x$($actualMachine.ToString('X4')); expected $Architecture."
  }
}

function Get-AppRegistrations {
  $registryPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
  )
  return @(
    foreach ($registryPath in $registryPaths) {
      Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue |
        Where-Object { (Get-OptionalProperty $_ "DisplayName") -eq $ProductName }
    }
  )
}

function Wait-AppRegistration {
  $deadline = [DateTime]::UtcNow.AddSeconds(30)
  do {
    $registrations = @(Get-AppRegistrations)
    if ($registrations.Count -eq 1) {
      return $registrations[0]
    }
    if ($registrations.Count -gt 1) {
      throw "Found multiple uninstall registrations for [$ProductName]."
    }
    Start-Sleep -Milliseconds 250
  } while ([DateTime]::UtcNow -lt $deadline)
  throw "Windows did not register [$ProductName] after installation."
}

function Get-OptionalProperty {
  param(
    [Parameter(Mandatory = $true)]$InputObject,
    [Parameter(Mandatory = $true)][string]$Name
  )
  $property = $InputObject.PSObject.Properties[$Name]
  if ($property -and $null -ne $property.Value) {
    return [string]$property.Value
  }
  return $null
}

function Get-ReleaseMetadata {
  param(
    [Parameter(Mandatory = $true)][string]$ReleaseBundleRoot,
    [switch]$VerifyCurrentSource
  )
  $path = Join-Path $ReleaseBundleRoot "metadata/release.json"
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "Release bundle is missing metadata/release.json."
  }
  $verificationArguments = @(
    "run", "--quiet", "--locked", "--manifest-path", (Join-Path $workspace "Cargo.toml"),
    "-p", "ssdev-release-manifest", "--", "metadata-verify", $path
  )
  if ($VerifyCurrentSource) {
    $verificationArguments += $workspace
  }
  # Native stdout is part of a PowerShell function's return stream. Send the
  # verifier's diagnostic output directly to the host so callers receive only
  # the parsed release metadata object below.
  & cargo @verificationArguments | Out-Host
  if ($LASTEXITCODE -ne 0) {
    throw "Release provenance metadata failed Rust verification."
  }
  $metadata = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
  if ($metadata.schemaVersion -ne 2 -or -not $metadata.appVersion -or -not $metadata.productName -or -not $metadata.identifier -or -not $metadata.sourceRevision) {
    throw "Release metadata is malformed or unsupported."
  }
  if ($metadata.productName -ne $ProductName -or $metadata.identifier -ne $ApplicationIdentifier) {
    throw "Release metadata does not match the expected product identity."
  }
  if ($RequireAuthenticode -and -not $metadata.authenticodeRequired) {
    throw "Release metadata marks this bundle as an unsigned test build."
  }
  try {
    [void][version]$metadata.appVersion
  } catch {
    throw "Release metadata appVersion is not a numeric Windows version."
  }
  return $metadata
}

function Assert-TrustKeyLifecycle {
  param(
    [Parameter(Mandatory = $true)][string]$TrustStorePath,
    [Parameter(Mandatory = $true)][string]$Label
  )
  & cargo run --quiet --locked --manifest-path (Join-Path $workspace "Cargo.toml") `
    -p ssdev-release-signing -- verify-trust-store `
    --trust-store $TrustStorePath `
    --required-purposes plugin,origin-policy,project-bundle
  if ($LASTEXITCODE -ne 0) {
    throw "$Label trust store is not ready for plugin, origin-policy, and project-bundle issuance."
  }
}

function Normalize-RegistryPath {
  param(
    [Parameter(Mandatory = $true)][string]$Value,
    [Parameter(Mandatory = $true)][string]$Name
  )
  $value = $Value.Trim()
  $startsQuoted = $value.StartsWith('"')
  $endsQuoted = $value.EndsWith('"')
  if ($startsQuoted -ne $endsQuoted) {
    throw "Windows uninstall registration [$Name] contains unmatched quotes."
  }
  if ($startsQuoted) {
    $value = $value.Substring(1, $value.Length - 2)
  }
  if (-not $value -or $value.Contains('"')) {
    throw "Windows uninstall registration [$Name] is not a plain path."
  }
  return $value
}

function Resolve-InstalledExecutable {
  param([Parameter(Mandatory = $true)]$Registration)
  $candidates = [System.Collections.Generic.List[string]]::new()
  $installLocation = Get-OptionalProperty $Registration "InstallLocation"
  if ($installLocation) {
    $installLocation = Normalize-RegistryPath $installLocation "InstallLocation"
    $candidates.Add((Join-Path $installLocation $MainExecutableName))
  }
  $displayIcon = Get-OptionalProperty $Registration "DisplayIcon"
  if ($displayIcon) {
    if ($displayIcon -match '^"([^"]+\.exe)"(?:,\d+)?$') {
      $candidates.Add($Matches[1])
    } elseif ($displayIcon -match '^(.+\.exe)(?:,\d+)?$') {
      $candidates.Add($Matches[1])
    }
  }
  $uninstallString = Get-OptionalProperty $Registration "UninstallString"
  if ($uninstallString) {
    if ($uninstallString -match '^"([^"]+\.exe)"') {
      $candidates.Add((Join-Path (Split-Path -Parent $Matches[1]) $MainExecutableName))
    }
  }
  foreach ($candidate in $candidates) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
      return (Resolve-Path -LiteralPath $candidate).Path
    }
  }
  throw "Could not resolve installed executable [$MainExecutableName] from the Windows uninstall registration."
}

function Assert-InstalledLayout {
  param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][string]$ReleaseMetadataDirectory,
    [string]$SignerSubject = $ExpectedSignerSubject
  )
  $installRoot = Split-Path -Parent $Executable
  $requiredFiles = @(
    $Executable,
    (Join-Path $installRoot "plugin-trust.json"),
    (Join-Path $installRoot "origin-policy.json"),
    (Join-Path $installRoot "origin-policy.sig.json"),
    (Join-Path $installRoot "app-update.json"),
    (Join-Path $installRoot "windows/webplus-plugin-host-x86.exe"),
    (Join-Path $installRoot "windows/webplus-plugin-host-x64.exe")
  )
  foreach ($requiredFile in $requiredFiles) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
      throw "Installed package is missing required file [$requiredFile]."
    }
  }

  $desktopArchitecture = if ($DesktopTarget -eq "i686-pc-windows-msvc") { "x86" } else { "x64" }
  Assert-PeArchitecture $Executable $desktopArchitecture
  $x86Host = Join-Path $installRoot "windows/webplus-plugin-host-x86.exe"
  $x64Host = Join-Path $installRoot "windows/webplus-plugin-host-x64.exe"
  Assert-PeArchitecture $x86Host "x86"
  Assert-PeArchitecture $x64Host "x64"
  Assert-Authenticode $Executable $SignerSubject
  Assert-Authenticode $x86Host $SignerSubject
  Assert-Authenticode $x64Host $SignerSubject

  Assert-TrustKeyLifecycle (Join-Path $installRoot "plugin-trust.json") "Installed"
  $originPolicy = Get-Content -Raw (Join-Path $installRoot "origin-policy.json") | ConvertFrom-Json
  $originSignature = Get-Content -Raw (Join-Path $installRoot "origin-policy.sig.json") | ConvertFrom-Json
  if ($originPolicy.schemaVersion -ne 2 -or $originSignature.schemaVersion -ne 1) {
    throw "Installed origin policy or signature has an unsupported schema."
  }
  if (@($originPolicy.businessGrants).Count -lt 1) {
    throw "Installed origin policy does not contain scoped business grants."
  }
  $grantOrigins = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach ($grant in @($originPolicy.businessGrants)) {
    if (-not $grant.origin -or -not $grantOrigins.Add([string]$grant.origin) -or @($grant.services).Count -lt 1) {
      throw "Installed origin policy contains an empty or duplicate business grant."
    }
    $grantServices = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($service in @($grant.services)) {
      if (-not $service.serviceId -or $service.serviceId -eq "*" -or -not $grantServices.Add([string]$service.serviceId) -or @($service.methods).Count -lt 1) {
        throw "Installed origin policy contains an empty, duplicate, or wildcard service grant."
      }
      $grantMethods = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
      foreach ($method in @($service.methods)) {
        if (-not $method -or $method -eq "*" -or -not $grantMethods.Add([string]$method)) {
          throw "Installed origin policy contains an empty, duplicate, or wildcard method grant."
        }
      }
    }
  }
  $updatePolicy = Get-Content -Raw (Join-Path $installRoot "app-update.json") | ConvertFrom-Json
  if ($updatePolicy.schemaVersion -ne 1 -or -not $updatePolicy.enabled -or @($updatePolicy.endpoints).Count -lt 1) {
    throw "Installed application update policy is disabled or malformed."
  }
  foreach ($endpoint in @($updatePolicy.endpoints)) {
    $uri = [System.Uri]$endpoint
    if ($uri.Scheme -ne "https" -or -not $uri.Host -or $uri.UserInfo -or $uri.Fragment) {
      throw "Installed update endpoint is not strict HTTPS."
    }
  }

  foreach ($policyName in @("plugin-trust.json", "origin-policy.json", "origin-policy.sig.json", "app-update.json")) {
    $installedPolicy = Join-Path $installRoot $policyName
    $releasePolicy = Join-Path $ReleaseMetadataDirectory $policyName
    if (-not (Test-Path -LiteralPath $releasePolicy -PathType Leaf)) {
      throw "Release metadata is missing [$policyName]."
    }
    if ((Get-FileHash -LiteralPath $installedPolicy -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $releasePolicy -Algorithm SHA256).Hash) {
      throw "Installed [$policyName] does not match the verified release input."
    }
  }
  foreach ($optionalPolicyName in @("process-policy.json", "process-policy.sig.json")) {
    $installedPolicy = Join-Path $installRoot $optionalPolicyName
    $releasePolicy = Join-Path $ReleaseMetadataDirectory $optionalPolicyName
    if (Test-Path -LiteralPath $releasePolicy -PathType Leaf) {
      if (-not (Test-Path -LiteralPath $installedPolicy -PathType Leaf)) {
        throw "Installed package is missing release policy [$optionalPolicyName]."
      }
      if ((Get-FileHash -LiteralPath $installedPolicy -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $releasePolicy -Algorithm SHA256).Hash) {
        throw "Installed [$optionalPolicyName] does not match the verified release input."
      }
    } elseif (Test-Path -LiteralPath $installedPolicy) {
      throw "Installed package contains unexpected policy [$optionalPolicyName]."
    }
  }
}

function Capture-CandidateRuntimeHashes {
  param([Parameter(Mandatory = $true)][string]$Executable)
  $installRoot = Split-Path -Parent $Executable
  $pluginTrustStore = Join-Path $installRoot "plugin-trust.json"
  $originPolicy = Join-Path $installRoot "origin-policy.json"
  $x86Host = Join-Path $installRoot "windows/webplus-plugin-host-x86.exe"
  $x64Host = Join-Path $installRoot "windows/webplus-plugin-host-x64.exe"
  foreach ($runtimeFile in @($pluginTrustStore, $originPolicy, $x86Host, $x64Host)) {
    if (-not (Test-Path -LiteralPath $runtimeFile -PathType Leaf)) {
      throw "Installed runtime identity file disappeared before final evidence capture."
    }
  }
  $script:CandidatePluginTrustStoreSha256 = (Get-FileHash -LiteralPath $pluginTrustStore -Algorithm SHA256).Hash.ToLowerInvariant()
  $script:CandidateOriginPolicySha256 = (Get-FileHash -LiteralPath $originPolicy -Algorithm SHA256).Hash.ToLowerInvariant()
  $script:CandidateX86HostSha256 = (Get-FileHash -LiteralPath $x86Host -Algorithm SHA256).Hash.ToLowerInvariant()
  $script:CandidateX64HostSha256 = (Get-FileHash -LiteralPath $x64Host -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Test-ReleaseTrustPolicies {
  param([Parameter(Mandatory = $true)][string]$ReleaseMetadataDirectory)
  $trustStore = Join-Path $ReleaseMetadataDirectory "plugin-trust.json"
  $originPolicy = Join-Path $ReleaseMetadataDirectory "origin-policy.json"
  $originSignature = Join-Path $ReleaseMetadataDirectory "origin-policy.sig.json"
  foreach ($requiredFile in @($trustStore, $originPolicy, $originSignature)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
      throw "Release trust verification is missing [$requiredFile]."
    }
  }
  Assert-TrustKeyLifecycle $trustStore "Release"
  & cargo run --quiet --locked --manifest-path (Join-Path $workspace "Cargo.toml") `
    -p ssdev-release-signing -- verify `
    --kind origin-policy `
    --document $originPolicy `
    --envelope $originSignature `
    --trust-store $trustStore
  if ($LASTEXITCODE -ne 0) {
    throw "Release origin policy is not signed by an active origin-policy key."
  }

  $processPolicy = Join-Path $ReleaseMetadataDirectory "process-policy.json"
  $processSignature = Join-Path $ReleaseMetadataDirectory "process-policy.sig.json"
  if ((Test-Path -LiteralPath $processPolicy) -ne (Test-Path -LiteralPath $processSignature)) {
    throw "Release process policy and signature must either both exist or both be absent."
  }
  if (Test-Path -LiteralPath $processPolicy -PathType Leaf) {
    & cargo run --quiet --locked --manifest-path (Join-Path $workspace "Cargo.toml") `
      -p ssdev-release-signing -- verify `
      --kind process-policy `
      --document $processPolicy `
      --envelope $processSignature `
      --trust-store $trustStore
    if ($LASTEXITCODE -ne 0) {
      throw "Release process policy is not signed by an active process-policy key."
    }
  }
}

function Test-UpdaterSignatures {
  param(
    [Parameter(Mandatory = $true)][string]$ReleaseBundleRoot,
    [Parameter(Mandatory = $true)][string]$ReleaseMetadataDirectory,
    [Parameter(Mandatory = $true)][string]$ExpectedPublicKeyText
  )
  $policy = Join-Path $ReleaseMetadataDirectory "app-update.json"
  if (-not (Test-Path -LiteralPath $policy -PathType Leaf)) {
    throw "Release metadata does not contain app-update.json."
  }
  $updatePolicy = Get-Content -Raw -LiteralPath $policy | ConvertFrom-Json
  if (-not [String]::Equals(([string]$updatePolicy.pubkey).Trim(), $ExpectedPublicKeyText, [StringComparison]::Ordinal)) {
    throw "Release update policy does not contain the independently supplied application update public key."
  }
  $releaseManifestSignature = Join-Path $ReleaseBundleRoot "metadata/artifacts.json.sig"
  $signatures = @(
    Get-ChildItem -Path $ReleaseBundleRoot -Recurse -Filter "*.sig" -File -ErrorAction SilentlyContinue |
      Where-Object { -not [String]::Equals($_.FullName, $releaseManifestSignature, [StringComparison]::OrdinalIgnoreCase) }
  )
  if ($signatures.Count -lt 1) {
    throw "Updater signature artifact was not produced under [$ReleaseBundleRoot]."
  }
  foreach ($signature in $signatures) {
    $artifact = $signature.FullName.Substring(0, $signature.FullName.Length - 4)
    if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
      throw "Updater signature [$($signature.FullName)] does not have a matching package."
    }
    & cargo run --quiet --locked --manifest-path (Join-Path $workspace "Cargo.toml") `
      -p ssdev-desktop-core --example verify_update_artifact -- `
      $policy $artifact $signature.FullName
    if ($LASTEXITCODE -ne 0) {
      throw "Updater Minisign verification failed for [$artifact]."
    }
  }
}

function Test-ReleaseArtifactManifest {
  param(
    [Parameter(Mandatory = $true)][string]$ReleaseBundleRoot,
    [Parameter(Mandatory = $true)][string]$ReleaseMetadataDirectory,
    [Parameter(Mandatory = $true)][string]$ExpectedPublicKeyText,
    [Parameter(Mandatory = $true)][string]$ExpectedProfileWebViewInstallMode
  )
  $policy = Join-Path $ReleaseMetadataDirectory "app-update.json"
  $manifestRelative = "metadata/artifacts.json"
  $manifest = Join-Path $ReleaseBundleRoot $manifestRelative
  $signature = "$manifest.sig"
  foreach ($requiredFile in @($policy, $manifest, $signature)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
      throw "Release artifact manifest verification is missing [$requiredFile]."
    }
  }
  $updatePolicy = Get-Content -Raw -LiteralPath $policy | ConvertFrom-Json
  if (-not [String]::Equals(([string]$updatePolicy.pubkey).Trim(), $ExpectedPublicKeyText, [StringComparison]::Ordinal)) {
    throw "Release artifact manifest is not anchored to the independently supplied application update public key."
  }
  & cargo run --quiet --locked --manifest-path (Join-Path $workspace "Cargo.toml") `
    -p ssdev-desktop-core --example verify_update_artifact -- `
    $policy $manifest $signature
  if ($LASTEXITCODE -ne 0) {
    throw "Release artifact manifest signature verification failed."
  }
  & cargo run --quiet --locked --manifest-path (Join-Path $workspace "Cargo.toml") `
    -p ssdev-release-manifest -- verify $ReleaseBundleRoot $manifestRelative
  if ($LASTEXITCODE -ne 0) {
    throw "Release artifact manifest does not exactly match the release bundle."
  }

  $packageProfilePath = Join-Path $ReleaseMetadataDirectory "package-profile.json"
  if (-not (Test-Path -LiteralPath $packageProfilePath -PathType Leaf)) {
    throw "Release metadata does not contain package-profile.json."
  }
  $packageProfile = Get-Content -Raw -LiteralPath $packageProfilePath | ConvertFrom-Json
  if (
    $packageProfile.schemaVersion -ne 1 -or
    $packageProfile.desktopTarget -ne $DesktopTarget -or
    $packageProfile.installerKind -ne "Nsis" -or
    $packageProfile.webviewInstallMode -ne $ExpectedProfileWebViewInstallMode
  ) {
    throw "Release package profile does not match the requested architecture, installer kind, or WebView2 mode."
  }

  $desktopArchitecture = if ($DesktopTarget -eq "i686-pc-windows-msvc") { "x86" } else { "x64" }
  $requiredSboms = @(
    [pscustomobject]@{ Name = "desktop-rust-$desktopArchitecture.cdx.json"; Component = "ssdev-desktop-core"; Target = $DesktopTarget; RequiredComponents = @("ssdev-invocation-ledger", "webplus-controller") },
    [pscustomobject]@{ Name = "plugin-host-rust-x64.cdx.json"; Component = "webplus-plugin-host"; Target = "x86_64-pc-windows-msvc"; RequiredComponents = @("webplus-native", "webplus-ipc") },
    [pscustomobject]@{ Name = "plugin-host-rust-x86.cdx.json"; Component = "webplus-plugin-host"; Target = "i686-pc-windows-msvc"; RequiredComponents = @("webplus-native", "webplus-ipc") },
    [pscustomobject]@{ Name = "desktop-npm.cdx.json"; Component = "desktop"; Target = $null; RequiredComponents = @("@tauri-apps/api", "vue") }
  )
  foreach ($requiredSbom in $requiredSboms) {
    $sbomPath = Join-Path $ReleaseMetadataDirectory $requiredSbom.Name
    if (-not (Test-Path -LiteralPath $sbomPath -PathType Leaf)) {
      throw "Release metadata is missing CycloneDX SBOM [$($requiredSbom.Name)]."
    }
    $rawSbom = Get-Content -Raw -LiteralPath $sbomPath
    if ($rawSbom -match "path\+file:|download_url=file|file:///[A-Za-z]:") {
      throw "CycloneDX SBOM [$($requiredSbom.Name)] exposes a build workspace path."
    }
    $sbom = $rawSbom | ConvertFrom-Json
    if (
      $sbom.bomFormat -ne "CycloneDX" -or
      $sbom.specVersion -ne "1.5" -or
      $sbom.version -ne 1 -or
      $sbom.metadata.component.name -ne $requiredSbom.Component -or
      @($sbom.components).Count -lt 1 -or
      @($sbom.dependencies).Count -lt 1
    ) {
      throw "CycloneDX SBOM [$($requiredSbom.Name)] is malformed or describes the wrong component."
    }
    if ($requiredSbom.Target) {
      $targetProperty = @($sbom.metadata.properties | Where-Object { $_.name -eq "cdx:rustc:sbom:target:triple" })
      if ($targetProperty.Count -ne 1 -or $targetProperty[0].value -ne $requiredSbom.Target) {
        throw "CycloneDX SBOM [$($requiredSbom.Name)] does not describe target [$($requiredSbom.Target)]."
      }
    }
    $componentNames = @($sbom.components | ForEach-Object { [string]$_.name })
    foreach ($requiredComponent in @($requiredSbom.RequiredComponents)) {
      if ($componentNames -cnotcontains $requiredComponent) {
        throw "CycloneDX SBOM [$($requiredSbom.Name)] is missing required component [$requiredComponent]."
      }
    }
  }
}

function Get-DiagnosticEventCount {
  param(
    [Parameter(Mandatory = $true)][string]$DiagnosticLog,
    [Parameter(Mandatory = $true)][string]$ExpectedVersion,
    [Parameter(Mandatory = $true)][string]$EventCode
  )
  if (-not (Test-Path -LiteralPath $DiagnosticLog -PathType Leaf)) {
    return 0
  }
  $count = 0
  foreach ($line in @(Get-Content -LiteralPath $DiagnosticLog -Tail 1000 -ErrorAction SilentlyContinue)) {
    try {
      $event = $line | ConvertFrom-Json
      if ($event.event_code -eq $EventCode -and $event.app_version -eq $ExpectedVersion) {
        $count += 1
      }
    } catch {
      # A concurrently written trailing line is retried on the next poll.
    }
  }
  return $count
}

function Get-ApplicationDataPaths {
  if (-not $env:APPDATA -or -not $env:LOCALAPPDATA) {
    throw "APPDATA and LOCALAPPDATA are required for the application smoke test."
  }
  if (
    $ApplicationIdentifier -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or
    $ApplicationIdentifier -in @('.', '..') -or
    [System.IO.Path]::GetFileName($ApplicationIdentifier) -ne $ApplicationIdentifier
  ) {
    throw "ApplicationIdentifier is not a safe application-data directory name."
  }
  $configRoot = [System.IO.Path]::GetFullPath((Join-Path $env:APPDATA $ApplicationIdentifier))
  $localDataRoot = [System.IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA $ApplicationIdentifier))
  $pluginRoot = Join-Path $localDataRoot "plugins"
  $localMappingRoot = Join-Path $localDataRoot "local-mappings"
  return [pscustomobject]@{
    ConfigRoot = $configRoot
    ConfigPath = (Join-Path $configRoot "config.json")
    LocalDataRoot = $localDataRoot
    PluginRoot = $pluginRoot
    PluginStateSentinel = (Join-Path $pluginRoot ".package-upgrade-sentinel")
    LocalMappingRoot = $localMappingRoot
    LocalMappingStateSentinel = (Join-Path $localMappingRoot ".package-upgrade-sentinel")
    DiagnosticLog = (Join-Path $localDataRoot "logs/ssdev.log")
    StartupFailure = (Join-Path $localDataRoot "logs/startup-failure.json")
  }
}

function Write-UpgradeStateSentinels {
  param(
    [Parameter(Mandatory = $true)]$Paths,
    [Parameter(Mandatory = $true)][string]$Sentinel
  )
  foreach ($directory in @($Paths.ConfigRoot, $Paths.PluginRoot, $Paths.LocalMappingRoot)) {
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
  }
  [System.IO.File]::WriteAllText(
    $Paths.ConfigPath,
    ([ordered]@{ upgradeSentinel = $Sentinel } | ConvertTo-Json),
    [System.Text.UTF8Encoding]::new($false)
  )
  foreach ($path in @($Paths.PluginStateSentinel, $Paths.LocalMappingStateSentinel)) {
    [System.IO.File]::WriteAllText($path, $Sentinel, [System.Text.UTF8Encoding]::new($false))
  }
}

function Assert-UpgradeStatePreserved {
  param(
    [Parameter(Mandatory = $true)]$Paths,
    [Parameter(Mandatory = $true)][string]$Sentinel,
    [Parameter(Mandatory = $true)][string]$Stage
  )
  if (-not (Test-Path -LiteralPath $Paths.ConfigPath -PathType Leaf)) {
    throw "$Stage removed the existing desktop configuration."
  }
  $preserved = Get-Content -Raw -LiteralPath $Paths.ConfigPath | ConvertFrom-Json
  if ((Get-OptionalProperty $preserved "upgradeSentinel") -ne $Sentinel) {
    throw "$Stage did not preserve unknown desktop configuration fields."
  }
  foreach ($state in @(
    [pscustomobject]@{ Path = $Paths.PluginStateSentinel; Label = "plugin data" },
    [pscustomobject]@{ Path = $Paths.LocalMappingStateSentinel; Label = "local mapping data" }
  )) {
    if (
      -not (Test-Path -LiteralPath $state.Path -PathType Leaf) -or
      -not [String]::Equals((Get-Content -Raw -LiteralPath $state.Path), $Sentinel, [StringComparison]::Ordinal)
    ) {
      throw "$Stage did not preserve existing $($state.Label)."
    }
  }
}

function Write-UnresolvedStartupFailureMarker {
  param([Parameter(Mandatory = $true)]$Paths)
  $logDirectory = Split-Path -Parent $Paths.StartupFailure
  New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
  $generatedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  $document = [ordered]@{
    schemaVersion = 1
    generatedAtUnixMs = $generatedAt
    eventCode = "desktop-startup-failed"
    errorCode = "startup-desktop-shell"
    summary = "Synthetic unresolved startup failure for package smoke."
    action = "The installed frontend must mark this record as recovered."
  }
  [System.IO.File]::WriteAllText(
    $Paths.StartupFailure,
    ($document | ConvertTo-Json -Compress),
    [System.Text.UTF8Encoding]::new($false)
  )
  return $generatedAt
}

function Assert-StartupFailureResolved {
  param(
    [Parameter(Mandatory = $true)]$Paths,
    [Parameter(Mandatory = $true)][string]$ExpectedVersion,
    [Parameter(Mandatory = $true)][long]$GeneratedAt
  )
  if (-not (Test-Path -LiteralPath $Paths.StartupFailure -PathType Leaf)) {
    throw "Installed application removed the startup failure record instead of resolving it."
  }
  $document = Get-Content -Raw -LiteralPath $Paths.StartupFailure | ConvertFrom-Json
  $resolvedAt = Get-OptionalProperty $document "resolvedAtUnixMs"
  if (
    $document.schemaVersion -ne 2 -or
    $document.errorCode -ne "startup-desktop-shell" -or
    -not $resolvedAt -or
    [long]$resolvedAt -lt $GeneratedAt -or
    (Get-OptionalProperty $document "resolvedByAppVersion") -ne $ExpectedVersion
  ) {
    throw "Installed frontend reached native IPC, but startup-failure.json was not marked as recovered by the running version."
  }
}

function Assert-ApplicationDataClean {
  param([Parameter(Mandatory = $true)]$Paths)
  foreach ($root in @($Paths.ConfigRoot, $Paths.LocalDataRoot)) {
    if (Test-Path -LiteralPath $root) {
      throw "Application data already exists at [$root]; package smoke requires an isolated Windows account or clean runner."
    }
  }
}

function Remove-OwnedApplicationData {
  param([Parameter(Mandatory = $true)]$Paths)
  $expected = Get-ApplicationDataPaths
  if (
    -not [String]::Equals($Paths.ConfigRoot, $expected.ConfigRoot, [StringComparison]::OrdinalIgnoreCase) -or
    -not [String]::Equals($Paths.LocalDataRoot, $expected.LocalDataRoot, [StringComparison]::OrdinalIgnoreCase)
  ) {
    throw "Refusing to clean application data outside the expected standard directories."
  }
  foreach ($root in @($Paths.ConfigRoot, $Paths.LocalDataRoot)) {
    if (Test-Path -LiteralPath $root) {
      Remove-Item -LiteralPath $root -Recurse -Force
    }
  }
}

function Invoke-ApplicationSmoke {
  param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][string]$ExpectedVersion
  )
  if ($SkipLaunch) {
    return
  }
  $processName = [System.IO.Path]::GetFileNameWithoutExtension($Executable)
  if (@(Get-Process -Name $processName -ErrorAction SilentlyContinue).Count -gt 0) {
    throw "A pre-existing [$processName] process would invalidate the package smoke test."
  }
  $dataPaths = Get-ApplicationDataPaths
  $application = $null
  try {
    $diagnosticLog = $dataPaths.DiagnosticLog
    $frontendEventsBefore = Get-DiagnosticEventCount $diagnosticLog $ExpectedVersion "frontend-ready"
    $startupFailureGeneratedAt = Write-UnresolvedStartupFailureMarker $dataPaths
    $application = Start-Process -FilePath $Executable -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $frontendReadyObserved = $false
    do {
      Start-Sleep -Milliseconds 250
      $application.Refresh()
      if ($application.HasExited) {
        throw "Installed application exited during startup with code $($application.ExitCode)."
      }
      if (Test-Path -LiteralPath $diagnosticLog -PathType Leaf) {
        if ((Get-DiagnosticEventCount $diagnosticLog $ExpectedVersion "frontend-ready") -gt $frontendEventsBefore) {
          $frontendReadyObserved = $true
        }
      }
    } while (-not $frontendReadyObserved -and [DateTime]::UtcNow -lt $deadline)
    if (-not $frontendReadyObserved) {
      throw "Installed application stayed alive, but the control frontend did not mount and reach native IPC."
    }
    Assert-StartupFailureResolved $dataPaths $ExpectedVersion $startupFailureGeneratedAt
  } finally {
    if ($application -and -not $application.HasExited) {
      Stop-Process -Id $application.Id -Force
      $application.WaitForExit(10000) | Out-Null
    }
  }
}

function Install-ApplicationPackage {
  param(
    [Parameter(Mandatory = $true)][string]$Installer,
    [string]$SignerSubject = $ExpectedSignerSubject,
    [switch]$AllowExisting
  )
  if (-not $AllowExisting -and @(Get-AppRegistrations).Count -ne 0) {
    throw "[$ProductName] is already installed; package smoke requires an isolated Windows account or clean runner."
  }
  Assert-Authenticode $Installer $SignerSubject
  $install = Start-Process -FilePath $Installer -ArgumentList "/S" -Wait -PassThru
  Assert-ExitCode $install "NSIS installation"
  $registration = Wait-AppRegistration
  $executable = Resolve-InstalledExecutable $registration
  return $executable
}

function Uninstall-ApplicationPackage {
  param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [string]$SignerSubject = $ExpectedSignerSubject
  )
  $uninstaller = Join-Path (Split-Path -Parent $Executable) "uninstall.exe"
  if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
    throw "NSIS uninstaller was not installed at [$uninstaller]."
  }
  Assert-Authenticode $uninstaller $SignerSubject
  $uninstall = Start-Process -FilePath $uninstaller -ArgumentList "/S" -Wait -PassThru
  Assert-ExitCode $uninstall "NSIS uninstall"
  Wait-ApplicationRemoved $Executable
}

function Wait-ApplicationRemoved {
  param([Parameter(Mandatory = $true)][string]$Executable)
  $deadline = [DateTime]::UtcNow.AddSeconds(30)
  do {
    if (-not (Test-Path -LiteralPath $Executable) -and @(Get-AppRegistrations).Count -eq 0) {
      return
    }
    Start-Sleep -Milliseconds 250
  } while ([DateTime]::UtcNow -lt $deadline)
  throw "Uninstall did not remove the application executable and registration."
}

function Test-Installer {
  param(
    [Parameter(Mandatory = $true)][string]$Installer
  )
  $dataPaths = Get-ApplicationDataPaths
  Assert-ApplicationDataClean $dataPaths
  $executable = $null
  try {
    $executable = Install-ApplicationPackage $Installer
    Assert-InstalledLayout $executable $metadataDirectory
    Invoke-ApplicationSmoke $executable $script:CandidateRelease.appVersion
    Capture-CandidateRuntimeHashes $executable
    Uninstall-ApplicationPackage $executable
    $executable = $null
    Write-Host "PASS NSIS install, layout, launch, and uninstall"
  } finally {
    if ($executable -and @(Get-AppRegistrations).Count -gt 0) {
      try {
        Uninstall-ApplicationPackage $executable
      } catch {
        Write-Warning "Best-effort cleanup after a failed NSIS package smoke also failed."
      }
    }
    Remove-OwnedApplicationData $dataPaths
  }
}

function Test-Upgrade {
  param(
    [Parameter(Mandatory = $true)][string]$PreviousInstaller,
    [Parameter(Mandatory = $true)][string]$CandidateInstaller,
    [Parameter(Mandatory = $true)][string]$PreviousMetadataDirectory
  )
  $dataPaths = Get-ApplicationDataPaths
  Assert-ApplicationDataClean $dataPaths
  $sentinel = [Guid]::NewGuid().ToString("N")
  $activeExecutable = $null
  $activeInstaller = $PreviousInstaller
  $previousSignerSubject = if ($PreviousExpectedSignerSubject) { $PreviousExpectedSignerSubject } else { $ExpectedSignerSubject }
  try {
    Write-UpgradeStateSentinels $dataPaths $sentinel
    $previousExecutable = Install-ApplicationPackage $PreviousInstaller $previousSignerSubject
    $activeExecutable = $previousExecutable
    Assert-InstalledLayout $previousExecutable $PreviousMetadataDirectory $previousSignerSubject
    Invoke-ApplicationSmoke $previousExecutable $script:PreviousRelease.appVersion
    Assert-UpgradeStatePreserved $dataPaths $sentinel "Previous-version startup"

    $candidateExecutable = Install-ApplicationPackage $CandidateInstaller $ExpectedSignerSubject -AllowExisting
    $activeExecutable = $candidateExecutable
    $activeInstaller = $CandidateInstaller
    Assert-InstalledLayout $candidateExecutable $metadataDirectory
    Assert-UpgradeStatePreserved $dataPaths $sentinel "NSIS candidate upgrade"
    Invoke-ApplicationSmoke $candidateExecutable $script:CandidateRelease.appVersion
    Assert-UpgradeStatePreserved $dataPaths $sentinel "Candidate startup"
    Capture-CandidateRuntimeHashes $candidateExecutable

    Uninstall-ApplicationPackage $candidateExecutable
    $activeExecutable = $null
    Assert-UpgradeStatePreserved $dataPaths $sentinel "Candidate uninstall"

    $rollbackExecutable = Install-ApplicationPackage $PreviousInstaller $previousSignerSubject
    $activeExecutable = $rollbackExecutable
    $activeInstaller = $PreviousInstaller
    Assert-InstalledLayout $rollbackExecutable $PreviousMetadataDirectory $previousSignerSubject
    Assert-UpgradeStatePreserved $dataPaths $sentinel "NSIS rollback reinstall"
    Invoke-ApplicationSmoke $rollbackExecutable $script:PreviousRelease.appVersion
    Assert-UpgradeStatePreserved $dataPaths $sentinel "Rolled-back application startup"
    Uninstall-ApplicationPackage $rollbackExecutable $previousSignerSubject
    $activeExecutable = $null
    Assert-UpgradeStatePreserved $dataPaths $sentinel "Final previous-version uninstall"
    $script:ApplicationStatePreservationVerified = $true
    Write-Host "PASS NSIS upgrade, configuration/plugin/mapping state preservation, candidate launch, rollback reinstall, previous-version launch, and final uninstall"
  } finally {
    if ($activeExecutable -and @(Get-AppRegistrations).Count -gt 0) {
      try {
        $cleanupSignerSubject = if ($activeInstaller -eq $PreviousInstaller) { $previousSignerSubject } else { $ExpectedSignerSubject }
        Uninstall-ApplicationPackage $activeExecutable $cleanupSignerSubject
      } catch {
        Write-Warning "Best-effort cleanup after a failed NSIS upgrade also failed."
      }
    }
    Remove-OwnedApplicationData $dataPaths
  }
}

$script:CandidateRelease = $null
$script:CandidatePluginTrustStoreSha256 = $null
$script:CandidateX86HostSha256 = $null
$script:CandidateX64HostSha256 = $null
$script:ApplicationStatePreservationVerified = $false
Test-ReleaseArtifactManifest $BundleRoot $metadataDirectory $script:ExpectedUpdatePublicKeyText $ExpectedWebViewInstallMode
Test-ReleaseTrustPolicies $metadataDirectory
$script:CandidateRelease = Get-ReleaseMetadata $BundleRoot -VerifyCurrentSource
Test-UpdaterSignatures $BundleRoot $metadataDirectory $script:ExpectedUpdatePublicKeyText

if ($PreviousBundleRoot) {
  $previousMetadataDirectory = Join-Path $PreviousBundleRoot "metadata"
  Test-ReleaseArtifactManifest $PreviousBundleRoot $previousMetadataDirectory $script:PreviousExpectedUpdatePublicKeyText $PreviousExpectedWebViewInstallMode
  Test-ReleaseTrustPolicies $previousMetadataDirectory
  $script:PreviousRelease = Get-ReleaseMetadata $PreviousBundleRoot
  $previousVersion = [version]([string]$script:PreviousRelease.appVersion)
  $candidateVersion = [version]([string]$script:CandidateRelease.appVersion)
  if ($previousVersion -ge $candidateVersion) {
    throw "Previous bundle version must be lower than candidate bundle version."
  }
  Test-UpdaterSignatures $PreviousBundleRoot $previousMetadataDirectory $script:PreviousExpectedUpdatePublicKeyText
}

$nsisInstaller = Get-SingleArtifact (Join-Path $BundleRoot "nsis") "*-setup.exe" "NSIS"
if ($PreviousBundleRoot) {
  $previousNsisInstaller = Get-SingleArtifact (Join-Path $PreviousBundleRoot "nsis") "*-setup.exe" "previous NSIS"
  Test-Upgrade $previousNsisInstaller $nsisInstaller $previousMetadataDirectory
} else {
  Test-Installer $nsisInstaller
}

if (Test-Path -LiteralPath $EvidenceOutput) {
  throw "EvidenceOutput appeared during package verification; refusing to overwrite it."
}
if (
  $script:CandidatePluginTrustStoreSha256 -notmatch '^[0-9a-f]{64}$' -or
  $script:CandidateOriginPolicySha256 -notmatch '^[0-9a-f]{64}$' -or
  $script:CandidateX86HostSha256 -notmatch '^[0-9a-f]{64}$' -or
  $script:CandidateX64HostSha256 -notmatch '^[0-9a-f]{64}$'
) {
  throw "Candidate installed runtime identity hashes were not captured during package verification."
}
if ($PreviousBundleRoot -and -not $script:ApplicationStatePreservationVerified) {
  throw "Windows upgrade completed without verified application state preservation."
}
$deploymentCheckEvidenceArgument = if ($DeploymentCheckRecord) { $DeploymentCheckRecord } else { "none" }
$evidenceArguments = @(
  "run", "--quiet", "--locked", "--manifest-path", (Join-Path $workspace "Cargo.toml"),
  "-p", "ssdev-cutover-evidence", "--", "windows-package",
  $workspace,
  (Join-Path $metadataDirectory "release.json"),
  (Join-Path $metadataDirectory "artifacts.json"),
  $EvidenceOutput,
  $EvidenceEnvironment,
  "Nsis",
  (-not $SkipLaunch).ToString().ToLowerInvariant(),
  $RequireAuthenticode.ToString().ToLowerInvariant(),
  $script:CandidatePluginTrustStoreSha256,
  $script:CandidateOriginPolicySha256,
  $script:CandidateX86HostSha256,
  $script:CandidateX64HostSha256,
  $deploymentCheckEvidenceArgument,
  $script:ApplicationStatePreservationVerified.ToString().ToLowerInvariant()
)
if ($PreviousBundleRoot) {
  $evidenceArguments += (Join-Path $previousMetadataDirectory "release.json")
}
& cargo @evidenceArguments
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $EvidenceOutput -PathType Leaf)) {
  throw "Windows package smoke passed, but its machine-verifiable evidence was not created."
}

Write-Host "All requested Windows package smoke tests passed."
