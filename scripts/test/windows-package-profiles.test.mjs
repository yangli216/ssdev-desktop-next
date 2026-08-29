import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const buildScriptUrl = new URL("../build-windows.ps1", import.meta.url);
const packageTestUrl = new URL("../test-windows-package.ps1", import.meta.url);
const pluginMatrixTestUrl = new URL(
  "../test-plugin-matrix.ps1",
  import.meta.url,
);
const workflowUrl = new URL("../../.github/workflows/ci.yml", import.meta.url);
const tauriConfigUrl = new URL(
  "../../apps/desktop/src-tauri/tauri.conf.json",
  import.meta.url,
);
const desktopMainUrl = new URL(
  "../../apps/desktop/src-tauri/src/main.rs",
  import.meta.url,
);
const pluginHostMainUrl = new URL(
  "../../crates/webplus-plugin-host/src/main.rs",
  import.meta.url,
);
const controllerUrl = new URL(
  "../../crates/webplus-controller/src/lib.rs",
  import.meta.url,
);
const cutoverEvidenceMainUrl = new URL(
  "../../crates/ssdev-cutover-evidence/src/main.rs",
  import.meta.url,
);
const controlHtmlUrl = new URL("../../apps/desktop/index.html", import.meta.url);

test("Windows build exposes only the supported installer and WebView2 profiles", async () => {
  const script = await readFile(buildScriptUrl, "utf8");

  assert.match(script, /\$bundleTargets = @\("nsis"\)/);
  assert.match(script, /installerKind = "Nsis"/);
  assert.doesNotMatch(script, /InstallerKind/);
  assert.doesNotMatch(script, /\bmsi\b/i);
  assert.match(
    script,
    /ValidateSet\("OfflineInstaller", "DownloadBootstrapper"\)/,
  );
  assert.match(script, /targets = @\(\$bundleTargets\)/);
  assert.match(script, /webviewInstallMode/);
  assert.match(script, /package-profile\.json/);
  assert.match(script, /larger than 128 MiB/);
  assert.doesNotMatch(script, /ValidateSet\([^\r\n]*"Skip"/);
});

test("Windows package smoke verifies the selected package profile", async () => {
  const script = await readFile(packageTestUrl, "utf8");

  assert.match(script, /ExpectedWebViewInstallMode/);
  assert.match(script, /package-profile\.json/);
  assert.match(script, /packageProfile\.installerKind -ne "Nsis"/);
  assert.doesNotMatch(script, /InstallerKind/);
  assert.doesNotMatch(script, /\bmsiexec\b/i);
  assert.match(
    script,
    /packageProfile\.webviewInstallMode -ne \$ExpectedProfileWebViewInstallMode/,
  );
  assert.match(script, /PreviousExpectedWebViewInstallMode/);
});

test("Windows production bundles require project delivery signing trust", async () => {
  const [buildScript, packageTest] = await Promise.all([
    readFile(buildScriptUrl, "utf8"),
    readFile(packageTestUrl, "utf8"),
  ]);

  for (const script of [buildScript, packageTest]) {
    assert.match(
      script,
      /--required-purposes plugin,origin-policy,project-bundle/,
    );
  }
});

test("CI publishes separate offline and online-light NSIS packages", async () => {
  const workflow = await readFile(workflowUrl, "utf8");
  const offlineUpload = workflow.indexOf(
    "name: ssdev-windows-${{ matrix.arch }}-offline-unsigned",
  );
  const onlineBuild = workflow.indexOf(
    "-WebViewInstallMode DownloadBootstrapper",
  );
  const onlineUpload = workflow.indexOf(
    "name: ssdev-windows-${{ matrix.arch }}-online-light-unsigned",
  );

  assert.ok(offlineUpload >= 0);
  assert.ok(onlineBuild > offlineUpload);
  assert.ok(onlineUpload > onlineBuild);
  assert.doesNotMatch(workflow, /InstallerKind/);
  assert.doesNotMatch(workflow, /\bMSI\b/);
  assert.match(
    workflow.slice(onlineBuild, onlineUpload),
    /-ExpectedWebViewInstallMode DownloadBootstrapper/,
  );
  assert.match(
    workflow.slice(onlineBuild, onlineUpload),
    /-PreviousBundleRoot \$env:SSDEV_CI_PREVIOUS_BUNDLE/,
  );
  assert.match(
    workflow.slice(onlineBuild, onlineUpload),
    /-PreviousExpectedWebViewInstallMode OfflineInstaller/,
  );
});

test("Windows upgrade gate permits a verified WebView2 package-profile transition", async () => {
  const packageTest = await readFile(packageTestUrl, "utf8");

  assert.match(
    packageTest,
    /Test-ReleaseArtifactManifest \$BundleRoot \$metadataDirectory \$script:ExpectedUpdatePublicKeyText \$ExpectedWebViewInstallMode/,
  );
  assert.match(
    packageTest,
    /Test-ReleaseArtifactManifest \$PreviousBundleRoot \$previousMetadataDirectory \$script:PreviousExpectedUpdatePublicKeyText \$PreviousExpectedWebViewInstallMode/,
  );
});

test("base Tauri configuration bundles only NSIS on Windows", async () => {
  const config = JSON.parse(await readFile(tauriConfigUrl, "utf8"));

  assert.deepEqual(config.bundle.targets, ["nsis"]);
  assert.deepEqual(config.plugins.updater, { pubkey: "", endpoints: [] });
});

test("Windows release executables and native hosts do not open consoles", async () => {
  const [desktopMain, pluginHostMain, controller] = await Promise.all([
    readFile(desktopMainUrl, "utf8"),
    readFile(pluginHostMainUrl, "utf8"),
    readFile(controllerUrl, "utf8"),
  ]);

  assert.match(desktopMain, /windows_subsystem = "windows"/);
  assert.match(pluginHostMain, /windows_subsystem = "windows"/);
  assert.match(controller, /\.creation_flags\(CREATE_NO_WINDOW\)/);
});

test("Windows package smoke requires a rendered frontend IPC signal", async () => {
  const [packageTest, controlHtml] = await Promise.all([
    readFile(packageTestUrl, "utf8"),
    readFile(controlHtmlUrl, "utf8"),
  ]);

  assert.match(packageTest, /"frontend-ready"/);
  assert.match(packageTest, /Write-UnresolvedStartupFailureMarker/);
  assert.match(packageTest, /Assert-StartupFailureResolved/);
  assert.match(packageTest, /resolvedAtUnixMs/);
  assert.match(packageTest, /resolvedByAppVersion/);
  assert.doesNotMatch(packageTest, /Get-StartupEventCount/);
  assert.match(controlHtml, /SSDEV Desktop 正在启动/);
});

test("Windows upgrade gate reinstalls and launches the exact previous release", async () => {
  const packageTest = await readFile(packageTestUrl, "utf8");

  assert.match(
    packageTest,
    /\$rollbackExecutable = Install-ApplicationPackage \$PreviousInstaller \$previousSignerSubject/,
  );
  assert.match(
    packageTest,
    /Assert-InstalledLayout \$rollbackExecutable \$PreviousMetadataDirectory \$previousSignerSubject/,
  );
  assert.match(
    packageTest,
    /Invoke-ApplicationSmoke \$rollbackExecutable \$script:PreviousRelease\.appVersion/,
  );
  assert.match(packageTest, /rollback reinstall did not preserve/);
  assert.match(
    packageTest,
    /Uninstall-ApplicationPackage \$rollbackExecutable \$previousSignerSubject/,
  );
});

test("production evidence binds delivery hosts, trust store, and origin policy", async () => {
  const [matrixTest, packageTest, cutoverEvidenceMain] = await Promise.all([
    readFile(pluginMatrixTestUrl, "utf8"),
    readFile(packageTestUrl, "utf8"),
    readFile(cutoverEvidenceMainUrl, "utf8"),
  ]);

  assert.match(matrixTest, /\[string\]\$X86Host/);
  assert.match(matrixTest, /\[string\]\$X64Host/);
  assert.match(matrixTest, /\$x86HostPath \$x64HostPath \$pluginRootPath/);
  assert.doesNotMatch(
    matrixTest,
    /cargo build[^\r\n]*webplus-plugin-host/,
  );

  assert.match(packageTest, /Capture-CandidateRuntimeHashes \$executable/);
  assert.match(packageTest, /Capture-CandidateRuntimeHashes \$candidateExecutable/);
  assert.match(packageTest, /\$pluginTrustStore = Join-Path[^\r\n]*plugin-trust\.json/);
  assert.match(packageTest, /\$originPolicy = Join-Path[^\r\n]*origin-policy\.json/);
  assert.match(packageTest, /Get-FileHash -LiteralPath \$pluginTrustStore/);
  assert.match(packageTest, /Get-FileHash -LiteralPath \$originPolicy/);
  assert.match(packageTest, /Get-FileHash -LiteralPath \$x86Host/);
  assert.match(packageTest, /Get-FileHash -LiteralPath \$x64Host/);
  assert.match(packageTest, /\$script:CandidatePluginTrustStoreSha256/);
  assert.match(packageTest, /\$script:CandidateOriginPolicySha256/);
  assert.match(packageTest, /\$script:CandidateX86HostSha256/);
  assert.match(packageTest, /\$script:CandidateX64HostSha256/);
  assert.equal(
    (
      cutoverEvidenceMain.match(
        /verify_manifest\(bundle_root, "metadata\/artifacts\.json"\)/g,
      ) ?? []
    ).length,
    2,
  );
  assert.equal(
    (
      cutoverEvidenceMain.match(
        /verify_manifest\(previous_bundle_root, "metadata\/artifacts\.json"\)/g,
      ) ?? []
    ).length,
    2,
  );
  assert.match(packageTest, /\[string\]\$DeploymentCheckRecord/);
  assert.match(packageTest, /DeploymentCheckRecord.*deep deployment-check JSON file/);
  assert.match(packageTest, /else \{ "none" \}/);
});
