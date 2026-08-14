import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const buildScriptUrl = new URL("../build-windows.ps1", import.meta.url);
const packageTestUrl = new URL("../test-windows-package.ps1", import.meta.url);
const workflowUrl = new URL("../../.github/workflows/ci.yml", import.meta.url);

test("Windows build exposes only the supported installer and WebView2 profiles", async () => {
  const script = await readFile(buildScriptUrl, "utf8");

  assert.match(script, /ValidateSet\("Both", "Nsis", "Msi"\)/);
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
  assert.match(script, /packageProfile\.installerKind -ne \$InstallerKind/);
  assert.match(
    script,
    /packageProfile\.webviewInstallMode -ne \$ExpectedWebViewInstallMode/,
  );
});

test("CI publishes offline NSIS and MSI separately from online-light NSIS", async () => {
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
  assert.match(
    workflow.slice(onlineBuild, onlineUpload),
    /-InstallerKind Nsis/,
  );
  assert.match(
    workflow.slice(onlineBuild, onlineUpload),
    /-ExpectedWebViewInstallMode DownloadBootstrapper/,
  );
});
