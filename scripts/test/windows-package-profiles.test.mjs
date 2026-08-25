import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const buildScriptUrl = new URL("../build-windows.ps1", import.meta.url);
const packageTestUrl = new URL("../test-windows-package.ps1", import.meta.url);
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
    /packageProfile\.webviewInstallMode -ne \$ExpectedWebViewInstallMode/,
  );
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
  assert.doesNotMatch(packageTest, /Get-StartupEventCount/);
  assert.match(controlHtml, /SSDEV Desktop 正在启动/);
});
