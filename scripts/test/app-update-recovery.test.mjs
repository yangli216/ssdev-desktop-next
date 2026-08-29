import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const appUpdateUrl = new URL(
  "../../apps/desktop/src-tauri/src/app_update.rs",
  import.meta.url,
);
const controlFrontendUrl = new URL(
  "../../apps/desktop/src/App.vue",
  import.meta.url,
);

test("failed application update handoff preserves the current business workspace", async () => {
  const source = await readFile(appUpdateUrl, "utf8");
  const start = source.indexOf("pub(crate) async fn install_app_update(");
  const end = source.indexOf("\nfn app_update_capability_state_digest(", start);

  assert.notEqual(start, -1, "install_app_update must remain available");
  assert.notEqual(end, -1, "install_app_update boundary must remain detectable");

  const body = source.slice(start, end);
  const installingEvent = body.indexOf(".send(AppUpdateEvent::Installing)");
  const stopAccepting = body.indexOf("coordinator.stop_accepting().await");
  const installHandoff = body.indexOf("update.install(&bytes)");
  const resumeController = body.indexOf("controller.resume_after_shutdown().await");
  const resumeCoordinator = body.indexOf("coordinator.resume_after_shutdown()");

  assert.doesNotMatch(body, /close_business_windows/);
  assert.ok(installingEvent >= 0 && installingEvent < stopAccepting);
  assert.ok(stopAccepting < installHandoff);
  assert.ok(installHandoff < resumeController);
  assert.ok(installHandoff < resumeCoordinator);
  assert.match(body, /event_code = "app-update-install-handoff-failed"/);
  assert.match(body, /error_code = "updater-install"/);
  assert.match(body, /当前版本已恢复可用/);
});

test("control console clears the consumed update plan after a failed handoff", async () => {
  const source = await readFile(controlFrontendUrl, "utf8");
  const start = source.indexOf("async function installAppUpdate()");
  const end = source.indexOf("\nasync function exportDiagnostics()", start);

  assert.notEqual(start, -1, "installAppUpdate must remain available");
  assert.notEqual(end, -1, "installAppUpdate boundary must remain detectable");

  const body = source.slice(start, end);
  assert.match(body, /let installHandoffStarted = false/);
  assert.match(body, /installHandoffStarted = true/);
  assert.match(body, /const completed = await run\(/);
  assert.match(body, /if \(!completed\)/);
  assert.match(body, /appUpdate\.value\.installPlanId = undefined/);
  assert.match(body, /当前版本与业务窗口已恢复，请重新检查更新后重试/);
  assert.match(body, /await refreshRuntimeStatus\(\)/);
});
