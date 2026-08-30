import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const deploymentCheckUrl = new URL(
  "../../apps/desktop/src-tauri/src/deployment_check.rs",
  import.meta.url,
);
const controlFrontendUrl = new URL(
  "../../apps/desktop/src/App.vue",
  import.meta.url,
);

test("quick checks cannot be presented as Windows delivery readiness", async () => {
  const [deploymentCheck, controlFrontend] = await Promise.all([
    readFile(deploymentCheckUrl, "utf8"),
    readFile(controlFrontendUrl, "utf8"),
  ]);

  assert.match(deploymentCheck, /deep_available: facts\.is_windows/);
  assert.match(
    deploymentCheck,
    /delivery_ready: facts\.is_windows && facts\.deep_preflight && ready/,
  );
  assert.match(controlFrontend, /if \(report\.deliveryReady\)/);
  assert.match(controlFrontend, /label: '待深度检查'/);
  assert.match(controlFrontend, /label: '开发预览'/);
  assert.match(controlFrontend, /进入项目交付/);
  assert.match(controlFrontend, /@click="runDeploymentCheck">/);
  assert.match(controlFrontend, /deploymentCheck\?\.deepAvailable === false/);
  assert.doesNotMatch(
    controlFrontend,
    /deploymentCheck \? deploymentCheck\.ready \? '可以交付'/,
  );
});
