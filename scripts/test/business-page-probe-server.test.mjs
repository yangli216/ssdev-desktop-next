import assert from "node:assert/strict";
import test from "node:test";

import { createBusinessPageProbeServer } from "../business-page-probe-server.mjs";

test("Windows business page probe is loopback-only, bounded, and inert", async () => {
  const server = createBusinessPageProbeServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const address = server.address();
    assert.equal(typeof address, "object");
    const response = await fetch(`http://127.0.0.1:${address.port}/`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-ssdev-business-probe"), "1");
    assert.equal(response.headers.get("cache-control"), "no-store");
    const page = await response.text();
    assert.match(page, /SSDEV Windows business page probe/);
    assert.doesNotMatch(page, /<script|7711|45121/i);

    const missing = await fetch(`http://127.0.0.1:${address.port}/missing`);
    assert.equal(missing.status, 404);
    const rejected = await fetch(`http://127.0.0.1:${address.port}/`, {
      method: "POST",
    });
    assert.equal(rejected.status, 405);
  } finally {
    await new Promise((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
});
