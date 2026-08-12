import assert from "node:assert/strict";
import test from "node:test";
import { normalizeCycloneDx } from "../normalize-cyclonedx.mjs";

function fixture() {
  const localRef =
    "path+file:///build/ssdev/crates/example#example@1.2.3";
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    serialNumber: "urn:uuid:00000000-0000-0000-0000-000000000000",
    metadata: {
      timestamp: "2026-01-01T00:00:00Z",
      component: {
        type: "application",
        "bom-ref": localRef,
        name: "example",
        version: "1.2.3",
        purl: "pkg:cargo/example@1.2.3?download_url=file://.#src/main.rs",
      },
    },
    components: [
      {
        type: "library",
        "bom-ref": "pkg:cargo/serde@1.0.0",
        name: "serde",
        version: "1.0.0",
        purl: "pkg:cargo/serde@1.0.0",
      },
    ],
    dependencies: [
      { ref: localRef, dependsOn: ["pkg:cargo/serde@1.0.0"] },
      { ref: "pkg:cargo/serde@1.0.0", dependsOn: [] },
    ],
  };
}

test("removes volatile identity and canonicalizes local Cargo references", () => {
  const normalized = normalizeCycloneDx(fixture(), "/build/ssdev");

  assert.equal(normalized.serialNumber, undefined);
  assert.equal(normalized.metadata.timestamp, undefined);
  assert.equal(normalized.metadata.component["bom-ref"], "pkg:cargo/example@1.2.3");
  assert.equal(normalized.metadata.component.purl, "pkg:cargo/example@1.2.3");
  assert.equal(normalized.dependencies[0].ref, "pkg:cargo/example@1.2.3");
  assert.doesNotMatch(JSON.stringify(normalized), /file:|\/build\/ssdev/);
});

test("rejects duplicate canonical component identities", () => {
  const input = fixture();
  input.components.push({ ...input.components[0] });

  assert.throws(
    () => normalizeCycloneDx(input, "/build/ssdev"),
    /unique canonical bom-ref/,
  );
});

test("rejects unsupported or incomplete documents", () => {
  const input = fixture();
  input.specVersion = "1.4";
  assert.throws(() => normalizeCycloneDx(input, "/build/ssdev"), /CycloneDX 1.5/);

  const missingGraph = fixture();
  delete missingGraph.dependencies;
  assert.throws(() => normalizeCycloneDx(missingGraph, "/build/ssdev"), /dependency graph/);
});
