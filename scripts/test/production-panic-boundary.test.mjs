import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const workspaceRoot = fileURLToPath(new URL("../../", import.meta.url));
const productionRoots = [
  "apps/desktop/src-tauri/src",
  "crates/webplus-controller/src",
  "crates/webplus-plugin-host/src",
  "crates/webplus-native/src",
];

async function rustFiles(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...await rustFiles(path));
    } else if (entry.isFile() && path.endsWith(".rs")) {
      files.push(path);
    }
  }
  return files;
}

function productionSource(source) {
  const testModule = source.search(
    /\n\s*#\[cfg\(test\)\]\s*\n\s*mod tests\s*\{/,
  );
  return testModule < 0 ? source : source.slice(0, testModule);
}

test("desktop and native production paths return errors instead of panicking", async () => {
  const files = (
    await Promise.all(
      productionRoots.map((root) => rustFiles(join(workspaceRoot, root))),
    )
  ).flat();
  assert.ok(files.length >= 10, "production Rust source set must remain covered");

  const prohibited = [
    /\.(?:unwrap|expect)\s*\(/,
    /\b(?:panic|unreachable|todo|unimplemented)!\s*\(/,
  ];
  for (const file of files) {
    const source = productionSource(await readFile(file, "utf8"));
    for (const pattern of prohibited) {
      assert.doesNotMatch(
        source,
        pattern,
        `${relative(workspaceRoot, file)} contains a direct production panic path`,
      );
    }
  }
});
