import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

function cargoPurl(component) {
  if (!component?.name || !component?.version) {
    throw new Error("path-based CycloneDX components require a name and version");
  }
  return `pkg:cargo/${encodeURIComponent(component.name)}@${encodeURIComponent(component.version)}`;
}

function visit(value, callback) {
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      value[index] = visit(value[index], callback);
    }
    return value;
  }
  if (value && typeof value === "object") {
    for (const key of Object.keys(value)) {
      value[key] = visit(value[key], callback);
    }
    return value;
  }
  return callback(value);
}

export function normalizeCycloneDx(input, workspaceRoot) {
  const bom = structuredClone(input);
  if (bom.bomFormat !== "CycloneDX" || bom.specVersion !== "1.5" || bom.version !== 1) {
    throw new Error("only CycloneDX 1.5 version 1 documents are supported");
  }
  if (!bom.metadata?.component || !Array.isArray(bom.components) || !Array.isArray(bom.dependencies)) {
    throw new Error("CycloneDX document is missing its component or dependency graph");
  }

  delete bom.serialNumber;
  delete bom.metadata.timestamp;

  const replacements = new Map();
  for (const component of [bom.metadata.component, ...bom.components]) {
    const reference = component["bom-ref"];
    const purl = component.purl;
    const isLocal =
      reference?.startsWith("path+file:") ||
      purl?.includes("download_url=file:") ||
      purl?.includes("download_url=file%3A");
    if (isLocal) {
      const canonical = cargoPurl(component);
      if (reference) {
        replacements.set(reference, canonical);
      }
      component["bom-ref"] = canonical;
      component.purl = canonical;
    }
  }

  visit(bom, (value) => {
    if (typeof value === "string" && replacements.has(value)) {
      return replacements.get(value);
    }
    return value;
  });

  const componentReferences = new Set();
  for (const component of bom.components) {
    const reference = component["bom-ref"];
    if (!reference || componentReferences.has(reference)) {
      throw new Error("CycloneDX components must have unique canonical bom-ref values");
    }
    componentReferences.add(reference);
  }

  const serialized = JSON.stringify(bom);
  const workspaceVariants = [
    path.resolve(workspaceRoot),
    pathToFileURL(path.resolve(workspaceRoot)).href,
  ];
  if (
    serialized.includes("path+file:") ||
    serialized.includes("download_url=file") ||
    workspaceVariants.some((workspace) => serialized.includes(workspace))
  ) {
    throw new Error("normalized CycloneDX document still exposes a workspace path");
  }
  return bom;
}

function main() {
  const [inputPath, outputPath, workspaceRoot, ...extra] = process.argv.slice(2);
  if (!inputPath || !outputPath || !workspaceRoot || extra.length > 0) {
    throw new Error(
      "usage: node normalize-cyclonedx.mjs <input.json> <output.json> <workspace-root>",
    );
  }
  const input = JSON.parse(fs.readFileSync(inputPath, "utf8"));
  const normalized = normalizeCycloneDx(input, workspaceRoot);
  fs.writeFileSync(outputPath, `${JSON.stringify(normalized, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    console.error(`CycloneDX normalization failed: ${error.message}`);
    process.exitCode = 1;
  }
}
