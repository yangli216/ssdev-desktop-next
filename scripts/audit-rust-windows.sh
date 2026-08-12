#!/usr/bin/env bash
set -euo pipefail

required_version="0.22.2"
actual_version="$(cargo audit --version)"
if [[ "$actual_version" != *" $required_version" ]]; then
  echo "Expected cargo-audit version [$required_version], found [$actual_version]." >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to evaluate target-specific RustSec warnings." >&2
  exit 1
fi

# cargo-audit fails here for vulnerabilities. Its warning classes are evaluated
# separately because Cargo.lock contains Linux-only Tauri dependencies even for
# a Windows release.
cargo audit

report="$(mktemp)"
trap 'rm -f "$report"' EXIT
cargo audit --json --no-fetch >"$report"

failure=0
while IFS=$'\t' read -r kind crate version advisory; do
  [[ -z "$crate" ]] && continue
  for target in x86_64-pc-windows-msvc i686-pc-windows-msvc; do
    tree="$(mktemp)"
    if cargo tree --locked --target "$target" -i "$crate@$version" >"$tree" 2>&1; then
      echo "RustSec $kind warning $advisory reaches Windows target $target through $crate@$version:" >&2
      cat "$tree" >&2
      failure=1
    elif ! grep -Fq "did not match any packages" "$tree"; then
      echo "Could not prove whether $crate@$version is absent from Windows target $target:" >&2
      cat "$tree" >&2
      failure=1
    fi
    rm -f "$tree"
  done
done < <(
  jq -r '
    .warnings
    | to_entries[]
    | .key as $kind
    | .value[]
    | [$kind, .package.name, .package.version, .advisory.id]
    | @tsv
  ' "$report"
)

if [[ "$failure" -ne 0 ]]; then
  echo "A RustSec warning is reachable from a production Windows dependency graph." >&2
  exit 1
fi

echo "PASS: no RustSec vulnerabilities and no warned crates in either production Windows dependency graph."
