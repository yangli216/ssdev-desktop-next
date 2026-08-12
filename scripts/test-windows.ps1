$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
$targets = @("i686-pc-windows-msvc", "x86_64-pc-windows-msvc")

Push-Location $workspace
try {
  foreach ($target in $targets) {
    rustup target add $target
  }

  cargo fmt --all --check
  cargo test --workspace --all-targets --locked
  cargo clippy --workspace --all-targets --locked -- -D warnings

  foreach ($target in $targets) {
    cargo clippy --locked `
      -p ssdev-process-policy `
      -p ssdev-cutover-evidence `
      -p ssdev-release-manifest `
      -p ssdev-release-signing `
      -p webplus-ipc `
      -p webplus-native `
      -p webplus-plugin-host `
      -p webplus-native-fixture `
      -p webplus-plugin-config `
      -p webplus-plugin-package `
      -p webplus-plugin-trust `
      -p ssdev-plugin-tool `
      -p webplus-protocol `
      --all-targets `
      --target $target `
      -- -D warnings
    cargo check --locked -p ssdev-process-policy --target $target
    cargo build --locked -p webplus-plugin-host --target $target
    cargo build --locked -p webplus-native-fixture --target $target

    $fixture = Join-Path $workspace "target/$target/debug/webplus_native_fixture.dll"
    cargo run --locked -p webplus-native --example dll_roundtrip --target $target -- $fixture
    cargo run --locked -p webplus-native --example com_roundtrip --target $target

    $pluginHostPath = Join-Path $workspace "target/$target/debug/webplus-plugin-host.exe"
    cargo run --locked -p webplus-controller --example host_roundtrip --target $target -- $pluginHostPath
  }
} finally {
  Pop-Location
}
