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
      -p ssdev-windows-system-example `
      -p webplus-protocol `
      --all-targets `
      --target $target `
      -- -D warnings
    cargo check --locked -p ssdev-process-policy --target $target
    cargo build --locked --release -p webplus-plugin-host --target $target
    cargo build --locked -p webplus-native-fixture --target $target
    cargo build --locked -p ssdev-windows-system-example --target $target

    $fixture = Join-Path $workspace "target/$target/debug/webplus_native_fixture.dll"
    cargo run --locked -p webplus-native --example dll_roundtrip --target $target -- $fixture
    cargo run --locked -p webplus-native --example com_roundtrip --target $target
    $systemExample = Join-Path $workspace "target/$target/debug/ssdev_windows_system_example.dll"
    $systemApi = if ($target -eq "i686-pc-windows-msvc") {
      Join-Path $workspace "examples/windows-system-plugin/api.x86.json"
    } else {
      Join-Path $workspace "examples/windows-system-plugin/api.x64.json"
    }
    cargo run --locked -p webplus-native --example windows_system_roundtrip --target $target -- $systemExample $systemApi

    $pluginHostPath = Join-Path $workspace "target/$target/release/webplus-plugin-host.exe"
    cargo run --locked -p webplus-controller --example host_roundtrip --target $target -- $pluginHostPath $fixture
  }

  ./scripts/test-plugin-matrix-ci.ps1 `
    -X86Host (Join-Path $workspace "target/i686-pc-windows-msvc/release/webplus-plugin-host.exe") `
    -X64Host (Join-Path $workspace "target/x86_64-pc-windows-msvc/release/webplus-plugin-host.exe")
} finally {
  Pop-Location
}
