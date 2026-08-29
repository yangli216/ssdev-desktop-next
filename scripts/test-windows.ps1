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
    cargo build --locked -p webplus-plugin-host --target $target
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

    $scaffoldParent = Join-Path ([System.IO.Path]::GetTempPath()) ("ssdev-plugin-scaffold-" + [Guid]::NewGuid().ToString("N"))
    $scaffold = Join-Path $scaffoldParent "echo-plugin"
    $scaffoldArchitecture = if ($target -eq "i686-pc-windows-msvc") { "x86" } else { "x64" }
    $scaffoldPluginId = "ci.echo-$scaffoldArchitecture"
    New-Item -ItemType Directory -Path $scaffoldParent | Out-Null
    try {
      cargo run --locked -p ssdev-plugin-tool -- init `
        --destination $scaffold `
        --plugin-id $scaffoldPluginId `
        --service-id "ci.echo" `
        --display-name "CI Echo" `
        --architecture $scaffoldArchitecture
      if ($LASTEXITCODE -ne 0) { throw "plugin scaffold generation failed with exit code $LASTEXITCODE" }
      & (Join-Path $scaffold "build.ps1")
      cargo run --locked -p webplus-native --example scaffold_roundtrip --target $target -- `
        (Join-Path $scaffold "release-source") $scaffoldPluginId
      if ($LASTEXITCODE -ne 0) { throw "generated plugin round-trip failed with exit code $LASTEXITCODE" }
    } finally {
      Remove-Item -LiteralPath $scaffoldParent -Recurse -Force
    }

    $pluginHostPath = Join-Path $workspace "target/$target/debug/webplus-plugin-host.exe"
    cargo run --locked -p webplus-controller --example host_roundtrip --target $target -- $pluginHostPath $fixture
  }
} finally {
  Pop-Location
}
