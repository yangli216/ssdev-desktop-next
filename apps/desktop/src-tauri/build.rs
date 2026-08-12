#[path = "src/command_permissions.rs"]
#[allow(dead_code)]
// This build target only consumes APP_COMMANDS; runtime and contract tests consume the subsets.
mod command_permissions;

fn main() {
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(command_permissions::APP_COMMANDS));
    tauri_build::try_build(attributes).expect("failed to build Tauri application metadata");
}
