pub const APP_COMMANDS: &[&str] = &[
    "bridge_status",
    "retry_plugin_host",
    "run_deployment_check",
    "export_deployment_check",
    "export_project_bundle",
    "inspect_project_bundle",
    "import_project_bundle",
    "frontend_ready",
    "business_frontend_ready",
    "inspect_plugin_package",
    "install_plugin_package",
    "install_plugin_from_catalog",
    "inspect_signed_plugin_uninstall",
    "uninstall_signed_plugin",
    "check_plugin_updates",
    "inspect_plugin_reload",
    "reload_plugins",
    "plugin_inventory",
    "inspect_native_component",
    "discover_registered_com_components",
    "local_mapping_inventory",
    "save_local_mapping",
    "export_local_mapping",
    "export_local_mapping_typescript",
    "export_local_mapping_release_source",
    "inspect_local_mapping_import",
    "import_local_mapping",
    "inspect_local_mapping_removal",
    "delete_local_mapping",
    "debug_plugin_invoke",
    "save_local_mapping_debug_case",
    "delete_local_mapping_debug_case",
    "run_local_mapping_debug_cases",
    "plugin_invoke",
    "plugin_invoke_tracked",
    "plugin_invocation_status",
    "system_declaration",
    "desktop_config",
    "save_desktop_config",
    "inspect_desktop_config_import",
    "import_desktop_config",
    "export_desktop_config",
    "open_business_window",
    "open_external_url",
    "open_secondary_window",
    "show_floating_window",
    "close_floating_window",
    "resolve_floating_window",
    "clear_business_data",
    "reload_business_windows",
    "retry_timed_out_business_windows",
    "capture_business_window",
    "capture_region_snapshot",
    "complete_region_capture",
    "cancel_region_capture",
    "check_app_update",
    "install_app_update",
    "export_diagnostics",
    "open_diagnostics_directory",
];

pub const CONTROL_PERMISSIONS: &[&str] = &[
    "allow-bridge-status",
    "allow-retry-plugin-host",
    "allow-run-deployment-check",
    "allow-export-deployment-check",
    "allow-export-project-bundle",
    "allow-inspect-project-bundle",
    "allow-import-project-bundle",
    "allow-frontend-ready",
    "allow-inspect-plugin-package",
    "allow-install-plugin-package",
    "allow-install-plugin-from-catalog",
    "allow-inspect-signed-plugin-uninstall",
    "allow-uninstall-signed-plugin",
    "allow-check-plugin-updates",
    "allow-inspect-plugin-reload",
    "allow-reload-plugins",
    "allow-plugin-inventory",
    "allow-inspect-native-component",
    "allow-discover-registered-com-components",
    "allow-local-mapping-inventory",
    "allow-save-local-mapping",
    "allow-export-local-mapping",
    "allow-export-local-mapping-typescript",
    "allow-export-local-mapping-release-source",
    "allow-inspect-local-mapping-import",
    "allow-import-local-mapping",
    "allow-inspect-local-mapping-removal",
    "allow-delete-local-mapping",
    "allow-debug-plugin-invoke",
    "allow-save-local-mapping-debug-case",
    "allow-delete-local-mapping-debug-case",
    "allow-run-local-mapping-debug-cases",
    "allow-desktop-config",
    "allow-save-desktop-config",
    "allow-inspect-desktop-config-import",
    "allow-import-desktop-config",
    "allow-export-desktop-config",
    "allow-open-business-window",
    "allow-clear-business-data",
    "allow-reload-business-windows",
    "allow-retry-timed-out-business-windows",
    "allow-check-app-update",
    "allow-install-app-update",
    "allow-export-diagnostics",
    "allow-open-diagnostics-directory",
];

pub const BUSINESS_PERMISSIONS: &[&str] = &[
    "allow-business-frontend-ready",
    "allow-plugin-invoke",
    "allow-plugin-invoke-tracked",
    "allow-plugin-invocation-status",
    "allow-system-declaration",
    "allow-capture-business-window",
    "allow-open-external-url",
    "allow-open-secondary-window",
    "allow-show-floating-window",
    "allow-close-floating-window",
];

pub const FLOATING_PERMISSIONS: &[&str] = &[
    "allow-close-floating-window",
    "allow-resolve-floating-window",
];

pub const CAPTURE_PERMISSIONS: &[&str] = &[
    "allow-capture-region-snapshot",
    "allow-complete-region-capture",
    "allow-cancel-region-capture",
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn every_permission_names_a_declared_command() {
        let commands = APP_COMMANDS.iter().copied().collect::<BTreeSet<_>>();
        let permissions = CONTROL_PERMISSIONS
            .iter()
            .chain(BUSINESS_PERMISSIONS)
            .chain(FLOATING_PERMISSIONS)
            .chain(CAPTURE_PERMISSIONS);
        for permission in permissions {
            let command = permission
                .strip_prefix("allow-")
                .expect("runtime permissions must only grant commands")
                .replace('-', "_");
            assert!(commands.contains(command.as_str()), "unknown {permission}");
        }
    }

    #[test]
    fn remote_business_permissions_do_not_include_control_commands() {
        let business = BUSINESS_PERMISSIONS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        for forbidden in [
            "allow-desktop-config",
            "allow-run-deployment-check",
            "allow-retry-plugin-host",
            "allow-export-deployment-check",
            "allow-export-project-bundle",
            "allow-inspect-project-bundle",
            "allow-import-project-bundle",
            "allow-save-desktop-config",
            "allow-inspect-desktop-config-import",
            "allow-inspect-plugin-package",
            "allow-install-plugin-package",
            "allow-install-plugin-from-catalog",
            "allow-inspect-signed-plugin-uninstall",
            "allow-uninstall-signed-plugin",
            "allow-check-plugin-updates",
            "allow-inspect-plugin-reload",
            "allow-import-desktop-config",
            "allow-export-desktop-config",
            "allow-inspect-native-component",
            "allow-discover-registered-com-components",
            "allow-local-mapping-inventory",
            "allow-save-local-mapping",
            "allow-export-local-mapping",
            "allow-export-local-mapping-typescript",
            "allow-export-local-mapping-release-source",
            "allow-inspect-local-mapping-import",
            "allow-import-local-mapping",
            "allow-delete-local-mapping",
            "allow-debug-plugin-invoke",
            "allow-save-local-mapping-debug-case",
            "allow-delete-local-mapping-debug-case",
            "allow-run-local-mapping-debug-cases",
            "allow-retry-timed-out-business-windows",
            "allow-install-app-update",
            "allow-export-diagnostics",
            "allow-open-diagnostics-directory",
        ] {
            assert!(
                !business.contains(forbidden),
                "business ACL contains {forbidden}"
            );
        }
    }

    #[test]
    fn bundled_capabilities_match_their_declared_command_sets() {
        fn app_permissions(document: &str) -> BTreeSet<String> {
            serde_json::from_str::<serde_json::Value>(document)
                .expect("capability must be valid JSON")["permissions"]
                .as_array()
                .expect("capability permissions must be an array")
                .iter()
                .filter_map(|permission| permission.as_str())
                .filter(|permission| permission.starts_with("allow-") && !permission.contains(':'))
                .map(str::to_owned)
                .collect()
        }

        assert_eq!(
            app_permissions(include_str!("../capabilities/local-shell.json")),
            CONTROL_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect()
        );
        assert_eq!(
            app_permissions(include_str!("../capabilities/capture-overlay.json")),
            CAPTURE_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect()
        );
    }

    #[test]
    fn bundled_pages_keep_a_restrictive_content_security_policy() {
        const PRODUCTION_CSP: &str = "default-src 'self'; connect-src ipc: http://ipc.localhost; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'; frame-ancestors 'none'; worker-src 'none'; media-src 'none'";
        const DEVELOPMENT_CSP: &str = "default-src 'self'; connect-src ipc: http://ipc.localhost ws://127.0.0.1:1420; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'; frame-ancestors 'none'; worker-src 'none'; media-src 'none'";

        let config = serde_json::from_str::<serde_json::Value>(include_str!("../tauri.conf.json"))
            .expect("Tauri config must be valid JSON");
        let security = &config["app"]["security"];

        assert_eq!(security["csp"].as_str(), Some(PRODUCTION_CSP));
        assert_eq!(security["devCsp"].as_str(), Some(DEVELOPMENT_CSP));
        assert_eq!(security["freezePrototype"].as_bool(), Some(true));
        assert!(!PRODUCTION_CSP.contains("unsafe-eval"));
        assert!(!PRODUCTION_CSP.contains("https:"));
        assert!(!PRODUCTION_CSP.contains("ws:"));
    }

    #[test]
    fn bundled_runtime_resources_match_the_paths_used_by_the_desktop() {
        let config = serde_json::from_str::<serde_json::Value>(include_str!("../tauri.conf.json"))
            .expect("Tauri config must be valid JSON");
        let resources = config["bundle"]["resources"]
            .as_object()
            .expect("bundle.resources must use explicit destination mappings");

        assert_eq!(
            resources
                .get("resources/*.json")
                .and_then(serde_json::Value::as_str),
            Some("")
        );
        assert_eq!(
            resources
                .get("resources/windows/")
                .and_then(serde_json::Value::as_str),
            Some("windows/")
        );
    }
}
