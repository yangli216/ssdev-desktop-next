use std::fs;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Map;
use webplus_controller::{PluginController, PluginTrust, SupervisorConfig};
use webplus_plugin_config::PluginManifest;
use webplus_protocol::InvokeRequest;

#[tokio::main]
async fn main() {
    let host = std::env::args_os()
        .nth(1)
        .expect("usage: host_roundtrip <plugin-host-executable>");
    let controller = Arc::new(
        PluginController::new(SupervisorConfig {
            x86_host: host.clone().into(),
            x64_host: host.into(),
            request_timeout: Duration::from_secs(5),
            max_in_flight_invocations: webplus_controller::DEFAULT_MAX_IN_FLIGHT_INVOCATIONS,
            plugin_trust: PluginTrust::AllowUnsigned,
        })
        .expect("invalid invocation admission configuration"),
    );
    let plugin_dir = tempfile::tempdir().expect("failed to create smoke plugin directory");
    fs::write(
        plugin_dir.path().join("api.json"),
        r#"{
          "serviceId": "smoke.service",
          "mainClass": "smoke.dll",
          "methods": [{"name": "probe"}]
        }"#,
    )
    .expect("failed to write smoke manifest");
    let manifest = PluginManifest::load("smoke-plugin", plugin_dir.path())
        .expect("failed to load smoke manifest");
    let maintenance = controller.begin_maintenance().await;
    maintenance
        .replace_manifests(std::slice::from_ref(&manifest))
        .await
        .expect("failed to register smoke manifest");
    let preflight = maintenance
        .preflight_manifest(&manifest)
        .await
        .expect("plugin host preflight failed");
    assert_eq!(preflight.hosts_started, 1);
    drop(maintenance);
    assert_eq!(controller.plugin_host_stats().active_hosts, 0);
    assert_eq!(controller.plugin_host_stats().successful_starts, 1);

    let mut calls = tokio::task::JoinSet::new();
    for _ in 0..webplus_controller::DEFAULT_MAX_IN_FLIGHT_INVOCATIONS {
        let controller = Arc::clone(&controller);
        calls.spawn(async move {
            controller
                .invoke(InvokeRequest {
                    service_id: "smoke.service".into(),
                    method: "probe".into(),
                    parameters: Map::new(),
                })
                .await
        });
    }
    while let Some(response) = calls.join_next().await {
        let response = response.expect("concurrent smoke call panicked");
        #[cfg(not(windows))]
        assert_eq!(response.res_code, -32004);
        #[cfg(windows)]
        assert_eq!(response.res_code, -32005);
    }
    let stats = controller.plugin_host_stats();
    assert_eq!(stats.active_hosts, 1);
    assert_eq!(stats.successful_starts, 2);
    assert_eq!(stats.failed_starts, 0);
    println!("plugin host single-flight round-trip succeeded: {stats:?}");
    controller.shutdown().await;
    assert_eq!(controller.plugin_host_stats().active_hosts, 0);
}
