#[cfg(windows)]
fn main() {
    use std::path::PathBuf;

    use serde_json::{json, Map};
    use webplus_native::NativePlugin;
    use webplus_plugin_config::PluginManifest;
    use webplus_protocol::{InvokeRequest, PluginArchitecture};

    let mut arguments = std::env::args_os().skip(1);
    let plugin_dir = PathBuf::from(
        arguments
            .next()
            .expect("usage: scaffold_roundtrip <release-source> <plugin-id>"),
    );
    let plugin_id = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .expect("plugin ID must be valid text");
    assert!(arguments.next().is_none(), "unexpected extra argument");

    let manifest = PluginManifest::load(&plugin_id, plugin_dir)
        .expect("failed to load generated plugin manifest");
    assert_eq!(manifest.services.len(), 1);
    let service_id = manifest.services[0].service_id.clone();
    let architecture = if cfg!(target_arch = "x86") {
        PluginArchitecture::X86
    } else {
        PluginArchitecture::X64
    };
    let mut plugin = NativePlugin::new(manifest);
    assert_eq!(plugin.preflight(architecture).unwrap(), 1);

    let response = plugin.invoke(&InvokeRequest {
        service_id,
        method: "echo".into(),
        parameters: Map::from_iter([("input".into(), json!("SSDEV_TEST"))]),
    });
    assert_eq!(response.res_code, 0, "{response:?}");
    assert_eq!(response.res_data["ReturnValue"], 0, "{response:?}");
    assert_eq!(response.res_data["value"], "SSDEV_TEST", "{response:?}");
    println!("generated DLL scaffold round-trip succeeded: {response:?}");
}

#[cfg(not(windows))]
fn main() {
    eprintln!("scaffold_roundtrip must run on Windows");
    std::process::exit(2);
}
