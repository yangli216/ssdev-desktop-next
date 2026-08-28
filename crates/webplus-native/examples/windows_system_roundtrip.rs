#[cfg(windows)]
fn main() {
    use std::fs;

    use serde_json::{json, Map, Value};
    use webplus_native::NativePlugin;
    use webplus_plugin_config::PluginManifest;
    use webplus_protocol::InvokeRequest;

    let mut arguments = std::env::args_os().skip(1);
    let dll = arguments
        .next()
        .expect("usage: windows_system_roundtrip <example.dll> <api.json>");
    let api = arguments
        .next()
        .expect("usage: windows_system_roundtrip <example.dll> <api.json>");
    let plugin_dir = tempfile::tempdir().expect("failed to create example plugin directory");
    fs::create_dir(plugin_dir.path().join("bin")).expect("failed to create bin directory");
    fs::copy(
        dll,
        plugin_dir
            .path()
            .join("bin/ssdev_windows_system_example.dll"),
    )
    .expect("failed to copy example DLL");
    fs::copy(api, plugin_dir.path().join("api.json")).expect("failed to copy example api.json");

    let manifest = PluginManifest::load("windows-system-example", plugin_dir.path())
        .expect("failed to load Windows system example");
    let mut plugin = NativePlugin::new(manifest);

    let invoke = |plugin: &mut NativePlugin, method: &str, parameters: Map<String, Value>| {
        let response = plugin.invoke(&InvokeRequest {
            service_id: "windows.system".into(),
            method: method.into(),
            parameters,
        });
        assert_eq!(response.res_code, 0, "{method}: {response:?}");
        response.res_data
    };

    let system = invoke(&mut plugin, "getSystemInfo", Map::new());
    assert_eq!(system["ReturnValue"], 0);
    let system_json: Value = serde_json::from_str(system["value"].as_str().unwrap()).unwrap();
    assert!(system_json["logicalProcessors"].as_u64().unwrap() >= 1);

    let memory = invoke(&mut plugin, "getMemoryStatus", Map::new());
    assert_eq!(memory["ReturnValue"], 0);
    let memory_json: Value = serde_json::from_str(memory["value"].as_str().unwrap()).unwrap();
    assert!(memory_json["totalPhysicalBytes"].as_u64().unwrap() > 0);

    let disk = invoke(
        &mut plugin,
        "getDiskSpace",
        Map::from_iter([("path".into(), json!(r"C:\"))]),
    );
    assert_eq!(disk["ReturnValue"], 0);
    let disk_json: Value = serde_json::from_str(disk["value"].as_str().unwrap()).unwrap();
    assert!(disk_json["totalBytes"].as_u64().unwrap() > 0);

    let process = invoke(&mut plugin, "getCurrentProcessId", Map::new());
    assert!(process["ReturnValue"].as_u64().unwrap() > 0);
    println!(
        "Windows system plugin round-trip succeeded: {system_json}; {memory_json}; {disk_json}"
    );
}

#[cfg(not(windows))]
fn main() {
    eprintln!("windows_system_roundtrip must run on Windows");
    std::process::exit(2);
}
