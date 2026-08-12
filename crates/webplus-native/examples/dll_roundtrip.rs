#[cfg(windows)]
fn main() {
    use std::fs;

    use serde_json::{json, Map};
    use webplus_native::NativePlugin;
    use webplus_plugin_config::PluginManifest;
    use webplus_protocol::InvokeRequest;

    let source = std::env::args_os()
        .nth(1)
        .expect("usage: dll_roundtrip <webplus_native_fixture.dll>");
    let plugin_dir = tempfile::tempdir().expect("failed to create fixture plugin directory");
    fs::copy(source, plugin_dir.path().join("fixture.dll")).expect("failed to copy fixture DLL");
    fs::write(
        plugin_dir.path().join("api.json"),
        serde_json::to_vec_pretty(&json!({
            "serviceId": "fixture.math",
            "mainClass": "fixture.dll",
            "mainType": "dll",
            "arch": if cfg!(target_arch = "x86") { "x86" } else { "x64" },
            "callingConvention": "cdecl",
            "methods": [
                {
                    "name": "Add",
                    "returnType": "int",
                    "parameters": [
                        {"name": "left", "type": "int32"},
                        {"name": "right", "type": "int32"}
                    ]
                },
                {
                    "name": "FillBuffer",
                    "returnType": "int",
                    "parameters": [
                        {"name": "$value", "type": "string", "len": 16}
                    ]
                }
            ]
        }))
        .unwrap(),
    )
    .expect("failed to write fixture manifest");

    let manifest = PluginManifest::load("native-fixture", plugin_dir.path())
        .expect("failed to load fixture manifest");
    let mut plugin = NativePlugin::new(manifest);
    let add = plugin.invoke(&InvokeRequest {
        service_id: "fixture.math".into(),
        method: "Add".into(),
        parameters: Map::from_iter([("left".into(), json!(19)), ("right".into(), json!(23))]),
    });
    assert_eq!(add.res_code, 0);
    assert_eq!(add.res_data["ReturnValue"], 42);

    let fill = plugin.invoke(&InvokeRequest {
        service_id: "fixture.math".into(),
        method: "FillBuffer".into(),
        parameters: Map::new(),
    });
    assert_eq!(fill.res_code, 0);
    assert_eq!(fill.res_data["value"], "fixture-ok");
    println!("native DLL round-trip succeeded: {add:?}; {fill:?}");
}

#[cfg(not(windows))]
fn main() {
    eprintln!("dll_roundtrip must run on Windows");
    std::process::exit(2);
}
