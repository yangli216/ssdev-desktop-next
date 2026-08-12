#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;

    use serde_json::{json, Map};
    use tempfile::tempdir;
    use webplus_native::NativePlugin;
    use webplus_plugin_config::PluginManifest;
    use webplus_protocol::InvokeRequest;

    let plugin_dir = tempdir()?;
    fs::write(
        plugin_dir.path().join("api.json"),
        serde_json::to_vec_pretty(&json!([{
            "serviceId": "fixture.dictionary",
            "mainClass": "Scripting.Dictionary",
            "mainType": "com",
            "cacheable": true,
            "methods": [
                {
                    "name": "Add",
                    "parameters": [
                        { "name": "key", "type": "string" },
                        "item"
                    ],
                    "props": ["Count"]
                },
                {
                    "name": "Exists",
                    "parameters": [{ "name": "key", "type": "string" }]
                }
            ]
        }]))?,
    )?;
    let manifest = PluginManifest::load("com-fixture", plugin_dir.path())?;
    let mut plugin = NativePlugin::new(manifest);

    let add = plugin.invoke(&InvokeRequest {
        service_id: "fixture.dictionary".into(),
        method: "Add".into(),
        parameters: Map::from_iter([("key".into(), json!("answer")), ("item".into(), json!(42))]),
    });
    assert_eq!(add.res_code, 0, "{add:?}");
    assert_eq!(add.res_data["Count"], 1);

    let exists = plugin.invoke(&InvokeRequest {
        service_id: "fixture.dictionary".into(),
        method: "Exists".into(),
        parameters: Map::from_iter([("key".into(), json!("answer"))]),
    });
    assert_eq!(exists.res_code, 0, "{exists:?}");
    assert_eq!(exists.res_data["ReturnValue"], true);
    println!("COM roundtrip succeeded: {exists:?}");
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("COM roundtrip is only available on Windows");
}
