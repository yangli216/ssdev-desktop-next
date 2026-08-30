use std::{fs, process::Command};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use tempfile::tempdir;

const PUBLIC_KEY: &str = "untrusted comment: minisign public key\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3\n";
const SIGNATURE: &str = "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1633700835\tfile:test\tprehashed\nwLMDjy9FLAuxZ3q4NlEvkgtyhrr0gtTu6KC4KBJdITbbOeAi1zBIYo0v4iTgt8jJpIidRJnp94ABQkJAgAooBQ==\n";

#[test]
fn update_verify_command_uses_the_shared_runtime_verifier() {
    let directory = tempdir().unwrap();
    let policy = directory.path().join("app-update.json");
    let artifact = directory.path().join("update.nsis.zip");
    let signature = directory.path().join("update.nsis.zip.sig");
    fs::write(
        &policy,
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "enabled": true,
            "endpoints": ["https://updates.example.test/latest.json"],
            "pubkey": BASE64.encode(PUBLIC_KEY),
            "maxDownloadBytes": 268435456
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(&artifact, b"test").unwrap();
    fs::write(&signature, BASE64.encode(SIGNATURE)).unwrap();

    let valid = Command::new(env!("CARGO_BIN_EXE_ssdev-release-manifest"))
        .arg("update-verify")
        .arg(&policy)
        .arg(&artifact)
        .arg(&signature)
        .output()
        .unwrap();
    assert!(valid.status.success());
    assert!(String::from_utf8(valid.stdout)
        .unwrap()
        .contains("verified for 4 bytes"));

    fs::write(&artifact, b"tampered").unwrap();
    let invalid = Command::new(env!("CARGO_BIN_EXE_ssdev-release-manifest"))
        .arg("update-verify")
        .arg(&policy)
        .arg(&artifact)
        .arg(&signature)
        .output()
        .unwrap();
    assert!(!invalid.status.success());
}
