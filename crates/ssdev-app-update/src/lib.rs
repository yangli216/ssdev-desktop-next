use std::{fs, io::Read, path::Path};

use base64::Engine as _;
use minisign_verify::{PublicKey, Signature};
use serde::Deserialize;
use url::Url;

pub const MAX_POLICY_BYTES: u64 = 64 * 1024;
pub const DEFAULT_MAX_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;
pub const HARD_MAX_DOWNLOAD_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_ENDPOINTS: usize = 4;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppUpdatePolicy {
    pub schema_version: u8,
    pub enabled: bool,
    #[serde(default)]
    pub endpoints: Vec<Url>,
    #[serde(default)]
    pub pubkey: String,
    #[serde(default = "default_max_download_bytes")]
    pub max_download_bytes: u64,
}

impl AppUpdatePolicy {
    pub fn load(path: &Path) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| "无法读取应用更新策略文件（app-update-policy-read）".to_owned())?;
        if !metadata.is_file() || metadata.len() > MAX_POLICY_BYTES {
            return Err(format!(
                "应用更新策略必须是普通文件且不超过 {MAX_POLICY_BYTES} 字节"
            ));
        }
        let bytes = fs::read(path)
            .map_err(|_| "无法读取应用更新策略文件（app-update-policy-read）".to_owned())?;
        let policy: Self = serde_json::from_slice(&bytes)
            .map_err(|error| format!("应用更新策略不是有效 JSON: {error}"))?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err(format!("不支持应用更新策略版本 {}", self.schema_version));
        }
        if !(16 * 1024 * 1024..=HARD_MAX_DOWNLOAD_BYTES).contains(&self.max_download_bytes) {
            return Err(format!(
                "应用更新包上限必须在 16 MiB 到 {} MiB 之间",
                HARD_MAX_DOWNLOAD_BYTES / 1024 / 1024
            ));
        }
        if !self.enabled {
            if !self.endpoints.is_empty() || !self.pubkey.trim().is_empty() {
                return Err("关闭应用更新时不得保留端点或公钥".into());
            }
            return Ok(());
        }
        if self.endpoints.is_empty() || self.endpoints.len() > MAX_ENDPOINTS {
            return Err(format!(
                "启用应用更新时必须配置 1 到 {MAX_ENDPOINTS} 个端点"
            ));
        }
        for endpoint in &self.endpoints {
            require_https_url(endpoint, "应用更新端点")?;
        }
        decode_public_key(&self.pubkey)?;
        Ok(())
    }
}

pub fn default_max_download_bytes() -> u64 {
    DEFAULT_MAX_DOWNLOAD_BYTES
}

pub fn decode_public_key(encoded: &str) -> Result<PublicKey, String> {
    let decoded = decode_base64_text(encoded, "应用更新公钥")?;
    PublicKey::decode(&decoded).map_err(|error| format!("应用更新公钥无效: {error}"))
}

pub fn decode_signature(encoded: &str) -> Result<Signature, String> {
    let decoded = decode_base64_text(encoded, "应用更新签名")?;
    Signature::decode(&decoded).map_err(|error| format!("应用更新签名无效: {error}"))
}

pub fn verify_update_artifact_files(
    policy_path: &Path,
    package_path: &Path,
    signature_path: &Path,
) -> Result<u64, String> {
    let policy = AppUpdatePolicy::load(policy_path)?;
    if !policy.enabled {
        return Err("应用更新策略未启用".into());
    }
    let metadata =
        fs::metadata(package_path).map_err(|error| format!("无法读取更新产物元数据: {error}"))?;
    if !metadata.is_file() || metadata.len() > policy.max_download_bytes {
        return Err("更新产物不是普通文件或超过策略上限".into());
    }
    let signature_metadata =
        fs::metadata(signature_path).map_err(|error| format!("无法读取更新签名元数据: {error}"))?;
    if !signature_metadata.is_file() || signature_metadata.len() > 16 * 1024 {
        return Err("更新签名不是普通文件或超过安全上限".into());
    }
    let encoded_signature =
        fs::read_to_string(signature_path).map_err(|error| format!("无法读取更新签名: {error}"))?;
    let public_key = decode_public_key(&policy.pubkey)?;
    let signature = decode_signature(encoded_signature.trim())?;
    let mut verifier = public_key
        .verify_stream(&signature)
        .map_err(|error| format!("更新签名必须使用现代预哈希格式: {error}"))?;
    let mut package =
        fs::File::open(package_path).map_err(|error| format!("无法打开更新产物: {error}"))?;
    let mut buffer = [0_u8; 64 * 1024];
    let mut verified_bytes = 0_u64;
    loop {
        let read = package
            .read(&mut buffer)
            .map_err(|error| format!("无法读取更新产物: {error}"))?;
        if read == 0 {
            break;
        }
        verified_bytes = verified_bytes.saturating_add(read as u64);
        if verified_bytes > policy.max_download_bytes {
            return Err("更新产物在读取期间超过策略上限".into());
        }
        verifier.update(&buffer[..read]);
    }
    if verified_bytes != metadata.len() {
        return Err("更新产物在验证期间发生变化".into());
    }
    verifier
        .finalize()
        .map_err(|error| format!("更新产物签名验证失败: {error}"))?;
    Ok(verified_bytes)
}

pub fn require_https_url(url: &Url, label: &str) -> Result<(), String> {
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(format!("{label}必须是无凭据、无片段的 HTTPS URL"));
    }
    Ok(())
}

fn decode_base64_text(encoded: &str, label: &str) -> Result<String, String> {
    if encoded.trim().is_empty() || encoded.len() > 16 * 1024 {
        return Err(format!("{label}为空或过长"));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| format!("{label}不是有效 Base64: {error}"))?;
    String::from_utf8(bytes).map_err(|error| format!("{label}不是 UTF-8 文本: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use tempfile::tempdir;

    const PUBLIC_KEY: &str = "untrusted comment: minisign public key\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3\n";
    const SIGNATURE: &str = "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1633700835\tfile:test\tprehashed\nwLMDjy9FLAuxZ3q4NlEvkgtyhrr0gtTu6KC4KBJdITbbOeAi1zBIYo0v4iTgt8jJpIidRJnp94ABQkJAgAooBQ==\n";

    #[test]
    fn validates_enabled_and_disabled_policies() {
        let disabled = AppUpdatePolicy {
            schema_version: 1,
            enabled: false,
            endpoints: vec![],
            pubkey: String::new(),
            max_download_bytes: DEFAULT_MAX_DOWNLOAD_BYTES,
        };
        assert!(disabled.validate().is_ok());

        let enabled = AppUpdatePolicy {
            schema_version: 1,
            enabled: true,
            endpoints: vec![Url::parse("https://updates.example.test/latest.json").unwrap()],
            pubkey: BASE64.encode(PUBLIC_KEY),
            max_download_bytes: DEFAULT_MAX_DOWNLOAD_BYTES,
        };
        assert!(enabled.validate().is_ok());
    }

    #[test]
    fn verifies_tauri_minisign_artifact_and_rejects_tampering() {
        let directory = tempdir().unwrap();
        let policy_path = directory.path().join("app-update.json");
        let package_path = directory.path().join("update.nsis.zip");
        let signature_path = directory.path().join("update.nsis.zip.sig");
        fs::write(
            &policy_path,
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 1,
                "enabled": true,
                "endpoints": ["https://updates.example.test/latest.json"],
                "pubkey": BASE64.encode(PUBLIC_KEY),
                "maxDownloadBytes": DEFAULT_MAX_DOWNLOAD_BYTES
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(&package_path, b"test").unwrap();
        fs::write(&signature_path, BASE64.encode(SIGNATURE)).unwrap();

        assert_eq!(
            verify_update_artifact_files(&policy_path, &package_path, &signature_path).unwrap(),
            4
        );
        fs::write(&package_path, b"tampered").unwrap();
        assert!(
            verify_update_artifact_files(&policy_path, &package_path, &signature_path).is_err()
        );
    }

    #[test]
    fn policy_file_has_a_hard_size_limit() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("app-update.json");
        fs::write(&path, vec![b' '; MAX_POLICY_BYTES as usize + 1]).unwrap();
        assert!(AppUpdatePolicy::load(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn policy_rejects_symbolic_links() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let target = directory.path().join("target.json");
        let link = directory.path().join("app-update.json");
        fs::write(
            &target,
            br#"{"schemaVersion":1,"enabled":false,"endpoints":[],"pubkey":"","maxDownloadBytes":268435456}"#,
        )
        .unwrap();
        symlink(&target, &link).unwrap();
        assert!(AppUpdatePolicy::load(&link).is_err());
    }
}
