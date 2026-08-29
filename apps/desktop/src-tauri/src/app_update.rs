use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine as _;
use minisign_verify::{PublicKey, Signature};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::ipc::Channel;
use tauri::{AppHandle, State, WebviewWindow};
use tauri_plugin_updater::{Update, UpdaterExt};
use tempfile::{Builder as TempBuilder, NamedTempFile};
use tokio::io::AsyncWriteExt;

const POLICY_FILENAME: &str = "app-update.json";
const MAX_POLICY_BYTES: u64 = 64 * 1024;
const DEFAULT_MAX_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;
const HARD_MAX_DOWNLOAD_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ENDPOINTS: usize = 4;
const MAX_NOTES_CHARS: usize = 4096;

pub(crate) struct AppUpdateState {
    policy: Option<AppUpdatePolicy>,
    policy_error: Option<String>,
    pending: Mutex<Option<Update>>,
    client: Client,
    temporary_directory: PathBuf,
}

impl AppUpdateState {
    pub(crate) fn load(resource_dir: &Path, local_data_dir: &Path, client: Client) -> Self {
        let path = resource_dir.join(POLICY_FILENAME);
        match AppUpdatePolicy::load(&path) {
            Ok(policy) => Self {
                policy: policy.enabled.then_some(policy),
                policy_error: None,
                pending: Mutex::new(None),
                client,
                temporary_directory: local_data_dir.join("updates"),
            },
            Err(error) => Self {
                policy: None,
                policy_error: Some(error),
                pending: Mutex::new(None),
                client,
                temporary_directory: local_data_dir.join("updates"),
            },
        }
    }

    pub(crate) fn status(&self) -> AppUpdateStatus {
        AppUpdateStatus {
            configured: self.policy.is_some(),
            error: self.policy_error.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AppUpdatePolicy {
    schema_version: u8,
    enabled: bool,
    #[serde(default)]
    endpoints: Vec<Url>,
    #[serde(default)]
    pubkey: String,
    #[serde(default = "default_max_download_bytes")]
    max_download_bytes: u64,
}

impl AppUpdatePolicy {
    fn load(path: &Path) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("无法读取应用更新策略 {path:?}: {error}"))?;
        if !metadata.is_file() || metadata.len() > MAX_POLICY_BYTES {
            return Err(format!(
                "应用更新策略必须是普通文件且不超过 {MAX_POLICY_BYTES} 字节"
            ));
        }
        let bytes =
            fs::read(path).map_err(|error| format!("无法读取应用更新策略 {path:?}: {error}"))?;
        let policy: Self = serde_json::from_slice(&bytes)
            .map_err(|error| format!("应用更新策略不是有效 JSON: {error}"))?;
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<(), String> {
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

fn default_max_download_bytes() -> u64 {
    DEFAULT_MAX_DOWNLOAD_BYTES
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AppUpdateStatus {
    pub(crate) configured: bool,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AppUpdateCheck {
    configured: bool,
    current_version: String,
    available: bool,
    compatible: bool,
    capability_blockers: usize,
    install_plan_id: Option<String>,
    version: Option<String>,
    date: Option<String>,
    notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppUpdatePlanMetadata {
    current_version: String,
    version: String,
    date: Option<String>,
    target: String,
    download_url: String,
    signature: String,
    notes: Option<String>,
}

impl AppUpdatePlanMetadata {
    fn from_update(update: &Update) -> Self {
        Self {
            current_version: update.current_version.clone(),
            version: update.version.clone(),
            date: update.date.map(|date| date.to_string()),
            target: update.target.clone(),
            download_url: update.download_url.to_string(),
            signature: update.signature.clone(),
            notes: update.body.as_deref().map(truncate_notes),
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(tag = "event", content = "data", rename_all = "camelCase")]
pub(crate) enum AppUpdateEvent {
    Started {
        content_length: Option<u64>,
        max_download_bytes: u64,
    },
    Progress {
        downloaded_bytes: u64,
    },
    Verified,
    Installing,
}

#[tauri::command]
pub(crate) async fn check_app_update(
    caller: WebviewWindow,
    app: AppHandle,
    bridge: State<'_, crate::BridgeState>,
    state: State<'_, AppUpdateState>,
) -> Result<AppUpdateCheck, String> {
    crate::desktop::require_control(&caller)?;
    *state
        .pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    let current_version = app.package_info().version.to_string();
    let Some(policy) = state.policy.as_ref() else {
        return match &state.policy_error {
            Some(error) => Err(error.clone()),
            None => Ok(AppUpdateCheck {
                configured: false,
                current_version,
                available: false,
                compatible: true,
                capability_blockers: 0,
                install_plan_id: None,
                version: None,
                date: None,
                notes: None,
            }),
        };
    };
    let updater = app
        .updater_builder()
        .pubkey(policy.pubkey.clone())
        .endpoints(policy.endpoints.clone())
        .map_err(|error| error.to_string())?
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| error.to_string())?;
    let update = updater.check().await.map_err(|error| error.to_string())?;
    let Some(update) = update else {
        *state
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        tracing::info!(
            event_code = "app-update-checked",
            available = false,
            "application update check completed"
        );
        return Ok(AppUpdateCheck {
            configured: true,
            current_version,
            available: false,
            compatible: true,
            capability_blockers: 0,
            install_plan_id: None,
            version: None,
            date: None,
            notes: None,
        });
    };
    require_https_url(&update.download_url, "应用更新包地址")?;
    let target_version = semver::Version::parse(&update.version)
        .map_err(|error| format!("更新版本不是合法 SemVer: {error}"))?;
    let _install = bridge.install_lock.lock().await;
    crate::recover_plugin_store(&bridge)?;
    let inspected = crate::inspect_all_plugins(
        &bridge.plugin_root,
        &bridge.local_mapping_root,
        bridge.trust_store.as_deref(),
        &target_version,
    )?;
    let api_baseline_blocked =
        crate::validate_signed_plugin_api_baseline(&bridge, &inspected.manifests).is_err();
    let capability_blockers = inspected.failures.len() + usize::from(api_baseline_blocked);
    let install_plan_id = if capability_blockers == 0 {
        let capability_state_sha256 =
            app_update_capability_state_digest(&inspected.manifests, &bridge.local_mapping_root)?;
        Some(app_update_plan_id(
            &AppUpdatePlanMetadata::from_update(&update),
            &capability_state_sha256,
        )?)
    } else {
        None
    };
    let metadata = AppUpdateCheck {
        configured: true,
        current_version: update.current_version.clone(),
        available: true,
        compatible: capability_blockers == 0,
        capability_blockers,
        install_plan_id,
        version: Some(update.version.clone()),
        date: update.date.map(|date| date.to_string()),
        notes: update.body.as_deref().map(truncate_notes),
    };
    *state
        .pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(update);
    tracing::info!(
        event_code = "app-update-checked",
        available = true,
        version = metadata.version.as_deref().unwrap_or("unknown"),
        "application update check completed"
    );
    Ok(metadata)
}

#[tauri::command]
pub(crate) async fn install_app_update(
    caller: WebviewWindow,
    app: AppHandle,
    bridge: State<'_, crate::BridgeState>,
    state: State<'_, AppUpdateState>,
    expected_plan_id: String,
    on_event: Channel<AppUpdateEvent>,
) -> Result<(), String> {
    crate::desktop::require_control(&caller)?;
    if !crate::is_lowercase_sha256(&expected_plan_id) {
        return Err("应用更新确认标识无效，请重新检查更新".to_owned());
    }
    let _install = bridge.install_lock.lock().await;
    crate::recover_plugin_store(&bridge)?;
    let policy = state
        .policy
        .clone()
        .ok_or_else(|| "尚未配置生产应用更新策略".to_owned())?;
    let pending_update = {
        let pending = state
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        pending
            .as_ref()
            .cloned()
            .ok_or_else(|| "没有待安装更新，请先检查更新".to_owned())?
    };
    let target_version = semver::Version::parse(&pending_update.version)
        .map_err(|error| format!("更新版本不是合法 SemVer: {error}"))?;
    let inspected = crate::inspect_all_plugins(
        &bridge.plugin_root,
        &bridge.local_mapping_root,
        bridge.trust_store.as_deref(),
        &target_version,
    )?;
    let api_baseline_blocked =
        crate::validate_signed_plugin_api_baseline(&bridge, &inspected.manifests).is_err();
    let capability_blockers = inspected.failures.len() + usize::from(api_baseline_blocked);
    if capability_blockers > 0 {
        return Err(format!(
            "有 {capability_blockers} 个插件或本地映射未声明支持 SSDEV Desktop {target_version}，或未通过完整性检查；请先修复对应能力"
        ));
    }
    let expected_capability_state_sha256 =
        app_update_capability_state_digest(&inspected.manifests, &bridge.local_mapping_root)?;
    let actual_plan_id = app_update_plan_id(
        &AppUpdatePlanMetadata::from_update(&pending_update),
        &expected_capability_state_sha256,
    )?;
    ensure_app_update_plan_matches(&expected_plan_id, &actual_plan_id)?;
    let update = state
        .pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
        .ok_or_else(|| "待安装更新状态发生变化，请重新检查更新".to_owned())?;
    let package = download_and_verify(
        &state.client,
        &update,
        &policy,
        &state.temporary_directory,
        &on_event,
    )
    .await?;
    on_event
        .send(AppUpdateEvent::Verified)
        .map_err(|error| error.to_string())?;
    let bytes = read_verified_package(package, policy.max_download_bytes)
        .await
        .map_err(|error| format!("无法读取已验签更新包: {error}"))?;
    let current_plugins = crate::inspect_all_plugins(
        &bridge.plugin_root,
        &bridge.local_mapping_root,
        bridge.trust_store.as_deref(),
        &target_version,
    )?;
    crate::validate_signed_plugin_api_baseline(&bridge, &current_plugins.manifests)?;
    if !current_plugins.failures.is_empty() {
        return Err(
            "下载期间插件或本地映射的兼容性、完整性发生变化，请重新检查应用更新".to_owned(),
        );
    }
    let current_capability_state_sha256 =
        app_update_capability_state_digest(&current_plugins.manifests, &bridge.local_mapping_root)?;
    if current_capability_state_sha256 != expected_capability_state_sha256 {
        return Err("下载期间插件或本地映射集合发生变化，请重新检查应用更新".to_owned());
    }
    tracing::info!(
        event_code = "app-update-verified",
        version = %update.version,
        package_bytes = bytes.len(),
        "application update signature verified"
    );
    on_event
        .send(AppUpdateEvent::Installing)
        .map_err(|error| error.to_string())?;
    if let Some(coordinator) = &bridge.invocation_coordinator {
        coordinator.stop_accepting().await;
    }
    bridge.controller.shutdown().await;
    if let Some(coordinator) = &bridge.invocation_coordinator {
        coordinator.drain().await;
    }
    if let Err(error) = update.install(&bytes) {
        bridge.controller.resume_after_shutdown().await;
        if let Some(coordinator) = &bridge.invocation_coordinator {
            coordinator.resume_after_shutdown();
        }
        tracing::warn!(
            event_code = "app-update-install-handoff-failed",
            error_code = "updater-install",
            "application update install handoff failed; current runtime resumed"
        );
        return Err(format!("无法启动系统安装程序，当前版本已恢复可用: {error}"));
    }
    crate::desktop::mark_exit_ready(&app);
    app.restart();
}

fn app_update_capability_state_digest(
    manifests: &[webplus_plugin_config::PluginManifest],
    local_mapping_root: &Path,
) -> Result<String, String> {
    let mut hasher = Sha256::new();
    hasher.update(b"SSDEV-APP-UPDATE-CAPABILITY-STATE\0");
    crate::hash_complete_plugin_state(&mut hasher, manifests, local_mapping_root)?;
    Ok(crate::lowercase_hex(&hasher.finalize()))
}

fn app_update_plan_id(
    metadata: &AppUpdatePlanMetadata,
    capability_state_sha256: &str,
) -> Result<String, String> {
    let metadata = serde_json::to_vec(metadata)
        .map_err(|error| format!("无法生成应用更新确认标识: {error}"))?;
    let mut hasher = Sha256::new();
    hasher.update(b"SSDEV-APP-UPDATE-PLAN\0");
    crate::hash_plan_field(&mut hasher, &metadata);
    crate::hash_plan_field(&mut hasher, capability_state_sha256.as_bytes());
    Ok(crate::lowercase_hex(&hasher.finalize()))
}

fn ensure_app_update_plan_matches(expected: &str, actual: &str) -> Result<(), String> {
    if expected != actual {
        return Err("待安装应用版本或当前插件集合在确认后发生变化，请重新检查应用更新".to_owned());
    }
    Ok(())
}

async fn read_verified_package(
    mut package: NamedTempFile,
    max_download_bytes: u64,
) -> Result<Vec<u8>, String> {
    tokio::task::spawn_blocking(move || {
        let actual = package
            .as_file()
            .metadata()
            .map_err(|error| error.to_string())?
            .len();
        if actual > max_download_bytes || actual > usize::MAX as u64 {
            return Err("已验签更新包超过内存安装上限".into());
        }
        let mut bytes = Vec::with_capacity(actual as usize);
        let file = package.as_file_mut();
        file.seek(SeekFrom::Start(0))
            .map_err(|error| error.to_string())?;
        file.read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() as u64 != actual {
            return Err("读取后的更新包大小发生变化".into());
        }
        Ok(bytes)
    })
    .await
    .map_err(|error| format!("更新包读取任务异常终止: {error}"))?
}

async fn download_and_verify(
    client: &Client,
    update: &Update,
    policy: &AppUpdatePolicy,
    temporary_directory: &Path,
    on_event: &Channel<AppUpdateEvent>,
) -> Result<NamedTempFile, String> {
    require_https_url(&update.download_url, "应用更新包地址")?;
    fs::create_dir_all(temporary_directory)
        .map_err(|error| format!("无法创建应用更新临时目录: {error}"))?;
    let file = TempBuilder::new()
        .prefix(".app-update-")
        .tempfile_in(temporary_directory)
        .map_err(|error| format!("无法创建应用更新临时文件: {error}"))?;
    let write_handle = file
        .reopen()
        .map_err(|error| format!("无法打开应用更新临时文件: {error}"))?;
    let mut output = tokio::fs::File::from_std(write_handle);
    let public_key = decode_public_key(&policy.pubkey)?;
    let signature = decode_signature(&update.signature)?;
    let mut verifier = public_key
        .verify_stream(&signature)
        .map_err(|error| format!("更新签名必须使用现代预哈希格式: {error}"))?;
    let mut response = client
        .get(update.download_url.clone())
        .send()
        .await
        .map_err(|error| format!("下载应用更新失败: {error}"))?
        .error_for_status()
        .map_err(|error| format!("应用更新服务器返回错误: {error}"))?;
    let content_length = response.content_length();
    if content_length.is_some_and(|length| length > policy.max_download_bytes) {
        return Err(format!(
            "应用更新包超过 {} MiB 安全上限",
            policy.max_download_bytes / 1024 / 1024
        ));
    }
    on_event
        .send(AppUpdateEvent::Started {
            content_length,
            max_download_bytes: policy.max_download_bytes,
        })
        .map_err(|error| error.to_string())?;
    let mut downloaded = 0_u64;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("读取应用更新数据失败: {error}"))?
    {
        downloaded = downloaded.saturating_add(chunk.len() as u64);
        if downloaded > policy.max_download_bytes {
            return Err(format!(
                "应用更新包超过 {} MiB 安全上限",
                policy.max_download_bytes / 1024 / 1024
            ));
        }
        verifier.update(&chunk);
        output
            .write_all(&chunk)
            .await
            .map_err(|error| format!("写入应用更新临时文件失败: {error}"))?;
        on_event
            .send(AppUpdateEvent::Progress {
                downloaded_bytes: downloaded,
            })
            .map_err(|error| error.to_string())?;
    }
    if content_length.is_some_and(|length| length != downloaded) {
        return Err("应用更新包实际大小与 Content-Length 不一致".into());
    }
    output
        .sync_all()
        .await
        .map_err(|error| format!("同步应用更新临时文件失败: {error}"))?;
    verifier
        .finalize()
        .map_err(|error| format!("应用更新包签名验证失败: {error}"))?;
    Ok(file)
}

fn decode_public_key(encoded: &str) -> Result<PublicKey, String> {
    let decoded = decode_base64_text(encoded, "应用更新公钥")?;
    PublicKey::decode(&decoded).map_err(|error| format!("应用更新公钥无效: {error}"))
}

fn decode_signature(encoded: &str) -> Result<Signature, String> {
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

fn decode_base64_text(encoded: &str, label: &str) -> Result<String, String> {
    if encoded.trim().is_empty() || encoded.len() > 16 * 1024 {
        return Err(format!("{label}为空或过长"));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| format!("{label}不是有效 Base64: {error}"))?;
    String::from_utf8(bytes).map_err(|error| format!("{label}不是 UTF-8 文本: {error}"))
}

fn require_https_url(url: &Url, label: &str) -> Result<(), String> {
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

fn truncate_notes(value: &str) -> String {
    let mut output = value.chars().take(MAX_NOTES_CHARS).collect::<String>();
    if value.chars().count() > MAX_NOTES_CHARS {
        output.push('…');
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use tempfile::tempdir;
    use webplus_plugin_config::{PluginManifest, API_FILENAME};
    use webplus_plugin_trust::{
        encode_signature_document, prepare_signing_material, SIGNATURE_FILENAME,
    };

    #[test]
    fn disabled_policy_is_explicit_and_empty() {
        let policy: AppUpdatePolicy = serde_json::from_value(json!({
            "schemaVersion": 1,
            "enabled": false,
            "endpoints": [],
            "pubkey": "",
            "maxDownloadBytes": DEFAULT_MAX_DOWNLOAD_BYTES
        }))
        .unwrap();
        assert!(policy.validate().is_ok());

        let mut invalid = policy;
        invalid.endpoints = vec![Url::parse("https://updates.example.test/latest.json").unwrap()];
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn enabled_policy_rejects_http_and_invalid_public_keys() {
        let mut policy = AppUpdatePolicy {
            schema_version: 1,
            enabled: true,
            endpoints: vec![Url::parse("http://updates.example.test/latest.json").unwrap()],
            pubkey: "not-base64".into(),
            max_download_bytes: DEFAULT_MAX_DOWNLOAD_BYTES,
        };
        assert!(policy.validate().is_err());
        policy.endpoints = vec![Url::parse("https://updates.example.test/latest.json").unwrap()];
        assert!(policy.validate().is_err());
    }

    #[test]
    fn accepts_a_valid_tauri_minisign_public_key_and_stream_signature() {
        const PUBLIC_KEY: &str = "untrusted comment: minisign public key\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3\n";
        const SIGNATURE: &str = "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1633700835\tfile:test\tprehashed\nwLMDjy9FLAuxZ3q4NlEvkgtyhrr0gtTu6KC4KBJdITbbOeAi1zBIYo0v4iTgt8jJpIidRJnp94ABQkJAgAooBQ==\n";
        let encoded_key = base64::engine::general_purpose::STANDARD.encode(PUBLIC_KEY);
        let encoded_signature = base64::engine::general_purpose::STANDARD.encode(SIGNATURE);
        let policy = AppUpdatePolicy {
            schema_version: 1,
            enabled: true,
            endpoints: vec![Url::parse(
                "https://updates.example.test/{{target}}/{{arch}}/{{current_version}}",
            )
            .unwrap()],
            pubkey: encoded_key.clone(),
            max_download_bytes: DEFAULT_MAX_DOWNLOAD_BYTES,
        };
        assert!(policy.endpoints[0].as_str().contains("%7B%7Btarget%7D%7D"));
        assert!(policy.validate().is_ok());

        let public_key = decode_public_key(&encoded_key).unwrap();
        let signature = decode_signature(&encoded_signature).unwrap();
        let mut verifier = public_key.verify_stream(&signature).unwrap();
        verifier.update(b"te");
        verifier.update(b"st");
        verifier.finalize().unwrap();

        let directory = tempdir().unwrap();
        let policy_path = directory.path().join(POLICY_FILENAME);
        let package_path = directory.path().join("update.nsis.zip");
        let signature_path = directory.path().join("update.nsis.zip.sig");
        fs::write(
            &policy_path,
            serde_json::to_vec(&json!({
                "schemaVersion": 1,
                "enabled": true,
                "endpoints": ["https://updates.example.test/latest.json"],
                "pubkey": encoded_key,
                "maxDownloadBytes": DEFAULT_MAX_DOWNLOAD_BYTES
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(&package_path, b"test").unwrap();
        fs::write(&signature_path, encoded_signature).unwrap();
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
        let path = directory.path().join(POLICY_FILENAME);
        fs::write(&path, vec![b' '; MAX_POLICY_BYTES as usize + 1]).unwrap();
        assert!(AppUpdatePolicy::load(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn update_policy_rejects_symbolic_links() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let target = directory.path().join("target.json");
        let link = directory.path().join(POLICY_FILENAME);
        fs::write(
            &target,
            br#"{"schemaVersion":1,"enabled":false,"endpoints":[],"pubkey":"","maxDownloadBytes":268435456}"#,
        )
        .unwrap();
        symlink(&target, &link).unwrap();
        assert!(AppUpdatePolicy::load(&link).is_err());
    }

    #[test]
    fn release_notes_are_bounded() {
        let notes = "文".repeat(MAX_NOTES_CHARS + 10);
        let bounded = truncate_notes(&notes);
        assert_eq!(bounded.chars().count(), MAX_NOTES_CHARS + 1);
        assert!(bounded.ends_with('…'));
    }

    #[test]
    fn app_update_plan_binds_pending_metadata_and_plugin_state() {
        let metadata = AppUpdatePlanMetadata {
            current_version: "0.1.0".into(),
            version: "0.2.0".into(),
            date: Some("2026-08-29T00:00:00Z".into()),
            target: "windows-x86_64".into(),
            download_url: "https://updates.example.test/ssdev-0.2.0.nsis.zip".into(),
            signature: "signed-release-a".into(),
            notes: Some("verified release".into()),
        };
        let plugin_state = "11".repeat(32);
        let base = app_update_plan_id(&metadata, &plugin_state).unwrap();
        assert!(crate::is_lowercase_sha256(&base));

        let mut changed_version = metadata.clone();
        changed_version.version = "0.2.1".into();
        assert_ne!(
            base,
            app_update_plan_id(&changed_version, &plugin_state).unwrap()
        );
        let mut changed_url = metadata.clone();
        changed_url.download_url = "https://updates.example.test/replaced.nsis.zip".into();
        assert_ne!(
            base,
            app_update_plan_id(&changed_url, &plugin_state).unwrap()
        );
        let mut changed_signature = metadata.clone();
        changed_signature.signature = "signed-release-b".into();
        assert_ne!(
            base,
            app_update_plan_id(&changed_signature, &plugin_state).unwrap()
        );
        assert_ne!(
            base,
            app_update_plan_id(&metadata, &"22".repeat(32)).unwrap()
        );
        assert!(ensure_app_update_plan_matches(&base, &base).is_ok());
        assert!(ensure_app_update_plan_matches(&base, &"33".repeat(32)).is_err());
    }

    #[test]
    fn app_update_capability_state_digest_binds_signed_plugin_content() {
        let root = tempdir().unwrap();
        let plugin = root.path().join("reader");
        fs::create_dir(&plugin).unwrap();
        fs::write(
            plugin.join(API_FILENAME),
            r#"{"serviceId":"reader","mainClass":"reader.dll"}"#,
        )
        .unwrap();
        fs::write(
            plugin.join("plugin.json"),
            r#"{"schemaVersion":1,"pluginId":"reader","version":"1.0.0","desktopVersionRequirement":">=0.1.0, <0.3.0"}"#,
        )
        .unwrap();
        fs::write(plugin.join("reader.dll"), b"first payload").unwrap();
        let signing_key = SigningKey::from_bytes(&[93_u8; 32]);
        let material = prepare_signing_material(&plugin, "reader", "test-key").unwrap();
        let signature = BASE64.encode(signing_key.sign(&material.payload).to_bytes());
        fs::write(
            plugin.join(SIGNATURE_FILENAME),
            encode_signature_document(&material, &signature).unwrap(),
        )
        .unwrap();
        let manifest = PluginManifest::load("reader", &plugin).unwrap();

        let local_mapping_root = root.path().join("local-mappings");
        let empty = app_update_capability_state_digest(&[], &local_mapping_root).unwrap();
        let before = app_update_capability_state_digest(
            std::slice::from_ref(&manifest),
            &local_mapping_root,
        )
        .unwrap();
        fs::write(plugin.join("reader.dll"), b"second payload").unwrap();
        let after = app_update_capability_state_digest(&[manifest], &local_mapping_root).unwrap();
        assert_ne!(empty, before);
        assert_ne!(before, after);

        let mut mismatched = PluginManifest::load("reader", &plugin).unwrap();
        mismatched.plugin_id = "another-reader".into();
        assert!(app_update_capability_state_digest(&[mismatched], &local_mapping_root).is_err());
    }

    #[test]
    fn app_update_capability_state_digest_binds_local_mapping_content() {
        let root = tempdir().unwrap();
        let local_mapping_root = root.path().join("local-mappings");
        let plugin = local_mapping_root.join("reader.local");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join(API_FILENAME),
            r#"{"serviceId":"reader","mainClass":"reader.dll"}"#,
        )
        .unwrap();
        fs::write(plugin.join("reader.dll"), b"first local payload").unwrap();
        let manifest = PluginManifest::load("reader.local", &plugin).unwrap();

        let before = app_update_capability_state_digest(
            std::slice::from_ref(&manifest),
            &local_mapping_root,
        )
        .unwrap();
        fs::write(plugin.join("reader.dll"), b"second local payload").unwrap();
        let after = app_update_capability_state_digest(&[manifest], &local_mapping_root).unwrap();

        assert_ne!(before, after);
    }
}
