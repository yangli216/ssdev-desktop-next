use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssdev_config::DesktopConfig;
use tempfile::{Builder as TempBuilder, TempDir};
use webplus_plugin_trust::{DetachedSignatureDocument, TrustPurpose, TrustStore};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter};

const SCHEMA_VERSION: u8 = 1;
const MANIFEST_FILENAME: &str = "project.json";
const CONFIG_FILENAME: &str = "config.json";
const MAX_BUNDLE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_COMPONENT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_COMPONENTS: usize = 128;
const MAX_ENTRIES: usize = MAX_COMPONENTS + 2;
const MAX_SIGNATURE_BYTES: u64 = 64 * 1024;
const PROJECT_BUNDLE_DOMAIN: &[u8] = b"SSDEV-PROJECT-BUNDLE\0";

#[derive(Debug, Clone)]
pub struct ProjectBundleInput {
    pub plugin_id: String,
    pub version: Option<String>,
    pub kind: ProjectComponentKind,
    pub path: PathBuf,
}

#[derive(Debug)]
pub struct OpenedProjectBundle {
    staging: TempDir,
    manifest: ProjectManifest,
    pub config: DesktopConfig,
}

impl OpenedProjectBundle {
    pub fn schema_version(&self) -> u8 {
        self.manifest.schema_version
    }

    pub fn created_by_version(&self) -> &str {
        &self.manifest.created_by_version
    }

    pub fn components(&self) -> impl Iterator<Item = OpenedProjectComponent<'_>> {
        self.manifest
            .components
            .iter()
            .map(|component| OpenedProjectComponent {
                plugin_id: &component.plugin_id,
                version: component.version.as_deref(),
                kind: component.kind,
                path: self.staging.path().join(&component.archive),
            })
    }
}

pub struct OpenedProjectComponent<'a> {
    pub plugin_id: &'a str,
    pub version: Option<&'a str>,
    pub kind: ProjectComponentKind,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProjectComponentKind {
    SignedPlugin,
    LocalMapping,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectBundleSummary {
    pub schema_version: u8,
    pub created_by_version: String,
    pub component_count: usize,
    pub signed_plugin_count: usize,
    pub local_mapping_count: usize,
    pub bundle_bytes: u64,
    pub bundle_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectBundleSigningMaterial {
    pub payload: Vec<u8>,
    pub summary: ProjectBundleSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectBundleSignature {
    pub key_id: String,
    pub summary: ProjectBundleSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProjectManifest {
    schema_version: u8,
    created_by_version: String,
    config_sha256: String,
    components: Vec<ProjectComponentManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProjectComponentManifest {
    plugin_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    kind: ProjectComponentKind,
    archive: String,
    sha256: String,
    bytes: u64,
}

pub fn create(
    destination: &Path,
    config: &DesktopConfig,
    created_by_version: &str,
    mut inputs: Vec<ProjectBundleInput>,
) -> Result<(), String> {
    require_extension(destination)?;
    config.validate().map_err(|error| error.to_string())?;
    if created_by_version.is_empty() || created_by_version.len() > 64 {
        return Err("项目包创建版本无效".into());
    }
    if inputs.len() > MAX_COMPONENTS {
        return Err(format!("项目包最多包含 {MAX_COMPONENTS} 个插件或映射"));
    }
    inputs.sort_by(|left, right| left.plugin_id.cmp(&right.plugin_id));
    let mut ids = BTreeSet::new();
    let mut manifests = Vec::with_capacity(inputs.len());
    let mut total_bytes = 0_u64;
    for input in &inputs {
        validate_plugin_id(&input.plugin_id)?;
        if !ids.insert(input.plugin_id.clone()) {
            return Err(format!("项目包包含重复插件 ID [{}]", input.plugin_id));
        }
        let metadata = fs::symlink_metadata(&input.path)
            .map_err(|error| format!("无法读取项目组件 [{}]: {error}", input.plugin_id))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!("项目组件 [{}] 不是安全的普通文件", input.plugin_id));
        }
        if metadata.len() > MAX_COMPONENT_BYTES {
            return Err(format!("项目组件 [{}] 超过 1 GiB 上限", input.plugin_id));
        }
        total_bytes = total_bytes.saturating_add(metadata.len());
        let archive = component_archive(&input.plugin_id, input.kind);
        manifests.push(ProjectComponentManifest {
            plugin_id: input.plugin_id.clone(),
            version: input.version.clone(),
            kind: input.kind,
            archive,
            sha256: sha256_file(&input.path)?,
            bytes: metadata.len(),
        });
    }
    if total_bytes > MAX_BUNDLE_BYTES {
        return Err("项目组件总大小超过 4 GiB 上限".into());
    }

    let config_bytes =
        serde_json::to_vec_pretty(config).map_err(|error| format!("无法编码项目配置: {error}"))?;
    if config_bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err("项目配置超过 1 MiB 上限".into());
    }
    let manifest = ProjectManifest {
        schema_version: SCHEMA_VERSION,
        created_by_version: created_by_version.to_owned(),
        config_sha256: sha256_bytes(&config_bytes),
        components: manifests,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("无法编码项目包清单: {error}"))?;
    if total_bytes
        .saturating_add(config_bytes.len() as u64)
        .saturating_add(manifest_bytes.len() as u64)
        > MAX_BUNDLE_BYTES
    {
        return Err("项目包总大小超过 4 GiB 上限".into());
    }

    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|error| format!("无法读取项目包目标目录: {error}"))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err("项目包目标必须是已有的真实目录".into());
    }
    if fs::symlink_metadata(destination).is_ok() {
        return Err("项目包目标已存在，拒绝覆盖".into());
    }
    let mut temporary = TempBuilder::new()
        .prefix(".ssdev-project-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|error| format!("无法创建项目包暂存文件: {error}"))?;
    {
        let mut archive = ZipWriter::new(temporary.as_file_mut());
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .last_modified_time(DateTime::default())
            .unix_permissions(0o644);
        archive
            .start_file(MANIFEST_FILENAME, options)
            .map_err(|error| format!("无法写入项目包清单: {error}"))?;
        archive
            .write_all(&manifest_bytes)
            .map_err(|error| format!("无法写入项目包清单: {error}"))?;
        archive
            .start_file(CONFIG_FILENAME, options)
            .map_err(|error| format!("无法写入项目配置: {error}"))?;
        archive
            .write_all(&config_bytes)
            .map_err(|error| format!("无法写入项目配置: {error}"))?;
        for (input, component) in inputs.iter().zip(&manifest.components) {
            archive
                .start_file(&component.archive, options)
                .map_err(|error| format!("无法写入项目组件: {error}"))?;
            let mut source = File::open(&input.path)
                .map_err(|error| format!("无法读取项目组件 [{}]: {error}", input.plugin_id))?;
            io::copy(&mut source, &mut archive)
                .map_err(|error| format!("无法复制项目组件 [{}]: {error}", input.plugin_id))?;
        }
        archive
            .finish()
            .map_err(|error| format!("无法完成项目包: {error}"))?;
    }
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| format!("无法持久化项目包: {error}"))?;
    temporary
        .persist_noclobber(destination)
        .map_err(|error| format!("无法保存项目包: {}", error.error))?;
    Ok(())
}

pub fn open(source: &Path) -> Result<OpenedProjectBundle, String> {
    require_extension(source)?;
    let metadata =
        fs::symlink_metadata(source).map_err(|error| format!("无法读取项目包: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("项目包必须是安全的普通文件".into());
    }
    if metadata.len() > MAX_BUNDLE_BYTES {
        return Err("项目包超过 4 GiB 上限".into());
    }
    let file = File::open(source).map_err(|error| format!("无法打开项目包: {error}"))?;
    let mut archive = ZipArchive::new(file).map_err(|error| format!("项目包格式无效: {error}"))?;
    if archive.len() > MAX_ENTRIES {
        return Err(format!("项目包文件超过 {MAX_ENTRIES} 项上限"));
    }
    let manifest_bytes = read_bounded_entry(&mut archive, MANIFEST_FILENAME, MAX_CONFIG_BYTES)?;
    let manifest: ProjectManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("项目包清单无效: {error}"))?;
    validate_manifest(&manifest)?;

    let expected = std::iter::once(MANIFEST_FILENAME.to_owned())
        .chain(std::iter::once(CONFIG_FILENAME.to_owned()))
        .chain(manifest.components.iter().map(|item| item.archive.clone()))
        .collect::<BTreeSet<_>>();
    if expected.len() != manifest.components.len() + 2 || archive.len() != expected.len() {
        return Err("项目包包含重复、缺失或未声明文件".into());
    }

    let staging = TempBuilder::new()
        .prefix("ssdev-project-open-")
        .tempdir()
        .map_err(|error| format!("无法创建项目包检查目录: {error}"))?;
    let mut actual = BTreeSet::new();
    let mut total_uncompressed = 0_u64;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| format!("无法读取项目包文件: {error}"))?;
        let name = entry.name().to_owned();
        validate_archive_path(&name)?;
        if !actual.insert(name.clone()) || !expected.contains(&name) {
            return Err("项目包包含重复或未声明文件".into());
        }
        if entry.is_dir() || entry.unix_mode().is_some_and(is_symlink_mode) {
            return Err("项目包不能包含目录、符号链接或特殊文件".into());
        }
        let limit = if name == CONFIG_FILENAME || name == MANIFEST_FILENAME {
            MAX_CONFIG_BYTES
        } else {
            MAX_COMPONENT_BYTES
        };
        if entry.size() > limit {
            return Err(format!("项目包文件 [{name}] 超过大小上限"));
        }
        let target = staging.path().join(&name);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("无法创建项目包检查目录: {error}"))?;
        }
        let mut output = File::create(&target)
            .map_err(|error| format!("无法暂存项目包文件 [{name}]: {error}"))?;
        let copied = io::copy(&mut entry.take(limit.saturating_add(1)), &mut output)
            .map_err(|error| format!("无法解压项目包文件 [{name}]: {error}"))?;
        if copied > limit {
            return Err(format!("项目包文件 [{name}] 解压后超过大小上限"));
        }
        total_uncompressed = total_uncompressed.saturating_add(copied);
        if total_uncompressed > MAX_BUNDLE_BYTES {
            return Err("项目包解压内容超过 4 GiB 上限".into());
        }
        output
            .sync_all()
            .map_err(|error| format!("无法持久化项目包文件 [{name}]: {error}"))?;
    }
    if actual != expected {
        return Err("项目包文件清单不完整".into());
    }

    let config_path = staging.path().join(CONFIG_FILENAME);
    if sha256_file(&config_path)? != manifest.config_sha256 {
        return Err("项目配置摘要不匹配".into());
    }
    let config_bytes =
        fs::read(&config_path).map_err(|error| format!("无法读取项目配置: {error}"))?;
    let config: DesktopConfig =
        serde_json::from_slice(&config_bytes).map_err(|error| format!("项目配置无效: {error}"))?;
    config.validate().map_err(|error| error.to_string())?;
    for component in &manifest.components {
        let path = staging.path().join(&component.archive);
        let size = fs::metadata(&path)
            .map_err(|error| format!("无法检查项目组件 [{}]: {error}", component.plugin_id))?
            .len();
        if size != component.bytes || sha256_file(&path)? != component.sha256 {
            return Err(format!(
                "项目组件 [{}] 摘要或大小不匹配",
                component.plugin_id
            ));
        }
    }
    Ok(OpenedProjectBundle {
        staging,
        manifest,
        config,
    })
}

pub fn signature_path(source: &Path) -> Result<PathBuf, String> {
    let name = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("项目包文件名无效")?;
    Ok(source.with_file_name(format!("{name}.sig.json")))
}

pub fn signing_material(source: &Path) -> Result<ProjectBundleSigningMaterial, String> {
    open_with_signing_material(source).map(|(_, material)| material)
}

/// Opens and fingerprints one stable project bundle as one bounded operation.
/// Debug tooling can use this to bind an unsigned preview to the exact bytes
/// that were inspected without duplicating the archive parsing rules.
pub fn open_with_signing_material(
    source: &Path,
) -> Result<(OpenedProjectBundle, ProjectBundleSigningMaterial), String> {
    let before = bundle_fingerprint(source)?;
    let opened = open(source)?;
    let material = signing_material_from_opened(source, &opened)?;
    ensure_unchanged(&before, &material.summary)?;
    Ok((opened, material))
}

pub fn open_verified(
    source: &Path,
    envelope_path: &Path,
    trust_store: &TrustStore,
) -> Result<(OpenedProjectBundle, ProjectBundleSignature), String> {
    let (opened, material) = open_with_signing_material(source)?;
    let envelope = read_signature_envelope(envelope_path)?;
    trust_store
        .verify_detached(
            TrustPurpose::ProjectBundle,
            &envelope.key_id,
            &material.payload,
            &envelope.signature,
        )
        .map_err(|error| format!("项目包签名验证失败: {error}"))?;
    Ok((
        opened,
        ProjectBundleSignature {
            key_id: envelope.key_id,
            summary: material.summary,
        },
    ))
}

fn bundle_fingerprint(source: &Path) -> Result<(u64, String), String> {
    let metadata =
        fs::symlink_metadata(source).map_err(|error| format!("无法读取项目包: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_BUNDLE_BYTES
    {
        return Err("项目包必须是大小受限的安全普通文件".into());
    }
    Ok((metadata.len(), sha256_file(source)?))
}

fn ensure_unchanged(before: &(u64, String), summary: &ProjectBundleSummary) -> Result<(), String> {
    if before.0 != summary.bundle_bytes || before.1 != summary.bundle_sha256 {
        return Err("项目包在读取期间发生变化，请重新选择稳定文件".into());
    }
    Ok(())
}

fn signing_material_from_opened(
    source: &Path,
    opened: &OpenedProjectBundle,
) -> Result<ProjectBundleSigningMaterial, String> {
    let metadata =
        fs::symlink_metadata(source).map_err(|error| format!("无法读取项目包: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_BUNDLE_BYTES
    {
        return Err("项目包必须是大小受限的安全普通文件".into());
    }
    let digest = sha256_file_digest(source)?;
    let mut payload = Vec::with_capacity(PROJECT_BUNDLE_DOMAIN.len() + digest.len());
    payload.extend_from_slice(PROJECT_BUNDLE_DOMAIN);
    payload.extend_from_slice(&digest);
    let signed_plugin_count = opened
        .manifest
        .components
        .iter()
        .filter(|component| component.kind == ProjectComponentKind::SignedPlugin)
        .count();
    let local_mapping_count = opened
        .manifest
        .components
        .len()
        .saturating_sub(signed_plugin_count);
    Ok(ProjectBundleSigningMaterial {
        payload,
        summary: ProjectBundleSummary {
            schema_version: opened.manifest.schema_version,
            created_by_version: opened.manifest.created_by_version.clone(),
            component_count: opened.manifest.components.len(),
            signed_plugin_count,
            local_mapping_count,
            bundle_bytes: metadata.len(),
            bundle_sha256: hex_digest(&digest),
        },
    })
}

fn read_signature_envelope(path: &Path) -> Result<DetachedSignatureDocument, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("无法读取项目包签名封套: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_SIGNATURE_BYTES
    {
        return Err("项目包签名封套必须是大小受限的安全普通文件".into());
    }
    let bytes = fs::read(path).map_err(|error| format!("无法读取项目包签名封套: {error}"))?;
    let envelope: DetachedSignatureDocument =
        serde_json::from_slice(&bytes).map_err(|error| format!("项目包签名封套无效: {error}"))?;
    envelope
        .validate()
        .map_err(|error| format!("项目包签名封套无效: {error}"))?;
    Ok(envelope)
}

fn validate_manifest(manifest: &ProjectManifest) -> Result<(), String> {
    if manifest.schema_version != SCHEMA_VERSION {
        return Err(format!("不支持项目包 schema {}", manifest.schema_version));
    }
    if manifest.created_by_version.is_empty() || manifest.created_by_version.len() > 64 {
        return Err("项目包创建版本无效".into());
    }
    if !is_sha256(&manifest.config_sha256) {
        return Err("项目配置摘要格式无效".into());
    }
    if manifest.components.len() > MAX_COMPONENTS {
        return Err(format!("项目包最多包含 {MAX_COMPONENTS} 个插件或映射"));
    }
    let mut ids = BTreeSet::new();
    for component in &manifest.components {
        validate_plugin_id(&component.plugin_id)?;
        if !ids.insert(component.plugin_id.clone()) {
            return Err(format!("项目包包含重复插件 ID [{}]", component.plugin_id));
        }
        if component.archive != component_archive(&component.plugin_id, component.kind) {
            return Err(format!("项目组件 [{}] 路径不规范", component.plugin_id));
        }
        if component.bytes > MAX_COMPONENT_BYTES || !is_sha256(&component.sha256) {
            return Err(format!("项目组件 [{}] 元数据无效", component.plugin_id));
        }
    }
    Ok(())
}

fn component_archive(plugin_id: &str, kind: ProjectComponentKind) -> String {
    let extension = match kind {
        ProjectComponentKind::SignedPlugin => "ssdev-plugin",
        ProjectComponentKind::LocalMapping => "ssdev-mapping",
    };
    format!("components/{plugin_id}.{extension}")
}

fn validate_plugin_id(plugin_id: &str) -> Result<(), String> {
    if plugin_id.is_empty()
        || plugin_id.len() > 128
        || plugin_id.starts_with('.')
        || !plugin_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!("项目组件 ID [{plugin_id}] 不可移植"));
    }
    Ok(())
}

fn require_extension(path: &Path) -> Result<(), String> {
    if path.extension().and_then(|value| value.to_str()) != Some("ssdev-project") {
        return Err("项目包必须使用 .ssdev-project 扩展名".into());
    }
    Ok(())
}

fn read_bounded_entry(
    archive: &mut ZipArchive<File>,
    name: &str,
    limit: u64,
) -> Result<Vec<u8>, String> {
    let entry = archive
        .by_name(name)
        .map_err(|_| format!("项目包缺少 {name}"))?;
    if entry.size() > limit || entry.is_dir() || entry.unix_mode().is_some_and(is_symlink_mode) {
        return Err(format!("项目包文件 [{name}] 不安全或超过大小上限"));
    }
    let mut bytes = Vec::with_capacity(entry.size() as usize);
    entry
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("无法读取项目包文件 [{name}]: {error}"))?;
    if bytes.len() as u64 > limit {
        return Err(format!("项目包文件 [{name}] 解压后超过大小上限"));
    }
    Ok(bytes)
}

fn validate_archive_path(path: &str) -> Result<(), String> {
    let path = Path::new(path);
    if path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("项目包包含不安全路径".into());
    }
    Ok(())
}

fn is_symlink_mode(mode: u32) -> bool {
    mode & 0o170000 == 0o120000
}

fn sha256_file(path: &Path) -> Result<String, String> {
    sha256_file_digest(path).map(|digest| hex_digest(&digest))
}

fn sha256_file_digest(path: &Path) -> Result<[u8; 32], String> {
    let mut file = File::open(path).map_err(|error| format!("无法读取摘要输入: {error}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("无法计算文件摘要: {error}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex_digest(Sha256::digest(bytes).as_slice())
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    fn config() -> DesktopConfig {
        DesktopConfig {
            website: Some("http://project.internal/app".into()),
            ..DesktopConfig::default()
        }
    }

    #[test]
    fn project_bundle_round_trip_preserves_config_and_component_inventory() {
        let root = tempfile::tempdir().unwrap();
        let plugin = root.path().join("reader.ssdev-plugin");
        let mapping = root.path().join("printer.ssdev-mapping");
        fs::write(&plugin, b"signed plugin fixture").unwrap();
        fs::write(&mapping, b"local mapping fixture").unwrap();
        let destination = root.path().join("clinic.ssdev-project");
        create(
            &destination,
            &config(),
            "1.2.3",
            vec![
                ProjectBundleInput {
                    plugin_id: "reader".into(),
                    version: Some("2.0.0".into()),
                    kind: ProjectComponentKind::SignedPlugin,
                    path: plugin,
                },
                ProjectBundleInput {
                    plugin_id: "printer.local".into(),
                    version: None,
                    kind: ProjectComponentKind::LocalMapping,
                    path: mapping,
                },
            ],
        )
        .unwrap();

        let opened = open(&destination).unwrap();
        assert_eq!(
            opened.config.website.as_deref(),
            Some("http://project.internal/app")
        );
        assert_eq!(opened.created_by_version(), "1.2.3");
        let components = opened.components().collect::<Vec<_>>();
        assert_eq!(components.len(), 2);
        assert!(components.iter().all(|component| component.path.is_file()));
    }

    #[test]
    fn export_refuses_duplicate_ids_and_existing_targets() {
        let root = tempfile::tempdir().unwrap();
        let component = root.path().join("reader.ssdev-plugin");
        fs::write(&component, b"fixture").unwrap();
        let destination = root.path().join("clinic.ssdev-project");
        let inputs = || {
            vec![
                ProjectBundleInput {
                    plugin_id: "reader".into(),
                    version: Some("1.0.0".into()),
                    kind: ProjectComponentKind::SignedPlugin,
                    path: component.clone(),
                },
                ProjectBundleInput {
                    plugin_id: "reader".into(),
                    version: None,
                    kind: ProjectComponentKind::LocalMapping,
                    path: component.clone(),
                },
            ]
        };
        assert!(create(&destination, &config(), "1.0.0", inputs()).is_err());
        fs::write(&destination, b"existing").unwrap();
        assert!(create(
            &destination,
            &config(),
            "1.0.0",
            vec![ProjectBundleInput {
                plugin_id: "reader".into(),
                version: Some("1.0.0".into()),
                kind: ProjectComponentKind::SignedPlugin,
                path: component,
            }],
        )
        .is_err());
    }

    #[test]
    fn import_rejects_component_tampering_even_when_zip_is_well_formed() {
        let root = tempfile::tempdir().unwrap();
        let component = root.path().join("reader.ssdev-plugin");
        fs::write(&component, b"original signed plugin fixture").unwrap();
        let original = root.path().join("original.ssdev-project");
        create(
            &original,
            &config(),
            "1.0.0",
            vec![ProjectBundleInput {
                plugin_id: "reader".into(),
                version: Some("1.0.0".into()),
                kind: ProjectComponentKind::SignedPlugin,
                path: component,
            }],
        )
        .unwrap();

        let tampered = root.path().join("tampered.ssdev-project");
        let input = File::open(&original).unwrap();
        let mut source = ZipArchive::new(input).unwrap();
        let output = File::create(&tampered).unwrap();
        let mut destination = ZipWriter::new(output);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .last_modified_time(DateTime::default())
            .unix_permissions(0o644);
        for index in 0..source.len() {
            let mut entry = source.by_index(index).unwrap();
            let name = entry.name().to_owned();
            destination.start_file(&name, options).unwrap();
            if name == "components/reader.ssdev-plugin" {
                destination.write_all(b"tampered plugin fixture").unwrap();
            } else {
                io::copy(&mut entry, &mut destination).unwrap();
            }
        }
        destination.finish().unwrap();

        assert!(open(&tampered).unwrap_err().contains("摘要或大小不匹配"));
    }

    #[test]
    fn detached_signature_binds_the_complete_project_bundle() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("clinic.ssdev-project");
        create(&project, &config(), "1.2.3", Vec::new()).unwrap();
        let signing_key = SigningKey::from_bytes(&[71; 32]);
        let material = signing_material(&project).unwrap();
        let signature = BASE64.encode(signing_key.sign(&material.payload).to_bytes());
        let envelope = signature_path(&project).unwrap();
        fs::write(
            &envelope,
            DetachedSignatureDocument::new("project-release", &signature)
                .unwrap()
                .to_pretty_json()
                .unwrap(),
        )
        .unwrap();
        let trust_path = root.path().join("trust.json");
        fs::write(
            &trust_path,
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "keys": [{
                    "keyId": "project-release",
                    "algorithm": "ed25519",
                    "publicKey": BASE64.encode(signing_key.verifying_key().to_bytes()),
                    "purposes": ["project-bundle"],
                    "status": "active"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let trust = TrustStore::load(&trust_path).unwrap();

        let (_, verified) = open_verified(&project, &envelope, &trust).unwrap();
        assert_eq!(verified.key_id, "project-release");
        assert_eq!(
            verified.summary.bundle_sha256,
            material.summary.bundle_sha256
        );

        let repacked = root.path().join("repacked.ssdev-project");
        create(&repacked, &config(), "1.2.4", Vec::new()).unwrap();
        assert!(open(&repacked).is_ok());
        assert!(open_verified(&repacked, &envelope, &trust).is_err());
    }
}
