use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::{Builder as TempBuilder, NamedTempFile, TempDir};
use uuid::Uuid;
use webplus_plugin_config::{
    build_local_mapping_integrity, ParameterDefinition, PluginManifest, PluginMetadata,
    ServiceDefinition, API_FILENAME, LOCAL_MAPPING_INTEGRITY_FILENAME, PLUGIN_METADATA_FILENAME,
};
use webplus_protocol::{
    contains_draft_placeholder, InvokeRequest, InvokeResponse, DRAFT_INPUT_PLACEHOLDER,
    DRAFT_RESPONSE_PLACEHOLDER,
};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter};

const LOCAL_MAPPING_FILENAME: &str = "local-mapping.json";
const LOCAL_MAPPING_SCHEMA_VERSION: u8 = 2;
const MAX_COMPONENT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EXPORTS: usize = 4096;
const MAX_PE_INSPECTION_BYTES: u64 = 512 * 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_BUNDLE_ENTRIES: usize = 512;
const MAX_DEBUG_CASES: usize = 32;
const MAX_EXPECTED_RES_DATA_BYTES: usize = 64 * 1024;
const MAX_EXPECTED_RES_DATA_DEPTH: usize = 16;
const MAX_EXPECTED_RES_DATA_NODES: usize = 512;
const MAX_RELEASE_MATRIX_CASES: usize = 1024;
const MAPPING_ACTIVATION_PREFIX: &str = ".mapping-activation-";
const MAPPING_COMMITTED_PREFIX: &str = ".mapping-committed-";
const MAPPING_IMPORT_PREFIX: &str = ".mapping-import-";
const MAPPING_STAGE_PREFIX: &str = ".mapping-stage-";
const MAPPING_TRANSACTION_JOURNAL: &str = "transaction.json";
const MAX_MAPPING_TRANSACTION_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LocalMappingDefinition {
    pub schema_version: u8,
    pub plugin_id: String,
    #[serde(default)]
    pub display_name: String,
    pub services: Vec<ServiceDefinition>,
    #[serde(default)]
    pub debug_cases: Vec<DebugCaseDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DebugCaseDefinition {
    pub name: String,
    pub service_id: String,
    pub method: String,
    #[serde(default)]
    pub parameters: serde_json::Map<String, serde_json::Value>,
    pub expected_res_code: i32,
    #[serde(default, skip_serializing_if = "is_false")]
    pub assert_res_data: bool,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub expected_res_data: serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NativeComponentInspection {
    pub file_name: String,
    pub file_bytes: u64,
    pub component_type: String,
    pub architecture: Option<&'static str>,
    pub exports: Vec<String>,
    pub warnings: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReleaseSourceExportResult {
    pub destination: PathBuf,
    pub matrix_seed: PathBuf,
    pub file_count: usize,
    pub bytes: u64,
    pub seeded_case_count: usize,
    pub placeholder_case_count: usize,
    pub review_required_case_count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReleaseMatrixSeed {
    schema_version: u8,
    draft: bool,
    cases: Vec<ReleaseMatrixCase>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReleaseMatrixCase {
    name: String,
    enabled: bool,
    review_required: bool,
    request: InvokeRequest,
    expected: InvokeResponse,
}

pub(crate) struct PreparedLocalMapping {
    staging: TempDir,
    definition: LocalMappingDefinition,
    manifest: PluginManifest,
}

pub(crate) struct ActivatedLocalMapping {
    manifest: PluginManifest,
    root: PathBuf,
    target: PathBuf,
    transaction: PathBuf,
    had_previous: bool,
    finalized: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LocalMappingRecoveryReport {
    pub(crate) rolled_back_activations: usize,
    pub(crate) finalized_activations: usize,
    pub(crate) removed_committed_transactions: usize,
    pub(crate) removed_staging_directories: usize,
}

impl LocalMappingRecoveryReport {
    pub(crate) fn total(self) -> usize {
        self.rolled_back_activations
            .saturating_add(self.finalized_activations)
            .saturating_add(self.removed_committed_transactions)
            .saturating_add(self.removed_staging_directories)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MappingActivationJournal {
    schema_version: u8,
    plugin_id: String,
    had_previous: bool,
}

impl ActivatedLocalMapping {
    pub(crate) fn commit(mut self) -> Result<PluginManifest, String> {
        commit_mapping_transaction(&self.root, &self.transaction)?;
        self.finalized = true;
        Ok(self.manifest.clone())
    }

    pub(crate) fn commit_grouped(mut self) -> Result<PluginManifest, String> {
        self.finalized = true;
        commit_mapping_transaction(&self.root, &self.transaction)?;
        Ok(self.manifest.clone())
    }

    pub(crate) fn rollback(mut self) -> Result<(), String> {
        rollback_mapping_transaction(
            &self.root,
            &self.transaction,
            &MappingActivationJournal {
                schema_version: 1,
                plugin_id: self
                    .target
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default()
                    .to_owned(),
                had_previous: self.had_previous,
            },
        )?;
        self.finalized = true;
        Ok(())
    }
}

impl Drop for ActivatedLocalMapping {
    fn drop(&mut self) {
        if !self.finalized
            && rollback_mapping_transaction(
                &self.root,
                &self.transaction,
                &MappingActivationJournal {
                    schema_version: 1,
                    plugin_id: self
                        .target
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or_default()
                        .to_owned(),
                    had_previous: self.had_previous,
                },
            )
            .is_err()
        {
            tracing::error!(
                event_code = "local-mapping-rollback-failed",
                "local mapping activation rollback failed"
            );
        }
    }
}

pub(crate) fn recover_incomplete_mapping_activations(
    root: &Path,
    committed_plugin_ids: &HashSet<String>,
) -> Result<LocalMappingRecoveryReport, String> {
    fs::create_dir_all(root).map_err(|error| format!("无法创建本地映射目录: {error}"))?;
    let root = root
        .canonicalize()
        .map_err(|error| format!("无法解析本地映射目录: {error}"))?;
    let mut entries = fs::read_dir(&root)
        .map_err(|error| format!("无法读取本地映射目录: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("无法读取本地映射目录项: {error}"))?;
    entries.sort_by_key(fs::DirEntry::file_name);

    let mut report = LocalMappingRecoveryReport::default();
    let mut activation_plugins = HashSet::new();
    let mut activations = Vec::new();
    for entry in entries {
        let file_type = entry
            .file_type()
            .map_err(|error| format!("无法检查本地映射事务: {error}"))?;
        if !file_type.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(MAPPING_COMMITTED_PREFIX) {
            fs::remove_dir_all(entry.path())
                .map_err(|error| format!("无法清理已提交映射事务: {error}"))?;
            report.removed_committed_transactions += 1;
        } else if name.starts_with(MAPPING_IMPORT_PREFIX) || name.starts_with(MAPPING_STAGE_PREFIX)
        {
            fs::remove_dir_all(entry.path())
                .map_err(|error| format!("无法清理映射暂存目录: {error}"))?;
            report.removed_staging_directories += 1;
        } else if name.starts_with(MAPPING_ACTIVATION_PREFIX) {
            let journal = read_mapping_activation_journal(&entry.path())?;
            bounded_plugin_target(&root, &journal.plugin_id)?;
            if !activation_plugins.insert(journal.plugin_id.clone()) {
                return Err(format!(
                    "本地映射 [{}] 存在多个未完成事务",
                    journal.plugin_id
                ));
            }
            activations.push((entry.path(), journal));
        }
    }
    for (transaction, journal) in activations {
        if committed_plugin_ids.contains(&journal.plugin_id) {
            commit_mapping_transaction(&root, &transaction)?;
            report.finalized_activations += 1;
        } else {
            rollback_mapping_transaction(&root, &transaction, &journal)?;
            report.rolled_back_activations += 1;
        }
    }
    Ok(report)
}

fn write_mapping_activation_journal(
    transaction: &Path,
    journal: &MappingActivationJournal,
) -> Result<(), String> {
    let path = transaction.join(MAPPING_TRANSACTION_JOURNAL);
    let bytes =
        serde_json::to_vec(journal).map_err(|error| format!("无法编码映射事务: {error}"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("无法创建映射事务记录: {error}"))?;
    file.write_all(&bytes)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("无法持久化映射事务记录: {error}"))
}

fn read_mapping_activation_journal(transaction: &Path) -> Result<MappingActivationJournal, String> {
    let path = transaction.join(MAPPING_TRANSACTION_JOURNAL);
    let metadata =
        fs::symlink_metadata(&path).map_err(|error| format!("无法读取映射事务记录: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_MAPPING_TRANSACTION_BYTES
    {
        return Err("映射事务记录不是受支持的普通文件".into());
    }
    let bytes = fs::read(&path).map_err(|error| format!("无法读取映射事务记录: {error}"))?;
    let journal: MappingActivationJournal =
        serde_json::from_slice(&bytes).map_err(|error| format!("映射事务记录无效: {error}"))?;
    if journal.schema_version != 1 {
        return Err(format!("不支持映射事务版本 {}", journal.schema_version));
    }
    validate_plugin_id(&journal.plugin_id)?;
    Ok(journal)
}

fn commit_mapping_transaction(root: &Path, transaction: &Path) -> Result<(), String> {
    let name = transaction
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix(MAPPING_ACTIVATION_PREFIX))
        .ok_or("映射事务目录名称无效")?;
    let committed = root.join(format!("{MAPPING_COMMITTED_PREFIX}{name}"));
    fs::rename(transaction, &committed).map_err(|error| format!("无法提交映射事务: {error}"))?;
    if let Err(error) = fs::remove_dir_all(&committed) {
        tracing::warn!(
            event_code = "local-mapping-transaction-cleanup-deferred",
            failure_kind = ?error.kind(),
            "committed local mapping transaction cleanup deferred"
        );
    }
    Ok(())
}

fn rollback_mapping_transaction(
    root: &Path,
    transaction: &Path,
    journal: &MappingActivationJournal,
) -> Result<(), String> {
    let target = bounded_plugin_target(root, &journal.plugin_id)?;
    let previous = transaction.join("previous");
    if journal.had_previous {
        if previous.exists() {
            require_mapping_directory(&previous, "旧映射备份")?;
            if target.exists() {
                require_mapping_directory(&target, "当前映射")?;
                fs::remove_dir_all(&target).map_err(|error| format!("无法撤销新映射: {error}"))?;
            }
            fs::rename(&previous, &target).map_err(|error| format!("无法恢复旧映射: {error}"))?;
        } else {
            require_mapping_directory(&target, "已恢复映射")?;
        }
    } else if target.exists() {
        require_mapping_directory(&target, "未完成的新映射")?;
        fs::remove_dir_all(&target).map_err(|error| format!("无法撤销新映射: {error}"))?;
    }
    fs::remove_dir_all(transaction).map_err(|error| format!("无法清理映射事务: {error}"))
}

fn require_mapping_directory(path: &Path, role: &str) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("无法检查{role}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{role}不是安全的真实目录"));
    }
    Ok(())
}

pub(crate) fn prepare_removal(
    root: &Path,
    plugin_id: &str,
) -> Result<ActivatedLocalMapping, String> {
    fs::create_dir_all(root).map_err(|error| format!("无法创建本地映射目录: {error}"))?;
    let root = root
        .canonicalize()
        .map_err(|error| format!("无法解析本地映射目录: {error}"))?;
    let target = bounded_plugin_target(&root, plugin_id)?;
    require_mapping_directory(&target, "待删除映射")?;
    let manifest = PluginManifest::load(plugin_id, &target).map_err(|error| error.to_string())?;
    let transaction = TempBuilder::new()
        .prefix(MAPPING_ACTIVATION_PREFIX)
        .tempdir_in(&root)
        .map_err(|error| format!("无法创建映射删除事务: {error}"))?
        .keep();
    if let Err(error) = write_mapping_activation_journal(
        &transaction,
        &MappingActivationJournal {
            schema_version: 1,
            plugin_id: plugin_id.to_owned(),
            had_previous: true,
        },
    ) {
        let _ = fs::remove_dir_all(&transaction);
        return Err(error);
    }
    let previous = transaction.join("previous");
    if let Err(error) = fs::rename(&target, &previous) {
        let _ = fs::remove_dir_all(&transaction);
        return Err(format!("无法暂存待删除映射: {error}"));
    }
    Ok(ActivatedLocalMapping {
        manifest,
        root,
        target,
        transaction,
        had_previous: true,
        finalized: false,
    })
}

impl PreparedLocalMapping {
    pub(crate) fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    pub(crate) fn plugin_id(&self) -> &str {
        &self.definition.plugin_id
    }

    pub(crate) fn definition(&self) -> &LocalMappingDefinition {
        &self.definition
    }

    pub(crate) fn activate(self, root: &Path) -> Result<ActivatedLocalMapping, String> {
        let plugin_id = self.definition.plugin_id.clone();
        let target = bounded_plugin_target(root, &plugin_id)?;
        let staging_path = self.staging.keep();
        let had_previous = match fs::symlink_metadata(&target) {
            Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_dir() => true,
            Ok(_) => {
                let _ = fs::remove_dir_all(&staging_path);
                return Err("现有本地映射目标不是安全的真实目录".into());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => {
                let _ = fs::remove_dir_all(&staging_path);
                return Err(format!("无法检查现有本地映射: {error}"));
            }
        };
        let transaction = TempBuilder::new()
            .prefix(MAPPING_ACTIVATION_PREFIX)
            .tempdir_in(root)
            .map_err(|error| format!("无法创建映射事务目录: {error}"))?
            .keep();
        let previous = transaction.join("previous");
        if let Err(error) = write_mapping_activation_journal(
            &transaction,
            &MappingActivationJournal {
                schema_version: 1,
                plugin_id: plugin_id.clone(),
                had_previous,
            },
        ) {
            let _ = fs::remove_dir_all(&transaction);
            let _ = fs::remove_dir_all(&staging_path);
            return Err(error);
        }
        if had_previous {
            if let Err(error) = fs::rename(&target, &previous) {
                let _ = fs::remove_dir_all(&transaction);
                let _ = fs::remove_dir_all(&staging_path);
                return Err(format!("无法暂存旧映射: {error}"));
            }
        }
        if let Err(error) = fs::rename(&staging_path, &target) {
            if had_previous {
                let _ = fs::rename(&previous, &target);
            }
            let _ = fs::remove_dir_all(&transaction);
            return Err(format!("无法启用新映射: {error}"));
        }
        let loaded = match PluginManifest::load(&plugin_id, &target) {
            Ok(manifest) => manifest,
            Err(error) => {
                let failed = root.join(format!(".mapping-failed-{}", Uuid::new_v4()));
                let _ = fs::rename(&target, &failed);
                if had_previous {
                    let _ = fs::rename(&previous, &target);
                }
                let _ = fs::remove_dir_all(failed);
                let _ = fs::remove_dir_all(&transaction);
                return Err(error.to_string());
            }
        };
        Ok(ActivatedLocalMapping {
            manifest: loaded,
            root: root.to_path_buf(),
            target,
            transaction,
            had_previous,
            finalized: false,
        })
    }
}

pub(crate) fn prepare(
    root: &Path,
    mut definition: LocalMappingDefinition,
) -> Result<PreparedLocalMapping, String> {
    validate_definition_header(&definition)?;
    definition.schema_version = LOCAL_MAPPING_SCHEMA_VERSION;
    fs::create_dir_all(root).map_err(|error| format!("无法创建本地映射目录: {error}"))?;
    let staging = TempBuilder::new()
        .prefix(".mapping-stage-")
        .tempdir_in(root)
        .map_err(|error| format!("无法创建映射暂存目录: {error}"))?;
    let mut copied_names = HashSet::new();
    for (service_index, service) in definition.services.iter_mut().enumerate() {
        let main_type = service.resolved_main_type().to_ascii_lowercase();
        if matches!(main_type.as_str(), "dll" | "exe" | "bat") {
            service.main_class = copy_component(
                staging.path(),
                Path::new(&service.main_class),
                "components",
                service_index,
                &mut copied_names,
            )?;
        }
        let mut dependencies = Vec::with_capacity(service.deps.len());
        for (dependency_index, dependency) in service.deps.iter().enumerate() {
            if dependency == "*" {
                return Err("本地可视化映射不允许使用 * 依赖通配符".into());
            }
            dependencies.push(copy_component(
                staging.path(),
                Path::new(dependency),
                "dependencies",
                service_index.saturating_mul(1024) + dependency_index,
                &mut copied_names,
            )?);
        }
        service.deps = dependencies;
    }
    let metadata = PluginMetadata {
        schema_version: 1,
        plugin_id: definition.plugin_id.clone(),
        version: Version::parse("0.0.0-local").map_err(|error| error.to_string())?,
        desktop_version_requirement: Some(semver::VersionReq::STAR),
        display_name: definition.display_name.clone(),
    };
    write_json(staging.path().join(API_FILENAME), &definition.services)?;
    write_json(staging.path().join(PLUGIN_METADATA_FILENAME), &metadata)?;
    write_json(staging.path().join(LOCAL_MAPPING_FILENAME), &definition)?;
    let integrity = build_local_mapping_integrity(staging.path(), &definition.services)
        .map_err(|error| error.to_string())?;
    write_bytes(
        staging.path().join(LOCAL_MAPPING_INTEGRITY_FILENAME),
        &integrity,
    )?;
    let manifest = PluginManifest::load(&definition.plugin_id, staging.path())
        .map_err(|error| error.to_string())?;
    Ok(PreparedLocalMapping {
        staging,
        definition,
        manifest,
    })
}

pub(crate) fn inspect_component(path: &Path) -> Result<NativeComponentInspection, String> {
    let metadata = bounded_regular_file(path)?;
    let component_type = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut inspection = NativeComponentInspection {
        file_name: path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("component")
            .to_owned(),
        file_bytes: metadata.len(),
        component_type: component_type.clone(),
        architecture: None,
        exports: Vec::new(),
        warnings: Vec::new(),
    };
    if matches!(component_type.as_str(), "dll" | "exe" | "ocx") {
        if metadata.len() > MAX_PE_INSPECTION_BYTES {
            return Err("原生组件超过 512 MiB 检查上限".into());
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        fs::File::open(path)
            .and_then(|mut file| file.read_to_end(&mut bytes))
            .map_err(|error| format!("无法读取原生组件: {error}"))?;
        let pe = inspect_pe(&bytes)?;
        inspection.architecture = pe.architecture;
        inspection.exports = pe.exports;
        if inspection.exports.is_empty() && component_type == "dll" {
            inspection
                .warnings
                .push("未发现命名导出函数；可能需要 COM/OCX 或序号调用适配");
        }
    } else if component_type == "com" {
        inspection
            .warnings
            .push("COM 映射使用 ProgID 或 CLSID，参数类型仍需按组件文档配置");
    } else {
        inspection
            .warnings
            .push("当前文件类型不提供 PE 导出函数检查");
    }
    Ok(inspection)
}

pub(crate) fn export_bundle(
    root: &Path,
    plugin_id: &str,
    destination: &Path,
) -> Result<(), String> {
    let source = bounded_plugin_target(root, plugin_id)?;
    let source_metadata =
        fs::symlink_metadata(&source).map_err(|error| format!("无法读取本地映射: {error}"))?;
    if source_metadata.file_type().is_symlink() || !source_metadata.is_dir() {
        return Err(format!("本地映射 [{plugin_id}] 不存在或目录不安全"));
    }
    let parent = destination.parent().ok_or("导出目标缺少父目录")?;
    fs::create_dir_all(parent).map_err(|error| format!("无法创建导出目录: {error}"))?;
    let mut files = Vec::new();
    collect_bundle_files(&source, &source, &mut files)?;
    if files.len() > MAX_BUNDLE_ENTRIES {
        return Err(format!("映射文件超过 {MAX_BUNDLE_ENTRIES} 项导出上限"));
    }
    let total = files.iter().try_fold(0_u64, |total, (_, path)| {
        let metadata =
            fs::symlink_metadata(path).map_err(|error| format!("无法检查待导出文件: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("映射包不能包含符号链接或特殊文件".to_owned());
        }
        Ok::<u64, String>(total.saturating_add(metadata.len()))
    })?;
    if total > MAX_BUNDLE_BYTES {
        return Err("映射包内容超过 1 GiB 导出上限".into());
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut temporary = TempBuilder::new()
        .prefix(".ssdev-mapping-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|error| format!("无法创建导出暂存文件: {error}"))?;
    {
        let mut archive = ZipWriter::new(temporary.as_file_mut());
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .last_modified_time(DateTime::default())
            .unix_permissions(0o644);
        for (relative, path) in files {
            archive
                .start_file(relative, options)
                .map_err(|error| format!("无法写入映射包: {error}"))?;
            let mut input =
                File::open(&path).map_err(|error| format!("无法读取映射文件: {error}"))?;
            io::copy(&mut input, &mut archive)
                .map_err(|error| format!("无法压缩映射文件: {error}"))?;
        }
        archive
            .finish()
            .map_err(|error| format!("无法完成映射包: {error}"))?;
    }
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| format!("无法持久化映射包: {error}"))?;
    temporary
        .persist(destination)
        .map_err(|error| format!("无法保存映射包: {}", error.error))?;
    Ok(())
}

pub(crate) fn prepare_import(root: &Path, source: &Path) -> Result<PreparedLocalMapping, String> {
    let metadata = bounded_regular_file(source)?;
    if metadata.len() > MAX_BUNDLE_BYTES {
        return Err("映射包超过 1 GiB 导入上限".into());
    }
    fs::create_dir_all(root).map_err(|error| format!("无法创建本地映射目录: {error}"))?;
    let staging = TempBuilder::new()
        .prefix(".mapping-import-")
        .tempdir_in(root)
        .map_err(|error| format!("无法创建映射导入暂存目录: {error}"))?;
    extract_bundle(source, staging.path())?;
    let mut definition = load_stored_definition(staging.path())?;
    validate_definition_header(&definition)?;
    let mut manifest = PluginManifest::load(&definition.plugin_id, staging.path())
        .map_err(|error| error.to_string())?;
    validate_stored_manifest(&manifest, &definition)?;
    if definition.schema_version == 1 {
        definition.schema_version = LOCAL_MAPPING_SCHEMA_VERSION;
        let integrity = build_local_mapping_integrity(staging.path(), &definition.services)
            .map_err(|error| error.to_string())?;
        write_bytes_atomic(
            staging.path().join(LOCAL_MAPPING_INTEGRITY_FILENAME),
            &integrity,
        )?;
        write_json_atomic(staging.path().join(LOCAL_MAPPING_FILENAME), &definition)?;
        manifest = PluginManifest::load(&definition.plugin_id, staging.path())
            .map_err(|error| error.to_string())?;
        validate_stored_manifest(&manifest, &definition)?;
    }
    Ok(PreparedLocalMapping {
        staging,
        definition,
        manifest,
    })
}

pub(crate) fn import_bundle_sha256(source: &Path) -> Result<String, String> {
    let metadata = bounded_regular_file(source)?;
    if metadata.len() > MAX_BUNDLE_BYTES {
        return Err("映射包超过 1 GiB 导入上限".into());
    }
    let mut file = File::open(source).map_err(|error| format!("无法打开映射包: {error}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("无法计算映射包摘要: {error}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub(crate) fn load_definition(plugin_dir: &Path) -> Result<LocalMappingDefinition, String> {
    let mut definition = load_stored_definition(plugin_dir)?;
    for service in &mut definition.services {
        let main_type = service.resolved_main_type().to_ascii_lowercase();
        if matches!(main_type.as_str(), "dll" | "exe" | "bat") {
            service.main_class = plugin_dir
                .join(&service.main_class)
                .to_string_lossy()
                .into_owned();
        }
        for dependency in &mut service.deps {
            *dependency = plugin_dir.join(&*dependency).to_string_lossy().into_owned();
        }
    }
    Ok(definition)
}

pub(crate) fn upsert_debug_case(
    root: &Path,
    plugin_id: &str,
    debug_case: DebugCaseDefinition,
) -> Result<Vec<DebugCaseDefinition>, String> {
    let plugin_dir = installed_mapping_dir(root, plugin_id)?;
    let mut definition = load_validated_stored_definition(&plugin_dir, plugin_id)?;
    if definition.plugin_id != plugin_id {
        return Err("本地映射目录身份与映射定义不一致".into());
    }
    if let Some(existing) = definition
        .debug_cases
        .iter_mut()
        .find(|existing| existing.name == debug_case.name)
    {
        *existing = debug_case;
    } else {
        definition.debug_cases.push(debug_case);
    }
    validate_definition_header(&definition)?;
    write_json_atomic(plugin_dir.join(LOCAL_MAPPING_FILENAME), &definition)?;
    Ok(definition.debug_cases)
}

pub(crate) fn delete_debug_case(
    root: &Path,
    plugin_id: &str,
    case_name: &str,
) -> Result<Vec<DebugCaseDefinition>, String> {
    let plugin_dir = installed_mapping_dir(root, plugin_id)?;
    let mut definition = load_validated_stored_definition(&plugin_dir, plugin_id)?;
    let previous_len = definition.debug_cases.len();
    definition
        .debug_cases
        .retain(|debug_case| debug_case.name != case_name);
    if definition.debug_cases.len() == previous_len {
        return Err(format!("调试用例 [{case_name}] 不存在"));
    }
    validate_definition_header(&definition)?;
    write_json_atomic(plugin_dir.join(LOCAL_MAPPING_FILENAME), &definition)?;
    Ok(definition.debug_cases)
}

pub(crate) fn load_debug_cases(
    root: &Path,
    plugin_id: &str,
) -> Result<Vec<DebugCaseDefinition>, String> {
    let plugin_dir = installed_mapping_dir(root, plugin_id)?;
    let definition = load_validated_stored_definition(&plugin_dir, plugin_id)?;
    Ok(definition.debug_cases)
}

pub(crate) fn export_typescript(
    root: &Path,
    plugin_id: &str,
    destination: &Path,
) -> Result<(), String> {
    let plugin_dir = installed_mapping_dir(root, plugin_id)?;
    let definition = load_validated_stored_definition(&plugin_dir, plugin_id)?;
    if destination.extension().and_then(|value| value.to_str()) != Some("ts") {
        return Err("TypeScript 导出目标必须使用 .ts 扩展名".into());
    }
    let parent = destination.parent().ok_or("导出目标缺少父目录")?;
    if !parent.is_dir() {
        return Err("TypeScript 导出目录不存在".into());
    }
    let source = generate_typescript(&definition)?;
    let mut temporary = TempBuilder::new()
        .prefix(".ssdev-types-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|error| format!("无法创建 TypeScript 暂存文件: {error}"))?;
    temporary
        .write_all(source.as_bytes())
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|error| format!("无法持久化 TypeScript 文件: {error}"))?;
    temporary.persist_noclobber(destination).map_err(|error| {
        format!(
            "无法保存 TypeScript 文件（不会覆盖已有文件）: {}",
            error.error
        )
    })?;
    Ok(())
}

pub(crate) fn export_release_source(
    root: &Path,
    plugin_id: &str,
    destination_parent: &Path,
) -> Result<ReleaseSourceExportResult, String> {
    let plugin_dir = installed_mapping_dir(root, plugin_id)?;
    let definition = load_validated_stored_definition(&plugin_dir, plugin_id)?;
    let parent_metadata = fs::symlink_metadata(destination_parent)
        .map_err(|error| format!("无法读取发布源目标目录: {error}"))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err("发布源目标必须是已存在的真实目录".into());
    }
    let destination_parent = destination_parent
        .canonicalize()
        .map_err(|error| format!("无法解析发布源目标目录: {error}"))?;
    let managed_root = root
        .canonicalize()
        .map_err(|error| format!("无法解析本地映射根目录: {error}"))?;
    if destination_parent.starts_with(&managed_root) {
        return Err("发布源不能写入客户端管理的本地映射目录".into());
    }
    let destination = destination_parent.join(format!("{plugin_id}-release-source"));
    let matrix_seed = destination_parent.join(format!("{plugin_id}-matrix-seed.json"));
    ensure_release_target_is_new(&destination, "发布源目标")?;
    ensure_release_target_is_new(&matrix_seed, "黄金矩阵种子")?;
    let (matrix, seeded_case_count, placeholder_case_count, review_required_case_count) =
        release_matrix_seed(&definition)?;
    fs::create_dir(&destination).map_err(|error| format!("无法创建发布源目录: {error}"))?;
    let exported = (|| {
        write_json(destination.join(API_FILENAME), &definition.services)?;
        let mut copied = HashSet::new();
        let mut file_count = 1_usize;
        let mut bytes = fs::metadata(destination.join(API_FILENAME))
            .map_err(|error| format!("无法检查发布源 API: {error}"))?
            .len();
        for service in &definition.services {
            let main_type = service.resolved_main_type().to_ascii_lowercase();
            if matches!(main_type.as_str(), "dll" | "exe" | "bat") {
                copy_release_file(
                    &plugin_dir,
                    &destination,
                    Path::new(&service.main_class),
                    &mut copied,
                    &mut file_count,
                    &mut bytes,
                )?;
            }
            for dependency in &service.deps {
                copy_release_file(
                    &plugin_dir,
                    &destination,
                    Path::new(dependency),
                    &mut copied,
                    &mut file_count,
                    &mut bytes,
                )?;
            }
        }
        write_json_noclobber(&matrix_seed, &matrix)?;
        Ok::<_, String>((file_count, bytes))
    })();
    let (file_count, bytes) = match exported {
        Ok(result) => result,
        Err(error) => {
            let _ = fs::remove_dir_all(&destination);
            return Err(error);
        }
    };
    Ok(ReleaseSourceExportResult {
        destination,
        matrix_seed,
        file_count,
        bytes,
        seeded_case_count,
        placeholder_case_count,
        review_required_case_count,
    })
}

fn ensure_release_target_is_new(path: &Path, role: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(format!("{role}已存在，不会覆盖: {}", path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("无法检查{role}: {error}")),
    }
}

fn release_matrix_seed(
    definition: &LocalMappingDefinition,
) -> Result<(ReleaseMatrixSeed, usize, usize, usize), String> {
    let mut cases = Vec::new();
    let mut names = HashSet::new();
    let mut covered = HashSet::new();
    for debug_case in &definition.debug_cases {
        let service = definition
            .services
            .iter()
            .find(|service| service.service_id == debug_case.service_id)
            .ok_or_else(|| format!("调试用例 [{}] 的服务不存在", debug_case.name))?;
        let method = service
            .method(&debug_case.method)
            .ok_or_else(|| format!("调试用例 [{}] 的方法不存在", debug_case.name))?;
        names.insert(debug_case.name.clone());
        covered.insert((service.service_id.clone(), method.name.clone()));
        let mut parameters = debug_case.parameters.clone();
        for parameter in method
            .parameters
            .iter()
            .filter(|parameter| !parameter.name().starts_with('$'))
        {
            parameters
                .entry(parameter.name().to_owned())
                .or_insert_with(|| release_parameter_placeholder(parameter));
        }
        cases.push(ReleaseMatrixCase {
            name: debug_case.name.clone(),
            enabled: true,
            review_required: true,
            request: InvokeRequest {
                service_id: debug_case.service_id.clone(),
                method: debug_case.method.clone(),
                parameters,
            },
            expected: InvokeResponse {
                res_code: debug_case.expected_res_code,
                res_data: if debug_case.assert_res_data {
                    debug_case.expected_res_data.clone()
                } else {
                    serde_json::Value::String(DRAFT_RESPONSE_PLACEHOLDER.into())
                },
            },
        });
    }
    let seeded_case_count = cases.len();
    for service in &definition.services {
        for method in &service.methods {
            if covered.contains(&(service.service_id.clone(), method.name.clone())) {
                continue;
            }
            let name = unique_matrix_case_name(
                &format!("{}.{} release draft", service.service_id, method.name),
                &mut names,
            );
            let parameters = method
                .parameters
                .iter()
                .filter(|parameter| !parameter.name().starts_with('$'))
                .map(|parameter| {
                    (
                        parameter.name().to_owned(),
                        release_parameter_placeholder(parameter),
                    )
                })
                .collect();
            cases.push(ReleaseMatrixCase {
                name,
                enabled: true,
                review_required: true,
                request: InvokeRequest {
                    service_id: service.service_id.clone(),
                    method: method.alias.clone().unwrap_or_else(|| method.name.clone()),
                    parameters,
                },
                expected: InvokeResponse::success(DRAFT_RESPONSE_PLACEHOLDER),
            });
        }
    }
    if cases.is_empty() || cases.len() > MAX_RELEASE_MATRIX_CASES {
        return Err(format!(
            "黄金矩阵种子必须包含 1 到 {MAX_RELEASE_MATRIX_CASES} 个用例"
        ));
    }
    let placeholder_case_count = cases
        .iter()
        .filter(|case| release_case_has_draft_placeholder(case))
        .count();
    let review_required_case_count = cases.iter().filter(|case| case.review_required).count();
    Ok((
        ReleaseMatrixSeed {
            schema_version: 1,
            draft: true,
            cases,
        },
        seeded_case_count,
        placeholder_case_count,
        review_required_case_count,
    ))
}

fn release_case_has_draft_placeholder(case: &ReleaseMatrixCase) -> bool {
    case.request
        .parameters
        .values()
        .any(contains_draft_placeholder)
        || contains_draft_placeholder(&case.expected.res_data)
}

fn unique_matrix_case_name(preferred: &str, names: &mut HashSet<String>) -> String {
    if names.insert(preferred.to_owned()) {
        return preferred.to_owned();
    }
    for suffix in 2_u16..=u16::MAX {
        let candidate = format!("{preferred} ({suffix})");
        if names.insert(candidate.clone()) {
            return candidate;
        }
    }
    unreachable!("matrix case count is bounded well below u16::MAX")
}

fn release_parameter_placeholder(_: &ParameterDefinition) -> serde_json::Value {
    serde_json::Value::String(DRAFT_INPUT_PLACEHOLDER.into())
}

fn write_json_noclobber(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let parent = path.parent().ok_or("黄金矩阵种子缺少父目录")?;
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("无法生成黄金矩阵种子: {error}"))?;
    bytes.push(b'\n');
    let mut temporary = TempBuilder::new()
        .prefix(".ssdev-matrix-seed-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|error| format!("无法创建黄金矩阵种子暂存文件: {error}"))?;
    temporary
        .write_all(&bytes)
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|error| format!("无法持久化黄金矩阵种子: {error}"))?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| format!("无法保存黄金矩阵种子（不会覆盖已有文件）: {}", error.error))?;
    Ok(())
}

pub(crate) fn validate_installed_manifest(manifest: &PluginManifest) -> Result<(), String> {
    let definition = load_stored_definition(&manifest.plugin_dir)?;
    validate_definition_header(&definition)?;
    if definition.schema_version != LOCAL_MAPPING_SCHEMA_VERSION
        || manifest.local_mapping_integrity_sha256.is_none()
    {
        return Err("本地映射尚未建立运行时完整性清单".into());
    }
    validate_stored_manifest(manifest, &definition)
}

/// One-time upgrade for local mappings created before runtime content pinning.
/// The integrity file is committed first; schema 2 is only exposed after the
/// protected bytes are durable, so interrupted upgrades are safe to retry.
pub(crate) fn migrate_legacy_integrity(root: &Path) -> Result<usize, String> {
    fs::create_dir_all(root).map_err(|error| format!("无法创建本地映射目录: {error}"))?;
    let mut entries = fs::read_dir(root)
        .map_err(|error| format!("无法读取本地映射目录: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("无法读取本地映射目录项: {error}"))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    let mut migrated = 0_usize;
    let mut failed = 0_usize;
    for entry in entries {
        let file_type = entry
            .file_type()
            .map_err(|error| format!("无法检查本地映射目录项: {error}"))?;
        if !file_type.is_dir() || entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let plugin_dir = entry.path();
        let outcome: Result<bool, String> = (|| {
            require_mapping_directory(&plugin_dir, "本地映射")?;
            let mut definition = load_stored_definition(&plugin_dir)?;
            validate_definition_header(&definition)?;
            if definition.schema_version == LOCAL_MAPPING_SCHEMA_VERSION {
                return Ok(false);
            }
            let manifest = PluginManifest::load(&definition.plugin_id, &plugin_dir)
                .map_err(|error| error.to_string())?;
            validate_stored_manifest(&manifest, &definition)?;
            let integrity = build_local_mapping_integrity(&plugin_dir, &definition.services)
                .map_err(|error| error.to_string())?;
            write_bytes_atomic(
                plugin_dir.join(LOCAL_MAPPING_INTEGRITY_FILENAME),
                &integrity,
            )?;
            definition.schema_version = LOCAL_MAPPING_SCHEMA_VERSION;
            write_json_atomic(plugin_dir.join(LOCAL_MAPPING_FILENAME), &definition)?;
            let verified = PluginManifest::load(&definition.plugin_id, &plugin_dir)
                .map_err(|error| error.to_string())?;
            validate_installed_manifest(&verified)?;
            Ok(true)
        })();
        match outcome {
            Ok(true) => migrated = migrated.saturating_add(1),
            Ok(false) => {}
            Err(_) => failed = failed.saturating_add(1),
        }
    }
    if failed > 0 {
        tracing::warn!(
            event_code = "local-mapping-integrity-migration-failed",
            failure_count = failed,
            "legacy local mappings were quarantined during integrity migration"
        );
    }
    Ok(migrated)
}

fn load_stored_definition(plugin_dir: &Path) -> Result<LocalMappingDefinition, String> {
    let path = plugin_dir.join(LOCAL_MAPPING_FILENAME);
    let metadata =
        fs::symlink_metadata(&path).map_err(|error| format!("无法读取映射定义: {error}"))?;
    if !metadata.is_file() || metadata.len() > 4 * 1024 * 1024 {
        return Err("本地映射定义不是受支持的普通文件".into());
    }
    let bytes = fs::read(&path).map_err(|error| format!("无法读取映射定义: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("本地映射定义无效: {error}"))
}

pub(crate) fn bounded_plugin_target(root: &Path, plugin_id: &str) -> Result<PathBuf, String> {
    validate_plugin_id(plugin_id)?;
    Ok(root.join(plugin_id))
}

fn validate_plugin_id(plugin_id: &str) -> Result<(), String> {
    let path = Path::new(plugin_id);
    if plugin_id.trim().is_empty()
        || plugin_id.starts_with('.')
        || plugin_id.chars().count() > 128
        || plugin_id.chars().any(char::is_control)
        || plugin_id.contains(['/', '\\'])
        || path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        return Err("映射 ID 必须是 1 到 128 个字符的单段名称".into());
    }
    Ok(())
}

fn validate_definition_header(definition: &LocalMappingDefinition) -> Result<(), String> {
    if !matches!(definition.schema_version, 1 | LOCAL_MAPPING_SCHEMA_VERSION) {
        return Err(format!(
            "仅支持本地映射 schemaVersion 1 或 {LOCAL_MAPPING_SCHEMA_VERSION}"
        ));
    }
    validate_plugin_id(&definition.plugin_id)?;
    if definition.display_name.trim().is_empty() || definition.display_name.chars().count() > 128 {
        return Err("映射显示名称必须是 1 到 128 个字符".into());
    }
    validate_debug_cases(definition)
}

fn validate_debug_cases(definition: &LocalMappingDefinition) -> Result<(), String> {
    if definition.debug_cases.len() > MAX_DEBUG_CASES {
        return Err(format!("每个映射最多保存 {MAX_DEBUG_CASES} 个调试用例"));
    }
    let mut names = HashSet::new();
    for debug_case in &definition.debug_cases {
        if debug_case.name.trim().is_empty()
            || debug_case.name.chars().count() > 128
            || !names.insert(debug_case.name.as_str())
        {
            return Err(format!(
                "调试用例名称为空、重复或超过 128 个字符 [{}]",
                debug_case.name
            ));
        }
        let service = definition
            .services
            .iter()
            .find(|service| service.service_id == debug_case.service_id)
            .ok_or_else(|| format!("调试用例 [{}] 引用了不存在的服务", debug_case.name))?;
        let method = service
            .method(&debug_case.method)
            .ok_or_else(|| format!("调试用例 [{}] 引用了不存在的方法", debug_case.name))?;
        let allowed = method
            .parameters
            .iter()
            .map(ParameterDefinition::name)
            .filter(|name| !name.starts_with('$'))
            .collect::<HashSet<_>>();
        if let Some(unexpected) = debug_case
            .parameters
            .keys()
            .find(|name| !allowed.contains(name.as_str()))
        {
            return Err(format!(
                "调试用例 [{}] 包含未声明的输入参数 [{unexpected}]",
                debug_case.name
            ));
        }
        InvokeRequest {
            service_id: debug_case.service_id.clone(),
            method: debug_case.method.clone(),
            parameters: debug_case.parameters.clone(),
        }
        .validate()
        .map_err(|error| format!("调试用例 [{}] 无效: {error}", debug_case.name))?;
        validate_expected_res_data(debug_case)?;
    }
    Ok(())
}

fn validate_expected_res_data(debug_case: &DebugCaseDefinition) -> Result<(), String> {
    if !debug_case.assert_res_data {
        if !debug_case.expected_res_data.is_null() {
            return Err(format!(
                "调试用例 [{}] 未启用 ResData 断言，不应保存期望数据",
                debug_case.name
            ));
        }
        return Ok(());
    }
    let bytes = serde_json::to_vec(&debug_case.expected_res_data).map_err(|error| {
        format!(
            "调试用例 [{}] 的 ResData 断言无效: {error}",
            debug_case.name
        )
    })?;
    if bytes.len() > MAX_EXPECTED_RES_DATA_BYTES {
        return Err(format!(
            "调试用例 [{}] 的 ResData 断言超过 64 KiB",
            debug_case.name
        ));
    }
    let mut nodes = 0_usize;
    validate_expected_value(&debug_case.expected_res_data, 0, &mut nodes).map_err(|error| {
        format!(
            "调试用例 [{}] 的 ResData 断言无效: {error}",
            debug_case.name
        )
    })
}

fn validate_expected_value(
    value: &serde_json::Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), String> {
    if depth > MAX_EXPECTED_RES_DATA_DEPTH {
        return Err(format!("嵌套深度超过 {MAX_EXPECTED_RES_DATA_DEPTH} 层"));
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_EXPECTED_RES_DATA_NODES {
        return Err(format!("节点数超过 {MAX_EXPECTED_RES_DATA_NODES} 项"));
    }
    match value {
        serde_json::Value::Object(entries) => {
            for (key, value) in entries {
                if key.is_empty() || key.chars().count() > 256 || key.chars().any(char::is_control)
                {
                    return Err("对象字段名为空、过长或包含控制字符".into());
                }
                validate_expected_value(value, depth + 1, nodes)?;
            }
        }
        serde_json::Value::Array(items) => {
            for value in items {
                validate_expected_value(value, depth + 1, nodes)?;
            }
        }
        serde_json::Value::String(value) if value.len() > 16 * 1024 => {
            return Err("单个期望字符串超过 16 KiB".into());
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn res_data_mismatch_path(
    expected: &serde_json::Value,
    actual: &serde_json::Value,
) -> Option<String> {
    find_res_data_mismatch(expected, actual, "$".to_owned())
}

fn find_res_data_mismatch(
    expected: &serde_json::Value,
    actual: &serde_json::Value,
    path: String,
) -> Option<String> {
    match (expected, actual) {
        (serde_json::Value::Object(expected), serde_json::Value::Object(actual)) => {
            for (key, expected_value) in expected {
                let child_path = format!("{path}/{}", json_pointer_segment(key));
                let Some(actual_value) = actual.get(key) else {
                    return Some(child_path);
                };
                if let Some(mismatch) =
                    find_res_data_mismatch(expected_value, actual_value, child_path)
                {
                    return Some(mismatch);
                }
            }
            None
        }
        (serde_json::Value::Array(expected), serde_json::Value::Array(actual)) => {
            if expected.len() != actual.len() {
                return Some(path);
            }
            expected
                .iter()
                .zip(actual)
                .enumerate()
                .find_map(|(index, (expected, actual))| {
                    find_res_data_mismatch(expected, actual, format!("{path}/{index}"))
                })
        }
        _ if expected == actual => None,
        _ => Some(path),
    }
}

fn json_pointer_segment(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn installed_mapping_dir(root: &Path, plugin_id: &str) -> Result<PathBuf, String> {
    let plugin_dir = bounded_plugin_target(root, plugin_id)?;
    let metadata = fs::symlink_metadata(&plugin_dir)
        .map_err(|error| format!("无法读取本地映射 [{plugin_id}]: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("本地映射 [{plugin_id}] 不存在或目录不安全"));
    }
    Ok(plugin_dir)
}

fn copy_release_file(
    plugin_dir: &Path,
    destination: &Path,
    relative: &Path,
    copied: &mut HashSet<String>,
    file_count: &mut usize,
    bytes: &mut u64,
) -> Result<(), String> {
    validate_plugin_file(plugin_dir, relative)?;
    let portable = relative
        .components()
        .map(|component| match component {
            Component::Normal(value) => value.to_str().ok_or("发布源文件名不是有效文本"),
            Component::CurDir => Ok("."),
            _ => Err("发布源文件路径不安全"),
        })
        .collect::<Result<Vec<_>, _>>()?
        .join("/");
    if !copied.insert(portable.to_ascii_lowercase()) {
        return Ok(());
    }
    let source = plugin_dir.join(relative);
    let length = fs::metadata(&source)
        .map_err(|error| format!("无法检查发布源组件: {error}"))?
        .len();
    *bytes = bytes.saturating_add(length);
    *file_count = file_count.saturating_add(1);
    if *bytes > MAX_BUNDLE_BYTES || *file_count > MAX_BUNDLE_ENTRIES {
        return Err("发布源超过 1 GiB 或 512 个文件上限".into());
    }
    let target = destination.join(relative);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("无法创建发布源子目录: {error}"))?;
    }
    fs::copy(&source, &target).map_err(|error| format!("无法复制发布源组件: {error}"))?;
    File::open(&target)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("无法持久化发布源组件: {error}"))?;
    Ok(())
}

fn load_validated_stored_definition(
    plugin_dir: &Path,
    plugin_id: &str,
) -> Result<LocalMappingDefinition, String> {
    let definition = load_stored_definition(plugin_dir)?;
    validate_definition_header(&definition)?;
    let manifest =
        PluginManifest::load(plugin_id, plugin_dir).map_err(|error| error.to_string())?;
    validate_stored_manifest(&manifest, &definition)?;
    Ok(definition)
}

fn generate_typescript(definition: &LocalMappingDefinition) -> Result<String, String> {
    let mut output = String::from(
        "// Generated by SSDEV Desktop. Do not edit generated route constants.\n\
import type { InvokeResponse, JsonObject, JsonValue, PluginInvoker } from '@bsoft/ssdev-web-bridge'\n\n",
    );
    let mut methods = Vec::new();
    for (service_index, service) in definition.services.iter().enumerate() {
        for (method_index, method) in service.methods.iter().enumerate() {
            let request_name = method.alias.as_deref().unwrap_or(&method.name);
            let stem = format!(
                "{}{}{}{}",
                ts_pascal_identifier(&service.service_id),
                service_index + 1,
                ts_pascal_identifier(request_name),
                method_index + 1
            );
            let parameters_type = format!("{stem}Parameters");
            let data_type = format!("{stem}Data");
            output.push_str(&format!(
                "export type {parameters_type} = JsonObject & {{\n"
            ));
            for parameter in method
                .parameters
                .iter()
                .filter(|parameter| !parameter.name().starts_with('$'))
            {
                output.push_str(&format!(
                    "  {}: {}\n",
                    ts_property(parameter.name())?,
                    ts_parameter_type(parameter)
                ));
            }
            output.push_str("}\n\n");
            output.push_str(&format!("export type {data_type} = JsonObject & {{\n"));
            output.push_str(&format!(
                "  ReturnValue: {}\n",
                ts_native_type(&method.return_type)
            ));
            for parameter in method
                .parameters
                .iter()
                .filter(|parameter| parameter.name().starts_with('$'))
            {
                let name = parameter.name().trim_start_matches('$');
                output.push_str(&format!(
                    "  {}: {}\n",
                    ts_property(name)?,
                    ts_parameter_type(parameter)
                ));
            }
            output.push_str("}\n\n");
            methods.push((
                format!(
                    "{}{}{}{}",
                    ts_camel_identifier(&service.service_id),
                    service_index + 1,
                    ts_pascal_identifier(request_name),
                    method_index + 1
                ),
                parameters_type,
                data_type,
                service.service_id.clone(),
                request_name.to_owned(),
            ));
        }
    }
    output.push_str(&format!(
        "export class {}Client {{\n  constructor(private readonly bridge: PluginInvoker) {{}}\n\n",
        ts_pascal_identifier(&definition.display_name)
    ));
    for (name, parameters_type, data_type, service_id, method) in methods {
        output.push_str(&format!(
            "  {name}(parameters: {parameters_type}): Promise<InvokeResponse<{data_type}>> {{\n    return this.bridge.invokePlugin<{data_type}>({}, {}, parameters)\n  }}\n\n",
            serde_json::to_string(&service_id).map_err(|error| error.to_string())?,
            serde_json::to_string(&method).map_err(|error| error.to_string())?,
        ));
    }
    output.push_str("}\n");
    Ok(output)
}

fn ts_parameter_type(parameter: &ParameterDefinition) -> &'static str {
    match parameter {
        ParameterDefinition::Name(_) => "JsonValue",
        ParameterDefinition::Detailed(detail) => ts_native_type(&detail.parameter_type),
    }
}

fn ts_native_type(native: &str) -> &'static str {
    match native.trim().to_ascii_lowercase().as_str() {
        "string" => "string",
        "bool" | "boolean" => "boolean",
        "int" | "int32" | "long" | "uint" | "uint32" | "dword" | "float" | "double" => "number",
        "void" => "null",
        _ => "JsonValue",
    }
}

fn ts_property(value: &str) -> Result<String, String> {
    serde_json::to_string(value).map_err(|error| error.to_string())
}

fn ts_pascal_identifier(value: &str) -> String {
    let mut output = String::new();
    let mut uppercase = true;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            if uppercase {
                output.push(character.to_ascii_uppercase());
                uppercase = false;
            } else {
                output.push(character);
            }
        } else {
            uppercase = true;
        }
    }
    if output.is_empty() || output.starts_with(|character: char| character.is_ascii_digit()) {
        output.insert_str(0, "Generated");
    }
    output
}

fn ts_camel_identifier(value: &str) -> String {
    let mut output = ts_pascal_identifier(value);
    if let Some(first) = output.get_mut(0..1) {
        first.make_ascii_lowercase();
    }
    output
}

fn validate_stored_manifest(
    manifest: &PluginManifest,
    definition: &LocalMappingDefinition,
) -> Result<(), String> {
    if definition.schema_version == LOCAL_MAPPING_SCHEMA_VERSION
        && manifest.local_mapping_integrity_sha256.is_none()
    {
        return Err("schemaVersion 2 本地映射缺少运行时完整性清单".into());
    }
    if manifest.plugin_id != definition.plugin_id {
        return Err("本地映射目录身份与映射定义不一致".into());
    }
    if serde_json::to_value(&definition.services).map_err(|error| error.to_string())?
        != serde_json::to_value(&manifest.services).map_err(|error| error.to_string())?
    {
        return Err("本地映射的 local-mapping.json 与 api.json 不一致".into());
    }
    let metadata = manifest
        .metadata
        .as_ref()
        .ok_or("本地映射缺少 plugin.json")?;
    if metadata.version != Version::parse("0.0.0-local").map_err(|error| error.to_string())?
        || metadata.display_name != definition.display_name
    {
        return Err("本地映射元数据与映射定义不一致".into());
    }
    for service in &manifest.services {
        let main_type = service.resolved_main_type().to_ascii_lowercase();
        if matches!(main_type.as_str(), "dll" | "exe" | "bat") {
            validate_plugin_file(&manifest.plugin_dir, Path::new(&service.main_class))?;
        }
        for dependency in &service.deps {
            if dependency == "*" {
                return Err("本地映射不允许使用 * 依赖通配符".into());
            }
            validate_plugin_file(&manifest.plugin_dir, Path::new(dependency))?;
        }
    }
    Ok(())
}

fn validate_plugin_file(plugin_dir: &Path, relative: &Path) -> Result<(), String> {
    let root = plugin_dir
        .canonicalize()
        .map_err(|error| format!("无法解析映射目录: {error}"))?;
    let candidate = plugin_dir.join(relative);
    bounded_regular_file(&candidate)?;
    let candidate = candidate
        .canonicalize()
        .map_err(|error| format!("无法解析映射组件: {error}"))?;
    if candidate == root || !candidate.starts_with(&root) {
        return Err("映射组件越过本地映射目录".into());
    }
    Ok(())
}

fn copy_component(
    staging: &Path,
    source: &Path,
    category: &str,
    index: usize,
    copied_names: &mut HashSet<String>,
) -> Result<String, String> {
    let metadata = bounded_regular_file(source)?;
    if metadata.len() > MAX_COMPONENT_BYTES {
        return Err("单个本地组件不能超过 512 MiB".into());
    }
    let original = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("组件文件名不是有效文本")?;
    let safe_name = original
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    let relative = format!("{category}/{index}-{safe_name}");
    if !copied_names.insert(relative.clone()) {
        return Err("组件目标文件名发生冲突".into());
    }
    let destination = staging.join(&relative);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("无法创建组件目录: {error}"))?;
    }
    fs::copy(source, &destination).map_err(|error| format!("无法复制组件: {error}"))?;
    Ok(relative)
}

fn collect_bundle_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<(String, PathBuf)>,
) -> Result<(), String> {
    let mut entries = fs::read_dir(current)
        .map_err(|error| format!("无法枚举映射目录: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("无法读取映射目录项: {error}"))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|error| format!("无法检查映射目录项: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("映射目录不能包含符号链接".into());
        }
        if metadata.is_dir() {
            collect_bundle_files(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "映射文件越过导出目录")?;
            let portable = relative
                .components()
                .map(|component| match component {
                    Component::Normal(value) => value.to_str().ok_or("映射文件名不是有效文本"),
                    _ => Err("映射文件路径不安全"),
                })
                .collect::<Result<Vec<_>, _>>()?
                .join("/");
            files.push((portable, path));
        } else {
            return Err("映射目录包含不支持的特殊文件".into());
        }
    }
    Ok(())
}

fn extract_bundle(source: &Path, destination: &Path) -> Result<(), String> {
    let file = File::open(source).map_err(|error| format!("无法打开映射包: {error}"))?;
    let mut archive = ZipArchive::new(file).map_err(|error| format!("映射包格式无效: {error}"))?;
    if archive.len() > MAX_BUNDLE_ENTRIES {
        return Err(format!("映射包超过 {MAX_BUNDLE_ENTRIES} 项导入上限"));
    }
    let mut total = 0_u64;
    let mut paths = HashSet::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| format!("无法读取映射包条目: {error}"))?;
        if entry.encrypted() {
            return Err("不支持加密映射包".into());
        }
        let relative = entry
            .enclosed_name()
            .ok_or_else(|| format!("映射包包含不安全路径 [{}]", entry.name()))?;
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err("映射包包含无效路径".into());
        }
        let portable = relative
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        if !paths.insert(portable) {
            return Err(format!("映射包包含重复路径 {relative:?}"));
        }
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err(format!("映射包包含符号链接 {relative:?}"));
        }
        let output = destination.join(&relative);
        if entry.is_dir() {
            fs::create_dir_all(&output).map_err(|error| format!("无法创建导入目录: {error}"))?;
            continue;
        }
        let declared_size = entry.size();
        total = total.saturating_add(declared_size);
        if total > MAX_BUNDLE_BYTES {
            return Err("映射包解压内容超过 1 GiB 上限".into());
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent).map_err(|error| format!("无法创建导入目录: {error}"))?;
        }
        let mut output_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&output)
            .map_err(|error| format!("无法创建导入文件: {error}"))?;
        let copied = io::copy(
            &mut entry.by_ref().take(declared_size.saturating_add(1)),
            &mut output_file,
        )
        .map_err(|error| format!("无法解压映射文件: {error}"))?;
        if copied != declared_size {
            return Err(format!("映射包条目大小不一致 {relative:?}"));
        }
        output_file
            .sync_all()
            .map_err(|error| format!("无法持久化导入文件: {error}"))?;
    }
    Ok(())
}

fn bounded_regular_file(path: &Path) -> Result<fs::Metadata, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| format!("无法读取组件: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("组件必须是普通文件且不能是符号链接".into());
    }
    Ok(metadata)
}

fn write_json(path: PathBuf, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    let mut file = fs::File::create(&path).map_err(|error| format!("无法写入映射文件: {error}"))?;
    file.write_all(&bytes)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("无法持久化映射文件: {error}"))
}

fn write_bytes(path: PathBuf, bytes: &[u8]) -> Result<(), String> {
    let mut file = fs::File::create(&path).map_err(|error| format!("无法写入映射文件: {error}"))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("无法持久化映射文件: {error}"))
}

fn write_bytes_atomic(path: PathBuf, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("映射完整性清单缺少父目录")?;
    let mut temporary = NamedTempFile::new_in(parent)
        .map_err(|error| format!("无法创建映射完整性清单暂存文件: {error}"))?;
    temporary
        .write_all(bytes)
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|error| format!("无法持久化映射完整性清单: {error}"))?;
    temporary
        .persist(&path)
        .map_err(|error| format!("无法替换映射完整性清单: {}", error.error))?;
    Ok(())
}

fn write_json_atomic(path: PathBuf, value: &impl Serialize) -> Result<(), String> {
    let parent = path.parent().ok_or("映射定义缺少父目录")?;
    let mut temporary = NamedTempFile::new_in(parent)
        .map_err(|error| format!("无法创建映射定义暂存文件: {error}"))?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), value)
        .map_err(|error| format!("无法序列化映射定义: {error}"))?;
    temporary
        .write_all(b"\n")
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|error| format!("无法持久化映射定义: {error}"))?;
    temporary
        .persist(&path)
        .map_err(|error| format!("无法替换映射定义: {}", error.error))?;
    Ok(())
}

struct PeInspection {
    architecture: Option<&'static str>,
    exports: Vec<String>,
}

fn inspect_pe(bytes: &[u8]) -> Result<PeInspection, String> {
    if bytes.get(0..2) != Some(b"MZ") {
        return Err("文件不是有效的 Windows PE 组件".into());
    }
    let pe_offset = read_u32(bytes, 0x3c)? as usize;
    if bytes.get(pe_offset..pe_offset.saturating_add(4)) != Some(b"PE\0\0") {
        return Err("文件缺少有效的 PE 标头".into());
    }
    let coff = pe_offset + 4;
    let machine = read_u16(bytes, coff)?;
    let architecture = match machine {
        0x014c => Some("x86"),
        0x8664 => Some("x64"),
        _ => None,
    };
    let section_count = read_u16(bytes, coff + 2)? as usize;
    let optional_size = read_u16(bytes, coff + 16)? as usize;
    let optional = coff + 20;
    let magic = read_u16(bytes, optional)?;
    let data_directory = match magic {
        0x10b => optional + 96,
        0x20b => optional + 112,
        _ => return Err("PE 可选标头类型不受支持".into()),
    };
    let export_rva = read_u32(bytes, data_directory)?;
    if export_rva == 0 {
        return Ok(PeInspection {
            architecture,
            exports: Vec::new(),
        });
    }
    let sections_offset = optional + optional_size;
    let sections = (0..section_count)
        .map(|index| {
            let offset = sections_offset + index * 40;
            Ok((
                read_u32(bytes, offset + 12)?,
                read_u32(bytes, offset + 8)?,
                read_u32(bytes, offset + 20)?,
                read_u32(bytes, offset + 16)?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let export_offset = rva_to_offset(export_rva, &sections, bytes.len())?;
    let name_count = (read_u32(bytes, export_offset + 24)? as usize).min(MAX_EXPORTS);
    let names_rva = read_u32(bytes, export_offset + 32)?;
    let names_offset = rva_to_offset(names_rva, &sections, bytes.len())?;
    let mut exports = Vec::with_capacity(name_count);
    for index in 0..name_count {
        let name_rva = read_u32(bytes, names_offset + index * 4)?;
        let name_offset = rva_to_offset(name_rva, &sections, bytes.len())?;
        if let Some(name) = read_c_string(bytes, name_offset, 1024) {
            exports.push(name);
        }
    }
    exports.sort();
    exports.dedup();
    Ok(PeInspection {
        architecture,
        exports,
    })
}

fn rva_to_offset(
    rva: u32,
    sections: &[(u32, u32, u32, u32)],
    file_len: usize,
) -> Result<usize, String> {
    for (virtual_address, virtual_size, raw_offset, raw_size) in sections {
        let span = (*virtual_size).max(*raw_size);
        if rva >= *virtual_address && rva < virtual_address.saturating_add(span) {
            let offset = raw_offset.saturating_add(rva - virtual_address) as usize;
            if offset < file_len {
                return Ok(offset);
            }
        }
    }
    Err("PE 数据目录超出文件边界".into())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let value = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or("PE 标头被截断")?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or("PE 标头被截断")?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_c_string(bytes: &[u8], offset: usize, limit: usize) -> Option<String> {
    let available = bytes.get(offset..offset.saturating_add(limit).min(bytes.len()))?;
    let end = available.iter().position(|byte| *byte == 0)?;
    std::str::from_utf8(&available[..end])
        .ok()
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_definition(component: &Path) -> LocalMappingDefinition {
        serde_json::from_value(serde_json::json!({
            "schemaVersion": 1,
            "pluginId": "reader.local",
            "displayName": "Reader local mapping",
            "services": [{
                "serviceId": "ReaderService",
                "mainClass": component,
                "mainType": "bat",
                "architecture": "x86",
                "charset": "utf8",
                "callingConvention": "system",
                "cacheable": false,
                "timeout": 5000,
                "deps": [],
                "methods": [{
                    "name": "read",
                    "returnType": "string",
                    "parameters": [{ "name": "port", "type": "string", "len": 32 }],
                    "props": []
                }]
            }]
        }))
        .unwrap()
    }

    #[test]
    fn plugin_ids_cannot_escape_the_local_mapping_root() {
        assert!(bounded_plugin_target(Path::new("root"), "reader.local").is_ok());
        assert!(bounded_plugin_target(Path::new("root"), "../reader").is_err());
        assert!(bounded_plugin_target(Path::new("root"), ".hidden").is_err());
    }

    #[test]
    fn rejects_non_pe_components_without_loading_them() {
        assert!(inspect_pe(b"not-a-pe").is_err());
    }

    #[test]
    fn mapping_bundle_round_trip_preserves_components_and_definition() {
        let source = tempfile::tempdir().unwrap();
        let component = source.path().join("reader.bat");
        fs::write(&component, b"@echo off\r\necho ready\r\n").unwrap();
        let active_root = tempfile::tempdir().unwrap();
        let prepared = prepare(active_root.path(), fixture_definition(&component)).unwrap();
        let activated = prepared.activate(active_root.path()).unwrap();
        activated.commit().unwrap();
        let installed_dir = active_root.path().join("reader.local");
        let installed = PluginManifest::load("reader.local", &installed_dir).unwrap();
        assert!(installed.local_mapping_integrity_sha256.is_some());
        assert_eq!(
            load_stored_definition(&installed_dir)
                .unwrap()
                .schema_version,
            2
        );

        let loaded = load_definition(&active_root.path().join("reader.local")).unwrap();
        assert!(Path::new(&loaded.services[0].main_class).is_absolute());

        let export_dir = tempfile::tempdir().unwrap();
        let bundle = export_dir.path().join("reader.ssdev-mapping");
        export_bundle(active_root.path(), "reader.local", &bundle).unwrap();
        assert!(bundle.is_file());
        let exported_sha256 = import_bundle_sha256(&bundle).unwrap();
        assert_eq!(exported_sha256.len(), 64);

        let import_root = tempfile::tempdir().unwrap();
        let imported = prepare_import(import_root.path(), &bundle).unwrap();
        assert_eq!(imported.plugin_id(), "reader.local");
        assert_eq!(imported.manifest().services[0].service_id, "ReaderService");
        assert!(imported
            .manifest()
            .plugin_dir
            .join(&imported.manifest().services[0].main_class)
            .is_file());
        fs::write(&bundle, b"changed bundle").unwrap();
        assert_ne!(exported_sha256, import_bundle_sha256(&bundle).unwrap());
        assert!(import_bundle_sha256(export_dir.path()).is_err());
    }

    #[test]
    fn legacy_mapping_migration_is_one_time_and_schema_two_fails_closed() {
        let source = tempfile::tempdir().unwrap();
        let component = source.path().join("reader.bat");
        fs::write(&component, b"legacy mapping").unwrap();
        let active_root = tempfile::tempdir().unwrap();
        prepare(active_root.path(), fixture_definition(&component))
            .unwrap()
            .activate(active_root.path())
            .unwrap()
            .commit()
            .unwrap();
        let plugin_dir = active_root.path().join("reader.local");
        let mut definition = load_stored_definition(&plugin_dir).unwrap();
        definition.schema_version = 1;
        write_json_atomic(plugin_dir.join(LOCAL_MAPPING_FILENAME), &definition).unwrap();
        fs::remove_file(plugin_dir.join(LOCAL_MAPPING_INTEGRITY_FILENAME)).unwrap();

        assert_eq!(migrate_legacy_integrity(active_root.path()).unwrap(), 1);
        assert_eq!(migrate_legacy_integrity(active_root.path()).unwrap(), 0);
        let manifest = PluginManifest::load("reader.local", &plugin_dir).unwrap();
        validate_installed_manifest(&manifest).unwrap();

        fs::remove_file(plugin_dir.join(LOCAL_MAPPING_INTEGRITY_FILENAME)).unwrap();
        assert_eq!(migrate_legacy_integrity(active_root.path()).unwrap(), 0);
        let unpinned = PluginManifest::load("reader.local", &plugin_dir).unwrap();
        assert!(validate_installed_manifest(&unpinned).is_err());

        let broken = active_root.path().join("broken.local");
        fs::create_dir(&broken).unwrap();
        let mut broken_definition = definition;
        broken_definition.plugin_id = "broken.local".into();
        broken_definition.schema_version = 1;
        write_json(broken.join(LOCAL_MAPPING_FILENAME), &broken_definition).unwrap();
        assert_eq!(migrate_legacy_integrity(active_root.path()).unwrap(), 0);
    }

    #[test]
    fn startup_recovery_rolls_back_an_interrupted_mapping_upgrade() {
        let source = tempfile::tempdir().unwrap();
        let component = source.path().join("reader.bat");
        let active_root = tempfile::tempdir().unwrap();
        fs::write(&component, b"old mapping").unwrap();
        prepare(active_root.path(), fixture_definition(&component))
            .unwrap()
            .activate(active_root.path())
            .unwrap()
            .commit()
            .unwrap();
        fs::write(&component, b"new mapping").unwrap();
        let activation = prepare(active_root.path(), fixture_definition(&component))
            .unwrap()
            .activate(active_root.path())
            .unwrap();
        std::mem::forget(activation);

        let report =
            recover_incomplete_mapping_activations(active_root.path(), &HashSet::new()).unwrap();
        assert_eq!(report.rolled_back_activations, 1);
        assert_eq!(
            fs::read(
                active_root
                    .path()
                    .join("reader.local/components/0-reader.bat")
            )
            .unwrap(),
            b"old mapping"
        );
    }

    #[test]
    fn mapping_removal_can_rollback_commit_and_recover_after_a_crash() {
        let source = tempfile::tempdir().unwrap();
        let component = source.path().join("reader.bat");
        fs::write(&component, b"installed mapping").unwrap();
        let active_root = tempfile::tempdir().unwrap();
        prepare(active_root.path(), fixture_definition(&component))
            .unwrap()
            .activate(active_root.path())
            .unwrap()
            .commit()
            .unwrap();
        let target = active_root.path().join("reader.local");

        let removal = prepare_removal(active_root.path(), "reader.local").unwrap();
        assert!(!target.exists());
        removal.rollback().unwrap();
        assert!(target.join(LOCAL_MAPPING_FILENAME).is_file());

        let removal = prepare_removal(active_root.path(), "reader.local").unwrap();
        std::mem::forget(removal);
        let report =
            recover_incomplete_mapping_activations(active_root.path(), &HashSet::new()).unwrap();
        assert_eq!(report.rolled_back_activations, 1);
        assert!(target.join(LOCAL_MAPPING_FILENAME).is_file());

        prepare_removal(active_root.path(), "reader.local")
            .unwrap()
            .commit()
            .unwrap();
        assert!(!target.exists());
    }

    #[cfg(unix)]
    #[test]
    fn mapping_activation_refuses_a_symbolic_link_target() {
        use std::os::unix::fs::symlink;

        let source = tempfile::tempdir().unwrap();
        let component = source.path().join("reader.bat");
        fs::write(&component, b"new mapping").unwrap();
        let active_root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), active_root.path().join("reader.local")).unwrap();

        assert!(prepare(active_root.path(), fixture_definition(&component))
            .unwrap()
            .activate(active_root.path())
            .is_err());
        assert!(outside.path().is_dir());
    }

    #[test]
    fn committed_set_recovery_keeps_the_new_mapping() {
        let source = tempfile::tempdir().unwrap();
        let component = source.path().join("reader.bat");
        let active_root = tempfile::tempdir().unwrap();
        fs::write(&component, b"old mapping").unwrap();
        prepare(active_root.path(), fixture_definition(&component))
            .unwrap()
            .activate(active_root.path())
            .unwrap()
            .commit()
            .unwrap();
        fs::write(&component, b"new mapping").unwrap();
        let activation = prepare(active_root.path(), fixture_definition(&component))
            .unwrap()
            .activate(active_root.path())
            .unwrap();
        std::mem::forget(activation);

        let report = recover_incomplete_mapping_activations(
            active_root.path(),
            &HashSet::from(["reader.local".to_owned()]),
        )
        .unwrap();
        assert_eq!(report.finalized_activations, 1);
        assert_eq!(
            fs::read(
                active_root
                    .path()
                    .join("reader.local/components/0-reader.bat")
            )
            .unwrap(),
            b"new mapping"
        );
    }

    #[test]
    fn installed_mapping_rejects_a_definition_manifest_mismatch() {
        let source = tempfile::tempdir().unwrap();
        let component = source.path().join("reader.bat");
        fs::write(&component, b"@echo off\r\n").unwrap();
        let active_root = tempfile::tempdir().unwrap();
        let prepared = prepare(active_root.path(), fixture_definition(&component)).unwrap();
        prepared
            .activate(active_root.path())
            .unwrap()
            .commit()
            .unwrap();
        let plugin_dir = active_root.path().join("reader.local");
        let manifest = PluginManifest::load("reader.local", &plugin_dir).unwrap();
        assert!(validate_installed_manifest(&manifest).is_ok());

        let definition_path = plugin_dir.join(LOCAL_MAPPING_FILENAME);
        let mut definition: serde_json::Value =
            serde_json::from_slice(&fs::read(&definition_path).unwrap()).unwrap();
        definition["displayName"] = serde_json::json!("tampered");
        fs::write(&definition_path, serde_json::to_vec(&definition).unwrap()).unwrap();
        assert!(validate_installed_manifest(&manifest).is_err());
    }

    #[test]
    fn debug_cases_are_validated_and_updated_atomically() {
        let source = tempfile::tempdir().unwrap();
        let component = source.path().join("reader.bat");
        fs::write(&component, b"@echo off\r\n").unwrap();
        let active_root = tempfile::tempdir().unwrap();
        prepare(active_root.path(), fixture_definition(&component))
            .unwrap()
            .activate(active_root.path())
            .unwrap()
            .commit()
            .unwrap();

        let debug_case = DebugCaseDefinition {
            name: "synthetic port".into(),
            service_id: "ReaderService".into(),
            method: "read".into(),
            parameters: serde_json::from_value(serde_json::json!({ "port": "TEST" })).unwrap(),
            expected_res_code: 0,
            assert_res_data: true,
            expected_res_data: serde_json::json!({ "ReturnValue": 0 }),
        };
        assert_eq!(
            upsert_debug_case(active_root.path(), "reader.local", debug_case.clone()).unwrap(),
            vec![debug_case]
        );
        assert!(upsert_debug_case(
            active_root.path(),
            "reader.local",
            DebugCaseDefinition {
                name: "invalid".into(),
                service_id: "ReaderService".into(),
                method: "read".into(),
                parameters: serde_json::from_value(serde_json::json!({ "secret": "value" }))
                    .unwrap(),
                expected_res_code: 0,
                assert_res_data: false,
                expected_res_data: serde_json::Value::Null,
            }
        )
        .is_err());
        assert!(
            delete_debug_case(active_root.path(), "reader.local", "synthetic port")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn generated_typescript_uses_bridge_types_and_public_routes() {
        let source = tempfile::tempdir().unwrap();
        let component = source.path().join("reader.bat");
        fs::write(&component, b"@echo off\r\n").unwrap();
        let mut definition = fixture_definition(&component);
        definition.services[0].methods[0].parameters.push(
            serde_json::from_value(serde_json::json!({
                "name": "$message",
                "type": "string",
                "len": 256
            }))
            .unwrap(),
        );
        let source = generate_typescript(&definition).unwrap();
        assert!(source.contains("from '@bsoft/ssdev-web-bridge'"));
        assert!(source.contains("PluginInvoker"));
        assert!(!source.contains("SsdevDesktopBridge"));
        assert!(source.contains("\"port\": string"));
        assert!(source.contains("\"message\": string"));
        assert!(source.contains(
            "invokePlugin<ReaderService1Read1Data>(\"ReaderService\", \"read\", parameters)"
        ));
        assert!(!source.contains("$message"));
    }

    #[test]
    fn res_data_assertions_match_object_subsets_without_disclosing_values() {
        let actual = serde_json::json!({
            "ReturnValue": 0,
            "device": { "state": "ready", "serial": "sensitive" },
            "ignored": true
        });
        assert_eq!(
            res_data_mismatch_path(
                &serde_json::json!({ "ReturnValue": 0, "device": { "state": "ready" } }),
                &actual
            ),
            None
        );
        assert_eq!(
            res_data_mismatch_path(&serde_json::json!({ "ReturnValue": 1 }), &actual),
            Some("$/ReturnValue".into())
        );
        assert_eq!(
            res_data_mismatch_path(
                &serde_json::json!({ "device": { "missing/key": true } }),
                &actual
            ),
            Some("$/device/missing~1key".into())
        );
    }

    #[test]
    fn disabled_res_data_assertions_cannot_hide_persisted_values() {
        let source = tempfile::tempdir().unwrap();
        let component = source.path().join("reader.bat");
        fs::write(&component, b"@echo off\r\n").unwrap();
        let mut definition = fixture_definition(&component);
        definition.debug_cases.push(DebugCaseDefinition {
            name: "hidden value".into(),
            service_id: "ReaderService".into(),
            method: "read".into(),
            parameters: serde_json::from_value(serde_json::json!({ "port": "TEST" })).unwrap(),
            expected_res_code: 0,
            assert_res_data: false,
            expected_res_data: serde_json::json!({ "secret": "must not persist" }),
        });
        assert!(validate_definition_header(&definition).is_err());
    }

    #[test]
    fn release_matrix_counts_seeded_cases_that_still_need_an_exact_response() {
        let source = tempfile::tempdir().unwrap();
        let component = source.path().join("reader.bat");
        fs::write(&component, b"@echo off\r\n").unwrap();
        let mut definition = fixture_definition(&component);
        definition.debug_cases.push(DebugCaseDefinition {
            name: "status-only field test".into(),
            service_id: "ReaderService".into(),
            method: "read".into(),
            parameters: serde_json::Map::new(),
            expected_res_code: 0,
            assert_res_data: false,
            expected_res_data: serde_json::Value::Null,
        });

        let (matrix, seeded, placeholders, reviews) = release_matrix_seed(&definition).unwrap();

        assert_eq!(matrix.cases.len(), 1);
        assert_eq!(seeded, 1);
        assert_eq!(placeholders, 1);
        assert_eq!(reviews, 1);
        assert!(matrix.cases[0].review_required);
        assert!(release_case_has_draft_placeholder(&matrix.cases[0]));
        assert_eq!(
            matrix.cases[0].request.parameters["port"],
            DRAFT_INPUT_PLACEHOLDER
        );
    }

    #[test]
    fn release_source_contains_only_api_and_referenced_native_files() {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine;
        use ed25519_dalek::SigningKey;
        use ssdev_plugin_tool::{prepare as prepare_release, PrepareOptions};

        let source = tempfile::tempdir().unwrap();
        let component = source.path().join("reader.bat");
        fs::write(&component, b"@echo off\r\necho ready\r\n").unwrap();
        let active_root = tempfile::tempdir().unwrap();
        let mut definition = fixture_definition(&component);
        definition.debug_cases.push(DebugCaseDefinition {
            name: "reader known response".into(),
            service_id: "ReaderService".into(),
            method: "read".into(),
            parameters: serde_json::from_value(serde_json::json!({ "port": "COM1" })).unwrap(),
            expected_res_code: 0,
            assert_res_data: true,
            expected_res_data: serde_json::json!({ "ReturnValue": "ready" }),
        });
        prepare(active_root.path(), definition)
            .unwrap()
            .activate(active_root.path())
            .unwrap()
            .commit()
            .unwrap();
        let plugin_dir = active_root.path().join("reader.local");
        fs::write(plugin_dir.join("unreferenced.txt"), b"must not ship").unwrap();

        let output = tempfile::tempdir().unwrap();
        let result =
            export_release_source(active_root.path(), "reader.local", output.path()).unwrap();
        assert_eq!(
            result.destination,
            output
                .path()
                .canonicalize()
                .unwrap()
                .join("reader.local-release-source")
        );
        assert_eq!(result.file_count, 2);
        assert_eq!(result.seeded_case_count, 1);
        assert_eq!(result.placeholder_case_count, 0);
        assert_eq!(result.review_required_case_count, 1);
        assert_eq!(
            result.matrix_seed,
            output
                .path()
                .canonicalize()
                .unwrap()
                .join("reader.local-matrix-seed.json")
        );
        let matrix_seed: serde_json::Value =
            serde_json::from_slice(&fs::read(&result.matrix_seed).unwrap()).unwrap();
        assert_eq!(matrix_seed["draft"], true);
        assert_eq!(matrix_seed["cases"][0]["name"], "reader known response");
        assert_eq!(
            matrix_seed["cases"][0]["expected"]["ResData"]["ReturnValue"],
            "ready"
        );
        assert!(result.destination.join(API_FILENAME).is_file());
        assert!(result.destination.join("components/0-reader.bat").is_file());
        assert!(!result.destination.join(LOCAL_MAPPING_FILENAME).exists());
        assert!(!result.destination.join(PLUGIN_METADATA_FILENAME).exists());
        assert!(!result.destination.join("unreferenced.txt").exists());

        let signing_key = SigningKey::from_bytes(&[41; 32]);
        let trust_store = output.path().join("trust.json");
        fs::write(
            &trust_store,
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "keys": [{
                    "keyId": "release-key",
                    "algorithm": "ed25519",
                    "publicKey": BASE64.encode(signing_key.verifying_key().to_bytes()),
                    "purposes": ["plugin"],
                    "status": "active"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let prepared = prepare_release(&PrepareOptions {
            source: &result.destination,
            staging: &output.path().join("signed-stage"),
            request: &output.path().join("signing-request.json"),
            matrix_template: &output.path().join("matrix.json"),
            plugin_id: "reader.local",
            version: "1.0.0",
            desktop_version_requirement: ">=0.1.0, <0.2.0",
            display_name: "Reader release",
            key_id: "release-key",
            trust_store: &trust_store,
            matrix_seed: Some(&result.matrix_seed),
        })
        .unwrap();
        assert_eq!(prepared.plugin_id, "reader.local");
        assert_eq!(prepared.method_count, 1);
        assert!(prepared.matrix_seeded);
        assert_eq!(prepared.matrix_case_count, 1);
        assert_eq!(prepared.matrix_placeholder_case_count, 0);
        assert_eq!(prepared.matrix_review_required_case_count, 1);

        assert!(export_release_source(active_root.path(), "reader.local", output.path()).is_err());
        assert!(
            export_release_source(active_root.path(), "reader.local", active_root.path()).is_err()
        );
    }
}
