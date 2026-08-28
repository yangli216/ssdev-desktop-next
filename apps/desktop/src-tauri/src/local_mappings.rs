use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use semver::Version;
use serde::{Deserialize, Serialize};
use tempfile::{Builder as TempBuilder, NamedTempFile, TempDir};
use uuid::Uuid;
use webplus_plugin_config::{
    ParameterDefinition, PluginManifest, PluginMetadata, ServiceDefinition, API_FILENAME,
    PLUGIN_METADATA_FILENAME,
};
use webplus_protocol::InvokeRequest;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter};

const LOCAL_MAPPING_FILENAME: &str = "local-mapping.json";
const MAX_COMPONENT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EXPORTS: usize = 4096;
const MAX_PE_INSPECTION_BYTES: u64 = 512 * 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_BUNDLE_ENTRIES: usize = 512;
const MAX_DEBUG_CASES: usize = 32;
const MAX_EXPECTED_RES_DATA_BYTES: usize = 64 * 1024;
const MAX_EXPECTED_RES_DATA_DEPTH: usize = 16;
const MAX_EXPECTED_RES_DATA_NODES: usize = 512;

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

pub(crate) struct PreparedLocalMapping {
    staging: TempDir,
    definition: LocalMappingDefinition,
    manifest: PluginManifest,
}

pub(crate) struct ActivatedLocalMapping {
    manifest: PluginManifest,
    target: PathBuf,
    backup: Option<PathBuf>,
}

impl ActivatedLocalMapping {
    pub(crate) fn commit(mut self) -> Result<PluginManifest, String> {
        if let Some(backup) = self.backup.take() {
            if let Err(error) = fs::remove_dir_all(&backup) {
                let failed = self
                    .target
                    .parent()
                    .ok_or("映射目录缺少父目录")?
                    .join(format!(".mapping-commit-failed-{}", Uuid::new_v4()));
                fs::rename(&self.target, &failed).map_err(|rollback| {
                    format!("无法清理旧映射: {error}; 撤销新映射失败: {rollback}")
                })?;
                if let Err(rollback) = fs::rename(&backup, &self.target) {
                    let _ = fs::rename(&failed, &self.target);
                    return Err(format!(
                        "无法清理旧映射: {error}; 恢复旧映射失败: {rollback}"
                    ));
                }
                let _ = fs::remove_dir_all(failed);
                return Err(format!("无法清理旧映射，已恢复旧映射: {error}"));
            }
        }
        Ok(self.manifest)
    }

    pub(crate) fn rollback(mut self) -> Result<(), String> {
        let failed = self
            .target
            .parent()
            .ok_or("映射目录缺少父目录")?
            .join(format!(".mapping-rollback-{}", Uuid::new_v4()));
        fs::rename(&self.target, &failed).map_err(|error| format!("无法撤销新映射: {error}"))?;
        if let Some(backup) = self.backup.take() {
            if let Err(error) = fs::rename(&backup, &self.target) {
                let _ = fs::rename(&failed, &self.target);
                return Err(format!("无法恢复旧映射: {error}"));
            }
        }
        fs::remove_dir_all(failed).map_err(|error| format!("无法清理撤销映射: {error}"))
    }
}

impl PreparedLocalMapping {
    pub(crate) fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    pub(crate) fn plugin_id(&self) -> &str {
        &self.definition.plugin_id
    }

    pub(crate) fn activate(self, root: &Path) -> Result<ActivatedLocalMapping, String> {
        let plugin_id = self.definition.plugin_id.clone();
        let target = bounded_plugin_target(root, &plugin_id)?;
        let staging_path = self.staging.keep();
        let backup = root.join(format!(".mapping-backup-{}", Uuid::new_v4()));
        let had_previous = target.exists();
        if had_previous {
            fs::rename(&target, &backup).map_err(|error| format!("无法暂存旧映射: {error}"))?;
        }
        if let Err(error) = fs::rename(&staging_path, &target) {
            if had_previous {
                let _ = fs::rename(&backup, &target);
            }
            return Err(format!("无法启用新映射: {error}"));
        }
        let loaded = match PluginManifest::load(&plugin_id, &target) {
            Ok(manifest) => manifest,
            Err(error) => {
                let failed = root.join(format!(".mapping-failed-{}", Uuid::new_v4()));
                let _ = fs::rename(&target, &failed);
                if had_previous {
                    let _ = fs::rename(&backup, &target);
                }
                let _ = fs::remove_dir_all(failed);
                return Err(error.to_string());
            }
        };
        Ok(ActivatedLocalMapping {
            manifest: loaded,
            target,
            backup: had_previous.then_some(backup),
        })
    }
}

pub(crate) fn prepare(
    root: &Path,
    mut definition: LocalMappingDefinition,
) -> Result<PreparedLocalMapping, String> {
    validate_definition_header(&definition)?;
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
        display_name: definition.display_name.clone(),
    };
    write_json(staging.path().join(API_FILENAME), &definition.services)?;
    write_json(staging.path().join(PLUGIN_METADATA_FILENAME), &metadata)?;
    write_json(staging.path().join(LOCAL_MAPPING_FILENAME), &definition)?;
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
    let definition = load_stored_definition(staging.path())?;
    validate_definition_header(&definition)?;
    let manifest = PluginManifest::load(&definition.plugin_id, staging.path())
        .map_err(|error| error.to_string())?;
    validate_stored_manifest(&manifest, &definition)?;
    Ok(PreparedLocalMapping {
        staging,
        definition,
        manifest,
    })
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

pub(crate) fn validate_installed_manifest(manifest: &PluginManifest) -> Result<(), String> {
    let definition = load_stored_definition(&manifest.plugin_dir)?;
    validate_definition_header(&definition)?;
    validate_stored_manifest(manifest, &definition)
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
    if definition.schema_version != 1 {
        return Err("仅支持本地映射 schemaVersion 1".into());
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
import type { InvokeResponse, JsonObject, JsonValue, SsdevDesktopBridge } from '@bsoft/ssdev-web-bridge'\n\n",
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
        "export class {}Client {{\n  constructor(private readonly bridge: SsdevDesktopBridge) {{}}\n\n",
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

        let loaded = load_definition(&active_root.path().join("reader.local")).unwrap();
        assert!(Path::new(&loaded.services[0].main_class).is_absolute());

        let export_dir = tempfile::tempdir().unwrap();
        let bundle = export_dir.path().join("reader.ssdev-mapping");
        export_bundle(active_root.path(), "reader.local", &bundle).unwrap();
        assert!(bundle.is_file());

        let import_root = tempfile::tempdir().unwrap();
        let imported = prepare_import(import_root.path(), &bundle).unwrap();
        assert_eq!(imported.plugin_id(), "reader.local");
        assert_eq!(imported.manifest().services[0].service_id, "ReaderService");
        assert!(imported
            .manifest()
            .plugin_dir
            .join(&imported.manifest().services[0].main_class)
            .is_file());
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
}
