use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use webplus_plugin_config::{
    compare_public_api, validate_plugin_services, PluginManifest, ServiceDefinition,
};

use crate::local_mappings;

const SCHEMA_VERSION: u8 = 4;
const MAX_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PLUGINS: usize = 1024;

#[derive(Debug)]
pub(crate) struct PluginApiBaselineStore {
    path: PathBuf,
    pending_path: PathBuf,
    schema_version: u8,
    entries: Vec<PluginApiBaselineEntry>,
    pending_entries: Option<Vec<PluginApiBaselineEntry>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PluginApiBaselineDocument {
    schema_version: u8,
    plugins: Vec<PluginApiBaselineEntry>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PluginApiBaselineEntry {
    plugin_id: String,
    version: semver::Version,
    services: Vec<ServiceDefinition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_mapping_integrity_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_mapping_definition_sha256: Option<String>,
    #[serde(default = "default_installed")]
    installed: bool,
}

impl PluginApiBaselineStore {
    /// Opens the previous accepted capability set and reviews the plugins and
    /// local mappings currently present on disk. A legacy document performs a
    /// one-time adoption of already verified local mappings. A missing document
    /// adopts only verified signed plugins and quarantines local mappings until
    /// an operator approves a managed reload, so deleting the baseline cannot
    /// downgrade the local approval boundary.
    pub(crate) fn open(
        path: PathBuf,
        manifests: &[PluginManifest],
        local_mapping_root: &Path,
    ) -> Result<(Self, BTreeSet<String>, BTreeSet<String>, bool), String> {
        let candidates = entries_from_manifests(manifests, local_mapping_root)?;
        let pending_path = pending_path(&path)?;
        let mut store = match read_document(&path)? {
            Some(document) => Self {
                path,
                pending_path,
                schema_version: document.schema_version,
                entries: document.plugins,
                pending_entries: None,
            },
            None => {
                if read_document(&pending_path)?.is_some() {
                    return Err("插件能力基线缺失，但存在无法归属的待提交记录".into());
                }
                let blocked_local = candidates
                    .iter()
                    .filter(|candidate| candidate.local_mapping_integrity_sha256.is_some())
                    .map(|candidate| candidate.plugin_id.clone())
                    .collect::<BTreeSet<_>>();
                let adopted_signed = candidates
                    .into_iter()
                    .filter(|candidate| candidate.local_mapping_integrity_sha256.is_none())
                    .collect();
                let store = Self {
                    path,
                    pending_path,
                    schema_version: SCHEMA_VERSION,
                    entries: adopted_signed,
                    pending_entries: None,
                };
                store.persist()?;
                return Ok((store, BTreeSet::new(), blocked_local, false));
            }
        };
        let recovered_transition = store.recover_pending_transition(&candidates)?;
        if store.schema_version < 3 {
            adopt_legacy_local_mappings(&mut store.entries, &candidates);
            store.schema_version = SCHEMA_VERSION;
        } else if store.schema_version == 3 {
            adopt_schema_three_local_mapping_definitions(&mut store.entries, &candidates);
            store.schema_version = SCHEMA_VERSION;
        }
        let blocked_signed = store.breaking_plugin_ids(&candidates);
        let blocked_local = store.changed_local_mapping_ids(&candidates);
        let reviewed =
            merge_reviewed_entries(&store.entries, candidates, &blocked_signed, &blocked_local);
        ensure_plugin_limit(&reviewed)?;
        store.entries = reviewed;
        store.persist()?;
        Ok((store, blocked_signed, blocked_local, recovered_transition))
    }

    pub(crate) fn baseline_services(&self, plugin_id: &str) -> Option<&[ServiceDefinition]> {
        self.entries
            .iter()
            .find(|entry| entry.plugin_id.eq_ignore_ascii_case(plugin_id))
            .map(|entry| entry.services.as_slice())
    }

    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn baseline_version(&self, plugin_id: &str) -> Option<&semver::Version> {
        self.entries
            .iter()
            .find(|entry| entry.plugin_id.eq_ignore_ascii_case(plugin_id))
            .map(|entry| &entry.version)
    }

    pub(crate) fn breaking_plugin_ids_for_manifests(
        &self,
        manifests: &[PluginManifest],
        local_mapping_root: &Path,
    ) -> Result<BTreeSet<String>, String> {
        let candidates = entries_from_manifests(manifests, local_mapping_root)?;
        Ok(self.breaking_plugin_ids(&candidates))
    }

    pub(crate) fn changed_local_mapping_ids_for_manifests(
        &self,
        manifests: &[PluginManifest],
        local_mapping_root: &Path,
    ) -> Result<BTreeSet<String>, String> {
        let candidates = entries_from_manifests(manifests, local_mapping_root)?;
        Ok(self.changed_local_mapping_ids(&candidates))
    }

    pub(crate) fn accepts_local_mapping_definition(
        &self,
        plugin_id: &str,
        definition_sha256: &str,
    ) -> bool {
        self.pending_entries
            .as_deref()
            .unwrap_or(&self.entries)
            .iter()
            .find(|entry| entry.plugin_id.eq_ignore_ascii_case(plugin_id) && entry.installed)
            .and_then(|entry| entry.local_mapping_definition_sha256.as_deref())
            == Some(definition_sha256)
    }

    /// Persists the exact next accepted set before a plugin or project
    /// transaction reaches its durable commit point. Startup recovery resolves
    /// this record only after the corresponding directory transactions have
    /// already been recovered.
    pub(crate) fn prepare_transition(
        &mut self,
        manifests: &[PluginManifest],
        local_mapping_root: &Path,
    ) -> Result<(), String> {
        self.prepare_transition_retiring(manifests, local_mapping_root, &[])
    }

    pub(crate) fn prepare_transition_retiring(
        &mut self,
        manifests: &[PluginManifest],
        local_mapping_root: &Path,
        retired_plugin_ids: &[&str],
    ) -> Result<(), String> {
        let mut entries = entries_from_manifests(manifests, local_mapping_root)?;
        let candidate_ids = entries
            .iter()
            .map(|entry| normalized_id(&entry.plugin_id))
            .collect::<BTreeSet<_>>();
        for previous in &self.entries {
            if !candidate_ids.contains(&normalized_id(&previous.plugin_id))
                && !retired_plugin_ids
                    .iter()
                    .any(|plugin_id| plugin_id.eq_ignore_ascii_case(&previous.plugin_id))
            {
                let mut tombstone = previous.clone();
                tombstone.installed = false;
                entries.push(tombstone);
            }
        }
        ensure_plugin_limit(&entries)?;
        entries.sort_by(|left, right| left.plugin_id.cmp(&right.plugin_id));
        if self.pending_entries.is_some() || read_document(&self.pending_path)?.is_some() {
            return Err("存在尚未完成的插件能力切换，请重新启动客户端完成恢复".into());
        }
        persist_document(
            &self.pending_path,
            &PluginApiBaselineDocument {
                schema_version: SCHEMA_VERSION,
                plugins: entries.clone(),
            },
        )?;
        self.pending_entries = Some(entries);
        Ok(())
    }

    /// Promotes the prepared set after the plugin/project transaction has
    /// durably committed. If cleanup fails, the pending record is intentionally
    /// retained so the next startup can deterministically finish promotion.
    pub(crate) fn commit_transition(&mut self) -> Result<(), String> {
        let entries = self
            .pending_entries
            .clone()
            .ok_or("不存在待提交的插件能力切换")?;
        persist_document(
            &self.path,
            &PluginApiBaselineDocument {
                schema_version: SCHEMA_VERSION,
                plugins: entries.clone(),
            },
        )?;
        self.schema_version = SCHEMA_VERSION;
        self.entries = entries;
        remove_regular_file(&self.pending_path)?;
        self.pending_entries = None;
        Ok(())
    }

    /// Discards the prepared set after the enclosing plugin/project operation
    /// rolls back or fails before its durable commit point.
    pub(crate) fn abort_transition(&mut self) -> Result<(), String> {
        if self.pending_entries.is_none() && read_document(&self.pending_path)?.is_none() {
            return Ok(());
        }
        remove_regular_file(&self.pending_path)?;
        self.pending_entries = None;
        Ok(())
    }

    fn recover_pending_transition(
        &mut self,
        candidates: &[PluginApiBaselineEntry],
    ) -> Result<bool, String> {
        let Some(pending) = read_document(&self.pending_path)? else {
            return Ok(false);
        };
        if document_matches_candidates(&pending.plugins, candidates, pending.schema_version) {
            self.schema_version = pending.schema_version;
            self.entries = pending.plugins;
            self.persist()?;
        } else if !document_matches_candidates(&self.entries, candidates, self.schema_version) {
            return Err("插件目录既不匹配已接受契约，也不匹配待提交契约；拒绝猜测恢复结果".into());
        }
        remove_regular_file(&self.pending_path)?;
        Ok(true)
    }

    fn breaking_plugin_ids(&self, candidates: &[PluginApiBaselineEntry]) -> BTreeSet<String> {
        let baselines = self
            .entries
            .iter()
            .map(|entry| (normalized_id(&entry.plugin_id), entry))
            .collect::<BTreeMap<_, _>>();
        candidates
            .iter()
            .filter(|candidate| candidate.local_mapping_integrity_sha256.is_none())
            .filter_map(|candidate| {
                let baseline = baselines.get(&normalized_id(&candidate.plugin_id))?;
                (baseline.local_mapping_integrity_sha256.is_some()
                    || !compare_public_api(&baseline.services, &candidate.services).compatible)
                    .then(|| candidate.plugin_id.clone())
            })
            .collect()
    }

    fn changed_local_mapping_ids(&self, candidates: &[PluginApiBaselineEntry]) -> BTreeSet<String> {
        let accepted = self.pending_entries.as_deref().unwrap_or(&self.entries);
        let accepted = accepted
            .iter()
            .map(|entry| (normalized_id(&entry.plugin_id), entry))
            .collect::<BTreeMap<_, _>>();
        candidates
            .iter()
            .filter(|candidate| candidate.local_mapping_integrity_sha256.is_some())
            .filter_map(|candidate| {
                let baseline = accepted.get(&normalized_id(&candidate.plugin_id));
                (!baseline.is_some_and(|baseline| same_capability(baseline, candidate)))
                    .then(|| candidate.plugin_id.clone())
            })
            .collect()
    }

    fn persist(&self) -> Result<(), String> {
        persist_document(
            &self.path,
            &PluginApiBaselineDocument {
                schema_version: self.schema_version,
                plugins: self.entries.clone(),
            },
        )
    }
}

fn entries_from_manifests(
    manifests: &[PluginManifest],
    local_mapping_root: &Path,
) -> Result<Vec<PluginApiBaselineEntry>, String> {
    let mut entries = Vec::new();
    let mut identities = BTreeSet::new();
    for manifest in manifests {
        let is_local_mapping = manifest.plugin_dir.starts_with(local_mapping_root);
        validate_plugin_services(&manifest.plugin_id, &manifest.services)
            .map_err(|error| format!("插件能力契约无效: {error}"))?;
        let metadata = manifest
            .metadata
            .as_ref()
            .ok_or_else(|| format!("插件 [{}] 缺少版本元数据", manifest.plugin_id))?;
        if metadata.plugin_id != manifest.plugin_id {
            return Err("插件能力身份与版本元数据不一致".into());
        }
        if !identities.insert(normalized_id(&manifest.plugin_id)) {
            return Err("插件能力基线包含重复或大小写冲突的插件 ID".into());
        }
        let local_mapping_integrity_sha256 = if is_local_mapping {
            let digest = manifest
                .local_mapping_integrity_sha256
                .clone()
                .ok_or_else(|| format!("本地映射 [{}] 缺少运行时完整性摘要", manifest.plugin_id))?;
            if !is_lowercase_sha256(&digest) {
                return Err(format!(
                    "本地映射 [{}] 的运行时完整性摘要无效",
                    manifest.plugin_id
                ));
            }
            Some(digest)
        } else {
            None
        };
        let local_mapping_definition_sha256 = if is_local_mapping {
            let digest =
                local_mappings::definition_sha256_for_manifest(manifest).map_err(|error| {
                    format!("本地映射 [{}] 的定义摘要无效: {error}", manifest.plugin_id)
                })?;
            if !is_lowercase_sha256(&digest) {
                return Err(format!("本地映射 [{}] 的定义摘要无效", manifest.plugin_id));
            }
            Some(digest)
        } else {
            None
        };
        entries.push(PluginApiBaselineEntry {
            plugin_id: manifest.plugin_id.clone(),
            version: metadata.version.clone(),
            services: manifest.services.clone(),
            local_mapping_integrity_sha256,
            local_mapping_definition_sha256,
            installed: true,
        });
    }
    ensure_plugin_limit(&entries)?;
    entries.sort_by(|left, right| left.plugin_id.cmp(&right.plugin_id));
    Ok(entries)
}

fn merge_reviewed_entries(
    previous: &[PluginApiBaselineEntry],
    candidates: Vec<PluginApiBaselineEntry>,
    blocked_signed: &BTreeSet<String>,
    blocked_local: &BTreeSet<String>,
) -> Vec<PluginApiBaselineEntry> {
    let mut merged = previous
        .iter()
        .map(|entry| {
            let mut tombstone = entry.clone();
            tombstone.installed = false;
            (normalized_id(&entry.plugin_id), tombstone)
        })
        .collect::<BTreeMap<_, _>>();
    for candidate in candidates {
        let blocked = if candidate.local_mapping_integrity_sha256.is_some() {
            blocked_local
        } else {
            blocked_signed
        };
        if !blocked
            .iter()
            .any(|plugin_id| plugin_id.eq_ignore_ascii_case(&candidate.plugin_id))
        {
            merged.insert(normalized_id(&candidate.plugin_id), candidate);
        }
    }
    merged.into_values().collect()
}

fn read_document(path: &Path) -> Result<Option<PluginApiBaselineDocument>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("无法读取插件能力基线: {error}")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("插件能力基线必须是普通文件".into());
    }
    if metadata.len() > MAX_DOCUMENT_BYTES {
        return Err("插件能力基线超过 4 MiB 限制".into());
    }
    let bytes = fs::read(path).map_err(|error| format!("无法读取插件能力基线: {error}"))?;
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err("插件能力基线读取期间发生变化或超过 4 MiB 限制".into());
    }
    let document: PluginApiBaselineDocument =
        serde_json::from_slice(&bytes).map_err(|error| format!("插件能力基线格式无效: {error}"))?;
    validate_document(&document)?;
    Ok(Some(document))
}

fn validate_document(document: &PluginApiBaselineDocument) -> Result<(), String> {
    if !matches!(document.schema_version, 1 | 2 | 3 | SCHEMA_VERSION) {
        return Err(format!(
            "不支持插件能力基线版本 {}",
            document.schema_version
        ));
    }
    if document.plugins.len() > MAX_PLUGINS {
        return Err(format!("插件能力基线不能超过 {MAX_PLUGINS} 个能力"));
    }
    let mut identities = BTreeSet::new();
    for entry in &document.plugins {
        validate_plugin_services(&entry.plugin_id, &entry.services)
            .map_err(|error| format!("插件能力基线声明无效: {error}"))?;
        if !identities.insert(normalized_id(&entry.plugin_id)) {
            return Err("插件能力基线包含重复或大小写冲突的插件 ID".into());
        }
        if document.schema_version < 3 && entry.local_mapping_integrity_sha256.is_some() {
            return Err("旧版插件契约基线不能声明本地映射完整性摘要".into());
        }
        if document.schema_version < SCHEMA_VERSION
            && entry.local_mapping_definition_sha256.is_some()
        {
            return Err("旧版插件契约基线不能声明本地映射定义摘要".into());
        }
        if entry
            .local_mapping_integrity_sha256
            .as_deref()
            .is_some_and(|digest| !is_lowercase_sha256(digest))
        {
            return Err("插件能力基线包含无效的本地映射完整性摘要".into());
        }
        if entry
            .local_mapping_definition_sha256
            .as_deref()
            .is_some_and(|digest| !is_lowercase_sha256(digest))
        {
            return Err("插件能力基线包含无效的本地映射定义摘要".into());
        }
        if entry.local_mapping_definition_sha256.is_some()
            && entry.local_mapping_integrity_sha256.is_none()
        {
            return Err("插件能力基线中的本地映射定义摘要缺少运行时完整性摘要".into());
        }
        if document.schema_version >= SCHEMA_VERSION
            && entry.installed
            && entry.local_mapping_integrity_sha256.is_some()
            && entry.local_mapping_definition_sha256.is_none()
        {
            return Err("已安装本地映射缺少定义摘要".into());
        }
    }
    Ok(())
}

fn persist_document(path: &Path, document: &PluginApiBaselineDocument) -> Result<(), String> {
    let parent = path.parent().ok_or("插件能力基线缺少父目录")?;
    fs::create_dir_all(parent).map_err(|error| format!("无法创建契约基线目录: {error}"))?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|error| format!("无法检查契约基线目录: {error}"))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err("插件能力基线目录必须是普通目录".into());
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("插件能力基线目标必须是普通文件".into());
        }
    }
    let mut bytes = serde_json::to_vec_pretty(document)
        .map_err(|error| format!("无法序列化插件能力基线: {error}"))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err("插件能力基线超过 4 MiB 限制".into());
    }
    let mut temporary = NamedTempFile::new_in(parent)
        .map_err(|error| format!("无法创建插件能力基线暂存文件: {error}"))?;
    temporary
        .write_all(&bytes)
        .and_then(|_| temporary.as_file_mut().sync_all())
        .map_err(|error| format!("无法持久化插件能力基线: {error}"))?;
    temporary
        .persist(path)
        .map_err(|error| format!("无法原子替换插件能力基线: {}", error.error))?;
    sync_directory(parent)?;
    Ok(())
}

fn pending_path(path: &Path) -> Result<PathBuf, String> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("插件能力基线文件名无效")?;
    Ok(path.with_file_name(format!("{file_name}.pending")))
}

fn remove_regular_file(path: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("无法检查签名插件契约待提交记录: {error}")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("签名插件契约待提交记录必须是普通文件".into());
    }
    fs::remove_file(path).map_err(|error| format!("无法清理签名插件契约待提交记录: {error}"))?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("无法持久化插件能力基线目录: {error}"))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn normalized_id(plugin_id: &str) -> String {
    plugin_id.to_ascii_lowercase()
}

fn default_installed() -> bool {
    true
}

fn ensure_plugin_limit(entries: &[PluginApiBaselineEntry]) -> Result<(), String> {
    if entries.len() > MAX_PLUGINS {
        return Err(format!("插件能力基线不能超过 {MAX_PLUGINS} 个能力"));
    }
    Ok(())
}

fn adopt_legacy_local_mappings(
    entries: &mut Vec<PluginApiBaselineEntry>,
    candidates: &[PluginApiBaselineEntry],
) {
    let mut identities = entries
        .iter()
        .map(|entry| normalized_id(&entry.plugin_id))
        .collect::<BTreeSet<_>>();
    for candidate in candidates
        .iter()
        .filter(|candidate| candidate.local_mapping_integrity_sha256.is_some())
    {
        if identities.insert(normalized_id(&candidate.plugin_id)) {
            entries.push(candidate.clone());
        }
    }
    entries.sort_by(|left, right| left.plugin_id.cmp(&right.plugin_id));
}

fn adopt_schema_three_local_mapping_definitions(
    entries: &mut [PluginApiBaselineEntry],
    candidates: &[PluginApiBaselineEntry],
) {
    let candidates = candidates
        .iter()
        .map(|candidate| (normalized_id(&candidate.plugin_id), candidate))
        .collect::<BTreeMap<_, _>>();
    for entry in entries
        .iter_mut()
        .filter(|entry| entry.installed && entry.local_mapping_integrity_sha256.is_some())
    {
        let Some(candidate) = candidates.get(&normalized_id(&entry.plugin_id)) else {
            continue;
        };
        if same_capability_for_schema(entry, candidate, 3) {
            entry.local_mapping_definition_sha256 =
                candidate.local_mapping_definition_sha256.clone();
        }
    }
}

fn same_capability(left: &PluginApiBaselineEntry, right: &PluginApiBaselineEntry) -> bool {
    left.plugin_id == right.plugin_id
        && left.version == right.version
        && left.services == right.services
        && left.local_mapping_integrity_sha256 == right.local_mapping_integrity_sha256
        && left.local_mapping_definition_sha256 == right.local_mapping_definition_sha256
}

fn same_capability_for_schema(
    left: &PluginApiBaselineEntry,
    right: &PluginApiBaselineEntry,
    schema_version: u8,
) -> bool {
    left.plugin_id == right.plugin_id
        && left.version == right.version
        && left.services == right.services
        && left.local_mapping_integrity_sha256 == right.local_mapping_integrity_sha256
        && (schema_version < SCHEMA_VERSION
            || left.local_mapping_definition_sha256 == right.local_mapping_definition_sha256)
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn document_matches_candidates(
    document: &[PluginApiBaselineEntry],
    candidates: &[PluginApiBaselineEntry],
    schema_version: u8,
) -> bool {
    let candidates = candidates
        .iter()
        .filter(|entry| schema_version >= 3 || entry.local_mapping_integrity_sha256.is_none())
        .collect::<Vec<_>>();
    let candidates = candidates
        .into_iter()
        .map(|entry| (normalized_id(&entry.plugin_id), entry))
        .collect::<BTreeMap<_, _>>();
    if candidates.len() != document.iter().filter(|entry| entry.installed).count() {
        return false;
    }
    document.iter().all(|entry| {
        let candidate = candidates.get(&normalized_id(&entry.plugin_id));
        if entry.installed {
            candidate.is_some_and(|candidate| {
                same_capability_for_schema(entry, candidate, schema_version)
                    && candidate.installed == entry.installed
            })
        } else {
            candidate.is_none()
        }
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use semver::{Version, VersionReq};
    use webplus_plugin_config::{PluginMetadata, ServiceDefinition};

    use super::*;

    fn manifest(plugin_id: &str, root: PathBuf, service: serde_json::Value) -> PluginManifest {
        PluginManifest {
            plugin_id: plugin_id.to_owned(),
            plugin_dir: root,
            metadata: Some(PluginMetadata {
                schema_version: 1,
                plugin_id: plugin_id.to_owned(),
                version: Version::new(1, 0, 0),
                desktop_version_requirement: Some(VersionReq::parse(">=0.1.0").unwrap()),
                display_name: plugin_id.to_owned(),
            }),
            services: vec![serde_json::from_value::<ServiceDefinition>(service).unwrap()],
            local_mapping_integrity_sha256: None,
        }
    }

    fn local_manifest(
        plugin_id: &str,
        root: PathBuf,
        integrity: &str,
        service: serde_json::Value,
    ) -> PluginManifest {
        let mut manifest = manifest(plugin_id, root, service);
        let metadata = manifest.metadata.as_mut().unwrap();
        metadata.version = Version::parse("0.0.0-local").unwrap();
        metadata.desktop_version_requirement = None;
        manifest.local_mapping_integrity_sha256 = Some(integrity.repeat(64));
        fs::create_dir_all(&manifest.plugin_dir).unwrap();
        let definition = serde_json::json!({
            "schemaVersion": 2,
            "pluginId": plugin_id,
            "displayName": plugin_id,
            "services": manifest.services.clone(),
            "debugCases": []
        });
        fs::write(
            manifest.plugin_dir.join("local-mapping.json"),
            serde_json::to_vec_pretty(&definition).unwrap(),
        )
        .unwrap();
        manifest
    }

    fn seed_legacy_empty_baseline(path: &Path) {
        fs::write(path, br#"{"schemaVersion":2,"plugins":[]}"#).unwrap();
    }

    #[test]
    fn baseline_blocks_offline_route_removal_but_adopts_safe_additions() {
        let root = tempfile::tempdir().unwrap();
        let plugin_root = root.path().join("plugins");
        let local_root = root.path().join("local-mappings");
        let path = root.path().join("plugin-api-baseline.json");
        let original = manifest(
            "reader",
            plugin_root.join("reader"),
            serde_json::json!({
                "serviceId": "card.reader",
                "mainClass": "reader.dll",
                "methods": [{"name": "read", "alias": "scan"}]
            }),
        );
        let (_, blocked, local_blocked, recovered) =
            PluginApiBaselineStore::open(path.clone(), &[original], &local_root).unwrap();
        assert!(blocked.is_empty());
        assert!(local_blocked.is_empty());
        assert!(!recovered);

        let breaking = manifest(
            "reader",
            plugin_root.join("reader"),
            serde_json::json!({
                "serviceId": "card.reader",
                "mainClass": "reader.dll",
                "methods": [{"name": "read"}]
            }),
        );
        let (store, blocked, local_blocked, recovered) =
            PluginApiBaselineStore::open(path.clone(), &[breaking], &local_root).unwrap();
        assert_eq!(blocked, BTreeSet::from(["reader".to_owned()]));
        assert!(local_blocked.is_empty());
        assert!(!recovered);
        assert!(store
            .baseline_services("reader")
            .is_some_and(|services| { services[0].methods[0].alias.as_deref() == Some("scan") }));

        let compatible = manifest(
            "reader",
            plugin_root.join("reader"),
            serde_json::json!({
                "serviceId": "card.reader",
                "mainClass": "reader-v2.dll",
                "methods": [
                    {"name": "read", "alias": "scan"},
                    {"name": "status"}
                ]
            }),
        );
        let (_, blocked, local_blocked, recovered) =
            PluginApiBaselineStore::open(path, &[compatible], &local_root).unwrap();
        assert!(blocked.is_empty());
        assert!(local_blocked.is_empty());
        assert!(!recovered);
    }

    #[test]
    fn baseline_rejects_symlinks_and_invalid_persisted_contracts() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("plugin-api-baseline.json");
        fs::write(
            &path,
            br#"{"schemaVersion":1,"plugins":[{"pluginId":"reader","version":"1.0.0","services":[]}]}"#,
        )
        .unwrap();
        assert!(PluginApiBaselineStore::open(
            path.clone(),
            &[],
            &root.path().join("local-mappings")
        )
        .is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let outside = root.path().join("outside.json");
            fs::write(&outside, b"{}").unwrap();
            fs::remove_file(&path).unwrap();
            symlink(outside, &path).unwrap();
            assert!(
                PluginApiBaselineStore::open(path, &[], &root.path().join("local-mappings"))
                    .is_err()
            );
        }
    }

    #[test]
    fn schema_one_baseline_migrates_and_pending_symlinks_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let plugin_root = root.path().join("plugins");
        let local_root = root.path().join("local-mappings");
        let path = root.path().join("plugin-api-baseline.json");
        let reader = manifest(
            "reader",
            plugin_root.join("reader"),
            serde_json::json!({
                "serviceId": "card.reader",
                "mainClass": "reader.dll",
                "methods": [{"name": "read"}]
            }),
        );
        let legacy = serde_json::json!({
            "schemaVersion": 1,
            "plugins": [{
                "pluginId": "reader",
                "version": "1.0.0",
                "services": reader.services.clone()
            }]
        });
        fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();

        PluginApiBaselineStore::open(path.clone(), std::slice::from_ref(&reader), &local_root)
            .unwrap();
        let migrated: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(migrated["schemaVersion"], SCHEMA_VERSION);
        assert_eq!(migrated["plugins"][0]["installed"], true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let outside = root.path().join("outside.json");
            fs::write(&outside, b"{}").unwrap();
            symlink(outside, pending_path(&path).unwrap()).unwrap();
            assert!(PluginApiBaselineStore::open(path, &[reader], &local_root).is_err());
        }
    }

    #[test]
    fn schema_two_adopts_verified_local_mappings_once() {
        let root = tempfile::tempdir().unwrap();
        let plugin_root = root.path().join("plugins");
        let local_root = root.path().join("local-mappings");
        let path = root.path().join("plugin-api-baseline.json");
        let reader = manifest(
            "reader",
            plugin_root.join("reader"),
            serde_json::json!({
                "serviceId": "card.reader",
                "mainClass": "reader.dll",
                "methods": [{"name": "read"}]
            }),
        );
        let mapping = local_manifest(
            "printer",
            local_root.join("printer"),
            "1",
            serde_json::json!({
                "serviceId": "label.printer",
                "mainClass": "printer.dll",
                "methods": [{"name": "print"}]
            }),
        );
        let legacy = serde_json::json!({
            "schemaVersion": 2,
            "plugins": [{
                "pluginId": "reader",
                "version": "1.0.0",
                "services": reader.services.clone(),
                "installed": true
            }]
        });
        fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();

        let (store, signed_blocked, local_blocked, recovered) =
            PluginApiBaselineStore::open(path.clone(), &[reader, mapping], &local_root).unwrap();
        assert!(signed_blocked.is_empty());
        assert!(local_blocked.is_empty());
        assert!(!recovered);
        assert_eq!(store.entry_count(), 2);
        let migrated: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(migrated["schemaVersion"], SCHEMA_VERSION);
        assert_eq!(
            migrated["plugins"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["pluginId"] == "printer")
                .unwrap()["localMappingIntegritySha256"],
            "1".repeat(64)
        );
        assert!(migrated["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["pluginId"] == "printer")
            .unwrap()["localMappingDefinitionSha256"]
            .as_str()
            .is_some_and(is_lowercase_sha256));
    }

    #[test]
    fn schema_three_adopts_only_matching_existing_local_definition_once() {
        let root = tempfile::tempdir().unwrap();
        let local_root = root.path().join("local-mappings");
        let path = root.path().join("plugin-api-baseline.json");
        let mapping = local_manifest(
            "printer",
            local_root.join("printer"),
            "1",
            serde_json::json!({
                "serviceId": "label.printer",
                "mainClass": "printer.dll",
                "methods": [{"name": "print"}]
            }),
        );
        let schema_three = serde_json::json!({
            "schemaVersion": 3,
            "plugins": [{
                "pluginId": "printer",
                "version": "0.0.0-local",
                "services": mapping.services.clone(),
                "localMappingIntegritySha256": "1".repeat(64),
                "installed": true
            }]
        });
        fs::write(&path, serde_json::to_vec(&schema_three).unwrap()).unwrap();

        let (_, signed_blocked, local_blocked, recovered) =
            PluginApiBaselineStore::open(path.clone(), std::slice::from_ref(&mapping), &local_root)
                .unwrap();
        assert!(signed_blocked.is_empty());
        assert!(local_blocked.is_empty());
        assert!(!recovered);
        let migrated: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(migrated["schemaVersion"], SCHEMA_VERSION);
        assert!(migrated["plugins"][0]["localMappingDefinitionSha256"]
            .as_str()
            .is_some_and(is_lowercase_sha256));
    }

    #[test]
    fn schema_four_blocks_offline_debug_case_drift_but_ignores_json_formatting() {
        let root = tempfile::tempdir().unwrap();
        let local_root = root.path().join("local-mappings");
        let path = root.path().join("plugin-api-baseline.json");
        seed_legacy_empty_baseline(&path);
        let mapping = local_manifest(
            "printer",
            local_root.join("printer"),
            "1",
            serde_json::json!({
                "serviceId": "label.printer",
                "mainClass": "printer.dll",
                "methods": [{"name": "print"}]
            }),
        );
        PluginApiBaselineStore::open(path.clone(), std::slice::from_ref(&mapping), &local_root)
            .unwrap();

        let definition_path = local_root.join("printer/local-mapping.json");
        let unchanged: serde_json::Value =
            serde_json::from_slice(&fs::read(&definition_path).unwrap()).unwrap();
        fs::write(&definition_path, serde_json::to_vec(&unchanged).unwrap()).unwrap();
        let (_, _, formatting_blocked, _) =
            PluginApiBaselineStore::open(path.clone(), std::slice::from_ref(&mapping), &local_root)
                .unwrap();
        assert!(formatting_blocked.is_empty());

        let mut changed = unchanged;
        changed["debugCases"] = serde_json::json!([{
            "name": "print-live-label",
            "serviceId": "label.printer",
            "method": "print",
            "parameters": {},
            "expectedResCode": 0
        }]);
        fs::write(&definition_path, serde_json::to_vec(&changed).unwrap()).unwrap();
        let (_, signed_blocked, local_blocked, recovered) =
            PluginApiBaselineStore::open(path, &[mapping], &local_root).unwrap();
        assert!(signed_blocked.is_empty());
        assert_eq!(local_blocked, BTreeSet::from(["printer".to_owned()]));
        assert!(!recovered);
    }

    #[test]
    fn managed_transition_accepts_a_definition_only_debug_case_change() {
        let root = tempfile::tempdir().unwrap();
        let local_root = root.path().join("local-mappings");
        let path = root.path().join("plugin-api-baseline.json");
        seed_legacy_empty_baseline(&path);
        let mapping = local_manifest(
            "printer",
            local_root.join("printer"),
            "1",
            serde_json::json!({
                "serviceId": "label.printer",
                "mainClass": "printer.dll",
                "methods": [{"name": "print"}]
            }),
        );
        let (mut store, _, _, _) =
            PluginApiBaselineStore::open(path.clone(), std::slice::from_ref(&mapping), &local_root)
                .unwrap();
        let previous_definition_sha256 = store
            .entries
            .iter()
            .find(|entry| entry.plugin_id == "printer")
            .unwrap()
            .local_mapping_definition_sha256
            .clone()
            .unwrap();

        let definition_path = local_root.join("printer/local-mapping.json");
        let mut changed: serde_json::Value =
            serde_json::from_slice(&fs::read(&definition_path).unwrap()).unwrap();
        changed["debugCases"] = serde_json::json!([{
            "name": "print-synthetic-label",
            "serviceId": "label.printer",
            "method": "print",
            "parameters": {},
            "expectedResCode": 0
        }]);
        fs::write(&definition_path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert_eq!(
            store
                .changed_local_mapping_ids_for_manifests(
                    std::slice::from_ref(&mapping),
                    &local_root,
                )
                .unwrap(),
            BTreeSet::from(["printer".to_owned()])
        );
        store
            .prepare_transition(std::slice::from_ref(&mapping), &local_root)
            .unwrap();
        let next_definition_sha256 =
            local_mappings::definition_sha256_for_manifest(&mapping).unwrap();
        assert_ne!(previous_definition_sha256, next_definition_sha256);
        assert!(store.accepts_local_mapping_definition("printer", &next_definition_sha256));
        drop(store);

        let (recovered, _, local_blocked, did_recover) =
            PluginApiBaselineStore::open(path, std::slice::from_ref(&mapping), &local_root)
                .unwrap();
        assert!(local_blocked.is_empty());
        assert!(did_recover);
        assert!(recovered.accepts_local_mapping_definition("printer", &next_definition_sha256));
    }

    #[test]
    fn schema_three_blocks_new_and_changed_offline_local_mappings() {
        let root = tempfile::tempdir().unwrap();
        let local_root = root.path().join("local-mappings");
        let path = root.path().join("plugin-api-baseline.json");
        seed_legacy_empty_baseline(&path);
        let original = local_manifest(
            "printer",
            local_root.join("printer"),
            "1",
            serde_json::json!({
                "serviceId": "label.printer",
                "mainClass": "printer.dll",
                "methods": [{"name": "print"}]
            }),
        );
        PluginApiBaselineStore::open(path.clone(), std::slice::from_ref(&original), &local_root)
            .unwrap();

        let changed = local_manifest(
            "printer",
            local_root.join("printer"),
            "2",
            serde_json::json!({
                "serviceId": "label.printer",
                "mainClass": "printer-v2.dll",
                "methods": [{"name": "print"}, {"name": "status"}]
            }),
        );
        let added = local_manifest(
            "scanner",
            local_root.join("scanner"),
            "3",
            serde_json::json!({
                "serviceId": "code.scanner",
                "mainClass": "scanner.dll",
                "methods": [{"name": "scan"}]
            }),
        );
        let (store, signed_blocked, local_blocked, recovered) =
            PluginApiBaselineStore::open(path, &[changed, added], &local_root).unwrap();
        assert!(signed_blocked.is_empty());
        assert_eq!(
            local_blocked,
            BTreeSet::from(["printer".to_owned(), "scanner".to_owned()])
        );
        assert!(!recovered);
        assert_eq!(store.entry_count(), 1);
        let original_integrity = "1".repeat(64);
        assert_eq!(
            store
                .entries
                .iter()
                .find(|entry| entry.plugin_id == "printer")
                .unwrap()
                .local_mapping_integrity_sha256
                .as_deref(),
            Some(original_integrity.as_str())
        );
    }

    #[test]
    fn managed_transition_accepts_local_replacement_and_retirement() {
        let root = tempfile::tempdir().unwrap();
        let local_root = root.path().join("local-mappings");
        let path = root.path().join("plugin-api-baseline.json");
        seed_legacy_empty_baseline(&path);
        let original = local_manifest(
            "printer",
            local_root.join("printer"),
            "1",
            serde_json::json!({
                "serviceId": "label.printer",
                "mainClass": "printer.dll",
                "methods": [{"name": "print"}]
            }),
        );
        let (mut store, _, _, _) = PluginApiBaselineStore::open(
            path.clone(),
            std::slice::from_ref(&original),
            &local_root,
        )
        .unwrap();
        let updated = local_manifest(
            "printer",
            local_root.join("printer"),
            "2",
            serde_json::json!({
                "serviceId": "label.printer",
                "mainClass": "printer-v2.dll",
                "methods": [{"name": "print"}, {"name": "status"}]
            }),
        );
        store
            .prepare_transition(std::slice::from_ref(&updated), &local_root)
            .unwrap();
        assert!(store
            .changed_local_mapping_ids_for_manifests(std::slice::from_ref(&updated), &local_root)
            .unwrap()
            .is_empty());
        drop(store);

        let (mut recovered, _, local_blocked, did_recover) =
            PluginApiBaselineStore::open(path.clone(), &[updated], &local_root).unwrap();
        assert!(local_blocked.is_empty());
        assert!(did_recover);
        recovered
            .prepare_transition_retiring(&[], &local_root, &["printer"])
            .unwrap();
        recovered.commit_transition().unwrap();

        let reappeared_manifest = local_manifest(
            "printer",
            local_root.join("printer"),
            "1",
            serde_json::json!({
                "serviceId": "label.printer",
                "mainClass": "printer.dll",
                "methods": [{"name": "print"}]
            }),
        );
        let (_, _, reappeared, _) =
            PluginApiBaselineStore::open(path, &[reappeared_manifest], &local_root).unwrap();
        assert_eq!(reappeared, BTreeSet::from(["printer".to_owned()]));
    }

    #[test]
    fn offline_signed_package_cannot_replace_a_local_mapping_identity() {
        let root = tempfile::tempdir().unwrap();
        let local_root = root.path().join("local-mappings");
        let path = root.path().join("plugin-api-baseline.json");
        seed_legacy_empty_baseline(&path);
        let local = local_manifest(
            "reader",
            local_root.join("reader"),
            "1",
            serde_json::json!({
                "serviceId": "card.reader",
                "mainClass": "reader.dll",
                "methods": [{"name": "read"}]
            }),
        );
        PluginApiBaselineStore::open(path.clone(), &[local], &local_root).unwrap();
        let signed = manifest(
            "reader",
            root.path().join("plugins/reader"),
            serde_json::json!({
                "serviceId": "card.reader",
                "mainClass": "reader.dll",
                "methods": [{"name": "read"}]
            }),
        );

        let (_, signed_blocked, local_blocked, _) =
            PluginApiBaselineStore::open(path, &[signed], &local_root).unwrap();
        assert_eq!(signed_blocked, BTreeSet::from(["reader".to_owned()]));
        assert!(local_blocked.is_empty());
    }

    #[test]
    fn missing_baseline_adopts_signed_plugins_but_quarantines_local_mappings() {
        let root = tempfile::tempdir().unwrap();
        let local_root = root.path().join("local-mappings");
        let path = root.path().join("plugin-api-baseline.json");
        let signed = manifest(
            "reader",
            root.path().join("plugins/reader"),
            serde_json::json!({
                "serviceId": "card.reader",
                "mainClass": "reader.dll",
                "methods": [{"name": "read"}]
            }),
        );
        let local = local_manifest(
            "printer",
            local_root.join("printer"),
            "1",
            serde_json::json!({
                "serviceId": "label.printer",
                "mainClass": "printer.dll",
                "methods": [{"name": "print"}]
            }),
        );

        let (store, signed_blocked, local_blocked, recovered) =
            PluginApiBaselineStore::open(path, &[signed, local], &local_root).unwrap();
        assert!(signed_blocked.is_empty());
        assert_eq!(local_blocked, BTreeSet::from(["printer".to_owned()]));
        assert!(!recovered);
        assert_eq!(store.entry_count(), 1);
        assert!(store.baseline_services("reader").is_some());
        assert!(store.baseline_services("printer").is_none());
    }

    #[test]
    fn controlled_replacement_can_retire_an_old_contract_identity() {
        let root = tempfile::tempdir().unwrap();
        let plugin_root = root.path().join("plugins");
        let local_root = root.path().join("local-mappings");
        let path = root.path().join("plugin-api-baseline.json");
        let original = manifest(
            "reader",
            plugin_root.join("reader"),
            serde_json::json!({
                "serviceId": "card.reader",
                "mainClass": "reader.dll",
                "methods": [{"name": "read", "alias": "scan"}]
            }),
        );
        let (mut store, _, _, _) =
            PluginApiBaselineStore::open(path.clone(), &[original], &local_root).unwrap();

        // An unexplained disappearance is retained as a tombstone so an
        // incompatible same-ID package cannot be reintroduced as a new plugin.
        let (reopened, _, _, _) =
            PluginApiBaselineStore::open(path.clone(), &[], &local_root).unwrap();
        assert_eq!(reopened.entry_count(), 1);

        // The explicit uninstall path replaces the accepted set after its
        // transaction commits, intentionally retiring that identity.
        store
            .prepare_transition_retiring(&[], &local_root, &["reader"])
            .unwrap();
        store.commit_transition().unwrap();
        let incompatible = manifest(
            "reader",
            plugin_root.join("reader"),
            serde_json::json!({
                "serviceId": "card.reader",
                "mainClass": "reader.dll",
                "methods": [{"name": "different"}]
            }),
        );
        let (_, blocked, _, _) =
            PluginApiBaselineStore::open(path, &[incompatible], &local_root).unwrap();
        assert!(blocked.is_empty());
    }

    #[test]
    fn unrelated_transition_preserves_missing_plugin_tombstones() {
        let root = tempfile::tempdir().unwrap();
        let plugin_root = root.path().join("plugins");
        let local_root = root.path().join("local-mappings");
        let path = root.path().join("plugin-api-baseline.json");
        let reader = manifest(
            "reader",
            plugin_root.join("reader"),
            serde_json::json!({
                "serviceId": "card.reader",
                "mainClass": "reader.dll",
                "methods": [{"name": "read"}]
            }),
        );
        PluginApiBaselineStore::open(path.clone(), &[reader], &local_root).unwrap();
        let (mut store, _, _, _) =
            PluginApiBaselineStore::open(path.clone(), &[], &local_root).unwrap();
        let writer = manifest(
            "writer",
            plugin_root.join("writer"),
            serde_json::json!({
                "serviceId": "card.writer",
                "mainClass": "writer.dll",
                "methods": [{"name": "write"}]
            }),
        );

        store
            .prepare_transition(std::slice::from_ref(&writer), &local_root)
            .unwrap();
        store.commit_transition().unwrap();
        drop(store);
        let (reopened, blocked, _, _) =
            PluginApiBaselineStore::open(path, &[writer], &local_root).unwrap();
        assert!(blocked.is_empty());
        assert_eq!(reopened.entry_count(), 2);
        assert!(reopened.baseline_services("reader").is_some());
    }

    #[test]
    fn pending_transition_recovers_committed_or_rolled_back_plugin_state() {
        let root = tempfile::tempdir().unwrap();
        let plugin_root = root.path().join("plugins");
        let local_root = root.path().join("local-mappings");
        let path = root.path().join("plugin-api-baseline.json");
        let original = manifest(
            "reader",
            plugin_root.join("reader"),
            serde_json::json!({
                "serviceId": "card.reader",
                "mainClass": "reader.dll",
                "methods": [{"name": "read"}]
            }),
        );
        let updated = manifest(
            "reader",
            plugin_root.join("reader"),
            serde_json::json!({
                "serviceId": "card.reader",
                "mainClass": "reader-v2.dll",
                "methods": [{"name": "read"}, {"name": "status"}]
            }),
        );
        let (mut store, _, _, _) = PluginApiBaselineStore::open(
            path.clone(),
            std::slice::from_ref(&original),
            &local_root,
        )
        .unwrap();

        store
            .prepare_transition(std::slice::from_ref(&updated), &local_root)
            .unwrap();
        drop(store);
        let (mut rolled_back, blocked, _, recovered) =
            PluginApiBaselineStore::open(path.clone(), &[original], &local_root).unwrap();
        assert!(blocked.is_empty());
        assert!(recovered);
        assert_eq!(rolled_back.entry_count(), 1);

        rolled_back
            .prepare_transition(std::slice::from_ref(&updated), &local_root)
            .unwrap();
        drop(rolled_back);
        let (committed, blocked, _, recovered) =
            PluginApiBaselineStore::open(path, &[updated], &local_root).unwrap();
        assert!(blocked.is_empty());
        assert!(recovered);
        assert!(committed
            .baseline_services("reader")
            .is_some_and(|services| services[0].methods.len() == 2));
    }

    #[test]
    fn pending_transition_refuses_ambiguous_plugin_state() {
        let root = tempfile::tempdir().unwrap();
        let plugin_root = root.path().join("plugins");
        let local_root = root.path().join("local-mappings");
        let path = root.path().join("plugin-api-baseline.json");
        let original = manifest(
            "reader",
            plugin_root.join("reader"),
            serde_json::json!({
                "serviceId": "card.reader",
                "mainClass": "reader.dll",
                "methods": [{"name": "read"}]
            }),
        );
        let updated = manifest(
            "reader",
            plugin_root.join("reader"),
            serde_json::json!({
                "serviceId": "card.reader",
                "mainClass": "reader-v2.dll",
                "methods": [{"name": "read"}, {"name": "status"}]
            }),
        );
        let unexpected = manifest(
            "reader",
            plugin_root.join("reader"),
            serde_json::json!({
                "serviceId": "card.reader",
                "mainClass": "reader-v3.dll",
                "methods": [{"name": "different"}]
            }),
        );
        let (mut store, _, _, _) =
            PluginApiBaselineStore::open(path.clone(), &[original], &local_root).unwrap();
        store.prepare_transition(&[updated], &local_root).unwrap();
        drop(store);

        assert!(PluginApiBaselineStore::open(path, &[unexpected], &local_root).is_err());
    }
}
