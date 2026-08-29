use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use webplus_plugin_config::{
    compare_public_api, validate_plugin_services, PluginManifest, ServiceDefinition,
};

const SCHEMA_VERSION: u8 = 2;
const MAX_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PLUGINS: usize = 1024;

#[derive(Debug)]
pub(crate) struct PluginApiBaselineStore {
    path: PathBuf,
    pending_path: PathBuf,
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
    #[serde(default = "default_installed")]
    installed: bool,
}

impl PluginApiBaselineStore {
    /// Opens the previous accepted contract set and reviews the signed plugins
    /// currently present on disk. A missing document is a one-time adoption of
    /// the already verified installation; later same-ID breaking changes are
    /// returned for quarantine instead of being adopted.
    pub(crate) fn open(
        path: PathBuf,
        manifests: &[PluginManifest],
        local_mapping_root: &Path,
    ) -> Result<(Self, BTreeSet<String>, bool), String> {
        let candidates = entries_from_manifests(manifests, local_mapping_root)?;
        let pending_path = pending_path(&path)?;
        let mut store = match read_document(&path)? {
            Some(document) => Self {
                path,
                pending_path,
                entries: document.plugins,
                pending_entries: None,
            },
            None => {
                if read_document(&pending_path)?.is_some() {
                    return Err("签名插件契约基线缺失，但存在无法归属的待提交记录".into());
                }
                let store = Self {
                    path,
                    pending_path,
                    entries: candidates,
                    pending_entries: None,
                };
                store.persist()?;
                return Ok((store, BTreeSet::new(), false));
            }
        };
        let recovered_transition = store.recover_pending_transition(&candidates)?;
        let blocked = store.breaking_plugin_ids(&candidates);
        let reviewed = merge_reviewed_entries(&store.entries, candidates, &blocked);
        ensure_plugin_limit(&reviewed)?;
        store.entries = reviewed;
        store.persist()?;
        Ok((store, blocked, recovered_transition))
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
            return Err("存在尚未完成的签名插件契约切换，请重新启动客户端完成恢复".into());
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
            .ok_or("不存在待提交的签名插件契约切换")?;
        persist_document(
            &self.path,
            &PluginApiBaselineDocument {
                schema_version: SCHEMA_VERSION,
                plugins: entries.clone(),
            },
        )?;
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
        if document_matches_candidates(&pending.plugins, candidates) {
            self.entries = pending.plugins;
            self.persist()?;
        } else if !document_matches_candidates(&self.entries, candidates) {
            return Err("插件目录既不匹配已接受契约，也不匹配待提交契约；拒绝猜测恢复结果".into());
        }
        remove_regular_file(&self.pending_path)?;
        Ok(true)
    }

    fn breaking_plugin_ids(&self, candidates: &[PluginApiBaselineEntry]) -> BTreeSet<String> {
        let candidates = candidates
            .iter()
            .map(|entry| (normalized_id(&entry.plugin_id), entry))
            .collect::<BTreeMap<_, _>>();
        self.entries
            .iter()
            .filter_map(|baseline| {
                let candidate = candidates.get(&normalized_id(&baseline.plugin_id))?;
                (!compare_public_api(&baseline.services, &candidate.services).compatible)
                    .then(|| candidate.plugin_id.clone())
            })
            .collect()
    }

    fn persist(&self) -> Result<(), String> {
        persist_document(
            &self.path,
            &PluginApiBaselineDocument {
                schema_version: SCHEMA_VERSION,
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
    for manifest in manifests
        .iter()
        .filter(|manifest| !manifest.plugin_dir.starts_with(local_mapping_root))
    {
        validate_plugin_services(&manifest.plugin_id, &manifest.services)
            .map_err(|error| format!("签名插件契约无效: {error}"))?;
        let metadata = manifest
            .metadata
            .as_ref()
            .ok_or_else(|| format!("签名插件 [{}] 缺少版本元数据", manifest.plugin_id))?;
        if metadata.plugin_id != manifest.plugin_id {
            return Err("签名插件契约身份与版本元数据不一致".into());
        }
        if !identities.insert(normalized_id(&manifest.plugin_id)) {
            return Err("签名插件契约基线包含重复或大小写冲突的插件 ID".into());
        }
        entries.push(PluginApiBaselineEntry {
            plugin_id: manifest.plugin_id.clone(),
            version: metadata.version.clone(),
            services: manifest.services.clone(),
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
    blocked: &BTreeSet<String>,
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
        Err(error) => return Err(format!("无法读取签名插件契约基线: {error}")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("签名插件契约基线必须是普通文件".into());
    }
    if metadata.len() > MAX_DOCUMENT_BYTES {
        return Err("签名插件契约基线超过 4 MiB 限制".into());
    }
    let bytes = fs::read(path).map_err(|error| format!("无法读取签名插件契约基线: {error}"))?;
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err("签名插件契约基线读取期间发生变化或超过 4 MiB 限制".into());
    }
    let document: PluginApiBaselineDocument = serde_json::from_slice(&bytes)
        .map_err(|error| format!("签名插件契约基线格式无效: {error}"))?;
    validate_document(&document)?;
    Ok(Some(document))
}

fn validate_document(document: &PluginApiBaselineDocument) -> Result<(), String> {
    if !matches!(document.schema_version, 1 | SCHEMA_VERSION) {
        return Err(format!(
            "不支持签名插件契约基线版本 {}",
            document.schema_version
        ));
    }
    if document.plugins.len() > MAX_PLUGINS {
        return Err(format!("签名插件契约基线不能超过 {MAX_PLUGINS} 个插件"));
    }
    let mut identities = BTreeSet::new();
    for entry in &document.plugins {
        validate_plugin_services(&entry.plugin_id, &entry.services)
            .map_err(|error| format!("签名插件契约基线声明无效: {error}"))?;
        if !identities.insert(normalized_id(&entry.plugin_id)) {
            return Err("签名插件契约基线包含重复或大小写冲突的插件 ID".into());
        }
    }
    Ok(())
}

fn persist_document(path: &Path, document: &PluginApiBaselineDocument) -> Result<(), String> {
    let parent = path.parent().ok_or("签名插件契约基线缺少父目录")?;
    fs::create_dir_all(parent).map_err(|error| format!("无法创建契约基线目录: {error}"))?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|error| format!("无法检查契约基线目录: {error}"))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err("签名插件契约基线目录必须是普通目录".into());
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("签名插件契约基线目标必须是普通文件".into());
        }
    }
    let mut bytes = serde_json::to_vec_pretty(document)
        .map_err(|error| format!("无法序列化签名插件契约基线: {error}"))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err("签名插件契约基线超过 4 MiB 限制".into());
    }
    let mut temporary = NamedTempFile::new_in(parent)
        .map_err(|error| format!("无法创建签名插件契约基线暂存文件: {error}"))?;
    temporary
        .write_all(&bytes)
        .and_then(|_| temporary.as_file_mut().sync_all())
        .map_err(|error| format!("无法持久化签名插件契约基线: {error}"))?;
    temporary
        .persist(path)
        .map_err(|error| format!("无法原子替换签名插件契约基线: {}", error.error))?;
    sync_directory(parent)?;
    Ok(())
}

fn pending_path(path: &Path) -> Result<PathBuf, String> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("签名插件契约基线文件名无效")?;
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
        .map_err(|error| format!("无法持久化签名插件契约基线目录: {error}"))
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
        return Err(format!("签名插件契约基线不能超过 {MAX_PLUGINS} 个插件"));
    }
    Ok(())
}

fn document_matches_candidates(
    document: &[PluginApiBaselineEntry],
    candidates: &[PluginApiBaselineEntry],
) -> bool {
    let candidates = candidates
        .iter()
        .map(|entry| (normalized_id(&entry.plugin_id), entry))
        .collect::<BTreeMap<_, _>>();
    if candidates.len() != document.iter().filter(|entry| entry.installed).count() {
        return false;
    }
    document.iter().all(|entry| {
        let candidate = candidates.get(&normalized_id(&entry.plugin_id));
        if entry.installed {
            candidate.is_some_and(|candidate| *candidate == entry)
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
        let (_, blocked, recovered) =
            PluginApiBaselineStore::open(path.clone(), &[original], &local_root).unwrap();
        assert!(blocked.is_empty());
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
        let (store, blocked, recovered) =
            PluginApiBaselineStore::open(path.clone(), &[breaking], &local_root).unwrap();
        assert_eq!(blocked, BTreeSet::from(["reader".to_owned()]));
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
        let (_, blocked, recovered) =
            PluginApiBaselineStore::open(path, &[compatible], &local_root).unwrap();
        assert!(blocked.is_empty());
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
        let (mut store, _, _) =
            PluginApiBaselineStore::open(path.clone(), &[original], &local_root).unwrap();

        // An unexplained disappearance is retained as a tombstone so an
        // incompatible same-ID package cannot be reintroduced as a new plugin.
        let (reopened, _, _) =
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
        let (_, blocked, _) =
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
        let (mut store, _, _) =
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
        let (reopened, blocked, _) =
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
        let (mut store, _, _) = PluginApiBaselineStore::open(
            path.clone(),
            std::slice::from_ref(&original),
            &local_root,
        )
        .unwrap();

        store
            .prepare_transition(std::slice::from_ref(&updated), &local_root)
            .unwrap();
        drop(store);
        let (mut rolled_back, blocked, recovered) =
            PluginApiBaselineStore::open(path.clone(), &[original], &local_root).unwrap();
        assert!(blocked.is_empty());
        assert!(recovered);
        assert_eq!(rolled_back.entry_count(), 1);

        rolled_back
            .prepare_transition(std::slice::from_ref(&updated), &local_root)
            .unwrap();
        drop(rolled_back);
        let (committed, blocked, recovered) =
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
        let (mut store, _, _) =
            PluginApiBaselineStore::open(path.clone(), &[original], &local_root).unwrap();
        store.prepare_transition(&[updated], &local_root).unwrap();
        drop(store);

        assert!(PluginApiBaselineStore::open(path, &[unexpected], &local_root).is_err());
    }
}
