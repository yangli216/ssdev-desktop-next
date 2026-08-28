use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use ssdev_config::DesktopConfig;
use webplus_plugin_package::{recover_incomplete_activations_with_committed, RecoveryReport};

use crate::local_mappings::{recover_incomplete_mapping_activations, LocalMappingRecoveryReport};

const PREPARED_JOURNAL: &str = "prepared.json";
const COMMITTED_JOURNAL: &str = "committed.json";
const PREVIOUS_CONFIG: &str = "previous-config.json";
const TARGET_CONFIG: &str = "target-config.json";
const MAX_JOURNAL_BYTES: u64 = 64 * 1024;
const MAX_MEMBERS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProjectActivationKind {
    SignedPlugin,
    LocalMapping,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProjectActivationMember {
    pub(crate) plugin_id: String,
    pub(crate) kind: ProjectActivationKind,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProjectActivationJournal {
    schema_version: u8,
    members: Vec<ProjectActivationMember>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ProjectRecoveryReport {
    pub(crate) recovered_project_transaction: bool,
    pub(crate) plugin: RecoveryReport,
    pub(crate) local_mapping: LocalMappingRecoveryReport,
}

impl ProjectRecoveryReport {
    pub(crate) fn total(self) -> usize {
        usize::from(self.recovered_project_transaction)
            .saturating_add(self.plugin.rolled_back_activations)
            .saturating_add(self.plugin.finalized_activations)
            .saturating_add(self.plugin.removed_committed_transactions)
            .saturating_add(self.plugin.removed_staging_directories)
            .saturating_add(self.local_mapping.total())
    }
}

pub(crate) struct ProjectActivation {
    root: PathBuf,
    finalized: bool,
}

impl ProjectActivation {
    pub(crate) fn begin(
        root: &Path,
        previous_config: &DesktopConfig,
        target_config: &DesktopConfig,
        members: Vec<ProjectActivationMember>,
    ) -> Result<Self, String> {
        validate_members(&members)?;
        let parent = root.parent().ok_or("项目事务目录缺少父目录")?;
        fs::create_dir_all(parent).map_err(|error| format!("无法创建项目事务父目录: {error}"))?;
        if root.exists() {
            return Err("存在尚未恢复的项目导入事务，请重新启动客户端后重试".into());
        }
        fs::create_dir(root).map_err(|error| format!("无法创建项目事务目录: {error}"))?;
        let created = (|| {
            ssdev_config::export_config_file(&root.join(PREVIOUS_CONFIG), previous_config)
                .map_err(|error| format!("无法保存项目导入前配置: {error}"))?;
            ssdev_config::export_config_file(&root.join(TARGET_CONFIG), target_config)
                .map_err(|error| format!("无法保存项目目标配置: {error}"))?;
            write_journal(
                &root.join(PREPARED_JOURNAL),
                &ProjectActivationJournal {
                    schema_version: 1,
                    members,
                },
            )?;
            sync_directory(root)
        })();
        if let Err(error) = created {
            let _ = fs::remove_dir_all(root);
            return Err(error);
        }
        Ok(Self {
            root: root.to_path_buf(),
            finalized: false,
        })
    }

    pub(crate) fn mark_committed(&self) -> Result<(), String> {
        fs::rename(
            self.root.join(PREPARED_JOURNAL),
            self.root.join(COMMITTED_JOURNAL),
        )
        .map_err(|error| format!("无法持久化项目切换提交点: {error}"))?;
        sync_directory(&self.root)
    }

    pub(crate) fn finish(mut self) -> Result<(), String> {
        let parent = self.root.parent().map(Path::to_path_buf);
        fs::remove_dir_all(&self.root).map_err(|error| format!("无法清理项目事务: {error}"))?;
        if let Some(parent) = parent {
            sync_directory(&parent)?;
        }
        self.finalized = true;
        Ok(())
    }

    pub(crate) fn abort(self) -> Result<(), String> {
        self.finish()
    }
}

impl Drop for ProjectActivation {
    fn drop(&mut self) {
        if !self.finalized {
            tracing::warn!(
                event_code = "project-activation-recovery-deferred",
                "project activation transaction requires recovery"
            );
        }
    }
}

pub(crate) fn recover(
    root: &Path,
    config_path: &Path,
    plugin_root: &Path,
    local_mapping_root: &Path,
) -> Result<ProjectRecoveryReport, String> {
    recover_inner(root, config_path, plugin_root, local_mapping_root, true)
}

pub(crate) fn recover_runtime(
    root: &Path,
    config_path: &Path,
    plugin_root: &Path,
    local_mapping_root: &Path,
) -> Result<ProjectRecoveryReport, String> {
    recover_inner(root, config_path, plugin_root, local_mapping_root, false)
}

fn recover_inner(
    root: &Path,
    config_path: &Path,
    plugin_root: &Path,
    local_mapping_root: &Path,
    allow_config_restore: bool,
) -> Result<ProjectRecoveryReport, String> {
    let mut report = ProjectRecoveryReport::default();
    let mut committed_plugins = HashSet::new();
    let mut committed_mappings = HashSet::new();
    if root.exists() {
        let metadata =
            fs::symlink_metadata(root).map_err(|error| format!("无法检查项目事务目录: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("项目事务路径不是安全的真实目录".into());
        }
        let prepared = root.join(PREPARED_JOURNAL);
        let committed = root.join(COMMITTED_JOURNAL);
        let (journal_path, is_committed) = match (prepared.is_file(), committed.is_file()) {
            (true, false) => (prepared, false),
            (false, true) => (committed, true),
            _ => return Err("项目事务提交状态不完整或存在歧义".into()),
        };
        let journal = read_journal(&journal_path)?;
        validate_members(&journal.members)?;
        if is_committed {
            let target = ssdev_config::load_config_file(&root.join(TARGET_CONFIG))
                .map_err(|error| format!("无法读取项目目标配置: {error}"))?;
            ssdev_config::export_config_file(config_path, &target)
                .map_err(|error| format!("无法完成已提交项目配置: {error}"))?;
            for member in journal.members {
                match member.kind {
                    ProjectActivationKind::SignedPlugin => {
                        committed_plugins.insert(member.plugin_id);
                    }
                    ProjectActivationKind::LocalMapping => {
                        committed_mappings.insert(member.plugin_id);
                    }
                }
            }
        } else if allow_config_restore {
            let previous = ssdev_config::load_config_file(&root.join(PREVIOUS_CONFIG))
                .map_err(|error| format!("无法读取项目导入前配置: {error}"))?;
            ssdev_config::export_config_file(config_path, &previous)
                .map_err(|error| format!("无法恢复项目导入前配置: {error}"))?;
        } else {
            return Err("项目导入需要在启动阶段恢复，请重新启动客户端后重试".into());
        }
        report.recovered_project_transaction = true;
    }

    report.plugin = recover_incomplete_activations_with_committed(plugin_root, &committed_plugins)
        .map_err(|error| format!("签名插件事务恢复失败: {error}"))?;
    report.local_mapping =
        recover_incomplete_mapping_activations(local_mapping_root, &committed_mappings)
            .map_err(|error| format!("本地映射事务恢复失败: {error}"))?;
    if report.recovered_project_transaction {
        fs::remove_dir_all(root).map_err(|error| format!("无法清理已恢复项目事务: {error}"))?;
        if let Some(parent) = root.parent() {
            sync_directory(parent)?;
        }
    }
    Ok(report)
}

fn validate_members(members: &[ProjectActivationMember]) -> Result<(), String> {
    if members.len() > MAX_MEMBERS {
        return Err(format!("项目事务最多包含 {MAX_MEMBERS} 个组件"));
    }
    let mut ids = HashSet::new();
    for member in members {
        let path = Path::new(&member.plugin_id);
        if member.plugin_id.trim().is_empty()
            || member.plugin_id.starts_with('.')
            || member.plugin_id.chars().count() > 128
            || member.plugin_id.chars().any(char::is_control)
            || member.plugin_id.contains(['/', '\\'])
            || path.components().count() != 1
            || !matches!(path.components().next(), Some(Component::Normal(_)))
        {
            return Err("项目事务包含无效组件 ID".into());
        }
        if !ids.insert(member.plugin_id.clone()) {
            return Err(format!("项目事务包含重复组件 [{}]", member.plugin_id));
        }
    }
    Ok(())
}

fn write_journal(path: &Path, journal: &ProjectActivationJournal) -> Result<(), String> {
    let bytes =
        serde_json::to_vec(journal).map_err(|error| format!("无法编码项目事务: {error}"))?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err("项目事务记录超过大小上限".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("无法创建项目事务记录: {error}"))?;
    file.write_all(&bytes)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("无法持久化项目事务记录: {error}"))
}

fn read_journal(path: &Path) -> Result<ProjectActivationJournal, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("无法检查项目事务记录: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_JOURNAL_BYTES
    {
        return Err("项目事务记录不是受支持的普通文件".into());
    }
    let bytes = fs::read(path).map_err(|error| format!("无法读取项目事务记录: {error}"))?;
    let journal: ProjectActivationJournal =
        serde_json::from_slice(&bytes).map_err(|error| format!("项目事务记录无效: {error}"))?;
    if journal.schema_version != 1 {
        return Err(format!("不支持项目事务版本 {}", journal.schema_version));
    }
    Ok(journal)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("无法持久化项目事务目录: {error}"))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_mappings::{prepare, LocalMappingDefinition};

    fn config(website: &str) -> DesktopConfig {
        DesktopConfig {
            website: Some(website.to_owned()),
            ..DesktopConfig::default()
        }
    }

    fn mapping_definition(component: &Path) -> LocalMappingDefinition {
        serde_json::from_value(serde_json::json!({
            "schemaVersion": 1,
            "pluginId": "reader.local",
            "displayName": "Reader local mapping",
            "services": [{
                "serviceId": "ReaderService",
                "mainClass": component,
                "mainType": "bat",
                "architecture": "x86",
                "methods": [{"name": "read", "returnType": "string", "parameters": []}]
            }]
        }))
        .unwrap()
    }

    #[test]
    fn prepared_recovery_restores_the_previous_config() {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("config.json");
        let transaction_root = root.path().join("project-activation");
        let plugins = root.path().join("plugins");
        let mappings = root.path().join("mappings");
        let component = root.path().join("reader.bat");
        fs::write(&component, b"old mapping").unwrap();
        prepare(&mappings, mapping_definition(&component))
            .unwrap()
            .activate(&mappings)
            .unwrap()
            .commit()
            .unwrap();
        ssdev_config::export_config_file(&config_path, &config("https://old.example.test"))
            .unwrap();
        let activation = ProjectActivation::begin(
            &transaction_root,
            &config("https://old.example.test"),
            &config("https://new.example.test"),
            vec![ProjectActivationMember {
                plugin_id: "reader.local".into(),
                kind: ProjectActivationKind::LocalMapping,
            }],
        )
        .unwrap();
        fs::write(&component, b"new mapping").unwrap();
        let mapping_activation = prepare(&mappings, mapping_definition(&component))
            .unwrap()
            .activate(&mappings)
            .unwrap();
        std::mem::forget(mapping_activation);
        ssdev_config::export_config_file(&config_path, &config("https://new.example.test"))
            .unwrap();
        std::mem::forget(activation);

        let report = recover(&transaction_root, &config_path, &plugins, &mappings).unwrap();
        assert!(report.recovered_project_transaction);
        assert_eq!(
            ssdev_config::load_config_file(&config_path)
                .unwrap()
                .website
                .as_deref(),
            Some("https://old.example.test")
        );
        assert_eq!(
            fs::read(mappings.join("reader.local/components/0-reader.bat")).unwrap(),
            b"old mapping"
        );
        assert!(!transaction_root.exists());
    }

    #[test]
    fn runtime_recovery_refuses_to_desynchronize_an_in_memory_config() {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("config.json");
        let transaction_root = root.path().join("project-activation");
        let plugins = root.path().join("plugins");
        let mappings = root.path().join("mappings");
        ssdev_config::export_config_file(&config_path, &config("https://old.example.test"))
            .unwrap();
        let activation = ProjectActivation::begin(
            &transaction_root,
            &config("https://old.example.test"),
            &config("https://new.example.test"),
            Vec::new(),
        )
        .unwrap();
        ssdev_config::export_config_file(&config_path, &config("https://new.example.test"))
            .unwrap();
        std::mem::forget(activation);

        assert!(recover_runtime(&transaction_root, &config_path, &plugins, &mappings).is_err());
        assert_eq!(
            ssdev_config::load_config_file(&config_path)
                .unwrap()
                .website
                .as_deref(),
            Some("https://new.example.test")
        );
        assert!(transaction_root.exists());
    }

    #[test]
    fn committed_recovery_keeps_the_new_config() {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("config.json");
        let transaction_root = root.path().join("project-activation");
        let plugins = root.path().join("plugins");
        let mappings = root.path().join("mappings");
        let component = root.path().join("reader.bat");
        fs::write(&component, b"old mapping").unwrap();
        prepare(&mappings, mapping_definition(&component))
            .unwrap()
            .activate(&mappings)
            .unwrap()
            .commit()
            .unwrap();
        ssdev_config::export_config_file(&config_path, &config("https://old.example.test"))
            .unwrap();
        let activation = ProjectActivation::begin(
            &transaction_root,
            &config("https://old.example.test"),
            &config("https://new.example.test"),
            vec![ProjectActivationMember {
                plugin_id: "reader.local".into(),
                kind: ProjectActivationKind::LocalMapping,
            }],
        )
        .unwrap();
        fs::write(&component, b"new mapping").unwrap();
        let mapping_activation = prepare(&mappings, mapping_definition(&component))
            .unwrap()
            .activate(&mappings)
            .unwrap();
        std::mem::forget(mapping_activation);
        ssdev_config::export_config_file(&config_path, &config("https://new.example.test"))
            .unwrap();
        activation.mark_committed().unwrap();
        std::mem::forget(activation);
        ssdev_config::export_config_file(&config_path, &config("https://drift.example.test"))
            .unwrap();

        recover(&transaction_root, &config_path, &plugins, &mappings).unwrap();
        assert_eq!(
            ssdev_config::load_config_file(&config_path)
                .unwrap()
                .website
                .as_deref(),
            Some("https://new.example.test")
        );
        assert_eq!(
            fs::read(mappings.join("reader.local/components/0-reader.bat")).unwrap(),
            b"new mapping"
        );
    }

    #[test]
    fn transaction_rejects_unsafe_or_duplicate_component_ids() {
        let root = tempfile::tempdir().unwrap();
        let config = DesktopConfig::default();
        assert!(ProjectActivation::begin(
            &root.path().join("unsafe"),
            &config,
            &config,
            vec![ProjectActivationMember {
                plugin_id: "../outside".into(),
                kind: ProjectActivationKind::SignedPlugin,
            }],
        )
        .is_err());
        assert!(ProjectActivation::begin(
            &root.path().join("duplicate"),
            &config,
            &config,
            vec![
                ProjectActivationMember {
                    plugin_id: "reader".into(),
                    kind: ProjectActivationKind::SignedPlugin,
                },
                ProjectActivationMember {
                    plugin_id: "reader".into(),
                    kind: ProjectActivationKind::LocalMapping,
                },
            ],
        )
        .is_err());
    }
}
