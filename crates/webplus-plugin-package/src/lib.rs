use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tempfile::{Builder as TempBuilder, TempDir};
use thiserror::Error;
use webplus_plugin_config::{PluginManifest, PluginMetadata};
use webplus_plugin_trust::{
    portable_plugin_path, prepare_signing_material, read_identity, PluginIdentity, TrustError,
    TrustStore, SIGNATURE_FILENAME,
};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter};

const MAX_PACKAGE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 4096;
const MAX_TRANSACTION_JOURNAL_BYTES: u64 = 64 * 1024;
const ACTIVATION_PREFIX: &str = ".activation-";
const COMMITTED_PREFIX: &str = ".committed-";
const STAGING_PREFIX: &str = ".staging-";
const TRANSACTION_JOURNAL: &str = "transaction.json";

/// Creates a byte-for-byte reproducible, already verified `.ssdev-plugin`
/// archive. Existing outputs are never overwritten.
pub fn create_deterministic_package(
    plugin_dir: &Path,
    package_path: &Path,
    trust_store: &TrustStore,
) -> Result<PluginIdentity, PackageError> {
    if package_path.extension().and_then(|value| value.to_str()) != Some("ssdev-plugin") {
        return Err(PackageError::Invalid(
            "package output must use the .ssdev-plugin extension".into(),
        ));
    }
    let plugin_dir = plugin_dir
        .canonicalize()
        .map_err(|source| PackageError::Io {
            path: plugin_dir.to_path_buf(),
            source,
        })?;
    require_real_directory(&plugin_dir, "plugin source")?;
    let package_parent = package_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_metadata =
        fs::symlink_metadata(package_parent).map_err(|source| PackageError::Io {
            path: package_parent.to_path_buf(),
            source,
        })?;
    if !parent_metadata.file_type().is_dir() {
        return Err(PackageError::Invalid(
            "package output parent must be an existing real directory".into(),
        ));
    }
    let package_parent = package_parent
        .canonicalize()
        .map_err(|source| PackageError::Io {
            path: package_parent.to_path_buf(),
            source,
        })?;
    let package_name = package_path
        .file_name()
        .ok_or_else(|| PackageError::Invalid("package output must have a file name".into()))?;
    let package_path = package_parent.join(package_name);
    if package_path.starts_with(&plugin_dir) {
        return Err(PackageError::Invalid(
            "package output must be outside the signed plugin directory".into(),
        ));
    }
    match fs::symlink_metadata(&package_path) {
        Ok(_) => {
            return Err(PackageError::Invalid(format!(
                "package output already exists: {package_path:?}"
            )))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(PackageError::Io {
                path: package_path.clone(),
                source,
            })
        }
    }

    let identity = read_identity(&plugin_dir)?;
    let manifest = PluginManifest::load(&identity.plugin_id, &plugin_dir)?;
    if manifest.metadata.is_none() {
        return Err(PackageError::Invalid(
            "signed plugin packages must contain plugin.json".into(),
        ));
    }
    trust_store.verify_for_issuance(&manifest)?;
    let material = prepare_signing_material(&plugin_dir, &identity.plugin_id, &identity.key_id)?;
    let mut files = material.files.keys().cloned().collect::<Vec<_>>();
    files.push(SIGNATURE_FILENAME.into());
    files.sort();

    let mut temporary = TempBuilder::new()
        .prefix(".ssdev-package-")
        .suffix(".tmp")
        .tempfile_in(&package_parent)
        .map_err(|source| PackageError::Io {
            path: package_parent.clone(),
            source,
        })?;
    {
        let mut zip = ZipWriter::new(temporary.as_file_mut());
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .last_modified_time(DateTime::default())
            .unix_permissions(0o644);
        for relative in files {
            zip.start_file(&relative, options)?;
            let source_path = plugin_dir.join(Path::new(&relative));
            let mut source = File::open(&source_path).map_err(|source| PackageError::Io {
                path: source_path.clone(),
                source,
            })?;
            io::copy(&mut source, &mut zip).map_err(|source| PackageError::Io {
                path: source_path,
                source,
            })?;
        }
        zip.finish()?;
    }
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| PackageError::Io {
            path: package_path.clone(),
            source,
        })?;
    let verification = TempBuilder::new()
        .prefix(".ssdev-package-verify-")
        .tempdir_in(&package_parent)
        .map_err(|source| PackageError::Io {
            path: package_parent.clone(),
            source,
        })?;
    extract_package(temporary.path(), verification.path())?;
    let packaged_identity = read_identity(verification.path())?;
    if packaged_identity.plugin_id != identity.plugin_id
        || packaged_identity.key_id != identity.key_id
    {
        return Err(PackageError::Invalid(
            "packaged plugin identity changed while the archive was created".into(),
        ));
    }
    let packaged_manifest =
        PluginManifest::load(&packaged_identity.plugin_id, verification.path())?;
    trust_store.verify_for_issuance(&packaged_manifest)?;
    temporary
        .persist_noclobber(&package_path)
        .map_err(|error| PackageError::Io {
            path: package_path,
            source: error.error,
        })?;
    sync_directory(&package_parent)?;
    Ok(identity)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), PackageError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| PackageError::Io {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), PackageError> {
    Ok(())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    pub rolled_back_activations: usize,
    pub finalized_activations: usize,
    pub removed_committed_transactions: usize,
    pub removed_staging_directories: usize,
}

impl RecoveryReport {
    pub fn recovered_anything(self) -> bool {
        self.rolled_back_activations > 0
            || self.finalized_activations > 0
            || self.removed_committed_transactions > 0
            || self.removed_staging_directories > 0
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActivationJournal {
    schema_version: u8,
    plugin_id: String,
    had_previous: bool,
}

/// Restores the pre-install state after a process crash or power loss.
///
/// An `.activation-*` directory is the durable rollback marker. A successful
/// commit atomically renames it to `.committed-*`; those directories only need
/// cleanup. Callers must serialize this function with package preparation and
/// activation so live staging directories cannot be mistaken for crash debris.
pub fn recover_incomplete_activations(plugin_root: &Path) -> Result<RecoveryReport, PackageError> {
    recover_incomplete_activations_with_committed(plugin_root, &HashSet::new())
}

/// Recovers standalone activations and finalizes the members of a durable
/// higher-level transaction that was already committed as one set.
pub fn recover_incomplete_activations_with_committed(
    plugin_root: &Path,
    committed_plugin_ids: &HashSet<String>,
) -> Result<RecoveryReport, PackageError> {
    fs::create_dir_all(plugin_root).map_err(|source| PackageError::Io {
        path: plugin_root.to_path_buf(),
        source,
    })?;
    let plugin_root = plugin_root
        .canonicalize()
        .map_err(|source| PackageError::Io {
            path: plugin_root.to_path_buf(),
            source,
        })?;
    let mut entries = fs::read_dir(&plugin_root)
        .map_err(|source| PackageError::Io {
            path: plugin_root.clone(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| PackageError::Io {
            path: plugin_root.clone(),
            source,
        })?;
    entries.sort_by_key(std::fs::DirEntry::file_name);

    let mut report = RecoveryReport::default();
    let mut activation_plugins = HashSet::new();
    let mut activations = Vec::new();
    for entry in entries {
        let file_type = entry.file_type().map_err(|source| PackageError::Io {
            path: entry.path(),
            source,
        })?;
        if !file_type.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(COMMITTED_PREFIX) {
            remove_directory(&entry.path())?;
            report.removed_committed_transactions += 1;
        } else if name.starts_with(STAGING_PREFIX) {
            remove_directory(&entry.path())?;
            report.removed_staging_directories += 1;
        } else if name.starts_with(ACTIVATION_PREFIX) {
            let journal = read_activation_journal(&entry.path())?;
            validated_plugin_target(&plugin_root, &journal.plugin_id)?;
            if !activation_plugins.insert(journal.plugin_id.clone()) {
                return Err(PackageError::Invalid(format!(
                    "multiple incomplete activation transactions exist for plugin [{}]",
                    journal.plugin_id
                )));
            }
            activations.push((entry.path(), journal));
        }
    }

    for (transaction, journal) in activations {
        if committed_plugin_ids.contains(&journal.plugin_id) {
            commit_transaction(&plugin_root, &transaction)?;
            report.finalized_activations += 1;
        } else {
            rollback_transaction(&plugin_root, &transaction, &journal)?;
            report.rolled_back_activations += 1;
        }
    }
    Ok(report)
}

pub struct PreparedPlugin {
    plugin_root: PathBuf,
    staging: TempDir,
    identity: PluginIdentity,
    metadata: PluginMetadata,
    manifest: PluginManifest,
}

impl PreparedPlugin {
    pub fn prepare(
        package_path: &Path,
        plugin_root: &Path,
        trust_store: &TrustStore,
    ) -> Result<Self, PackageError> {
        let metadata = fs::metadata(package_path).map_err(|source| PackageError::Io {
            path: package_path.to_path_buf(),
            source,
        })?;
        if !metadata.is_file() {
            return Err(PackageError::Invalid("package path is not a file".into()));
        }
        if metadata.len() > MAX_PACKAGE_BYTES {
            return Err(PackageError::TooLarge {
                actual: metadata.len(),
                limit: MAX_PACKAGE_BYTES,
            });
        }

        fs::create_dir_all(plugin_root).map_err(|source| PackageError::Io {
            path: plugin_root.to_path_buf(),
            source,
        })?;
        let plugin_root = plugin_root
            .canonicalize()
            .map_err(|source| PackageError::Io {
                path: plugin_root.to_path_buf(),
                source,
            })?;
        let staging = TempBuilder::new()
            .prefix(STAGING_PREFIX)
            .tempdir_in(&plugin_root)
            .map_err(|source| PackageError::Io {
                path: plugin_root.clone(),
                source,
            })?;
        extract_package(package_path, staging.path())?;

        let identity = read_identity(staging.path())?;
        let manifest = PluginManifest::load(&identity.plugin_id, staging.path())?;
        let metadata = manifest.metadata.clone().ok_or_else(|| {
            PackageError::Invalid("signed plugin packages must contain plugin.json".into())
        })?;
        if metadata.plugin_id != identity.plugin_id {
            return Err(PackageError::Invalid(
                "plugin.json ID does not match plugin-signature.json".into(),
            ));
        }
        trust_store.verify(&manifest)?;
        Ok(Self {
            plugin_root,
            staging,
            identity,
            metadata,
            manifest,
        })
    }

    pub fn identity(&self) -> &PluginIdentity {
        &self.identity
    }

    pub fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    pub fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    pub fn activate(self) -> Result<PluginActivation, PackageError> {
        let target = validated_plugin_target(&self.plugin_root, &self.identity.plugin_id)?;
        if target.exists() {
            require_real_directory(&target, "existing plugin target")?;
        }
        let transaction_temp = TempBuilder::new()
            .prefix(ACTIVATION_PREFIX)
            .tempdir_in(&self.plugin_root)
            .map_err(|source| PackageError::Io {
                path: self.plugin_root.clone(),
                source,
            })?;
        let transaction = transaction_temp.keep();
        let previous = transaction.join("previous");
        let had_previous = target.exists();
        let journal = ActivationJournal {
            schema_version: 1,
            plugin_id: self.identity.plugin_id.clone(),
            had_previous,
        };
        if let Err(error) = write_activation_journal(&transaction, &journal) {
            let _ = fs::remove_dir_all(&transaction);
            return Err(error);
        }
        if had_previous {
            if let Err(source) = fs::rename(&target, &previous) {
                let _ = fs::remove_dir_all(&transaction);
                return Err(PackageError::Io {
                    path: target.clone(),
                    source,
                });
            }
        }

        let staging = self.staging.keep();
        if let Err(source) = fs::rename(&staging, &target) {
            if had_previous {
                if fs::rename(&previous, &target).is_ok() {
                    let _ = fs::remove_dir_all(&transaction);
                }
            } else {
                let _ = fs::remove_dir_all(&transaction);
            }
            let _ = fs::remove_dir_all(&staging);
            return Err(PackageError::Io {
                path: target,
                source,
            });
        }

        Ok(PluginActivation {
            plugin_root: self.plugin_root,
            target,
            transaction,
            had_previous,
            finalized: false,
        })
    }
}

/// Moves an installed plugin into the same durable activation transaction used
/// by upgrades. Committing removes the backup; dropping or rolling back restores
/// the exact previous directory. Startup recovery therefore treats an
/// interrupted removal as an uncommitted change instead of losing the plugin.
pub fn prepare_plugin_removal(
    plugin_root: &Path,
    plugin_id: &str,
) -> Result<PluginActivation, PackageError> {
    fs::create_dir_all(plugin_root).map_err(|source| PackageError::Io {
        path: plugin_root.to_path_buf(),
        source,
    })?;
    let plugin_root = plugin_root
        .canonicalize()
        .map_err(|source| PackageError::Io {
            path: plugin_root.to_path_buf(),
            source,
        })?;
    let target = validated_plugin_target(&plugin_root, plugin_id)?;
    require_real_directory(&target, "installed plugin target")?;
    let transaction = TempBuilder::new()
        .prefix(ACTIVATION_PREFIX)
        .tempdir_in(&plugin_root)
        .map_err(|source| PackageError::Io {
            path: plugin_root.clone(),
            source,
        })?
        .keep();
    let journal = ActivationJournal {
        schema_version: 1,
        plugin_id: plugin_id.to_owned(),
        had_previous: true,
    };
    if let Err(error) = write_activation_journal(&transaction, &journal) {
        let _ = fs::remove_dir_all(&transaction);
        return Err(error);
    }
    let previous = transaction.join("previous");
    if let Err(source) = fs::rename(&target, &previous) {
        let _ = fs::remove_dir_all(&transaction);
        return Err(PackageError::Io {
            path: target.clone(),
            source,
        });
    }
    Ok(PluginActivation {
        plugin_root,
        target,
        transaction,
        had_previous: true,
        finalized: false,
    })
}

pub struct PluginActivation {
    plugin_root: PathBuf,
    target: PathBuf,
    transaction: PathBuf,
    had_previous: bool,
    finalized: bool,
}

impl PluginActivation {
    pub fn transaction_root(&self) -> &Path {
        &self.transaction
    }

    pub fn commit(mut self) -> Result<(), PackageError> {
        commit_transaction(&self.plugin_root, &self.transaction)?;
        self.finalized = true;
        Ok(())
    }

    /// Finalizes a member after its enclosing set has durably committed. A
    /// cleanup error leaves the activation journal for set-level recovery and
    /// must never make Drop roll the already-committed member back.
    pub fn commit_grouped(mut self) -> Result<(), PackageError> {
        self.finalized = true;
        commit_transaction(&self.plugin_root, &self.transaction)
    }

    pub fn rollback(mut self) -> Result<(), PackageError> {
        self.rollback_inner()?;
        self.finalized = true;
        Ok(())
    }

    fn rollback_inner(&mut self) -> Result<(), PackageError> {
        rollback_transaction(
            &self.plugin_root,
            &self.transaction,
            &ActivationJournal {
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
    }
}

fn commit_transaction(plugin_root: &Path, transaction: &Path) -> Result<(), PackageError> {
    let transaction_name = transaction
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| PackageError::Invalid("activation transaction name is invalid".into()))?;
    let suffix = transaction_name
        .strip_prefix(ACTIVATION_PREFIX)
        .ok_or_else(|| PackageError::Invalid("activation transaction prefix is invalid".into()))?;
    let committed = plugin_root.join(format!("{COMMITTED_PREFIX}{suffix}"));
    fs::rename(transaction, &committed).map_err(|source| PackageError::Io {
        path: transaction.to_path_buf(),
        source,
    })?;
    if let Err(cleanup_failure) = fs::remove_dir_all(&committed) {
        tracing::warn!(
            event_code = "plugin-transaction-cleanup-deferred",
            failure_kind = ?cleanup_failure.kind(),
            "committed plugin transaction cleanup deferred until next startup"
        );
    }
    Ok(())
}

fn write_activation_journal(
    transaction: &Path,
    journal: &ActivationJournal,
) -> Result<(), PackageError> {
    let path = transaction.join(TRANSACTION_JOURNAL);
    let bytes = serde_json::to_vec(journal).map_err(|error| {
        PackageError::Invalid(format!("cannot encode activation journal: {error}"))
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|source| PackageError::Io {
            path: path.clone(),
            source,
        })?;
    file.write_all(&bytes)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all())
        .map_err(|source| PackageError::Io { path, source })
}

fn read_activation_journal(transaction: &Path) -> Result<ActivationJournal, PackageError> {
    let path = transaction.join(TRANSACTION_JOURNAL);
    let metadata = fs::symlink_metadata(&path).map_err(|source| PackageError::Io {
        path: path.clone(),
        source,
    })?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_TRANSACTION_JOURNAL_BYTES {
        return Err(PackageError::Invalid(format!(
            "activation journal at {path:?} is not a bounded regular file"
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(&path)
        .and_then(|file| {
            file.take(MAX_TRANSACTION_JOURNAL_BYTES + 1)
                .read_to_end(&mut bytes)
        })
        .map_err(|source| PackageError::Io {
            path: path.clone(),
            source,
        })?;
    if bytes.len() as u64 > MAX_TRANSACTION_JOURNAL_BYTES {
        return Err(PackageError::Invalid(format!(
            "activation journal at {path:?} exceeds its size limit"
        )));
    }
    let journal: ActivationJournal = serde_json::from_slice(&bytes).map_err(|error| {
        PackageError::Invalid(format!(
            "activation journal at {path:?} is invalid: {error}"
        ))
    })?;
    if journal.schema_version != 1 {
        return Err(PackageError::Invalid(format!(
            "activation journal at {path:?} has unsupported schema {}",
            journal.schema_version
        )));
    }
    Ok(journal)
}

fn validated_plugin_target(plugin_root: &Path, plugin_id: &str) -> Result<PathBuf, PackageError> {
    let path = Path::new(plugin_id);
    if webplus_plugin_config::validate_portable_plugin_id(plugin_id).is_err()
        || portable_plugin_path(path)? != plugin_id
    {
        return Err(PackageError::Invalid(format!(
            "activation journal contains unsafe plugin ID [{plugin_id}]"
        )));
    }
    Ok(plugin_root.join(plugin_id))
}

fn rollback_transaction(
    plugin_root: &Path,
    transaction: &Path,
    journal: &ActivationJournal,
) -> Result<(), PackageError> {
    let target = validated_plugin_target(plugin_root, &journal.plugin_id)?;
    let previous = transaction.join("previous");
    if journal.had_previous {
        if previous.exists() {
            require_real_directory(&previous, "previous plugin backup")?;
            if target.exists() {
                require_real_directory(&target, "active plugin target")?;
                remove_directory(&target)?;
            }
            fs::rename(&previous, &target).map_err(|source| PackageError::Io {
                path: target.clone(),
                source,
            })?;
        } else {
            if !target.exists() {
                return Err(PackageError::Invalid(format!(
                    "cannot recover plugin [{}]: neither active nor previous directory exists",
                    journal.plugin_id
                )));
            }
            require_real_directory(&target, "restored plugin target")?;
        }
    } else if target.exists() {
        require_real_directory(&target, "interrupted plugin target")?;
        remove_directory(&target)?;
    }
    remove_directory(transaction)
}

fn remove_directory(path: &Path) -> Result<(), PackageError> {
    fs::remove_dir_all(path).map_err(|source| PackageError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn require_real_directory(path: &Path, role: &str) -> Result<(), PackageError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| PackageError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_dir() {
        return Err(PackageError::Invalid(format!(
            "{role} at {path:?} is not a real directory"
        )));
    }
    Ok(())
}

impl Drop for PluginActivation {
    fn drop(&mut self) {
        if !self.finalized && self.rollback_inner().is_err() {
            tracing::error!(
                event_code = "plugin-rollback-failed",
                "plugin activation rollback failed"
            );
        }
    }
}

fn extract_package(package_path: &Path, destination: &Path) -> Result<(), PackageError> {
    let file = File::open(package_path).map_err(|source| PackageError::Io {
        path: package_path.to_path_buf(),
        source,
    })?;
    let mut archive = ZipArchive::new(file)?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(PackageError::Invalid(format!(
            "archive contains more than {MAX_ARCHIVE_ENTRIES} entries"
        )));
    }

    let mut total_bytes = 0_u64;
    let mut paths = HashSet::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        if entry.encrypted() {
            return Err(PackageError::Invalid(
                "encrypted plugin packages are not supported".into(),
            ));
        }
        let relative = entry.enclosed_name().ok_or_else(|| {
            PackageError::Invalid(format!(
                "archive entry [{}] has an unsafe path",
                entry.name()
            ))
        })?;
        if relative.as_os_str().is_empty() {
            return Err(PackageError::Invalid(
                "archive contains an empty path".into(),
            ));
        }
        let portable_path = portable_plugin_path(&relative)?;
        if !paths.insert(portable_path.to_lowercase()) {
            return Err(PackageError::Invalid(format!(
                "archive contains duplicate path {relative:?}"
            )));
        }
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err(PackageError::Invalid(format!(
                "archive contains a symbolic link at {relative:?}"
            )));
        }

        let output = destination.join(&relative);
        if entry.is_dir() {
            fs::create_dir_all(&output).map_err(|source| PackageError::Io {
                path: output,
                source,
            })?;
            continue;
        }
        let declared_size = entry.size();
        total_bytes = total_bytes.saturating_add(declared_size);
        if total_bytes > MAX_PACKAGE_BYTES {
            return Err(PackageError::TooLarge {
                actual: total_bytes,
                limit: MAX_PACKAGE_BYTES,
            });
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent).map_err(|source| PackageError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let mut output_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)
            .map_err(|source| PackageError::Io {
                path: output.clone(),
                source,
            })?;
        let copied = io::copy(
            &mut entry.by_ref().take(declared_size + 1),
            &mut output_file,
        )
        .map_err(|source| PackageError::Io {
            path: output.clone(),
            source,
        })?;
        if copied != declared_size {
            return Err(PackageError::Invalid(format!(
                "archive entry {relative:?} declared {} bytes but produced {copied}",
                declared_size
            )));
        }
        output_file.flush().map_err(|source| PackageError::Io {
            path: output,
            source,
        })?;
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum PackageError {
    #[error("plugin package is invalid: {0}")]
    Invalid(String),
    #[error("plugin package size {actual} exceeds limit {limit}")]
    TooLarge { actual: u64, limit: u64 },
    #[error("filesystem operation failed at {path:?}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("ZIP package error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("plugin manifest error: {0}")]
    Manifest(#[from] webplus_plugin_config::ConfigError),
    #[error("plugin signature error: {0}")]
    Trust(#[from] TrustError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use std::io::Write;
    use tempfile::tempdir;
    use webplus_plugin_trust::{prepare_signing_material, SIGNATURE_FILENAME};
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    fn trust_store(root: &Path, signing_key: &SigningKey) -> TrustStore {
        let path = root.join("trust.json");
        fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "keys": [{
                    "keyId": "test-key",
                    "algorithm": "ed25519",
                    "publicKey": BASE64.encode(signing_key.verifying_key().to_bytes()),
                    "purposes": ["plugin"]
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        TrustStore::load(&path).unwrap()
    }

    fn signed_plugin(root: &Path, signing_key: &SigningKey) -> PathBuf {
        let plugin = root.join("source");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("api.json"),
            r#"{"serviceId":"reader","mainClass":"reader.dll"}"#,
        )
        .unwrap();
        fs::write(
            plugin.join("plugin.json"),
            r#"{"schemaVersion":1,"pluginId":"reader-plugin","version":"1.2.3","displayName":"Reader"}"#,
        )
        .unwrap();
        fs::write(plugin.join("reader.dll"), b"signed fixture").unwrap();
        let material = prepare_signing_material(&plugin, "reader-plugin", "test-key").unwrap();
        let signature = signing_key.sign(&material.payload);
        fs::write(
            plugin.join(SIGNATURE_FILENAME),
            serde_json::to_vec_pretty(&serde_json::json!({
                "schemaVersion": 1,
                "keyId": "test-key",
                "algorithm": "ed25519",
                "pluginId": "reader-plugin",
                "files": material.files,
                "signature": BASE64.encode(signature.to_bytes())
            }))
            .unwrap(),
        )
        .unwrap();
        plugin
    }

    fn zip_directory(source: &Path, package: &Path) {
        let file = File::create(package).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        for name in ["api.json", "plugin.json", "reader.dll", SIGNATURE_FILENAME] {
            zip.start_file(name, options).unwrap();
            zip.write_all(&fs::read(source.join(name)).unwrap())
                .unwrap();
        }
        zip.finish().unwrap();
    }

    #[test]
    fn activates_and_rolls_back_a_verified_package() {
        let root = tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let trust = trust_store(root.path(), &signing_key);
        let source = signed_plugin(root.path(), &signing_key);
        let package = root.path().join("reader.ssdev-plugin");
        zip_directory(&source, &package);
        let plugin_root = root.path().join("plugins");
        let previous = plugin_root.join("reader-plugin");
        fs::create_dir_all(&previous).unwrap();
        fs::write(previous.join("old.txt"), b"previous version").unwrap();

        let prepared = PreparedPlugin::prepare(&package, &plugin_root, &trust).unwrap();
        assert_eq!(prepared.identity().plugin_id, "reader-plugin");
        let activation = prepared.activate().unwrap();
        assert_eq!(
            fs::read(plugin_root.join("reader-plugin/reader.dll")).unwrap(),
            b"signed fixture"
        );
        activation.rollback().unwrap();

        assert_eq!(
            fs::read(plugin_root.join("reader-plugin/old.txt")).unwrap(),
            b"previous version"
        );
    }

    #[test]
    fn commit_keeps_the_new_verified_version() {
        let root = tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[10; 32]);
        let trust = trust_store(root.path(), &signing_key);
        let source = signed_plugin(root.path(), &signing_key);
        let package = root.path().join("reader.ssdev-plugin");
        zip_directory(&source, &package);
        let plugin_root = root.path().join("plugins");

        PreparedPlugin::prepare(&package, &plugin_root, &trust)
            .unwrap()
            .activate()
            .unwrap()
            .commit()
            .unwrap();

        assert!(plugin_root.join("reader-plugin/api.json").is_file());
    }

    #[test]
    fn release_packages_are_byte_for_byte_reproducible() {
        let root = tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[11; 32]);
        let trust = trust_store(root.path(), &signing_key);
        let source = signed_plugin(root.path(), &signing_key);
        let first = root.path().join("first.ssdev-plugin");
        let second = root.path().join("second.ssdev-plugin");

        create_deterministic_package(&source, &first, &trust).unwrap();
        create_deterministic_package(&source, &second, &trust).unwrap();

        assert_eq!(fs::read(first).unwrap(), fs::read(second).unwrap());
    }

    #[test]
    fn startup_recovery_rolls_back_an_interrupted_upgrade() {
        let root = tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[12; 32]);
        let trust = trust_store(root.path(), &signing_key);
        let source = signed_plugin(root.path(), &signing_key);
        let package = root.path().join("reader.ssdev-plugin");
        zip_directory(&source, &package);
        let plugin_root = root.path().join("plugins");
        let previous = plugin_root.join("reader-plugin");
        fs::create_dir_all(&previous).unwrap();
        fs::write(previous.join("old.txt"), b"previous version").unwrap();

        let activation = PreparedPlugin::prepare(&package, &plugin_root, &trust)
            .unwrap()
            .activate()
            .unwrap();
        std::mem::forget(activation);

        let report = recover_incomplete_activations(&plugin_root).unwrap();
        assert_eq!(report.rolled_back_activations, 1);
        assert_eq!(
            fs::read(plugin_root.join("reader-plugin/old.txt")).unwrap(),
            b"previous version"
        );
        assert!(!plugin_root.join("reader-plugin/reader.dll").exists());
        assert_no_transaction_debris(&plugin_root);
    }

    #[test]
    fn startup_recovery_removes_an_interrupted_new_install() {
        let root = tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[13; 32]);
        let trust = trust_store(root.path(), &signing_key);
        let source = signed_plugin(root.path(), &signing_key);
        let package = root.path().join("reader.ssdev-plugin");
        zip_directory(&source, &package);
        let plugin_root = root.path().join("plugins");

        let activation = PreparedPlugin::prepare(&package, &plugin_root, &trust)
            .unwrap()
            .activate()
            .unwrap();
        std::mem::forget(activation);

        let report = recover_incomplete_activations(&plugin_root).unwrap();
        assert_eq!(report.rolled_back_activations, 1);
        assert!(!plugin_root.join("reader-plugin").exists());
        assert_no_transaction_debris(&plugin_root);
    }

    #[test]
    fn plugin_removal_can_rollback_commit_and_recover_after_a_crash() {
        let root = tempdir().unwrap();
        let plugin_root = root.path().join("plugins");
        let target = plugin_root.join("reader-plugin");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("marker.txt"), b"installed plugin").unwrap();

        let removal = prepare_plugin_removal(&plugin_root, "reader-plugin").unwrap();
        assert!(!target.exists());
        removal.rollback().unwrap();
        assert_eq!(
            fs::read(target.join("marker.txt")).unwrap(),
            b"installed plugin"
        );

        let removal = prepare_plugin_removal(&plugin_root, "reader-plugin").unwrap();
        std::mem::forget(removal);
        let report = recover_incomplete_activations(&plugin_root).unwrap();
        assert_eq!(report.rolled_back_activations, 1);
        assert_eq!(
            fs::read(target.join("marker.txt")).unwrap(),
            b"installed plugin"
        );

        prepare_plugin_removal(&plugin_root, "reader-plugin")
            .unwrap()
            .commit()
            .unwrap();
        assert!(!target.exists());
        assert_no_transaction_debris(&plugin_root);
    }

    #[test]
    fn committed_set_recovery_keeps_the_new_plugin_and_discards_its_backup() {
        let root = tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[16; 32]);
        let trust = trust_store(root.path(), &signing_key);
        let source = signed_plugin(root.path(), &signing_key);
        let package = root.path().join("reader.ssdev-plugin");
        zip_directory(&source, &package);
        let plugin_root = root.path().join("plugins");
        let previous = plugin_root.join("reader-plugin");
        fs::create_dir_all(&previous).unwrap();
        fs::write(previous.join("old.txt"), b"previous version").unwrap();

        let activation = PreparedPlugin::prepare(&package, &plugin_root, &trust)
            .unwrap()
            .activate()
            .unwrap();
        std::mem::forget(activation);

        let report = recover_incomplete_activations_with_committed(
            &plugin_root,
            &HashSet::from(["reader-plugin".to_owned()]),
        )
        .unwrap();
        assert_eq!(report.finalized_activations, 1);
        assert!(plugin_root.join("reader-plugin/reader.dll").is_file());
        assert!(!plugin_root.join("reader-plugin/old.txt").exists());
        assert_no_transaction_debris(&plugin_root);
    }

    #[test]
    fn recovery_is_idempotent_after_the_previous_plugin_was_restored() {
        let root = tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[14; 32]);
        let trust = trust_store(root.path(), &signing_key);
        let source = signed_plugin(root.path(), &signing_key);
        let package = root.path().join("reader.ssdev-plugin");
        zip_directory(&source, &package);
        let plugin_root = root.path().join("plugins");
        let target = plugin_root.join("reader-plugin");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("old.txt"), b"previous version").unwrap();

        let activation = PreparedPlugin::prepare(&package, &plugin_root, &trust)
            .unwrap()
            .activate()
            .unwrap();
        std::mem::forget(activation);
        let transaction = activation_directories(&plugin_root).pop().unwrap();
        fs::remove_dir_all(&target).unwrap();
        fs::rename(transaction.join("previous"), &target).unwrap();

        let report = recover_incomplete_activations(&plugin_root).unwrap();
        assert_eq!(report.rolled_back_activations, 1);
        assert_eq!(
            fs::read(target.join("old.txt")).unwrap(),
            b"previous version"
        );
        assert_no_transaction_debris(&plugin_root);
        assert_eq!(
            recover_incomplete_activations(&plugin_root).unwrap(),
            RecoveryReport::default()
        );
    }

    #[test]
    fn recovery_cleans_committed_and_abandoned_staging_directories() {
        let root = tempdir().unwrap();
        let plugin_root = root.path().join("plugins");
        fs::create_dir_all(plugin_root.join(".committed-test")).unwrap();
        fs::create_dir_all(plugin_root.join(".staging-test")).unwrap();

        let report = recover_incomplete_activations(&plugin_root).unwrap();
        assert_eq!(report.removed_committed_transactions, 1);
        assert_eq!(report.removed_staging_directories, 1);
        assert!(!plugin_root.join(".committed-test").exists());
        assert!(!plugin_root.join(".staging-test").exists());
    }

    #[test]
    fn recovery_rejects_an_unsafe_plugin_id_without_touching_outside_data() {
        let root = tempdir().unwrap();
        let plugin_root = root.path().join("plugins");
        for plugin_id in ["reader.", "CON", "com1.device", "读卡器"] {
            assert!(validated_plugin_target(&plugin_root, plugin_id).is_err());
        }
        let transaction = plugin_root.join(".activation-test");
        fs::create_dir_all(&transaction).unwrap();
        write_activation_journal(
            &transaction,
            &ActivationJournal {
                schema_version: 1,
                plugin_id: "../outside".into(),
                had_previous: false,
            },
        )
        .unwrap();
        let outside = root.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep.txt"), b"keep").unwrap();

        let result = recover_incomplete_activations(&plugin_root);
        assert!(matches!(result, Err(PackageError::Invalid(_))));
        assert_eq!(fs::read(outside.join("keep.txt")).unwrap(), b"keep");
    }

    #[cfg(unix)]
    #[test]
    fn recovery_refuses_a_symbolic_link_plugin_target() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let plugin_root = root.path().join("plugins");
        let transaction = plugin_root.join(".activation-test");
        fs::create_dir_all(&transaction).unwrap();
        write_activation_journal(
            &transaction,
            &ActivationJournal {
                schema_version: 1,
                plugin_id: "reader-plugin".into(),
                had_previous: false,
            },
        )
        .unwrap();
        let outside = root.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep.txt"), b"keep").unwrap();
        symlink(&outside, plugin_root.join("reader-plugin")).unwrap();

        let result = recover_incomplete_activations(&plugin_root);
        assert!(matches!(result, Err(PackageError::Invalid(_))));
        assert_eq!(fs::read(outside.join("keep.txt")).unwrap(), b"keep");
    }

    fn activation_directories(plugin_root: &Path) -> Vec<PathBuf> {
        fs::read_dir(plugin_root)
            .unwrap()
            .map(Result::unwrap)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(ACTIVATION_PREFIX)
            })
            .map(|entry| entry.path())
            .collect()
    }

    fn assert_no_transaction_debris(plugin_root: &Path) {
        assert!(activation_directories(plugin_root).is_empty());
    }

    #[test]
    fn rejects_zip_slip_before_writing_outside_staging() {
        let root = tempdir().unwrap();
        let package = root.path().join("bad.zip");
        let file = File::create(&package).unwrap();
        let mut zip = ZipWriter::new(file);
        zip.start_file("../escape.dll", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"escape").unwrap();
        zip.finish().unwrap();
        let signing_key = SigningKey::from_bytes(&[11; 32]);
        let trust = trust_store(root.path(), &signing_key);

        let error = PreparedPlugin::prepare(&package, &root.path().join("plugins"), &trust)
            .err()
            .expect("unsafe archive must be rejected");
        assert!(matches!(error, PackageError::Invalid(_)));
        assert!(!root.path().join("escape.dll").exists());
    }
}
