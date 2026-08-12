use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Output},
};
use thiserror::Error;

pub const SCHEMA_VERSION: u32 = 1;
pub const HASH_ALGORITHM: &str = "SHA-256";
const MAX_FILES: usize = 20_000;
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_RELATIVE_PATH_BYTES: usize = 512;
const MAX_RELEASE_METADATA_BYTES: u64 = 1024 * 1024;
const MAX_TOOL_VERSION_BYTES: usize = 1024;
const SOURCE_INPUTS: [&str; 5] = [
    "Cargo.lock",
    "rust-toolchain.toml",
    "apps/desktop/package-lock.json",
    "apps/desktop/src-tauri/tauri.conf.json",
    "packages/web-bridge/package-lock.json",
];
const BUILD_TOOLS: [&str; 5] = ["cargo", "cargoCyclonedx", "node", "npm", "rustc"];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub hash_algorithm: String,
    pub files: Vec<ReleaseFile>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseFile {
    pub relative_path: String,
    pub length: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseMetadata {
    pub schema_version: u32,
    pub app_version: String,
    pub product_name: String,
    pub identifier: String,
    pub authenticode_required: bool,
    pub synthetic_version_override: bool,
    pub source_revision: String,
    pub source_dirty: bool,
    pub source_inputs: BTreeMap<String, String>,
    pub build_tools: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct ReleaseMetadataOptions<'a> {
    pub workspace_root: &'a Path,
    pub output: &'a Path,
    pub app_version: &'a str,
    pub product_name: &'a str,
    pub identifier: &'a str,
    pub authenticode_required: bool,
    pub synthetic_version_override: bool,
    pub allow_dirty_source: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceIdentity {
    pub revision: String,
    pub dirty: bool,
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("release bundle root is not a regular directory")]
    InvalidRoot,
    #[error("release manifest path is invalid")]
    InvalidManifestPath,
    #[error("release bundle contains an unsupported symbolic link")]
    SymbolicLink,
    #[error("release bundle contains a non-UTF-8 or invalid relative path")]
    InvalidRelativePath,
    #[error("release bundle contains too many files")]
    TooManyFiles,
    #[error("release bundle contains an oversized file")]
    OversizedFile,
    #[error("release manifest already exists")]
    ManifestExists,
    #[error("release manifest is oversized")]
    OversizedManifest,
    #[error("release manifest is malformed or unsupported")]
    MalformedManifest,
    #[error("release manifest entries are duplicated or not in canonical order")]
    NonCanonicalEntries,
    #[error("release manifest does not exactly match the bundle inventory")]
    InventoryMismatch,
    #[error("release file length or digest does not match the manifest")]
    DigestMismatch,
    #[error("release provenance metadata is invalid: {0}")]
    InvalidReleaseMetadata(String),
    #[error("signed production releases require a clean source workspace")]
    DirtyProductionSource,
    #[error("release provenance command [{0}] failed")]
    ProvenanceCommand(&'static str),
    #[error("release manifest I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("release manifest JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn create_manifest(
    root: impl AsRef<Path>,
    manifest_relative_path: &str,
) -> Result<ReleaseManifest, ManifestError> {
    let root = validate_root(root.as_ref())?;
    let manifest_relative_path = validate_manifest_path(manifest_relative_path)?;
    let signature_relative_path = format!("{manifest_relative_path}.sig");
    let exclusions = HashSet::from([manifest_relative_path.clone(), signature_relative_path]);
    let files = collect_inventory(&root, &exclusions)?;
    let manifest = ReleaseManifest {
        schema_version: SCHEMA_VERSION,
        hash_algorithm: HASH_ALGORITHM.to_owned(),
        files,
    };
    write_manifest_atomic(
        &root.join(path_from_manifest(&manifest_relative_path)),
        &manifest,
    )?;
    Ok(manifest)
}

pub fn verify_manifest(
    root: impl AsRef<Path>,
    manifest_relative_path: &str,
) -> Result<ReleaseManifest, ManifestError> {
    let root = validate_root(root.as_ref())?;
    let manifest_relative_path = validate_manifest_path(manifest_relative_path)?;
    let signature_relative_path = format!("{manifest_relative_path}.sig");
    let manifest_path = root.join(path_from_manifest(&manifest_relative_path));
    let metadata = fs::symlink_metadata(&manifest_path)?;
    if metadata.file_type().is_symlink() {
        return Err(ManifestError::SymbolicLink);
    }
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::OversizedManifest);
    }
    let manifest: ReleaseManifest =
        serde_json::from_reader(BufReader::new(File::open(&manifest_path)?))?;
    validate_manifest(&manifest)?;

    let exclusions = HashSet::from([manifest_relative_path, signature_relative_path]);
    let actual = collect_inventory(&root, &exclusions)?;
    if actual != manifest.files {
        let actual_paths: Vec<_> = actual
            .iter()
            .map(|entry| entry.relative_path.as_str())
            .collect();
        let expected_paths: Vec<_> = manifest
            .files
            .iter()
            .map(|entry| entry.relative_path.as_str())
            .collect();
        if actual_paths != expected_paths {
            return Err(ManifestError::InventoryMismatch);
        }
        return Err(ManifestError::DigestMismatch);
    }
    Ok(manifest)
}

pub fn create_release_metadata(
    options: &ReleaseMetadataOptions<'_>,
) -> Result<ReleaseMetadata, ManifestError> {
    let workspace = validate_root(options.workspace_root)?;
    let environment = capture_release_environment(&workspace)?;
    let metadata = ReleaseMetadata {
        schema_version: 2,
        app_version: options.app_version.to_owned(),
        product_name: options.product_name.to_owned(),
        identifier: options.identifier.to_owned(),
        authenticode_required: options.authenticode_required,
        synthetic_version_override: options.synthetic_version_override,
        source_revision: environment.source_revision,
        source_dirty: environment.source_dirty,
        source_inputs: environment.source_inputs,
        build_tools: environment.build_tools,
    };
    validate_release_metadata(&metadata)?;
    if metadata.source_dirty && !options.allow_dirty_source {
        return Err(ManifestError::DirtyProductionSource);
    }
    write_release_metadata_atomic(options.output, &metadata)?;
    Ok(metadata)
}

pub fn verify_release_metadata(
    path: &Path,
    current_workspace: Option<&Path>,
) -> Result<ReleaseMetadata, ManifestError> {
    let file_metadata = fs::symlink_metadata(path)?;
    if file_metadata.file_type().is_symlink()
        || !file_metadata.is_file()
        || file_metadata.len() > MAX_RELEASE_METADATA_BYTES
    {
        return Err(ManifestError::InvalidReleaseMetadata(
            "metadata must be a bounded regular file".into(),
        ));
    }
    let metadata: ReleaseMetadata = serde_json::from_reader(BufReader::new(File::open(path)?))?;
    validate_release_metadata(&metadata)?;
    if let Some(workspace) = current_workspace {
        let workspace = validate_root(workspace)?;
        let current = capture_release_environment(&workspace)?;
        if metadata.source_revision != current.source_revision
            || metadata.source_dirty != current.source_dirty
            || metadata.source_inputs != current.source_inputs
            || metadata.build_tools != current.build_tools
        {
            return Err(ManifestError::InvalidReleaseMetadata(
                "metadata does not match the current source and build environment".into(),
            ));
        }
    }
    Ok(metadata)
}

struct ReleaseEnvironment {
    source_revision: String,
    source_dirty: bool,
    source_inputs: BTreeMap<String, String>,
    build_tools: BTreeMap<String, String>,
}

fn capture_release_environment(workspace: &Path) -> Result<ReleaseEnvironment, ManifestError> {
    let identity = capture_source_identity_from_validated(workspace)?;

    let mut source_inputs = BTreeMap::new();
    for relative in SOURCE_INPUTS {
        let path = workspace.join(path_from_manifest(relative));
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ManifestError::InvalidReleaseMetadata(format!(
                "source input [{relative}] must be a regular file"
            )));
        }
        let (_, digest) = digest_file(&path)?;
        source_inputs.insert(relative.to_owned(), digest);
    }

    let npm_program = if cfg!(windows) { "npm.cmd" } else { "npm" };
    let commands: [(&str, &str, &[&str]); 5] = [
        ("cargo", "cargo", &["--version"]),
        ("cargoCyclonedx", "cargo", &["cyclonedx", "--version"]),
        ("node", "node", &["--version"]),
        ("npm", npm_program, &["--version"]),
        ("rustc", "rustc", &["--version"]),
    ];
    let mut build_tools = BTreeMap::new();
    for (name, program, arguments) in commands {
        let mut command = Command::new(program);
        command.args(arguments);
        build_tools.insert(name.to_owned(), single_line_output(command.output(), name)?);
    }

    Ok(ReleaseEnvironment {
        source_revision: identity.revision,
        source_dirty: identity.dirty,
        source_inputs,
        build_tools,
    })
}

pub fn capture_source_identity(workspace: &Path) -> Result<SourceIdentity, ManifestError> {
    let workspace = validate_root(workspace)?;
    capture_source_identity_from_validated(&workspace)
}

fn capture_source_identity_from_validated(
    workspace: &Path,
) -> Result<SourceIdentity, ManifestError> {
    let mut revision = Command::new("git");
    revision
        .arg("-C")
        .arg(workspace)
        .args(["rev-parse", "--verify", "HEAD"]);
    let source_revision = single_line_output(revision.output(), "git-revision")?;

    let mut status = Command::new("git");
    status.arg("-C").arg(workspace).args([
        "status",
        "--porcelain=v1",
        "--untracked-files=normal",
        "--",
        ".",
    ]);
    let status = successful_output(status.output(), "git-status")?;
    if status.stdout.len() > MAX_RELEASE_METADATA_BYTES as usize {
        return Err(ManifestError::InvalidReleaseMetadata(
            "source status output exceeds the safety limit".into(),
        ));
    }

    Ok(SourceIdentity {
        revision: source_revision,
        dirty: !status.stdout.is_empty(),
    })
}

fn successful_output(
    output: io::Result<Output>,
    label: &'static str,
) -> Result<Output, ManifestError> {
    let output = output.map_err(|_| ManifestError::ProvenanceCommand(label))?;
    if !output.status.success() {
        return Err(ManifestError::ProvenanceCommand(label));
    }
    Ok(output)
}

fn single_line_output(
    output: io::Result<Output>,
    label: &'static str,
) -> Result<String, ManifestError> {
    let output = successful_output(output, label)?;
    if output.stdout.len() > MAX_TOOL_VERSION_BYTES {
        return Err(ManifestError::InvalidReleaseMetadata(format!(
            "{label} output exceeds the safety limit"
        )));
    }
    let value = std::str::from_utf8(&output.stdout)
        .map_err(|_| ManifestError::InvalidReleaseMetadata(format!("{label} output is not UTF-8")))?
        .trim();
    if value.is_empty() || value.lines().count() != 1 || value.chars().any(char::is_control) {
        return Err(ManifestError::InvalidReleaseMetadata(format!(
            "{label} output is not one safe line"
        )));
    }
    Ok(value.to_owned())
}

fn validate_release_metadata(metadata: &ReleaseMetadata) -> Result<(), ManifestError> {
    if metadata.schema_version != 2 {
        return Err(ManifestError::InvalidReleaseMetadata(
            "unsupported schema version".into(),
        ));
    }
    let version = Version::parse(&metadata.app_version).map_err(|_| {
        ManifestError::InvalidReleaseMetadata("appVersion must be semantic versioning".into())
    })?;
    if !version.pre.is_empty() || !version.build.is_empty() {
        return Err(ManifestError::InvalidReleaseMetadata(
            "appVersion must not contain prerelease or build metadata".into(),
        ));
    }
    validate_release_text(&metadata.product_name, 128, "productName")?;
    if metadata.identifier.is_empty()
        || metadata.identifier.len() > 256
        || !metadata
            .identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(ManifestError::InvalidReleaseMetadata(
            "identifier is not portable".into(),
        ));
    }
    if !matches!(metadata.source_revision.len(), 40 | 64)
        || !metadata
            .source_revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ManifestError::InvalidReleaseMetadata(
            "sourceRevision must be a lowercase Git object ID".into(),
        ));
    }
    let expected_inputs = SOURCE_INPUTS
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if metadata
        .source_inputs
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != expected_inputs
        || metadata
            .source_inputs
            .values()
            .any(|digest| !is_sha256(digest))
    {
        return Err(ManifestError::InvalidReleaseMetadata(
            "sourceInputs must contain the exact required SHA-256 set".into(),
        ));
    }
    let expected_tools = BUILD_TOOLS
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if metadata
        .build_tools
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != expected_tools
    {
        return Err(ManifestError::InvalidReleaseMetadata(
            "buildTools must contain the exact required tool set".into(),
        ));
    }
    for value in metadata.build_tools.values() {
        validate_release_text(value, MAX_TOOL_VERSION_BYTES, "buildTools value")?;
        if value.lines().count() != 1 {
            return Err(ManifestError::InvalidReleaseMetadata(
                "buildTools values must each use one line".into(),
            ));
        }
    }
    if metadata.authenticode_required && metadata.source_dirty {
        return Err(ManifestError::DirtyProductionSource);
    }
    if metadata.authenticode_required && metadata.synthetic_version_override {
        return Err(ManifestError::InvalidReleaseMetadata(
            "signed production releases cannot use a synthetic version override".into(),
        ));
    }
    Ok(())
}

fn validate_release_text(value: &str, max_bytes: usize, label: &str) -> Result<(), ManifestError> {
    if value.trim() != value
        || value.is_empty()
        || value.len() > max_bytes
        || value.chars().any(char::is_control)
    {
        return Err(ManifestError::InvalidReleaseMetadata(format!(
            "{label} is empty, oversized, or contains control characters"
        )));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn validate_root(root: &Path) -> Result<PathBuf, ManifestError> {
    let metadata = fs::symlink_metadata(root).map_err(|_| ManifestError::InvalidRoot)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ManifestError::InvalidRoot);
    }
    fs::canonicalize(root).map_err(ManifestError::Io)
}

fn validate_manifest_path(path: &str) -> Result<String, ManifestError> {
    if path.is_empty()
        || path.len() > MAX_RELATIVE_PATH_BYTES
        || path.contains('\\')
        || path.contains(':')
        || Path::new(path).is_absolute()
    {
        return Err(ManifestError::InvalidManifestPath);
    }
    let components: Vec<_> = Path::new(path).components().collect();
    if components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ManifestError::InvalidManifestPath);
    }
    Ok(components
        .iter()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/"))
}

fn validate_manifest(manifest: &ReleaseManifest) -> Result<(), ManifestError> {
    if manifest.schema_version != SCHEMA_VERSION
        || manifest.hash_algorithm != HASH_ALGORITHM
        || manifest.files.len() > MAX_FILES
    {
        return Err(ManifestError::MalformedManifest);
    }
    let mut previous: Option<&str> = None;
    for entry in &manifest.files {
        if normalize_relative(Path::new(&entry.relative_path))
            .ok()
            .as_deref()
            != Some(entry.relative_path.as_str())
            || entry.length > MAX_FILE_BYTES
            || entry.sha256.len() != 64
            || !entry
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || previous.is_some_and(|previous| previous >= entry.relative_path.as_str())
        {
            return Err(ManifestError::NonCanonicalEntries);
        }
        previous = Some(&entry.relative_path);
    }
    Ok(())
}

fn collect_inventory(
    root: &Path,
    exclusions: &HashSet<String>,
) -> Result<Vec<ReleaseFile>, ManifestError> {
    let mut paths = Vec::new();
    collect_paths(root, root, exclusions, &mut paths)?;
    paths.sort_by(|left, right| left.0.cmp(&right.0));
    if paths.len() > MAX_FILES {
        return Err(ManifestError::TooManyFiles);
    }
    paths
        .into_iter()
        .map(|(relative_path, absolute_path)| {
            let (length, sha256) = digest_file(&absolute_path)?;
            Ok(ReleaseFile {
                relative_path,
                length,
                sha256,
            })
        })
        .collect()
}

fn collect_paths(
    root: &Path,
    directory: &Path,
    exclusions: &HashSet<String>,
    paths: &mut Vec<(String, PathBuf)>,
) -> Result<(), ManifestError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(ManifestError::SymbolicLink);
        }
        if metadata.is_dir() {
            collect_paths(root, &path, exclusions, paths)?;
        } else if metadata.is_file() {
            if metadata.len() > MAX_FILE_BYTES {
                return Err(ManifestError::OversizedFile);
            }
            let relative = normalize_relative(
                path.strip_prefix(root)
                    .map_err(|_| ManifestError::InvalidRelativePath)?,
            )?;
            if !exclusions.contains(&relative) {
                paths.push((relative, path));
                if paths.len() > MAX_FILES {
                    return Err(ManifestError::TooManyFiles);
                }
            }
        }
    }
    Ok(())
}

fn normalize_relative(path: &Path) -> Result<String, ManifestError> {
    if path.is_absolute() {
        return Err(ManifestError::InvalidRelativePath);
    }
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(value) = component else {
            return Err(ManifestError::InvalidRelativePath);
        };
        let value = value.to_str().ok_or(ManifestError::InvalidRelativePath)?;
        if value.is_empty()
            || value.len() > MAX_RELATIVE_PATH_BYTES
            || value.contains('/')
            || value.contains('\\')
        {
            return Err(ManifestError::InvalidRelativePath);
        }
        parts.push(value);
    }
    let normalized = parts.join("/");
    if normalized.is_empty() || normalized.len() > MAX_RELATIVE_PATH_BYTES {
        return Err(ManifestError::InvalidRelativePath);
    }
    Ok(normalized)
}

fn path_from_manifest(path: &str) -> PathBuf {
    path.split('/').collect()
}

fn digest_file(path: &Path) -> Result<(u64, String), ManifestError> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
        return Err(ManifestError::OversizedFile);
    }
    let mut reader = BufReader::new(file);
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut length = 0_u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        length = length
            .checked_add(read as u64)
            .ok_or(ManifestError::OversizedFile)?;
        if length > MAX_FILE_BYTES {
            return Err(ManifestError::OversizedFile);
        }
        digest.update(&buffer[..read]);
    }
    let sha256 = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok((length, sha256))
}

fn write_manifest_atomic(path: &Path, manifest: &ReleaseManifest) -> Result<(), ManifestError> {
    if path.exists() {
        return Err(ManifestError::ManifestExists);
    }
    let parent = path.parent().ok_or(ManifestError::InvalidManifestPath)?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("json.pending");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = (|| {
        let mut writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, manifest)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn write_release_metadata_atomic(
    path: &Path,
    metadata: &ReleaseMetadata,
) -> Result<(), ManifestError> {
    match fs::symlink_metadata(path) {
        Ok(_) => return Err(ManifestError::ManifestExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(ManifestError::Io(error)),
    }
    let parent = path
        .parent()
        .ok_or_else(|| ManifestError::InvalidReleaseMetadata("output path has no parent".into()))?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(ManifestError::InvalidReleaseMetadata(
            "output parent must be a real existing directory".into(),
        ));
    }
    let temporary = path.with_extension("json.pending");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = (|| {
        let mut writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, metadata)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "ssdev-release-manifest-{}-{nonce}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn seed(root: &Path) {
        fs::create_dir_all(root.join("nsis")).unwrap();
        fs::create_dir_all(root.join("metadata")).unwrap();
        fs::write(root.join("nsis/setup.exe"), b"installer").unwrap();
        fs::write(root.join("metadata/release.json"), b"{}").unwrap();
    }

    fn provenance(
        authenticode_required: bool,
        source_dirty: bool,
        synthetic_version_override: bool,
    ) -> ReleaseMetadata {
        ReleaseMetadata {
            schema_version: 2,
            app_version: "1.2.3".into(),
            product_name: "SSDEV Desktop".into(),
            identifier: "com.bsoft.ssdev.desktop".into(),
            authenticode_required,
            synthetic_version_override,
            source_revision: "11".repeat(20),
            source_dirty,
            source_inputs: SOURCE_INPUTS
                .into_iter()
                .map(|path| (path.to_owned(), "22".repeat(32)))
                .collect(),
            build_tools: BUILD_TOOLS
                .into_iter()
                .map(|tool| (tool.to_owned(), format!("{tool} 1.2.3")))
                .collect(),
        }
    }

    #[test]
    fn creates_and_verifies_an_exact_canonical_inventory() {
        let root = TestRoot::new();
        seed(&root.0);
        let created = create_manifest(&root.0, "metadata/artifacts.json").unwrap();
        fs::write(root.0.join("metadata/artifacts.json.sig"), b"signature").unwrap();
        let verified = verify_manifest(&root.0, "metadata/artifacts.json").unwrap();

        assert_eq!(created, verified);
        assert_eq!(created.files.len(), 2);
        assert!(created
            .files
            .windows(2)
            .all(|window| window[0].relative_path < window[1].relative_path));
    }

    #[test]
    fn rejects_tampering_and_unlisted_files() {
        let root = TestRoot::new();
        seed(&root.0);
        create_manifest(&root.0, "metadata/artifacts.json").unwrap();
        fs::write(root.0.join("nsis/setup.exe"), b"tampered").unwrap();
        assert!(matches!(
            verify_manifest(&root.0, "metadata/artifacts.json"),
            Err(ManifestError::DigestMismatch)
        ));

        fs::write(root.0.join("nsis/setup.exe"), b"installer").unwrap();
        fs::write(root.0.join("hidden.bin"), b"hidden").unwrap();
        assert!(matches!(
            verify_manifest(&root.0, "metadata/artifacts.json"),
            Err(ManifestError::InventoryMismatch)
        ));
    }

    #[test]
    fn rejects_noncanonical_or_traversing_manifest_entries() {
        let root = TestRoot::new();
        seed(&root.0);
        let mut manifest = create_manifest(&root.0, "metadata/artifacts.json").unwrap();
        manifest.files[0].relative_path = "../outside".into();
        serde_json::to_writer_pretty(
            File::create(root.0.join("metadata/artifacts.json")).unwrap(),
            &manifest,
        )
        .unwrap();

        assert!(matches!(
            verify_manifest(&root.0, "metadata/artifacts.json"),
            Err(ManifestError::NonCanonicalEntries)
        ));
        assert!(matches!(
            create_manifest(&root.0, "../artifacts.json"),
            Err(ManifestError::InvalidManifestPath)
        ));
    }

    #[test]
    fn release_provenance_requires_exact_inputs_and_safe_values() {
        let root = TestRoot::new();
        let path = root.0.join("release.json");
        fs::write(
            &path,
            serde_json::to_vec_pretty(&provenance(true, false, false)).unwrap(),
        )
        .unwrap();
        let verified = verify_release_metadata(&path, None).unwrap();
        assert_eq!(verified.schema_version, 2);
        assert_eq!(verified.source_inputs.len(), SOURCE_INPUTS.len());

        let mut missing_input = provenance(false, false, false);
        missing_input.source_inputs.remove("Cargo.lock");
        fs::write(&path, serde_json::to_vec(&missing_input).unwrap()).unwrap();
        assert!(verify_release_metadata(&path, None).is_err());
    }

    #[test]
    fn signed_production_provenance_rejects_dirty_or_synthetic_sources() {
        assert!(matches!(
            validate_release_metadata(&provenance(true, true, false)),
            Err(ManifestError::DirtyProductionSource)
        ));
        assert!(validate_release_metadata(&provenance(true, false, true)).is_err());
        validate_release_metadata(&provenance(false, true, true)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symbolic_links_without_following_them() {
        use std::os::unix::fs::symlink;

        let root = TestRoot::new();
        seed(&root.0);
        symlink(root.0.join("nsis/setup.exe"), root.0.join("linked.exe")).unwrap();
        assert!(matches!(
            create_manifest(&root.0, "metadata/artifacts.json"),
            Err(ManifestError::SymbolicLink)
        ));
    }
}
