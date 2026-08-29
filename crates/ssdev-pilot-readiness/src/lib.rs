use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

pub const MANIFEST_SCHEMA_VERSION: u8 = 1;
pub const REPORT_SCHEMA_VERSION: u8 = 1;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_INPUTS_PER_CATEGORY: usize = 256;
const MAX_FILES_PER_CATEGORY: u64 = 100_000;
const MAX_ENTRIES_PER_CATEGORY: u64 = 200_000;
const MAX_BYTES_PER_CATEGORY: u64 = 64 * 1024 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 512;
const MAX_LOGICAL_PATH_BYTES: usize = 4096;
const MAX_DIRECTORY_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Applicability {
    Required,
    Conditional,
}

#[derive(Clone, Copy, Debug)]
struct CategoryRule {
    id: &'static str,
    applicability: Applicability,
}

const CATEGORY_RULES: &[CategoryRule] = &[
    CategoryRule {
        id: "legacy-config",
        applicability: Applicability::Required,
    },
    CategoryRule {
        id: "production-native-assets",
        applicability: Applicability::Required,
    },
    CategoryRule {
        id: "golden-cases",
        applicability: Applicability::Required,
    },
    CategoryRule {
        id: "business-assets",
        applicability: Applicability::Required,
    },
    CategoryRule {
        id: "business-hars",
        applicability: Applicability::Required,
    },
    CategoryRule {
        id: "signed-origin-policy",
        applicability: Applicability::Required,
    },
    CategoryRule {
        id: "plugin-release-set",
        applicability: Applicability::Required,
    },
    CategoryRule {
        id: "organization-public-trust",
        applicability: Applicability::Required,
    },
    CategoryRule {
        id: "previous-windows-release",
        applicability: Applicability::Required,
    },
    CategoryRule {
        id: "windows-hardware-plan",
        applicability: Applicability::Required,
    },
    CategoryRule {
        id: "legacy-keymap",
        applicability: Applicability::Conditional,
    },
    CategoryRule {
        id: "legacy-processes",
        applicability: Applicability::Conditional,
    },
    CategoryRule {
        id: "external-local-http-callers",
        applicability: Applicability::Conditional,
    },
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MaterialStatus {
    Provided,
    NotApplicable,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MaterialCategory {
    pub id: String,
    pub status: MaterialStatus,
    #[serde(default)]
    pub inputs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_reference: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PilotMaterialManifest {
    pub schema_version: u8,
    pub project_label: String,
    pub categories: Vec<MaterialCategory>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ReportMaterialStatus {
    Provided,
    NotApplicable,
    Missing,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MaterialCategoryReport {
    pub id: String,
    pub status: ReportMaterialStatus,
    pub input_count: u32,
    pub file_count: u64,
    pub total_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_reference_sha256: Option<String>,
    pub blocker_codes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PilotReadinessReport {
    pub schema_version: u8,
    pub report_type: String,
    pub manifest_sha256: String,
    pub project_label_sha256: String,
    pub material_set_sha256: String,
    pub intake_complete: bool,
    pub downstream_validation_required: bool,
    pub categories: Vec<MaterialCategoryReport>,
    pub blocker_codes: Vec<String>,
}

#[derive(Debug, Error)]
pub enum PilotReadinessError {
    #[error("pilot readiness input is invalid: {0}")]
    Invalid(String),
    #[error("pilot readiness I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("pilot readiness JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("pilot readiness report already exists")]
    OutputExists,
}

#[derive(Default)]
struct ScanState {
    entries: BTreeMap<String, Vec<u8>>,
    entry_count: u64,
    file_count: u64,
    total_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ScanFailure {
    Changed,
    InvalidPath,
    LimitExceeded,
    NonUtf8Name,
    PrivateMaterial,
    Symlink,
    Unavailable,
    UnsupportedType,
}

impl ScanFailure {
    fn suffix(self) -> &'static str {
        match self {
            Self::Changed => "input-changed",
            Self::InvalidPath => "input-path-invalid",
            Self::LimitExceeded => "input-limit-exceeded",
            Self::NonUtf8Name => "input-name-invalid",
            Self::PrivateMaterial => "private-material-forbidden",
            Self::Symlink => "input-symlink",
            Self::Unavailable => "input-unavailable",
            Self::UnsupportedType => "input-type-unsupported",
        }
    }
}

pub fn load_manifest(path: &Path) -> Result<(PilotMaterialManifest, Vec<u8>), PilotReadinessError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_MANIFEST_BYTES
    {
        return Err(PilotReadinessError::Invalid(
            "manifest must be a bounded regular file".into(),
        ));
    }
    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(MAX_MANIFEST_BYTES as usize));
    File::open(path)?
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = fs::symlink_metadata(path)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES
        || after.file_type().is_symlink()
        || !after.is_file()
        || after.len() != metadata.len()
        || after.len() != bytes.len() as u64
        || after.modified().ok() != metadata.modified().ok()
    {
        return Err(PilotReadinessError::Invalid(
            "manifest changed or exceeded its limit while being read".into(),
        ));
    }
    let manifest = serde_json::from_slice(&bytes)?;
    Ok((manifest, bytes))
}

pub fn inspect_materials(
    materials_root: &Path,
    manifest: &PilotMaterialManifest,
    manifest_bytes: &[u8],
) -> Result<PilotReadinessReport, PilotReadinessError> {
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(PilotReadinessError::Invalid(
            "unsupported pilot material manifest schema".into(),
        ));
    }
    validate_label(&manifest.project_label, "project label")?;
    if manifest.categories.len() > CATEGORY_RULES.len() + 32 {
        return Err(PilotReadinessError::Invalid(
            "manifest contains too many material categories".into(),
        ));
    }
    let root_metadata = fs::symlink_metadata(materials_root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(PilotReadinessError::Invalid(
            "materials root must be a real directory".into(),
        ));
    }
    let materials_root = fs::canonicalize(materials_root)?;

    let rules = CATEGORY_RULES
        .iter()
        .map(|rule| (rule.id, rule.applicability))
        .collect::<BTreeMap<_, _>>();
    let mut supplied = BTreeMap::<&str, &MaterialCategory>::new();
    let mut global_blockers = BTreeSet::new();
    for category in &manifest.categories {
        if !rules.contains_key(category.id.as_str()) {
            global_blockers.insert("unknown-material-category".to_string());
            continue;
        }
        if supplied.insert(category.id.as_str(), category).is_some() {
            global_blockers.insert("duplicate-material-category".to_string());
        }
    }

    let mut reports = Vec::with_capacity(CATEGORY_RULES.len());
    let mut material_payloads = BTreeMap::new();
    for rule in CATEGORY_RULES {
        let report = match supplied.get(rule.id) {
            None => missing_report(rule.id),
            Some(category) => inspect_category(&materials_root, rule, category),
        };
        global_blockers.extend(report.blocker_codes.iter().cloned());
        material_payloads.insert(rule.id.to_string(), category_identity_payload(&report));
        reports.push(report);
    }
    let material_set_sha256 = digest_named_payloads("pilot-material-set", &material_payloads)?;
    let blocker_codes = global_blockers.into_iter().collect::<Vec<_>>();
    Ok(PilotReadinessReport {
        schema_version: REPORT_SCHEMA_VERSION,
        report_type: "pilot-material-readiness".into(),
        manifest_sha256: sha256_bytes(manifest_bytes),
        project_label_sha256: sha256_bytes(manifest.project_label.as_bytes()),
        material_set_sha256,
        intake_complete: blocker_codes.is_empty(),
        downstream_validation_required: true,
        categories: reports,
        blocker_codes,
    })
}

pub fn prepare_new_output(path: &Path) -> Result<PathBuf, PilotReadinessError> {
    match fs::symlink_metadata(path) {
        Ok(_) => return Err(PilotReadinessError::OutputExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PilotReadinessError::Invalid(
            "report output parent must be a real existing directory".into(),
        ));
    }
    let parent = fs::canonicalize(parent)?;
    let file_name = path.file_name().ok_or_else(|| {
        PilotReadinessError::Invalid("report output must include a file name".into())
    })?;
    Ok(parent.join(file_name))
}

pub fn write_report(path: &Path, report: &PilotReadinessReport) -> Result<(), PilotReadinessError> {
    let mut file = File::options().write(true).create_new(true).open(path)?;
    serde_json::to_writer_pretty(&mut file, report)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn missing_report(id: &str) -> MaterialCategoryReport {
    MaterialCategoryReport {
        id: id.into(),
        status: ReportMaterialStatus::Missing,
        input_count: 0,
        file_count: 0,
        total_bytes: 0,
        content_sha256: None,
        approval_reference_sha256: None,
        blocker_codes: vec![format!("{id}-missing")],
    }
}

fn inspect_category(
    materials_root: &Path,
    rule: &CategoryRule,
    category: &MaterialCategory,
) -> MaterialCategoryReport {
    match category.status {
        MaterialStatus::NotApplicable => inspect_not_applicable(rule, category),
        MaterialStatus::Provided => inspect_provided(materials_root, rule.id, category),
    }
}

fn inspect_not_applicable(
    rule: &CategoryRule,
    category: &MaterialCategory,
) -> MaterialCategoryReport {
    let mut blockers = BTreeSet::new();
    if !category.inputs.is_empty() {
        blockers.insert(format!("{}-not-applicable-has-inputs", rule.id));
    }
    let approval_reference_sha256 = category
        .approval_reference
        .as_deref()
        .filter(|value| validate_approval_reference(value))
        .map(|value| sha256_bytes(value.as_bytes()));
    if rule.applicability == Applicability::Required {
        blockers.insert(format!("{}-required", rule.id));
    } else if approval_reference_sha256.is_none() {
        blockers.insert(format!("{}-approval-missing", rule.id));
    }
    MaterialCategoryReport {
        id: rule.id.into(),
        status: ReportMaterialStatus::NotApplicable,
        input_count: u32::try_from(category.inputs.len()).unwrap_or(u32::MAX),
        file_count: 0,
        total_bytes: 0,
        content_sha256: None,
        approval_reference_sha256,
        blocker_codes: blockers.into_iter().collect(),
    }
}

fn inspect_provided(
    materials_root: &Path,
    id: &str,
    category: &MaterialCategory,
) -> MaterialCategoryReport {
    let mut blockers = BTreeSet::new();
    if category.approval_reference.is_some() {
        blockers.insert(format!("{id}-provided-has-approval"));
    }
    if category.inputs.is_empty() {
        blockers.insert(format!("{id}-inputs-empty"));
    } else if category.inputs.len() < minimum_inputs(id) {
        blockers.insert(format!("{id}-input-count-below-minimum"));
    }
    if category.inputs.len() > MAX_INPUTS_PER_CATEGORY {
        blockers.insert(format!("{id}-input-limit-exceeded"));
    }
    let mut normalized_inputs = BTreeSet::new();
    for input in &category.inputs {
        match normalize_relative_path(input) {
            Ok(normalized) => {
                if !normalized_inputs.insert(normalized) {
                    blockers.insert(format!("{id}-input-duplicate"));
                }
            }
            Err(failure) => {
                blockers.insert(format!("{id}-{}", failure.suffix()));
            }
        }
    }

    let mut state = ScanState::default();
    if blockers.is_empty() {
        for (index, input) in normalized_inputs.iter().enumerate() {
            state.entries.insert(
                format!("input-{index}/declared-path"),
                input.as_bytes().to_vec(),
            );
            match resolve_without_symlink(materials_root, input).and_then(|path| {
                scan_path(
                    &path,
                    &format!("input-{index}"),
                    0,
                    id == "organization-public-trust",
                    &mut state,
                )
            }) {
                Ok(()) => {}
                Err(failure) => {
                    blockers.insert(format!("{id}-{}", failure.suffix()));
                }
            }
        }
    }
    if blockers.is_empty() && state.file_count == 0 {
        blockers.insert(format!("{id}-content-empty"));
    }
    let content_sha256 = if blockers.is_empty() {
        match digest_named_payloads(id, &state.entries) {
            Ok(digest) => Some(digest),
            Err(_) => {
                blockers.insert(format!("{id}-identity-failed"));
                None
            }
        }
    } else {
        None
    };
    MaterialCategoryReport {
        id: id.into(),
        status: ReportMaterialStatus::Provided,
        input_count: u32::try_from(category.inputs.len()).unwrap_or(u32::MAX),
        file_count: state.file_count,
        total_bytes: state.total_bytes,
        content_sha256,
        approval_reference_sha256: None,
        blocker_codes: blockers.into_iter().collect(),
    }
}

fn normalize_relative_path(raw: &str) -> Result<String, ScanFailure> {
    if raw.is_empty()
        || raw.len() > MAX_PATH_BYTES
        || raw.contains('\\')
        || raw.chars().any(char::is_control)
    {
        return Err(ScanFailure::InvalidPath);
    }
    let path = Path::new(raw);
    if path.is_absolute() {
        return Err(ScanFailure::InvalidPath);
    }
    let mut segments = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(segment) => {
                let segment = segment.to_str().ok_or(ScanFailure::NonUtf8Name)?;
                if !is_portable_segment(segment) {
                    return Err(ScanFailure::InvalidPath);
                }
                segments.push(segment);
            }
            _ => return Err(ScanFailure::InvalidPath),
        }
    }
    if segments.is_empty() {
        return Err(ScanFailure::InvalidPath);
    }
    Ok(segments.join("/"))
}

fn resolve_without_symlink(root: &Path, normalized: &str) -> Result<PathBuf, ScanFailure> {
    let mut current = root.to_path_buf();
    for segment in normalized.split('/') {
        current.push(segment);
        let metadata = fs::symlink_metadata(&current).map_err(|_| ScanFailure::Unavailable)?;
        if metadata.file_type().is_symlink() {
            return Err(ScanFailure::Symlink);
        }
    }
    Ok(current)
}

fn scan_path(
    path: &Path,
    logical: &str,
    depth: usize,
    public_only: bool,
    state: &mut ScanState,
) -> Result<(), ScanFailure> {
    state.entry_count = state
        .entry_count
        .checked_add(1)
        .ok_or(ScanFailure::LimitExceeded)?;
    if state.entry_count > MAX_ENTRIES_PER_CATEGORY
        || depth > MAX_DIRECTORY_DEPTH
        || logical.len() > MAX_LOGICAL_PATH_BYTES
    {
        return Err(ScanFailure::LimitExceeded);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| ScanFailure::Unavailable)?;
    if metadata.file_type().is_symlink() {
        return Err(ScanFailure::Symlink);
    }
    if metadata.is_file() {
        return scan_file(path, logical, &metadata, public_only, state);
    }
    if !metadata.is_dir() {
        return Err(ScanFailure::UnsupportedType);
    }
    let mut children = Vec::new();
    for child in fs::read_dir(path).map_err(|_| ScanFailure::Unavailable)? {
        if children.len() >= MAX_ENTRIES_PER_CATEGORY as usize {
            return Err(ScanFailure::LimitExceeded);
        }
        children.push(child.map_err(|_| ScanFailure::Unavailable)?);
    }
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let name = child
            .file_name()
            .into_string()
            .map_err(|_| ScanFailure::NonUtf8Name)?;
        if !is_portable_segment(&name) {
            return Err(ScanFailure::InvalidPath);
        }
        let child_logical = format!("{logical}/{name}");
        scan_path(&child.path(), &child_logical, depth + 1, public_only, state)?;
    }
    Ok(())
}

fn is_portable_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value != "."
        && value != ".."
        && !is_windows_reserved_name(value)
        && !value.ends_with(['.', ' '])
        && !value
            .chars()
            .any(|character| character.is_control() || r#"<>:\"/\\|?*"#.contains(character))
}

fn is_windows_reserved_name(value: &str) -> bool {
    let base = value
        .split_once('.')
        .map_or(value, |(base, _extension)| base)
        .to_ascii_uppercase();
    matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || base
            .strip_prefix("COM")
            .or_else(|| base.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
}

fn scan_file(
    path: &Path,
    logical: &str,
    before: &fs::Metadata,
    public_only: bool,
    state: &mut ScanState,
) -> Result<(), ScanFailure> {
    if public_only && has_private_key_extension(path) {
        return Err(ScanFailure::PrivateMaterial);
    }
    state.file_count = state
        .file_count
        .checked_add(1)
        .ok_or(ScanFailure::LimitExceeded)?;
    state.total_bytes = state
        .total_bytes
        .checked_add(before.len())
        .ok_or(ScanFailure::LimitExceeded)?;
    if state.file_count > MAX_FILES_PER_CATEGORY || state.total_bytes > MAX_BYTES_PER_CATEGORY {
        return Err(ScanFailure::LimitExceeded);
    }
    let mut reader = BufReader::new(File::open(path).map_err(|_| ScanFailure::Unavailable)?);
    let mut hasher = Sha256::new();
    let mut bytes_read = 0_u64;
    let mut prefix = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| ScanFailure::Unavailable)?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read
            .checked_add(read as u64)
            .ok_or(ScanFailure::LimitExceeded)?;
        hasher.update(&buffer[..read]);
        if public_only && prefix.len() < 64 * 1024 {
            let remaining = 64 * 1024 - prefix.len();
            prefix.extend_from_slice(&buffer[..read.min(remaining)]);
        }
    }
    let after = fs::symlink_metadata(path).map_err(|_| ScanFailure::Changed)?;
    if after.file_type().is_symlink()
        || !after.is_file()
        || bytes_read != before.len()
        || after.len() != before.len()
        || after.modified().ok() != before.modified().ok()
    {
        return Err(ScanFailure::Changed);
    }
    if public_only
        && String::from_utf8_lossy(&prefix)
            .to_ascii_uppercase()
            .contains("PRIVATE KEY")
    {
        return Err(ScanFailure::PrivateMaterial);
    }
    let mut payload = before.len().to_be_bytes().to_vec();
    payload.extend_from_slice(&hasher.finalize());
    state.entries.insert(logical.into(), payload);
    Ok(())
}

fn has_private_key_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "pfx" | "p12" | "key" | "jks" | "keystore"
            )
        })
}

fn minimum_inputs(id: &str) -> usize {
    match id {
        "signed-origin-policy" => 3,
        "plugin-release-set" | "previous-windows-release" => 2,
        _ => 1,
    }
}

fn category_identity_payload(report: &MaterialCategoryReport) -> Vec<u8> {
    serde_json::to_vec(report).expect("category report serialization is infallible")
}

fn validate_label(value: &str, field: &str) -> Result<(), PilotReadinessError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(PilotReadinessError::Invalid(format!(
            "{field} must be a portable non-sensitive label"
        )));
    }
    Ok(())
}

fn validate_approval_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn digest_named_payloads(
    domain: &str,
    payloads: &BTreeMap<String, Vec<u8>>,
) -> Result<String, PilotReadinessError> {
    validate_label(domain, "digest domain")?;
    let mut hasher = Sha256::new();
    hasher.update(b"SSDEV-PILOT-READINESS\0");
    append_field(&mut hasher, domain.as_bytes());
    for (name, payload) in payloads {
        append_field(&mut hasher, name.as_bytes());
        append_field(&mut hasher, payload);
    }
    Ok(hex_digest(hasher.finalize()))
}

fn append_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex_digest(Sha256::digest(bytes))
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn complete_manifest(root: &Path) -> PilotMaterialManifest {
        let categories = CATEGORY_RULES
            .iter()
            .enumerate()
            .map(|(index, rule)| {
                if rule.applicability == Applicability::Conditional {
                    MaterialCategory {
                        id: rule.id.into(),
                        status: MaterialStatus::NotApplicable,
                        inputs: Vec::new(),
                        approval_reference: Some(format!("PILOT-{index}")),
                    }
                } else {
                    let inputs = (0..minimum_inputs(rule.id))
                        .map(|input_index| {
                            let file = format!("material-{index}-{input_index}.bin");
                            fs::write(root.join(&file), format!("content-{index}-{input_index}"))
                                .unwrap();
                            file
                        })
                        .collect();
                    MaterialCategory {
                        id: rule.id.into(),
                        status: MaterialStatus::Provided,
                        inputs,
                        approval_reference: None,
                    }
                }
            })
            .collect();
        PilotMaterialManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            project_label: "hospital-a-pilot".into(),
            categories,
        }
    }

    #[test]
    fn complete_intake_is_bound_without_exposing_paths_or_approvals() {
        let temp = tempdir().unwrap();
        let manifest = complete_manifest(temp.path());
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let report = inspect_materials(temp.path(), &manifest, &bytes).unwrap();
        assert!(report.intake_complete);
        assert!(report.downstream_validation_required);
        assert!(report.blocker_codes.is_empty());
        assert_eq!(report.categories.len(), CATEGORY_RULES.len());
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("material-0-0.bin"));
        assert!(!json.contains("PILOT-10"));
        assert!(!json.contains(temp.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn material_identity_is_stable_and_changes_with_content() {
        let temp = tempdir().unwrap();
        let manifest = complete_manifest(temp.path());
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let first = inspect_materials(temp.path(), &manifest, &bytes).unwrap();
        let second = inspect_materials(temp.path(), &manifest, &bytes).unwrap();
        assert_eq!(first.material_set_sha256, second.material_set_sha256);
        fs::write(temp.path().join("material-0-0.bin"), "changed").unwrap();
        let changed = inspect_materials(temp.path(), &manifest, &bytes).unwrap();
        assert_ne!(first.material_set_sha256, changed.material_set_sha256);
    }

    #[test]
    fn missing_invalid_and_unapproved_materials_are_explicit_blockers() {
        let temp = tempdir().unwrap();
        let mut manifest = complete_manifest(temp.path());
        manifest
            .categories
            .retain(|item| item.id != "business-hars");
        let keymap = manifest
            .categories
            .iter_mut()
            .find(|item| item.id == "legacy-keymap")
            .unwrap();
        keymap.approval_reference = None;
        let native = manifest
            .categories
            .iter_mut()
            .find(|item| item.id == "production-native-assets")
            .unwrap();
        native.status = MaterialStatus::NotApplicable;
        native.inputs.clear();
        native.approval_reference = Some("PILOT-REQUIRED".into());
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let report = inspect_materials(temp.path(), &manifest, &bytes).unwrap();
        assert!(!report.intake_complete);
        assert!(report
            .blocker_codes
            .contains(&"business-hars-missing".into()));
        assert!(report
            .blocker_codes
            .contains(&"legacy-keymap-approval-missing".into()));
        assert!(report
            .blocker_codes
            .contains(&"production-native-assets-required".into()));
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_links_are_rejected_without_disclosing_their_target() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let mut manifest = complete_manifest(temp.path());
        symlink(
            temp.path().join("material-1-0.bin"),
            temp.path().join("linked.bin"),
        )
        .unwrap();
        let category = manifest
            .categories
            .iter_mut()
            .find(|item| item.id == "production-native-assets")
            .unwrap();
        category.inputs = vec!["linked.bin".into()];
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let report = inspect_materials(temp.path(), &manifest, &bytes).unwrap();
        assert!(report
            .blocker_codes
            .contains(&"production-native-assets-input-symlink".into()));
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("linked.bin"));
        assert!(!json.contains("material-1-0.bin"));
    }

    #[test]
    fn reports_are_no_clobber() {
        let temp = tempdir().unwrap();
        let output = temp.path().join("report.json");
        fs::write(&output, "existing").unwrap();
        assert!(matches!(
            prepare_new_output(&output),
            Err(PilotReadinessError::OutputExists)
        ));
    }

    #[test]
    fn public_trust_material_rejects_obvious_private_keys_without_naming_them() {
        let temp = tempdir().unwrap();
        let mut manifest = complete_manifest(temp.path());
        fs::write(temp.path().join("signing.pfx"), b"private material").unwrap();
        let category = manifest
            .categories
            .iter_mut()
            .find(|item| item.id == "organization-public-trust")
            .unwrap();
        category.inputs = vec!["signing.pfx".into()];
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let report = inspect_materials(temp.path(), &manifest, &bytes).unwrap();
        assert!(report
            .blocker_codes
            .contains(&"organization-public-trust-private-material-forbidden".into()));
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("signing.pfx"));
    }

    #[test]
    fn material_paths_are_portable_to_windows() {
        assert!(normalize_relative_path("business/dist/index.html").is_ok());
        assert_eq!(
            normalize_relative_path("business/CON.json"),
            Err(ScanFailure::InvalidPath)
        );
        assert_eq!(
            normalize_relative_path("business/name?.json"),
            Err(ScanFailure::InvalidPath)
        );
    }

    #[test]
    fn documented_manifest_keeps_the_complete_fixed_category_set() {
        let manifest: PilotMaterialManifest =
            serde_json::from_str(include_str!("../../../docs/pilot-materials.example.json"))
                .unwrap();
        assert_eq!(manifest.schema_version, MANIFEST_SCHEMA_VERSION);
        let documented = manifest
            .categories
            .iter()
            .map(|category| category.id.as_str())
            .collect::<BTreeSet<_>>();
        let required = CATEGORY_RULES
            .iter()
            .map(|rule| rule.id)
            .collect::<BTreeSet<_>>();
        assert_eq!(documented, required);
    }
}
