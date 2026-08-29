use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

pub const MANIFEST_SCHEMA_VERSION: u8 = 2;
pub const REPORT_SCHEMA_VERSION: u8 = 2;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_REPORT_BYTES: u64 = 1024 * 1024;
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
    pub migration_audit_bindings: MigrationAuditBindings,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MigrationAuditBindings {
    pub configs: Vec<String>,
    pub plugin_roots: Vec<String>,
    pub keymaps: Vec<String>,
    pub browser_asset_roots: Vec<String>,
    pub browser_hars: Vec<String>,
    pub origin_policy: String,
    pub origin_policy_envelope: String,
    pub release_trust_store: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ReportMaterialStatus {
    Provided,
    NotApplicable,
    Missing,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PilotReadinessReport {
    pub schema_version: u8,
    pub report_type: String,
    pub manifest_sha256: String,
    pub project_label_sha256: String,
    pub migration_audit_bindings_sha256: String,
    pub material_set_sha256: String,
    pub intake_complete: bool,
    pub downstream_validation_required: bool,
    pub categories: Vec<MaterialCategoryReport>,
    pub blocker_codes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedMigrationAuditInputs {
    pub configs: Vec<PathBuf>,
    pub plugin_roots: Vec<PathBuf>,
    pub keymaps: Vec<PathBuf>,
    pub browser_asset_roots: Vec<PathBuf>,
    pub browser_hars: Vec<PathBuf>,
    pub origin_policy: PathBuf,
    pub origin_policy_envelope: PathBuf,
    pub release_trust_store: PathBuf,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NormalizedMigrationAuditBindings {
    configs: Vec<String>,
    plugin_roots: Vec<String>,
    keymaps: Vec<String>,
    browser_asset_roots: Vec<String>,
    browser_hars: Vec<String>,
    origin_policy: String,
    origin_policy_envelope: String,
    release_trust_store: String,
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
    #[error("pilot readiness report does not match the current manifest and material set")]
    VerificationFailed,
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
    let bytes = read_bounded_regular_file(path, MAX_MANIFEST_BYTES, "manifest")?;
    let manifest = serde_json::from_slice(&bytes)?;
    Ok((manifest, bytes))
}

pub fn load_report(path: &Path) -> Result<(PilotReadinessReport, Vec<u8>), PilotReadinessError> {
    let bytes = read_bounded_regular_file(path, MAX_REPORT_BYTES, "report")?;
    let report: PilotReadinessReport = serde_json::from_slice(&bytes)?;
    validate_report(&report)?;
    Ok((report, bytes))
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

    let (migration_audit_bindings_sha256, bindings_valid) =
        match normalize_migration_audit_bindings(&manifest.migration_audit_bindings) {
            Ok(bindings) => {
                let valid = migration_audit_bindings_match_categories(&bindings, &supplied);
                (
                    sha256_bytes(
                        &serde_json::to_vec(&bindings)
                            .expect("normalized migration audit bindings are serializable"),
                    ),
                    valid,
                )
            }
            Err(_) => (
                sha256_bytes(
                    &serde_json::to_vec(&manifest.migration_audit_bindings)
                        .expect("migration audit bindings are serializable"),
                ),
                false,
            ),
        };
    if !bindings_valid {
        global_blockers.insert("migration-audit-binding-mismatch".into());
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
    material_payloads.insert(
        "migration-audit-bindings".into(),
        migration_audit_bindings_sha256.as_bytes().to_vec(),
    );
    let material_set_sha256 = digest_named_payloads("pilot-material-set", &material_payloads)?;
    let blocker_codes = global_blockers.into_iter().collect::<Vec<_>>();
    Ok(PilotReadinessReport {
        schema_version: REPORT_SCHEMA_VERSION,
        report_type: "pilot-material-readiness".into(),
        manifest_sha256: sha256_bytes(manifest_bytes),
        project_label_sha256: sha256_bytes(manifest.project_label.as_bytes()),
        migration_audit_bindings_sha256,
        material_set_sha256,
        intake_complete: blocker_codes.is_empty(),
        downstream_validation_required: true,
        categories: reports,
        blocker_codes,
    })
}

pub fn verify_materials(
    materials_root: &Path,
    manifest: &PilotMaterialManifest,
    manifest_bytes: &[u8],
    expected: &PilotReadinessReport,
) -> Result<(), PilotReadinessError> {
    validate_report(expected)?;
    let actual = inspect_materials(materials_root, manifest, manifest_bytes)?;
    if &actual != expected {
        return Err(PilotReadinessError::VerificationFailed);
    }
    Ok(())
}

pub fn resolve_migration_audit_inputs(
    materials_root: &Path,
    manifest: &PilotMaterialManifest,
) -> Result<ResolvedMigrationAuditInputs, PilotReadinessError> {
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(PilotReadinessError::Invalid(
            "unsupported pilot material manifest schema".into(),
        ));
    }
    let root_metadata = fs::symlink_metadata(materials_root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(PilotReadinessError::Invalid(
            "materials root must be a real directory".into(),
        ));
    }
    let root = fs::canonicalize(materials_root)?;
    let normalized = normalize_migration_audit_bindings(&manifest.migration_audit_bindings)
        .map_err(|_| PilotReadinessError::Invalid("migration audit bindings are invalid".into()))?;
    let mut supplied = BTreeMap::new();
    for category in &manifest.categories {
        if supplied.insert(category.id.as_str(), category).is_some() {
            return Err(PilotReadinessError::Invalid(
                "migration audit bindings contain duplicate material categories".into(),
            ));
        }
    }
    if !migration_audit_bindings_match_categories(&normalized, &supplied) {
        return Err(PilotReadinessError::Invalid(
            "migration audit bindings do not exactly match their material categories".into(),
        ));
    }
    Ok(ResolvedMigrationAuditInputs {
        configs: resolve_binding_paths(&root, &normalized.configs)?,
        plugin_roots: resolve_binding_paths(&root, &normalized.plugin_roots)?,
        keymaps: resolve_binding_paths(&root, &normalized.keymaps)?,
        browser_asset_roots: resolve_binding_paths(&root, &normalized.browser_asset_roots)?,
        browser_hars: resolve_binding_paths(&root, &normalized.browser_hars)?,
        origin_policy: resolve_binding_path(&root, &normalized.origin_policy)?,
        origin_policy_envelope: resolve_binding_path(&root, &normalized.origin_policy_envelope)?,
        release_trust_store: resolve_binding_path(&root, &normalized.release_trust_store)?,
    })
}

pub fn resolve_material_category_inputs(
    materials_root: &Path,
    manifest: &PilotMaterialManifest,
    category_id: &str,
) -> Result<Vec<PathBuf>, PilotReadinessError> {
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION
        || !CATEGORY_RULES.iter().any(|rule| rule.id == category_id)
    {
        return Err(PilotReadinessError::Invalid(
            "unsupported pilot material manifest or category".into(),
        ));
    }
    let root_metadata = fs::symlink_metadata(materials_root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(PilotReadinessError::Invalid(
            "materials root must be a real directory".into(),
        ));
    }
    let root = fs::canonicalize(materials_root)?;
    let mut matches = manifest
        .categories
        .iter()
        .filter(|category| category.id == category_id);
    let category = matches
        .next()
        .ok_or_else(|| PilotReadinessError::Invalid("pilot material category is missing".into()))?;
    if matches.next().is_some()
        || category.status != MaterialStatus::Provided
        || category.approval_reference.is_some()
    {
        return Err(PilotReadinessError::Invalid(
            "pilot material category is duplicated or not provided".into(),
        ));
    }
    let normalized = normalize_binding_paths(&category.inputs)
        .map_err(|_| PilotReadinessError::Invalid("material category inputs are invalid".into()))?;
    if normalized.is_empty() {
        return Err(PilotReadinessError::Invalid(
            "material category inputs are empty".into(),
        ));
    }
    resolve_binding_paths(&root, &normalized)
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
    validate_report(report)?;
    let mut file = File::options().write(true).create_new(true).open(path)?;
    serde_json::to_writer_pretty(&mut file, report)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn validate_report(report: &PilotReadinessReport) -> Result<(), PilotReadinessError> {
    if report.schema_version != REPORT_SCHEMA_VERSION
        || report.report_type != "pilot-material-readiness"
        || !report.downstream_validation_required
        || !is_sha256(&report.manifest_sha256)
        || !is_sha256(&report.project_label_sha256)
        || !is_sha256(&report.migration_audit_bindings_sha256)
        || !is_sha256(&report.material_set_sha256)
        || report.intake_complete != report.blocker_codes.is_empty()
        || !is_sorted_unique_codes(&report.blocker_codes)
        || report.categories.len() != CATEGORY_RULES.len()
    {
        return Err(PilotReadinessError::Invalid(
            "pilot readiness report is malformed or unsupported".into(),
        ));
    }
    let mut payloads = BTreeMap::new();
    let mut category_blockers = BTreeSet::new();
    for (category, rule) in report.categories.iter().zip(CATEGORY_RULES) {
        if category.id != rule.id
            || category.input_count as usize > MAX_INPUTS_PER_CATEGORY + 1
            || category.file_count > MAX_FILES_PER_CATEGORY
            || category.total_bytes > MAX_BYTES_PER_CATEGORY
            || !is_sorted_unique_codes(&category.blocker_codes)
            || !category
                .blocker_codes
                .iter()
                .all(|code| is_allowed_category_blocker(rule.id, code))
            || category
                .content_sha256
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
            || category
                .approval_reference_sha256
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
        {
            return Err(PilotReadinessError::Invalid(
                "pilot readiness category report is malformed".into(),
            ));
        }
        category_blockers.extend(category.blocker_codes.iter().cloned());
        match category.status {
            ReportMaterialStatus::Missing
                if category.blocker_codes != [format!("{}-missing", rule.id)]
                    || category.input_count != 0
                    || category.file_count != 0
                    || category.total_bytes != 0
                    || category.content_sha256.is_some()
                    || category.approval_reference_sha256.is_some() =>
            {
                return Err(PilotReadinessError::Invalid(
                    "missing material report contains impossible content".into(),
                ));
            }
            ReportMaterialStatus::NotApplicable
                if (rule.applicability == Applicability::Required
                    && !category
                        .blocker_codes
                        .contains(&format!("{}-required", rule.id)))
                    || (rule.applicability == Applicability::Conditional
                        && category.approval_reference_sha256.is_none()
                        && !category
                            .blocker_codes
                            .contains(&format!("{}-approval-missing", rule.id)))
                    || (category.input_count > 0
                        && !category
                            .blocker_codes
                            .contains(&format!("{}-not-applicable-has-inputs", rule.id)))
                    || category.file_count != 0
                    || category.total_bytes != 0
                    || category.content_sha256.is_some() =>
            {
                return Err(PilotReadinessError::Invalid(
                    "not-applicable material report contains content".into(),
                ));
            }
            ReportMaterialStatus::Provided
                if category.approval_reference_sha256.is_some()
                    || (category.input_count == 0
                        && !category
                            .blocker_codes
                            .contains(&format!("{}-inputs-empty", rule.id)))
                    || (category.input_count > 0
                        && (category.input_count as usize) < minimum_inputs(rule.id)
                        && !category
                            .blocker_codes
                            .contains(&format!("{}-input-count-below-minimum", rule.id)))
                    || (category.input_count as usize > MAX_INPUTS_PER_CATEGORY
                        && !category
                            .blocker_codes
                            .contains(&format!("{}-input-limit-exceeded", rule.id)))
                    || (!category.blocker_codes.is_empty()
                        && category.content_sha256.is_some())
                    || (category.blocker_codes.is_empty()
                        && (category.content_sha256.is_none() || category.file_count == 0)) =>
            {
                return Err(PilotReadinessError::Invalid(
                    "provided material report has an invalid identity".into(),
                ));
            }
            _ => {}
        }
        payloads.insert(category.id.clone(), category_identity_payload(category));
    }
    let report_blockers = report
        .blocker_codes
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if !category_blockers.is_subset(&report_blockers)
        || report_blockers.difference(&category_blockers).any(|code| {
            !matches!(
                code.as_str(),
                "unknown-material-category"
                    | "duplicate-material-category"
                    | "migration-audit-binding-mismatch"
            )
        })
    {
        return Err(PilotReadinessError::Invalid(
            "pilot readiness report blocker summary is inconsistent".into(),
        ));
    }
    payloads.insert(
        "migration-audit-bindings".into(),
        report.migration_audit_bindings_sha256.as_bytes().to_vec(),
    );
    if digest_named_payloads("pilot-material-set", &payloads)? != report.material_set_sha256 {
        return Err(PilotReadinessError::Invalid(
            "pilot readiness material set digest is inconsistent".into(),
        ));
    }
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
        input_count: reported_input_count(category.inputs.len()),
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
    if blockers.is_empty()
        && id == "previous-windows-release"
        && !previous_windows_bundle_layout_is_valid(materials_root, &normalized_inputs)
    {
        blockers.insert(format!("{id}-layout-invalid"));
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
        input_count: reported_input_count(category.inputs.len()),
        file_count: state.file_count,
        total_bytes: state.total_bytes,
        content_sha256,
        approval_reference_sha256: None,
        blocker_codes: blockers.into_iter().collect(),
    }
}

fn normalize_migration_audit_bindings(
    bindings: &MigrationAuditBindings,
) -> Result<NormalizedMigrationAuditBindings, ScanFailure> {
    let normalized = NormalizedMigrationAuditBindings {
        configs: normalize_binding_paths(&bindings.configs)?,
        plugin_roots: normalize_binding_paths(&bindings.plugin_roots)?,
        keymaps: normalize_binding_paths(&bindings.keymaps)?,
        browser_asset_roots: normalize_binding_paths(&bindings.browser_asset_roots)?,
        browser_hars: normalize_binding_paths(&bindings.browser_hars)?,
        origin_policy: normalize_relative_path(&bindings.origin_policy)?,
        origin_policy_envelope: normalize_relative_path(&bindings.origin_policy_envelope)?,
        release_trust_store: normalize_relative_path(&bindings.release_trust_store)?,
    };
    if normalized.configs.is_empty()
        || normalized.plugin_roots.is_empty()
        || normalized.browser_asset_roots.is_empty()
        || normalized.browser_hars.is_empty()
    {
        return Err(ScanFailure::InvalidPath);
    }
    Ok(normalized)
}

fn normalize_binding_paths(paths: &[String]) -> Result<Vec<String>, ScanFailure> {
    if paths.len() > MAX_INPUTS_PER_CATEGORY {
        return Err(ScanFailure::LimitExceeded);
    }
    let normalized = paths
        .iter()
        .map(|path| normalize_relative_path(path))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if normalized.len() != paths.len() {
        return Err(ScanFailure::InvalidPath);
    }
    Ok(normalized.into_iter().collect())
}

fn migration_audit_bindings_match_categories(
    bindings: &NormalizedMigrationAuditBindings,
    supplied: &BTreeMap<&str, &MaterialCategory>,
) -> bool {
    category_inputs("legacy-config", supplied).as_ref() == Some(&bindings.configs)
        && category_inputs("production-native-assets", supplied).as_ref()
            == Some(&bindings.plugin_roots)
        && category_inputs("legacy-keymap", supplied).as_ref() == Some(&bindings.keymaps)
        && category_inputs("business-assets", supplied).as_ref()
            == Some(&bindings.browser_asset_roots)
        && category_inputs("business-hars", supplied).as_ref() == Some(&bindings.browser_hars)
        && category_inputs("signed-origin-policy", supplied).is_some_and(|inputs| {
            inputs
                == [
                    bindings.origin_policy.clone(),
                    bindings.origin_policy_envelope.clone(),
                    bindings.release_trust_store.clone(),
                ]
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        })
}

fn category_inputs(id: &str, supplied: &BTreeMap<&str, &MaterialCategory>) -> Option<Vec<String>> {
    let category = supplied.get(id)?;
    normalize_binding_paths(&category.inputs).ok()
}

fn resolve_binding_paths(
    root: &Path,
    bindings: &[String],
) -> Result<Vec<PathBuf>, PilotReadinessError> {
    bindings
        .iter()
        .map(|binding| resolve_binding_path(root, binding))
        .collect()
}

fn resolve_binding_path(root: &Path, binding: &str) -> Result<PathBuf, PilotReadinessError> {
    resolve_without_symlink(root, binding).map_err(|_| {
        PilotReadinessError::Invalid("a migration audit binding is unavailable or unsafe".into())
    })
}

fn previous_windows_bundle_layout_is_valid(
    materials_root: &Path,
    normalized_inputs: &BTreeSet<String>,
) -> bool {
    let Some(bundle_relative) = normalized_inputs.iter().next() else {
        return false;
    };
    if normalized_inputs.len() != 1 {
        return false;
    }
    let Ok(bundle) = resolve_without_symlink(materials_root, bundle_relative) else {
        return false;
    };
    if !fs::symlink_metadata(&bundle).is_ok_and(|metadata| metadata.is_dir()) {
        return false;
    }
    for required in [
        "metadata/release.json",
        "metadata/artifacts.json",
        "metadata/artifacts.json.sig",
        "metadata/app-update.json",
    ] {
        let relative = format!("{bundle_relative}/{required}");
        let Ok(path) = resolve_without_symlink(materials_root, &relative) else {
            return false;
        };
        if !fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file()) {
            return false;
        }
    }
    let nsis_relative = format!("{bundle_relative}/nsis");
    let Ok(nsis) = resolve_without_symlink(materials_root, &nsis_relative) else {
        return false;
    };
    let Ok(entries) = fs::read_dir(nsis) else {
        return false;
    };
    let installers = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            let Ok(name) = entry.file_name().into_string() else {
                return false;
            };
            name.ends_with("-setup.exe")
                && fs::symlink_metadata(entry.path())
                    .is_ok_and(|metadata| !metadata.file_type().is_symlink() && metadata.is_file())
        })
        .count();
    installers == 1
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
    if state.file_count >= MAX_FILES_PER_CATEGORY
        || before.len() > MAX_BYTES_PER_CATEGORY.saturating_sub(state.total_bytes)
    {
        return Err(ScanFailure::LimitExceeded);
    }
    state.file_count = state
        .file_count
        .checked_add(1)
        .ok_or(ScanFailure::LimitExceeded)?;
    state.total_bytes = state
        .total_bytes
        .checked_add(before.len())
        .ok_or(ScanFailure::LimitExceeded)?;
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
        "plugin-release-set" => 2,
        _ => 1,
    }
}

fn reported_input_count(actual: usize) -> u32 {
    u32::try_from(actual.min(MAX_INPUTS_PER_CATEGORY + 1))
        .expect("the bounded input count always fits u32")
}

fn category_identity_payload(report: &MaterialCategoryReport) -> Vec<u8> {
    serde_json::to_vec(report).expect("category report serialization is infallible")
}

fn read_bounded_regular_file(
    path: &Path,
    limit: u64,
    kind: &str,
) -> Result<Vec<u8>, PilotReadinessError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err(PilotReadinessError::Invalid(format!(
            "{kind} must be a bounded regular file"
        )));
    }
    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(limit as usize));
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    let after = fs::symlink_metadata(path)?;
    if bytes.len() as u64 > limit
        || after.file_type().is_symlink()
        || !after.is_file()
        || after.len() != metadata.len()
        || after.len() != bytes.len() as u64
        || after.modified().ok() != metadata.modified().ok()
    {
        return Err(PilotReadinessError::Invalid(format!(
            "{kind} changed or exceeded its limit while being read"
        )));
    }
    Ok(bytes)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_sorted_unique_codes(codes: &[String]) -> bool {
    codes.windows(2).all(|pair| pair[0] < pair[1])
        && codes.iter().all(|code| {
            !code.is_empty()
                && code.len() <= 160
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn is_allowed_category_blocker(id: &str, code: &str) -> bool {
    let Some(suffix) = code
        .strip_prefix(id)
        .and_then(|value| value.strip_prefix('-'))
    else {
        return false;
    };
    matches!(
        suffix,
        "missing"
            | "not-applicable-has-inputs"
            | "required"
            | "approval-missing"
            | "provided-has-approval"
            | "inputs-empty"
            | "input-count-below-minimum"
            | "input-limit-exceeded"
            | "input-duplicate"
            | "input-path-invalid"
            | "input-name-invalid"
            | "input-changed"
            | "input-symlink"
            | "input-unavailable"
            | "input-type-unsupported"
            | "private-material-forbidden"
            | "content-empty"
            | "identity-failed"
            | "layout-invalid"
    )
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

    fn write_previous_windows_bundle(root: &Path, relative: &str) {
        let bundle = root.join(relative);
        fs::create_dir_all(bundle.join("metadata")).unwrap();
        fs::create_dir_all(bundle.join("nsis")).unwrap();
        for file in [
            "metadata/release.json",
            "metadata/artifacts.json",
            "metadata/artifacts.json.sig",
            "metadata/app-update.json",
            "nsis/ssdev-setup.exe",
        ] {
            fs::write(bundle.join(file), file).unwrap();
        }
    }

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
                    let inputs = if rule.id == "previous-windows-release" {
                        let relative = format!("material-{index}-bundle");
                        write_previous_windows_bundle(root, &relative);
                        vec![relative]
                    } else {
                        (0..minimum_inputs(rule.id))
                            .map(|input_index| {
                                let file = format!("material-{index}-{input_index}.bin");
                                fs::write(
                                    root.join(&file),
                                    format!("content-{index}-{input_index}"),
                                )
                                .unwrap();
                                file
                            })
                            .collect()
                    };
                    MaterialCategory {
                        id: rule.id.into(),
                        status: MaterialStatus::Provided,
                        inputs,
                        approval_reference: None,
                    }
                }
            })
            .collect::<Vec<_>>();
        let category_inputs = |id: &str| {
            categories
                .iter()
                .find(|category| category.id == id)
                .unwrap()
                .inputs
                .clone()
        };
        let signed_policy = category_inputs("signed-origin-policy");
        let migration_audit_bindings = MigrationAuditBindings {
            configs: category_inputs("legacy-config"),
            plugin_roots: category_inputs("production-native-assets"),
            keymaps: category_inputs("legacy-keymap"),
            browser_asset_roots: category_inputs("business-assets"),
            browser_hars: category_inputs("business-hars"),
            origin_policy: signed_policy[0].clone(),
            origin_policy_envelope: signed_policy[1].clone(),
            release_trust_store: signed_policy[2].clone(),
        };
        PilotMaterialManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            project_label: "hospital-a-pilot".into(),
            categories,
            migration_audit_bindings,
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
    fn migration_audit_roles_are_exact_and_part_of_the_material_identity() {
        let temp = tempdir().unwrap();
        let manifest = complete_manifest(temp.path());
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let first = inspect_materials(temp.path(), &manifest, &bytes).unwrap();
        let resolved = resolve_migration_audit_inputs(temp.path(), &manifest).unwrap();
        assert_eq!(resolved.configs.len(), 1);
        assert_eq!(resolved.plugin_roots.len(), 1);
        assert_eq!(resolved.browser_asset_roots.len(), 1);
        assert_eq!(resolved.browser_hars.len(), 1);

        let mut role_changed = manifest.clone();
        std::mem::swap(
            &mut role_changed.migration_audit_bindings.origin_policy,
            &mut role_changed.migration_audit_bindings.origin_policy_envelope,
        );
        let changed_bytes = serde_json::to_vec(&role_changed).unwrap();
        let changed = inspect_materials(temp.path(), &role_changed, &changed_bytes).unwrap();
        assert!(changed.intake_complete);
        assert_ne!(
            first.migration_audit_bindings_sha256,
            changed.migration_audit_bindings_sha256
        );
        assert_ne!(first.material_set_sha256, changed.material_set_sha256);

        let mut incomplete = manifest;
        incomplete.migration_audit_bindings.browser_hars.clear();
        let incomplete_bytes = serde_json::to_vec(&incomplete).unwrap();
        let incomplete_report =
            inspect_materials(temp.path(), &incomplete, &incomplete_bytes).unwrap();
        assert!(!incomplete_report.intake_complete);
        assert!(incomplete_report
            .blocker_codes
            .contains(&"migration-audit-binding-mismatch".into()));
    }

    #[test]
    fn previous_windows_release_requires_a_complete_bundle_layout() {
        let temp = tempdir().unwrap();
        let manifest = complete_manifest(temp.path());
        let resolved =
            resolve_material_category_inputs(temp.path(), &manifest, "previous-windows-release")
                .unwrap();
        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].is_dir());
        assert!(resolve_material_category_inputs(temp.path(), &manifest, "unknown").is_err());
        let previous = manifest
            .categories
            .iter()
            .find(|category| category.id == "previous-windows-release")
            .unwrap();
        fs::remove_file(
            temp.path()
                .join(&previous.inputs[0])
                .join("metadata/artifacts.json.sig"),
        )
        .unwrap();
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let report = inspect_materials(temp.path(), &manifest, &bytes).unwrap();
        assert!(!report.intake_complete);
        assert!(report
            .blocker_codes
            .contains(&"previous-windows-release-layout-invalid".into()));
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
    fn a_handoff_report_round_trips_and_detects_material_or_identity_drift() {
        let temp = tempdir().unwrap();
        let materials = temp.path().join("materials");
        fs::create_dir(&materials).unwrap();
        let manifest = complete_manifest(&materials);
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let report = inspect_materials(&materials, &manifest, &bytes).unwrap();
        let report_path = temp.path().join("report.json");
        write_report(&report_path, &report).unwrap();
        let (loaded, _) = load_report(&report_path).unwrap();
        verify_materials(&materials, &manifest, &bytes, &loaded).unwrap();

        fs::write(materials.join("material-0-0.bin"), "changed").unwrap();
        assert!(matches!(
            verify_materials(&materials, &manifest, &bytes, &loaded),
            Err(PilotReadinessError::VerificationFailed)
        ));

        fs::write(materials.join("material-0-0.bin"), "content-0-0").unwrap();
        let mut changed_identity = loaded;
        changed_identity.project_label_sha256 = "0".repeat(64);
        assert!(matches!(
            verify_materials(&materials, &manifest, &bytes, &changed_identity),
            Err(PilotReadinessError::VerificationFailed)
        ));

        let mut internally_inconsistent = report;
        internally_inconsistent.categories[0].file_count += 1;
        let corrupt_path = temp.path().join("corrupt-report.json");
        fs::write(
            &corrupt_path,
            serde_json::to_vec(&internally_inconsistent).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            load_report(&corrupt_path),
            Err(PilotReadinessError::Invalid(_))
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
