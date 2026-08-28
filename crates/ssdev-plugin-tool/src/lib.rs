use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tempfile::Builder as TempBuilder;
use thiserror::Error;
use webplus_plugin_config::{discover_plugins, PluginManifest, PluginMetadata};
use webplus_plugin_package::{create_deterministic_package, PreparedPlugin};
use webplus_plugin_repository::{encode_catalog_document, CatalogEntry};
use webplus_plugin_trust::{
    encode_signature_document, portable_plugin_path, prepare_signing_material, TrustPurpose,
    TrustStore, SIGNATURE_FILENAME,
};
use webplus_protocol::{
    contains_draft_placeholder, InvokeRequest, InvokeResponse, PluginArchitecture,
    DRAFT_INPUT_PLACEHOLDER, DRAFT_RESPONSE_PLACEHOLDER,
};

const MAX_PLUGIN_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PLUGIN_FILES: usize = 4096;
const MAX_SIGNING_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 1024;
const MAX_MATRIX_CASES: usize = 1024;
const MAX_MATRIX_PLUGINS: usize = 256;
const MAX_MATRIX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TRUST_STORE_BYTES: u64 = 256 * 1024;
const MAX_RELEASE_SET_SPEC_BYTES: u64 = 256 * 1024;
const MAX_CATALOG_SPEC_BYTES: u64 = 1024 * 1024;
const MAX_CATALOG_PACKAGES: usize = 4096;
const PLUGIN_METADATA_FILENAME: &str = "plugin.json";
const LEGACY_LICENSE_FILENAME: &str = "license.dat";

#[derive(Debug, Clone)]
pub struct PrepareOptions<'a> {
    pub source: &'a Path,
    pub staging: &'a Path,
    pub request: &'a Path,
    pub matrix_template: &'a Path,
    pub plugin_id: &'a str,
    pub version: &'a str,
    pub display_name: &'a str,
    pub key_id: &'a str,
    pub trust_store: &'a Path,
    pub matrix_seed: Option<&'a Path>,
}

#[derive(Debug, Clone)]
pub struct FinalizeOptions<'a> {
    pub staging: &'a Path,
    pub request: &'a Path,
    pub signature: &'a Path,
    pub trust_store: &'a Path,
    pub package: &'a Path,
}

#[derive(Debug, Clone)]
pub struct CatalogOptions<'a> {
    pub spec: &'a Path,
    pub trust_store: &'a Path,
    pub catalog: &'a Path,
    pub now: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareReport {
    pub schema_version: u8,
    pub plugin_id: String,
    pub version: String,
    pub key_id: String,
    pub service_count: usize,
    pub method_count: usize,
    pub signed_file_count: usize,
    pub payload_sha256: String,
    pub legacy_license_excluded: bool,
    pub matrix_seeded: bool,
    pub matrix_case_count: usize,
    pub matrix_placeholder_case_count: usize,
    pub matrix_review_required_case_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizeReport {
    pub schema_version: u8,
    pub plugin_id: String,
    pub version: String,
    pub key_id: String,
    pub signed_file_count: usize,
    pub payload_sha256: String,
    pub package_sha256: String,
    pub package_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyReport {
    pub schema_version: u8,
    pub plugin_id: String,
    pub version: String,
    pub key_id: String,
    pub service_count: usize,
    pub package_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseCheckReport {
    pub schema_version: u8,
    pub plugin_id: String,
    pub version: String,
    pub key_id: String,
    pub package_sha256: String,
    pub trust_store_sha256: String,
    pub matrix_sha256: String,
    pub service_count: usize,
    pub method_count: usize,
    pub case_count: usize,
    pub enabled_case_count: usize,
    pub package_verified: bool,
    pub matrix_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleasePackageReport {
    pub plugin_id: String,
    pub version: String,
    pub key_id: String,
    pub package_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseSetCheckReport {
    pub schema_version: u8,
    pub spec_sha256: String,
    pub package_set_sha256: String,
    pub trust_store_sha256: String,
    pub matrix_sha256: String,
    pub packages: Vec<ReleasePackageReport>,
    pub plugin_count: usize,
    pub service_count: usize,
    pub method_count: usize,
    pub case_count: usize,
    pub enabled_case_count: usize,
    pub packages_verified: bool,
    pub matrix_verified: bool,
}

struct CheckedReleasePackages {
    packages: Vec<ReleasePackageReport>,
    package_set_sha256: String,
    trust_store_sha256: String,
    matrix_sha256: String,
    matrix_report: MatrixCheckReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogReport {
    pub schema_version: u8,
    pub issued_at: u64,
    pub expires_at: u64,
    pub package_count: usize,
    pub catalog_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SigningRequest {
    schema_version: u8,
    plugin_id: String,
    version: String,
    key_id: String,
    algorithm: String,
    files: BTreeMap<String, String>,
    payload_base64: String,
    payload_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseSetSpec {
    schema_version: u8,
    packages: Vec<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginMatrix {
    pub schema_version: u8,
    pub draft: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plugins: Vec<PluginMatrixTarget>,
    pub cases: Vec<PluginMatrixCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginMatrixTarget {
    pub plugin_id: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginMatrixCase {
    pub name: String,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub review_required: bool,
    pub request: InvokeRequest,
    pub expected: InvokeResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MatrixCheckReport {
    pub schema_version: u8,
    pub plugin_count: usize,
    pub service_count: usize,
    pub method_count: usize,
    pub case_count: usize,
    pub enabled_case_count: usize,
    pub identity_bound: bool,
}

fn enabled_by_default() -> bool {
    true
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CatalogSpec {
    schema_version: u8,
    issued_at: u64,
    expires_at: u64,
    packages: Vec<CatalogPackageSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CatalogPackageSpec {
    package: PathBuf,
    url: url::Url,
}

pub fn prepare(options: &PrepareOptions<'_>) -> Result<PrepareReport, ToolError> {
    ensure_fresh_output(options.staging, "staging directory")?;
    ensure_fresh_output(options.request, "signing request")?;
    ensure_fresh_output(options.matrix_template, "matrix template")?;
    let trust_store = TrustStore::load(options.trust_store)?;
    trust_store.ensure_key_can_issue(TrustPurpose::Plugin, options.key_id)?;
    let source = canonical_real_directory(options.source)?;
    let matrix_seed = options
        .matrix_seed
        .map(|path| canonical_real_file(path, MAX_MATRIX_BYTES))
        .transpose()?;
    if matrix_seed
        .as_ref()
        .is_some_and(|matrix_seed| matrix_seed.starts_with(&source))
    {
        return Err(ToolError::Invalid(
            "matrix seed must stay outside the signed source directory".into(),
        ));
    }
    let staging = normalized_new_path(options.staging)?;
    let request = normalized_new_path(options.request)?;
    let matrix_template = normalized_new_path(options.matrix_template)?;
    for (role, path) in [
        ("staging directory", &staging),
        ("signing request", &request),
        ("matrix template", &matrix_template),
    ] {
        if path.starts_with(&source) {
            return Err(ToolError::Invalid(format!(
                "{role} must be outside the legacy source directory"
            )));
        }
    }
    if request.starts_with(&staging) || matrix_template.starts_with(&staging) {
        return Err(ToolError::Invalid(
            "signing request and matrix template must stay outside the signed staging directory"
                .into(),
        ));
    }

    let version = Version::parse(options.version)
        .map_err(|error| ToolError::Invalid(format!("plugin version is not SemVer: {error}")))?;
    fs::create_dir(&staging).map_err(|source| ToolError::Io {
        path: staging.clone(),
        source,
    })?;
    let prepared = (|| {
        let copy = copy_legacy_plugin(&source, &staging)?;
        let metadata = PluginMetadata {
            schema_version: 1,
            plugin_id: options.plugin_id.to_owned(),
            version: version.clone(),
            display_name: options.display_name.to_owned(),
        };
        write_new_json(staging.join(PLUGIN_METADATA_FILENAME), &metadata)?;

        let manifest = PluginManifest::load(options.plugin_id, &staging)?;
        validate_release_manifest(&manifest)?;
        let material = prepare_signing_material(&staging, options.plugin_id, options.key_id)?;
        let payload_sha256 = sha256_hex(&material.payload);
        let signing_request = SigningRequest {
            schema_version: 1,
            plugin_id: material.plugin_id.clone(),
            version: version.to_string(),
            key_id: material.key_id.clone(),
            algorithm: "ed25519".into(),
            files: material.files.clone(),
            payload_base64: BASE64.encode(&material.payload),
            payload_sha256: payload_sha256.clone(),
        };
        let matrix = match matrix_seed.as_deref() {
            Some(path) => load_matrix_seed(path, &manifest)?,
            None => draft_matrix(&manifest)?,
        };
        Ok::<_, ToolError>((
            copy,
            manifest,
            material,
            payload_sha256,
            signing_request,
            matrix,
        ))
    })();
    let (copy, manifest, material, payload_sha256, signing_request, matrix) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }
    };
    if let Err(error) =
        write_external_outputs(&request, &signing_request, &matrix_template, &matrix)
    {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }

    Ok(PrepareReport {
        schema_version: 1,
        plugin_id: options.plugin_id.to_owned(),
        version: version.to_string(),
        key_id: options.key_id.to_owned(),
        service_count: manifest.services.len(),
        method_count: manifest
            .services
            .iter()
            .map(|service| service.methods.len())
            .sum(),
        signed_file_count: material.files.len(),
        payload_sha256,
        legacy_license_excluded: copy.legacy_license_excluded,
        matrix_seeded: matrix_seed.is_some(),
        matrix_case_count: matrix.cases.len(),
        matrix_placeholder_case_count: matrix
            .cases
            .iter()
            .filter(|case| matrix_case_has_draft_placeholder(case))
            .count(),
        matrix_review_required_case_count: matrix
            .cases
            .iter()
            .filter(|case| case.review_required)
            .count(),
    })
}

pub fn finalize(options: &FinalizeOptions<'_>) -> Result<FinalizeReport, ToolError> {
    ensure_fresh_output(options.package, "plugin package")?;
    let staging = canonical_real_directory(options.staging)?;
    let request: SigningRequest = read_bounded_json(options.request, MAX_SIGNING_REQUEST_BYTES)?;
    if request.schema_version != 1 || request.algorithm != "ed25519" {
        return Err(ToolError::Invalid(
            "signing request must use schema 1 and Ed25519".into(),
        ));
    }
    let manifest = PluginManifest::load(&request.plugin_id, &staging)?;
    let staged_metadata = manifest
        .metadata
        .as_ref()
        .ok_or_else(|| ToolError::Invalid("staging directory must contain plugin.json".into()))?;
    if request.version != staged_metadata.version.to_string() {
        return Err(ToolError::Invalid(
            "signing request version does not match staged plugin metadata".into(),
        ));
    }
    let material = prepare_signing_material(&staging, &request.plugin_id, &request.key_id)?;
    if request.files != material.files
        || request.payload_base64 != BASE64.encode(&material.payload)
        || request.payload_sha256 != sha256_hex(&material.payload)
    {
        return Err(ToolError::Invalid(
            "staging directory changed after the signing request was created".into(),
        ));
    }
    let signature = read_signature(options.signature)?;
    let envelope = encode_signature_document(&material, &signature)?;
    let trust_store = TrustStore::load(options.trust_store)?;
    trust_store.verify_detached_for_issuance(
        TrustPurpose::Plugin,
        &material.key_id,
        &material.payload,
        &signature,
    )?;
    let signature_path = staging.join(SIGNATURE_FILENAME);
    match fs::symlink_metadata(&signature_path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file()
                || fs::read(&signature_path).map_err(|source| ToolError::Io {
                    path: signature_path.clone(),
                    source,
                })? != envelope
            {
                return Err(ToolError::Invalid(
                    "staging directory already contains a different or unsafe signature envelope"
                        .into(),
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_new_bytes(&signature_path, &envelope)?;
        }
        Err(source) => {
            return Err(ToolError::Io {
                path: signature_path,
                source,
            })
        }
    }

    trust_store.verify_for_issuance(&manifest)?;
    create_deterministic_package(&staging, options.package, &trust_store)?;

    let verification_root = tempfile::tempdir().map_err(|source| ToolError::Io {
        path: std::env::temp_dir(),
        source,
    })?;
    let verified =
        PreparedPlugin::prepare(options.package, verification_root.path(), &trust_store)?;
    let metadata = verified.metadata();
    let package_sha256 = sha256_file(options.package)?;
    Ok(FinalizeReport {
        schema_version: 1,
        plugin_id: verified.identity().plugin_id.clone(),
        version: metadata.version.to_string(),
        key_id: verified.identity().key_id.clone(),
        signed_file_count: material.files.len(),
        payload_sha256: request.payload_sha256,
        package_sha256,
        package_verified: true,
    })
}

pub fn verify(package: &Path, trust_store: &Path) -> Result<VerifyReport, ToolError> {
    let trust_store = TrustStore::load(trust_store)?;
    let verification_root = tempfile::tempdir().map_err(|source| ToolError::Io {
        path: std::env::temp_dir(),
        source,
    })?;
    let prepared = PreparedPlugin::prepare(package, verification_root.path(), &trust_store)?;
    let package_sha256 = sha256_file(package)?;
    Ok(VerifyReport {
        schema_version: 1,
        plugin_id: prepared.identity().plugin_id.clone(),
        version: prepared.metadata().version.to_string(),
        key_id: prepared.identity().key_id.clone(),
        service_count: prepared.manifest().services.len(),
        package_sha256,
    })
}

pub fn check_release_candidate(
    package: &Path,
    trust_store: &Path,
    matrix: &Path,
) -> Result<ReleaseCheckReport, ToolError> {
    let checked = check_release_packages(&[package.to_path_buf()], trust_store, matrix)?;
    let package = checked
        .packages
        .into_iter()
        .next()
        .ok_or_else(|| ToolError::Invalid("release candidate package is missing".into()))?;
    Ok(ReleaseCheckReport {
        schema_version: 1,
        plugin_id: package.plugin_id,
        version: package.version,
        key_id: package.key_id,
        package_sha256: package.package_sha256,
        trust_store_sha256: checked.trust_store_sha256,
        matrix_sha256: checked.matrix_sha256,
        service_count: checked.matrix_report.service_count,
        method_count: checked.matrix_report.method_count,
        case_count: checked.matrix_report.case_count,
        enabled_case_count: checked.matrix_report.enabled_case_count,
        package_verified: true,
        matrix_verified: true,
    })
}

pub fn check_release_set(
    spec: &Path,
    trust_store: &Path,
    matrix: &Path,
) -> Result<ReleaseSetCheckReport, ToolError> {
    let spec = canonical_real_file(spec, MAX_RELEASE_SET_SPEC_BYTES)?;
    let spec_sha256 = sha256_file_bounded(&spec, MAX_RELEASE_SET_SPEC_BYTES)?;
    let document: ReleaseSetSpec = read_bounded_json(&spec, MAX_RELEASE_SET_SPEC_BYTES)?;
    if document.schema_version != 1
        || document.packages.is_empty()
        || document.packages.len() > MAX_MATRIX_PLUGINS
    {
        return Err(ToolError::Invalid(format!(
            "release set spec must use schema 1 and contain 1 to {MAX_MATRIX_PLUGINS} packages"
        )));
    }
    let parent = spec
        .parent()
        .ok_or_else(|| ToolError::Invalid("release set spec has no parent directory".into()))?;
    let package_paths = document
        .packages
        .into_iter()
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                parent.join(path)
            }
        })
        .collect::<Vec<_>>();
    let checked = check_release_packages(&package_paths, trust_store, matrix)?;
    if spec_sha256 != sha256_file_bounded(&spec, MAX_RELEASE_SET_SPEC_BYTES)? {
        return Err(ToolError::Invalid(
            "release set spec changed while it was checked".into(),
        ));
    }
    Ok(ReleaseSetCheckReport {
        schema_version: 1,
        spec_sha256,
        package_set_sha256: checked.package_set_sha256,
        trust_store_sha256: checked.trust_store_sha256,
        matrix_sha256: checked.matrix_sha256,
        plugin_count: checked.matrix_report.plugin_count,
        service_count: checked.matrix_report.service_count,
        method_count: checked.matrix_report.method_count,
        case_count: checked.matrix_report.case_count,
        enabled_case_count: checked.matrix_report.enabled_case_count,
        packages: checked.packages,
        packages_verified: true,
        matrix_verified: true,
    })
}

pub fn check_release_root_against_set(
    plugin_root: &Path,
    spec: &Path,
    trust_store: &Path,
    matrix: &Path,
) -> Result<ReleaseSetCheckReport, ToolError> {
    let release_set = check_release_set(spec, trust_store, matrix)?;
    let manifests = discover_clean_plugin_root(plugin_root)?;
    let trust = TrustStore::load(trust_store)?;
    for manifest in &manifests {
        trust.verify_for_issuance(manifest)?;
    }
    let (_, coverage) = validate_executable_matrix(matrix, &manifests)?;
    if coverage.plugin_count != release_set.plugin_count
        || coverage.service_count != release_set.service_count
        || coverage.method_count != release_set.method_count
        || coverage.enabled_case_count != release_set.enabled_case_count
    {
        return Err(ToolError::Invalid(
            "tested plugin root coverage does not match the release set".into(),
        ));
    }
    verify_release_packages_match_manifests(&release_set, &manifests, &trust)?;
    Ok(release_set)
}

fn verify_release_packages_match_manifests(
    release_set: &ReleaseSetCheckReport,
    manifests: &[PluginManifest],
    trust_store: &TrustStore,
) -> Result<(), ToolError> {
    if release_set.packages.len() != manifests.len() {
        return Err(ToolError::Invalid(
            "release set package count does not match the tested plugin root".into(),
        ));
    }
    let packages = release_set
        .packages
        .iter()
        .map(|package| (package.plugin_id.as_str(), package))
        .collect::<BTreeMap<_, _>>();
    if packages.len() != manifests.len() {
        return Err(ToolError::Invalid(
            "release set contains duplicate plugin identities".into(),
        ));
    }
    let rebuilt = tempfile::tempdir().map_err(|source| ToolError::Io {
        path: std::env::temp_dir(),
        source,
    })?;
    for manifest in manifests {
        let metadata = manifest.metadata.as_ref().ok_or_else(|| {
            ToolError::Invalid(
                "tested plugin root contains a plugin without version metadata".into(),
            )
        })?;
        let expected = packages.get(manifest.plugin_id.as_str()).ok_or_else(|| {
            ToolError::Invalid("tested plugin root is not the approved release set".into())
        })?;
        if expected.version != metadata.version.to_string() {
            return Err(ToolError::Invalid(
                "tested plugin version is not the approved release set version".into(),
            ));
        }
        let package_path = rebuilt
            .path()
            .join(format!("{}.ssdev-plugin", manifest.plugin_id));
        let identity =
            create_deterministic_package(&manifest.plugin_dir, &package_path, trust_store)?;
        if identity.key_id != expected.key_id
            || sha256_file(&package_path)? != expected.package_sha256
        {
            return Err(ToolError::Invalid(
                "tested plugin bytes do not match the approved release package".into(),
            ));
        }
    }
    Ok(())
}

fn check_release_packages(
    packages: &[PathBuf],
    trust_store: &Path,
    matrix: &Path,
) -> Result<CheckedReleasePackages, ToolError> {
    if packages.is_empty() || packages.len() > MAX_MATRIX_PLUGINS {
        return Err(ToolError::Invalid(format!(
            "release candidate must contain 1 to {MAX_MATRIX_PLUGINS} packages"
        )));
    }
    let mut package_paths = HashSet::new();
    let mut package_inputs = Vec::with_capacity(packages.len());
    for package in packages {
        let package = canonical_real_file(package, MAX_PLUGIN_BYTES)?;
        if package.extension().and_then(|value| value.to_str()) != Some("ssdev-plugin") {
            return Err(ToolError::Invalid(
                "release candidate packages must use the .ssdev-plugin extension".into(),
            ));
        }
        if !package_paths.insert(package.clone()) {
            return Err(ToolError::Invalid(
                "release candidate contains the same package path more than once".into(),
            ));
        }
        let digest = sha256_file(&package)?;
        package_inputs.push((package, digest));
    }

    let trust_store_sha256 = sha256_file_bounded(trust_store, MAX_TRUST_STORE_BYTES)?;
    let matrix_sha256 = sha256_file_bounded(matrix, MAX_MATRIX_BYTES)?;
    let trust = TrustStore::load(trust_store)?;
    let verification_root = tempfile::tempdir().map_err(|source| ToolError::Io {
        path: std::env::temp_dir(),
        source,
    })?;
    let mut prepared = Vec::with_capacity(package_inputs.len());
    for (package, _) in &package_inputs {
        let candidate = PreparedPlugin::prepare(package, verification_root.path(), &trust)?;
        trust.verify_for_issuance(candidate.manifest())?;
        prepared.push(candidate);
    }
    let manifests = prepared
        .iter()
        .map(|candidate| candidate.manifest().clone())
        .collect::<Vec<_>>();
    let (_, matrix_report) = validate_executable_matrix(matrix, &manifests)?;
    if !matrix_report.identity_bound {
        return Err(ToolError::Invalid(
            "release candidate matrix must bind the exact plugin IDs and versions".into(),
        ));
    }

    for (package, digest) in &package_inputs {
        if digest != &sha256_file(package)? {
            return Err(ToolError::Invalid(
                "release candidate package changed while it was checked".into(),
            ));
        }
    }
    if trust_store_sha256 != sha256_file_bounded(trust_store, MAX_TRUST_STORE_BYTES)?
        || matrix_sha256 != sha256_file_bounded(matrix, MAX_MATRIX_BYTES)?
    {
        return Err(ToolError::Invalid(
            "release candidate trust store or matrix changed while it was checked".into(),
        ));
    }

    let mut package_reports = prepared
        .iter()
        .zip(&package_inputs)
        .map(|(candidate, (_, package_sha256))| ReleasePackageReport {
            plugin_id: candidate.identity().plugin_id.clone(),
            version: candidate.metadata().version.to_string(),
            key_id: candidate.identity().key_id.clone(),
            package_sha256: package_sha256.clone(),
        })
        .collect::<Vec<_>>();
    package_reports.sort_by(|left, right| {
        left.plugin_id
            .to_ascii_lowercase()
            .cmp(&right.plugin_id.to_ascii_lowercase())
            .then_with(|| left.version.cmp(&right.version))
    });
    let package_bytes = serde_json::to_vec(&package_reports)?;
    let mut package_set_payload = b"SSDEV-PLUGIN-RELEASE-SET\0".to_vec();
    package_set_payload.extend_from_slice(&package_bytes);
    Ok(CheckedReleasePackages {
        packages: package_reports,
        package_set_sha256: sha256_hex(&package_set_payload),
        trust_store_sha256,
        matrix_sha256,
        matrix_report,
    })
}

pub fn create_catalog(options: &CatalogOptions<'_>) -> Result<CatalogReport, ToolError> {
    ensure_fresh_output(options.catalog, "plugin catalog")?;
    let spec: CatalogSpec = read_bounded_json(options.spec, MAX_CATALOG_SPEC_BYTES)?;
    if spec.schema_version != 1 {
        return Err(ToolError::Invalid(format!(
            "unsupported catalog build spec schema [{}]",
            spec.schema_version
        )));
    }
    if spec.packages.len() > MAX_CATALOG_PACKAGES {
        return Err(ToolError::Invalid(format!(
            "catalog build spec contains more than {MAX_CATALOG_PACKAGES} packages"
        )));
    }
    let spec_parent = canonical_real_directory(output_parent(options.spec))?;
    let trust_store = TrustStore::load(options.trust_store)?;
    let verification_root = tempfile::tempdir().map_err(|source| ToolError::Io {
        path: std::env::temp_dir(),
        source,
    })?;
    let mut package_paths = HashSet::new();
    let mut package_urls = HashSet::new();
    let mut entries = Vec::with_capacity(spec.packages.len());
    for package_spec in spec.packages {
        let package_path = if package_spec.package.is_absolute() {
            package_spec.package
        } else {
            spec_parent.join(package_spec.package)
        };
        let metadata = fs::symlink_metadata(&package_path).map_err(|source| ToolError::Io {
            path: package_path.clone(),
            source,
        })?;
        if !metadata.file_type().is_file() {
            return Err(ToolError::Invalid(
                "catalog package inputs must be regular files, not links".into(),
            ));
        }
        let package_path = package_path
            .canonicalize()
            .map_err(|source| ToolError::Io {
                path: package_path.clone(),
                source,
            })?;
        if !package_paths.insert(package_path.clone()) {
            return Err(ToolError::Invalid(
                "catalog build spec contains a duplicate package path".into(),
            ));
        }
        if !package_urls.insert(package_spec.url.as_str().to_owned()) {
            return Err(ToolError::Invalid(
                "catalog build spec contains a duplicate package URL".into(),
            ));
        }
        let size_before = metadata.len();
        let digest_before = sha256_file(&package_path)?;
        let prepared =
            PreparedPlugin::prepare(&package_path, verification_root.path(), &trust_store)?;
        let identity = prepared.identity().clone();
        let version = prepared.metadata().version.clone();
        drop(prepared);
        let metadata_after =
            fs::symlink_metadata(&package_path).map_err(|source| ToolError::Io {
                path: package_path.clone(),
                source,
            })?;
        let digest_after = sha256_file(&package_path)?;
        if !metadata_after.file_type().is_file()
            || metadata_after.len() != size_before
            || digest_after != digest_before
        {
            return Err(ToolError::Invalid(
                "plugin package changed while the catalog was being created".into(),
            ));
        }
        entries.push(CatalogEntry {
            plugin_id: identity.plugin_id,
            version,
            url: package_spec.url,
            sha256: digest_before,
            size: size_before,
        });
    }
    let bytes = encode_catalog_document(spec.issued_at, spec.expires_at, entries, options.now)?;
    let catalog_sha256 = sha256_hex(&bytes);
    write_new_bytes(options.catalog, &bytes)?;
    Ok(CatalogReport {
        schema_version: 1,
        issued_at: spec.issued_at,
        expires_at: spec.expires_at,
        package_count: package_urls.len(),
        catalog_sha256,
    })
}

#[derive(Default)]
struct CopyReport {
    legacy_license_excluded: bool,
    files: usize,
    bytes: u64,
    portable_paths: HashSet<String>,
}

fn copy_legacy_plugin(source: &Path, destination: &Path) -> Result<CopyReport, ToolError> {
    let mut report = CopyReport::default();
    copy_directory(source, source, destination, &mut report)?;
    Ok(report)
}

fn copy_directory(
    root: &Path,
    directory: &Path,
    destination: &Path,
    report: &mut CopyReport,
) -> Result<(), ToolError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|source| ToolError::Io {
            path: directory.to_path_buf(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| ToolError::Io {
            path: directory.to_path_buf(),
            source,
        })?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let file_type = entry.file_type().map_err(|source| ToolError::Io {
            path: entry.path(),
            source,
        })?;
        if file_type.is_symlink() {
            return Err(ToolError::Invalid(
                "legacy plugin contains a symbolic link".into(),
            ));
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| {
                ToolError::Invalid("legacy plugin entry escaped its source directory".into())
            })?
            .to_path_buf();
        let portable = portable_plugin_path(&relative)?;
        let normalized = portable.to_ascii_lowercase();
        if !report.portable_paths.insert(normalized) {
            return Err(ToolError::Invalid(format!(
                "legacy plugin contains a case-insensitive duplicate path: {portable}"
            )));
        }
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if name == LEGACY_LICENSE_FILENAME {
            report.legacy_license_excluded = true;
            continue;
        }
        if relative.components().count() == 1
            && (name == PLUGIN_METADATA_FILENAME || name == SIGNATURE_FILENAME)
        {
            continue;
        }
        let target = destination.join(&relative);
        if file_type.is_dir() {
            fs::create_dir(&target).map_err(|source| ToolError::Io {
                path: target.clone(),
                source,
            })?;
            copy_directory(root, &entry.path(), destination, report)?;
        } else if file_type.is_file() {
            let length = entry
                .metadata()
                .map_err(|source| ToolError::Io {
                    path: entry.path(),
                    source,
                })?
                .len();
            report.files += 1;
            report.bytes = report.bytes.saturating_add(length);
            if report.files > MAX_PLUGIN_FILES || report.bytes > MAX_PLUGIN_BYTES {
                return Err(ToolError::Invalid(
                    "legacy plugin exceeds the file-count or byte limit".into(),
                ));
            }
            fs::copy(entry.path(), &target).map_err(|source| ToolError::Io {
                path: target,
                source,
            })?;
        } else {
            return Err(ToolError::Invalid(
                "legacy plugin may contain only regular files and directories".into(),
            ));
        }
    }
    Ok(())
}

fn validate_release_manifest(manifest: &PluginManifest) -> Result<(), ToolError> {
    let method_count = manifest
        .services
        .iter()
        .map(|service| service.methods.len())
        .sum::<usize>();
    if method_count > MAX_MATRIX_CASES {
        return Err(ToolError::Invalid(format!(
            "plugin defines {method_count} methods; one release matrix supports at most {MAX_MATRIX_CASES}"
        )));
    }
    for service in &manifest.services {
        if service
            .extensions
            .get("installRun")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Err(ToolError::Invalid(format!(
                "service [{}] still declares legacy installRun",
                service.service_id
            )));
        }
        if service.methods.is_empty() {
            return Err(ToolError::Invalid(format!(
                "service [{}] has no callable methods",
                service.service_id
            )));
        }
        let main_type = service.resolved_main_type().to_ascii_lowercase();
        if matches!(main_type.as_str(), "dll" | "exe" | "bat") {
            let component =
                resolve_component(&manifest.plugin_dir, &service.main_class, &main_type)?;
            if matches!(main_type.as_str(), "dll" | "exe") {
                let actual = detect_pe_architecture(&component)?.ok_or_else(|| {
                    ToolError::Invalid(format!(
                        "service [{}] entry is not a supported PE file",
                        service.service_id
                    ))
                })?;
                if actual != service.architecture {
                    return Err(ToolError::Invalid(format!(
                        "service [{}] declares {:?} but its PE entry is {:?}",
                        service.service_id, service.architecture, actual
                    )));
                }
            }
        }
        for dependency in &service.deps {
            if dependency != "*" && !manifest.plugin_dir.join(dependency).is_file() {
                return Err(ToolError::Invalid(format!(
                    "service [{}] dependency is missing: {dependency}",
                    service.service_id
                )));
            }
        }
    }
    Ok(())
}

fn resolve_component(root: &Path, main_class: &str, extension: &str) -> Result<PathBuf, ToolError> {
    let direct = root.join(main_class);
    let candidate = if direct.is_file()
        || main_class
            .to_ascii_lowercase()
            .ends_with(&format!(".{extension}"))
    {
        direct
    } else {
        root.join(format!("{main_class}.{extension}"))
    };
    if !candidate.is_file() {
        return Err(ToolError::Invalid(format!(
            "native component is missing: {main_class}"
        )));
    }
    let root = root.canonicalize().map_err(|source| ToolError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    let component = candidate.canonicalize().map_err(|source| ToolError::Io {
        path: candidate,
        source,
    })?;
    if !component.starts_with(root) {
        return Err(ToolError::Invalid(
            "native component escaped the plugin directory".into(),
        ));
    }
    Ok(component)
}

fn detect_pe_architecture(path: &Path) -> Result<Option<PluginArchitecture>, ToolError> {
    let mut file = File::open(path).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut dos = [0_u8; 64];
    file.read_exact(&mut dos).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if &dos[0..2] != b"MZ" {
        return Ok(None);
    }
    let offset = u32::from_le_bytes(dos[0x3c..0x40].try_into().expect("fixed slice")) as u64;
    let length = file
        .metadata()
        .map_err(|source| ToolError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    if offset > length.saturating_sub(6) {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| ToolError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let mut header = [0_u8; 6];
    file.read_exact(&mut header)
        .map_err(|source| ToolError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if &header[0..4] != b"PE\0\0" {
        return Ok(None);
    }
    Ok(match u16::from_le_bytes([header[4], header[5]]) {
        0x014c => Some(PluginArchitecture::X86),
        0x8664 => Some(PluginArchitecture::X64),
        _ => None,
    })
}

fn draft_matrix(manifest: &PluginManifest) -> Result<PluginMatrix, ToolError> {
    let cases = manifest
        .services
        .iter()
        .flat_map(|service| {
            service.methods.iter().map(move |method| {
                let mut parameters = Map::new();
                for parameter in method
                    .parameters
                    .iter()
                    .filter(|parameter| !parameter.name().starts_with('$'))
                {
                    parameters.insert(
                        parameter.name().trim_start_matches('$').to_owned(),
                        Value::String(DRAFT_INPUT_PLACEHOLDER.into()),
                    );
                }
                PluginMatrixCase {
                    name: format!("{}.{}", service.service_id, method.name),
                    enabled: true,
                    review_required: true,
                    request: InvokeRequest {
                        service_id: service.service_id.clone(),
                        method: method.name.clone(),
                        parameters,
                    },
                    expected: InvokeResponse::success(DRAFT_RESPONSE_PLACEHOLDER),
                }
            })
        })
        .collect::<Vec<_>>();
    Ok(PluginMatrix {
        schema_version: 1,
        draft: true,
        plugins: vec![matrix_target(manifest)?],
        cases,
    })
}

fn matrix_case_has_draft_placeholder(case: &PluginMatrixCase) -> bool {
    case.request
        .parameters
        .values()
        .any(contains_draft_placeholder)
        || contains_draft_placeholder(&case.expected.res_data)
}

fn load_matrix_seed(path: &Path, manifest: &PluginManifest) -> Result<PluginMatrix, ToolError> {
    let mut matrix: PluginMatrix = read_bounded_json(path, MAX_MATRIX_BYTES)?;
    if matrix.schema_version != 1 || !matrix.draft {
        return Err(ToolError::Invalid(
            "matrix seed must use schema 1 and remain draft=true".into(),
        ));
    }
    if matrix.cases.is_empty() || matrix.cases.len() > MAX_MATRIX_CASES {
        return Err(ToolError::Invalid(format!(
            "matrix seed must contain 1 to {MAX_MATRIX_CASES} cases"
        )));
    }
    let required = manifest
        .services
        .iter()
        .flat_map(|service| {
            service
                .methods
                .iter()
                .map(move |method| (service.service_id.clone(), method.name.clone()))
        })
        .collect::<BTreeSet<_>>();
    let mut covered = BTreeSet::new();
    let mut names = BTreeSet::new();
    for case in &matrix.cases {
        if case.name.trim() != case.name
            || case.name.is_empty()
            || case.name.chars().count() > 256
            || case.name.chars().any(char::is_control)
            || !names.insert(case.name.as_str())
        {
            return Err(ToolError::Invalid(
                "matrix seed case names must be unique, trimmed, and at most 256 safe characters"
                    .into(),
            ));
        }
        case.request.validate().map_err(|error| {
            ToolError::Invalid(format!("matrix seed request is invalid: {error}"))
        })?;
        let service = manifest
            .services
            .iter()
            .find(|service| service.service_id == case.request.service_id)
            .ok_or_else(|| {
                ToolError::Invalid(format!(
                    "matrix seed case [{}] targets an unknown service",
                    case.name
                ))
            })?;
        let method = service.method(&case.request.method).ok_or_else(|| {
            ToolError::Invalid(format!(
                "matrix seed case [{}] targets an unknown method",
                case.name
            ))
        })?;
        let allowed_parameters = method
            .parameters
            .iter()
            .map(|parameter| parameter.name())
            .filter(|name| !name.starts_with('$'))
            .collect::<HashSet<_>>();
        if let Some(unexpected) = case
            .request
            .parameters
            .keys()
            .find(|name| !allowed_parameters.contains(name.as_str()))
        {
            return Err(ToolError::Invalid(format!(
                "matrix seed case [{}] contains undeclared input parameter [{unexpected}]",
                case.name
            )));
        }
        if let Some(missing) = allowed_parameters
            .iter()
            .find(|name| !case.request.parameters.contains_key(**name))
        {
            return Err(ToolError::Invalid(format!(
                "matrix seed case [{}] is missing declared input parameter [{missing}]",
                case.name
            )));
        }
        if case.enabled {
            covered.insert((service.service_id.clone(), method.name.clone()));
        }
    }
    if covered != required {
        return Err(ToolError::Invalid(format!(
            "enabled matrix seed cases do not cover {} declared method(s)",
            required.difference(&covered).count()
        )));
    }
    validate_matrix_targets(&matrix.plugins, std::slice::from_ref(manifest))?;
    matrix.plugins = vec![matrix_target(manifest)?];
    Ok(matrix)
}

pub fn check_executable_matrix_root(
    plugin_root: &Path,
    matrix_path: &Path,
) -> Result<MatrixCheckReport, ToolError> {
    let manifests = discover_clean_plugin_root(plugin_root)?;
    let (_, report) = validate_executable_matrix(matrix_path, &manifests)?;
    Ok(report)
}

fn discover_clean_plugin_root(plugin_root: &Path) -> Result<Vec<PluginManifest>, ToolError> {
    let plugin_root = canonical_real_directory(plugin_root)?;
    let discovery = discover_plugins(&plugin_root)?;
    if !discovery.failures.is_empty() {
        let first = &discovery.failures[0];
        return Err(ToolError::Invalid(format!(
            "plugin root contains {} invalid plugin director{}; first failure [{}]: {}",
            discovery.failures.len(),
            if discovery.failures.len() == 1 {
                "y"
            } else {
                "ies"
            },
            first.plugin_id,
            first.error
        )));
    }
    Ok(discovery.manifests)
}

pub fn check_executable_matrix_plugin(
    plugin_dir: &Path,
    matrix_path: &Path,
) -> Result<MatrixCheckReport, ToolError> {
    let plugin_dir = canonical_real_directory(plugin_dir)?;
    let metadata = PluginMetadata::load_optional(&plugin_dir)?.ok_or_else(|| {
        ToolError::Invalid("plugin directory must contain normalized plugin.json".into())
    })?;
    let manifest = PluginManifest::load(metadata.plugin_id, &plugin_dir)?;
    let (_, report) = validate_executable_matrix(matrix_path, &[manifest])?;
    Ok(report)
}

fn matrix_target(manifest: &PluginManifest) -> Result<PluginMatrixTarget, ToolError> {
    let metadata = manifest.metadata.as_ref().ok_or_else(|| {
        ToolError::Invalid("matrix identity binding requires normalized plugin.json".into())
    })?;
    Ok(PluginMatrixTarget {
        plugin_id: metadata.plugin_id.clone(),
        version: metadata.version.to_string(),
    })
}

fn validate_matrix_targets(
    targets: &[PluginMatrixTarget],
    manifests: &[PluginManifest],
) -> Result<bool, ToolError> {
    if targets.is_empty() {
        return Ok(false);
    }
    if targets.len() > MAX_MATRIX_PLUGINS {
        return Err(ToolError::Invalid(format!(
            "matrix identity binding contains more than {MAX_MATRIX_PLUGINS} plugins"
        )));
    }

    let mut expected = BTreeMap::new();
    for manifest in manifests {
        let target = matrix_target(manifest)?;
        expected.insert(
            target.plugin_id.to_ascii_lowercase(),
            (target.plugin_id, target.version),
        );
    }
    let mut actual = BTreeMap::new();
    for target in targets {
        let path = Path::new(&target.plugin_id);
        let version = Version::parse(&target.version).map_err(|error| {
            ToolError::Invalid(format!(
                "matrix plugin target version is not SemVer: {error}"
            ))
        })?;
        if target.plugin_id.trim() != target.plugin_id
            || path.components().count() != 1
            || portable_plugin_path(path)? != target.plugin_id
            || version.to_string() != target.version
        {
            return Err(ToolError::Invalid(
                "matrix plugin targets must use canonical portable IDs and SemVer versions".into(),
            ));
        }
        if actual
            .insert(
                target.plugin_id.to_ascii_lowercase(),
                (target.plugin_id.clone(), target.version.clone()),
            )
            .is_some()
        {
            return Err(ToolError::Invalid(
                "matrix identity binding contains a duplicate portable plugin ID".into(),
            ));
        }
    }
    if actual != expected {
        return Err(ToolError::Invalid(
            "matrix plugin identities or versions do not exactly match the checked plugins".into(),
        ));
    }
    Ok(true)
}

pub fn validate_executable_matrix(
    matrix_path: &Path,
    manifests: &[PluginManifest],
) -> Result<(PluginMatrix, MatrixCheckReport), ToolError> {
    let matrix: PluginMatrix = read_bounded_json(matrix_path, MAX_MATRIX_BYTES)?;
    if matrix.schema_version != 1
        || matrix.cases.is_empty()
        || matrix.cases.len() > MAX_MATRIX_CASES
    {
        return Err(ToolError::Invalid(format!(
            "executable matrix must use schema 1 and contain 1 to {MAX_MATRIX_CASES} cases"
        )));
    }
    if matrix.draft {
        return Err(ToolError::Invalid(
            "executable matrix is still marked as draft".into(),
        ));
    }
    let mut services = BTreeMap::new();
    let mut required = BTreeSet::new();
    let mut plugin_ids = BTreeSet::new();
    for manifest in manifests {
        if !plugin_ids.insert(manifest.plugin_id.to_ascii_lowercase()) {
            return Err(ToolError::Invalid(format!(
                "verified plugin manifests contain duplicate portable plugin ID [{}]",
                manifest.plugin_id
            )));
        }
        for service in &manifest.services {
            if services
                .insert(service.service_id.as_str(), service)
                .is_some()
            {
                return Err(ToolError::Invalid(format!(
                    "verified plugin manifests declare duplicate serviceId [{}]",
                    service.service_id
                )));
            }
            for method in &service.methods {
                required.insert((service.service_id.as_str(), method.name.as_str()));
            }
        }
    }
    if required.is_empty() {
        return Err(ToolError::Invalid(
            "verified plugin manifests do not declare callable methods".into(),
        ));
    }
    let identity_bound = validate_matrix_targets(&matrix.plugins, manifests)?;

    let mut names = BTreeSet::new();
    let mut covered = BTreeSet::new();
    let mut enabled_case_count = 0_usize;
    for case in &matrix.cases {
        if case.name.trim() != case.name
            || case.name.is_empty()
            || case.name.chars().count() > 256
            || case.name.chars().any(char::is_control)
            || !names.insert(case.name.as_str())
        {
            return Err(ToolError::Invalid(
                "matrix case names must be unique, trimmed, and at most 256 safe characters".into(),
            ));
        }
        case.request.validate().map_err(|error| {
            ToolError::Invalid(format!(
                "matrix case [{}] contains an invalid invoke request: {error}",
                case.name
            ))
        })?;
        let service = services
            .get(case.request.service_id.as_str())
            .copied()
            .ok_or_else(|| {
                ToolError::Invalid(format!(
                    "matrix case [{}] targets an unknown service",
                    case.name
                ))
            })?;
        let method = service.method(&case.request.method).ok_or_else(|| {
            ToolError::Invalid(format!(
                "matrix case [{}] targets an unknown method",
                case.name
            ))
        })?;
        let declared_inputs = method
            .parameters
            .iter()
            .map(|parameter| parameter.name())
            .filter(|name| !name.starts_with('$'))
            .collect::<BTreeSet<_>>();
        let provided_inputs = case
            .request
            .parameters
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if provided_inputs != declared_inputs {
            return Err(ToolError::Invalid(format!(
                "matrix case [{}] inputs do not exactly match the declared method inputs",
                case.name
            )));
        }
        if !case.enabled {
            continue;
        }
        enabled_case_count = enabled_case_count.saturating_add(1);
        if case.review_required {
            return Err(ToolError::Invalid(format!(
                "matrix case [{}] still requires exact response review",
                case.name
            )));
        }
        if matrix_case_has_draft_placeholder(case) {
            return Err(ToolError::Invalid(format!(
                "matrix case [{}] still contains a generated draft placeholder",
                case.name
            )));
        }
        covered.insert((service.service_id.as_str(), method.name.as_str()));
    }
    if enabled_case_count == 0 {
        return Err(ToolError::Invalid(
            "executable matrix must contain at least one enabled case".into(),
        ));
    }
    if covered != required {
        return Err(ToolError::Invalid(format!(
            "enabled matrix cases do not cover {} declared method(s)",
            required.difference(&covered).count()
        )));
    }

    let report = MatrixCheckReport {
        schema_version: 1,
        plugin_count: manifests.len(),
        service_count: services.len(),
        method_count: required.len(),
        case_count: matrix.cases.len(),
        enabled_case_count,
        identity_bound,
    };
    Ok((matrix, report))
}

fn write_external_outputs(
    request_path: &Path,
    request: &SigningRequest,
    matrix_path: &Path,
    matrix: &PluginMatrix,
) -> Result<(), ToolError> {
    write_new_json(request_path, request)?;
    if let Err(error) = write_new_json(matrix_path, matrix) {
        let _ = fs::remove_file(request_path);
        return Err(error);
    }
    Ok(())
}

fn write_new_json(path: impl AsRef<Path>, value: &impl Serialize) -> Result<(), ToolError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_new_bytes(path.as_ref(), &bytes)
}

fn write_new_bytes(path: &Path, bytes: &[u8]) -> Result<(), ToolError> {
    let parent = output_parent(path);
    let mut temporary = TempBuilder::new()
        .prefix(".ssdev-write-")
        .tempfile_in(parent)
        .map_err(|source| ToolError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    temporary
        .write_all(bytes)
        .and_then(|_| temporary.flush())
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|source| ToolError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| ToolError::Io {
            path: path.to_path_buf(),
            source: error.error,
        })?;
    Ok(())
}

fn read_bounded_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    limit: u64,
) -> Result<T, ToolError> {
    let bytes = read_bounded_file(path, limit)?;
    serde_json::from_slice(&bytes).map_err(ToolError::from)
}

fn read_signature(path: &Path) -> Result<String, ToolError> {
    let bytes = read_bounded_file(path, MAX_SIGNATURE_BYTES)?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| ToolError::Invalid("signature file must contain UTF-8 base64".into()))?
        .trim();
    if value.is_empty() || value.lines().count() != 1 {
        return Err(ToolError::Invalid(
            "signature file must contain exactly one base64 value".into(),
        ));
    }
    Ok(value.to_owned())
}

fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>, ToolError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() || metadata.len() > limit {
        return Err(ToolError::Invalid(format!(
            "input must be a regular file no larger than {limit} bytes"
        )));
    }
    fs::read(path).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn canonical_real_directory(path: &Path) -> Result<PathBuf, ToolError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_dir() {
        return Err(ToolError::Invalid("input must be a real directory".into()));
    }
    path.canonicalize().map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn canonical_real_file(path: &Path, limit: u64) -> Result<PathBuf, ToolError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() || metadata.len() > limit {
        return Err(ToolError::Invalid(format!(
            "input must be a real file no larger than {limit} bytes"
        )));
    }
    path.canonicalize().map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn normalized_new_path(path: &Path) -> Result<PathBuf, ToolError> {
    let parent = output_parent(path);
    let metadata = fs::symlink_metadata(parent).map_err(|source| ToolError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_dir() {
        return Err(ToolError::Invalid(
            "output parent must be an existing real directory".into(),
        ));
    }
    let parent = parent.canonicalize().map_err(|source| ToolError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    let name = path.file_name().ok_or_else(|| {
        ToolError::Invalid("output path must have a file or directory name".into())
    })?;
    Ok(parent.join(name))
}

fn ensure_fresh_output(path: &Path, role: &str) -> Result<(), ToolError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(ToolError::Invalid(format!("{role} already exists"))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ToolError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest_hex(Sha256::digest(bytes))
}

fn sha256_file(path: &Path) -> Result<String, ToolError> {
    sha256_file_bounded(path, MAX_PLUGIN_BYTES)
}

fn sha256_file_bounded(path: &Path, limit: u64) -> Result<String, ToolError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() || metadata.len() > limit {
        return Err(ToolError::Invalid(format!(
            "digest input must be a regular file no larger than {limit} bytes"
        )));
    }
    let mut file = File::open(path).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer).map_err(|source| ToolError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if total > limit {
            return Err(ToolError::Invalid(format!(
                "digest input exceeds {limit} bytes while being read"
            )));
        }
        hasher.update(&buffer[..count]);
    }
    Ok(digest_hex(hasher.finalize()))
}

fn digest_hex(digest: impl AsRef<[u8]>) -> String {
    let digest = digest.as_ref();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("invalid plugin release input: {0}")]
    Invalid(String),
    #[error("filesystem operation failed at {path:?}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("JSON encoding or decoding failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("plugin manifest is invalid: {0}")]
    Manifest(#[from] webplus_plugin_config::ConfigError),
    #[error("plugin signature is invalid: {0}")]
    Trust(#[from] webplus_plugin_trust::TrustError),
    #[error("plugin package is invalid: {0}")]
    Package(#[from] webplus_plugin_package::PackageError),
    #[error("plugin catalog is invalid: {0}")]
    Catalog(#[from] webplus_plugin_repository::RepositoryError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use std::time::{Duration, UNIX_EPOCH};

    fn pe(machine: u16) -> Vec<u8> {
        let mut bytes = vec![0_u8; 128];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&64_u32.to_le_bytes());
        bytes[64..68].copy_from_slice(b"PE\0\0");
        bytes[68..70].copy_from_slice(&machine.to_le_bytes());
        bytes
    }

    fn source(root: &Path) -> PathBuf {
        let source = root.join("legacy");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("api.json"),
            r#"{"serviceId":"reader","mainClass":"reader.dll","architecture":"x86","methods":[{"name":"read","parameters":["timeout"]}]}"#,
        )
        .unwrap();
        fs::write(source.join("reader.dll"), pe(0x014c)).unwrap();
        fs::write(source.join("license.dat"), b"legacy private-key envelope").unwrap();
        source
    }

    fn trust_store(root: &Path, signing_key: &SigningKey, status: Option<&str>) -> PathBuf {
        let path = root.join("trust.json");
        let mut key = json!({
            "keyId": "test-key",
            "algorithm": "ed25519",
            "publicKey": BASE64.encode(signing_key.verifying_key().to_bytes()),
            "purposes": ["plugin"]
        });
        if let Some(status) = status {
            key["status"] = Value::String(status.to_owned());
        }
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "schemaVersion": 2,
                "keys": [key]
            }))
            .unwrap(),
        )
        .unwrap();
        path
    }

    fn signed_package(
        root: &Path,
        source: &Path,
        prefix: &str,
        plugin_id: &str,
        version: &str,
        trust_store: &Path,
        signing_key: &SigningKey,
    ) -> PathBuf {
        let staging = root.join(format!("{prefix}-stage"));
        let request = root.join(format!("{prefix}-request.json"));
        let matrix = root.join(format!("{prefix}-draft-matrix.json"));
        prepare(&PrepareOptions {
            source,
            staging: &staging,
            request: &request,
            matrix_template: &matrix,
            plugin_id,
            version,
            display_name: plugin_id,
            key_id: "test-key",
            trust_store,
            matrix_seed: None,
        })
        .unwrap();
        let signing_request: SigningRequest =
            serde_json::from_slice(&fs::read(&request).unwrap()).unwrap();
        let payload = BASE64.decode(signing_request.payload_base64).unwrap();
        let signature = root.join(format!("{prefix}-signature.txt"));
        fs::write(
            &signature,
            BASE64.encode(signing_key.sign(&payload).to_bytes()),
        )
        .unwrap();
        let package = root.join(format!("{prefix}.ssdev-plugin"));
        finalize(&FinalizeOptions {
            staging: &staging,
            request: &request,
            signature: &signature,
            trust_store,
            package: &package,
        })
        .unwrap();
        package
    }

    fn matrix_file(root: &Path, name: &str, value: Value) -> PathBuf {
        let path = root.join(name);
        fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        path
    }

    fn executable_matrix(case: Value) -> Value {
        json!({
            "schemaVersion": 1,
            "draft": false,
            "cases": [case]
        })
    }

    fn bound_executable_matrix(case: Value, plugin_id: &str, version: &str) -> Value {
        json!({
            "schemaVersion": 1,
            "draft": false,
            "plugins": [{
                "pluginId": plugin_id,
                "version": version
            }],
            "cases": [case]
        })
    }

    fn executable_case() -> Value {
        json!({
            "name": "reader.read verified",
            "reviewRequired": false,
            "request": {
                "serviceId": "reader",
                "method": "read",
                "parameters": { "timeout": 5 }
            },
            "expected": {
                "ResCode": 0,
                "ResData": { "ReturnValue": 0 }
            }
        })
    }

    #[test]
    fn executable_matrix_check_is_cross_platform_and_reports_exact_coverage() {
        let root = tempfile::tempdir().unwrap();
        let plugin_dir = source(root.path());
        let matrix = matrix_file(
            root.path(),
            "executable-matrix.json",
            executable_matrix(executable_case()),
        );
        let manifest = PluginManifest::load("reader", plugin_dir).unwrap();

        let (parsed, report) = validate_executable_matrix(&matrix, &[manifest]).unwrap();

        assert_eq!(parsed.cases.len(), 1);
        assert_eq!(report.plugin_count, 1);
        assert_eq!(report.service_count, 1);
        assert_eq!(report.method_count, 1);
        assert_eq!(report.case_count, 1);
        assert_eq!(report.enabled_case_count, 1);
        assert!(!report.identity_bound);
        assert_eq!(
            check_executable_matrix_root(root.path(), &matrix).unwrap(),
            report
        );

        let staging = root.path().join("arbitrary-release-staging-name");
        fs::create_dir(&staging).unwrap();
        fs::copy(
            root.path().join("legacy/api.json"),
            staging.join("api.json"),
        )
        .unwrap();
        fs::copy(
            root.path().join("legacy/reader.dll"),
            staging.join("reader.dll"),
        )
        .unwrap();
        fs::write(
            staging.join("plugin.json"),
            serde_json::to_vec(&json!({
                "schemaVersion": 1,
                "pluginId": "reader",
                "version": "1.0.0",
                "displayName": "Reader"
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            check_executable_matrix_plugin(&staging, &matrix).unwrap(),
            report
        );
    }

    #[test]
    fn executable_matrix_check_rejects_every_unfinished_hardware_gate() {
        let root = tempfile::tempdir().unwrap();
        let plugin_dir = source(root.path());
        let manifest = PluginManifest::load("reader", plugin_dir).unwrap();

        let mut draft = executable_matrix(executable_case());
        draft["draft"] = Value::Bool(true);
        let error = validate_executable_matrix(
            &matrix_file(root.path(), "draft.json", draft),
            std::slice::from_ref(&manifest),
        )
        .unwrap_err();
        assert!(error.to_string().contains("marked as draft"));

        let mut review = executable_case();
        review["reviewRequired"] = Value::Bool(true);
        let error = validate_executable_matrix(
            &matrix_file(root.path(), "review.json", executable_matrix(review)),
            std::slice::from_ref(&manifest),
        )
        .unwrap_err();
        assert!(error.to_string().contains("requires exact response review"));

        let mut placeholder = executable_case();
        placeholder["expected"]["ResData"] = Value::String(DRAFT_RESPONSE_PLACEHOLDER.into());
        let error = validate_executable_matrix(
            &matrix_file(
                root.path(),
                "placeholder.json",
                executable_matrix(placeholder),
            ),
            std::slice::from_ref(&manifest),
        )
        .unwrap_err();
        assert!(error.to_string().contains("draft placeholder"));

        let mut incomplete = executable_case();
        incomplete["request"]["parameters"] = json!({});
        let error = validate_executable_matrix(
            &matrix_file(
                root.path(),
                "incomplete.json",
                executable_matrix(incomplete),
            ),
            &[manifest],
        )
        .unwrap_err();
        assert!(error.to_string().contains("exactly match"));
    }

    #[test]
    fn executable_matrix_check_rejects_route_and_coverage_drift() {
        let root = tempfile::tempdir().unwrap();
        let plugin_dir = source(root.path());
        let mut manifest = PluginManifest::load("reader", plugin_dir).unwrap();

        let mut unknown = executable_case();
        unknown["request"]["method"] = Value::String("missing".into());
        let error = validate_executable_matrix(
            &matrix_file(root.path(), "unknown.json", executable_matrix(unknown)),
            std::slice::from_ref(&manifest),
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown method"));

        let mut reset = manifest.services[0].methods[0].clone();
        reset.name = "reset".into();
        reset.alias = None;
        reset.parameters.clear();
        manifest.services[0].methods.push(reset);
        let matrix = matrix_file(
            root.path(),
            "incomplete-coverage.json",
            executable_matrix(executable_case()),
        );
        let error =
            validate_executable_matrix(&matrix, std::slice::from_ref(&manifest)).unwrap_err();
        assert!(error.to_string().contains("do not cover 1"));

        let error =
            validate_executable_matrix(&matrix, &[manifest.clone(), manifest.clone()]).unwrap_err();
        assert!(error.to_string().contains("duplicate portable plugin ID"));

        let mut duplicate = manifest.clone();
        duplicate.plugin_id = "duplicate-reader".into();
        let error = validate_executable_matrix(&matrix, &[manifest, duplicate]).unwrap_err();
        assert!(error.to_string().contains("duplicate serviceId"));
    }

    #[test]
    fn release_set_check_verifies_every_bound_package_as_one_candidate() {
        let root = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[51; 32]);
        let trust = trust_store(root.path(), &signing_key, None);

        let reader_source = source(root.path());
        let reader_package = signed_package(
            root.path(),
            &reader_source,
            "reader",
            "reader-plugin",
            "1.2.3",
            &trust,
            &signing_key,
        );
        let printer_root = root.path().join("printer-source-root");
        fs::create_dir(&printer_root).unwrap();
        let printer_source = source(&printer_root);
        fs::write(
            printer_source.join("api.json"),
            r#"{"serviceId":"printer","mainClass":"reader.dll","architecture":"x86","methods":[{"name":"read","parameters":["timeout"]}]}"#,
        )
        .unwrap();
        let printer_package = signed_package(
            root.path(),
            &printer_source,
            "printer",
            "printer-plugin",
            "2.0.0",
            &trust,
            &signing_key,
        );

        let reader_case = executable_case();
        let mut printer_case = executable_case();
        printer_case["name"] = Value::String("printer.read verified".into());
        printer_case["request"]["serviceId"] = Value::String("printer".into());
        let matrix = matrix_file(
            root.path(),
            "release-set-matrix.json",
            json!({
                "schemaVersion": 1,
                "draft": false,
                "plugins": [
                    { "pluginId": "reader-plugin", "version": "1.2.3" },
                    { "pluginId": "printer-plugin", "version": "2.0.0" }
                ],
                "cases": [reader_case, printer_case]
            }),
        );
        let spec = matrix_file(
            root.path(),
            "release-set.json",
            json!({
                "schemaVersion": 1,
                "packages": [
                    reader_package.file_name().unwrap().to_string_lossy(),
                    printer_package.file_name().unwrap().to_string_lossy()
                ]
            }),
        );

        let report = check_release_set(&spec, &trust, &matrix).unwrap();
        assert_eq!(report.plugin_count, 2);
        assert_eq!(report.service_count, 2);
        assert_eq!(report.method_count, 2);
        assert_eq!(report.case_count, 2);
        assert_eq!(report.enabled_case_count, 2);
        assert_eq!(
            report
                .packages
                .iter()
                .map(|package| package.plugin_id.as_str())
                .collect::<Vec<_>>(),
            ["printer-plugin", "reader-plugin"]
        );
        assert_eq!(report.spec_sha256.len(), 64);
        assert_eq!(report.package_set_sha256.len(), 64);
        assert!(report.packages_verified);
        assert!(report.matrix_verified);

        let reversed_spec = matrix_file(
            root.path(),
            "reversed-release-set.json",
            json!({
                "schemaVersion": 1,
                "packages": [
                    printer_package.file_name().unwrap().to_string_lossy(),
                    reader_package.file_name().unwrap().to_string_lossy()
                ]
            }),
        );
        let reversed = check_release_set(&reversed_spec, &trust, &matrix).unwrap();
        assert_eq!(reversed.package_set_sha256, report.package_set_sha256);
        assert_eq!(reversed.packages, report.packages);

        let plugin_root = root.path().join("tested-plugin-root");
        let trust_store = TrustStore::load(&trust).unwrap();
        for package in [&reader_package, &printer_package] {
            PreparedPlugin::prepare(package, &plugin_root, &trust_store)
                .unwrap()
                .activate()
                .unwrap()
                .commit()
                .unwrap();
        }
        let rooted = check_release_root_against_set(&plugin_root, &spec, &trust, &matrix).unwrap();
        assert_eq!(rooted.package_set_sha256, report.package_set_sha256);
        fs::write(plugin_root.join("reader-plugin/reader.dll"), b"tampered").unwrap();
        let error =
            check_release_root_against_set(&plugin_root, &spec, &trust, &matrix).unwrap_err();
        assert!(error.to_string().contains("signature"));

        let duplicate_spec = matrix_file(
            root.path(),
            "duplicate-release-set.json",
            json!({
                "schemaVersion": 1,
                "packages": [
                    reader_package.file_name().unwrap().to_string_lossy(),
                    reader_package.file_name().unwrap().to_string_lossy()
                ]
            }),
        );
        let error = check_release_set(&duplicate_spec, &trust, &matrix).unwrap_err();
        assert!(error.to_string().contains("same package path"));

        let copied_package = root.path().join("reader-copy.ssdev-plugin");
        fs::copy(&reader_package, &copied_package).unwrap();
        let duplicate_identity_spec = matrix_file(
            root.path(),
            "duplicate-identity-release-set.json",
            json!({
                "schemaVersion": 1,
                "packages": [
                    reader_package.file_name().unwrap().to_string_lossy(),
                    copied_package.file_name().unwrap().to_string_lossy()
                ]
            }),
        );
        let error = check_release_set(&duplicate_identity_spec, &trust, &matrix).unwrap_err();
        assert!(error.to_string().contains("duplicate portable plugin ID"));
    }

    #[test]
    fn prepares_signs_packages_and_verifies_without_copying_legacy_license() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let staging = root.path().join("stage");
        let request = root.path().join("request.json");
        let matrix = root.path().join("matrix.json");
        let signing_key = SigningKey::from_bytes(&[33; 32]);
        let trust_path = trust_store(root.path(), &signing_key, None);
        let report = prepare(&PrepareOptions {
            source: &source,
            staging: &staging,
            request: &request,
            matrix_template: &matrix,
            plugin_id: "reader-plugin",
            version: "1.2.3",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust_path,
            matrix_seed: None,
        })
        .unwrap();
        assert!(report.legacy_license_excluded);
        assert!(!report.matrix_seeded);
        assert_eq!(report.matrix_case_count, 1);
        assert_eq!(report.matrix_placeholder_case_count, 1);
        assert_eq!(report.matrix_review_required_case_count, 1);
        assert!(!staging.join("license.dat").exists());
        let generated_matrix: Value = serde_json::from_slice(&fs::read(&matrix).unwrap()).unwrap();
        assert!(generated_matrix["draft"].as_bool().unwrap());
        assert_eq!(
            generated_matrix["plugins"][0],
            json!({ "pluginId": "reader-plugin", "version": "1.2.3" })
        );

        let signing_request: SigningRequest =
            serde_json::from_slice(&fs::read(&request).unwrap()).unwrap();
        let payload = BASE64.decode(signing_request.payload_base64).unwrap();
        let signature_path = root.path().join("signature.txt");
        fs::write(
            &signature_path,
            BASE64.encode(signing_key.sign(&payload).to_bytes()),
        )
        .unwrap();
        let package = root.path().join("reader.ssdev-plugin");
        let finalized = finalize(&FinalizeOptions {
            staging: &staging,
            request: &request,
            signature: &signature_path,
            trust_store: &trust_path,
            package: &package,
        })
        .unwrap();
        assert!(finalized.package_verified);
        assert_eq!(finalized.payload_sha256, report.payload_sha256);
        let verified = verify(&package, &trust_path).unwrap();
        assert_eq!(verified.plugin_id, "reader-plugin");
        assert_eq!(verified.package_sha256, finalized.package_sha256);

        let finalized_matrix = matrix_file(
            root.path(),
            "finalized-matrix.json",
            bound_executable_matrix(executable_case(), "reader-plugin", "1.2.3"),
        );
        let candidate = check_release_candidate(&package, &trust_path, &finalized_matrix).unwrap();
        assert_eq!(candidate.plugin_id, "reader-plugin");
        assert_eq!(candidate.version, "1.2.3");
        assert_eq!(candidate.package_sha256, finalized.package_sha256);
        assert_eq!(
            candidate.matrix_sha256,
            sha256_file(&finalized_matrix).unwrap()
        );
        assert_eq!(candidate.service_count, 1);
        assert_eq!(candidate.method_count, 1);
        assert_eq!(candidate.case_count, 1);
        assert_eq!(candidate.enabled_case_count, 1);
        assert!(candidate.package_verified);
        assert!(candidate.matrix_verified);

        let unbound_matrix = matrix_file(
            root.path(),
            "unbound-matrix.json",
            executable_matrix(executable_case()),
        );
        let error = check_release_candidate(&package, &trust_path, &unbound_matrix).unwrap_err();
        assert!(error.to_string().contains("bind the exact plugin"));

        let stale_matrix = matrix_file(
            root.path(),
            "stale-version-matrix.json",
            bound_executable_matrix(executable_case(), "reader-plugin", "1.2.2"),
        );
        let error = check_release_candidate(&package, &trust_path, &stale_matrix).unwrap_err();
        assert!(error.to_string().contains("do not exactly match"));

        let mut mismatched_case = executable_case();
        mismatched_case["request"]["method"] = Value::String("other-version-method".into());
        let mismatched_matrix = matrix_file(
            root.path(),
            "mismatched-matrix.json",
            bound_executable_matrix(mismatched_case, "reader-plugin", "1.2.3"),
        );
        let error = check_release_candidate(&package, &trust_path, &mismatched_matrix).unwrap_err();
        assert!(error.to_string().contains("unknown method"));

        trust_store(root.path(), &signing_key, Some("retired"));
        let error = check_release_candidate(&package, &trust_path, &finalized_matrix).unwrap_err();
        assert!(error.to_string().contains("retired"));
        trust_store(root.path(), &signing_key, None);

        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let spec = root.path().join("catalog-spec.json");
        fs::write(
            &spec,
            serde_json::to_vec_pretty(&json!({
                "schemaVersion": 1,
                "issuedAt": 1_699_999_940_u64,
                "expiresAt": 1_700_003_600_u64,
                "packages": [{
                    "package": "reader.ssdev-plugin",
                    "url": "https://plugins.example.test/reader.ssdev-plugin"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let catalog_path = root.path().join("catalog.json");
        let catalog_report = create_catalog(&CatalogOptions {
            spec: &spec,
            trust_store: &trust_path,
            catalog: &catalog_path,
            now,
        })
        .unwrap();
        assert_eq!(catalog_report.package_count, 1);
        let catalog_bytes = fs::read(&catalog_path).unwrap();
        assert_eq!(catalog_report.catalog_sha256, sha256_hex(&catalog_bytes));
        let catalog =
            webplus_plugin_repository::PluginCatalog::from_unsigned_bytes(&catalog_bytes, now)
                .unwrap();
        assert_eq!(catalog.entries()[0].plugin_id, "reader-plugin");
        assert_eq!(
            catalog.entries()[0].version,
            Version::parse("1.2.3").unwrap()
        );
        assert_eq!(catalog.entries()[0].sha256, finalized.package_sha256);
    }

    #[test]
    fn prepare_validates_and_adopts_an_external_draft_matrix_seed() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let seed = root.path().join("release-matrix-seed.json");
        fs::write(
            &seed,
            serde_json::to_vec_pretty(&json!({
                "schemaVersion": 1,
                "draft": true,
                "cases": [{
                    "name": "known reader response",
                    "enabled": true,
                    "request": {
                        "serviceId": "reader",
                        "method": "read",
                        "parameters": { "timeout": 5 }
                    },
                    "expected": {
                        "ResCode": 0,
                        "ResData": { "ReturnValue": 0 }
                    }
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let matrix = root.path().join("matrix.json");
        let trust = trust_store(root.path(), &SigningKey::from_bytes(&[42; 32]), None);

        let report = prepare(&PrepareOptions {
            source: &source,
            staging: &root.path().join("stage"),
            request: &root.path().join("request.json"),
            matrix_template: &matrix,
            plugin_id: "reader-plugin",
            version: "1.0.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust,
            matrix_seed: Some(&seed),
        })
        .unwrap();

        assert!(report.matrix_seeded);
        assert_eq!(report.matrix_case_count, 1);
        assert_eq!(report.matrix_placeholder_case_count, 0);
        assert_eq!(report.matrix_review_required_case_count, 0);
        let generated: Value = serde_json::from_slice(&fs::read(matrix).unwrap()).unwrap();
        assert_eq!(generated["cases"][0]["name"], "known reader response");
        assert_eq!(generated["plugins"][0]["pluginId"], "reader-plugin");
        assert_eq!(generated["plugins"][0]["version"], "1.0.0");
        assert_eq!(
            generated["cases"][0]["expected"]["ResData"]["ReturnValue"],
            0
        );
    }

    #[test]
    fn prepare_rejects_a_matrix_seed_inside_the_signed_source() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let seed = source.join("matrix-seed.json");
        fs::write(&seed, b"{}").unwrap();
        let trust = trust_store(root.path(), &SigningKey::from_bytes(&[43; 32]), None);

        let error = prepare(&PrepareOptions {
            source: &source,
            staging: &root.path().join("stage"),
            request: &root.path().join("request.json"),
            matrix_template: &root.path().join("matrix.json"),
            plugin_id: "reader-plugin",
            version: "1.0.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust,
            matrix_seed: Some(&seed),
        })
        .unwrap_err();

        assert!(error.to_string().contains("outside the signed source"));
        assert!(!root.path().join("stage").exists());
    }

    #[test]
    fn prepare_rejects_undeclared_matrix_seed_inputs() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let seed = root.path().join("invalid-matrix-seed.json");
        fs::write(
            &seed,
            serde_json::to_vec(&json!({
                "schemaVersion": 1,
                "draft": true,
                "cases": [{
                    "name": "undeclared input",
                    "request": {
                        "serviceId": "reader",
                        "method": "read",
                        "parameters": { "secret": "must-not-pass" }
                    },
                    "expected": { "ResCode": 0, "ResData": null }
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let trust = trust_store(root.path(), &SigningKey::from_bytes(&[44; 32]), None);

        let error = prepare(&PrepareOptions {
            source: &source,
            staging: &root.path().join("stage"),
            request: &root.path().join("request.json"),
            matrix_template: &root.path().join("matrix.json"),
            plugin_id: "reader-plugin",
            version: "1.0.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust,
            matrix_seed: Some(&seed),
        })
        .unwrap_err();

        assert!(error.to_string().contains("undeclared input parameter"));
        assert!(!root.path().join("stage").exists());
    }

    #[test]
    fn prepare_rejects_missing_matrix_seed_inputs() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let seed = root.path().join("missing-input-matrix-seed.json");
        fs::write(
            &seed,
            serde_json::to_vec(&json!({
                "schemaVersion": 1,
                "draft": true,
                "cases": [{
                    "name": "missing timeout",
                    "request": {
                        "serviceId": "reader",
                        "method": "read",
                        "parameters": {}
                    },
                    "expected": { "ResCode": 0, "ResData": null }
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let trust = trust_store(root.path(), &SigningKey::from_bytes(&[45; 32]), None);

        let error = prepare(&PrepareOptions {
            source: &source,
            staging: &root.path().join("stage"),
            request: &root.path().join("request.json"),
            matrix_template: &root.path().join("matrix.json"),
            plugin_id: "reader-plugin",
            version: "1.0.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust,
            matrix_seed: Some(&seed),
        })
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("missing declared input parameter"));
        assert!(!root.path().join("stage").exists());
    }

    #[test]
    fn prepare_rejects_install_run_and_architecture_mismatch() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        fs::write(
            source.join("api.json"),
            r#"{"serviceId":"reader","mainClass":"reader.dll","architecture":"x64","installRun":"setup.exe","methods":[{"name":"read"}]}"#,
        )
        .unwrap();
        let trust = trust_store(root.path(), &SigningKey::from_bytes(&[35; 32]), None);
        let error = prepare(&PrepareOptions {
            source: &source,
            staging: &root.path().join("stage"),
            request: &root.path().join("request.json"),
            matrix_template: &root.path().join("matrix.json"),
            plugin_id: "reader-plugin",
            version: "1.0.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust,
            matrix_seed: None,
        })
        .unwrap_err();
        assert!(error.to_string().contains("installRun"));
        assert!(!root.path().join("stage").exists());
    }

    #[test]
    fn prepare_rejects_a_retired_key_before_creating_signing_material() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let trust = trust_store(
            root.path(),
            &SigningKey::from_bytes(&[38; 32]),
            Some("retired"),
        );
        let staging = root.path().join("stage");
        let request = root.path().join("request.json");

        let error = prepare(&PrepareOptions {
            source: &source,
            staging: &staging,
            request: &request,
            matrix_template: &root.path().join("matrix.json"),
            plugin_id: "reader-plugin",
            version: "1.0.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust,
            matrix_seed: None,
        })
        .unwrap_err();

        assert!(error.to_string().contains("retired"));
        assert!(!staging.exists());
        assert!(!request.exists());
    }

    #[test]
    fn finalize_rejects_a_changed_staging_directory_before_importing_signature() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let staging = root.path().join("stage");
        let request = root.path().join("request.json");
        let trust = trust_store(root.path(), &SigningKey::from_bytes(&[36; 32]), None);
        prepare(&PrepareOptions {
            source: &source,
            staging: &staging,
            request: &request,
            matrix_template: &root.path().join("matrix.json"),
            plugin_id: "reader-plugin",
            version: "1.0.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust,
            matrix_seed: None,
        })
        .unwrap();
        fs::write(staging.join("reader.dll"), pe(0x8664)).unwrap();
        let signature = root.path().join("signature.txt");
        fs::write(&signature, BASE64.encode([0_u8; 64])).unwrap();
        let error = finalize(&FinalizeOptions {
            staging: &staging,
            request: &request,
            signature: &signature,
            trust_store: &root.path().join("missing-trust.json"),
            package: &root.path().join("reader.ssdev-plugin"),
        })
        .unwrap_err();
        assert!(error.to_string().contains("changed"));
        assert!(!staging.join(SIGNATURE_FILENAME).exists());
    }

    #[test]
    fn finalize_rejects_a_retired_plugin_signing_key() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let staging = root.path().join("stage");
        let request = root.path().join("request.json");
        let signing_key = SigningKey::from_bytes(&[34; 32]);
        let trust_path = trust_store(root.path(), &signing_key, None);
        prepare(&PrepareOptions {
            source: &source,
            staging: &staging,
            request: &request,
            matrix_template: &root.path().join("matrix.json"),
            plugin_id: "reader-plugin",
            version: "1.0.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust_path,
            matrix_seed: None,
        })
        .unwrap();
        let signing_request: SigningRequest =
            serde_json::from_slice(&fs::read(&request).unwrap()).unwrap();
        let payload = BASE64.decode(signing_request.payload_base64).unwrap();
        let signature = root.path().join("signature.txt");
        fs::write(
            &signature,
            BASE64.encode(signing_key.sign(&payload).to_bytes()),
        )
        .unwrap();
        trust_store(root.path(), &signing_key, Some("retired"));
        let package = root.path().join("reader.ssdev-plugin");

        let error = finalize(&FinalizeOptions {
            staging: &staging,
            request: &request,
            signature: &signature,
            trust_store: &trust_path,
            package: &package,
        })
        .unwrap_err();

        assert!(error.to_string().contains("retired"));
        assert!(!package.exists());
        assert!(!staging.join(SIGNATURE_FILENAME).exists());
    }

    #[cfg(unix)]
    #[test]
    fn prepare_never_replaces_a_dangling_output_symlink() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let staging = root.path().join("stage");
        symlink(root.path().join("missing"), &staging).unwrap();
        let trust = trust_store(root.path(), &SigningKey::from_bytes(&[37; 32]), None);

        let error = prepare(&PrepareOptions {
            source: &source,
            staging: &staging,
            request: &root.path().join("request.json"),
            matrix_template: &root.path().join("matrix.json"),
            plugin_id: "reader-plugin",
            version: "1.0.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust,
            matrix_seed: None,
        })
        .unwrap_err();

        assert!(error.to_string().contains("already exists"));
        assert!(fs::symlink_metadata(staging)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn bare_output_names_use_the_current_directory() {
        assert_eq!(output_parent(Path::new("catalog.json")), Path::new("."));
    }
}
