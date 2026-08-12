use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tempfile::Builder as TempBuilder;
use thiserror::Error;
use webplus_plugin_config::{PluginManifest, PluginMetadata};
use webplus_plugin_package::{create_deterministic_package, PreparedPlugin};
use webplus_plugin_repository::{encode_catalog_document, CatalogEntry};
use webplus_plugin_trust::{
    encode_signature_document, portable_plugin_path, prepare_signing_material, TrustPurpose,
    TrustStore, SIGNATURE_FILENAME,
};
use webplus_protocol::PluginArchitecture;

const MAX_PLUGIN_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PLUGIN_FILES: usize = 4096;
const MAX_SIGNING_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 1024;
const MAX_MATRIX_CASES: usize = 1024;
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
        let matrix = draft_matrix(&manifest);
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

fn draft_matrix(manifest: &PluginManifest) -> Value {
    let cases = manifest
        .services
        .iter()
        .flat_map(|service| {
            service.methods.iter().map(move |method| {
                let mut parameters = Map::new();
                for parameter in &method.parameters {
                    parameters.insert(
                        parameter.name().trim_start_matches('$').to_owned(),
                        Value::String("<replace-with-redacted-input>".into()),
                    );
                }
                json!({
                    "name": format!("{}.{}", service.service_id, method.name),
                    "enabled": true,
                    "request": {
                        "serviceId": service.service_id,
                        "method": method.name,
                        "parameters": parameters,
                    },
                    "expected": {
                        "ResCode": 0,
                        "ResData": "<replace-with-redacted-golden-response>"
                    }
                })
            })
        })
        .collect::<Vec<_>>();
    json!({
        "schemaVersion": 1,
        "draft": true,
        "cases": cases,
    })
}

fn write_external_outputs(
    request_path: &Path,
    request: &SigningRequest,
    matrix_path: &Path,
    matrix: &Value,
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
        if total > MAX_PLUGIN_BYTES {
            return Err(ToolError::Invalid(format!(
                "plugin package exceeds {MAX_PLUGIN_BYTES} bytes while being read"
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
        })
        .unwrap();
        assert!(report.legacy_license_excluded);
        assert!(!staging.join("license.dat").exists());
        assert!(
            serde_json::from_slice::<Value>(&fs::read(&matrix).unwrap()).unwrap()["draft"]
                .as_bool()
                .unwrap()
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
