use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssdev_cutover_evidence::{
    cutover_decision_signing_payload, evidence_attestation_signing_payload, CutoverDecision,
    EvidenceAttestationKind, MigrationAuditEvidence, PluginMatrixEvidence, WindowsPackageEvidence,
};
use ssdev_origin_policy::{signing_payload as origin_payload, OriginPolicy};
use ssdev_process_policy::{signing_payload as process_payload, ProcessPolicy};
use tempfile::Builder as TempBuilder;
use thiserror::Error;
use webplus_plugin_repository::{signing_payload as catalog_payload, PluginCatalog};
use webplus_plugin_trust::{
    validate_signing_key_id, DetachedSignatureDocument, TrustPurpose, TrustStore, TrustStoreStats,
};

const MAX_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    CutoverDecision,
    MigrationAuditEvidence,
    OriginPolicy,
    PluginMatrixEvidence,
    ProcessPolicy,
    PluginCatalog,
    WindowsPackageEvidence,
}

impl ArtifactKind {
    pub const fn trust_purpose(self) -> TrustPurpose {
        match self {
            Self::CutoverDecision => TrustPurpose::CutoverDecision,
            Self::MigrationAuditEvidence
            | Self::PluginMatrixEvidence
            | Self::WindowsPackageEvidence => TrustPurpose::CutoverEvidence,
            Self::OriginPolicy => TrustPurpose::OriginPolicy,
            Self::ProcessPolicy => TrustPurpose::ProcessPolicy,
            Self::PluginCatalog => TrustPurpose::PluginCatalog,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CutoverDecision => "cutover-decision",
            Self::MigrationAuditEvidence => "migration-audit-evidence",
            Self::OriginPolicy => "origin-policy",
            Self::PluginMatrixEvidence => "plugin-matrix-evidence",
            Self::ProcessPolicy => "process-policy",
            Self::PluginCatalog => "plugin-catalog",
            Self::WindowsPackageEvidence => "windows-package-evidence",
        }
    }
}

impl std::str::FromStr for ArtifactKind {
    type Err = SigningError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "cutover-decision" => Ok(Self::CutoverDecision),
            "migration-audit-evidence" => Ok(Self::MigrationAuditEvidence),
            "origin-policy" => Ok(Self::OriginPolicy),
            "plugin-matrix-evidence" => Ok(Self::PluginMatrixEvidence),
            "process-policy" => Ok(Self::ProcessPolicy),
            "plugin-catalog" => Ok(Self::PluginCatalog),
            "windows-package-evidence" => Ok(Self::WindowsPackageEvidence),
            _ => Err(SigningError::Invalid(format!(
                "unsupported artifact kind [{value}]"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "artifactKind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum ArtifactSummary {
    CutoverDecision {
        source_revision: String,
        app_version: String,
        evaluated_at_unix_seconds: u64,
        approval_signer_key_id: String,
    },
    MigrationAuditEvidence {
        source_revision: String,
        browser_asset_files: u32,
        browser_har_requests: u32,
        critical_findings: u32,
        warning_findings: u32,
        info_findings: u32,
    },
    OriginPolicy {
        business_origins: usize,
        service_grants: usize,
        method_grants: usize,
        navigation_origins: usize,
        external_origins: usize,
        allow_insecure_http: bool,
    },
    ProcessPolicy {
        process_count: usize,
    },
    PluginCatalog {
        issued_at: u64,
        expires_at: u64,
        entry_count: usize,
    },
    PluginMatrixEvidence {
        source_revision: String,
        plugin_count: u32,
        service_count: u32,
        method_count: u32,
        enabled_case_count: u32,
    },
    WindowsPackageEvidence {
        source_revision: String,
        app_version: String,
        authenticode_verified: bool,
        nsis_install_verified: bool,
        msi_install_verified: bool,
        launch_verified: bool,
        upgrade_verified: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SigningRequest {
    pub schema_version: u8,
    pub artifact_kind: ArtifactKind,
    pub trust_purpose: TrustPurpose,
    pub key_id: String,
    pub document_sha256: String,
    pub payload_base64: String,
    pub payload_sha256: String,
    pub summary: ArtifactSummary,
}

#[derive(Debug, Clone)]
pub struct PrepareOptions<'a> {
    pub kind: ArtifactKind,
    pub document: &'a Path,
    pub key_id: &'a str,
    pub trust_store: &'a Path,
    pub request: &'a Path,
    pub now: SystemTime,
}

#[derive(Debug, Clone)]
pub struct FinalizeOptions<'a> {
    pub kind: ArtifactKind,
    pub document: &'a Path,
    pub request: &'a Path,
    pub signature: &'a Path,
    pub trust_store: &'a Path,
    pub envelope: &'a Path,
    pub now: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningReport {
    pub schema_version: u8,
    pub artifact_kind: ArtifactKind,
    pub trust_purpose: TrustPurpose,
    pub key_id: String,
    pub document_sha256: String,
    pub payload_sha256: String,
    pub summary: ArtifactSummary,
    pub verified: bool,
}

#[derive(Debug, Clone)]
struct Material {
    document_sha256: String,
    payload: Vec<u8>,
    payload_sha256: String,
    summary: ArtifactSummary,
}

pub fn prepare(options: &PrepareOptions<'_>) -> Result<SigningReport, SigningError> {
    ensure_fresh_output(options.request, "signing request")?;
    validate_signing_key_id(options.key_id)?;
    TrustStore::load(options.trust_store)?
        .ensure_key_can_issue(options.kind.trust_purpose(), options.key_id)?;
    let document = read_bounded(options.document, MAX_DOCUMENT_BYTES)?;
    let material = prepare_material(options.kind, &document, options.now)?;
    ensure_expected_signer(&material.summary, options.key_id)?;
    let request = SigningRequest {
        schema_version: 1,
        artifact_kind: options.kind,
        trust_purpose: options.kind.trust_purpose(),
        key_id: options.key_id.to_owned(),
        document_sha256: material.document_sha256.clone(),
        payload_base64: BASE64.encode(&material.payload),
        payload_sha256: material.payload_sha256.clone(),
        summary: material.summary.clone(),
    };
    write_new_json(options.request, &request)?;
    Ok(report(&request, false))
}

pub fn verify_trust_store(
    trust_store_path: &Path,
    required_purposes: &[TrustPurpose],
) -> Result<TrustStoreStats, SigningError> {
    let trust_store = TrustStore::load(trust_store_path)?;
    trust_store
        .ensure_release_ready(required_purposes)
        .map_err(Into::into)
}

pub fn finalize(options: &FinalizeOptions<'_>) -> Result<SigningReport, SigningError> {
    ensure_fresh_output(options.envelope, "signature envelope")?;
    let document = read_bounded(options.document, MAX_DOCUMENT_BYTES)?;
    let request: SigningRequest =
        serde_json::from_slice(&read_bounded(options.request, MAX_REQUEST_BYTES)?)?;
    validate_request(options.kind, &document, &request, options.now)?;
    let signature = read_signature(options.signature)?;
    let envelope = DetachedSignatureDocument::new(&request.key_id, &signature)?;
    let trust_store = TrustStore::load(options.trust_store)?;
    let payload = BASE64.decode(&request.payload_base64).map_err(|error| {
        SigningError::Invalid(format!(
            "signing request payload is invalid base64: {error}"
        ))
    })?;
    trust_store.verify_detached_for_issuance(
        options.kind.trust_purpose(),
        &request.key_id,
        &payload,
        &signature,
    )?;
    write_new_bytes(options.envelope, &envelope.to_pretty_json()?)?;
    verify(
        options.kind,
        options.document,
        options.envelope,
        options.trust_store,
        options.now,
    )
}

pub fn verify(
    kind: ArtifactKind,
    document_path: &Path,
    envelope_path: &Path,
    trust_store_path: &Path,
    now: SystemTime,
) -> Result<SigningReport, SigningError> {
    let document = read_bounded(document_path, MAX_DOCUMENT_BYTES)?;
    let envelope_bytes = read_bounded(envelope_path, MAX_REQUEST_BYTES)?;
    let envelope: DetachedSignatureDocument = serde_json::from_slice(&envelope_bytes)?;
    envelope.validate()?;
    let material = prepare_material(kind, &document, now)?;
    ensure_expected_signer(&material.summary, &envelope.key_id)?;
    let trust_store = TrustStore::load(trust_store_path)?;
    trust_store.verify_detached_for_issuance(
        kind.trust_purpose(),
        &envelope.key_id,
        &material.payload,
        &envelope.signature,
    )?;
    Ok(SigningReport {
        schema_version: 1,
        artifact_kind: kind,
        trust_purpose: kind.trust_purpose(),
        key_id: envelope.key_id,
        document_sha256: material.document_sha256,
        payload_sha256: material.payload_sha256,
        summary: material.summary,
        verified: true,
    })
}

fn validate_request(
    kind: ArtifactKind,
    document: &[u8],
    request: &SigningRequest,
    now: SystemTime,
) -> Result<(), SigningError> {
    if request.schema_version != 1
        || request.artifact_kind != kind
        || request.trust_purpose != kind.trust_purpose()
    {
        return Err(SigningError::Invalid(
            "signing request schema, artifact kind, or trust purpose does not match".into(),
        ));
    }
    validate_signing_key_id(&request.key_id)?;
    let material = prepare_material(kind, document, now)?;
    ensure_expected_signer(&material.summary, &request.key_id)?;
    if request.document_sha256 != material.document_sha256
        || request.payload_base64 != BASE64.encode(&material.payload)
        || request.payload_sha256 != material.payload_sha256
        || request.summary != material.summary
    {
        return Err(SigningError::Invalid(
            "document changed after the signing request was created".into(),
        ));
    }
    Ok(())
}

fn prepare_material(
    kind: ArtifactKind,
    document: &[u8],
    now: SystemTime,
) -> Result<Material, SigningError> {
    let (payload, summary) = match kind {
        ArtifactKind::CutoverDecision => {
            let decision = CutoverDecision::from_bytes_for_signing(document)?;
            (
                cutover_decision_signing_payload(document),
                ArtifactSummary::CutoverDecision {
                    source_revision: decision.target_source_revision,
                    app_version: decision.app_version,
                    evaluated_at_unix_seconds: decision.evaluated_at_unix_seconds,
                    approval_signer_key_id: decision.approval_signer_key_id,
                },
            )
        }
        ArtifactKind::MigrationAuditEvidence => {
            let evidence: MigrationAuditEvidence = serde_json::from_slice(document)?;
            evidence.validate()?;
            (
                evidence_attestation_signing_payload(
                    EvidenceAttestationKind::MigrationAudit,
                    document,
                )?,
                ArtifactSummary::MigrationAuditEvidence {
                    source_revision: evidence.source_revision,
                    browser_asset_files: evidence.browser_asset_files_scanned,
                    browser_har_requests: evidence.browser_har_requests_scanned,
                    critical_findings: evidence.critical_findings,
                    warning_findings: evidence.warning_findings,
                    info_findings: evidence.info_findings,
                },
            )
        }
        ArtifactKind::OriginPolicy => {
            let policy = OriginPolicy::from_unsigned_bytes(document)?;
            let summary = policy.summary();
            (
                origin_payload(document),
                ArtifactSummary::OriginPolicy {
                    business_origins: summary.business_origins,
                    service_grants: summary.service_grants,
                    method_grants: summary.method_grants,
                    navigation_origins: summary.navigation_origins,
                    external_origins: summary.external_origins,
                    allow_insecure_http: summary.allow_insecure_http,
                },
            )
        }
        ArtifactKind::ProcessPolicy => {
            let policy = ProcessPolicy::from_unsigned_bytes(document)?;
            (
                process_payload(document),
                ArtifactSummary::ProcessPolicy {
                    process_count: policy.len(),
                },
            )
        }
        ArtifactKind::PluginCatalog => {
            let catalog = PluginCatalog::from_unsigned_bytes(document, now)?;
            (
                catalog_payload(document),
                ArtifactSummary::PluginCatalog {
                    issued_at: catalog.issued_at(),
                    expires_at: catalog.expires_at(),
                    entry_count: catalog.entries().len(),
                },
            )
        }
        ArtifactKind::PluginMatrixEvidence => {
            let evidence: PluginMatrixEvidence = serde_json::from_slice(document)?;
            evidence.validate()?;
            (
                evidence_attestation_signing_payload(
                    EvidenceAttestationKind::PluginMatrix,
                    document,
                )?,
                ArtifactSummary::PluginMatrixEvidence {
                    source_revision: evidence.source_revision,
                    plugin_count: evidence.plugin_count,
                    service_count: evidence.service_count,
                    method_count: evidence.method_count,
                    enabled_case_count: evidence.enabled_case_count,
                },
            )
        }
        ArtifactKind::WindowsPackageEvidence => {
            let evidence: WindowsPackageEvidence = serde_json::from_slice(document)?;
            evidence.validate()?;
            (
                evidence_attestation_signing_payload(
                    EvidenceAttestationKind::WindowsPackage,
                    document,
                )?,
                ArtifactSummary::WindowsPackageEvidence {
                    source_revision: evidence.source_revision,
                    app_version: evidence.app_version,
                    authenticode_verified: evidence.authenticode_verified,
                    nsis_install_verified: evidence.nsis_install_verified,
                    msi_install_verified: evidence.msi_install_verified,
                    launch_verified: evidence.launch_verified,
                    upgrade_verified: evidence.upgrade_verified,
                },
            )
        }
    };
    Ok(Material {
        document_sha256: sha256_hex(document),
        payload_sha256: sha256_hex(&payload),
        payload,
        summary,
    })
}

fn ensure_expected_signer(summary: &ArtifactSummary, key_id: &str) -> Result<(), SigningError> {
    if let ArtifactSummary::CutoverDecision {
        approval_signer_key_id,
        ..
    } = summary
    {
        if approval_signer_key_id != key_id {
            return Err(SigningError::Invalid(
                "cutover approval signer does not match the production policy".into(),
            ));
        }
    }
    Ok(())
}

fn report(request: &SigningRequest, verified: bool) -> SigningReport {
    SigningReport {
        schema_version: 1,
        artifact_kind: request.artifact_kind,
        trust_purpose: request.trust_purpose,
        key_id: request.key_id.clone(),
        document_sha256: request.document_sha256.clone(),
        payload_sha256: request.payload_sha256.clone(),
        summary: request.summary.clone(),
        verified,
    }
}

fn read_signature(path: &Path) -> Result<String, SigningError> {
    let bytes = read_bounded(path, MAX_SIGNATURE_BYTES)?;
    let signature = std::str::from_utf8(&bytes)
        .map_err(|_| SigningError::Invalid("signature file must contain UTF-8 base64".into()))?
        .trim();
    if signature.is_empty() || signature.lines().count() != 1 {
        return Err(SigningError::Invalid(
            "signature file must contain exactly one base64 value".into(),
        ));
    }
    Ok(signature.to_owned())
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, SigningError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| SigningError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() || metadata.len() > limit {
        return Err(SigningError::Invalid(format!(
            "input must be a regular file no larger than {limit} bytes"
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|file| file.take(limit + 1).read_to_end(&mut bytes))
        .map_err(|source| SigningError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > limit {
        return Err(SigningError::Invalid(format!(
            "input exceeds {limit} bytes while being read"
        )));
    }
    Ok(bytes)
}

fn write_new_json(path: &Path, value: &impl Serialize) -> Result<(), SigningError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_new_bytes(path, &bytes)
}

fn write_new_bytes(path: &Path, bytes: &[u8]) -> Result<(), SigningError> {
    let parent = output_parent(path);
    let metadata = fs::symlink_metadata(parent).map_err(|source| SigningError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_dir() {
        return Err(SigningError::Invalid(
            "output parent must be an existing real directory".into(),
        ));
    }
    let mut temporary = TempBuilder::new()
        .prefix(".ssdev-signing-")
        .tempfile_in(parent)
        .map_err(|source| SigningError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    temporary
        .write_all(bytes)
        .and_then(|_| temporary.flush())
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|source| SigningError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| SigningError::Io {
            path: path.to_path_buf(),
            source: error.error,
        })?;
    Ok(())
}

fn ensure_fresh_output(path: &Path, role: &str) -> Result<(), SigningError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(SigningError::Invalid(format!("{role} already exists"))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(SigningError::Io {
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
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

pub fn unix_time(seconds: u64) -> Result<SystemTime, SigningError> {
    UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(seconds))
        .ok_or_else(|| SigningError::Invalid("Unix time is out of range".into()))
}

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("release signing input is invalid: {0}")]
    Invalid(String),
    #[error("filesystem operation failed at {path:?}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("JSON encoding or decoding failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("origin policy validation failed: {0}")]
    OriginPolicy(#[from] ssdev_origin_policy::OriginPolicyError),
    #[error("process policy validation failed: {0}")]
    ProcessPolicy(#[from] ssdev_process_policy::PolicyError),
    #[error("plugin catalog validation failed: {0}")]
    PluginCatalog(#[from] webplus_plugin_repository::RepositoryError),
    #[error("cutover decision failed validation: {0}")]
    CutoverDecision(#[from] ssdev_cutover_evidence::EvidenceError),
    #[error("signature trust validation failed: {0}")]
    Trust(#[from] webplus_plugin_trust::TrustError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use ssdev_cutover_evidence::verify_evidence_attestation;

    const NOW: u64 = 1_700_000_000;

    fn documents(root: &Path) -> Vec<(ArtifactKind, PathBuf)> {
        let executable = if cfg!(windows) {
            r"C:\Program Files\Bsoft\helper.exe"
        } else {
            "/opt/bsoft/helper"
        };
        let working_directory = if cfg!(windows) {
            r"C:\Program Files\Bsoft"
        } else {
            "/opt/bsoft"
        };
        let values = [
            (
                ArtifactKind::OriginPolicy,
                serde_json::json!({
                    "schemaVersion": 2,
                    "businessGrants": [{
                        "origin": "https://business.example.test",
                        "services": [{"serviceId": "reader", "methods": ["read"]}]
                    }],
                    "navigationOrigins": [],
                    "externalOrigins": [],
                    "allowInsecureHttp": false
                }),
            ),
            (
                ArtifactKind::ProcessPolicy,
                serde_json::json!({
                    "schemaVersion": 1,
                    "processes": [{
                        "id": "helper",
                        "executable": executable,
                        "sha256": "11".repeat(32),
                        "arguments": ["--managed"],
                        "workingDirectory": working_directory,
                        "singleton": true
                    }]
                }),
            ),
            (
                ArtifactKind::PluginCatalog,
                serde_json::json!({
                    "schemaVersion": 1,
                    "issuedAt": NOW - 60,
                    "expiresAt": NOW + 3600,
                    "entries": [{
                        "pluginId": "reader-plugin",
                        "version": "1.2.3",
                        "url": "https://plugins.example.test/reader.ssdev-plugin",
                        "sha256": "22".repeat(32),
                        "size": 1234
                    }]
                }),
            ),
            (
                ArtifactKind::PluginMatrixEvidence,
                serde_json::json!({
                    "schemaVersion": 1,
                    "evidenceType": "plugin-matrix",
                    "sourceRevision": "aa".repeat(20),
                    "sourceDirty": false,
                    "executedAtUnixSeconds": NOW,
                    "environment": "plugin-reader-lab",
                    "runnerOs": "windows",
                    "runnerArchitecture": "x86_64",
                    "pluginSetSha256": "11".repeat(32),
                    "trustStoreSha256": "22".repeat(32),
                    "matrixSha256": "33".repeat(32),
                    "x86HostSha256": "44".repeat(32),
                    "x64HostSha256": "55".repeat(32),
                    "pluginCount": 1,
                    "serviceCount": 1,
                    "methodCount": 1,
                    "enabledCaseCount": 1,
                    "passed": true
                }),
            ),
            (
                ArtifactKind::MigrationAuditEvidence,
                serde_json::json!({
                    "schemaVersion": 1,
                    "evidenceType": "migration-audit",
                    "sourceRevision": "aa".repeat(20),
                    "sourceDirty": false,
                    "executedAtUnixSeconds": NOW,
                    "environment": "migration-workflows",
                    "runnerOs": "windows",
                    "runnerArchitecture": "x86_64",
                    "reportSha256": "66".repeat(32),
                    "configFiles": 1,
                    "pluginDirectories": 1,
                    "serviceCount": 1,
                    "keyBindingCount": 0,
                    "browserAssetRoots": 1,
                    "browserAssetFilesScanned": 10,
                    "browserHarFiles": 1,
                    "browserHarRequestsScanned": 20,
                    "webplusHttpEvidence": "notObserved",
                    "desktopCallbackHttpEvidence": "notObserved",
                    "criticalFindings": 0,
                    "warningFindings": 0,
                    "infoFindings": 1,
                    "findingCodeCounts": {"inventory-summary": 1}
                }),
            ),
            (
                ArtifactKind::WindowsPackageEvidence,
                serde_json::json!({
                    "schemaVersion": 1,
                    "evidenceType": "windows-package",
                    "sourceRevision": "aa".repeat(20),
                    "sourceDirty": false,
                    "executedAtUnixSeconds": NOW,
                    "environment": "windows-package-lab",
                    "runnerOs": "windows",
                    "runnerArchitecture": "x86_64",
                    "releaseMetadataSha256": "77".repeat(32),
                    "artifactManifestSha256": "88".repeat(32),
                    "appVersion": "1.2.3",
                    "authenticodeRequired": true,
                    "authenticodeVerified": true,
                    "nsisInstallVerified": true,
                    "msiInstallVerified": true,
                    "launchVerified": true,
                    "upgradeVerified": true,
                    "previousAppVersion": "1.2.2",
                    "previousReleaseMetadataSha256": "99".repeat(32),
                    "passed": true
                }),
            ),
            (
                ArtifactKind::CutoverDecision,
                serde_json::json!({
                    "schemaVersion": 1,
                    "targetSourceRevision": "aa".repeat(20),
                    "appVersion": "1.2.3",
                    "approvalSignerKeyId": "release-key",
                    "evaluatedAtUnixSeconds": NOW,
                    "policySha256": "11".repeat(32),
                    "evidenceTrustStoreSha256": "88".repeat(32),
                    "pluginMatrixEvidenceSha256": "22".repeat(32),
                    "migrationAuditEvidenceSha256": "33".repeat(32),
                    "windowsPackageEvidenceSha256": "44".repeat(32),
                    "pluginMatrixAttestationSha256": "55".repeat(32),
                    "migrationAuditAttestationSha256": "66".repeat(32),
                    "windowsPackageAttestationSha256": "77".repeat(32),
                    "eligible": true,
                    "blockerCodes": []
                }),
            ),
        ];
        values
            .into_iter()
            .map(|(kind, value)| {
                let path = root.join(format!("{}.json", kind.as_str()));
                fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
                (kind, path)
            })
            .collect()
    }

    fn trust_store(root: &Path, signing_key: &SigningKey) -> PathBuf {
        trust_store_with_status(root, signing_key, None)
    }

    fn trust_store_with_status(
        root: &Path,
        signing_key: &SigningKey,
        status: Option<&str>,
    ) -> PathBuf {
        let path = root.join("trust.json");
        let mut key = serde_json::json!({
            "keyId": "release-key",
            "algorithm": "ed25519",
            "publicKey": BASE64.encode(signing_key.verifying_key().to_bytes()),
            "purposes": ["cutover-decision", "cutover-evidence", "origin-policy", "process-policy", "plugin-catalog"]
        });
        if let Some(status) = status {
            key["status"] = serde_json::Value::String(status.to_owned());
        }
        fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "keys": [key]
            }))
            .unwrap(),
        )
        .unwrap();
        path
    }

    #[test]
    fn all_detached_release_artifacts_use_one_external_signing_workflow() {
        let root = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[51_u8; 32]);
        let trust = trust_store(root.path(), &signing_key);
        let now = unix_time(NOW).unwrap();
        let stats = verify_trust_store(
            &trust,
            &[
                TrustPurpose::OriginPolicy,
                TrustPurpose::ProcessPolicy,
                TrustPurpose::PluginCatalog,
                TrustPurpose::CutoverDecision,
                TrustPurpose::CutoverEvidence,
            ],
        )
        .unwrap();
        assert_eq!(stats.active, 1);

        for (kind, document) in documents(root.path()) {
            let request = root.path().join(format!("{}.request.json", kind.as_str()));
            let signature = root.path().join(format!("{}.signature", kind.as_str()));
            let envelope = root.path().join(format!("{}.sig.json", kind.as_str()));
            let prepared = prepare(&PrepareOptions {
                kind,
                document: &document,
                key_id: "release-key",
                trust_store: &trust,
                request: &request,
                now,
            })
            .unwrap();
            assert!(!prepared.verified);
            let request_document: SigningRequest =
                serde_json::from_slice(&fs::read(&request).unwrap()).unwrap();
            let payload = BASE64.decode(request_document.payload_base64).unwrap();
            fs::write(
                &signature,
                BASE64.encode(signing_key.sign(&payload).to_bytes()),
            )
            .unwrap();

            let finalized = finalize(&FinalizeOptions {
                kind,
                document: &document,
                request: &request,
                signature: &signature,
                trust_store: &trust,
                envelope: &envelope,
                now,
            })
            .unwrap();
            assert!(finalized.verified);
            assert_eq!(
                verify(kind, &document, &envelope, &trust, now).unwrap(),
                finalized
            );
            let evidence_kind = match kind {
                ArtifactKind::PluginMatrixEvidence => Some(EvidenceAttestationKind::PluginMatrix),
                ArtifactKind::MigrationAuditEvidence => {
                    Some(EvidenceAttestationKind::MigrationAudit)
                }
                ArtifactKind::WindowsPackageEvidence => {
                    Some(EvidenceAttestationKind::WindowsPackage)
                }
                _ => None,
            };
            if let Some(evidence_kind) = evidence_kind {
                verify_evidence_attestation(
                    evidence_kind,
                    &document,
                    &envelope,
                    &trust,
                    "release-key",
                )
                .unwrap();
                assert!(verify_evidence_attestation(
                    evidence_kind,
                    &document,
                    &envelope,
                    &trust,
                    "different-qa-key",
                )
                .is_err());
            }
        }
    }

    #[test]
    fn no_go_decisions_cannot_enter_the_external_signing_workflow() {
        let root = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[59_u8; 32]);
        let trust = trust_store(root.path(), &signing_key);
        let (_, document) = documents(root.path()).pop().unwrap();
        let mut decision: serde_json::Value =
            serde_json::from_slice(&fs::read(&document).unwrap()).unwrap();
        decision["eligible"] = serde_json::json!(false);
        decision["blockerCodes"] = serde_json::json!(["windows-launch-not-verified"]);
        fs::write(&document, serde_json::to_vec_pretty(&decision).unwrap()).unwrap();
        let request = root.path().join("no-go.request.json");

        assert!(prepare(&PrepareOptions {
            kind: ArtifactKind::CutoverDecision,
            document: &document,
            key_id: "release-key",
            trust_store: &trust,
            request: &request,
            now: unix_time(NOW).unwrap(),
        })
        .is_err());
        assert!(!request.exists());
    }

    #[test]
    fn cutover_decision_requires_the_policy_selected_approval_key() {
        let root = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[60_u8; 32]);
        let trust = trust_store(root.path(), &signing_key);
        let (_, document) = documents(root.path()).pop().unwrap();
        let mut decision: serde_json::Value =
            serde_json::from_slice(&fs::read(&document).unwrap()).unwrap();
        decision["approvalSignerKeyId"] = serde_json::json!("other-approval-key");
        fs::write(&document, serde_json::to_vec_pretty(&decision).unwrap()).unwrap();
        let request = root.path().join("wrong-approval-key.request.json");

        assert!(prepare(&PrepareOptions {
            kind: ArtifactKind::CutoverDecision,
            document: &document,
            key_id: "release-key",
            trust_store: &trust,
            request: &request,
            now: unix_time(NOW).unwrap(),
        })
        .is_err());
        assert!(!request.exists());
    }

    #[test]
    fn changed_document_is_rejected_before_an_envelope_is_written() {
        let root = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[52_u8; 32]);
        let trust = trust_store(root.path(), &signing_key);
        let now = unix_time(NOW).unwrap();
        let (kind, document) = documents(root.path()).remove(0);
        let request = root.path().join("request.json");
        prepare(&PrepareOptions {
            kind,
            document: &document,
            key_id: "release-key",
            trust_store: &trust,
            request: &request,
            now,
        })
        .unwrap();
        let request_document: SigningRequest =
            serde_json::from_slice(&fs::read(&request).unwrap()).unwrap();
        let payload = BASE64.decode(request_document.payload_base64).unwrap();
        let signature = root.path().join("signature");
        fs::write(
            &signature,
            BASE64.encode(signing_key.sign(&payload).to_bytes()),
        )
        .unwrap();
        let mut changed: serde_json::Value =
            serde_json::from_slice(&fs::read(&document).unwrap()).unwrap();
        changed["externalOrigins"] = serde_json::json!(["https://newly-added.example.test"]);
        fs::write(&document, serde_json::to_vec_pretty(&changed).unwrap()).unwrap();
        let envelope = root.path().join("envelope.json");

        let error = finalize(&FinalizeOptions {
            kind,
            document: &document,
            request: &request,
            signature: &signature,
            trust_store: &trust,
            envelope: &envelope,
            now,
        })
        .unwrap_err();

        assert!(error.to_string().contains("document changed"));
        assert!(!envelope.exists());
    }

    #[test]
    fn a_key_for_the_wrong_purpose_cannot_create_an_envelope() {
        let root = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[53_u8; 32]);
        let trust = trust_store(root.path(), &signing_key);
        let now = unix_time(NOW).unwrap();
        let (kind, document) = documents(root.path()).remove(0);
        let request = root.path().join("request.json");
        prepare(&PrepareOptions {
            kind,
            document: &document,
            key_id: "release-key",
            trust_store: &trust,
            request: &request,
            now,
        })
        .unwrap();
        let request_document: SigningRequest =
            serde_json::from_slice(&fs::read(&request).unwrap()).unwrap();
        let signature = root.path().join("signature");
        let payload = BASE64.decode(request_document.payload_base64).unwrap();
        fs::write(
            &signature,
            BASE64.encode(signing_key.sign(&payload).to_bytes()),
        )
        .unwrap();
        fs::write(
            &trust,
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "keys": [{
                    "keyId": "release-key",
                    "algorithm": "ed25519",
                    "publicKey": BASE64.encode(signing_key.verifying_key().to_bytes()),
                    "purposes": ["plugin"]
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let envelope = root.path().join("envelope.json");

        let error = finalize(&FinalizeOptions {
            kind,
            document: &document,
            request: &request,
            signature: &signature,
            trust_store: &trust,
            envelope: &envelope,
            now,
        })
        .unwrap_err();

        assert!(error.to_string().contains("not authorized"));
        assert!(!envelope.exists());
    }

    #[test]
    fn retired_keys_cannot_finalize_new_release_documents() {
        let root = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[54_u8; 32]);
        let trust = trust_store(root.path(), &signing_key);
        let now = unix_time(NOW).unwrap();
        let (kind, document) = documents(root.path()).remove(0);
        let request = root.path().join("request.json");
        prepare(&PrepareOptions {
            kind,
            document: &document,
            key_id: "release-key",
            trust_store: &trust,
            request: &request,
            now,
        })
        .unwrap();
        let request_document: SigningRequest =
            serde_json::from_slice(&fs::read(&request).unwrap()).unwrap();
        let payload = BASE64.decode(request_document.payload_base64).unwrap();
        let signature = root.path().join("signature");
        fs::write(
            &signature,
            BASE64.encode(signing_key.sign(&payload).to_bytes()),
        )
        .unwrap();
        trust_store_with_status(root.path(), &signing_key, Some("retired"));
        assert!(verify_trust_store(&trust, &[TrustPurpose::OriginPolicy]).is_err());
        let envelope = root.path().join("envelope.json");

        let error = finalize(&FinalizeOptions {
            kind,
            document: &document,
            request: &request,
            signature: &signature,
            trust_store: &trust,
            envelope: &envelope,
            now,
        })
        .unwrap_err();

        assert!(error.to_string().contains("retired"));
        assert!(!envelope.exists());
    }

    #[test]
    fn retired_keys_are_rejected_before_a_release_request_is_created() {
        let root = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[55_u8; 32]);
        let trust = trust_store_with_status(root.path(), &signing_key, Some("retired"));
        let now = unix_time(NOW).unwrap();
        let (kind, document) = documents(root.path()).remove(0);
        let request = root.path().join("request.json");

        let error = prepare(&PrepareOptions {
            kind,
            document: &document,
            key_id: "release-key",
            trust_store: &trust,
            request: &request,
            now,
        })
        .unwrap_err();

        assert!(error.to_string().contains("retired"));
        assert!(!request.exists());
    }

    #[test]
    fn bare_output_names_use_the_current_directory() {
        assert_eq!(output_parent(Path::new("request.json")), Path::new("."));
    }
}
