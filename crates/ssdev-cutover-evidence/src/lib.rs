use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;
use webplus_plugin_trust::{
    validate_signing_key_id, DetachedSignatureDocument, TrustPurpose, TrustStore,
};

pub const EVIDENCE_SCHEMA_VERSION: u8 = 3;
pub const PLUGIN_MATRIX_EVIDENCE_SCHEMA_VERSION: u8 = 2;
pub const WINDOWS_PACKAGE_EVIDENCE_SCHEMA_VERSION: u8 = 6;
pub const CUTOVER_POLICY_SCHEMA_VERSION: u8 = 7;
pub const CUTOVER_DECISION_SCHEMA_VERSION: u8 = 3;
const MAX_EVIDENCE_BYTES: u64 = 1024 * 1024;
const MAX_DEPLOYMENT_CHECK_BYTES: u64 = 128 * 1024;
const MAX_DEPLOYMENT_CHECK_AGE_SECONDS: u64 = 60 * 60;
const MAX_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_HASHED_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_NAMED_PAYLOADS: usize = 4096;
const MAX_NAMED_PAYLOAD_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceType {
    PluginMatrix,
    MigrationAudit,
    WindowsPackage,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EvidenceAttestationKind {
    PluginMatrix,
    MigrationAudit,
    WindowsPackage,
}

impl EvidenceAttestationKind {
    pub const fn domain(self) -> &'static [u8] {
        match self {
            Self::PluginMatrix => b"SSDEV-PLUGIN-MATRIX-EVIDENCE\0",
            Self::MigrationAudit => b"SSDEV-MIGRATION-AUDIT-EVIDENCE\0",
            Self::WindowsPackage => b"SSDEV-WINDOWS-PACKAGE-EVIDENCE\0",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginMatrixEvidence {
    pub schema_version: u8,
    pub evidence_type: EvidenceType,
    pub source_revision: String,
    pub source_dirty: bool,
    pub executed_at_unix_seconds: u64,
    pub environment: String,
    pub runner_os: String,
    pub runner_architecture: String,
    pub release_set_spec_sha256: String,
    pub package_set_sha256: String,
    pub plugin_set_sha256: String,
    pub trust_store_sha256: String,
    pub matrix_sha256: String,
    pub x86_host_sha256: String,
    pub x64_host_sha256: String,
    pub plugin_count: u32,
    pub service_count: u32,
    pub method_count: u32,
    pub enabled_case_count: u32,
    pub passed: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum HttpEvidenceLevel {
    ConfirmedRuntime,
    StaticReferences,
    NotObserved,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MigrationAuditEvidence {
    pub schema_version: u8,
    pub evidence_type: EvidenceType,
    pub source_revision: String,
    pub source_dirty: bool,
    pub executed_at_unix_seconds: u64,
    pub environment: String,
    pub runner_os: String,
    pub runner_architecture: String,
    pub report_sha256: String,
    pub pilot_material_set_sha256: String,
    pub origin_policy_sha256: String,
    pub config_files: u32,
    pub plugin_directories: u32,
    pub service_count: u32,
    pub key_binding_count: u32,
    pub browser_asset_roots: u32,
    pub browser_asset_files_scanned: u32,
    pub browser_har_files: u32,
    pub browser_har_requests_scanned: u32,
    pub insecure_http_origin_count: u32,
    pub authorized_insecure_http_origin_count: u32,
    pub webplus_http_evidence: HttpEvidenceLevel,
    pub desktop_callback_http_evidence: HttpEvidenceLevel,
    pub critical_findings: u32,
    pub warning_findings: u32,
    pub info_findings: u32,
    pub finding_code_counts: BTreeMap<String, u32>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsPackageEvidence {
    pub schema_version: u8,
    pub evidence_type: EvidenceType,
    pub source_revision: String,
    pub source_dirty: bool,
    pub executed_at_unix_seconds: u64,
    pub environment: String,
    pub runner_os: String,
    pub runner_architecture: String,
    pub release_metadata_sha256: String,
    pub artifact_manifest_sha256: String,
    pub plugin_trust_store_sha256: String,
    pub origin_policy_sha256: String,
    pub x86_host_sha256: String,
    pub x64_host_sha256: String,
    pub deployment_check_sha256: Option<String>,
    pub deployment_check_generated_at_unix_ms: Option<u64>,
    pub app_version: String,
    pub authenticode_required: bool,
    pub authenticode_verified: bool,
    pub nsis_install_verified: bool,
    pub msi_install_verified: bool,
    pub launch_verified: bool,
    pub upgrade_verified: bool,
    pub rollback_verified: bool,
    pub previous_app_version: Option<String>,
    pub previous_release_metadata_sha256: Option<String>,
    pub previous_artifact_manifest_sha256: Option<String>,
    pub passed: bool,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentCheckRecord {
    pub schema_version: u16,
    pub generated_at_unix_ms: u64,
    pub desktop_version: String,
    pub os: String,
    pub architecture: String,
    pub evidence_level: String,
    pub report: DeploymentCheckRecordReport,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentCheckRecordReport {
    pub deep: bool,
    pub deep_available: bool,
    pub ready: bool,
    pub delivery_ready: bool,
    pub passed: usize,
    pub warnings: usize,
    pub failures: usize,
    pub items: Vec<DeploymentCheckRecordItem>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentCheckRecordItem {
    pub id: String,
    pub label: String,
    pub status: DeploymentCheckRecordStatus,
    pub summary: String,
    pub action: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum DeploymentCheckRecordStatus {
    Pass,
    Warning,
    Fail,
    Info,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MigrationCoverageMinimums {
    pub config_files: u32,
    pub plugin_directories: u32,
    pub services: u32,
    pub key_bindings: u32,
    pub browser_asset_roots: u32,
    pub browser_asset_files_scanned: u32,
    pub browser_har_files: u32,
    pub browser_har_requests_scanned: u32,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductionCutoverPolicy {
    pub schema_version: u8,
    pub target_source_revision: String,
    pub expected_app_version: String,
    pub expected_previous_app_version: String,
    pub maximum_evidence_age_seconds: u64,
    pub expected_windows_artifact_manifest_sha256: String,
    pub expected_previous_windows_artifact_manifest_sha256: String,
    pub expected_previous_release_metadata_sha256: String,
    pub expected_plugin_release_set_spec_sha256: String,
    pub expected_plugin_package_set_sha256: String,
    pub expected_plugin_trust_store_sha256: String,
    pub expected_evidence_trust_store_sha256: String,
    pub expected_plugin_matrix_sha256: String,
    pub expected_pilot_material_set_sha256: String,
    pub expected_origin_policy_sha256: String,
    pub migration_coverage_minimums: MigrationCoverageMinimums,
    pub plugin_matrix_signer_key_id: String,
    pub migration_audit_signer_key_id: String,
    pub windows_package_signer_key_id: String,
    pub cutover_decision_signer_key_id: String,
}

impl ProductionCutoverPolicy {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.schema_version != CUTOVER_POLICY_SCHEMA_VERSION {
            return Err(EvidenceError::Invalid(
                "production cutover policy uses an unsupported schema".into(),
            ));
        }
        validate_git_revision(&self.target_source_revision)?;
        let expected_version = Version::parse(&self.expected_app_version).map_err(|_| {
            EvidenceError::Invalid("expectedAppVersion must be a semantic version".into())
        })?;
        let previous_version =
            Version::parse(&self.expected_previous_app_version).map_err(|_| {
                EvidenceError::Invalid(
                    "expectedPreviousAppVersion must be a semantic version".into(),
                )
            })?;
        if previous_version >= expected_version {
            return Err(EvidenceError::Invalid(
                "expectedPreviousAppVersion must be lower than expectedAppVersion".into(),
            ));
        }
        if !(60..=31 * 24 * 60 * 60).contains(&self.maximum_evidence_age_seconds) {
            return Err(EvidenceError::Invalid(
                "maximumEvidenceAgeSeconds must be between 60 seconds and 31 days".into(),
            ));
        }
        if [
            &self.expected_windows_artifact_manifest_sha256,
            &self.expected_previous_windows_artifact_manifest_sha256,
            &self.expected_previous_release_metadata_sha256,
            &self.expected_plugin_release_set_spec_sha256,
            &self.expected_plugin_package_set_sha256,
            &self.expected_plugin_trust_store_sha256,
            &self.expected_evidence_trust_store_sha256,
            &self.expected_plugin_matrix_sha256,
            &self.expected_pilot_material_set_sha256,
            &self.expected_origin_policy_sha256,
        ]
        .into_iter()
        .any(|digest| !is_sha256(digest))
        {
            return Err(EvidenceError::Invalid(
                "expected production input hashes must be lowercase SHA-256 digests".into(),
            ));
        }
        for key_id in [
            &self.plugin_matrix_signer_key_id,
            &self.migration_audit_signer_key_id,
            &self.windows_package_signer_key_id,
            &self.cutover_decision_signer_key_id,
        ] {
            validate_signing_key_id(key_id)?;
        }
        let distinct_signers = BTreeSet::from([
            self.plugin_matrix_signer_key_id.as_str(),
            self.migration_audit_signer_key_id.as_str(),
            self.windows_package_signer_key_id.as_str(),
            self.cutover_decision_signer_key_id.as_str(),
        ]);
        if distinct_signers.len() != 4 {
            return Err(EvidenceError::Invalid(
                "production cutover requires distinct signer key IDs for all four duties".into(),
            ));
        }
        Ok(())
    }

    pub fn from_bytes_for_signing(bytes: &[u8]) -> Result<Self, EvidenceError> {
        if bytes.len() as u64 > MAX_EVIDENCE_BYTES {
            return Err(EvidenceError::Invalid(
                "production cutover policy exceeds the safety limit".into(),
            ));
        }
        let policy: Self = serde_json::from_slice(bytes)?;
        policy.validate()?;
        Ok(policy)
    }
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CutoverDecision {
    pub schema_version: u8,
    pub target_source_revision: String,
    pub app_version: String,
    pub approval_signer_key_id: String,
    pub evaluated_at_unix_seconds: u64,
    pub policy_sha256: String,
    pub policy_attestation_sha256: String,
    pub evidence_trust_store_sha256: String,
    pub approval_trust_store_sha256: String,
    pub plugin_matrix_evidence_sha256: String,
    pub migration_audit_evidence_sha256: String,
    pub windows_package_evidence_sha256: String,
    pub plugin_matrix_attestation_sha256: String,
    pub migration_audit_attestation_sha256: String,
    pub windows_package_attestation_sha256: String,
    pub eligible: bool,
    pub blocker_codes: Vec<String>,
}

impl CutoverDecision {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.schema_version != CUTOVER_DECISION_SCHEMA_VERSION {
            return Err(EvidenceError::Invalid(
                "cutover decision uses an unsupported schema".into(),
            ));
        }
        validate_git_revision(&self.target_source_revision)?;
        Version::parse(&self.app_version).map_err(|_| {
            EvidenceError::Invalid("cutover appVersion must be a semantic version".into())
        })?;
        validate_signing_key_id(&self.approval_signer_key_id)?;
        if self.evaluated_at_unix_seconds == 0 {
            return Err(EvidenceError::Invalid(
                "cutover evaluation time must be positive".into(),
            ));
        }
        for digest in [
            &self.policy_sha256,
            &self.policy_attestation_sha256,
            &self.evidence_trust_store_sha256,
            &self.approval_trust_store_sha256,
            &self.plugin_matrix_evidence_sha256,
            &self.migration_audit_evidence_sha256,
            &self.windows_package_evidence_sha256,
            &self.plugin_matrix_attestation_sha256,
            &self.migration_audit_attestation_sha256,
            &self.windows_package_attestation_sha256,
        ] {
            if !is_sha256(digest) {
                return Err(EvidenceError::Invalid(
                    "cutover input hashes must be lowercase SHA-256 digests".into(),
                ));
            }
        }
        if self.blocker_codes.len() > 64
            || self.blocker_codes.windows(2).any(|pair| pair[0] >= pair[1])
            || self.blocker_codes.iter().any(|code| !is_finding_code(code))
            || self.eligible != self.blocker_codes.is_empty()
        {
            return Err(EvidenceError::Invalid(
                "cutover blockers must be unique, sorted, bounded, and agree with eligibility"
                    .into(),
            ));
        }
        Ok(())
    }

    pub fn from_bytes_for_signing(bytes: &[u8]) -> Result<Self, EvidenceError> {
        if bytes.len() as u64 > MAX_EVIDENCE_BYTES {
            return Err(EvidenceError::Invalid(
                "cutover decision exceeds the safety limit".into(),
            ));
        }
        let decision: Self = serde_json::from_slice(bytes)?;
        decision.validate()?;
        if !decision.eligible {
            return Err(EvidenceError::Invalid(
                "a no-go cutover decision cannot be signed for release".into(),
            ));
        }
        Ok(decision)
    }
}

impl WindowsPackageEvidence {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.schema_version != WINDOWS_PACKAGE_EVIDENCE_SCHEMA_VERSION
            || self.evidence_type != EvidenceType::WindowsPackage
        {
            return Err(EvidenceError::Invalid(
                "Windows package evidence uses an unsupported schema or type".into(),
            ));
        }
        validate_common_execution(
            &self.source_revision,
            self.executed_at_unix_seconds,
            &self.environment,
            &self.runner_os,
            &self.runner_architecture,
        )?;
        if self.runner_os != "windows" || self.runner_architecture != "x86_64" {
            return Err(EvidenceError::Invalid(
                "Windows package evidence must be produced by a Windows x86_64 runner".into(),
            ));
        }
        if [
            &self.release_metadata_sha256,
            &self.artifact_manifest_sha256,
            &self.plugin_trust_store_sha256,
            &self.origin_policy_sha256,
            &self.x86_host_sha256,
            &self.x64_host_sha256,
        ]
        .into_iter()
        .any(|digest| !is_sha256(digest))
        {
            return Err(EvidenceError::Invalid(
                "Windows package input hashes must be lowercase SHA-256 digests".into(),
            ));
        }
        match (
            self.deployment_check_sha256.as_deref(),
            self.deployment_check_generated_at_unix_ms,
        ) {
            (None, None) => {}
            (Some(digest), Some(generated_at_unix_ms)) => {
                if !is_sha256(digest) || generated_at_unix_ms == 0 {
                    return Err(EvidenceError::Invalid(
                        "deployment check binding must use a lowercase SHA-256 digest and non-zero timestamp".into(),
                    ));
                }
                let generated_at_unix_seconds = generated_at_unix_ms / 1_000;
                if generated_at_unix_seconds > self.executed_at_unix_seconds.saturating_add(300)
                    || self
                        .executed_at_unix_seconds
                        .saturating_sub(generated_at_unix_seconds)
                        > MAX_DEPLOYMENT_CHECK_AGE_SECONDS
                {
                    return Err(EvidenceError::Invalid(
                        "deployment check record must be generated within one hour of package evidence".into(),
                    ));
                }
            }
            _ => {
                return Err(EvidenceError::Invalid(
                    "deployment check digest and timestamp must be present together".into(),
                ));
            }
        }
        if self.rollback_verified
            && (!self.upgrade_verified || !self.launch_verified || !self.nsis_install_verified)
        {
            return Err(EvidenceError::Invalid(
                "rollback requires verified NSIS, launch, and previous-version upgrade results"
                    .into(),
            ));
        }
        let app_version = Version::parse(&self.app_version).map_err(|_| {
            EvidenceError::Invalid("appVersion must be a valid semantic version".into())
        })?;
        if !self.nsis_install_verified && !self.msi_install_verified {
            return Err(EvidenceError::Invalid(
                "at least one Windows installer must have passed".into(),
            ));
        }
        if self.authenticode_verified && !self.authenticode_required {
            return Err(EvidenceError::Invalid(
                "Authenticode cannot be verified when release metadata marks it optional".into(),
            ));
        }
        match (
            self.upgrade_verified,
            self.previous_app_version.as_deref(),
            self.previous_release_metadata_sha256.as_deref(),
            self.previous_artifact_manifest_sha256.as_deref(),
        ) {
            (false, None, None, None) => {}
            (true, Some(previous), Some(previous_metadata_hash), Some(previous_manifest_hash)) => {
                let previous = Version::parse(previous).map_err(|_| {
                    EvidenceError::Invalid(
                        "previousAppVersion must be a valid semantic version".into(),
                    )
                })?;
                if previous >= app_version
                    || !is_sha256(previous_metadata_hash)
                    || !is_sha256(previous_manifest_hash)
                {
                    return Err(EvidenceError::Invalid(
                        "verified upgrade must bind a lower previous version, metadata hash, and artifact manifest hash".into(),
                    ));
                }
            }
            _ => {
                return Err(EvidenceError::Invalid(
                    "upgrade fields must be present together".into(),
                ));
            }
        }
        if !self.passed {
            return Err(EvidenceError::Invalid(
                "Windows package evidence must represent a passing requested run".into(),
            ));
        }
        Ok(())
    }
}

impl DeploymentCheckRecord {
    pub fn validate_for_delivery(&self, expected_version: &str) -> Result<(), EvidenceError> {
        if self.schema_version != 1
            || self.evidence_level != "unsigned-local-record"
            || self.generated_at_unix_ms == 0
            || self.os != "windows"
            || !matches!(self.architecture.as_str(), "x86" | "x86_64")
            || self.desktop_version != expected_version
            || Version::parse(&self.desktop_version).is_err()
        {
            return Err(EvidenceError::Invalid(
                "deployment check record metadata does not match the candidate Windows release"
                    .into(),
            ));
        }
        let report = &self.report;
        if !report.deep
            || !report.deep_available
            || !report.ready
            || !report.delivery_ready
            || report.failures != 0
            || report.items.len() != 13
        {
            return Err(EvidenceError::Invalid(
                "deployment check record is not a passing Windows deep delivery check".into(),
            ));
        }
        let passed = report
            .items
            .iter()
            .filter(|item| item.status == DeploymentCheckRecordStatus::Pass)
            .count();
        let warnings = report
            .items
            .iter()
            .filter(|item| item.status == DeploymentCheckRecordStatus::Warning)
            .count();
        let failures = report
            .items
            .iter()
            .filter(|item| item.status == DeploymentCheckRecordStatus::Fail)
            .count();
        if (report.passed, report.warnings, report.failures) != (passed, warnings, failures) {
            return Err(EvidenceError::Invalid(
                "deployment check record counters do not match its items".into(),
            ));
        }
        let expected_ids = BTreeSet::from([
            "webview-runtime",
            "business-frontend",
            "project-config",
            "origin-policy",
            "plugin-trust",
            "plugin-hosts",
            "plugin-inventory",
            "plugin-route-policy",
            "tracked-invocations",
            "plugin-preflight",
            "diagnostics",
            "managed-processes",
            "app-update",
        ]);
        let actual_ids = report
            .items
            .iter()
            .map(|item| item.id.as_str())
            .collect::<BTreeSet<_>>();
        if actual_ids != expected_ids
            || !report.items.iter().any(|item| {
                item.id == "business-frontend" && item.status == DeploymentCheckRecordStatus::Pass
            })
            || report.items.iter().any(|item| {
                item.label.is_empty()
                    || item.label.len() > 128
                    || item.summary.is_empty()
                    || item.summary.len() > 2_048
                    || item
                        .action
                        .as_ref()
                        .is_some_and(|action| action.is_empty() || action.len() > 2_048)
            })
        {
            return Err(EvidenceError::Invalid(
                "deployment check record does not contain the complete bounded delivery checklist"
                    .into(),
            ));
        }
        Ok(())
    }
}

pub fn load_delivery_ready_deployment_check(
    path: &Path,
    expected_version: &str,
) -> Result<(DeploymentCheckRecord, String), EvidenceError> {
    let bytes = read_bounded_bytes(path, MAX_DEPLOYMENT_CHECK_BYTES)?;
    let digest = sha256_bytes(&bytes);
    let record: DeploymentCheckRecord = serde_json::from_slice(&bytes)?;
    record.validate_for_delivery(expected_version)?;
    Ok((record, digest))
}

impl MigrationAuditEvidence {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.schema_version != EVIDENCE_SCHEMA_VERSION
            || self.evidence_type != EvidenceType::MigrationAudit
        {
            return Err(EvidenceError::Invalid(
                "migration audit evidence uses an unsupported schema or type".into(),
            ));
        }
        validate_common_execution(
            &self.source_revision,
            self.executed_at_unix_seconds,
            &self.environment,
            &self.runner_os,
            &self.runner_architecture,
        )?;
        if !is_sha256(&self.report_sha256)
            || !is_sha256(&self.pilot_material_set_sha256)
            || !is_sha256(&self.origin_policy_sha256)
        {
            return Err(EvidenceError::Invalid(
                "migration report, pilot material set, and origin policy hashes must be lowercase SHA-256 digests".into(),
            ));
        }
        if self.authorized_insecure_http_origin_count > self.insecure_http_origin_count {
            return Err(EvidenceError::Invalid(
                "authorized HTTP origin count cannot exceed the audited HTTP origin count".into(),
            ));
        }
        if self.finding_code_counts.len() > 4096
            || self
                .finding_code_counts
                .iter()
                .any(|(code, count)| *count == 0 || !is_finding_code(code))
        {
            return Err(EvidenceError::Invalid(
                "findingCodeCounts contains invalid codes or counts".into(),
            ));
        }
        let total_codes = self
            .finding_code_counts
            .values()
            .try_fold(0_u32, |total, count| total.checked_add(*count))
            .ok_or_else(|| EvidenceError::Invalid("finding counts overflowed".into()))?;
        let total_severities = self
            .critical_findings
            .checked_add(self.warning_findings)
            .and_then(|total| total.checked_add(self.info_findings))
            .ok_or_else(|| EvidenceError::Invalid("severity counts overflowed".into()))?;
        if total_codes != total_severities {
            return Err(EvidenceError::Invalid(
                "finding code and severity totals do not match".into(),
            ));
        }
        if self.browser_asset_roots == 0 && self.browser_asset_files_scanned != 0 {
            return Err(EvidenceError::Invalid(
                "browser asset files cannot be recorded without an asset root".into(),
            ));
        }
        if self.browser_har_files == 0 && self.browser_har_requests_scanned != 0 {
            return Err(EvidenceError::Invalid(
                "HAR requests cannot be recorded without a HAR file".into(),
            ));
        }
        Ok(())
    }
}

impl PluginMatrixEvidence {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.schema_version != PLUGIN_MATRIX_EVIDENCE_SCHEMA_VERSION
            || self.evidence_type != EvidenceType::PluginMatrix
        {
            return Err(EvidenceError::Invalid(
                "plugin matrix evidence uses an unsupported schema or type".into(),
            ));
        }
        validate_common_execution(
            &self.source_revision,
            self.executed_at_unix_seconds,
            &self.environment,
            &self.runner_os,
            &self.runner_architecture,
        )?;
        if self.runner_os != "windows" || self.runner_architecture != "x86_64" {
            return Err(EvidenceError::Invalid(
                "real plugin evidence must be produced by a Windows x86_64 runner".into(),
            ));
        }
        for (name, digest) in [
            ("releaseSetSpecSha256", &self.release_set_spec_sha256),
            ("packageSetSha256", &self.package_set_sha256),
            ("pluginSetSha256", &self.plugin_set_sha256),
            ("trustStoreSha256", &self.trust_store_sha256),
            ("matrixSha256", &self.matrix_sha256),
            ("x86HostSha256", &self.x86_host_sha256),
            ("x64HostSha256", &self.x64_host_sha256),
        ] {
            if !is_sha256(digest) {
                return Err(EvidenceError::Invalid(format!(
                    "{name} must be a lowercase SHA-256 digest"
                )));
            }
        }
        if self.plugin_count == 0
            || self.service_count == 0
            || self.method_count == 0
            || self.enabled_case_count < self.method_count
            || !self.passed
        {
            return Err(EvidenceError::Invalid(
                "plugin evidence must pass and cover non-empty plugins, services, and methods"
                    .into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("cutover evidence is invalid: {0}")]
    Invalid(String),
    #[error("cutover evidence output already exists")]
    OutputExists,
    #[error("cutover evidence I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("cutover evidence JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("cutover evidence trust verification failed: {0}")]
    Trust(#[from] webplus_plugin_trust::TrustError),
}

pub fn prepare_new_output(path: &Path) -> Result<PathBuf, EvidenceError> {
    match fs::symlink_metadata(path) {
        Ok(_) => return Err(EvidenceError::OutputExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(EvidenceError::Invalid(
            "evidence output parent must be a real existing directory".into(),
        ));
    }
    let parent = fs::canonicalize(parent)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| EvidenceError::Invalid("evidence output must include a file name".into()))?;
    Ok(parent.join(file_name))
}

pub fn write_plugin_matrix_evidence(
    path: &Path,
    evidence: &PluginMatrixEvidence,
) -> Result<(), EvidenceError> {
    evidence.validate()?;
    write_new_json(path, evidence)
}

pub fn load_plugin_matrix_evidence(path: &Path) -> Result<PluginMatrixEvidence, EvidenceError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_EVIDENCE_BYTES
    {
        return Err(EvidenceError::Invalid(
            "evidence must be a bounded regular file".into(),
        ));
    }
    let evidence = serde_json::from_reader(BufReader::new(File::open(path)?))?;
    PluginMatrixEvidence::validate(&evidence)?;
    Ok(evidence)
}

pub fn write_migration_audit_evidence(
    path: &Path,
    evidence: &MigrationAuditEvidence,
) -> Result<(), EvidenceError> {
    evidence.validate()?;
    write_new_json(path, evidence)
}

pub fn load_migration_audit_evidence(path: &Path) -> Result<MigrationAuditEvidence, EvidenceError> {
    let evidence = read_bounded_json(path)?;
    MigrationAuditEvidence::validate(&evidence)?;
    Ok(evidence)
}

pub fn write_windows_package_evidence(
    path: &Path,
    evidence: &WindowsPackageEvidence,
) -> Result<(), EvidenceError> {
    evidence.validate()?;
    write_new_json(path, evidence)
}

pub fn load_windows_package_evidence(path: &Path) -> Result<WindowsPackageEvidence, EvidenceError> {
    let evidence = read_bounded_json(path)?;
    WindowsPackageEvidence::validate(&evidence)?;
    Ok(evidence)
}

pub fn evidence_attestation_signing_payload(
    kind: EvidenceAttestationKind,
    document: &[u8],
) -> Result<Vec<u8>, EvidenceError> {
    if document.len() as u64 > MAX_EVIDENCE_BYTES {
        return Err(EvidenceError::Invalid(
            "attested evidence exceeds the safety limit".into(),
        ));
    }
    match kind {
        EvidenceAttestationKind::PluginMatrix => {
            let evidence: PluginMatrixEvidence = serde_json::from_slice(document)?;
            evidence.validate()?;
        }
        EvidenceAttestationKind::MigrationAudit => {
            let evidence: MigrationAuditEvidence = serde_json::from_slice(document)?;
            evidence.validate()?;
        }
        EvidenceAttestationKind::WindowsPackage => {
            let evidence: WindowsPackageEvidence = serde_json::from_slice(document)?;
            evidence.validate()?;
        }
    }
    let digest = Sha256::digest(document);
    let mut payload = kind.domain().to_vec();
    payload.extend_from_slice(&digest);
    Ok(payload)
}

pub fn verify_evidence_attestation(
    kind: EvidenceAttestationKind,
    evidence_path: &Path,
    envelope_path: &Path,
    trust_store_path: &Path,
    expected_key_id: &str,
) -> Result<(), EvidenceError> {
    validate_signing_key_id(expected_key_id)?;
    let document = read_bounded_bytes(evidence_path, MAX_EVIDENCE_BYTES)?;
    let payload = evidence_attestation_signing_payload(kind, &document)?;
    let envelope: DetachedSignatureDocument =
        serde_json::from_slice(&read_bounded_bytes(envelope_path, MAX_EVIDENCE_BYTES)?)?;
    envelope.validate()?;
    if envelope.key_id != expected_key_id {
        return Err(EvidenceError::Invalid(
            "evidence attestation signer does not match the production policy".into(),
        ));
    }
    TrustStore::load(trust_store_path)?.verify_detached_for_issuance(
        TrustPurpose::CutoverEvidence,
        &envelope.key_id,
        &payload,
        &envelope.signature,
    )?;
    Ok(())
}

pub fn verify_production_cutover_policy_attestation(
    policy_path: &Path,
    envelope_path: &Path,
    trust_store_path: &Path,
) -> Result<ProductionCutoverPolicy, EvidenceError> {
    let document = read_bounded_bytes(policy_path, MAX_EVIDENCE_BYTES)?;
    let policy = ProductionCutoverPolicy::from_bytes_for_signing(&document)?;
    let envelope: DetachedSignatureDocument =
        serde_json::from_slice(&read_bounded_bytes(envelope_path, MAX_EVIDENCE_BYTES)?)?;
    envelope.validate()?;
    if envelope.key_id != policy.cutover_decision_signer_key_id {
        return Err(EvidenceError::Invalid(
            "cutover policy signer does not match the approved release duty".into(),
        ));
    }
    if sha256_file(trust_store_path)? != policy.expected_plugin_trust_store_sha256 {
        return Err(EvidenceError::Invalid(
            "cutover policy approval trust store does not match the approved release trust root"
                .into(),
        ));
    }
    TrustStore::load(trust_store_path)?.verify_detached_for_issuance(
        TrustPurpose::CutoverDecision,
        &envelope.key_id,
        &cutover_policy_signing_payload(&document)?,
        &envelope.signature,
    )?;
    Ok(policy)
}

pub fn load_production_cutover_policy(
    path: &Path,
) -> Result<ProductionCutoverPolicy, EvidenceError> {
    let policy = read_bounded_json(path)?;
    ProductionCutoverPolicy::validate(&policy)?;
    Ok(policy)
}

pub fn write_production_cutover_policy(
    path: &Path,
    policy: &ProductionCutoverPolicy,
) -> Result<(), EvidenceError> {
    policy.validate()?;
    write_new_json(path, policy)
}

#[derive(Debug)]
pub struct ProductionCutoverInputs<'a> {
    pub policy: &'a ProductionCutoverPolicy,
    pub policy_sha256: String,
    pub policy_attestation_sha256: String,
    pub evidence_trust_store_sha256: String,
    pub approval_trust_store_sha256: String,
    pub plugin: &'a PluginMatrixEvidence,
    pub plugin_sha256: String,
    pub plugin_attestation_sha256: String,
    pub migration: &'a MigrationAuditEvidence,
    pub migration_sha256: String,
    pub migration_attestation_sha256: String,
    pub windows: &'a WindowsPackageEvidence,
    pub windows_sha256: String,
    pub windows_attestation_sha256: String,
}

pub fn evaluate_production_cutover(
    inputs: ProductionCutoverInputs<'_>,
    evaluated_at_unix_seconds: u64,
) -> Result<CutoverDecision, EvidenceError> {
    let ProductionCutoverInputs {
        policy,
        policy_sha256,
        policy_attestation_sha256,
        evidence_trust_store_sha256,
        approval_trust_store_sha256,
        plugin,
        plugin_sha256,
        plugin_attestation_sha256,
        migration,
        migration_sha256,
        migration_attestation_sha256,
        windows,
        windows_sha256,
        windows_attestation_sha256,
    } = inputs;
    policy.validate()?;
    plugin.validate()?;
    migration.validate()?;
    windows.validate()?;
    for digest in [
        &policy_sha256,
        &policy_attestation_sha256,
        &evidence_trust_store_sha256,
        &approval_trust_store_sha256,
        &plugin_sha256,
        &migration_sha256,
        &windows_sha256,
        &plugin_attestation_sha256,
        &migration_attestation_sha256,
        &windows_attestation_sha256,
    ] {
        if !is_sha256(digest) {
            return Err(EvidenceError::Invalid(
                "cutover inputs must be bound by lowercase SHA-256 digests".into(),
            ));
        }
    }
    if evaluated_at_unix_seconds == 0 {
        return Err(EvidenceError::Invalid(
            "cutover evaluation time must be positive".into(),
        ));
    }

    let mut blockers = std::collections::BTreeSet::new();
    if evidence_trust_store_sha256 != policy.expected_evidence_trust_store_sha256 {
        blockers.insert("evidence-trust-store-mismatch".into());
    }
    if approval_trust_store_sha256 != policy.expected_plugin_trust_store_sha256 {
        blockers.insert("approval-trust-store-mismatch".into());
    }
    for (name, revision, dirty, executed_at) in [
        (
            "plugin-matrix",
            plugin.source_revision.as_str(),
            plugin.source_dirty,
            plugin.executed_at_unix_seconds,
        ),
        (
            "migration-audit",
            migration.source_revision.as_str(),
            migration.source_dirty,
            migration.executed_at_unix_seconds,
        ),
        (
            "windows-package",
            windows.source_revision.as_str(),
            windows.source_dirty,
            windows.executed_at_unix_seconds,
        ),
    ] {
        if revision != policy.target_source_revision {
            blockers.insert(format!("{name}-source-mismatch"));
        }
        if dirty {
            blockers.insert(format!("{name}-dirty-source"));
        }
        if executed_at > evaluated_at_unix_seconds.saturating_add(300) {
            blockers.insert(format!("{name}-future-timestamp"));
        } else if evaluated_at_unix_seconds.saturating_sub(executed_at)
            > policy.maximum_evidence_age_seconds
        {
            blockers.insert(format!("{name}-stale"));
        }
    }
    if plugin.release_set_spec_sha256 != policy.expected_plugin_release_set_spec_sha256 {
        blockers.insert("plugin-release-set-spec-mismatch".into());
    }
    if plugin.package_set_sha256 != policy.expected_plugin_package_set_sha256 {
        blockers.insert("plugin-package-set-mismatch".into());
    }
    if plugin.trust_store_sha256 != policy.expected_plugin_trust_store_sha256 {
        blockers.insert("plugin-trust-store-mismatch".into());
    }
    if plugin.matrix_sha256 != policy.expected_plugin_matrix_sha256 {
        blockers.insert("plugin-matrix-mismatch".into());
    }
    if migration.origin_policy_sha256 != policy.expected_origin_policy_sha256 {
        blockers.insert("migration-origin-policy-mismatch".into());
    }
    if migration.pilot_material_set_sha256 != policy.expected_pilot_material_set_sha256 {
        blockers.insert("migration-pilot-material-set-mismatch".into());
    }
    if windows.origin_policy_sha256 != policy.expected_origin_policy_sha256 {
        blockers.insert("windows-origin-policy-mismatch".into());
    }
    if migration.authorized_insecure_http_origin_count != migration.insecure_http_origin_count {
        blockers.insert("migration-http-origin-authorization-incomplete".into());
    }
    let minimums = &policy.migration_coverage_minimums;
    for (actual, minimum, blocker) in [
        (
            migration.config_files,
            minimums.config_files,
            "migration-config-files-below-policy",
        ),
        (
            migration.plugin_directories,
            minimums.plugin_directories,
            "migration-plugin-directories-below-policy",
        ),
        (
            migration.service_count,
            minimums.services,
            "migration-services-below-policy",
        ),
        (
            migration.key_binding_count,
            minimums.key_bindings,
            "migration-key-bindings-below-policy",
        ),
        (
            migration.browser_asset_roots,
            minimums.browser_asset_roots,
            "migration-browser-asset-roots-below-policy",
        ),
        (
            migration.browser_asset_files_scanned,
            minimums.browser_asset_files_scanned,
            "migration-browser-asset-files-below-policy",
        ),
        (
            migration.browser_har_files,
            minimums.browser_har_files,
            "migration-browser-har-files-below-policy",
        ),
        (
            migration.browser_har_requests_scanned,
            minimums.browser_har_requests_scanned,
            "migration-browser-har-requests-below-policy",
        ),
    ] {
        if actual < minimum {
            blockers.insert(blocker.into());
        }
    }
    if migration.browser_asset_roots == 0 || migration.browser_asset_files_scanned == 0 {
        blockers.insert("browser-assets-not-covered".into());
    }
    if migration.browser_har_files == 0 || migration.browser_har_requests_scanned == 0 {
        blockers.insert("browser-har-not-covered".into());
    }
    if migration.webplus_http_evidence != HttpEvidenceLevel::NotObserved {
        blockers.insert("legacy-webplus-http-observed".into());
    }
    if migration.desktop_callback_http_evidence != HttpEvidenceLevel::NotObserved {
        blockers.insert("legacy-desktop-http-observed".into());
    }
    if migration.critical_findings != 0 {
        blockers.insert("migration-critical-findings".into());
    }
    if migration.warning_findings != 0 {
        blockers.insert("migration-warning-findings".into());
    }
    if windows.app_version != policy.expected_app_version {
        blockers.insert("windows-app-version-mismatch".into());
    }
    if windows.previous_app_version.as_deref()
        != Some(policy.expected_previous_app_version.as_str())
    {
        blockers.insert("windows-previous-app-version-mismatch".into());
    }
    if windows.artifact_manifest_sha256 != policy.expected_windows_artifact_manifest_sha256 {
        blockers.insert("windows-artifact-manifest-mismatch".into());
    }
    if windows.previous_artifact_manifest_sha256.as_deref()
        != Some(
            policy
                .expected_previous_windows_artifact_manifest_sha256
                .as_str(),
        )
    {
        blockers.insert("windows-previous-artifact-manifest-mismatch".into());
    }
    if windows.previous_release_metadata_sha256.as_deref()
        != Some(policy.expected_previous_release_metadata_sha256.as_str())
    {
        blockers.insert("windows-previous-release-metadata-mismatch".into());
    }
    if windows.plugin_trust_store_sha256 != plugin.trust_store_sha256 {
        blockers.insert("windows-plugin-trust-store-mismatch".into());
    }
    if windows.x86_host_sha256 != plugin.x86_host_sha256 {
        blockers.insert("windows-x86-host-mismatch".into());
    }
    if windows.x64_host_sha256 != plugin.x64_host_sha256 {
        blockers.insert("windows-x64-host-mismatch".into());
    }
    if !windows.authenticode_required || !windows.authenticode_verified {
        blockers.insert("windows-authenticode-not-verified".into());
    }
    if !windows.nsis_install_verified {
        blockers.insert("windows-nsis-not-verified".into());
    }
    if !windows.launch_verified {
        blockers.insert("windows-launch-not-verified".into());
    }
    if windows.deployment_check_sha256.is_none() {
        blockers.insert("windows-business-frontend-not-verified".into());
    }
    if !windows.upgrade_verified {
        blockers.insert("windows-upgrade-not-verified".into());
    }
    if !windows.rollback_verified {
        blockers.insert("windows-rollback-not-verified".into());
    }
    let decision = CutoverDecision {
        schema_version: CUTOVER_DECISION_SCHEMA_VERSION,
        target_source_revision: policy.target_source_revision.clone(),
        app_version: policy.expected_app_version.clone(),
        approval_signer_key_id: policy.cutover_decision_signer_key_id.clone(),
        evaluated_at_unix_seconds,
        policy_sha256,
        policy_attestation_sha256,
        evidence_trust_store_sha256,
        approval_trust_store_sha256,
        plugin_matrix_evidence_sha256: plugin_sha256,
        migration_audit_evidence_sha256: migration_sha256,
        windows_package_evidence_sha256: windows_sha256,
        plugin_matrix_attestation_sha256: plugin_attestation_sha256,
        migration_audit_attestation_sha256: migration_attestation_sha256,
        windows_package_attestation_sha256: windows_attestation_sha256,
        eligible: blockers.is_empty(),
        blocker_codes: blockers.into_iter().collect(),
    };
    decision.validate()?;
    Ok(decision)
}

pub fn write_cutover_decision(
    path: &Path,
    decision: &CutoverDecision,
) -> Result<(), EvidenceError> {
    decision.validate()?;
    write_new_json(path, decision)
}

pub fn load_cutover_decision(path: &Path) -> Result<CutoverDecision, EvidenceError> {
    let decision = read_bounded_json(path)?;
    CutoverDecision::validate(&decision)?;
    Ok(decision)
}

fn write_new_json(path: &Path, value: &impl Serialize) -> Result<(), EvidenceError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_new_bytes(path, &bytes)
}

pub fn write_new_bytes(path: &Path, bytes: &[u8]) -> Result<(), EvidenceError> {
    if bytes.len() as u64 > MAX_OUTPUT_BYTES {
        return Err(EvidenceError::Invalid(
            "cutover evidence output exceeds the safety limit".into(),
        ));
    }
    let path = prepare_new_output(path)?;
    let parent = path.parent().ok_or_else(|| {
        EvidenceError::Invalid("evidence output must have a parent directory".into())
    })?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| match error.error.kind() {
            io::ErrorKind::AlreadyExists => EvidenceError::OutputExists,
            _ => EvidenceError::Io(error.error),
        })?;
    Ok(())
}

fn read_bounded_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, EvidenceError> {
    Ok(serde_json::from_slice(&read_bounded_bytes(
        path,
        MAX_EVIDENCE_BYTES,
    )?)?)
}

fn read_bounded_bytes(path: &Path, limit: u64) -> Result<Vec<u8>, EvidenceError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err(EvidenceError::Invalid(
            "evidence must be a bounded regular file".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?.read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > limit {
        return Err(EvidenceError::Invalid(
            "evidence changed while it was being read".into(),
        ));
    }
    Ok(bytes)
}

pub fn sha256_file(path: &Path) -> Result<String, EvidenceError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_HASHED_FILE_BYTES
    {
        return Err(EvidenceError::Invalid(
            "hashed input must be a bounded regular file".into(),
        ));
    }
    let mut reader = BufReader::new(File::open(path)?);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut length = 0_u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        length = length
            .checked_add(read as u64)
            .ok_or_else(|| EvidenceError::Invalid("hashed input length overflowed".into()))?;
        if length > MAX_HASHED_FILE_BYTES {
            return Err(EvidenceError::Invalid(
                "hashed input exceeds the safety limit".into(),
            ));
        }
        hasher.update(&buffer[..read]);
    }
    if length != metadata.len() {
        return Err(EvidenceError::Invalid(
            "hashed input changed while it was being read".into(),
        ));
    }
    Ok(hex_digest(hasher.finalize()))
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    hex_digest(Sha256::digest(bytes))
}

pub fn cutover_decision_signing_payload(document: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(document);
    let mut payload = b"SSDEV-CUTOVER-DECISION\0".to_vec();
    payload.extend_from_slice(&digest);
    payload
}

pub fn cutover_policy_signing_payload(document: &[u8]) -> Result<Vec<u8>, EvidenceError> {
    ProductionCutoverPolicy::from_bytes_for_signing(document)?;
    let digest = Sha256::digest(document);
    let mut payload = b"SSDEV-CUTOVER-POLICY\0".to_vec();
    payload.extend_from_slice(&digest);
    Ok(payload)
}

pub fn digest_named_payloads(
    domain: &str,
    payloads: &BTreeMap<String, Vec<u8>>,
) -> Result<String, EvidenceError> {
    validate_portable_label(domain, "digest domain")?;
    if payloads.is_empty() || payloads.len() > MAX_NAMED_PAYLOADS {
        return Err(EvidenceError::Invalid(
            "named digest requires a bounded non-empty payload set".into(),
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"SSDEV-CUTOVER-EVIDENCE\0");
    append_digest_field(&mut hasher, domain.as_bytes())?;
    for (name, payload) in payloads {
        if name.is_empty()
            || name.len() > 512
            || name.chars().any(char::is_control)
            || payload.len() > MAX_NAMED_PAYLOAD_BYTES
        {
            return Err(EvidenceError::Invalid(
                "named digest contains an invalid name or oversized payload".into(),
            ));
        }
        append_digest_field(&mut hasher, name.as_bytes())?;
        append_digest_field(&mut hasher, payload)?;
    }
    Ok(hex_digest(hasher.finalize()))
}

fn append_digest_field(hasher: &mut Sha256, value: &[u8]) -> Result<(), EvidenceError> {
    let length = u64::try_from(value.len())
        .map_err(|_| EvidenceError::Invalid("digest field length overflowed".into()))?;
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn validate_git_revision(revision: &str) -> Result<(), EvidenceError> {
    if !matches!(revision.len(), 40 | 64)
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(EvidenceError::Invalid(
            "sourceRevision must be a lowercase Git object ID".into(),
        ));
    }
    Ok(())
}

fn validate_common_execution(
    source_revision: &str,
    executed_at_unix_seconds: u64,
    environment: &str,
    runner_os: &str,
    runner_architecture: &str,
) -> Result<(), EvidenceError> {
    validate_git_revision(source_revision)?;
    validate_portable_label(environment, "environment")?;
    validate_portable_label(runner_os, "runner OS")?;
    validate_portable_label(runner_architecture, "runner architecture")?;
    if executed_at_unix_seconds == 0 {
        return Err(EvidenceError::Invalid(
            "execution time must be a positive Unix timestamp".into(),
        ));
    }
    Ok(())
}

fn validate_portable_label(value: &str, label: &str) -> Result<(), EvidenceError> {
    if value.is_empty()
        || value.len() > 128
        || value.starts_with('.')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(EvidenceError::Invalid(format!(
            "{label} must be a portable identifier"
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

fn is_finding_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn hex_digest(value: impl AsRef<[u8]>) -> String {
    value
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> PluginMatrixEvidence {
        PluginMatrixEvidence {
            schema_version: PLUGIN_MATRIX_EVIDENCE_SCHEMA_VERSION,
            evidence_type: EvidenceType::PluginMatrix,
            source_revision: "a".repeat(40),
            source_dirty: false,
            executed_at_unix_seconds: 1,
            environment: "reader-lab-1".into(),
            runner_os: "windows".into(),
            runner_architecture: "x86_64".into(),
            release_set_spec_sha256: "0".repeat(64),
            package_set_sha256: "9".repeat(64),
            plugin_set_sha256: "1".repeat(64),
            trust_store_sha256: "2".repeat(64),
            matrix_sha256: "3".repeat(64),
            x86_host_sha256: "4".repeat(64),
            x64_host_sha256: "5".repeat(64),
            plugin_count: 1,
            service_count: 2,
            method_count: 3,
            enabled_case_count: 4,
            passed: true,
        }
    }

    fn valid_migration() -> MigrationAuditEvidence {
        MigrationAuditEvidence {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            evidence_type: EvidenceType::MigrationAudit,
            source_revision: "b".repeat(40),
            source_dirty: false,
            executed_at_unix_seconds: 1,
            environment: "production-workflows".into(),
            runner_os: "windows".into(),
            runner_architecture: "x86_64".into(),
            report_sha256: "6".repeat(64),
            pilot_material_set_sha256: "b".repeat(64),
            origin_policy_sha256: "a".repeat(64),
            config_files: 1,
            plugin_directories: 2,
            service_count: 3,
            key_binding_count: 4,
            browser_asset_roots: 1,
            browser_asset_files_scanned: 50,
            browser_har_files: 1,
            browser_har_requests_scanned: 100,
            insecure_http_origin_count: 2,
            authorized_insecure_http_origin_count: 2,
            webplus_http_evidence: HttpEvidenceLevel::NotObserved,
            desktop_callback_http_evidence: HttpEvidenceLevel::StaticReferences,
            critical_findings: 0,
            warning_findings: 1,
            info_findings: 1,
            finding_code_counts: BTreeMap::from([
                ("browser-static-reference".into(), 1),
                ("inventory-summary".into(), 1),
            ]),
        }
    }

    fn valid_windows_package() -> WindowsPackageEvidence {
        WindowsPackageEvidence {
            schema_version: WINDOWS_PACKAGE_EVIDENCE_SCHEMA_VERSION,
            evidence_type: EvidenceType::WindowsPackage,
            source_revision: "c".repeat(40),
            source_dirty: false,
            executed_at_unix_seconds: 1,
            environment: "isolated-windows-lab".into(),
            runner_os: "windows".into(),
            runner_architecture: "x86_64".into(),
            release_metadata_sha256: "7".repeat(64),
            artifact_manifest_sha256: "8".repeat(64),
            plugin_trust_store_sha256: "2".repeat(64),
            origin_policy_sha256: "a".repeat(64),
            x86_host_sha256: "4".repeat(64),
            x64_host_sha256: "5".repeat(64),
            deployment_check_sha256: Some("6".repeat(64)),
            deployment_check_generated_at_unix_ms: Some(1_000),
            app_version: "1.2.3".into(),
            authenticode_required: true,
            authenticode_verified: true,
            nsis_install_verified: true,
            msi_install_verified: false,
            launch_verified: true,
            upgrade_verified: true,
            rollback_verified: true,
            previous_app_version: Some("1.2.2".into()),
            previous_release_metadata_sha256: Some("9".repeat(64)),
            previous_artifact_manifest_sha256: Some("d".repeat(64)),
            passed: true,
        }
    }

    fn valid_deployment_check_record() -> DeploymentCheckRecord {
        let items = [
            "webview-runtime",
            "business-frontend",
            "project-config",
            "origin-policy",
            "plugin-trust",
            "plugin-hosts",
            "plugin-inventory",
            "plugin-route-policy",
            "tracked-invocations",
            "plugin-preflight",
            "diagnostics",
            "managed-processes",
            "app-update",
        ]
        .into_iter()
        .map(|id| DeploymentCheckRecordItem {
            id: id.into(),
            label: id.into(),
            status: DeploymentCheckRecordStatus::Pass,
            summary: "verified".into(),
            action: None,
        })
        .collect::<Vec<_>>();
        DeploymentCheckRecord {
            schema_version: 1,
            generated_at_unix_ms: 1_000,
            desktop_version: "1.2.3".into(),
            os: "windows".into(),
            architecture: "x86_64".into(),
            evidence_level: "unsigned-local-record".into(),
            report: DeploymentCheckRecordReport {
                deep: true,
                deep_available: true,
                ready: true,
                delivery_ready: true,
                passed: items.len(),
                warnings: 0,
                failures: 0,
                items,
            },
        }
    }

    fn valid_policy(revision: String) -> ProductionCutoverPolicy {
        ProductionCutoverPolicy {
            schema_version: CUTOVER_POLICY_SCHEMA_VERSION,
            target_source_revision: revision,
            expected_app_version: "1.2.3".into(),
            expected_previous_app_version: "1.2.2".into(),
            maximum_evidence_age_seconds: 3600,
            expected_windows_artifact_manifest_sha256: "8".repeat(64),
            expected_previous_windows_artifact_manifest_sha256: "d".repeat(64),
            expected_previous_release_metadata_sha256: "9".repeat(64),
            expected_plugin_release_set_spec_sha256: "0".repeat(64),
            expected_plugin_package_set_sha256: "9".repeat(64),
            expected_plugin_trust_store_sha256: "2".repeat(64),
            expected_evidence_trust_store_sha256: "8".repeat(64),
            expected_plugin_matrix_sha256: "3".repeat(64),
            expected_pilot_material_set_sha256: "b".repeat(64),
            expected_origin_policy_sha256: "a".repeat(64),
            migration_coverage_minimums: MigrationCoverageMinimums {
                config_files: 1,
                plugin_directories: 2,
                services: 3,
                key_bindings: 4,
                browser_asset_roots: 1,
                browser_asset_files_scanned: 50,
                browser_har_files: 1,
                browser_har_requests_scanned: 100,
            },
            plugin_matrix_signer_key_id: "plugin-matrix-qa".into(),
            migration_audit_signer_key_id: "migration-audit-qa".into(),
            windows_package_signer_key_id: "windows-package-qa".into(),
            cutover_decision_signer_key_id: "cutover-approval".into(),
        }
    }

    fn test_dir() -> PathBuf {
        tempfile::Builder::new()
            .prefix("ssdev-cutover-evidence-")
            .tempdir()
            .unwrap()
            .keep()
    }

    #[test]
    fn plugin_matrix_evidence_is_strict_and_no_clobber() {
        let root = test_dir();
        let path = root.join("plugin-matrix.json");
        write_plugin_matrix_evidence(&path, &valid()).unwrap();
        assert_eq!(load_plugin_matrix_evidence(&path).unwrap(), valid());
        assert!(matches!(
            write_plugin_matrix_evidence(&path, &valid()),
            Err(EvidenceError::OutputExists)
        ));

        let mut malformed = valid();
        malformed.enabled_case_count = 2;
        assert!(malformed.validate().is_err());

        let mut legacy = valid();
        legacy.schema_version = 1;
        assert!(legacy.validate().is_err());

        let mut unbound = valid();
        unbound.package_set_sha256 = "not-a-digest".into();
        assert!(unbound.validate().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn windows_package_evidence_preserves_legacy_installer_fields() {
        let mut evidence = valid_windows_package();
        evidence.msi_install_verified = false;
        evidence.launch_verified = false;
        evidence.upgrade_verified = false;
        evidence.rollback_verified = false;
        evidence.previous_app_version = None;
        evidence.previous_release_metadata_sha256 = None;
        evidence.previous_artifact_manifest_sha256 = None;
        evidence.validate().unwrap();

        evidence.rollback_verified = true;
        assert!(evidence.validate().is_err());
        evidence.rollback_verified = false;

        evidence.authenticode_required = false;
        assert!(evidence.validate().is_err());
        evidence.authenticode_verified = false;
        evidence.validate().unwrap();

        let mut rollback_without_launch = valid_windows_package();
        rollback_without_launch.launch_verified = false;
        assert!(rollback_without_launch.validate().is_err());

        let mut rollback_without_nsis = valid_windows_package();
        rollback_without_nsis.nsis_install_verified = false;
        rollback_without_nsis.msi_install_verified = true;
        assert!(rollback_without_nsis.validate().is_err());

        let mut legacy = valid_windows_package();
        legacy.schema_version = 5;
        assert!(legacy.validate().is_err());

        let mut unbound = valid_windows_package();
        unbound.x86_host_sha256 = "not-a-digest".into();
        assert!(unbound.validate().is_err());

        let mut missing_timestamp = valid_windows_package();
        missing_timestamp.deployment_check_generated_at_unix_ms = None;
        assert!(missing_timestamp.validate().is_err());

        let mut stale = valid_windows_package();
        stale.executed_at_unix_seconds = MAX_DEPLOYMENT_CHECK_AGE_SECONDS + 2;
        assert!(stale.validate().is_err());
    }

    #[test]
    fn deployment_check_binding_requires_a_complete_real_business_handshake() {
        let record = valid_deployment_check_record();
        record.validate_for_delivery("1.2.3").unwrap();

        let mut no_business_handshake = record.clone();
        let business = no_business_handshake
            .report
            .items
            .iter_mut()
            .find(|item| item.id == "business-frontend")
            .unwrap();
        business.status = DeploymentCheckRecordStatus::Warning;
        no_business_handshake.report.passed -= 1;
        no_business_handshake.report.warnings = 1;
        assert!(no_business_handshake
            .validate_for_delivery("1.2.3")
            .is_err());

        let mut wrong_version = record.clone();
        wrong_version.desktop_version = "1.2.4".into();
        assert!(wrong_version.validate_for_delivery("1.2.3").is_err());
    }

    #[test]
    fn production_gate_requires_the_same_clean_complete_evidence_set() {
        let revision = "d".repeat(40);
        let policy = valid_policy(revision.clone());
        let mut plugin = valid();
        plugin.source_revision = revision.clone();
        plugin.executed_at_unix_seconds = 1000;
        let mut migration = valid_migration();
        migration.source_revision = revision.clone();
        migration.executed_at_unix_seconds = 1000;
        migration.desktop_callback_http_evidence = HttpEvidenceLevel::NotObserved;
        migration.warning_findings = 0;
        migration.finding_code_counts = BTreeMap::from([("inventory-summary".into(), 1)]);
        let mut windows = valid_windows_package();
        windows.source_revision = revision;
        windows.executed_at_unix_seconds = 1000;

        let decision = evaluate_production_cutover(
            ProductionCutoverInputs {
                policy: &policy,
                policy_sha256: "1".repeat(64),
                policy_attestation_sha256: "0".repeat(64),
                evidence_trust_store_sha256: "8".repeat(64),
                approval_trust_store_sha256: "2".repeat(64),
                plugin: &plugin,
                plugin_sha256: "2".repeat(64),
                plugin_attestation_sha256: "5".repeat(64),
                migration: &migration,
                migration_sha256: "3".repeat(64),
                migration_attestation_sha256: "6".repeat(64),
                windows: &windows,
                windows_sha256: "4".repeat(64),
                windows_attestation_sha256: "7".repeat(64),
            },
            1000,
        )
        .unwrap();
        assert!(decision.eligible);
        assert!(decision.blocker_codes.is_empty());
        assert_eq!(decision.policy_attestation_sha256, "0".repeat(64));
        assert_eq!(decision.approval_trust_store_sha256, "2".repeat(64));
        let mut legacy_decision = decision.clone();
        legacy_decision.schema_version = 2;
        assert!(legacy_decision.validate().is_err());

        let substituted_trust = evaluate_production_cutover(
            ProductionCutoverInputs {
                policy: &policy,
                policy_sha256: "1".repeat(64),
                policy_attestation_sha256: "0".repeat(64),
                evidence_trust_store_sha256: "f".repeat(64),
                approval_trust_store_sha256: "2".repeat(64),
                plugin: &plugin,
                plugin_sha256: "2".repeat(64),
                plugin_attestation_sha256: "5".repeat(64),
                migration: &migration,
                migration_sha256: "3".repeat(64),
                migration_attestation_sha256: "6".repeat(64),
                windows: &windows,
                windows_sha256: "4".repeat(64),
                windows_attestation_sha256: "7".repeat(64),
            },
            1000,
        )
        .unwrap();
        assert_eq!(
            substituted_trust.blocker_codes,
            ["evidence-trust-store-mismatch"]
        );

        let substituted_approval_trust = evaluate_production_cutover(
            ProductionCutoverInputs {
                policy: &policy,
                policy_sha256: "1".repeat(64),
                policy_attestation_sha256: "0".repeat(64),
                evidence_trust_store_sha256: "8".repeat(64),
                approval_trust_store_sha256: "f".repeat(64),
                plugin: &plugin,
                plugin_sha256: "2".repeat(64),
                plugin_attestation_sha256: "5".repeat(64),
                migration: &migration,
                migration_sha256: "3".repeat(64),
                migration_attestation_sha256: "6".repeat(64),
                windows: &windows,
                windows_sha256: "4".repeat(64),
                windows_attestation_sha256: "7".repeat(64),
            },
            1000,
        )
        .unwrap();
        assert_eq!(
            substituted_approval_trust.blocker_codes,
            ["approval-trust-store-mismatch"]
        );

        let mut policy_drift_migration = migration.clone();
        policy_drift_migration.origin_policy_sha256 = "b".repeat(64);
        policy_drift_migration.pilot_material_set_sha256 = "c".repeat(64);
        policy_drift_migration.authorized_insecure_http_origin_count = 1;
        let mut policy_drift_windows = windows.clone();
        policy_drift_windows.origin_policy_sha256 = "c".repeat(64);
        let drift = evaluate_production_cutover(
            ProductionCutoverInputs {
                policy: &policy,
                policy_sha256: "1".repeat(64),
                policy_attestation_sha256: "0".repeat(64),
                evidence_trust_store_sha256: "8".repeat(64),
                approval_trust_store_sha256: "2".repeat(64),
                plugin: &plugin,
                plugin_sha256: "2".repeat(64),
                plugin_attestation_sha256: "5".repeat(64),
                migration: &policy_drift_migration,
                migration_sha256: "3".repeat(64),
                migration_attestation_sha256: "6".repeat(64),
                windows: &policy_drift_windows,
                windows_sha256: "4".repeat(64),
                windows_attestation_sha256: "7".repeat(64),
            },
            1000,
        )
        .unwrap();
        assert_eq!(
            drift.blocker_codes,
            [
                "migration-http-origin-authorization-incomplete",
                "migration-origin-policy-mismatch",
                "migration-pilot-material-set-mismatch",
                "windows-origin-policy-mismatch",
            ]
        );

        let mut different_previous_release = windows.clone();
        different_previous_release.previous_app_version = Some("1.2.1".into());
        different_previous_release.previous_release_metadata_sha256 = Some("e".repeat(64));
        different_previous_release.previous_artifact_manifest_sha256 = Some("f".repeat(64));
        let previous_release_drift = evaluate_production_cutover(
            ProductionCutoverInputs {
                policy: &policy,
                policy_sha256: "1".repeat(64),
                policy_attestation_sha256: "0".repeat(64),
                evidence_trust_store_sha256: "8".repeat(64),
                approval_trust_store_sha256: "2".repeat(64),
                plugin: &plugin,
                plugin_sha256: "2".repeat(64),
                plugin_attestation_sha256: "5".repeat(64),
                migration: &migration,
                migration_sha256: "3".repeat(64),
                migration_attestation_sha256: "6".repeat(64),
                windows: &different_previous_release,
                windows_sha256: "4".repeat(64),
                windows_attestation_sha256: "7".repeat(64),
            },
            1000,
        )
        .unwrap();
        assert_eq!(
            previous_release_drift.blocker_codes,
            [
                "windows-previous-app-version-mismatch",
                "windows-previous-artifact-manifest-mismatch",
                "windows-previous-release-metadata-mismatch",
            ]
        );

        let mut no_deployment_check = windows.clone();
        no_deployment_check.deployment_check_sha256 = None;
        no_deployment_check.deployment_check_generated_at_unix_ms = None;
        let no_business_acceptance = evaluate_production_cutover(
            ProductionCutoverInputs {
                policy: &policy,
                policy_sha256: "1".repeat(64),
                policy_attestation_sha256: "0".repeat(64),
                evidence_trust_store_sha256: "8".repeat(64),
                approval_trust_store_sha256: "2".repeat(64),
                plugin: &plugin,
                plugin_sha256: "2".repeat(64),
                plugin_attestation_sha256: "5".repeat(64),
                migration: &migration,
                migration_sha256: "3".repeat(64),
                migration_attestation_sha256: "6".repeat(64),
                windows: &no_deployment_check,
                windows_sha256: "4".repeat(64),
                windows_attestation_sha256: "7".repeat(64),
            },
            1000,
        )
        .unwrap();
        assert_eq!(
            no_business_acceptance.blocker_codes,
            ["windows-business-frontend-not-verified"]
        );

        let mut no_rollback = windows.clone();
        no_rollback.rollback_verified = false;
        let no_recovery_evidence = evaluate_production_cutover(
            ProductionCutoverInputs {
                policy: &policy,
                policy_sha256: "1".repeat(64),
                policy_attestation_sha256: "0".repeat(64),
                evidence_trust_store_sha256: "8".repeat(64),
                approval_trust_store_sha256: "2".repeat(64),
                plugin: &plugin,
                plugin_sha256: "2".repeat(64),
                plugin_attestation_sha256: "5".repeat(64),
                migration: &migration,
                migration_sha256: "3".repeat(64),
                migration_attestation_sha256: "6".repeat(64),
                windows: &no_rollback,
                windows_sha256: "4".repeat(64),
                windows_attestation_sha256: "7".repeat(64),
            },
            1000,
        )
        .unwrap();
        assert_eq!(
            no_recovery_evidence.blocker_codes,
            ["windows-rollback-not-verified"]
        );

        windows.launch_verified = false;
        windows.rollback_verified = false;
        windows.source_dirty = true;
        let decision = evaluate_production_cutover(
            ProductionCutoverInputs {
                policy: &policy,
                policy_sha256: "1".repeat(64),
                policy_attestation_sha256: "0".repeat(64),
                evidence_trust_store_sha256: "8".repeat(64),
                approval_trust_store_sha256: "2".repeat(64),
                plugin: &plugin,
                plugin_sha256: "2".repeat(64),
                plugin_attestation_sha256: "5".repeat(64),
                migration: &migration,
                migration_sha256: "3".repeat(64),
                migration_attestation_sha256: "6".repeat(64),
                windows: &windows,
                windows_sha256: "4".repeat(64),
                windows_attestation_sha256: "7".repeat(64),
            },
            1000,
        )
        .unwrap();
        assert!(!decision.eligible);
        assert_eq!(
            decision.blocker_codes,
            [
                "windows-launch-not-verified",
                "windows-package-dirty-source",
                "windows-rollback-not-verified"
            ]
        );
        assert!(
            CutoverDecision::from_bytes_for_signing(&serde_json::to_vec(&decision).unwrap())
                .is_err()
        );
    }

    #[test]
    fn production_gate_binds_approved_plugin_inputs_inventory_and_shipped_hosts() {
        let revision = "d".repeat(40);
        let mut policy = valid_policy(revision.clone());
        policy.migration_coverage_minimums.browser_asset_roots = 2;
        policy.migration_coverage_minimums.browser_har_files = 2;
        let mut plugin = valid();
        plugin.source_revision = revision.clone();
        plugin.executed_at_unix_seconds = 1000;
        plugin.release_set_spec_sha256 = "a".repeat(64);
        plugin.package_set_sha256 = "b".repeat(64);
        plugin.trust_store_sha256 = "c".repeat(64);
        plugin.matrix_sha256 = "d".repeat(64);
        let mut migration = valid_migration();
        migration.source_revision = revision.clone();
        migration.executed_at_unix_seconds = 1000;
        migration.config_files = 0;
        migration.plugin_directories = 1;
        migration.service_count = 2;
        migration.key_binding_count = 3;
        migration.browser_asset_roots = 1;
        migration.browser_asset_files_scanned = 49;
        migration.browser_har_files = 1;
        migration.browser_har_requests_scanned = 99;
        migration.desktop_callback_http_evidence = HttpEvidenceLevel::NotObserved;
        migration.warning_findings = 0;
        migration.finding_code_counts = BTreeMap::from([("inventory-summary".into(), 1)]);
        let mut windows = valid_windows_package();
        windows.source_revision = revision;
        windows.executed_at_unix_seconds = 1000;
        windows.artifact_manifest_sha256 = "6".repeat(64);
        windows.plugin_trust_store_sha256 = "7".repeat(64);
        windows.x86_host_sha256 = "e".repeat(64);
        windows.x64_host_sha256 = "f".repeat(64);

        let decision = evaluate_production_cutover(
            ProductionCutoverInputs {
                policy: &policy,
                policy_sha256: "1".repeat(64),
                policy_attestation_sha256: "0".repeat(64),
                evidence_trust_store_sha256: "8".repeat(64),
                approval_trust_store_sha256: "2".repeat(64),
                plugin: &plugin,
                plugin_sha256: "2".repeat(64),
                plugin_attestation_sha256: "5".repeat(64),
                migration: &migration,
                migration_sha256: "3".repeat(64),
                migration_attestation_sha256: "6".repeat(64),
                windows: &windows,
                windows_sha256: "4".repeat(64),
                windows_attestation_sha256: "7".repeat(64),
            },
            1000,
        )
        .unwrap();
        assert_eq!(
            decision.blocker_codes,
            [
                "migration-browser-asset-files-below-policy",
                "migration-browser-asset-roots-below-policy",
                "migration-browser-har-files-below-policy",
                "migration-browser-har-requests-below-policy",
                "migration-config-files-below-policy",
                "migration-key-bindings-below-policy",
                "migration-plugin-directories-below-policy",
                "migration-services-below-policy",
                "plugin-matrix-mismatch",
                "plugin-package-set-mismatch",
                "plugin-release-set-spec-mismatch",
                "plugin-trust-store-mismatch",
                "windows-artifact-manifest-mismatch",
                "windows-plugin-trust-store-mismatch",
                "windows-x64-host-mismatch",
                "windows-x86-host-mismatch",
            ]
        );
    }

    #[test]
    fn canonical_named_digest_is_ordered_and_mutation_sensitive() {
        let first = BTreeMap::from([("b".into(), b"two".to_vec()), ("a".into(), b"one".to_vec())]);
        let second = BTreeMap::from([("a".into(), b"one".to_vec()), ("b".into(), b"two".to_vec())]);
        assert_eq!(
            digest_named_payloads("plugin-set", &first).unwrap(),
            digest_named_payloads("plugin-set", &second).unwrap()
        );
        let changed = BTreeMap::from([
            ("a".into(), b"changed".to_vec()),
            ("b".into(), b"two".to_vec()),
        ]);
        assert_ne!(
            digest_named_payloads("plugin-set", &first).unwrap(),
            digest_named_payloads("plugin-set", &changed).unwrap()
        );
    }

    #[test]
    fn documented_production_policy_remains_schema_valid() {
        let mut policy: ProductionCutoverPolicy =
            serde_json::from_str(include_str!("../../../docs/cutover-policy.example.json"))
                .unwrap();
        policy.validate().unwrap();
        policy.cutover_decision_signer_key_id = policy.windows_package_signer_key_id.clone();
        assert!(policy.validate().is_err());

        let mut legacy = valid_policy("d".repeat(40));
        legacy.schema_version = 6;
        assert!(legacy.validate().is_err());

        let mut malformed = valid_policy("d".repeat(40));
        malformed.expected_plugin_package_set_sha256 = "not-a-digest".into();
        assert!(malformed.validate().is_err());

        let mut invalid_upgrade = valid_policy("d".repeat(40));
        invalid_upgrade.expected_previous_app_version =
            invalid_upgrade.expected_app_version.clone();
        assert!(invalid_upgrade.validate().is_err());

        let bytes = serde_json::to_vec(&valid_policy("d".repeat(40))).unwrap();
        ProductionCutoverPolicy::from_bytes_for_signing(&bytes).unwrap();
        assert!(cutover_policy_signing_payload(&bytes)
            .unwrap()
            .starts_with(b"SSDEV-CUTOVER-POLICY\0"));
        assert_ne!(
            cutover_policy_signing_payload(&bytes).unwrap(),
            cutover_decision_signing_payload(&bytes)
        );
    }

    #[test]
    fn generated_production_policy_cannot_overwrite_an_existing_record() {
        let root = test_dir();
        let path = root.join("policy.json");
        let policy = valid_policy("d".repeat(40));
        write_production_cutover_policy(&path, &policy).unwrap();
        assert_eq!(load_production_cutover_policy(&path).unwrap(), policy);
        assert!(write_production_cutover_policy(&path, &policy).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn migration_evidence_preserves_counts_without_input_paths() {
        let root = test_dir();
        let path = root.join("migration.json");
        write_migration_audit_evidence(&path, &valid_migration()).unwrap();
        assert_eq!(
            load_migration_audit_evidence(&path).unwrap(),
            valid_migration()
        );
        let encoded = fs::read_to_string(&path).unwrap();
        assert!(!encoded.contains("C:\\"));

        let mut inconsistent = valid_migration();
        inconsistent.warning_findings = 2;
        assert!(inconsistent.validate().is_err());
        let mut legacy = valid_migration();
        legacy.schema_version = 2;
        assert!(legacy.validate().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn evidence_reading_rejects_symbolic_links() {
        use std::os::unix::fs::symlink;

        let root = test_dir();
        let target = root.join("target.json");
        let link = root.join("link.json");
        write_plugin_matrix_evidence(&target, &valid()).unwrap();
        symlink(&target, &link).unwrap();
        assert!(load_plugin_matrix_evidence(&link).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
