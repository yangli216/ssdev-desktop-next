use std::error::Error;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use ssdev_cutover_evidence::{
    current_cutover_authorization_blocker, evaluate_production_cutover,
    evaluate_production_cutover_readiness, load_delivery_ready_deployment_check,
    load_migration_audit_evidence, load_plugin_matrix_evidence, load_windows_package_evidence,
    prepare_new_output, production_cutover_blocker_remediation,
    reproduce_production_cutover_decision, sha256_file, verify_evidence_attestation,
    verify_evidence_attestation_with_current_trust, verify_production_cutover_decision_attestation,
    verify_production_cutover_decision_attestation_with_current_trust,
    verify_production_cutover_policy_attestation,
    verify_production_cutover_policy_attestation_with_current_trust, write_cutover_decision,
    write_production_cutover_policy, write_windows_package_evidence, CutoverDecision,
    EvidenceAttestationKind, EvidenceType, MigrationCoverageMinimums, ProductionCutoverInputs,
    ProductionCutoverPolicy, ProductionCutoverReadinessInputs, WindowsPackageEvidence,
    CUTOVER_POLICY_SCHEMA_VERSION, WINDOWS_PACKAGE_EVIDENCE_SCHEMA_VERSION,
};
use ssdev_origin_policy::{signing_payload as origin_policy_signing_payload, OriginPolicy};
use ssdev_pilot_readiness::{
    load_manifest, load_report, resolve_material_category_inputs, resolve_migration_audit_inputs,
    verify_materials,
};
use ssdev_plugin_tool::check_release_set_with_package_root;
use ssdev_release_manifest::{
    capture_source_identity, verify_manifest, verify_release_metadata, ReleaseMetadata,
};
use webplus_plugin_trust::{DetachedSignatureDocument, TrustPurpose, TrustStore};

const MAX_POLICY_APPROVAL_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyApprovalInputs {
    schema_version: u8,
    maximum_evidence_age_seconds: u64,
    maximum_cutover_decision_age_seconds: u64,
    migration_coverage_minimums: MigrationCoverageMinimums,
    plugin_matrix_signer_key_id: String,
    migration_audit_signer_key_id: String,
    windows_package_signer_key_id: String,
    cutover_decision_signer_key_id: String,
}

#[derive(Debug, Eq, PartialEq)]
struct UnsignedCutoverHashes {
    policy: String,
    policy_attestation: String,
    approval_trust_store: String,
    evidence_trust_store: String,
    plugin: String,
    migration: String,
    windows: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SignedCutoverArchiveHashes {
    decision: String,
    decision_attestation: String,
    policy: String,
    policy_attestation: String,
    approval_trust_store: String,
    evidence_trust_store: String,
    plugin: String,
    plugin_attestation: String,
    migration: String,
    migration_attestation: String,
    windows: String,
    windows_attestation: String,
}

struct VerifiedGoArchive {
    decision: CutoverDecision,
    policy: ProductionCutoverPolicy,
    windows: WindowsPackageEvidence,
    hashes: SignedCutoverArchiveHashes,
}

#[derive(Debug, Eq, PartialEq)]
struct BundlePolicyIdentity {
    metadata: ReleaseMetadata,
    release_metadata_sha256: String,
    artifact_manifest_sha256: String,
}

fn run_prepare_policy(arguments: &[OsString]) -> Result<(), Box<dyn Error>> {
    if arguments.len() != 9 {
        return Err(usage().into());
    }
    let workspace =
        canonical_real_directory(&path_argument(arguments.get(1), "workspace")?, "workspace")?;
    let materials_root = canonical_real_directory(
        &path_argument(arguments.get(2), "pilot materials root")?,
        "pilot materials root",
    )?;
    let manifest_path = canonical_regular_file(
        &path_argument(arguments.get(3), "pilot manifest")?,
        "pilot manifest",
    )?;
    let report_path = canonical_regular_file(
        &path_argument(arguments.get(4), "pilot report")?,
        "pilot report",
    )?;
    let candidate_root = canonical_real_directory(
        &path_argument(arguments.get(5), "candidate bundle root")?,
        "candidate bundle root",
    )?;
    let evidence_trust_store = canonical_regular_file(
        &path_argument(arguments.get(6), "evidence trust store")?,
        "evidence trust store",
    )?;
    let approval_path = canonical_regular_file(
        &path_argument(arguments.get(7), "policy approval inputs")?,
        "policy approval inputs",
    )?;
    let output = prepare_new_output(&path_argument(arguments.get(8), "policy output")?)?;

    let source_before = capture_source_identity(&workspace)?;
    if source_before.dirty {
        return Err(invalid_input(
            "production cutover policy requires a clean source workspace",
        ));
    }
    let (manifest, manifest_bytes_before) = load_manifest(&manifest_path)?;
    let (report, report_bytes_before) = load_report(&report_path)?;
    verify_materials(&materials_root, &manifest, &manifest_bytes_before, &report)?;
    if !report.intake_complete {
        return Err(invalid_input(
            "pilot material intake must be complete before policy preparation",
        ));
    }

    let migration_inputs = resolve_migration_audit_inputs(&materials_root, &manifest)?;
    let (release_set_spec, package_root) = single_file_and_directory(
        resolve_material_category_inputs(&materials_root, &manifest, "plugin-release-set")?,
        "plugin release set",
    )?;
    let matrix = single_regular_file(
        resolve_material_category_inputs(&materials_root, &manifest, "golden-cases")?,
        "golden case matrix",
    )?;
    let previous_root = single_real_directory(
        resolve_material_category_inputs(&materials_root, &manifest, "previous-windows-release")?,
        "previous Windows release",
    )?;
    require_category_contains_file(
        &evidence_trust_store,
        &resolve_material_category_inputs(&materials_root, &manifest, "organization-public-trust")?,
        "evidence trust store",
    )?;
    for protected_root in [&workspace, &materials_root, &candidate_root, &previous_root] {
        if output.starts_with(protected_root) {
            return Err(invalid_input(
                "policy output must stay outside the source, pilot, and release bundles",
            ));
        }
    }

    let approval_bytes_before = read_bounded_regular_file(
        &approval_path,
        MAX_POLICY_APPROVAL_BYTES,
        "policy approvals",
    )?;
    let approval: PolicyApprovalInputs = serde_json::from_slice(&approval_bytes_before)?;
    if approval.schema_version != 2 {
        return Err(invalid_input("policy approval inputs must use schema 2"));
    }
    let evidence_trust_store_sha256 = sha256_file(&evidence_trust_store)?;
    validate_cutover_signing_keys(
        &evidence_trust_store,
        &migration_inputs.release_trust_store,
        &approval,
    )?;

    let candidate_before = capture_bundle_policy_identity(&candidate_root, Some(&workspace))?;
    let previous_before = capture_bundle_policy_identity(&previous_root, None)?;
    validate_previous_version(&candidate_before.metadata, Some(&previous_before.metadata))?;
    let origin_policy_sha256 = verify_origin_policy_for_issuance(
        &migration_inputs.origin_policy,
        &migration_inputs.origin_policy_envelope,
        &migration_inputs.release_trust_store,
    )?;
    let release_set = check_release_set_with_package_root(
        &release_set_spec,
        &package_root,
        &migration_inputs.release_trust_store,
        &matrix,
    )?;

    let source_after = capture_source_identity(&workspace)?;
    let candidate_after = capture_bundle_policy_identity(&candidate_root, Some(&workspace))?;
    let previous_after = capture_bundle_policy_identity(&previous_root, None)?;
    let approval_bytes_after = read_bounded_regular_file(
        &approval_path,
        MAX_POLICY_APPROVAL_BYTES,
        "policy approvals",
    )?;
    let (manifest_after, manifest_bytes_after) = load_manifest(&manifest_path)?;
    let (report_after, report_bytes_after) = load_report(&report_path)?;
    verify_materials(
        &materials_root,
        &manifest_after,
        &manifest_bytes_after,
        &report_after,
    )?;
    if source_before != source_after
        || source_after.dirty
        || candidate_before != candidate_after
        || previous_before != previous_after
        || approval_bytes_before != approval_bytes_after
        || evidence_trust_store_sha256 != sha256_file(&evidence_trust_store)?
        || manifest_bytes_before != manifest_bytes_after
        || report_bytes_before != report_bytes_after
    {
        return Err(invalid_input(
            "source, policy approvals, pilot materials, or release bundles changed during preparation",
        ));
    }

    let policy = ProductionCutoverPolicy {
        schema_version: CUTOVER_POLICY_SCHEMA_VERSION,
        target_source_revision: source_after.revision,
        expected_app_version: candidate_after.metadata.app_version,
        expected_previous_app_version: previous_after.metadata.app_version,
        maximum_evidence_age_seconds: approval.maximum_evidence_age_seconds,
        maximum_cutover_decision_age_seconds: approval.maximum_cutover_decision_age_seconds,
        expected_windows_artifact_manifest_sha256: candidate_after.artifact_manifest_sha256,
        expected_previous_windows_artifact_manifest_sha256: previous_after.artifact_manifest_sha256,
        expected_previous_release_metadata_sha256: previous_after.release_metadata_sha256,
        expected_plugin_release_set_spec_sha256: release_set.spec_sha256,
        expected_plugin_package_set_sha256: release_set.package_set_sha256,
        expected_plugin_trust_store_sha256: release_set.trust_store_sha256,
        expected_evidence_trust_store_sha256: evidence_trust_store_sha256,
        expected_plugin_matrix_sha256: release_set.matrix_sha256,
        expected_pilot_material_set_sha256: report_after.material_set_sha256,
        expected_origin_policy_sha256: origin_policy_sha256,
        migration_coverage_minimums: approval.migration_coverage_minimums,
        plugin_matrix_signer_key_id: approval.plugin_matrix_signer_key_id,
        migration_audit_signer_key_id: approval.migration_audit_signer_key_id,
        windows_package_signer_key_id: approval.windows_package_signer_key_id,
        cutover_decision_signer_key_id: approval.cutover_decision_signer_key_id,
    };
    write_production_cutover_policy(&output, &policy)?;
    println!(
        "Production cutover policy prepared for {} from {} verified plugins and pilot material set {}",
        policy.expected_app_version,
        release_set.plugin_count,
        policy.expected_pilot_material_set_sha256
    );
    Ok(())
}

fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => std::process::exit(3),
        Err(error) => {
            eprintln!("cutover evidence failed: {error}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<bool, Box<dyn Error>> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    match string_argument(arguments.first(), "operation")?.as_str() {
        "prepare-policy" => {
            run_prepare_policy(&arguments)?;
            Ok(true)
        }
        "windows-package" => {
            run_windows_package(&arguments)?;
            Ok(true)
        }
        "precheck" => run_precheck(&arguments),
        "decide" => run_decision(&arguments),
        "verify-go" => run_verify_go(&arguments),
        "check-current-go" => run_check_current_go(&arguments),
        _ => Err(usage().into()),
    }
}

fn run_precheck(arguments: &[OsString]) -> Result<bool, Box<dyn Error>> {
    if arguments.len() != 8 {
        return Err(usage().into());
    }
    let policy_path = path_argument(arguments.get(1), "production cutover policy")?;
    let policy_attestation_path =
        path_argument(arguments.get(2), "production cutover policy attestation")?;
    let approval_trust_store_path = path_argument(arguments.get(3), "approval trust store")?;
    let evidence_trust_store_path = path_argument(arguments.get(4), "evidence trust store")?;
    let plugin_path = path_argument(arguments.get(5), "plugin matrix evidence")?;
    let migration_path = path_argument(arguments.get(6), "migration audit evidence")?;
    let windows_path = path_argument(arguments.get(7), "Windows package evidence")?;

    let hashes_before = capture_unsigned_cutover_hashes(
        &policy_path,
        &policy_attestation_path,
        &approval_trust_store_path,
        &evidence_trust_store_path,
        &plugin_path,
        &migration_path,
        &windows_path,
    )?;
    let policy = verify_production_cutover_policy_attestation(
        &policy_path,
        &policy_attestation_path,
        &approval_trust_store_path,
    )?;
    let evidence_trust = TrustStore::load(&evidence_trust_store_path)?;
    for key_id in [
        &policy.plugin_matrix_signer_key_id,
        &policy.migration_audit_signer_key_id,
        &policy.windows_package_signer_key_id,
    ] {
        evidence_trust.ensure_key_can_issue(TrustPurpose::CutoverEvidence, key_id)?;
    }
    let plugin = load_plugin_matrix_evidence(&plugin_path)?;
    let migration = load_migration_audit_evidence(&migration_path)?;
    let windows = load_windows_package_evidence(&windows_path)?;
    let evaluated_at_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid_input("system clock is before the Unix epoch"))?
        .as_secs();
    let hashes_after = capture_unsigned_cutover_hashes(
        &policy_path,
        &policy_attestation_path,
        &approval_trust_store_path,
        &evidence_trust_store_path,
        &plugin_path,
        &migration_path,
        &windows_path,
    )?;
    if hashes_before != hashes_after {
        return Err(invalid_input(
            "cutover policy, trust store, or unsigned evidence changed during precheck",
        ));
    }

    let readiness = evaluate_production_cutover_readiness(
        ProductionCutoverReadinessInputs {
            policy: &policy,
            evidence_trust_store_sha256: hashes_after.evidence_trust_store,
            approval_trust_store_sha256: hashes_after.approval_trust_store,
            plugin: &plugin,
            migration: &migration,
            windows: &windows,
        },
        evaluated_at_unix_seconds,
    )?;
    if readiness.eligible_for_evidence_signing {
        println!(
            "READY-FOR-EVIDENCE-SIGNING: unsigned evidence satisfies the current production policy"
        );
    } else {
        eprintln!(
            "{}",
            render_cutover_blockers(
                "production cutover precheck: BLOCKED",
                &readiness.blocker_codes,
                "resolve every blocker, regenerate affected unsigned evidence, and rerun precheck before QA signing",
            )?
        );
    }
    Ok(readiness.eligible_for_evidence_signing)
}

fn capture_unsigned_cutover_hashes(
    policy: &Path,
    policy_attestation: &Path,
    approval_trust_store: &Path,
    evidence_trust_store: &Path,
    plugin: &Path,
    migration: &Path,
    windows: &Path,
) -> Result<UnsignedCutoverHashes, Box<dyn Error>> {
    Ok(UnsignedCutoverHashes {
        policy: sha256_file(policy)?,
        policy_attestation: sha256_file(policy_attestation)?,
        approval_trust_store: sha256_file(approval_trust_store)?,
        evidence_trust_store: sha256_file(evidence_trust_store)?,
        plugin: sha256_file(plugin)?,
        migration: sha256_file(migration)?,
        windows: sha256_file(windows)?,
    })
}

fn run_windows_package(arguments: &[OsString]) -> Result<(), Box<dyn Error>> {
    if !matches!(arguments.len(), 15 | 16) {
        return Err(usage().into());
    }
    if std::env::consts::OS != "windows" || std::env::consts::ARCH != "x86_64" {
        return Err(invalid_input(
            "Windows package evidence requires a Windows x86_64 runner",
        ));
    }
    let workspace = fs::canonicalize(path_argument(arguments.get(1), "workspace")?)?;
    if !workspace.is_dir() {
        return Err(invalid_input("workspace must be an existing directory"));
    }
    let release_metadata_path = canonical_regular_file(
        &path_argument(arguments.get(2), "release metadata")?,
        "release metadata",
    )?;
    let artifact_manifest_path = canonical_regular_file(
        &path_argument(arguments.get(3), "artifact manifest")?,
        "artifact manifest",
    )?;
    require_file_name(&release_metadata_path, "release.json")?;
    require_file_name(&artifact_manifest_path, "artifacts.json")?;
    if release_metadata_path.parent() != artifact_manifest_path.parent() {
        return Err(invalid_input(
            "release metadata and artifact manifest must share a metadata directory",
        ));
    }
    let bundle_root = release_metadata_path
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| invalid_input("release metadata is not inside a bundle"))?;
    let output = prepare_new_output(&path_argument(arguments.get(4), "evidence output")?)?;
    if output.starts_with(&workspace) || output.starts_with(bundle_root) {
        return Err(invalid_input(
            "evidence output must stay outside the source workspace and verified bundle",
        ));
    }

    let environment = string_argument(arguments.get(5), "environment")?;
    let installer_kind = string_argument(arguments.get(6), "installer kind")?;
    let launch_verified = bool_argument(arguments.get(7), "launch verified")?;
    let authenticode_verified = bool_argument(arguments.get(8), "Authenticode verified")?;
    let plugin_trust_store_sha256 =
        string_argument(arguments.get(9), "installed plugin trust store SHA-256")?;
    let origin_policy_sha256 =
        string_argument(arguments.get(10), "installed origin policy SHA-256")?;
    let x86_host_sha256 = string_argument(arguments.get(11), "x86 host SHA-256")?;
    let x64_host_sha256 = string_argument(arguments.get(12), "x64 host SHA-256")?;
    let deployment_check_argument = string_argument(arguments.get(13), "deployment check")?;
    let application_state_preservation_verified =
        bool_argument(arguments.get(14), "application state preservation verified")?;
    let deployment_check_path = if deployment_check_argument == "none" {
        None
    } else {
        let path = canonical_regular_file(
            Path::new(&deployment_check_argument),
            "deployment check record",
        )?;
        if path.starts_with(&workspace) || path.starts_with(bundle_root) {
            return Err(invalid_input(
                "deployment check record must stay outside the source workspace and verified bundle",
            ));
        }
        Some(path)
    };
    let previous_metadata_path = arguments
        .get(15)
        .map(|value| path_argument(Some(value), "previous release metadata"))
        .transpose()?
        .map(|path| canonical_regular_file(&path, "previous release metadata"))
        .transpose()?;
    let previous_bundle_root = previous_metadata_path
        .as_deref()
        .map(release_bundle_root_from_metadata)
        .transpose()?;
    if let Some(path) = &previous_metadata_path {
        require_file_name(path, "release.json")?;
        if output.starts_with(
            previous_bundle_root.expect("previous metadata has a resolved bundle root"),
        ) {
            return Err(invalid_input(
                "evidence output must stay outside the previous release bundle",
            ));
        }
    }
    let previous_artifact_manifest_path = previous_metadata_path
        .as_ref()
        .map(|path| {
            path.parent()
                .expect("canonical release metadata has a parent")
                .join("artifacts.json")
        })
        .map(|path| canonical_regular_file(&path, "previous artifact manifest"))
        .transpose()?;

    let source_before = capture_source_identity(&workspace)?;
    verify_manifest(bundle_root, "metadata/artifacts.json")?;
    if let Some(previous_bundle_root) = previous_bundle_root {
        verify_manifest(previous_bundle_root, "metadata/artifacts.json")?;
    }
    let release_metadata_before = sha256_file(&release_metadata_path)?;
    let artifact_manifest_before = sha256_file(&artifact_manifest_path)?;
    let current = verify_release_metadata(&release_metadata_path, Some(&workspace))?;
    let deployment_check = deployment_check_path
        .as_deref()
        .map(|path| load_delivery_ready_deployment_check(path, &current.app_version))
        .transpose()?;
    let deployment_check_hash_before = deployment_check.as_ref().map(|(_, digest)| digest.clone());
    let previous = previous_metadata_path
        .as_deref()
        .map(|path| verify_release_metadata(path, None))
        .transpose()?;
    let previous_hash_before = previous_metadata_path
        .as_deref()
        .map(sha256_file)
        .transpose()?;
    let previous_artifact_manifest_hash_before = previous_artifact_manifest_path
        .as_deref()
        .map(sha256_file)
        .transpose()?;
    validate_previous_version(&current, previous.as_ref())?;

    verify_manifest(bundle_root, "metadata/artifacts.json")?;
    if let Some(previous_bundle_root) = previous_bundle_root {
        verify_manifest(previous_bundle_root, "metadata/artifacts.json")?;
    }
    let source_after = capture_source_identity(&workspace)?;
    let release_metadata_after = sha256_file(&release_metadata_path)?;
    let artifact_manifest_after = sha256_file(&artifact_manifest_path)?;
    let previous_hash_after = previous_metadata_path
        .as_deref()
        .map(sha256_file)
        .transpose()?;
    let previous_artifact_manifest_hash_after = previous_artifact_manifest_path
        .as_deref()
        .map(sha256_file)
        .transpose()?;
    let deployment_check_hash_after = deployment_check_path
        .as_deref()
        .map(sha256_file)
        .transpose()?;
    if source_before != source_after
        || release_metadata_before != release_metadata_after
        || artifact_manifest_before != artifact_manifest_after
        || previous_hash_before != previous_hash_after
        || previous_artifact_manifest_hash_before != previous_artifact_manifest_hash_after
        || deployment_check_hash_before != deployment_check_hash_after
    {
        return Err(invalid_input(
            "source or release evidence inputs changed during verification",
        ));
    }

    if installer_kind != "Nsis" {
        return Err(invalid_input("installer kind must be Nsis"));
    }
    let executed_at_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid_input("system clock is before the Unix epoch"))?
        .as_secs();
    write_windows_package_evidence(
        &output,
        &WindowsPackageEvidence {
            schema_version: WINDOWS_PACKAGE_EVIDENCE_SCHEMA_VERSION,
            evidence_type: EvidenceType::WindowsPackage,
            source_revision: source_after.revision,
            source_dirty: source_after.dirty,
            executed_at_unix_seconds,
            environment,
            runner_os: std::env::consts::OS.into(),
            runner_architecture: std::env::consts::ARCH.into(),
            release_metadata_sha256: release_metadata_after,
            artifact_manifest_sha256: artifact_manifest_after,
            plugin_trust_store_sha256,
            origin_policy_sha256,
            x86_host_sha256,
            x64_host_sha256,
            deployment_check_sha256: deployment_check_hash_after,
            deployment_check_generated_at_unix_ms: deployment_check
                .map(|(record, _)| record.generated_at_unix_ms),
            app_version: current.app_version,
            authenticode_required: current.authenticode_required,
            authenticode_verified,
            nsis_install_verified: true,
            // Retained in the evidence schema so existing signed records remain readable.
            msi_install_verified: false,
            launch_verified,
            upgrade_verified: previous.is_some(),
            rollback_verified: previous.is_some() && launch_verified,
            application_state_preservation_verified,
            previous_app_version: previous.map(|metadata| metadata.app_version),
            previous_release_metadata_sha256: previous_hash_after,
            previous_artifact_manifest_sha256: previous_artifact_manifest_hash_after,
            passed: true,
        },
    )?;
    println!("Windows package evidence written after all requested smoke tests passed");
    Ok(())
}

fn run_decision(arguments: &[OsString]) -> Result<bool, Box<dyn Error>> {
    if arguments.len() != 12 {
        return Err(usage().into());
    }
    let policy_path = path_argument(arguments.get(1), "production cutover policy")?;
    let policy_attestation_path =
        path_argument(arguments.get(2), "production cutover policy attestation")?;
    let approval_trust_store_path = path_argument(arguments.get(3), "approval trust store")?;
    let trust_store_path = path_argument(arguments.get(4), "evidence trust store")?;
    let plugin_path = path_argument(arguments.get(5), "plugin matrix evidence")?;
    let plugin_attestation_path = path_argument(arguments.get(6), "plugin matrix attestation")?;
    let migration_path = path_argument(arguments.get(7), "migration audit evidence")?;
    let migration_attestation_path =
        path_argument(arguments.get(8), "migration audit attestation")?;
    let windows_path = path_argument(arguments.get(9), "Windows package evidence")?;
    let windows_attestation_path = path_argument(arguments.get(10), "Windows package attestation")?;
    let output = prepare_new_output(&path_argument(arguments.get(11), "decision output")?)?;

    let policy_hash_before = sha256_file(&policy_path)?;
    let policy_attestation_hash_before = sha256_file(&policy_attestation_path)?;
    let approval_trust_store_hash_before = sha256_file(&approval_trust_store_path)?;
    let trust_store_hash_before = sha256_file(&trust_store_path)?;
    let plugin_hash_before = sha256_file(&plugin_path)?;
    let plugin_attestation_hash_before = sha256_file(&plugin_attestation_path)?;
    let migration_hash_before = sha256_file(&migration_path)?;
    let migration_attestation_hash_before = sha256_file(&migration_attestation_path)?;
    let windows_hash_before = sha256_file(&windows_path)?;
    let windows_attestation_hash_before = sha256_file(&windows_attestation_path)?;
    let policy = verify_production_cutover_policy_attestation(
        &policy_path,
        &policy_attestation_path,
        &approval_trust_store_path,
    )?;
    verify_evidence_attestation(
        EvidenceAttestationKind::PluginMatrix,
        &plugin_path,
        &plugin_attestation_path,
        &trust_store_path,
        &policy.plugin_matrix_signer_key_id,
    )?;
    verify_evidence_attestation(
        EvidenceAttestationKind::MigrationAudit,
        &migration_path,
        &migration_attestation_path,
        &trust_store_path,
        &policy.migration_audit_signer_key_id,
    )?;
    verify_evidence_attestation(
        EvidenceAttestationKind::WindowsPackage,
        &windows_path,
        &windows_attestation_path,
        &trust_store_path,
        &policy.windows_package_signer_key_id,
    )?;
    let plugin = load_plugin_matrix_evidence(&plugin_path)?;
    let migration = load_migration_audit_evidence(&migration_path)?;
    let windows = load_windows_package_evidence(&windows_path)?;
    let evaluated_at_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid_input("system clock is before the Unix epoch"))?
        .as_secs();
    let policy_hash_after = sha256_file(&policy_path)?;
    let policy_attestation_hash_after = sha256_file(&policy_attestation_path)?;
    let approval_trust_store_hash_after = sha256_file(&approval_trust_store_path)?;
    let trust_store_hash_after = sha256_file(&trust_store_path)?;
    let plugin_hash_after = sha256_file(&plugin_path)?;
    let plugin_attestation_hash_after = sha256_file(&plugin_attestation_path)?;
    let migration_hash_after = sha256_file(&migration_path)?;
    let migration_attestation_hash_after = sha256_file(&migration_attestation_path)?;
    let windows_hash_after = sha256_file(&windows_path)?;
    let windows_attestation_hash_after = sha256_file(&windows_attestation_path)?;
    if policy_hash_before != policy_hash_after
        || policy_attestation_hash_before != policy_attestation_hash_after
        || approval_trust_store_hash_before != approval_trust_store_hash_after
        || trust_store_hash_before != trust_store_hash_after
        || plugin_hash_before != plugin_hash_after
        || plugin_attestation_hash_before != plugin_attestation_hash_after
        || migration_hash_before != migration_hash_after
        || migration_attestation_hash_before != migration_attestation_hash_after
        || windows_hash_before != windows_hash_after
        || windows_attestation_hash_before != windows_attestation_hash_after
    {
        return Err(invalid_input(
            "cutover policy, trust store, or evidence changed during evaluation",
        ));
    }
    let decision = evaluate_production_cutover(
        ProductionCutoverInputs {
            policy: &policy,
            policy_sha256: policy_hash_after,
            policy_attestation_sha256: policy_attestation_hash_after,
            evidence_trust_store_sha256: trust_store_hash_after,
            approval_trust_store_sha256: approval_trust_store_hash_after,
            plugin: &plugin,
            plugin_sha256: plugin_hash_after,
            plugin_attestation_sha256: plugin_attestation_hash_after,
            migration: &migration,
            migration_sha256: migration_hash_after,
            migration_attestation_sha256: migration_attestation_hash_after,
            windows: &windows,
            windows_sha256: windows_hash_after,
            windows_attestation_sha256: windows_attestation_hash_after,
        },
        evaluated_at_unix_seconds,
    )?;
    write_cutover_decision(&output, &decision)?;
    if decision.eligible {
        println!(
            "GO: production cutover evidence is complete for {} at source {}",
            decision.app_version, decision.target_source_revision
        );
    } else {
        eprintln!(
            "{}",
            render_cutover_blockers(
                "production cutover decision: NO-GO",
                &decision.blocker_codes,
                "archive this NO-GO decision, resolve every blocker, regenerate and sign affected evidence, then decide to a new output path",
            )?
        );
    }
    Ok(decision.eligible)
}

fn verify_go_archive(arguments: &[OsString]) -> Result<VerifiedGoArchive, Box<dyn Error>> {
    if arguments.len() != 13 {
        return Err(usage().into());
    }
    let decision_path = path_argument(arguments.get(1), "production cutover decision")?;
    let decision_attestation_path =
        path_argument(arguments.get(2), "production cutover decision attestation")?;
    let policy_path = path_argument(arguments.get(3), "production cutover policy")?;
    let policy_attestation_path =
        path_argument(arguments.get(4), "production cutover policy attestation")?;
    let approval_trust_store_path = path_argument(arguments.get(5), "approval trust store")?;
    let evidence_trust_store_path = path_argument(arguments.get(6), "evidence trust store")?;
    let plugin_path = path_argument(arguments.get(7), "plugin matrix evidence")?;
    let plugin_attestation_path = path_argument(arguments.get(8), "plugin matrix attestation")?;
    let migration_path = path_argument(arguments.get(9), "migration audit evidence")?;
    let migration_attestation_path =
        path_argument(arguments.get(10), "migration audit attestation")?;
    let windows_path = path_argument(arguments.get(11), "Windows package evidence")?;
    let windows_attestation_path = path_argument(arguments.get(12), "Windows package attestation")?;

    let hashes_before = capture_signed_cutover_archive_hashes(
        &decision_path,
        &decision_attestation_path,
        &policy_path,
        &policy_attestation_path,
        &approval_trust_store_path,
        &evidence_trust_store_path,
        &plugin_path,
        &plugin_attestation_path,
        &migration_path,
        &migration_attestation_path,
        &windows_path,
        &windows_attestation_path,
    )?;
    let decision = verify_production_cutover_decision_attestation(
        &decision_path,
        &decision_attestation_path,
        &approval_trust_store_path,
    )?;
    let policy = verify_production_cutover_policy_attestation(
        &policy_path,
        &policy_attestation_path,
        &approval_trust_store_path,
    )?;
    verify_evidence_attestation(
        EvidenceAttestationKind::PluginMatrix,
        &plugin_path,
        &plugin_attestation_path,
        &evidence_trust_store_path,
        &policy.plugin_matrix_signer_key_id,
    )?;
    verify_evidence_attestation(
        EvidenceAttestationKind::MigrationAudit,
        &migration_path,
        &migration_attestation_path,
        &evidence_trust_store_path,
        &policy.migration_audit_signer_key_id,
    )?;
    verify_evidence_attestation(
        EvidenceAttestationKind::WindowsPackage,
        &windows_path,
        &windows_attestation_path,
        &evidence_trust_store_path,
        &policy.windows_package_signer_key_id,
    )?;
    let plugin = load_plugin_matrix_evidence(&plugin_path)?;
    let migration = load_migration_audit_evidence(&migration_path)?;
    let windows = load_windows_package_evidence(&windows_path)?;
    let hashes_after = capture_signed_cutover_archive_hashes(
        &decision_path,
        &decision_attestation_path,
        &policy_path,
        &policy_attestation_path,
        &approval_trust_store_path,
        &evidence_trust_store_path,
        &plugin_path,
        &plugin_attestation_path,
        &migration_path,
        &migration_attestation_path,
        &windows_path,
        &windows_attestation_path,
    )?;
    if hashes_before != hashes_after {
        return Err(invalid_input(
            "signed cutover archive changed during verification",
        ));
    }
    let verified_hashes = hashes_after.clone();
    reproduce_production_cutover_decision(
        ProductionCutoverInputs {
            policy: &policy,
            policy_sha256: hashes_after.policy,
            policy_attestation_sha256: hashes_after.policy_attestation,
            evidence_trust_store_sha256: hashes_after.evidence_trust_store,
            approval_trust_store_sha256: hashes_after.approval_trust_store,
            plugin: &plugin,
            plugin_sha256: hashes_after.plugin,
            plugin_attestation_sha256: hashes_after.plugin_attestation,
            migration: &migration,
            migration_sha256: hashes_after.migration,
            migration_attestation_sha256: hashes_after.migration_attestation,
            windows: &windows,
            windows_sha256: hashes_after.windows,
            windows_attestation_sha256: hashes_after.windows_attestation,
        },
        &decision,
    )?;
    Ok(VerifiedGoArchive {
        decision,
        policy,
        windows,
        hashes: verified_hashes,
    })
}

fn run_verify_go(arguments: &[OsString]) -> Result<bool, Box<dyn Error>> {
    let verified = verify_go_archive(arguments)?;
    println!(
        "VERIFIED-GO: signed decision and complete cutover archive reproduce the approved production decision for {} at source {}",
        verified.decision.app_version, verified.decision.target_source_revision
    );
    Ok(true)
}

fn run_check_current_go(arguments: &[OsString]) -> Result<bool, Box<dyn Error>> {
    if arguments.len() != 16 {
        return Err(usage().into());
    }
    let verified = verify_go_archive(&arguments[..13])?;
    let decision_path = path_argument(arguments.get(1), "production cutover decision")?;
    let decision_attestation_path =
        path_argument(arguments.get(2), "production cutover decision attestation")?;
    let policy_path = path_argument(arguments.get(3), "production cutover policy")?;
    let policy_attestation_path =
        path_argument(arguments.get(4), "production cutover policy attestation")?;
    let archived_approval_trust_store_path =
        path_argument(arguments.get(5), "archived approval trust store")?;
    let archived_evidence_trust_store_path =
        path_argument(arguments.get(6), "archived evidence trust store")?;
    let plugin_path = path_argument(arguments.get(7), "plugin matrix evidence")?;
    let plugin_attestation_path = path_argument(arguments.get(8), "plugin matrix attestation")?;
    let migration_path = path_argument(arguments.get(9), "migration audit evidence")?;
    let migration_attestation_path =
        path_argument(arguments.get(10), "migration audit attestation")?;
    let windows_path = path_argument(arguments.get(11), "Windows package evidence")?;
    let windows_attestation_path = path_argument(arguments.get(12), "Windows package attestation")?;
    let current_approval_trust_store_path =
        path_argument(arguments.get(13), "current approval trust store")?;
    let current_evidence_trust_store_path =
        path_argument(arguments.get(14), "current evidence trust store")?;
    let candidate_bundle_root = canonical_real_directory(
        &path_argument(arguments.get(15), "candidate Windows bundle root")?,
        "candidate Windows bundle root",
    )?;
    let current_trust_hashes_before = (
        sha256_file(&current_approval_trust_store_path)?,
        sha256_file(&current_evidence_trust_store_path)?,
    );
    let current_archive_hashes_before = capture_signed_cutover_archive_hashes(
        &decision_path,
        &decision_attestation_path,
        &policy_path,
        &policy_attestation_path,
        &archived_approval_trust_store_path,
        &archived_evidence_trust_store_path,
        &plugin_path,
        &plugin_attestation_path,
        &migration_path,
        &migration_attestation_path,
        &windows_path,
        &windows_attestation_path,
    )?;
    if current_archive_hashes_before != verified.hashes {
        return Err(invalid_input(
            "signed cutover archive changed before current trust verification",
        ));
    }
    let candidate_bundle_before = match capture_bundle_policy_identity(&candidate_bundle_root, None)
    {
        Ok(identity) if candidate_bundle_matches_verified_go(&identity, &verified) => identity,
        Ok(_) | Err(_) => {
            print_current_go_blocker(
                "cutover-candidate-bundle-mismatch",
                "restore the exact protected candidate bundle bound by the signed Windows evidence and rerun the check before launching its NSIS installer",
            );
            return Ok(false);
        }
    };
    let current_trust_result = (|| {
        verify_production_cutover_decision_attestation_with_current_trust(
            &decision_path,
            &decision_attestation_path,
            &current_approval_trust_store_path,
        )?;
        verify_production_cutover_policy_attestation_with_current_trust(
            &policy_path,
            &policy_attestation_path,
            &current_approval_trust_store_path,
        )?;
        verify_evidence_attestation_with_current_trust(
            EvidenceAttestationKind::PluginMatrix,
            &plugin_path,
            &plugin_attestation_path,
            &current_evidence_trust_store_path,
            &verified.policy.plugin_matrix_signer_key_id,
        )?;
        verify_evidence_attestation_with_current_trust(
            EvidenceAttestationKind::MigrationAudit,
            &migration_path,
            &migration_attestation_path,
            &current_evidence_trust_store_path,
            &verified.policy.migration_audit_signer_key_id,
        )?;
        verify_evidence_attestation_with_current_trust(
            EvidenceAttestationKind::WindowsPackage,
            &windows_path,
            &windows_attestation_path,
            &current_evidence_trust_store_path,
            &verified.policy.windows_package_signer_key_id,
        )?;
        Ok::<(), Box<dyn Error>>(())
    })();
    let current_trust_hashes_after = (
        sha256_file(&current_approval_trust_store_path)?,
        sha256_file(&current_evidence_trust_store_path)?,
    );
    let current_archive_hashes_after = capture_signed_cutover_archive_hashes(
        &decision_path,
        &decision_attestation_path,
        &policy_path,
        &policy_attestation_path,
        &archived_approval_trust_store_path,
        &archived_evidence_trust_store_path,
        &plugin_path,
        &plugin_attestation_path,
        &migration_path,
        &migration_attestation_path,
        &windows_path,
        &windows_attestation_path,
    )?;
    if current_archive_hashes_before != current_archive_hashes_after {
        return Err(invalid_input(
            "signed cutover archive changed during current trust verification",
        ));
    }
    if current_trust_hashes_before != current_trust_hashes_after {
        return Err(invalid_input(
            "current cutover trust stores changed during verification",
        ));
    }
    let candidate_bundle_after = capture_bundle_policy_identity(&candidate_bundle_root, None)
        .map_err(|_| invalid_input("candidate Windows bundle changed during verification"))?;
    if candidate_bundle_before != candidate_bundle_after {
        return Err(invalid_input(
            "candidate Windows bundle changed during verification",
        ));
    }
    if current_trust_result.is_err() {
        print_current_go_blocker(
            "cutover-current-trust-rejected",
            "obtain the current protected approval and evidence trust stores, resolve any revoked, missing, or substituted signer, and issue a new signed GO before rollout",
        );
        return Ok(false);
    }
    let now_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid_input("system clock is before the Unix epoch"))?
        .as_secs();
    if let Some(blocker) = current_cutover_authorization_blocker(
        &verified.policy,
        &verified.decision,
        now_unix_seconds,
    )? {
        print_current_go_blocker(blocker.code, blocker.remediation);
        return Ok(false);
    }
    println!(
        "CURRENT-GO: signed decision, current trust, and candidate Windows bundle {} are approved for {} at source {}",
        candidate_bundle_after.artifact_manifest_sha256,
        verified.decision.app_version,
        verified.decision.target_source_revision
    );
    Ok(true)
}

fn candidate_bundle_matches_verified_go(
    bundle: &BundlePolicyIdentity,
    verified: &VerifiedGoArchive,
) -> bool {
    bundle.release_metadata_sha256 == verified.windows.release_metadata_sha256
        && bundle.artifact_manifest_sha256 == verified.windows.artifact_manifest_sha256
        && bundle.artifact_manifest_sha256
            == verified.policy.expected_windows_artifact_manifest_sha256
        && bundle.metadata.app_version == verified.decision.app_version
        && bundle.metadata.source_revision == verified.decision.target_source_revision
}

fn print_current_go_blocker(code: &str, remediation: &str) {
    eprintln!(
        "current cutover authorization: BLOCKED (1 blocker)\nblocker: {code}\naction: {remediation}\nnext: resolve the blocker and repeat check-current-go immediately before rollout"
    );
}

#[allow(clippy::too_many_arguments)]
fn capture_signed_cutover_archive_hashes(
    decision: &Path,
    decision_attestation: &Path,
    policy: &Path,
    policy_attestation: &Path,
    approval_trust_store: &Path,
    evidence_trust_store: &Path,
    plugin: &Path,
    plugin_attestation: &Path,
    migration: &Path,
    migration_attestation: &Path,
    windows: &Path,
    windows_attestation: &Path,
) -> Result<SignedCutoverArchiveHashes, Box<dyn Error>> {
    Ok(SignedCutoverArchiveHashes {
        decision: sha256_file(decision)?,
        decision_attestation: sha256_file(decision_attestation)?,
        policy: sha256_file(policy)?,
        policy_attestation: sha256_file(policy_attestation)?,
        approval_trust_store: sha256_file(approval_trust_store)?,
        evidence_trust_store: sha256_file(evidence_trust_store)?,
        plugin: sha256_file(plugin)?,
        plugin_attestation: sha256_file(plugin_attestation)?,
        migration: sha256_file(migration)?,
        migration_attestation: sha256_file(migration_attestation)?,
        windows: sha256_file(windows)?,
        windows_attestation: sha256_file(windows_attestation)?,
    })
}

fn render_cutover_blockers(
    heading: &str,
    blocker_codes: &[String],
    next: &str,
) -> Result<String, Box<dyn Error>> {
    if blocker_codes.is_empty() {
        return Err(invalid_input(
            "blocked cutover summary requires at least one blocker",
        ));
    }
    let mut lines = vec![format!("{heading} ({} blockers)", blocker_codes.len())];
    for code in blocker_codes {
        let remediation = production_cutover_blocker_remediation(code).ok_or_else(|| {
            invalid_input("cutover blocker does not have stable remediation guidance")
        })?;
        lines.push(format!("blocker: {code}"));
        lines.push(format!("action: {remediation}"));
    }
    lines.push(format!("next: {next}"));
    Ok(lines.join("\n"))
}

fn validate_previous_version(
    current: &ReleaseMetadata,
    previous: Option<&ReleaseMetadata>,
) -> Result<(), Box<dyn Error>> {
    let current = Version::parse(&current.app_version)?;
    if let Some(previous) = previous {
        if Version::parse(&previous.app_version)? >= current {
            return Err(invalid_input(
                "previous bundle version must be lower than candidate bundle version",
            ));
        }
    }
    Ok(())
}

fn capture_bundle_policy_identity(
    root: &Path,
    workspace: Option<&Path>,
) -> Result<BundlePolicyIdentity, Box<dyn Error>> {
    let release_metadata = canonical_regular_file(
        &root.join("metadata/release.json"),
        "bundle release metadata",
    )?;
    let artifact_manifest = canonical_regular_file(
        &root.join("metadata/artifacts.json"),
        "bundle artifact manifest",
    )?;
    canonical_regular_file(
        &root.join("metadata/artifacts.json.sig"),
        "bundle artifact manifest signature",
    )?;
    canonical_regular_file(
        &root.join("metadata/app-update.json"),
        "bundle application update policy",
    )?;
    let release_metadata_sha256 = sha256_file(&release_metadata)?;
    let artifact_manifest_sha256 = sha256_file(&artifact_manifest)?;
    verify_manifest(root, "metadata/artifacts.json")?;
    let metadata = verify_release_metadata(&release_metadata, workspace)?;
    if release_metadata_sha256 != sha256_file(&release_metadata)?
        || artifact_manifest_sha256 != sha256_file(&artifact_manifest)?
    {
        return Err(invalid_input(
            "release bundle metadata changed during verification",
        ));
    }
    Ok(BundlePolicyIdentity {
        metadata,
        release_metadata_sha256,
        artifact_manifest_sha256,
    })
}

fn verify_origin_policy_for_issuance(
    policy_path: &Path,
    envelope_path: &Path,
    trust_store_path: &Path,
) -> Result<String, Box<dyn Error>> {
    let policy_bytes =
        read_bounded_regular_file(policy_path, MAX_POLICY_APPROVAL_BYTES, "origin policy")?;
    let envelope_bytes = read_bounded_regular_file(
        envelope_path,
        MAX_POLICY_APPROVAL_BYTES,
        "origin policy signature",
    )?;
    let envelope: DetachedSignatureDocument = serde_json::from_slice(&envelope_bytes)?;
    envelope.validate()?;
    let trust_store = TrustStore::load(trust_store_path)?;
    trust_store.verify_detached_for_issuance(
        TrustPurpose::OriginPolicy,
        &envelope.key_id,
        &origin_policy_signing_payload(&policy_bytes),
        &envelope.signature,
    )?;
    OriginPolicy::from_unsigned_bytes(&policy_bytes)?;
    Ok(format!("{:x}", Sha256::digest(&policy_bytes)))
}

fn single_file_and_directory(
    paths: Vec<PathBuf>,
    label: &str,
) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let mut file = None;
    let mut directory = None;
    for path in paths {
        if path.is_file() {
            if file.replace(path).is_none() {
                continue;
            }
        } else if path.is_dir() && directory.replace(path).is_none() {
            continue;
        }
        return Err(invalid_input(&format!(
            "{label} must contain exactly one regular file and one real directory"
        )));
    }
    match (file, directory) {
        (Some(file), Some(directory)) => Ok((file, directory)),
        _ => Err(invalid_input(&format!(
            "{label} must contain exactly one regular file and one real directory"
        ))),
    }
}

fn single_regular_file(paths: Vec<PathBuf>, label: &str) -> Result<PathBuf, Box<dyn Error>> {
    if paths.len() != 1 || !paths[0].is_file() {
        return Err(invalid_input(&format!(
            "{label} must contain exactly one regular file"
        )));
    }
    canonical_regular_file(&paths[0], label)
}

fn single_real_directory(paths: Vec<PathBuf>, label: &str) -> Result<PathBuf, Box<dyn Error>> {
    if paths.len() != 1 {
        return Err(invalid_input(&format!(
            "{label} must contain exactly one real directory"
        )));
    }
    canonical_real_directory(&paths[0], label)
}

fn require_category_contains_file(
    file: &Path,
    category_inputs: &[PathBuf],
    label: &str,
) -> Result<(), Box<dyn Error>> {
    if category_inputs.iter().any(|input| {
        (input.is_file() && file == input) || (input.is_dir() && file.starts_with(input))
    }) {
        return Ok(());
    }
    Err(invalid_input(&format!(
        "{label} must come from the approved pilot material category"
    )))
}

fn validate_cutover_signing_keys(
    evidence_trust_store: &Path,
    approval_trust_store: &Path,
    approval: &PolicyApprovalInputs,
) -> Result<(), Box<dyn Error>> {
    let evidence_trust = TrustStore::load(evidence_trust_store)?;
    for key_id in [
        &approval.plugin_matrix_signer_key_id,
        &approval.migration_audit_signer_key_id,
        &approval.windows_package_signer_key_id,
    ] {
        evidence_trust.ensure_key_can_issue(TrustPurpose::CutoverEvidence, key_id)?;
    }
    TrustStore::load(approval_trust_store)?.ensure_key_can_issue(
        TrustPurpose::CutoverDecision,
        &approval.cutover_decision_signer_key_id,
    )?;
    Ok(())
}

fn canonical_real_directory(path: &Path, label: &str) -> Result<PathBuf, Box<dyn Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid_input(&format!(
            "{label} must be a real existing directory"
        )));
    }
    Ok(fs::canonicalize(path)?)
}

fn read_bounded_regular_file(
    path: &Path,
    limit: u64,
    label: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err(invalid_input(&format!(
            "{label} must be a bounded regular file"
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
        return Err(invalid_input(&format!(
            "{label} changed or exceeded its limit while being read"
        )));
    }
    Ok(bytes)
}

fn canonical_regular_file(path: &Path, label: &str) -> Result<PathBuf, Box<dyn Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid_input(&format!(
            "{label} must be a regular non-symbolic-link file"
        )));
    }
    Ok(fs::canonicalize(path)?)
}

fn require_file_name(path: &Path, expected: &str) -> Result<(), Box<dyn Error>> {
    if path.file_name().and_then(|name| name.to_str()) != Some(expected) {
        return Err(invalid_input(&format!("expected file named {expected}")));
    }
    Ok(())
}

fn release_bundle_root_from_metadata(path: &Path) -> Result<&Path, Box<dyn Error>> {
    let metadata_directory = path
        .parent()
        .ok_or_else(|| invalid_input("previous release metadata has no parent directory"))?;
    if metadata_directory
        .file_name()
        .and_then(|name| name.to_str())
        != Some("metadata")
    {
        return Err(invalid_input(
            "previous release metadata must be inside the bundle metadata directory",
        ));
    }
    metadata_directory
        .parent()
        .ok_or_else(|| invalid_input("previous release metadata has no bundle root"))
}

fn string_argument(value: Option<&OsString>, label: &str) -> Result<String, String> {
    value
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("{label} must be non-empty Unicode"))
}

fn path_argument(value: Option<&OsString>, label: &str) -> Result<PathBuf, String> {
    value
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| format!("{label} is required"))
}

fn bool_argument(value: Option<&OsString>, label: &str) -> Result<bool, String> {
    match string_argument(value, label)?.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("{label} must be true or false")),
    }
}

fn invalid_input(message: &str) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidInput, message).into()
}

fn usage() -> &'static str {
    "usage:\n  ssdev-cutover-evidence prepare-policy <workspace> <pilot-materials-root> <pilot-manifest.json> <pilot-report.json> <candidate-bundle-root> <evidence-trust.json> <policy-approval-inputs.json> <policy-output.json>\n  ssdev-cutover-evidence windows-package <workspace> <release.json> <artifacts.json> <output> <environment> <Nsis> <launch-verified> <authenticode-verified> <installed-plugin-trust-store-sha256> <installed-origin-policy-sha256> <x86-host-sha256> <x64-host-sha256> <deployment-check.json|none> <application-state-preservation-verified> [previous-release.json]\n  ssdev-cutover-evidence precheck <production-policy.json> <production-policy.sig.json> <approval-trust.json> <evidence-trust.json> <plugin-evidence.json> <migration-evidence.json> <windows-evidence.json>\n  ssdev-cutover-evidence decide <production-policy.json> <production-policy.sig.json> <approval-trust.json> <evidence-trust.json> <plugin-evidence.json> <plugin-evidence.sig.json> <migration-evidence.json> <migration-evidence.sig.json> <windows-evidence.json> <windows-evidence.sig.json> <decision-output.json>\n  ssdev-cutover-evidence verify-go <cutover-decision.json> <cutover-decision.sig.json> <production-policy.json> <production-policy.sig.json> <approval-trust.json> <evidence-trust.json> <plugin-evidence.json> <plugin-evidence.sig.json> <migration-evidence.json> <migration-evidence.sig.json> <windows-evidence.json> <windows-evidence.sig.json>\n  ssdev-cutover-evidence check-current-go <cutover-decision.json> <cutover-decision.sig.json> <production-policy.json> <production-policy.sig.json> <approval-trust.json> <evidence-trust.json> <plugin-evidence.json> <plugin-evidence.sig.json> <migration-evidence.json> <migration-evidence.sig.json> <windows-evidence.json> <windows-evidence.sig.json> <current-approval-trust.json> <current-evidence-trust.json> <candidate-windows-bundle-root>"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    use ssdev_cutover_evidence::{
        cutover_decision_signing_payload, cutover_policy_signing_payload,
        evidence_attestation_signing_payload, write_migration_audit_evidence,
        write_plugin_matrix_evidence, HttpEvidenceLevel, MigrationAuditEvidence,
        PluginMatrixEvidence, CUTOVER_DECISION_SCHEMA_VERSION, EVIDENCE_SCHEMA_VERSION,
        PLUGIN_MATRIX_EVIDENCE_SCHEMA_VERSION,
    };
    use ssdev_release_manifest::create_manifest;
    use tempfile::tempdir;

    struct SignedGoFixture {
        arguments: Vec<OsString>,
        approval_trust_path: PathBuf,
        evidence_trust_path: PathBuf,
        candidate_bundle_root: PathBuf,
        windows_path: PathBuf,
        windows_signing_key: SigningKey,
        windows_attestation_path: PathBuf,
    }

    fn write_test_attestation(path: &Path, key_id: &str, signing_key: &SigningKey, payload: &[u8]) {
        let signature = BASE64.encode(signing_key.sign(payload).to_bytes());
        let envelope = DetachedSignatureDocument::new(key_id, &signature).unwrap();
        fs::write(path, envelope.to_pretty_json().unwrap()).unwrap();
    }

    fn write_test_candidate_bundle(
        root: &Path,
        source_revision: &str,
        installer_bytes: &[u8],
    ) -> BundlePolicyIdentity {
        fs::create_dir_all(root.join("metadata")).unwrap();
        fs::create_dir_all(root.join("nsis")).unwrap();
        let release = ReleaseMetadata {
            schema_version: 2,
            app_version: "1.2.3".into(),
            product_name: "SSDEV Desktop".into(),
            identifier: "com.bsoft.ssdev.desktop".into(),
            authenticode_required: true,
            synthetic_version_override: false,
            source_revision: source_revision.into(),
            source_dirty: false,
            source_inputs: BTreeMap::from([
                ("Cargo.lock".into(), "1".repeat(64)),
                ("rust-toolchain.toml".into(), "2".repeat(64)),
                ("apps/desktop/package-lock.json".into(), "3".repeat(64)),
                (
                    "apps/desktop/src-tauri/tauri.conf.json".into(),
                    "4".repeat(64),
                ),
                (
                    "packages/web-bridge/package-lock.json".into(),
                    "5".repeat(64),
                ),
            ]),
            build_tools: BTreeMap::from([
                ("cargo".into(), "cargo 1.90.0".into()),
                ("cargoCyclonedx".into(), "cargo-cyclonedx 0.5.7".into()),
                ("node".into(), "node 22.0.0".into()),
                ("npm".into(), "npm 10.0.0".into()),
                ("rustc".into(), "rustc 1.90.0".into()),
            ]),
        };
        fs::write(
            root.join("metadata/release.json"),
            serde_json::to_vec_pretty(&release).unwrap(),
        )
        .unwrap();
        fs::write(root.join("metadata/app-update.json"), b"test-update-policy").unwrap();
        fs::write(root.join("nsis/ssdev-setup.exe"), installer_bytes).unwrap();
        create_manifest(root, "metadata/artifacts.json").unwrap();
        fs::write(
            root.join("metadata/artifacts.json.sig"),
            b"test-update-signature",
        )
        .unwrap();
        capture_bundle_policy_identity(root, None).unwrap()
    }

    fn build_signed_go_fixture(root: &Path, evaluated_at: u64) -> SignedGoFixture {
        let revision = "d".repeat(40);
        let approval_key = SigningKey::from_bytes(&[11_u8; 32]);
        let plugin_key = SigningKey::from_bytes(&[21_u8; 32]);
        let migration_key = SigningKey::from_bytes(&[22_u8; 32]);
        let windows_key = SigningKey::from_bytes(&[23_u8; 32]);
        let approval_trust_path = root.join("approval-trust.json");
        let evidence_trust_path = root.join("evidence-trust.json");
        fs::write(
            &approval_trust_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "schemaVersion": 2,
                "keys": [{
                    "keyId": "cutover-approval",
                    "algorithm": "ed25519",
                    "publicKey": BASE64.encode(approval_key.verifying_key().to_bytes()),
                    "purposes": ["cutover-decision"],
                    "status": "active"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            &evidence_trust_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "schemaVersion": 2,
                "keys": [
                    {
                        "keyId": "plugin-matrix-qa",
                        "algorithm": "ed25519",
                        "publicKey": BASE64.encode(plugin_key.verifying_key().to_bytes()),
                        "purposes": ["cutover-evidence"],
                        "status": "active"
                    },
                    {
                        "keyId": "migration-audit-qa",
                        "algorithm": "ed25519",
                        "publicKey": BASE64.encode(migration_key.verifying_key().to_bytes()),
                        "purposes": ["cutover-evidence"],
                        "status": "active"
                    },
                    {
                        "keyId": "windows-package-qa",
                        "algorithm": "ed25519",
                        "publicKey": BASE64.encode(windows_key.verifying_key().to_bytes()),
                        "purposes": ["cutover-evidence"],
                        "status": "active"
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();
        let approval_trust_sha256 = sha256_file(&approval_trust_path).unwrap();
        let evidence_trust_sha256 = sha256_file(&evidence_trust_path).unwrap();
        let candidate_bundle_root = root.join("candidate-bundle");
        let candidate_bundle =
            write_test_candidate_bundle(&candidate_bundle_root, &revision, b"approved-installer");

        let policy_path = root.join("production-policy.json");
        let policy_attestation_path = root.join("production-policy.sig.json");
        let policy = ProductionCutoverPolicy {
            schema_version: CUTOVER_POLICY_SCHEMA_VERSION,
            target_source_revision: revision.clone(),
            expected_app_version: "1.2.3".into(),
            expected_previous_app_version: "1.2.2".into(),
            maximum_evidence_age_seconds: 3_600,
            maximum_cutover_decision_age_seconds: 86_400,
            expected_windows_artifact_manifest_sha256: candidate_bundle
                .artifact_manifest_sha256
                .clone(),
            expected_previous_windows_artifact_manifest_sha256: "d".repeat(64),
            expected_previous_release_metadata_sha256: "9".repeat(64),
            expected_plugin_release_set_spec_sha256: "0".repeat(64),
            expected_plugin_package_set_sha256: "9".repeat(64),
            expected_plugin_trust_store_sha256: approval_trust_sha256.clone(),
            expected_evidence_trust_store_sha256: evidence_trust_sha256.clone(),
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
        };
        write_production_cutover_policy(&policy_path, &policy).unwrap();
        let policy_bytes = fs::read(&policy_path).unwrap();
        write_test_attestation(
            &policy_attestation_path,
            "cutover-approval",
            &approval_key,
            &cutover_policy_signing_payload(&policy_bytes).unwrap(),
        );

        let plugin_path = root.join("plugin-evidence.json");
        let plugin_attestation_path = root.join("plugin-evidence.sig.json");
        let plugin = PluginMatrixEvidence {
            schema_version: PLUGIN_MATRIX_EVIDENCE_SCHEMA_VERSION,
            evidence_type: EvidenceType::PluginMatrix,
            source_revision: revision.clone(),
            source_dirty: false,
            executed_at_unix_seconds: evaluated_at,
            environment: "plugin-qa".into(),
            runner_os: "windows".into(),
            runner_architecture: "x86_64".into(),
            release_set_spec_sha256: "0".repeat(64),
            package_set_sha256: "9".repeat(64),
            plugin_set_sha256: "1".repeat(64),
            trust_store_sha256: approval_trust_sha256.clone(),
            matrix_sha256: "3".repeat(64),
            x86_host_sha256: "4".repeat(64),
            x64_host_sha256: "5".repeat(64),
            plugin_count: 1,
            service_count: 2,
            method_count: 3,
            enabled_case_count: 3,
            passed: true,
        };
        write_plugin_matrix_evidence(&plugin_path, &plugin).unwrap();
        let plugin_bytes = fs::read(&plugin_path).unwrap();
        write_test_attestation(
            &plugin_attestation_path,
            "plugin-matrix-qa",
            &plugin_key,
            &evidence_attestation_signing_payload(
                EvidenceAttestationKind::PluginMatrix,
                &plugin_bytes,
            )
            .unwrap(),
        );

        let migration_path = root.join("migration-evidence.json");
        let migration_attestation_path = root.join("migration-evidence.sig.json");
        let migration = MigrationAuditEvidence {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            evidence_type: EvidenceType::MigrationAudit,
            source_revision: revision.clone(),
            source_dirty: false,
            executed_at_unix_seconds: evaluated_at,
            environment: "migration-qa".into(),
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
            desktop_callback_http_evidence: HttpEvidenceLevel::NotObserved,
            critical_findings: 0,
            warning_findings: 0,
            info_findings: 1,
            finding_code_counts: BTreeMap::from([("inventory-summary".into(), 1)]),
        };
        write_migration_audit_evidence(&migration_path, &migration).unwrap();
        let migration_bytes = fs::read(&migration_path).unwrap();
        write_test_attestation(
            &migration_attestation_path,
            "migration-audit-qa",
            &migration_key,
            &evidence_attestation_signing_payload(
                EvidenceAttestationKind::MigrationAudit,
                &migration_bytes,
            )
            .unwrap(),
        );

        let windows_path = root.join("windows-evidence.json");
        let windows_attestation_path = root.join("windows-evidence.sig.json");
        let windows = WindowsPackageEvidence {
            schema_version: WINDOWS_PACKAGE_EVIDENCE_SCHEMA_VERSION,
            evidence_type: EvidenceType::WindowsPackage,
            source_revision: revision.clone(),
            source_dirty: false,
            executed_at_unix_seconds: evaluated_at,
            environment: "windows-qa".into(),
            runner_os: "windows".into(),
            runner_architecture: "x86_64".into(),
            release_metadata_sha256: candidate_bundle.release_metadata_sha256,
            artifact_manifest_sha256: candidate_bundle.artifact_manifest_sha256,
            plugin_trust_store_sha256: approval_trust_sha256.clone(),
            origin_policy_sha256: "a".repeat(64),
            x86_host_sha256: "4".repeat(64),
            x64_host_sha256: "5".repeat(64),
            deployment_check_sha256: Some("6".repeat(64)),
            deployment_check_generated_at_unix_ms: Some(evaluated_at * 1_000),
            app_version: "1.2.3".into(),
            authenticode_required: true,
            authenticode_verified: true,
            nsis_install_verified: true,
            msi_install_verified: false,
            launch_verified: true,
            upgrade_verified: true,
            rollback_verified: true,
            application_state_preservation_verified: true,
            previous_app_version: Some("1.2.2".into()),
            previous_release_metadata_sha256: Some("9".repeat(64)),
            previous_artifact_manifest_sha256: Some("d".repeat(64)),
            passed: true,
        };
        write_windows_package_evidence(&windows_path, &windows).unwrap();
        let windows_bytes = fs::read(&windows_path).unwrap();
        write_test_attestation(
            &windows_attestation_path,
            "windows-package-qa",
            &windows_key,
            &evidence_attestation_signing_payload(
                EvidenceAttestationKind::WindowsPackage,
                &windows_bytes,
            )
            .unwrap(),
        );

        let decision_path = root.join("cutover-decision.json");
        let decision_attestation_path = root.join("cutover-decision.sig.json");
        let decision = evaluate_production_cutover(
            ProductionCutoverInputs {
                policy: &policy,
                policy_sha256: sha256_file(&policy_path).unwrap(),
                policy_attestation_sha256: sha256_file(&policy_attestation_path).unwrap(),
                evidence_trust_store_sha256: evidence_trust_sha256,
                approval_trust_store_sha256: approval_trust_sha256,
                plugin: &plugin,
                plugin_sha256: sha256_file(&plugin_path).unwrap(),
                plugin_attestation_sha256: sha256_file(&plugin_attestation_path).unwrap(),
                migration: &migration,
                migration_sha256: sha256_file(&migration_path).unwrap(),
                migration_attestation_sha256: sha256_file(&migration_attestation_path).unwrap(),
                windows: &windows,
                windows_sha256: sha256_file(&windows_path).unwrap(),
                windows_attestation_sha256: sha256_file(&windows_attestation_path).unwrap(),
            },
            evaluated_at,
        )
        .unwrap();
        assert!(decision.eligible);
        assert_eq!(decision.schema_version, CUTOVER_DECISION_SCHEMA_VERSION);
        write_cutover_decision(&decision_path, &decision).unwrap();
        let decision_bytes = fs::read(&decision_path).unwrap();
        write_test_attestation(
            &decision_attestation_path,
            "cutover-approval",
            &approval_key,
            &cutover_decision_signing_payload(&decision_bytes),
        );

        let arguments = [
            PathBuf::from("verify-go"),
            decision_path,
            decision_attestation_path,
            policy_path,
            policy_attestation_path,
            approval_trust_path.clone(),
            evidence_trust_path.clone(),
            plugin_path,
            plugin_attestation_path,
            migration_path,
            migration_attestation_path,
            windows_path.clone(),
            windows_attestation_path.clone(),
        ]
        .into_iter()
        .map(|path| path.into_os_string())
        .collect();
        SignedGoFixture {
            arguments,
            approval_trust_path,
            evidence_trust_path,
            candidate_bundle_root,
            windows_path,
            windows_signing_key: windows_key,
            windows_attestation_path,
        }
    }

    fn current_go_arguments(
        fixture: &SignedGoFixture,
        root: &Path,
    ) -> (Vec<OsString>, PathBuf, PathBuf) {
        let current_approval = root.join("current-approval-trust.json");
        let current_evidence = root.join("current-evidence-trust.json");
        fs::copy(&fixture.approval_trust_path, &current_approval).unwrap();
        fs::copy(&fixture.evidence_trust_path, &current_evidence).unwrap();
        let mut arguments = fixture.arguments.clone();
        arguments[0] = OsString::from("check-current-go");
        arguments.push(current_approval.clone().into_os_string());
        arguments.push(current_evidence.clone().into_os_string());
        arguments.push(fixture.candidate_bundle_root.clone().into_os_string());
        (arguments, current_approval, current_evidence)
    }

    #[test]
    fn previous_release_metadata_identifies_only_a_bundle_metadata_directory() {
        let path = Path::new("verified/bundle/metadata/release.json");
        assert_eq!(
            release_bundle_root_from_metadata(path).unwrap(),
            Path::new("verified/bundle")
        );
        assert!(
            release_bundle_root_from_metadata(Path::new("verified/bundle/release.json")).is_err()
        );
    }

    #[test]
    fn documented_policy_approvals_are_strict_and_complete() {
        let approval: PolicyApprovalInputs = serde_json::from_str(include_str!(
            "../../../docs/cutover-policy-approval.example.json"
        ))
        .unwrap();
        assert_eq!(approval.schema_version, 2);
        assert_eq!(approval.maximum_evidence_age_seconds, 604_800);
        assert_eq!(approval.maximum_cutover_decision_age_seconds, 86_400);

        let with_unknown = include_str!("../../../docs/cutover-policy-approval.example.json")
            .replace("\n}", ",\n  \"unexpected\": true\n}");
        assert!(serde_json::from_str::<PolicyApprovalInputs>(&with_unknown).is_err());
    }

    #[test]
    fn release_set_material_roles_require_one_file_and_one_directory() {
        let root = tempdir().unwrap();
        let spec = root.path().join("release-set.json");
        let packages = root.path().join("packages");
        fs::write(&spec, b"{}").unwrap();
        fs::create_dir(&packages).unwrap();
        assert_eq!(
            single_file_and_directory(vec![packages.clone(), spec.clone()], "release set").unwrap(),
            (spec.clone(), packages)
        );

        let second = root.path().join("second.json");
        fs::write(&second, b"{}").unwrap();
        assert!(single_file_and_directory(vec![spec, second], "release set").is_err());
    }

    #[test]
    fn trust_store_must_be_inside_an_approved_material_input() {
        let root = tempdir().unwrap();
        let approved = root.path().join("approved");
        let unrelated = root.path().join("unrelated");
        fs::create_dir(&approved).unwrap();
        fs::create_dir(&unrelated).unwrap();
        let trust = approved.join("evidence-trust.json");
        let substitute = unrelated.join("evidence-trust.json");
        fs::write(&trust, b"{}").unwrap();
        fs::write(&substitute, b"{}").unwrap();
        assert!(require_category_contains_file(&trust, &[approved], "evidence trust").is_ok());
        assert!(require_category_contains_file(&substitute, &[trust], "evidence trust").is_err());
    }

    #[test]
    fn policy_preparation_requires_active_keys_for_each_cutover_duty() {
        let root = tempdir().unwrap();
        let evidence = root.path().join("evidence-trust.json");
        let approval_trust = root.path().join("release-trust.json");
        let public_key = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
        let approval: PolicyApprovalInputs = serde_json::from_str(include_str!(
            "../../../docs/cutover-policy-approval.example.json"
        ))
        .unwrap();
        let evidence_keys = [
            &approval.plugin_matrix_signer_key_id,
            &approval.migration_audit_signer_key_id,
            &approval.windows_package_signer_key_id,
        ]
        .into_iter()
        .map(|key_id| {
            serde_json::json!({
                "keyId": key_id,
                "algorithm": "ed25519",
                "publicKey": public_key,
                "purposes": ["cutover-evidence"],
                "status": "active"
            })
        })
        .collect::<Vec<_>>();
        fs::write(
            &evidence,
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "keys": evidence_keys
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            &approval_trust,
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "keys": [{
                    "keyId": approval.cutover_decision_signer_key_id,
                    "algorithm": "ed25519",
                    "publicKey": public_key,
                    "purposes": ["cutover-decision"],
                    "status": "active"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        validate_cutover_signing_keys(&evidence, &approval_trust, &approval).unwrap();

        let mut retired: serde_json::Value =
            serde_json::from_slice(&fs::read(&evidence).unwrap()).unwrap();
        retired["keys"][0]["status"] = serde_json::json!("retired");
        fs::write(&evidence, serde_json::to_vec(&retired).unwrap()).unwrap();
        assert!(validate_cutover_signing_keys(&evidence, &approval_trust, &approval).is_err());
    }

    #[test]
    fn usage_places_unsigned_precheck_before_the_final_signed_decision() {
        let help = usage();
        let precheck = help.find("ssdev-cutover-evidence precheck").unwrap();
        let decide = help.find("ssdev-cutover-evidence decide").unwrap();
        let verify = help.find("ssdev-cutover-evidence verify-go").unwrap();
        let current = help
            .find("ssdev-cutover-evidence check-current-go")
            .unwrap();

        assert!(precheck < decide);
        assert!(decide < verify);
        assert!(verify < current);
        assert!(help.contains("<plugin-evidence.json> <migration-evidence.json>"));
        assert!(!help[precheck..decide].contains("plugin-evidence.sig.json"));
        assert!(help[verify..].contains("<cutover-decision.sig.json>"));
        assert!(help[current..].contains("<current-approval-trust.json>"));
        assert!(help[current..].contains("<current-evidence-trust.json>"));
        assert!(help[current..].contains("<candidate-windows-bundle-root>"));
    }

    #[test]
    fn unsigned_precheck_hashes_bind_every_input_without_writing_output() {
        let root = tempdir().unwrap();
        let paths = (0..7)
            .map(|index| {
                let path = root.path().join(format!("input-{index}.json"));
                fs::write(&path, format!("input-{index}")).unwrap();
                path
            })
            .collect::<Vec<_>>();
        let before = capture_unsigned_cutover_hashes(
            &paths[0], &paths[1], &paths[2], &paths[3], &paths[4], &paths[5], &paths[6],
        )
        .unwrap();

        fs::write(&paths[6], "changed").unwrap();
        let after = capture_unsigned_cutover_hashes(
            &paths[0], &paths[1], &paths[2], &paths[3], &paths[4], &paths[5], &paths[6],
        )
        .unwrap();

        assert_ne!(before, after);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 7);
    }

    #[test]
    fn cutover_blocker_summary_is_actionable_and_rejects_unknown_codes() {
        let codes = vec![
            "migration-warning-findings".to_string(),
            "windows-rollback-not-verified".to_string(),
        ];
        let summary = render_cutover_blockers("cutover: BLOCKED", &codes, "rerun").unwrap();

        assert!(summary.starts_with("cutover: BLOCKED (2 blockers)"));
        assert_eq!(summary.matches("blocker:").count(), 2);
        assert_eq!(summary.matches("action:").count(), 2);
        assert!(summary.contains("next: rerun"));
        assert!(!summary.contains("C:\\"));
        assert!(!summary.contains("/Users/"));
        assert!(render_cutover_blockers(
            "cutover: BLOCKED",
            &["unknown-future-blocker".into()],
            "rerun",
        )
        .is_err());
        assert!(render_cutover_blockers("cutover: BLOCKED", &[], "rerun").is_err());
    }

    #[test]
    fn signed_archive_hashes_bind_all_twelve_inputs_without_writing_output() {
        let root = tempdir().unwrap();
        let paths = (0..12)
            .map(|index| {
                let path = root.path().join(format!("archive-{index}.json"));
                fs::write(&path, format!("archive-{index}")).unwrap();
                path
            })
            .collect::<Vec<_>>();
        let before = capture_signed_cutover_archive_hashes(
            &paths[0], &paths[1], &paths[2], &paths[3], &paths[4], &paths[5], &paths[6], &paths[7],
            &paths[8], &paths[9], &paths[10], &paths[11],
        )
        .unwrap();

        fs::write(&paths[1], "changed-envelope").unwrap();
        let after = capture_signed_cutover_archive_hashes(
            &paths[0], &paths[1], &paths[2], &paths[3], &paths[4], &paths[5], &paths[6], &paths[7],
            &paths[8], &paths[9], &paths[10], &paths[11],
        )
        .unwrap();

        assert_ne!(before, after);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 12);
    }

    #[test]
    fn verify_go_replays_a_complete_signed_archive_and_rejects_resigned_substitution() {
        let root = tempdir().unwrap();
        let fixture = build_signed_go_fixture(root.path(), 1_000);

        assert!(run_verify_go(&fixture.arguments).unwrap());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 13);

        let mut changed_windows: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.windows_path).unwrap()).unwrap();
        changed_windows["environment"] = serde_json::json!("substituted-windows-qa");
        fs::write(
            &fixture.windows_path,
            serde_json::to_vec_pretty(&changed_windows).unwrap(),
        )
        .unwrap();
        let changed_bytes = fs::read(&fixture.windows_path).unwrap();
        write_test_attestation(
            &fixture.windows_attestation_path,
            "windows-package-qa",
            &fixture.windows_signing_key,
            &evidence_attestation_signing_payload(
                EvidenceAttestationKind::WindowsPackage,
                &changed_bytes,
            )
            .unwrap(),
        );

        let error = run_verify_go(&fixture.arguments).unwrap_err();
        assert!(error
            .to_string()
            .contains("does not reproduce from the supplied archive inputs"));
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 13);
    }

    #[test]
    fn check_current_go_accepts_only_the_policy_approved_rollout_window() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let current_root = tempdir().unwrap();
        let current = build_signed_go_fixture(current_root.path(), now);
        let (current_arguments, _, _) = current_go_arguments(&current, current_root.path());
        assert!(run_check_current_go(&current_arguments).unwrap());
        assert_eq!(fs::read_dir(current_root.path()).unwrap().count(), 15);

        let stale_root = tempdir().unwrap();
        let stale = build_signed_go_fixture(stale_root.path(), now.saturating_sub(86_401));
        let (stale_arguments, _, _) = current_go_arguments(&stale, stale_root.path());
        assert!(!run_check_current_go(&stale_arguments).unwrap());
        assert_eq!(fs::read_dir(stale_root.path()).unwrap().count(), 15);
    }

    #[test]
    fn check_current_go_accepts_retired_signers_and_blocks_current_revocation() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let root = tempdir().unwrap();
        let fixture = build_signed_go_fixture(root.path(), now);
        let (arguments, current_approval, current_evidence) =
            current_go_arguments(&fixture, root.path());

        let mut approval: serde_json::Value =
            serde_json::from_slice(&fs::read(&current_approval).unwrap()).unwrap();
        approval["keys"][0]["status"] = serde_json::json!("retired");
        fs::write(
            &current_approval,
            serde_json::to_vec_pretty(&approval).unwrap(),
        )
        .unwrap();
        assert!(run_check_current_go(&arguments).unwrap());

        let mut evidence: serde_json::Value =
            serde_json::from_slice(&fs::read(&current_evidence).unwrap()).unwrap();
        evidence["keys"][2]["status"] = serde_json::json!("revoked");
        fs::write(
            &current_evidence,
            serde_json::to_vec_pretty(&evidence).unwrap(),
        )
        .unwrap();
        assert!(!run_check_current_go(&arguments).unwrap());

        evidence["keys"][2]["status"] = serde_json::json!("active");
        fs::write(
            &current_evidence,
            serde_json::to_vec_pretty(&evidence).unwrap(),
        )
        .unwrap();
        approval["keys"][0]["status"] = serde_json::json!("revoked");
        fs::write(
            &current_approval,
            serde_json::to_vec_pretty(&approval).unwrap(),
        )
        .unwrap();
        assert!(!run_check_current_go(&arguments).unwrap());

        assert!(run_verify_go(&fixture.arguments).unwrap());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 15);
    }

    #[test]
    fn check_current_go_blocks_a_different_valid_windows_bundle() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let root = tempdir().unwrap();
        let fixture = build_signed_go_fixture(root.path(), now);
        let (mut arguments, _, _) = current_go_arguments(&fixture, root.path());
        let approved_identity =
            capture_bundle_policy_identity(&fixture.candidate_bundle_root, None).unwrap();
        let substitute = root.path().join("substitute-bundle");
        let substitute_identity =
            write_test_candidate_bundle(&substitute, &"d".repeat(40), b"different-valid-installer");
        assert_ne!(
            substitute_identity.artifact_manifest_sha256,
            approved_identity.artifact_manifest_sha256
        );
        arguments[15] = substitute.into_os_string();

        assert!(!run_check_current_go(&arguments).unwrap());
        arguments[15] = fixture.candidate_bundle_root.clone().into_os_string();
        fs::write(
            fixture.candidate_bundle_root.join("nsis/ssdev-setup.exe"),
            b"tampered-installer",
        )
        .unwrap();
        assert!(!run_check_current_go(&arguments).unwrap());
        assert!(run_verify_go(&fixture.arguments).unwrap());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 16);
    }
}
