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
    evaluate_production_cutover, evaluate_production_cutover_readiness,
    load_delivery_ready_deployment_check, load_migration_audit_evidence,
    load_plugin_matrix_evidence, load_windows_package_evidence, prepare_new_output, sha256_file,
    verify_evidence_attestation, verify_production_cutover_policy_attestation,
    write_cutover_decision, write_production_cutover_policy, write_windows_package_evidence,
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
    if approval.schema_version != 1 {
        return Err(invalid_input("policy approval inputs must use schema 1"));
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
            "BLOCKED: {} blocker(s): {}",
            readiness.blocker_codes.len(),
            readiness.blocker_codes.join(", ")
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
            "NO-GO: {} blocker(s): {}",
            decision.blocker_codes.len(),
            decision.blocker_codes.join(", ")
        );
    }
    Ok(decision.eligible)
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
    "usage:\n  ssdev-cutover-evidence prepare-policy <workspace> <pilot-materials-root> <pilot-manifest.json> <pilot-report.json> <candidate-bundle-root> <evidence-trust.json> <policy-approval-inputs.json> <policy-output.json>\n  ssdev-cutover-evidence windows-package <workspace> <release.json> <artifacts.json> <output> <environment> <Nsis> <launch-verified> <authenticode-verified> <installed-plugin-trust-store-sha256> <installed-origin-policy-sha256> <x86-host-sha256> <x64-host-sha256> <deployment-check.json|none> <application-state-preservation-verified> [previous-release.json]\n  ssdev-cutover-evidence precheck <production-policy.json> <production-policy.sig.json> <approval-trust.json> <evidence-trust.json> <plugin-evidence.json> <migration-evidence.json> <windows-evidence.json>\n  ssdev-cutover-evidence decide <production-policy.json> <production-policy.sig.json> <approval-trust.json> <evidence-trust.json> <plugin-evidence.json> <plugin-evidence.sig.json> <migration-evidence.json> <migration-evidence.sig.json> <windows-evidence.json> <windows-evidence.sig.json> <decision-output.json>"
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
        assert_eq!(approval.schema_version, 1);
        assert_eq!(approval.maximum_evidence_age_seconds, 604_800);

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

        assert!(precheck < decide);
        assert!(help.contains("<plugin-evidence.json> <migration-evidence.json>"));
        assert!(!help[precheck..decide].contains("plugin-evidence.sig.json"));
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
}
