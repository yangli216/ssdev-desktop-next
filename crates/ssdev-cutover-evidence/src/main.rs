use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use semver::Version;
use ssdev_cutover_evidence::{
    evaluate_production_cutover, load_migration_audit_evidence, load_plugin_matrix_evidence,
    load_production_cutover_policy, load_windows_package_evidence, prepare_new_output, sha256_file,
    verify_evidence_attestation, write_cutover_decision, write_windows_package_evidence,
    EvidenceAttestationKind, EvidenceType, ProductionCutoverInputs, WindowsPackageEvidence,
    WINDOWS_PACKAGE_EVIDENCE_SCHEMA_VERSION,
};
use ssdev_release_manifest::{capture_source_identity, verify_release_metadata, ReleaseMetadata};

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
        "windows-package" => {
            run_windows_package(&arguments)?;
            Ok(true)
        }
        "decide" => run_decision(&arguments),
        _ => Err(usage().into()),
    }
}

fn run_windows_package(arguments: &[OsString]) -> Result<(), Box<dyn Error>> {
    if !matches!(arguments.len(), 13 | 14) {
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
    let previous_metadata_path = arguments
        .get(13)
        .map(|value| path_argument(Some(value), "previous release metadata"))
        .transpose()?
        .map(|path| canonical_regular_file(&path, "previous release metadata"))
        .transpose()?;
    if let Some(path) = &previous_metadata_path {
        require_file_name(path, "release.json")?;
        let previous_bundle_root = release_bundle_root_from_metadata(path)?;
        if output.starts_with(previous_bundle_root) {
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
    let release_metadata_before = sha256_file(&release_metadata_path)?;
    let artifact_manifest_before = sha256_file(&artifact_manifest_path)?;
    let current = verify_release_metadata(&release_metadata_path, Some(&workspace))?;
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
    if source_before != source_after
        || release_metadata_before != release_metadata_after
        || artifact_manifest_before != artifact_manifest_after
        || previous_hash_before != previous_hash_after
        || previous_artifact_manifest_hash_before != previous_artifact_manifest_hash_after
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
            app_version: current.app_version,
            authenticode_required: current.authenticode_required,
            authenticode_verified,
            nsis_install_verified: true,
            // Retained in the evidence schema so existing signed records remain readable.
            msi_install_verified: false,
            launch_verified,
            upgrade_verified: previous.is_some(),
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
    if arguments.len() != 10 {
        return Err(usage().into());
    }
    let policy_path = path_argument(arguments.get(1), "production cutover policy")?;
    let trust_store_path = path_argument(arguments.get(2), "evidence trust store")?;
    let plugin_path = path_argument(arguments.get(3), "plugin matrix evidence")?;
    let plugin_attestation_path = path_argument(arguments.get(4), "plugin matrix attestation")?;
    let migration_path = path_argument(arguments.get(5), "migration audit evidence")?;
    let migration_attestation_path =
        path_argument(arguments.get(6), "migration audit attestation")?;
    let windows_path = path_argument(arguments.get(7), "Windows package evidence")?;
    let windows_attestation_path = path_argument(arguments.get(8), "Windows package attestation")?;
    let output = prepare_new_output(&path_argument(arguments.get(9), "decision output")?)?;

    let policy_hash_before = sha256_file(&policy_path)?;
    let trust_store_hash_before = sha256_file(&trust_store_path)?;
    let plugin_hash_before = sha256_file(&plugin_path)?;
    let plugin_attestation_hash_before = sha256_file(&plugin_attestation_path)?;
    let migration_hash_before = sha256_file(&migration_path)?;
    let migration_attestation_hash_before = sha256_file(&migration_attestation_path)?;
    let windows_hash_before = sha256_file(&windows_path)?;
    let windows_attestation_hash_before = sha256_file(&windows_attestation_path)?;
    let policy = load_production_cutover_policy(&policy_path)?;
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
    let trust_store_hash_after = sha256_file(&trust_store_path)?;
    let plugin_hash_after = sha256_file(&plugin_path)?;
    let plugin_attestation_hash_after = sha256_file(&plugin_attestation_path)?;
    let migration_hash_after = sha256_file(&migration_path)?;
    let migration_attestation_hash_after = sha256_file(&migration_attestation_path)?;
    let windows_hash_after = sha256_file(&windows_path)?;
    let windows_attestation_hash_after = sha256_file(&windows_attestation_path)?;
    if policy_hash_before != policy_hash_after
        || trust_store_hash_before != trust_store_hash_after
        || plugin_hash_before != plugin_hash_after
        || plugin_attestation_hash_before != plugin_attestation_hash_after
        || migration_hash_before != migration_hash_after
        || migration_attestation_hash_before != migration_attestation_hash_after
        || windows_hash_before != windows_hash_after
        || windows_attestation_hash_before != windows_attestation_hash_after
    {
        return Err(invalid_input(
            "cutover policy or evidence changed during evaluation",
        ));
    }
    let decision = evaluate_production_cutover(
        ProductionCutoverInputs {
            policy: &policy,
            policy_sha256: policy_hash_after,
            evidence_trust_store_sha256: trust_store_hash_after,
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
    "usage:\n  ssdev-cutover-evidence windows-package <workspace> <release.json> <artifacts.json> <output> <environment> <Nsis> <launch-verified> <authenticode-verified> <installed-plugin-trust-store-sha256> <installed-origin-policy-sha256> <x86-host-sha256> <x64-host-sha256> [previous-release.json]\n  ssdev-cutover-evidence decide <production-policy.json> <evidence-trust.json> <plugin-evidence.json> <plugin-evidence.sig.json> <migration-evidence.json> <migration-evidence.sig.json> <windows-evidence.json> <windows-evidence.sig.json> <decision-output.json>"
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
