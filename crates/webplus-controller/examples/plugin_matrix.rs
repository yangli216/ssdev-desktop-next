use std::error::Error;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ssdev_cutover_evidence::{
    digest_named_payloads, prepare_new_output, sha256_file, write_plugin_matrix_evidence,
    EvidenceType, PluginMatrixEvidence, PLUGIN_MATRIX_EVIDENCE_SCHEMA_VERSION,
};
use ssdev_plugin_tool::{check_release_root_against_set, validate_executable_matrix};
use ssdev_release_manifest::{capture_source_identity, SourceIdentity};
use webplus_controller::{PluginController, PluginTrust, SupervisorConfig};
use webplus_plugin_config::{discover_plugins, PluginManifest};
use webplus_plugin_trust::{prepare_signing_material, read_identity, TrustStore};

#[derive(Debug, PartialEq, Eq)]
struct EvidenceInputs {
    source: SourceIdentity,
    release_set_spec_sha256: String,
    package_set_sha256: String,
    plugin_set_sha256: String,
    trust_store_sha256: String,
    matrix_sha256: String,
    x86_host_sha256: String,
    x64_host_sha256: String,
}

struct EvidenceFiles<'a> {
    workspace: &'a std::path::Path,
    x86_host: &'a std::path::Path,
    x64_host: &'a std::path::Path,
    plugin_root: &'a std::path::Path,
    release_set_spec: &'a std::path::Path,
    trust_store: &'a std::path::Path,
    matrix: &'a std::path::Path,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MatrixBlocker {
    ArgumentsInvalid,
    RunnerUnsupported,
    RunnerFailed,
    EvidenceOutputInvalid,
    TrustStoreInvalid,
    PluginDiscoveryFailed,
    PluginVerificationFailed,
    MatrixDefinitionInvalid,
    ReleaseInputsInvalid,
    HostPreflightFailed,
    GoldenCaseFailed,
    InputsChanged,
    RunnerClockInvalid,
    EvidenceWriteFailed,
}

impl MatrixBlocker {
    #[cfg(test)]
    const ALL: [Self; 14] = [
        Self::ArgumentsInvalid,
        Self::RunnerUnsupported,
        Self::RunnerFailed,
        Self::EvidenceOutputInvalid,
        Self::TrustStoreInvalid,
        Self::PluginDiscoveryFailed,
        Self::PluginVerificationFailed,
        Self::MatrixDefinitionInvalid,
        Self::ReleaseInputsInvalid,
        Self::HostPreflightFailed,
        Self::GoldenCaseFailed,
        Self::InputsChanged,
        Self::RunnerClockInvalid,
        Self::EvidenceWriteFailed,
    ];

    const fn code(self) -> &'static str {
        match self {
            Self::ArgumentsInvalid => "matrix-arguments-invalid",
            Self::RunnerUnsupported => "matrix-runner-unsupported",
            Self::RunnerFailed => "matrix-runner-failed",
            Self::EvidenceOutputInvalid => "matrix-evidence-output-invalid",
            Self::TrustStoreInvalid => "matrix-trust-store-invalid",
            Self::PluginDiscoveryFailed => "matrix-plugin-discovery-failed",
            Self::PluginVerificationFailed => "matrix-plugin-verification-failed",
            Self::MatrixDefinitionInvalid => "matrix-definition-invalid",
            Self::ReleaseInputsInvalid => "matrix-release-inputs-invalid",
            Self::HostPreflightFailed => "matrix-host-preflight-failed",
            Self::GoldenCaseFailed => "matrix-golden-case-failed",
            Self::InputsChanged => "matrix-inputs-changed",
            Self::RunnerClockInvalid => "matrix-runner-clock-invalid",
            Self::EvidenceWriteFailed => "matrix-evidence-write-failed",
        }
    }

    const fn action(self) -> &'static str {
        match self {
            Self::ArgumentsInvalid => {
                "Use the documented wrapper with every required argument; do not invoke the example directly."
            }
            Self::RunnerUnsupported => {
                "Run the formal matrix on an approved Windows x64 validation machine."
            }
            Self::RunnerFailed => {
                "Discard this run, preserve the controlled inputs, and inspect the validation machine before retrying."
            }
            Self::EvidenceOutputInvalid => {
                "Choose a new evidence file outside the source workspace and verified plugin root."
            }
            Self::TrustStoreInvalid => {
                "Restore the approved active plugin trust store, then repeat the release-set check."
            }
            Self::PluginDiscoveryFailed => {
                "Re-materialize the approved release set into a new plugin root; do not repair it in place."
            }
            Self::PluginVerificationFailed => {
                "Re-materialize plugins from the approved signed packages and trust store."
            }
            Self::MatrixDefinitionInvalid => {
                "Run matrix-check, complete every required review, and approve a fully covered non-draft matrix."
            }
            Self::ReleaseInputsInvalid => {
                "Repeat release-set-check and materialization with the approved packages, trust store, and matrix."
            }
            Self::HostPreflightFailed => {
                "Verify both signed delivery hosts and native dependencies on the validation machine before retrying."
            }
            Self::GoldenCaseFailed => {
                "Stop release approval, reconcile device results in the controlled matrix workspace, then run a new matrix."
            }
            Self::InputsChanged => {
                "Discard this run, restore immutable approved inputs, and execute the complete matrix again."
            }
            Self::RunnerClockInvalid => {
                "Correct and synchronize the validation machine clock before running the matrix again."
            }
            Self::EvidenceWriteFailed => {
                "Use a new writable evidence destination and rerun the complete matrix; do not reconstruct evidence manually."
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct MatrixRunFailure {
    blocker: MatrixBlocker,
    affected_count: Option<usize>,
}

impl MatrixRunFailure {
    const fn new(blocker: MatrixBlocker) -> Self {
        Self {
            blocker,
            affected_count: None,
        }
    }

    const fn with_count(blocker: MatrixBlocker, affected_count: usize) -> Self {
        Self {
            blocker,
            affected_count: Some(affected_count),
        }
    }

    fn emit(&self) {
        let stderr = std::io::stderr();
        let mut output = stderr.lock();
        let _ = writeln!(output, "plugin matrix: BLOCKED");
        let _ = writeln!(output, "blocker: {}", self.blocker.code());
        if let Some(affected_count) = self.affected_count {
            let _ = writeln!(output, "affected-count: {affected_count}");
        }
        let _ = writeln!(output, "action: {}", self.blocker.action());
        let _ = writeln!(output, "evidence: not produced");
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
struct MatrixTally {
    executed: usize,
    skipped: usize,
    failed: usize,
}

impl MatrixTally {
    fn record_skipped(&mut self) {
        self.skipped += 1;
    }

    fn record_executed(&mut self, passed: bool) {
        self.executed += 1;
        if !passed {
            self.failed += 1;
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    install_redacted_panic_hook();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            failure.emit();
            ExitCode::from(1)
        }
    }
}

async fn run() -> Result<(), MatrixRunFailure> {
    let mut arguments = std::env::args_os().skip(1);
    let arguments_invalid = || MatrixRunFailure::new(MatrixBlocker::ArgumentsInvalid);
    let x86_host = required(&mut arguments, "x86 plugin host").map_err(|_| arguments_invalid())?;
    let x64_host = required(&mut arguments, "x64 plugin host").map_err(|_| arguments_invalid())?;
    let plugin_root = required(&mut arguments, "plugin root").map_err(|_| arguments_invalid())?;
    let release_set_spec =
        required(&mut arguments, "release set spec").map_err(|_| arguments_invalid())?;
    let trust_store_path =
        required(&mut arguments, "trust store").map_err(|_| arguments_invalid())?;
    let matrix_path = required(&mut arguments, "matrix JSON").map_err(|_| arguments_invalid())?;
    let workspace =
        required(&mut arguments, "source workspace").map_err(|_| arguments_invalid())?;
    let evidence_output =
        required(&mut arguments, "evidence output").map_err(|_| arguments_invalid())?;
    let environment =
        required_string(&mut arguments, "evidence environment").map_err(|_| arguments_invalid())?;
    if arguments.next().is_some() {
        return Err(arguments_invalid());
    }
    if std::env::consts::OS != "windows" || std::env::consts::ARCH != "x86_64" {
        return Err(MatrixRunFailure::new(MatrixBlocker::RunnerUnsupported));
    }
    let evidence_output = prepare_new_output(&evidence_output)
        .map_err(|_| MatrixRunFailure::new(MatrixBlocker::EvidenceOutputInvalid))?;
    let plugin_root_canonical = plugin_root
        .canonicalize()
        .map_err(|_| MatrixRunFailure::new(MatrixBlocker::EvidenceOutputInvalid))?;
    let workspace_canonical = workspace
        .canonicalize()
        .map_err(|_| MatrixRunFailure::new(MatrixBlocker::EvidenceOutputInvalid))?;
    if evidence_output.starts_with(&plugin_root_canonical) {
        return Err(MatrixRunFailure::new(MatrixBlocker::EvidenceOutputInvalid));
    }
    if evidence_output.starts_with(&workspace_canonical) {
        return Err(MatrixRunFailure::new(MatrixBlocker::EvidenceOutputInvalid));
    }

    let trust_store = TrustStore::load(&trust_store_path)
        .map_err(|_| MatrixRunFailure::new(MatrixBlocker::TrustStoreInvalid))?;
    let discovery = discover_plugins(&plugin_root)
        .map_err(|_| MatrixRunFailure::new(MatrixBlocker::PluginDiscoveryFailed))?;
    if !discovery.failures.is_empty() {
        return Err(MatrixRunFailure::with_count(
            MatrixBlocker::PluginDiscoveryFailed,
            discovery.failures.len(),
        ));
    }
    for manifest in &discovery.manifests {
        trust_store
            .verify(manifest)
            .map_err(|_| MatrixRunFailure::new(MatrixBlocker::PluginVerificationFailed))?;
    }

    let (matrix, coverage) = validate_executable_matrix(&matrix_path, &discovery.manifests)
        .map_err(|_| MatrixRunFailure::new(MatrixBlocker::MatrixDefinitionInvalid))?;
    let evidence_files = EvidenceFiles {
        workspace: &workspace,
        x86_host: &x86_host,
        x64_host: &x64_host,
        plugin_root: &plugin_root,
        release_set_spec: &release_set_spec,
        trust_store: &trust_store_path,
        matrix: &matrix_path,
    };
    let evidence_before = capture_evidence_inputs(&evidence_files, &discovery.manifests)
        .map_err(|_| MatrixRunFailure::new(MatrixBlocker::ReleaseInputsInvalid))?;

    let controller = Arc::new(
        PluginController::new(SupervisorConfig {
            x86_host: x86_host.clone(),
            x64_host: x64_host.clone(),
            request_timeout: Duration::from_secs(30),
            max_in_flight_invocations: webplus_controller::DEFAULT_MAX_IN_FLIGHT_INVOCATIONS,
            plugin_trust: PluginTrust::Strict {
                trust_store: trust_store_path.clone(),
            },
        })
        .map_err(|_| MatrixRunFailure::new(MatrixBlocker::HostPreflightFailed))?,
    );
    if controller
        .replace_manifests(&discovery.manifests)
        .await
        .is_err()
    {
        controller.shutdown().await;
        return Err(MatrixRunFailure::new(MatrixBlocker::HostPreflightFailed));
    }

    let mut tally = MatrixTally::default();
    for case in matrix.cases {
        if !case.enabled {
            tally.record_skipped();
            continue;
        }
        let actual = controller.invoke(case.request).await;
        tally.record_executed(actual == case.expected);
    }
    controller.shutdown().await;
    if tally.executed != coverage.enabled_case_count {
        return Err(MatrixRunFailure::new(
            MatrixBlocker::MatrixDefinitionInvalid,
        ));
    }
    if tally.failed > 0 {
        return Err(MatrixRunFailure::with_count(
            MatrixBlocker::GoldenCaseFailed,
            tally.failed,
        ));
    }

    let evidence_after = capture_evidence_inputs(&evidence_files, &discovery.manifests)
        .map_err(|_| MatrixRunFailure::new(MatrixBlocker::InputsChanged))?;
    if evidence_before != evidence_after {
        return Err(MatrixRunFailure::new(MatrixBlocker::InputsChanged));
    }
    let executed_at_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| MatrixRunFailure::new(MatrixBlocker::RunnerClockInvalid))?
        .as_secs();
    let evidence_count = |value| {
        u32::try_from(value).map_err(|_| MatrixRunFailure::new(MatrixBlocker::EvidenceWriteFailed))
    };
    write_plugin_matrix_evidence(
        &evidence_output,
        &PluginMatrixEvidence {
            schema_version: PLUGIN_MATRIX_EVIDENCE_SCHEMA_VERSION,
            evidence_type: EvidenceType::PluginMatrix,
            source_revision: evidence_after.source.revision,
            source_dirty: evidence_after.source.dirty,
            executed_at_unix_seconds,
            environment,
            runner_os: std::env::consts::OS.into(),
            runner_architecture: std::env::consts::ARCH.into(),
            release_set_spec_sha256: evidence_after.release_set_spec_sha256,
            package_set_sha256: evidence_after.package_set_sha256,
            plugin_set_sha256: evidence_after.plugin_set_sha256,
            trust_store_sha256: evidence_after.trust_store_sha256,
            matrix_sha256: evidence_after.matrix_sha256,
            x86_host_sha256: evidence_after.x86_host_sha256,
            x64_host_sha256: evidence_after.x64_host_sha256,
            plugin_count: evidence_count(coverage.plugin_count)?,
            service_count: evidence_count(coverage.service_count)?,
            method_count: evidence_count(coverage.method_count)?,
            enabled_case_count: evidence_count(coverage.enabled_case_count)?,
            passed: true,
        },
    )
    .map_err(|_| MatrixRunFailure::new(MatrixBlocker::EvidenceWriteFailed))?;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    let _ = writeln!(output, "plugin matrix: CLEAR");
    let _ = writeln!(
        output,
        "coverage: {} enabled cases, {} skipped cases, {} methods, {} services, {} plugins",
        tally.executed,
        tally.skipped,
        coverage.method_count,
        coverage.service_count,
        coverage.plugin_count
    );
    let _ = writeln!(
        output,
        "next: archive this evidence and continue the independent Windows package and Go/No-Go gates"
    );
    Ok(())
}

fn install_redacted_panic_hook() {
    std::panic::set_hook(Box::new(|_| {
        MatrixRunFailure::new(MatrixBlocker::RunnerFailed).emit();
    }));
}

fn capture_evidence_inputs(
    files: &EvidenceFiles<'_>,
    manifests: &[PluginManifest],
) -> Result<EvidenceInputs, Box<dyn Error>> {
    let trust_store = TrustStore::load(files.trust_store)?;
    let release_set = check_release_root_against_set(
        files.plugin_root,
        files.release_set_spec,
        files.trust_store,
        files.matrix,
    )?;
    let mut plugin_payloads = std::collections::BTreeMap::new();
    for manifest in manifests {
        trust_store.verify(manifest)?;
        let identity = read_identity(&manifest.plugin_dir)?;
        let material =
            prepare_signing_material(&manifest.plugin_dir, &manifest.plugin_id, &identity.key_id)?;
        if plugin_payloads
            .insert(manifest.plugin_id.clone(), material.payload)
            .is_some()
        {
            return Err("verified plugin IDs must be unique".into());
        }
    }
    let trust_store_sha256 = sha256_file(files.trust_store)?;
    let matrix_sha256 = sha256_file(files.matrix)?;
    if release_set.trust_store_sha256 != trust_store_sha256
        || release_set.matrix_sha256 != matrix_sha256
    {
        return Err("release set report is not bound to the tested trust store and matrix".into());
    }
    Ok(EvidenceInputs {
        source: capture_source_identity(files.workspace)?,
        release_set_spec_sha256: release_set.spec_sha256,
        package_set_sha256: release_set.package_set_sha256,
        plugin_set_sha256: digest_named_payloads("plugin-set", &plugin_payloads)?,
        trust_store_sha256,
        matrix_sha256,
        x86_host_sha256: sha256_file(files.x86_host)?,
        x64_host_sha256: sha256_file(files.x64_host)?,
    })
}

fn required(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
    name: &str,
) -> Result<PathBuf, Box<dyn Error>> {
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {name} argument").into())
}

fn required_string(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
    name: &str,
) -> Result<String, Box<dyn Error>> {
    arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing or non-Unicode {name} argument").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocker_codes_and_actions_are_stable_bounded_and_portable() {
        for blocker in MatrixBlocker::ALL {
            let code = blocker.code();
            let action = blocker.action();
            assert!(!code.is_empty());
            assert!(code.bytes().all(|value| value.is_ascii_lowercase()
                || value.is_ascii_digit()
                || value == b'-'));
            assert!(!action.is_empty());
            assert!(action.len() <= 240);
            assert!(!action.chars().any(char::is_control));
        }
    }

    #[test]
    fn matrix_tally_keeps_only_aggregate_results() {
        let mut tally = MatrixTally::default();
        tally.record_skipped();
        tally.record_executed(true);
        tally.record_executed(false);

        assert_eq!(
            tally,
            MatrixTally {
                executed: 2,
                skipped: 1,
                failed: 1,
            }
        );
    }

    #[test]
    fn golden_failure_exposes_only_code_action_and_count() {
        let failure = MatrixRunFailure::with_count(MatrixBlocker::GoldenCaseFailed, 3);

        assert_eq!(failure.blocker.code(), "matrix-golden-case-failed");
        assert_eq!(failure.affected_count, Some(3));
        assert!(!failure.blocker.action().contains('{'));
        assert!(!failure.blocker.action().contains('['));
    }
}
