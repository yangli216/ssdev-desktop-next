use std::error::Error;
use std::path::PathBuf;
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let x86_host = required(&mut arguments, "x86 plugin host")?;
    let x64_host = required(&mut arguments, "x64 plugin host")?;
    let plugin_root = required(&mut arguments, "plugin root")?;
    let release_set_spec = required(&mut arguments, "release set spec")?;
    let trust_store_path = required(&mut arguments, "trust store")?;
    let matrix_path = required(&mut arguments, "matrix JSON")?;
    let workspace = required(&mut arguments, "source workspace")?;
    let evidence_output = required(&mut arguments, "evidence output")?;
    let environment = required_string(&mut arguments, "evidence environment")?;
    if arguments.next().is_some() {
        return Err("too many arguments".into());
    }
    if std::env::consts::OS != "windows" || std::env::consts::ARCH != "x86_64" {
        return Err("real plugin evidence requires a Windows x86_64 runner".into());
    }
    let evidence_output = prepare_new_output(&evidence_output)?;
    let plugin_root_canonical = plugin_root.canonicalize()?;
    let workspace_canonical = workspace.canonicalize()?;
    if evidence_output.starts_with(&plugin_root_canonical) {
        return Err("evidence output must stay outside the verified plugin root".into());
    }
    if evidence_output.starts_with(&workspace_canonical) {
        return Err("evidence output must stay outside the source workspace".into());
    }

    let trust_store = TrustStore::load(&trust_store_path)?;
    let discovery = discover_plugins(&plugin_root)?;
    if !discovery.failures.is_empty() {
        for failure in discovery.failures {
            eprintln!(
                "plugin discovery failed for [{}] at {:?}: {}",
                failure.plugin_id, failure.path, failure.error
            );
        }
        return Err("plugin discovery did not produce a clean matrix".into());
    }
    for manifest in &discovery.manifests {
        trust_store.verify(manifest)?;
    }

    let (matrix, coverage) = validate_executable_matrix(&matrix_path, &discovery.manifests)?;
    let evidence_files = EvidenceFiles {
        workspace: &workspace,
        x86_host: &x86_host,
        x64_host: &x64_host,
        plugin_root: &plugin_root,
        release_set_spec: &release_set_spec,
        trust_store: &trust_store_path,
        matrix: &matrix_path,
    };
    let evidence_before = capture_evidence_inputs(&evidence_files, &discovery.manifests)?;

    let controller = Arc::new(PluginController::new(SupervisorConfig {
        x86_host: x86_host.clone(),
        x64_host: x64_host.clone(),
        request_timeout: Duration::from_secs(30),
        max_in_flight_invocations: webplus_controller::DEFAULT_MAX_IN_FLIGHT_INVOCATIONS,
        plugin_trust: PluginTrust::Strict {
            trust_store: trust_store_path.clone(),
        },
    })?);
    controller.replace_manifests(&discovery.manifests).await?;

    let mut failures = Vec::new();
    for case in matrix.cases {
        if !case.enabled {
            println!("SKIP {}", case.name);
            continue;
        }
        let actual = controller.invoke(case.request).await;
        if actual == case.expected {
            println!("PASS {}", case.name);
        } else {
            failures.push(format!(
                "{}: expected {:?}, received {:?}",
                case.name, case.expected, actual
            ));
        }
    }
    controller.shutdown().await;
    if failures.is_empty() {
        let evidence_after = capture_evidence_inputs(&evidence_files, &discovery.manifests)?;
        if evidence_before != evidence_after {
            return Err(
                "source, release set, plugins, trust, matrix, or hosts changed during execution"
                    .into(),
            );
        }
        let executed_at_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch")?
            .as_secs();
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
                plugin_count: u32::try_from(coverage.plugin_count)?,
                service_count: u32::try_from(coverage.service_count)?,
                method_count: u32::try_from(coverage.method_count)?,
                enabled_case_count: u32::try_from(coverage.enabled_case_count)?,
                passed: true,
            },
        )?;
        println!(
            "all {} enabled golden cases passed and covered {} methods across {} services in {} plugins",
            coverage.enabled_case_count,
            coverage.method_count,
            coverage.service_count,
            coverage.plugin_count
        );
        Ok(())
    } else {
        for failure in &failures {
            eprintln!("FAIL {failure}");
        }
        Err(format!("{} golden case(s) failed", failures.len()).into())
    }
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
