use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use ssdev_cutover_evidence::{
    digest_named_payloads, prepare_new_output, sha256_file, write_plugin_matrix_evidence,
    EvidenceType, PluginMatrixEvidence, EVIDENCE_SCHEMA_VERSION,
};
use ssdev_release_manifest::{capture_source_identity, SourceIdentity};
use webplus_controller::{PluginController, PluginTrust, SupervisorConfig};
use webplus_plugin_config::{discover_plugins, PluginManifest};
use webplus_plugin_trust::{prepare_signing_material, read_identity, TrustStore};
use webplus_protocol::{contains_draft_placeholder, InvokeRequest, InvokeResponse};

const MAX_MATRIX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CASES: usize = 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Matrix {
    schema_version: u8,
    #[serde(default)]
    draft: bool,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Case {
    name: String,
    #[serde(default = "enabled_by_default")]
    enabled: bool,
    #[serde(default)]
    review_required: bool,
    request: InvokeRequest,
    expected: InvokeResponse,
}

fn enabled_by_default() -> bool {
    true
}

impl Matrix {
    fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 1 || self.cases.len() > MAX_CASES {
            return Err("matrix must use schema 1 and contain at most 1024 cases");
        }
        if self.draft {
            return Err("matrix is still marked as draft; replace all placeholders and set draft=false before invoking hardware");
        }
        if !self.cases.iter().any(|case| case.enabled) {
            return Err("matrix must contain at least one enabled case");
        }
        let mut names = BTreeSet::new();
        for case in &self.cases {
            if case.name.trim() != case.name
                || case.name.is_empty()
                || case.name.chars().count() > 256
                || case.name.chars().any(char::is_control)
            {
                return Err("matrix case names must contain 1 to 256 safe characters");
            }
            if !names.insert(case.name.as_str()) {
                return Err("matrix case names must be unique");
            }
            case.request
                .validate()
                .map_err(|_| "matrix contains an invalid invoke request")?;
            if case.enabled && case.review_required {
                return Err("enabled matrix cases must be explicitly approved after exact review");
            }
            if case.enabled
                && (case
                    .request
                    .parameters
                    .values()
                    .any(contains_draft_placeholder)
                    || contains_draft_placeholder(&case.expected.res_data))
            {
                return Err("enabled matrix cases must not contain generated draft placeholders");
            }
        }
        Ok(())
    }

    fn validate_coverage(&self, manifests: &[PluginManifest]) -> Result<MatrixCoverage, String> {
        let mut required = BTreeSet::new();
        let mut service_count = 0_usize;
        for manifest in manifests {
            for service in &manifest.services {
                service_count = service_count.saturating_add(1);
                for method in &service.methods {
                    required.insert((service.service_id.as_str(), method.name.as_str()));
                }
            }
        }
        if required.is_empty() {
            return Err("verified plugins do not declare any callable methods".into());
        }

        let mut covered = BTreeSet::new();
        let mut enabled_case_count = 0_usize;
        for case in self.cases.iter().filter(|case| case.enabled) {
            enabled_case_count = enabled_case_count.saturating_add(1);
            let service = manifests
                .iter()
                .flat_map(|manifest| &manifest.services)
                .find(|service| service.service_id == case.request.service_id)
                .ok_or_else(|| {
                    format!(
                        "enabled matrix case [{}] targets an unknown service",
                        case.name
                    )
                })?;
            let method = service.method(&case.request.method).ok_or_else(|| {
                format!(
                    "enabled matrix case [{}] targets an unknown method",
                    case.name
                )
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
                return Err(format!(
                    "enabled matrix case [{}] inputs do not exactly match the declared method inputs",
                    case.name
                ));
            }
            covered.insert((service.service_id.as_str(), method.name.as_str()));
        }
        if covered != required {
            let missing = required.difference(&covered).count();
            return Err(format!(
                "enabled matrix cases do not cover {missing} declared plugin method(s)"
            ));
        }
        Ok(MatrixCoverage {
            plugin_count: manifests.len(),
            service_count,
            method_count: required.len(),
            enabled_case_count,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
struct MatrixCoverage {
    plugin_count: usize,
    service_count: usize,
    method_count: usize,
    enabled_case_count: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct EvidenceInputs {
    source: SourceIdentity,
    plugin_set_sha256: String,
    trust_store_sha256: String,
    matrix_sha256: String,
    x86_host_sha256: String,
    x64_host_sha256: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let x86_host = required(&mut arguments, "x86 plugin host")?;
    let x64_host = required(&mut arguments, "x64 plugin host")?;
    let plugin_root = required(&mut arguments, "plugin root")?;
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

    let metadata = fs::metadata(&matrix_path)?;
    if !metadata.is_file() || metadata.len() > MAX_MATRIX_BYTES {
        return Err("matrix JSON is not a regular file or exceeds 16 MiB".into());
    }
    let matrix: Matrix = serde_json::from_slice(&fs::read(&matrix_path)?)?;
    matrix.validate()?;
    let coverage = matrix.validate_coverage(&discovery.manifests)?;
    let evidence_before = capture_evidence_inputs(
        &workspace,
        &x86_host,
        &x64_host,
        &trust_store_path,
        &matrix_path,
        &discovery.manifests,
    )?;

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
        let evidence_after = capture_evidence_inputs(
            &workspace,
            &x86_host,
            &x64_host,
            &trust_store_path,
            &matrix_path,
            &discovery.manifests,
        )?;
        if evidence_before != evidence_after {
            return Err("source, plugins, trust, matrix, or hosts changed during execution".into());
        }
        let executed_at_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch")?
            .as_secs();
        write_plugin_matrix_evidence(
            &evidence_output,
            &PluginMatrixEvidence {
                schema_version: EVIDENCE_SCHEMA_VERSION,
                evidence_type: EvidenceType::PluginMatrix,
                source_revision: evidence_after.source.revision,
                source_dirty: evidence_after.source.dirty,
                executed_at_unix_seconds,
                environment,
                runner_os: std::env::consts::OS.into(),
                runner_architecture: std::env::consts::ARCH.into(),
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
    workspace: &std::path::Path,
    x86_host: &std::path::Path,
    x64_host: &std::path::Path,
    trust_store_path: &std::path::Path,
    matrix_path: &std::path::Path,
    manifests: &[PluginManifest],
) -> Result<EvidenceInputs, Box<dyn Error>> {
    let trust_store = TrustStore::load(trust_store_path)?;
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
    Ok(EvidenceInputs {
        source: capture_source_identity(workspace)?,
        plugin_set_sha256: digest_named_payloads("plugin-set", &plugin_payloads)?,
        trust_store_sha256: sha256_file(trust_store_path)?,
        matrix_sha256: sha256_file(matrix_path)?,
        x86_host_sha256: sha256_file(x86_host)?,
        x64_host_sha256: sha256_file(x64_host)?,
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
    use serde_json::Map;
    use std::collections::HashMap;
    use webplus_plugin_config::{MethodDefinition, ParameterDefinition, ServiceDefinition};
    use webplus_protocol::{
        PluginArchitecture, DRAFT_INPUT_PLACEHOLDER, DRAFT_RESPONSE_PLACEHOLDER,
    };

    fn case(enabled: bool) -> Case {
        Case {
            name: "reader.read".into(),
            enabled,
            review_required: false,
            request: InvokeRequest {
                service_id: "reader".into(),
                method: "read".into(),
                parameters: Map::new(),
            },
            expected: InvokeResponse::success("ok"),
        }
    }

    #[test]
    fn draft_and_empty_enabled_matrices_cannot_touch_hardware() {
        assert!(Matrix {
            schema_version: 1,
            draft: true,
            cases: vec![case(true)],
        }
        .validate()
        .unwrap_err()
        .contains("draft"));
        assert!(Matrix {
            schema_version: 1,
            draft: false,
            cases: vec![case(false)],
        }
        .validate()
        .unwrap_err()
        .contains("enabled"));
    }

    #[test]
    fn legacy_schema_one_matrices_remain_enabled_by_default() {
        let matrix: Matrix = serde_json::from_value(serde_json::json!({
            "schemaVersion": 1,
            "cases": [{
                "name": "reader.read",
                "request": {
                    "serviceId": "reader",
                    "method": "read",
                    "parameters": {}
                },
                "expected": {
                    "ResCode": 0,
                    "ResData": "ok"
                }
            }]
        }))
        .unwrap();

        matrix.validate().unwrap();
        assert!(matrix.cases[0].enabled);
        assert!(!matrix.draft);
    }

    #[test]
    fn finalized_matrices_cannot_retain_generated_placeholders() {
        let mut review_required = case(true);
        review_required.review_required = true;
        assert!(Matrix {
            schema_version: 1,
            draft: false,
            cases: vec![review_required],
        }
        .validate()
        .unwrap_err()
        .contains("exact review"));

        let mut input_placeholder = case(true);
        input_placeholder.request.parameters.insert(
            "port".into(),
            serde_json::Value::String(DRAFT_INPUT_PLACEHOLDER.into()),
        );
        assert!(Matrix {
            schema_version: 1,
            draft: false,
            cases: vec![input_placeholder],
        }
        .validate()
        .unwrap_err()
        .contains("placeholders"));

        let mut response_placeholder = case(true);
        response_placeholder.expected = InvokeResponse::success(serde_json::json!({
            "nested": [DRAFT_RESPONSE_PLACEHOLDER]
        }));
        assert!(Matrix {
            schema_version: 1,
            draft: false,
            cases: vec![response_placeholder],
        }
        .validate()
        .unwrap_err()
        .contains("placeholders"));

        let mut disabled_placeholder = case(false);
        disabled_placeholder.expected = InvokeResponse::success(DRAFT_RESPONSE_PLACEHOLDER);
        let mut enabled = case(true);
        enabled.name = "reader.read verified".into();
        Matrix {
            schema_version: 1,
            draft: false,
            cases: vec![disabled_placeholder, enabled],
        }
        .validate()
        .unwrap();
    }

    fn manifest() -> PluginManifest {
        let method = |name: &str, alias: Option<&str>| MethodDefinition {
            name: name.into(),
            alias: alias.map(str::to_owned),
            timeout: 0,
            return_type: String::new(),
            parameters: Vec::new(),
            props: Vec::new(),
            extensions: HashMap::new(),
        };
        PluginManifest {
            plugin_id: "reader-plugin".into(),
            plugin_dir: PathBuf::from("reader-plugin"),
            metadata: None,
            services: vec![ServiceDefinition {
                service_id: "reader".into(),
                main_class: "reader.dll".into(),
                main_type: "dll".into(),
                architecture: PluginArchitecture::X86,
                charset: String::new(),
                calling_convention: "system".into(),
                cacheable: false,
                timeout: 0,
                deps: Vec::new(),
                methods: vec![method("read", Some("readCard")), method("reset", None)],
                extensions: HashMap::new(),
            }],
        }
    }

    #[test]
    fn coverage_requires_every_declared_method_and_accepts_aliases() {
        let matrix = Matrix {
            schema_version: 1,
            draft: false,
            cases: vec![
                Case {
                    name: "reader.read".into(),
                    enabled: true,
                    review_required: false,
                    request: InvokeRequest {
                        service_id: "reader".into(),
                        method: "readCard".into(),
                        parameters: Map::new(),
                    },
                    expected: InvokeResponse::success("ok"),
                },
                Case {
                    name: "reader.reset".into(),
                    enabled: true,
                    review_required: false,
                    request: InvokeRequest {
                        service_id: "reader".into(),
                        method: "reset".into(),
                        parameters: Map::new(),
                    },
                    expected: InvokeResponse::success("ok"),
                },
            ],
        };
        assert_eq!(
            matrix.validate_coverage(&[manifest()]).unwrap(),
            MatrixCoverage {
                plugin_count: 1,
                service_count: 1,
                method_count: 2,
                enabled_case_count: 2,
            }
        );

        let incomplete = Matrix {
            cases: vec![case(true)],
            ..matrix
        };
        assert!(incomplete
            .validate_coverage(&[manifest()])
            .unwrap_err()
            .contains("do not cover 1"));
    }

    #[test]
    fn coverage_rejects_unknown_routes_and_duplicate_case_names() {
        let mut unknown = case(true);
        unknown.request.service_id = "missing".into();
        let matrix = Matrix {
            schema_version: 1,
            draft: false,
            cases: vec![unknown],
        };
        assert!(matrix
            .validate_coverage(&[manifest()])
            .unwrap_err()
            .contains("unknown service"));

        let duplicate = Matrix {
            schema_version: 1,
            draft: false,
            cases: vec![case(true), case(true)],
        };
        assert!(duplicate.validate().unwrap_err().contains("unique"));
    }

    #[test]
    fn coverage_requires_the_exact_declared_input_set() {
        let mut manifest = manifest();
        manifest.services[0].methods[0].parameters = vec![ParameterDefinition::Name("port".into())];
        let mut read = case(true);
        read.request.method = "readCard".into();
        read.request
            .parameters
            .insert("port".into(), serde_json::json!("COM1"));
        let mut reset = case(true);
        reset.name = "reader.reset".into();
        reset.request.method = "reset".into();
        let exact = Matrix {
            schema_version: 1,
            draft: false,
            cases: vec![read, reset],
        };
        exact.validate_coverage(&[manifest.clone()]).unwrap();

        let mut missing = exact;
        missing.cases[0].request.parameters.clear();
        assert!(missing
            .validate_coverage(&[manifest.clone()])
            .unwrap_err()
            .contains("exactly match"));

        missing.cases[0]
            .request
            .parameters
            .insert("port".into(), serde_json::json!("COM1"));
        missing.cases[0]
            .request
            .parameters
            .insert("undeclared".into(), serde_json::json!(true));
        assert!(missing
            .validate_coverage(&[manifest])
            .unwrap_err()
            .contains("exactly match"));
    }
}
