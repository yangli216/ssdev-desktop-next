use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ssdev_cutover_evidence::{
    prepare_new_output, sha256_bytes, sha256_file, write_migration_audit_evidence, write_new_bytes,
    EvidenceType, HttpEvidenceLevel, MigrationAuditEvidence, EVIDENCE_SCHEMA_VERSION,
};
use ssdev_migration_audit::{
    audit, audit_with_verified_origin_policy, AuditInputs, AuditReport,
    EvidenceLevel as AuditEvidenceLevel, PilotMaterialAudit, Severity,
};
use ssdev_origin_policy::OriginPolicy;
use ssdev_pilot_readiness::{
    load_manifest, load_report, resolve_migration_audit_inputs, verify_materials,
};
use ssdev_release_manifest::capture_source_identity;
use ssdev_release_signing::{verify, ArtifactKind};
use webplus_plugin_trust::TrustStore;

#[derive(Debug)]
struct CliOptions {
    inputs: AuditInputs,
    formal: Option<FormalOutputs>,
    origin_policy: Option<OriginPolicyInputs>,
    pilot: Option<PilotInputPaths>,
}

#[derive(Debug)]
struct PilotInputPaths {
    materials_root: PathBuf,
    manifest: PathBuf,
    report: PathBuf,
}

struct VerifiedPilotInputs {
    paths: PilotInputPaths,
    manifest_bytes: Vec<u8>,
    report_bytes: Vec<u8>,
    audit_inputs: AuditInputs,
    origin_policy: OriginPolicyInputs,
    material_set_sha256: String,
    migration_audit_bindings_sha256: String,
}

#[derive(Debug)]
struct OriginPolicyInputs {
    document: PathBuf,
    envelope: PathBuf,
    trust_store: PathBuf,
}

struct VerifiedOriginPolicy {
    policy: OriginPolicy,
    document_sha256: String,
    envelope_sha256: String,
    trust_store_sha256: String,
    inputs: OriginPolicyInputs,
}

#[derive(Debug)]
struct FormalOutputs {
    report_output: PathBuf,
    evidence_output: PathBuf,
    evidence_environment: String,
    workspace: PathBuf,
}

#[derive(Debug)]
struct FindingSummary {
    critical_findings: u32,
    warning_findings: u32,
    info_findings: u32,
    code_counts: BTreeMap<String, u32>,
    guidance: BTreeMap<String, FindingGuidance>,
}

#[derive(Debug)]
struct FindingGuidance {
    severity: Severity,
    count: u32,
    remediation: &'static str,
}

fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => std::process::exit(3),
        Err(error) => {
            eprintln!("{error}\n\n用法: ssdev-migration-audit [--config FILE]... [--plugins DIR]... [--keymap FILE]... [--browser-assets FILE_OR_DIR]... [--browser-har FILE]... [--origin-policy FILE --origin-policy-envelope FILE --release-trust-store FILE] [--pilot-materials-root DIR --pilot-manifest FILE --pilot-report FILE] [--workspace DIR --report-output FILE --evidence-output FILE --evidence-environment LABEL]");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<bool, Box<dyn Error>> {
    let mut options = parse_args(env::args().skip(1))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let verified_pilot = options.pilot.map(load_verified_pilot_inputs).transpose()?;
    if let Some(pilot) = &verified_pilot {
        options.inputs = AuditInputs {
            configs: pilot.audit_inputs.configs.clone(),
            plugin_roots: pilot.audit_inputs.plugin_roots.clone(),
            keymaps: pilot.audit_inputs.keymaps.clone(),
            browser_asset_roots: pilot.audit_inputs.browser_asset_roots.clone(),
            browser_hars: pilot.audit_inputs.browser_hars.clone(),
        };
    }
    let policy_inputs = verified_pilot
        .as_ref()
        .map(|pilot| OriginPolicyInputs {
            document: pilot.origin_policy.document.clone(),
            envelope: pilot.origin_policy.envelope.clone(),
            trust_store: pilot.origin_policy.trust_store.clone(),
        })
        .or(options.origin_policy);
    let verified_policy = policy_inputs.map(load_verified_origin_policy).transpose()?;
    match options.formal {
        None => {
            let mut report = match verified_policy.as_ref() {
                Some(verified) => audit_with_verified_origin_policy(
                    &options.inputs,
                    &verified.policy,
                    verified.document_sha256.clone(),
                ),
                None => audit(&options.inputs),
            };
            bind_pilot_materials(&mut report, verified_pilot.as_ref());
            if let Some(pilot) = &verified_pilot {
                pilot.verify_unchanged()?;
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(true)
        }
        Some(formal) => run_formal(
            &options.inputs,
            formal,
            verified_policy.ok_or_else(|| {
                invalid_input("formal migration evidence requires a verified signed origin policy")
            })?,
            verified_pilot.ok_or_else(|| {
                invalid_input("formal migration evidence requires verified pilot materials")
            })?,
        ),
    }
}

fn load_verified_pilot_inputs(
    paths: PilotInputPaths,
) -> Result<VerifiedPilotInputs, Box<dyn Error>> {
    let canonical_root = fs::canonicalize(&paths.materials_root)?;
    let canonical_report = fs::canonicalize(&paths.report)?;
    if canonical_report.starts_with(&canonical_root) {
        return Err(invalid_input(
            "pilot readiness report must stay outside the materials root",
        ));
    }
    let (manifest, manifest_bytes) = load_manifest(&paths.manifest)?;
    let (report, report_bytes) = load_report(&paths.report)?;
    verify_materials(&paths.materials_root, &manifest, &manifest_bytes, &report)?;
    if !report.intake_complete {
        return Err(invalid_input(
            "pilot material report is verified but still incomplete",
        ));
    }
    let resolved = resolve_migration_audit_inputs(&paths.materials_root, &manifest)?;
    Ok(VerifiedPilotInputs {
        paths,
        manifest_bytes,
        report_bytes,
        audit_inputs: AuditInputs {
            configs: resolved.configs,
            plugin_roots: resolved.plugin_roots,
            keymaps: resolved.keymaps,
            browser_asset_roots: resolved.browser_asset_roots,
            browser_hars: resolved.browser_hars,
        },
        origin_policy: OriginPolicyInputs {
            document: resolved.origin_policy,
            envelope: resolved.origin_policy_envelope,
            trust_store: resolved.release_trust_store,
        },
        material_set_sha256: report.material_set_sha256,
        migration_audit_bindings_sha256: report.migration_audit_bindings_sha256,
    })
}

impl VerifiedPilotInputs {
    fn verify_unchanged(&self) -> Result<(), Box<dyn Error>> {
        let (manifest, manifest_bytes) = load_manifest(&self.paths.manifest)?;
        let (report, report_bytes) = load_report(&self.paths.report)?;
        if manifest_bytes != self.manifest_bytes || report_bytes != self.report_bytes {
            return Err(invalid_input(
                "pilot manifest or readiness report changed during migration audit",
            ));
        }
        verify_materials(
            &self.paths.materials_root,
            &manifest,
            &manifest_bytes,
            &report,
        )?;
        Ok(())
    }
}

fn bind_pilot_materials(report: &mut AuditReport, pilot: Option<&VerifiedPilotInputs>) {
    if let Some(pilot) = pilot {
        report.pilot_materials = Some(PilotMaterialAudit {
            material_set_sha256: pilot.material_set_sha256.clone(),
            migration_audit_bindings_sha256: pilot.migration_audit_bindings_sha256.clone(),
        });
    }
}

fn load_verified_origin_policy(
    inputs: OriginPolicyInputs,
) -> Result<VerifiedOriginPolicy, Box<dyn Error>> {
    let document_sha256 = sha256_file(&inputs.document)?;
    let envelope_sha256 = sha256_file(&inputs.envelope)?;
    let trust_store_sha256 = sha256_file(&inputs.trust_store)?;
    let signing_report = verify(
        ArtifactKind::OriginPolicy,
        &inputs.document,
        &inputs.envelope,
        &inputs.trust_store,
        SystemTime::now(),
    )?;
    if !signing_report.verified || signing_report.document_sha256 != document_sha256 {
        return Err(invalid_input(
            "origin policy verification did not bind the current document",
        ));
    }
    let trust_store = TrustStore::load(&inputs.trust_store)?;
    let policy = OriginPolicy::load(&inputs.document, &inputs.envelope, &trust_store)?;
    if document_sha256 != sha256_file(&inputs.document)?
        || envelope_sha256 != sha256_file(&inputs.envelope)?
        || trust_store_sha256 != sha256_file(&inputs.trust_store)?
    {
        return Err(invalid_input(
            "origin policy inputs changed during signature verification",
        ));
    }
    Ok(VerifiedOriginPolicy {
        policy,
        document_sha256,
        envelope_sha256,
        trust_store_sha256,
        inputs,
    })
}

fn run_formal(
    inputs: &AuditInputs,
    formal: FormalOutputs,
    verified_policy: VerifiedOriginPolicy,
    verified_pilot: VerifiedPilotInputs,
) -> Result<bool, Box<dyn Error>> {
    let workspace = fs::canonicalize(&formal.workspace)?;
    if !workspace.is_dir() {
        return Err(invalid_input("workspace must be an existing directory"));
    }
    let report_output = prepare_new_output(&formal.report_output)?;
    let evidence_output = prepare_new_output(&formal.evidence_output)?;
    if report_output == evidence_output {
        return Err(invalid_input(
            "report and evidence outputs must be different files",
        ));
    }
    let pilot_materials_root = fs::canonicalize(&verified_pilot.paths.materials_root)?;
    validate_formal_output_locations(
        &report_output,
        &evidence_output,
        &workspace,
        &pilot_materials_root,
    )?;

    let source_before = capture_source_identity(&workspace)?;
    let mut report = audit_with_verified_origin_policy(
        inputs,
        &verified_policy.policy,
        verified_policy.document_sha256.clone(),
    );
    bind_pilot_materials(&mut report, Some(&verified_pilot));
    let finding_summary = summarize_findings(&report)?;
    let formal_summary = render_formal_summary(&report, &finding_summary);
    let mut report_bytes = serde_json::to_vec_pretty(&report)?;
    report_bytes.push(b'\n');
    let report_sha256 = sha256_bytes(&report_bytes);
    let source_after = capture_source_identity(&workspace)?;
    if source_before != source_after
        || verified_policy.document_sha256 != sha256_file(&verified_policy.inputs.document)?
        || verified_policy.envelope_sha256 != sha256_file(&verified_policy.inputs.envelope)?
        || verified_policy.trust_store_sha256 != sha256_file(&verified_policy.inputs.trust_store)?
    {
        return Err(invalid_input(
            "source identity or signed origin policy inputs changed during migration audit",
        ));
    }
    verified_pilot.verify_unchanged()?;

    let evidence = build_evidence(
        &report,
        source_after,
        report_sha256,
        formal.evidence_environment,
        &finding_summary,
    )?;
    evidence.validate()?;
    write_new_bytes(&report_output, &report_bytes)?;
    write_migration_audit_evidence(&evidence_output, &evidence)?;
    println!("{formal_summary}");
    Ok(!is_formal_audit_blocked(&finding_summary))
}

fn summarize_findings(report: &AuditReport) -> Result<FindingSummary, Box<dyn Error>> {
    let mut summary = FindingSummary {
        critical_findings: 0,
        warning_findings: 0,
        info_findings: 0,
        code_counts: BTreeMap::new(),
        guidance: BTreeMap::new(),
    };
    for finding in &report.findings {
        if finding.code.is_empty()
            || finding.code.len() > 128
            || !finding
                .code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || finding.remediation.is_empty()
            || finding.remediation.len() > 512
            || finding.remediation.chars().any(char::is_control)
        {
            return Err(invalid_input(
                "migration finding code or remediation is not safe for the formal summary",
            ));
        }
        increment_count(
            summary.code_counts.entry(finding.code.into()).or_default(),
            "finding count",
        )?;
        let severity_count = match finding.severity {
            Severity::Critical => &mut summary.critical_findings,
            Severity::Warning => &mut summary.warning_findings,
            Severity::Info => &mut summary.info_findings,
        };
        increment_count(severity_count, "severity count")?;
        let guidance = summary
            .guidance
            .entry(finding.code.into())
            .or_insert(FindingGuidance {
                severity: finding.severity,
                count: 0,
                remediation: finding.remediation,
            });
        if guidance.severity != finding.severity || guidance.remediation != finding.remediation {
            return Err(invalid_input(
                "one migration finding code has inconsistent severity or remediation",
            ));
        }
        increment_count(&mut guidance.count, "blocker count")?;
    }
    if usize::try_from(summary.critical_findings).ok() != Some(report.summary.critical_findings)
        || usize::try_from(summary.warning_findings).ok() != Some(report.summary.warning_findings)
    {
        return Err(invalid_input(
            "migration audit finding severity summary is inconsistent",
        ));
    }
    Ok(summary)
}

fn increment_count(value: &mut u32, name: &str) -> Result<(), Box<dyn Error>> {
    *value = value
        .checked_add(1)
        .ok_or_else(|| invalid_input(&format!("{name} overflowed")))?;
    Ok(())
}

fn is_formal_audit_blocked(summary: &FindingSummary) -> bool {
    summary.critical_findings > 0 || summary.warning_findings > 0
}

fn render_formal_summary(report: &AuditReport, summary: &FindingSummary) -> String {
    let blocked = is_formal_audit_blocked(summary);
    let state = if blocked { "BLOCKED" } else { "CLEAR" };
    let mut lines = vec![format!(
        "migration audit: {state} ({} critical, {} warnings, {} info)",
        summary.critical_findings, summary.warning_findings, summary.info_findings
    )];
    lines.push(format!(
        "coverage: {} configs, {} plugin directories, {} services, {} browser files, {} HAR requests",
        report.summary.config_files,
        report.summary.plugin_directories,
        report.summary.services,
        report.browser_compatibility.asset_files_scanned,
        report.browser_compatibility.har_requests_scanned
    ));
    for (code, guidance) in &summary.guidance {
        let severity = match guidance.severity {
            Severity::Critical => "critical",
            Severity::Warning => "warning",
            Severity::Info => continue,
        };
        lines.push(format!(
            "blocker: {code} ({severity}, {} occurrences)",
            guidance.count
        ));
        lines.push(format!("action: {}", guidance.remediation));
    }
    lines.push(if blocked {
        "next: report and evidence were written, but cannot satisfy GO; resolve every critical and warning finding, then rerun with new output paths".into()
    } else {
        "next: sign this clear migration evidence and continue the plugin matrix and Windows package gates; this audit alone is not GO".into()
    });
    lines.join("\n")
}

fn validate_formal_output_locations(
    report_output: &std::path::Path,
    evidence_output: &std::path::Path,
    workspace: &std::path::Path,
    pilot_materials_root: &std::path::Path,
) -> Result<(), Box<dyn Error>> {
    if report_output.starts_with(workspace) || evidence_output.starts_with(workspace) {
        return Err(invalid_input(
            "formal outputs must stay outside the source workspace",
        ));
    }
    if report_output.starts_with(pilot_materials_root)
        || evidence_output.starts_with(pilot_materials_root)
    {
        return Err(invalid_input(
            "formal outputs must stay outside the pilot materials root",
        ));
    }
    Ok(())
}

fn build_evidence(
    report: &AuditReport,
    source: ssdev_release_manifest::SourceIdentity,
    report_sha256: String,
    environment: String,
    finding_summary: &FindingSummary,
) -> Result<MigrationAuditEvidence, Box<dyn Error>> {
    let executed_at_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid_input("system clock is before the Unix epoch"))?
        .as_secs();
    Ok(MigrationAuditEvidence {
        schema_version: EVIDENCE_SCHEMA_VERSION,
        evidence_type: EvidenceType::MigrationAudit,
        source_revision: source.revision,
        source_dirty: source.dirty,
        executed_at_unix_seconds,
        environment,
        runner_os: env::consts::OS.into(),
        runner_architecture: env::consts::ARCH.into(),
        report_sha256,
        pilot_material_set_sha256: report
            .pilot_materials
            .as_ref()
            .ok_or_else(|| invalid_input("formal audit report is missing pilot material binding"))?
            .material_set_sha256
            .clone(),
        origin_policy_sha256: report
            .origin_policy
            .as_ref()
            .ok_or_else(|| invalid_input("formal audit report is missing origin policy binding"))?
            .document_sha256
            .clone(),
        config_files: to_u32(report.summary.config_files, "config file count")?,
        plugin_directories: to_u32(report.summary.plugin_directories, "plugin directory count")?,
        service_count: to_u32(report.summary.services, "service count")?,
        key_binding_count: to_u32(report.summary.key_bindings, "key binding count")?,
        browser_asset_roots: to_u32(
            report.browser_compatibility.asset_roots,
            "browser asset root count",
        )?,
        browser_asset_files_scanned: to_u32(
            report.browser_compatibility.asset_files_scanned,
            "browser asset file count",
        )?,
        browser_har_files: to_u32(
            report.browser_compatibility.har_files,
            "browser HAR file count",
        )?,
        browser_har_requests_scanned: to_u32(
            report.browser_compatibility.har_requests_scanned,
            "browser HAR request count",
        )?,
        insecure_http_origin_count: to_u32(
            report
                .origin_policy
                .as_ref()
                .map_or(0, |policy| policy.insecure_http_origin_count),
            "insecure HTTP origin count",
        )?,
        authorized_insecure_http_origin_count: to_u32(
            report
                .origin_policy
                .as_ref()
                .map_or(0, |policy| policy.authorized_insecure_http_origin_count),
            "authorized insecure HTTP origin count",
        )?,
        webplus_http_evidence: map_http_evidence(
            report.browser_compatibility.webplus_http_evidence,
        ),
        desktop_callback_http_evidence: map_http_evidence(
            report.browser_compatibility.desktop_callback_http_evidence,
        ),
        critical_findings: finding_summary.critical_findings,
        warning_findings: finding_summary.warning_findings,
        info_findings: finding_summary.info_findings,
        finding_code_counts: finding_summary.code_counts.clone(),
    })
}

fn map_http_evidence(level: AuditEvidenceLevel) -> HttpEvidenceLevel {
    match level {
        AuditEvidenceLevel::ConfirmedRuntime => HttpEvidenceLevel::ConfirmedRuntime,
        AuditEvidenceLevel::StaticReferences => HttpEvidenceLevel::StaticReferences,
        AuditEvidenceLevel::NotObserved => HttpEvidenceLevel::NotObserved,
    }
}

fn to_u32(value: usize, name: &str) -> Result<u32, Box<dyn Error>> {
    u32::try_from(value).map_err(|_| invalid_input(&format!("{name} exceeds the evidence limit")))
}

fn invalid_input(message: &str) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidInput, message).into()
}

fn parse_args(arguments: impl IntoIterator<Item = String>) -> Result<CliOptions, String> {
    let mut inputs = AuditInputs::default();
    let mut report_output = None;
    let mut evidence_output = None;
    let mut evidence_environment = None;
    let mut workspace = None;
    let mut origin_policy = None;
    let mut origin_policy_envelope = None;
    let mut release_trust_store = None;
    let mut pilot_materials_root = None;
    let mut pilot_manifest = None;
    let mut pilot_report = None;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("参数 [{argument}] 缺少路径"))?;
        match argument.as_str() {
            "--config" => inputs.configs.push(PathBuf::from(value)),
            "--plugins" => inputs.plugin_roots.push(PathBuf::from(value)),
            "--keymap" => inputs.keymaps.push(PathBuf::from(value)),
            "--browser-assets" => inputs.browser_asset_roots.push(PathBuf::from(value)),
            "--browser-har" => inputs.browser_hars.push(PathBuf::from(value)),
            "--report-output" => set_once(&mut report_output, PathBuf::from(value), &argument)?,
            "--evidence-output" => set_once(&mut evidence_output, PathBuf::from(value), &argument)?,
            "--evidence-environment" => set_once(&mut evidence_environment, value, &argument)?,
            "--workspace" => set_once(&mut workspace, PathBuf::from(value), &argument)?,
            "--origin-policy" => set_once(&mut origin_policy, PathBuf::from(value), &argument)?,
            "--origin-policy-envelope" => {
                set_once(&mut origin_policy_envelope, PathBuf::from(value), &argument)?
            }
            "--release-trust-store" => {
                set_once(&mut release_trust_store, PathBuf::from(value), &argument)?
            }
            "--pilot-materials-root" => {
                set_once(&mut pilot_materials_root, PathBuf::from(value), &argument)?
            }
            "--pilot-manifest" => set_once(&mut pilot_manifest, PathBuf::from(value), &argument)?,
            "--pilot-report" => set_once(&mut pilot_report, PathBuf::from(value), &argument)?,
            _ => return Err(format!("未知参数 [{argument}]")),
        }
    }
    let manual_inputs_present = !inputs.configs.is_empty()
        || !inputs.plugin_roots.is_empty()
        || !inputs.keymaps.is_empty()
        || !inputs.browser_asset_roots.is_empty()
        || !inputs.browser_hars.is_empty();
    let pilot_count = [
        pilot_materials_root.is_some(),
        pilot_manifest.is_some(),
        pilot_report.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    let pilot = match pilot_count {
        0 => None,
        3 => Some(PilotInputPaths {
            materials_root: pilot_materials_root.unwrap(),
            manifest: pilot_manifest.unwrap(),
            report: pilot_report.unwrap(),
        }),
        _ => return Err(
            "试点材料模式必须同时提供 --pilot-materials-root、--pilot-manifest 和 --pilot-report"
                .into(),
        ),
    };
    if !manual_inputs_present && pilot.is_none() {
        return Err("至少需要一个审计输入或一套已复验试点材料".into());
    }
    if pilot.is_some() && manual_inputs_present {
        return Err("试点材料模式不能同时提供手工 --config/--plugins/--keymap/--browser-assets/--browser-har 输入".into());
    }
    let formal_count = [
        report_output.is_some(),
        evidence_output.is_some(),
        evidence_environment.is_some(),
        workspace.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    let formal = match formal_count {
        0 => None,
        4 => Some(FormalOutputs {
            report_output: report_output.unwrap(),
            evidence_output: evidence_output.unwrap(),
            evidence_environment: evidence_environment.unwrap(),
            workspace: workspace.unwrap(),
        }),
        _ => {
            return Err("正式模式必须同时提供 --workspace、--report-output、--evidence-output 和 --evidence-environment".into())
        }
    };
    if formal.is_some() && pilot.is_none() {
        return Err("正式迁移审计必须从 --pilot-materials-root、--pilot-manifest 和 --pilot-report 派生输入".into());
    }
    let policy_count = [
        origin_policy.is_some(),
        origin_policy_envelope.is_some(),
        release_trust_store.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if pilot.is_some() && policy_count != 0 {
        return Err("试点材料模式从 manifest 派生签名来源策略，不能同时提供手工策略参数".into());
    }
    let origin_policy = match policy_count {
        0 if formal.is_none() || pilot.is_some() => None,
        3 => Some(OriginPolicyInputs {
            document: origin_policy.unwrap(),
            envelope: origin_policy_envelope.unwrap(),
            trust_store: release_trust_store.unwrap(),
        }),
        0 => {
            return Err("正式模式必须提供 --origin-policy、--origin-policy-envelope 和 --release-trust-store".into())
        }
        _ => {
            return Err("签名来源策略必须同时提供 --origin-policy、--origin-policy-envelope 和 --release-trust-store".into())
        }
    };
    Ok(CliOptions {
        inputs,
        formal,
        origin_policy,
        pilot,
    })
}

fn set_once<T>(slot: &mut Option<T>, value: T, argument: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("参数 [{argument}] 不能重复"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use ssdev_pilot_readiness::{inspect_materials, write_report, PilotMaterialManifest};
    use tempfile::tempdir;

    #[test]
    fn verified_policy_loader_requires_and_binds_an_active_signature() {
        let root = tempdir().unwrap();
        let document = root.path().join("origin-policy.json");
        let envelope = root.path().join("origin-policy.sig.json");
        let trust_store = root.path().join("plugin-trust.json");
        let bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "schemaVersion": 2,
            "businessGrants": [{
                "origin": "http://10.17.5.57",
                "services": [{"serviceId": "reader", "methods": ["read"]}]
            }],
            "allowInsecureHttp": true
        }))
        .unwrap();
        fs::write(&document, &bytes).unwrap();
        let signing_key = SigningKey::from_bytes(&[17; 32]);
        let signature = signing_key.sign(&ssdev_origin_policy::signing_payload(&bytes));
        fs::write(
            &envelope,
            serde_json::to_vec_pretty(&serde_json::json!({
                "schemaVersion": 1,
                "keyId": "origin-policy-test",
                "algorithm": "ed25519",
                "signature": STANDARD.encode(signature.to_bytes())
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            &trust_store,
            serde_json::to_vec_pretty(&serde_json::json!({
                "schemaVersion": 2,
                "keys": [{
                    "keyId": "origin-policy-test",
                    "algorithm": "ed25519",
                    "publicKey": STANDARD.encode(signing_key.verifying_key().to_bytes()),
                    "purposes": ["origin-policy"]
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        let verified = load_verified_origin_policy(OriginPolicyInputs {
            document: document.clone(),
            envelope: envelope.clone(),
            trust_store: trust_store.clone(),
        })
        .unwrap();
        assert_eq!(verified.document_sha256, sha256_bytes(&bytes));

        let mut changed = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
        changed["allowInsecureHttp"] = serde_json::json!(false);
        fs::write(&envelope, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(load_verified_origin_policy(OriginPolicyInputs {
            document,
            envelope,
            trust_store,
        })
        .is_err());
    }

    #[test]
    fn arguments_are_explicit_and_repeatable() {
        let parsed = parse_args([
            "--config".into(),
            "a.json".into(),
            "--config".into(),
            "b.json".into(),
            "--plugins".into(),
            "plugins".into(),
            "--browser-assets".into(),
            "dist".into(),
            "--browser-har".into(),
            "workflow.har".into(),
        ])
        .unwrap();
        assert_eq!(parsed.inputs.configs.len(), 2);
        assert_eq!(parsed.inputs.plugin_roots.len(), 1);
        assert_eq!(parsed.inputs.browser_asset_roots.len(), 1);
        assert_eq!(parsed.inputs.browser_hars.len(), 1);
        assert!(parsed.formal.is_none());
        assert!(parse_args(["--unknown".into(), "x".into()]).is_err());
    }

    #[test]
    fn formal_outputs_are_all_or_none_and_unique() {
        assert!(parse_args([
            "--config".into(),
            "a.json".into(),
            "--workspace".into(),
            ".".into(),
        ])
        .is_err());
        assert!(parse_args([
            "--config".into(),
            "a.json".into(),
            "--workspace".into(),
            ".".into(),
            "--workspace".into(),
            ".".into(),
            "--report-output".into(),
            "report.json".into(),
            "--evidence-output".into(),
            "evidence.json".into(),
            "--evidence-environment".into(),
            "production".into(),
        ])
        .is_err());
        let parsed = parse_args([
            "--pilot-materials-root".into(),
            "materials".into(),
            "--pilot-manifest".into(),
            "pilot-materials.json".into(),
            "--pilot-report".into(),
            "pilot-readiness.json".into(),
            "--workspace".into(),
            ".".into(),
            "--report-output".into(),
            "report.json".into(),
            "--evidence-output".into(),
            "evidence.json".into(),
            "--evidence-environment".into(),
            "production".into(),
        ])
        .unwrap();
        assert!(parsed.formal.is_some());
        assert!(parsed.pilot.is_some());
        assert!(parsed.origin_policy.is_none());
        assert!(parse_args([
            "--config".into(),
            "a.json".into(),
            "--pilot-materials-root".into(),
            "materials".into(),
            "--pilot-manifest".into(),
            "pilot-materials.json".into(),
            "--pilot-report".into(),
            "pilot-readiness.json".into(),
        ])
        .is_err());
    }

    #[test]
    fn formal_outputs_cannot_modify_source_or_pilot_materials() {
        let root = tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let materials = root.path().join("materials");
        let outputs = root.path().join("outputs");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&materials).unwrap();
        fs::create_dir_all(&outputs).unwrap();

        assert!(validate_formal_output_locations(
            &workspace.join("migration-report.json"),
            &outputs.join("migration-evidence.json"),
            &workspace,
            &materials,
        )
        .is_err());
        assert!(validate_formal_output_locations(
            &outputs.join("migration-report.json"),
            &materials.join("migration-evidence.json"),
            &workspace,
            &materials,
        )
        .is_err());
        validate_formal_output_locations(
            &outputs.join("migration-report.json"),
            &outputs.join("migration-evidence.json"),
            &workspace,
            &materials,
        )
        .unwrap();
    }

    #[test]
    fn formal_summary_is_actionable_path_free_and_fail_closed() {
        let mut report = audit(&AuditInputs::default());
        report.findings = vec![
            ssdev_migration_audit::Finding {
                severity: Severity::Critical,
                code: "legacy-install-run",
                source: PathBuf::from(r"C:\secret\hospital-a\api.json"),
                message: "private endpoint http://10.17.5.57 must not escape".into(),
                remediation: "remove automatic execution and move the reviewed step into controlled deployment",
            },
            ssdev_migration_audit::Finding {
                severity: Severity::Critical,
                code: "legacy-install-run",
                source: PathBuf::from(r"D:\another-private-path\api.json"),
                message: "another sensitive finding".into(),
                remediation: "remove automatic execution and move the reviewed step into controlled deployment",
            },
            ssdev_migration_audit::Finding {
                severity: Severity::Info,
                code: "legacy-insecure-business-origin-authorized",
                source: PathBuf::from("private-config.json"),
                message: "authorized private origin".into(),
                remediation: "retain the signed policy binding",
            },
        ];
        report.summary.critical_findings = 2;
        report.summary.warning_findings = 0;

        let summary = summarize_findings(&report).unwrap();
        assert!(is_formal_audit_blocked(&summary));
        assert_eq!(summary.critical_findings, 2);
        assert_eq!(summary.info_findings, 1);
        assert_eq!(summary.code_counts["legacy-install-run"], 2);
        assert_eq!(summary.guidance["legacy-install-run"].count, 2);
        let rendered = render_formal_summary(&report, &summary);
        assert!(rendered.contains("migration audit: BLOCKED (2 critical, 0 warnings, 1 info)"));
        assert!(rendered.contains("blocker: legacy-install-run (critical, 2 occurrences)"));
        assert!(rendered.contains("action: remove automatic execution"));
        assert!(rendered.contains("cannot satisfy GO"));
        assert_eq!(rendered.matches("action:").count(), 1);
        assert!(!rendered.contains("C:\\secret"));
        assert!(!rendered.contains("10.17.5.57"));
        assert!(!rendered.contains("another sensitive finding"));

        let mut clear = audit(&AuditInputs::default());
        clear.findings.clear();
        clear.summary.critical_findings = 0;
        clear.summary.warning_findings = 0;
        let summary = summarize_findings(&clear).unwrap();
        assert!(!is_formal_audit_blocked(&summary));
        let rendered = render_formal_summary(&clear, &summary);
        assert!(rendered.contains("migration audit: CLEAR (0 critical, 0 warnings, 0 info)"));
        assert!(rendered.contains("this audit alone is not GO"));
        assert!(!rendered.contains("blocker:"));

        let mut inconsistent = audit(&AuditInputs::default());
        inconsistent.findings = vec![
            ssdev_migration_audit::Finding {
                severity: Severity::Critical,
                code: "legacy-install-run",
                source: PathBuf::new(),
                message: String::new(),
                remediation: "first action",
            },
            ssdev_migration_audit::Finding {
                severity: Severity::Warning,
                code: "legacy-install-run",
                source: PathBuf::new(),
                message: String::new(),
                remediation: "first action",
            },
        ];
        inconsistent.summary.critical_findings = 1;
        inconsistent.summary.warning_findings = 1;
        assert!(summarize_findings(&inconsistent).is_err());
    }

    #[test]
    fn pilot_handoff_derives_the_exact_audit_and_policy_inputs() {
        let root = tempdir().unwrap();
        let materials = root.path().join("materials");
        fs::create_dir(&materials).unwrap();
        let manifest_bytes = include_bytes!("../../../docs/pilot-materials.example.json");
        let manifest: PilotMaterialManifest = serde_json::from_slice(manifest_bytes).unwrap();
        for input in manifest
            .categories
            .iter()
            .flat_map(|category| &category.inputs)
        {
            let path = materials.join(input);
            if input == "native/components" {
                fs::create_dir_all(path.join("reader")).unwrap();
                fs::write(
                    path.join("reader/api.json"),
                    r#"{"serviceId":"reader","mainClass":"reader.dll","mainType":"dll","methods":[{"name":"read"}]}"#,
                )
                .unwrap();
            } else if input == "previous/bundle" {
                fs::create_dir_all(path.join("metadata")).unwrap();
                fs::create_dir_all(path.join("nsis")).unwrap();
                for file in [
                    "metadata/release.json",
                    "metadata/artifacts.json",
                    "metadata/artifacts.json.sig",
                    "metadata/app-update.json",
                    "nsis/ssdev-setup.exe",
                ] {
                    fs::write(path.join(file), file).unwrap();
                }
            } else {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, b"{}\n").unwrap();
            }
        }
        fs::write(
            materials.join("legacy/config"),
            r#"{"website":"http://10.17.5.57/project"}"#,
        )
        .unwrap();
        fs::write(
            materials.join("business/representative.har"),
            r#"{"log":{"entries":[{"request":{"url":"https://example.test/flow"}}]}}"#,
        )
        .unwrap();

        let policy_path = materials.join("policy/origin-policy.json");
        let envelope_path = materials.join("policy/origin-policy.sig.json");
        let trust_path = materials.join("policy/release-trust.json");
        let policy_bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "schemaVersion": 2,
            "businessGrants": [{
                "origin": "http://10.17.5.57",
                "services": [{"serviceId": "reader", "methods": ["read"]}]
            }],
            "allowInsecureHttp": true
        }))
        .unwrap();
        fs::write(&policy_path, &policy_bytes).unwrap();
        let signing_key = SigningKey::from_bytes(&[23; 32]);
        let signature = signing_key.sign(&ssdev_origin_policy::signing_payload(&policy_bytes));
        fs::write(
            &envelope_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "schemaVersion": 1,
                "keyId": "pilot-origin-policy-test",
                "algorithm": "ed25519",
                "signature": STANDARD.encode(signature.to_bytes())
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            &trust_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "schemaVersion": 2,
                "keys": [{
                    "keyId": "pilot-origin-policy-test",
                    "algorithm": "ed25519",
                    "publicKey": STANDARD.encode(signing_key.verifying_key().to_bytes()),
                    "purposes": ["origin-policy"]
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        let manifest_path = root.path().join("pilot-materials.json");
        let report_path = root.path().join("pilot-readiness.json");
        fs::write(&manifest_path, manifest_bytes).unwrap();
        let report = inspect_materials(&materials, &manifest, manifest_bytes).unwrap();
        assert!(report.intake_complete);
        write_report(&report_path, &report).unwrap();

        let verified = load_verified_pilot_inputs(PilotInputPaths {
            materials_root: materials.clone(),
            manifest: manifest_path,
            report: report_path,
        })
        .unwrap();
        let canonical_materials = fs::canonicalize(&materials).unwrap();
        assert_eq!(
            verified.audit_inputs.configs,
            vec![canonical_materials.join("legacy/config")]
        );
        assert_eq!(
            verified.audit_inputs.browser_hars,
            vec![canonical_materials.join("business/representative.har")]
        );
        let verified_policy = load_verified_origin_policy(OriginPolicyInputs {
            document: verified.origin_policy.document.clone(),
            envelope: verified.origin_policy.envelope.clone(),
            trust_store: verified.origin_policy.trust_store.clone(),
        })
        .unwrap();
        let mut audit_report = audit_with_verified_origin_policy(
            &verified.audit_inputs,
            &verified_policy.policy,
            verified_policy.document_sha256,
        );
        bind_pilot_materials(&mut audit_report, Some(&verified));
        assert_eq!(
            audit_report
                .pilot_materials
                .as_ref()
                .unwrap()
                .material_set_sha256,
            report.material_set_sha256
        );

        fs::write(
            materials.join("business/representative.har"),
            r#"{"log":{"entries":[]}}"#,
        )
        .unwrap();
        assert!(verified.verify_unchanged().is_err());
    }
}
