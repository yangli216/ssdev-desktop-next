use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ssdev_cutover_evidence::{
    prepare_new_output, sha256_bytes, write_migration_audit_evidence, write_new_bytes,
    EvidenceType, HttpEvidenceLevel, MigrationAuditEvidence, EVIDENCE_SCHEMA_VERSION,
};
use ssdev_migration_audit::{
    audit, AuditInputs, AuditReport, EvidenceLevel as AuditEvidenceLevel, Severity,
};
use ssdev_release_manifest::capture_source_identity;

#[derive(Debug)]
struct CliOptions {
    inputs: AuditInputs,
    formal: Option<FormalOutputs>,
}

#[derive(Debug)]
struct FormalOutputs {
    report_output: PathBuf,
    evidence_output: PathBuf,
    evidence_environment: String,
    workspace: PathBuf,
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(error) => {
            eprintln!("{error}\n\n用法: ssdev-migration-audit [--config FILE]... [--plugins DIR]... [--keymap FILE]... [--browser-assets FILE_OR_DIR]... [--browser-har FILE]... [--workspace DIR --report-output FILE --evidence-output FILE --evidence-environment LABEL]");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let options = parse_args(env::args().skip(1))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    match options.formal {
        None => {
            println!("{}", serde_json::to_string_pretty(&audit(&options.inputs))?);
            Ok(())
        }
        Some(formal) => run_formal(&options.inputs, formal),
    }
}

fn run_formal(inputs: &AuditInputs, formal: FormalOutputs) -> Result<(), Box<dyn Error>> {
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
    if report_output.starts_with(&workspace) || evidence_output.starts_with(&workspace) {
        return Err(invalid_input(
            "formal outputs must stay outside the source workspace",
        ));
    }

    let source_before = capture_source_identity(&workspace)?;
    let report = audit(inputs);
    let mut report_bytes = serde_json::to_vec_pretty(&report)?;
    report_bytes.push(b'\n');
    let report_sha256 = sha256_bytes(&report_bytes);
    let source_after = capture_source_identity(&workspace)?;
    if source_before != source_after {
        return Err(invalid_input(
            "source identity changed during migration audit",
        ));
    }

    let evidence = build_evidence(
        &report,
        source_after,
        report_sha256,
        formal.evidence_environment,
    )?;
    evidence.validate()?;
    write_new_bytes(&report_output, &report_bytes)?;
    write_migration_audit_evidence(&evidence_output, &evidence)?;
    println!(
        "migration audit report and evidence written: {} findings, {} browser files, {} HAR requests",
        report.findings.len(),
        report.browser_compatibility.asset_files_scanned,
        report.browser_compatibility.har_requests_scanned
    );
    Ok(())
}

fn build_evidence(
    report: &AuditReport,
    source: ssdev_release_manifest::SourceIdentity,
    report_sha256: String,
    environment: String,
) -> Result<MigrationAuditEvidence, Box<dyn Error>> {
    let mut finding_code_counts = BTreeMap::new();
    let mut critical_findings = 0_u32;
    let mut warning_findings = 0_u32;
    let mut info_findings = 0_u32;
    for finding in &report.findings {
        let count = finding_code_counts
            .entry(finding.code.to_owned())
            .or_insert(0_u32);
        *count = count
            .checked_add(1)
            .ok_or_else(|| invalid_input("finding count overflowed"))?;
        let severity = match finding.severity {
            Severity::Critical => &mut critical_findings,
            Severity::Warning => &mut warning_findings,
            Severity::Info => &mut info_findings,
        };
        *severity = severity
            .checked_add(1)
            .ok_or_else(|| invalid_input("severity count overflowed"))?;
    }
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
        webplus_http_evidence: map_http_evidence(
            report.browser_compatibility.webplus_http_evidence,
        ),
        desktop_callback_http_evidence: map_http_evidence(
            report.browser_compatibility.desktop_callback_http_evidence,
        ),
        critical_findings,
        warning_findings,
        info_findings,
        finding_code_counts,
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
            _ => return Err(format!("未知参数 [{argument}]")),
        }
    }
    if inputs.configs.is_empty()
        && inputs.plugin_roots.is_empty()
        && inputs.keymaps.is_empty()
        && inputs.browser_asset_roots.is_empty()
        && inputs.browser_hars.is_empty()
    {
        return Err("至少需要一个审计输入".into());
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
    Ok(CliOptions { inputs, formal })
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
            "--config".into(),
            "a.json".into(),
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
    }
}
