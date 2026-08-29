use ssdev_pilot_readiness::{
    inspect_materials, load_manifest, load_report, prepare_new_output, verify_materials,
    write_report, PilotReadinessError, PilotReadinessReport,
};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => std::process::exit(3),
        Err(error) => {
            eprintln!("pilot material readiness failed: {error}\n\n{}", usage());
            std::process::exit(1);
        }
    }
}

fn run() -> Result<bool, PilotReadinessError> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    run_with_arguments(&arguments)
}

fn run_with_arguments(arguments: &[OsString]) -> Result<bool, PilotReadinessError> {
    match arguments.first().and_then(|value| value.to_str()) {
        Some("create") if arguments.len() == 4 => run_create(&arguments[1..]),
        Some("verify") if arguments.len() == 4 => run_verify(&arguments[1..]),
        // Retained for the initial schema 1 CLI shipped before named operations existed.
        _ if arguments.len() == 3 => run_create(arguments),
        _ => Err(PilotReadinessError::Invalid(usage().into())),
    }
}

fn run_create(arguments: &[OsString]) -> Result<bool, PilotReadinessError> {
    let materials_root = PathBuf::from(&arguments[0]);
    let manifest_path = PathBuf::from(&arguments[1]);
    let output = prepare_new_output(&PathBuf::from(&arguments[2]))?;
    let canonical_root = fs::canonicalize(&materials_root)?;
    if output.starts_with(&canonical_root) {
        return Err(PilotReadinessError::Invalid(
            "report output must stay outside the materials root".into(),
        ));
    }
    let (manifest, before) = load_manifest(&manifest_path)?;
    let report = inspect_materials(&materials_root, &manifest, &before)?;
    let (_, after) = load_manifest(&manifest_path)?;
    if before != after {
        return Err(PilotReadinessError::Invalid(
            "manifest changed during inspection".into(),
        ));
    }
    write_report(&output, &report)?;
    println!("{}", render_report_summary(&report, false));
    Ok(report.intake_complete)
}

fn run_verify(arguments: &[OsString]) -> Result<bool, PilotReadinessError> {
    let materials_root = PathBuf::from(&arguments[0]);
    let manifest_path = PathBuf::from(&arguments[1]);
    let report_path = PathBuf::from(&arguments[2]);
    let canonical_root = fs::canonicalize(&materials_root)?;
    let canonical_report = fs::canonicalize(&report_path)?;
    if canonical_report.starts_with(&canonical_root) {
        return Err(PilotReadinessError::Invalid(
            "verified report must stay outside the materials root".into(),
        ));
    }
    let (manifest, manifest_before) = load_manifest(&manifest_path)?;
    let (report, report_before) = load_report(&report_path)?;
    verify_materials(&materials_root, &manifest, &manifest_before, &report)?;
    let (_, manifest_after) = load_manifest(&manifest_path)?;
    let (_, report_after) = load_report(&report_path)?;
    if manifest_before != manifest_after || report_before != report_after {
        return Err(PilotReadinessError::Invalid(
            "manifest or report changed during verification".into(),
        ));
    }
    println!("{}", render_report_summary(&report, true));
    Ok(report.intake_complete)
}

fn render_report_summary(report: &PilotReadinessReport, verified: bool) -> String {
    let operation = if verified {
        "pilot material report verified"
    } else {
        "pilot material intake"
    };
    let state = if report.intake_complete {
        "COMPLETE"
    } else {
        "INCOMPLETE"
    };
    let mut lines = vec![format!(
        "{operation}: {state} ({} blockers)",
        report.blocker_codes.len()
    )];
    if report.intake_complete {
        lines.push(format!(
            "material set sha256: {}",
            report.material_set_sha256
        ));
        lines.push(if verified {
            "next: run the migration audit from this verified materials set before hardware and Windows package validation".into()
        } else {
            "next: transfer the same materials root, manifest, and report; the receiver must run verify before migration audit".into()
        });
    } else {
        lines.extend(
            report
                .blocker_codes
                .iter()
                .map(|code| format!("blocker: {code}")),
        );
        lines.push(if verified {
            "next: this incomplete report is authentic; resolve its blocker codes and create a new non-overwriting report".into()
        } else {
            "next: resolve the blocker codes, then run create again with a new report output path".into()
        });
    }
    lines.join("\n")
}

fn usage() -> &'static str {
    "usage:\n  ssdev-pilot-readiness create <materials-root> <manifest.json> <report-output.json>\n  ssdev-pilot-readiness verify <materials-root> <manifest.json> <report.json>"
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssdev_pilot_readiness::{PilotMaterialManifest, REPORT_SCHEMA_VERSION};
    use tempfile::tempdir;

    #[test]
    fn named_create_and_verify_operations_round_trip_the_documented_manifest() {
        let temp = tempdir().unwrap();
        let materials = temp.path().join("materials");
        fs::create_dir(&materials).unwrap();
        let manifest_bytes = include_bytes!("../../../docs/pilot-materials.example.json");
        let manifest: PilotMaterialManifest = serde_json::from_slice(manifest_bytes).unwrap();
        for input in manifest
            .categories
            .iter()
            .flat_map(|category| &category.inputs)
        {
            let path = materials.join(input);
            if input == "previous/bundle" {
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
                fs::write(path, input.as_bytes()).unwrap();
            }
        }
        let manifest_path = temp.path().join("pilot-materials.json");
        let report_path = temp.path().join("pilot-readiness.json");
        fs::write(&manifest_path, manifest_bytes).unwrap();
        assert!(run_with_arguments(&[
            "create".into(),
            materials.as_os_str().into(),
            manifest_path.as_os_str().into(),
            report_path.as_os_str().into(),
        ])
        .unwrap());
        assert!(run_with_arguments(&[
            "verify".into(),
            materials.as_os_str().into(),
            manifest_path.as_os_str().into(),
            report_path.as_os_str().into(),
        ])
        .unwrap());
    }

    #[test]
    fn console_summary_exposes_only_stable_blockers_or_the_material_set_digest() {
        let digest = "a".repeat(64);
        let incomplete = PilotReadinessReport {
            schema_version: REPORT_SCHEMA_VERSION,
            report_type: "pilot-material-readiness".into(),
            manifest_sha256: "b".repeat(64),
            project_label_sha256: "c".repeat(64),
            migration_audit_bindings_sha256: "d".repeat(64),
            material_set_sha256: digest.clone(),
            intake_complete: false,
            downstream_validation_required: true,
            categories: Vec::new(),
            blocker_codes: vec![
                "business-hars-missing".into(),
                "migration-audit-binding-mismatch".into(),
            ],
        };
        let summary = render_report_summary(&incomplete, false);
        assert!(summary.contains("pilot material intake: INCOMPLETE (2 blockers)"));
        assert!(summary.contains("blocker: business-hars-missing"));
        assert!(summary.contains("blocker: migration-audit-binding-mismatch"));
        assert!(!summary.contains(&digest));
        assert!(!summary.contains("hospital-a-pilot"));
        assert!(!summary.contains("D:\\ssdev-pilot"));

        let complete = PilotReadinessReport {
            intake_complete: true,
            blocker_codes: Vec::new(),
            ..incomplete
        };
        let summary = render_report_summary(&complete, true);
        assert!(summary.contains("pilot material report verified: COMPLETE (0 blockers)"));
        assert!(summary.contains(&format!("material set sha256: {digest}")));
        assert!(summary.contains("run the migration audit"));
        assert!(!summary.contains("blocker:"));
    }
}
