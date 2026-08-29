use ssdev_pilot_readiness::{
    inspect_materials, load_manifest, load_report, prepare_new_output, verify_materials,
    write_report, PilotReadinessError,
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
    println!(
        "pilot material intake: {} ({} blockers)",
        if report.intake_complete {
            "COMPLETE"
        } else {
            "INCOMPLETE"
        },
        report.blocker_codes.len()
    );
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
    println!(
        "pilot material report verified: {} ({} blockers)",
        if report.intake_complete {
            "COMPLETE"
        } else {
            "INCOMPLETE"
        },
        report.blocker_codes.len()
    );
    Ok(report.intake_complete)
}

fn usage() -> &'static str {
    "usage:\n  ssdev-pilot-readiness create <materials-root> <manifest.json> <report-output.json>\n  ssdev-pilot-readiness verify <materials-root> <manifest.json> <report.json>"
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssdev_pilot_readiness::PilotMaterialManifest;
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
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, input.as_bytes()).unwrap();
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
}
