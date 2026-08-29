use ssdev_pilot_readiness::{
    inspect_materials, load_manifest, prepare_new_output, write_report, PilotReadinessError,
};
use std::env;
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
    if arguments.len() != 3 {
        return Err(PilotReadinessError::Invalid(usage().into()));
    }
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

fn usage() -> &'static str {
    "usage: ssdev-pilot-readiness <materials-root> <manifest.json> <report-output.json>"
}
