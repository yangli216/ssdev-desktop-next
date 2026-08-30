use std::ffi::OsString;
use std::path::PathBuf;

use ssdev_app_update::verify_update_artifact_files;
use ssdev_release_manifest::{
    create_manifest, create_release_metadata, verify_manifest, verify_release_metadata,
    ReleaseMetadataOptions,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("release artifact manifest failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let operation = string_argument(arguments.first(), "operation")?;
    match operation.as_str() {
        "create" => {
            require_argument_count(&arguments, 3)?;
            let created = create_manifest(
                path_argument(arguments.get(1), "bundle root")?,
                &string_argument(arguments.get(2), "manifest relative path")?,
            )?;
            println!(
                "release artifact manifest created for {} files",
                created.files.len()
            );
        }
        "verify" => {
            require_argument_count(&arguments, 3)?;
            let verified = verify_manifest(
                path_argument(arguments.get(1), "bundle root")?,
                &string_argument(arguments.get(2), "manifest relative path")?,
            )?;
            println!(
                "release artifact manifest verified for {} files",
                verified.files.len()
            );
        }
        "metadata-create" => {
            require_argument_count(&arguments, 9)?;
            let workspace_root = path_argument(arguments.get(1), "workspace root")?;
            let output = path_argument(arguments.get(2), "metadata output")?;
            let app_version = string_argument(arguments.get(3), "app version")?;
            let product_name = string_argument(arguments.get(4), "product name")?;
            let identifier = string_argument(arguments.get(5), "application identifier")?;
            let authenticode_required = bool_argument(arguments.get(6), "authenticode required")?;
            let synthetic_version_override =
                bool_argument(arguments.get(7), "synthetic version override")?;
            let allow_dirty_source = bool_argument(arguments.get(8), "allow dirty source")?;
            let metadata = create_release_metadata(&ReleaseMetadataOptions {
                workspace_root: &workspace_root,
                output: &output,
                app_version: &app_version,
                product_name: &product_name,
                identifier: &identifier,
                authenticode_required,
                synthetic_version_override,
                allow_dirty_source,
            })?;
            println!(
                "release provenance created for source {}",
                metadata.source_revision
            );
        }
        "metadata-verify" => {
            if !matches!(arguments.len(), 2 | 3) {
                return Err(usage().into());
            }
            let metadata = path_argument(arguments.get(1), "metadata path")?;
            let workspace = arguments
                .get(2)
                .map(|value| path_argument(Some(value), "current workspace"))
                .transpose()?;
            let verified = verify_release_metadata(&metadata, workspace.as_deref())?;
            println!(
                "release provenance verified for source {}",
                verified.source_revision
            );
        }
        "update-verify" => {
            require_argument_count(&arguments, 4)?;
            let verified_bytes = verify_update_artifact_files(
                &path_argument(arguments.get(1), "application update policy")?,
                &path_argument(arguments.get(2), "update artifact")?,
                &path_argument(arguments.get(3), "update signature")?,
            )?;
            println!("application update signature verified for {verified_bytes} bytes");
        }
        _ => return Err(usage().into()),
    }
    Ok(())
}

fn require_argument_count(arguments: &[OsString], expected: usize) -> Result<(), &'static str> {
    if arguments.len() == expected {
        Ok(())
    } else {
        Err(usage())
    }
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

fn usage() -> &'static str {
    "usage:\n  ssdev-release-manifest <create|verify> <bundle-root> <manifest-relative-path>\n  ssdev-release-manifest metadata-create <workspace-root> <output> <app-version> <product-name> <identifier> <authenticode-required> <synthetic-version-override> <allow-dirty-source>\n  ssdev-release-manifest metadata-verify <metadata-path> [current-workspace-root]\n  ssdev-release-manifest update-verify <app-update.json> <update-artifact> <update-artifact.sig>"
}
