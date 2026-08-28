use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::time::SystemTime;

use ssdev_release_signing::{
    finalize, prepare, verify, verify_trust_store, ArtifactKind, FinalizeOptions, PrepareOptions,
};
use webplus_plugin_trust::TrustPurpose;

fn main() {
    match run(env::args().skip(1)) {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("{error}\n\n{}", usage());
            std::process::exit(2);
        }
    }
}

fn run(arguments: impl IntoIterator<Item = String>) -> Result<String, String> {
    let mut arguments = arguments.into_iter();
    let command = arguments.next().ok_or_else(|| "缺少子命令".to_owned())?;
    let options = parse_options(arguments)?;
    let now = SystemTime::now();
    let value = match command.as_str() {
        "prepare" => {
            reject_unknown(
                &options,
                &["kind", "document", "key-id", "trust-store", "request"],
            )?;
            let kind = required_kind(&options)?;
            serde_json::to_value(
                prepare(&PrepareOptions {
                    kind,
                    document: required_path(&options, "document")?,
                    key_id: required(&options, "key-id")?,
                    trust_store: required_path(&options, "trust-store")?,
                    request: required_path(&options, "request")?,
                    now,
                })
                .map_err(|error| error.to_string())?,
            )
        }
        "finalize" => {
            reject_unknown(
                &options,
                &[
                    "kind",
                    "document",
                    "request",
                    "signature",
                    "trust-store",
                    "envelope",
                ],
            )?;
            let kind = required_kind(&options)?;
            serde_json::to_value(
                finalize(&FinalizeOptions {
                    kind,
                    document: required_path(&options, "document")?,
                    request: required_path(&options, "request")?,
                    signature: required_path(&options, "signature")?,
                    trust_store: required_path(&options, "trust-store")?,
                    envelope: required_path(&options, "envelope")?,
                    now,
                })
                .map_err(|error| error.to_string())?,
            )
        }
        "verify" => {
            reject_unknown(&options, &["kind", "document", "envelope", "trust-store"])?;
            let kind = required_kind(&options)?;
            serde_json::to_value(
                verify(
                    kind,
                    required_path(&options, "document")?,
                    required_path(&options, "envelope")?,
                    required_path(&options, "trust-store")?,
                    now,
                )
                .map_err(|error| error.to_string())?,
            )
        }
        "verify-trust-store" => {
            reject_unknown(&options, &["trust-store", "required-purposes"])?;
            let required_purposes = required_purposes(&options)?;
            serde_json::to_value(
                verify_trust_store(required_path(&options, "trust-store")?, &required_purposes)
                    .map_err(|error| error.to_string())?,
            )
        }
        _ => return Err(format!("未知子命令 [{command}]")),
    }
    .and_then(|value| serde_json::to_string_pretty(&value))
    .map_err(|error| error.to_string())?;
    Ok(value)
}

fn parse_options(
    arguments: impl IntoIterator<Item = String>,
) -> Result<HashMap<String, String>, String> {
    let mut arguments = arguments.into_iter();
    let mut options = HashMap::new();
    while let Some(flag) = arguments.next() {
        let name = flag
            .strip_prefix("--")
            .filter(|name| !name.is_empty())
            .ok_or_else(|| format!("无效参数 [{flag}]"))?;
        let value = arguments
            .next()
            .ok_or_else(|| format!("参数 [{flag}] 缺少值"))?;
        if options.insert(name.to_owned(), value).is_some() {
            return Err(format!("参数 [{flag}] 重复"));
        }
    }
    Ok(options)
}

fn reject_unknown(options: &HashMap<String, String>, allowed: &[&str]) -> Result<(), String> {
    if let Some(name) = options
        .keys()
        .find(|name| !allowed.contains(&name.as_str()))
    {
        return Err(format!("未知参数 [--{name}]"));
    }
    Ok(())
}

fn required<'a>(options: &'a HashMap<String, String>, name: &str) -> Result<&'a str, String> {
    options
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("缺少 --{name}"))
}

fn required_path<'a>(options: &'a HashMap<String, String>, name: &str) -> Result<&'a Path, String> {
    required(options, name).map(Path::new)
}

fn required_kind(options: &HashMap<String, String>) -> Result<ArtifactKind, String> {
    required(options, "kind")?
        .parse()
        .map_err(|error: ssdev_release_signing::SigningError| error.to_string())
}

fn required_purposes(options: &HashMap<String, String>) -> Result<Vec<TrustPurpose>, String> {
    let mut purposes = Vec::new();
    for value in required(options, "required-purposes")?.split(',') {
        let purpose = match value {
            "cutover-decision" => TrustPurpose::CutoverDecision,
            "cutover-evidence" => TrustPurpose::CutoverEvidence,
            "plugin" => TrustPurpose::Plugin,
            "plugin-catalog" => TrustPurpose::PluginCatalog,
            "project-bundle" => TrustPurpose::ProjectBundle,
            "origin-policy" => TrustPurpose::OriginPolicy,
            "process-policy" => TrustPurpose::ProcessPolicy,
            _ => return Err(format!("不支持的信任用途 [{value}]")),
        };
        if purposes.contains(&purpose) {
            return Err(format!("信任用途 [{value}] 重复"));
        }
        purposes.push(purpose);
    }
    if purposes.is_empty() {
        return Err("--required-purposes 不能为空".into());
    }
    Ok(purposes)
}

fn usage() -> &'static str {
    "用法:\n  ssdev-release-signing prepare --kind <cutover-decision|plugin-matrix-evidence|migration-audit-evidence|windows-package-evidence|origin-policy|process-policy|plugin-catalog|project-bundle> --document FILE --key-id ID --trust-store FILE --request FILE\n  ssdev-release-signing finalize --kind KIND --document FILE --request FILE --signature FILE --trust-store FILE --envelope FILE\n  ssdev-release-signing verify --kind KIND --document FILE --envelope FILE --trust-store FILE\n  ssdev-release-signing verify-trust-store --trust-store FILE --required-purposes plugin,origin-policy,project-bundle"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_rejects_duplicate_and_unknown_commands() {
        assert!(parse_options([
            "--kind".into(),
            "origin-policy".into(),
            "--kind".into(),
            "process-policy".into(),
        ])
        .is_err());
        assert!(
            run(["unknown".into(), "--kind".into(), "origin-policy".into()])
                .unwrap_err()
                .contains("未知子命令")
        );
        assert!(required_purposes(&HashMap::from([(
            "required-purposes".into(),
            "plugin,plugin".into(),
        )]))
        .is_err());
    }
}
