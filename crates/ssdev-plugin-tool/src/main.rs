use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::time::SystemTime;

use ssdev_plugin_tool::{
    check_executable_matrix_plugin, check_executable_matrix_root, create_catalog, finalize,
    prepare, verify, CatalogOptions, FinalizeOptions, PrepareOptions,
};

fn main() {
    let result = run(env::args().skip(1));
    match result {
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
    let report = match command.as_str() {
        "prepare" => {
            reject_unknown(
                &options,
                &[
                    "source",
                    "staging",
                    "request",
                    "matrix-template",
                    "plugin-id",
                    "version",
                    "display-name",
                    "key-id",
                    "trust-store",
                    "matrix-seed",
                ],
            )?;
            let display_name = options
                .get("display-name")
                .or_else(|| options.get("plugin-id"))
                .ok_or_else(|| "缺少 --plugin-id".to_owned())?;
            serde_json::to_string_pretty(
                &prepare(&PrepareOptions {
                    source: required_path(&options, "source")?,
                    staging: required_path(&options, "staging")?,
                    request: required_path(&options, "request")?,
                    matrix_template: required_path(&options, "matrix-template")?,
                    plugin_id: required(&options, "plugin-id")?,
                    version: required(&options, "version")?,
                    display_name,
                    key_id: required(&options, "key-id")?,
                    trust_store: required_path(&options, "trust-store")?,
                    matrix_seed: options.get("matrix-seed").map(Path::new),
                })
                .map_err(|error| error.to_string())?,
            )
        }
        "finalize" => {
            reject_unknown(
                &options,
                &["staging", "request", "signature", "trust-store", "package"],
            )?;
            serde_json::to_string_pretty(
                &finalize(&FinalizeOptions {
                    staging: required_path(&options, "staging")?,
                    request: required_path(&options, "request")?,
                    signature: required_path(&options, "signature")?,
                    trust_store: required_path(&options, "trust-store")?,
                    package: required_path(&options, "package")?,
                })
                .map_err(|error| error.to_string())?,
            )
        }
        "verify" => {
            reject_unknown(&options, &["package", "trust-store"])?;
            serde_json::to_string_pretty(
                &verify(
                    required_path(&options, "package")?,
                    required_path(&options, "trust-store")?,
                )
                .map_err(|error| error.to_string())?,
            )
        }
        "catalog" => {
            reject_unknown(&options, &["spec", "trust-store", "catalog"])?;
            serde_json::to_string_pretty(
                &create_catalog(&CatalogOptions {
                    spec: required_path(&options, "spec")?,
                    trust_store: required_path(&options, "trust-store")?,
                    catalog: required_path(&options, "catalog")?,
                    now: SystemTime::now(),
                })
                .map_err(|error| error.to_string())?,
            )
        }
        "matrix-check" => {
            reject_unknown(&options, &["plugin-root", "plugin-dir", "matrix"])?;
            let matrix = required_path(&options, "matrix")?;
            let report = match (options.get("plugin-root"), options.get("plugin-dir")) {
                (Some(root), None) => check_executable_matrix_root(Path::new(root), matrix),
                (None, Some(plugin)) => check_executable_matrix_plugin(Path::new(plugin), matrix),
                _ => {
                    return Err(
                        "matrix-check 必须且只能指定 --plugin-root 或 --plugin-dir 之一".into(),
                    )
                }
            };
            serde_json::to_string_pretty(&report.map_err(|error| error.to_string())?)
        }
        _ => return Err(format!("未知子命令 [{command}]")),
    }
    .map_err(|error| error.to_string())?;
    Ok(report)
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

fn usage() -> &'static str {
    "用法:\n  ssdev-plugin-tool prepare --source DIR --staging DIR --request FILE --matrix-template FILE --plugin-id ID --version SEMVER [--display-name NAME] --key-id ID --trust-store FILE [--matrix-seed FILE]\n  ssdev-plugin-tool finalize --staging DIR --request FILE --signature FILE --trust-store FILE --package FILE.ssdev-plugin\n  ssdev-plugin-tool verify --package FILE.ssdev-plugin --trust-store FILE\n  ssdev-plugin-tool catalog --spec FILE --trust-store FILE --catalog FILE\n  ssdev-plugin-tool matrix-check (--plugin-root DIR | --plugin-dir DIR) --matrix FILE"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_rejects_duplicates_and_unknown_commands() {
        assert!(
            parse_options(["--source".into(), "a".into(), "--source".into(), "b".into()]).is_err()
        );
        assert!(run(["unknown".into()]).unwrap_err().contains("未知子命令"));
        assert!(run([
            "matrix-check".into(),
            "--matrix".into(),
            "matrix.json".into()
        ])
        .unwrap_err()
        .contains("必须且只能指定"));
    }
}
