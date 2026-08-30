use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ssdev_diagnostics::{export_offline_diagnostics, inspect_offline_diagnostics};

const APP_DATA_DIRECTORY: &str = "com.bsoft.ssdev.desktop";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Inspect {
        data_root: Option<PathBuf>,
    },
    Collect {
        destination: PathBuf,
        data_root: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("BLOCKED {}", error.code);
            eprintln!("action: {}", error.action);
            ExitCode::from(2)
        }
    }
}

fn run(arguments: impl Iterator<Item = std::ffi::OsString>) -> Result<ExitCode, CliError> {
    let command = parse_arguments(arguments)?;
    let data_root = resolve_data_root(match &command {
        Command::Inspect { data_root } | Command::Collect { data_root, .. } => data_root.as_deref(),
    })?;
    let log_dir = data_root.join("logs");
    match command {
        Command::Inspect { .. } => {
            let summary = inspect_offline_diagnostics(&log_dir).map_err(map_diagnostics_error)?;
            println!(
                "status: {}",
                if summary.requires_attention() {
                    "ATTENTION"
                } else {
                    "CLEAR"
                }
            );
            println!("logFiles: {}", summary.log_files);
            println!("logBytes: {}", summary.log_bytes);
            if let Some(failure) = &summary.startup_failure {
                println!("startupFailureCode: {}", failure.error_code);
                println!(
                    "startupFailureState: {}",
                    if failure.resolved {
                        "resolved"
                    } else {
                        "active"
                    }
                );
            } else if summary.startup_failure_marker_invalid {
                println!("startupFailureState: invalid");
            } else {
                println!("startupFailureState: none");
            }
            if summary.requires_attention() {
                println!("action: {}", summary.action());
                Ok(ExitCode::from(3))
            } else {
                println!("action: 启动诊断未发现阻塞；仍需结合目标业务页面和真实设备检查。");
                Ok(ExitCode::SUCCESS)
            }
        }
        Command::Collect { destination, .. } => {
            let summary = inspect_offline_diagnostics(&log_dir).map_err(map_diagnostics_error)?;
            if summary.log_bytes == 0
                && summary.startup_failure.is_none()
                && !summary.startup_failure_marker_invalid
            {
                return Err(CliError::new(
                    "desktop-diagnostics-not-found",
                    "先以发生故障的 Windows 用户运行客户端一次，再重新收集。",
                ));
            }
            let bytes = export_offline_diagnostics(&log_dir, &destination)
                .map_err(map_diagnostics_error)?;
            println!("COLLECTED");
            println!("archiveBytes: {bytes}");
            println!("logFiles: {}", summary.log_files);
            println!(
                "startupFailureIncluded: {}",
                summary.startup_failure.is_some()
            );
            println!("action: 通过组织批准的支持渠道传输该诊断包。");
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn parse_arguments(
    arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<Command, CliError> {
    let arguments = arguments.map(PathBuf::from).collect::<Vec<_>>();
    let Some(operation) = arguments.first().and_then(|value| value.to_str()) else {
        return Err(usage_error());
    };
    let mut position = 1;
    let destination = if operation == "collect" {
        let value = arguments.get(position).ok_or_else(usage_error)?.clone();
        position += 1;
        Some(value)
    } else if operation == "inspect" {
        None
    } else {
        return Err(usage_error());
    };
    let mut data_root = None;
    if arguments.get(position).and_then(|value| value.to_str()) == Some("--data-root") {
        data_root = Some(arguments.get(position + 1).ok_or_else(usage_error)?.clone());
        position += 2;
    }
    if position != arguments.len() {
        return Err(usage_error());
    }
    match destination {
        Some(destination) => Ok(Command::Collect {
            destination,
            data_root,
        }),
        None => Ok(Command::Inspect { data_root }),
    }
}

fn resolve_data_root(explicit: Option<&Path>) -> Result<PathBuf, CliError> {
    if let Some(root) = explicit {
        if !root.is_absolute() {
            return Err(CliError::new(
                "desktop-diagnostics-data-root-invalid",
                "使用当前用户的默认目录，或通过 --data-root 提供绝对路径。",
            ));
        }
        return Ok(root.to_path_buf());
    }
    let local_app_data = env::var_os("LOCALAPPDATA").ok_or_else(|| {
        CliError::new(
            "desktop-diagnostics-data-root-unavailable",
            "请在发生故障的 Windows 用户会话中运行，或通过 --data-root 提供绝对路径。",
        )
    })?;
    let local_app_data = PathBuf::from(local_app_data);
    if !local_app_data.is_absolute() {
        return Err(CliError::new(
            "desktop-diagnostics-data-root-invalid",
            "修复当前 Windows 用户配置文件后重试。",
        ));
    }
    Ok(local_app_data.join(APP_DATA_DIRECTORY))
}

fn map_diagnostics_error(error: ssdev_diagnostics::DiagnosticsError) -> CliError {
    CliError::new(
        error.code(),
        match error.code() {
            "diagnostics-destination-exists" => "选择一个尚不存在的新 ZIP 文件。",
            "diagnostics-invalid-destination" => "提供绝对路径、已存在父目录和 .zip 扩展名。",
            "diagnostics-unsafe-log-entry" => {
                "保留现场并检查日志目录中的链接或异常文件，不要绕过安全检查。"
            }
            _ => "保留现场，检查日志目录权限、磁盘空间和安全软件后重试。",
        },
    )
}

fn usage_error() -> CliError {
    CliError::new(
        "desktop-doctor-usage",
        "用法：ssdev-desktop-doctor inspect [--data-root <绝对目录>]；或 ssdev-desktop-doctor collect <新建的绝对 ZIP 路径> [--data-root <绝对目录>]。",
    )
}

#[derive(Debug)]
struct CliError {
    code: &'static str,
    action: &'static str,
}

impl CliError {
    const fn new(code: &'static str, action: &'static str) -> Self {
        Self { code, action }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_bounded_inspect_and_collect_commands() {
        assert_eq!(
            parse_arguments(["inspect"].into_iter().map(Into::into)).unwrap(),
            Command::Inspect { data_root: None }
        );
        assert_eq!(
            parse_arguments(
                [
                    "collect",
                    "C:\\support\\desktop.zip",
                    "--data-root",
                    "C:\\data"
                ]
                .into_iter()
                .map(Into::into)
            )
            .unwrap(),
            Command::Collect {
                destination: PathBuf::from("C:\\support\\desktop.zip"),
                data_root: Some(PathBuf::from("C:\\data")),
            }
        );
        assert_eq!(
            parse_arguments(["delete"].into_iter().map(Into::into))
                .unwrap_err()
                .code,
            "desktop-doctor-usage"
        );
    }

    #[test]
    fn explicit_data_root_must_be_absolute_for_the_current_platform() {
        assert_eq!(
            resolve_data_root(Some(Path::new("relative")))
                .unwrap_err()
                .code,
            "desktop-diagnostics-data-root-invalid"
        );
    }
}
