use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;

use serde_json::{Map, Value};
use webplus_plugin_config::{MethodDefinition, ServiceDefinition};
use webplus_protocol::InvokeResponse;

use crate::{resolve_component_with_extension, NativeError};

const MAX_PROCESS_OUTPUT_BYTES: usize = 1024 * 1024;

pub(crate) fn invoke(
    plugin_dir: &std::path::Path,
    service: &ServiceDefinition,
    method: &MethodDefinition,
    parameters: &Map<String, Value>,
) -> Result<InvokeResponse, NativeError> {
    let main_type = service.resolved_main_type().to_ascii_lowercase();
    let component = resolve_component_with_extension(plugin_dir, &service.main_class, &main_type)?;
    let args = method
        .parameters
        .iter()
        .map(|definition| {
            let name = definition.name();
            let value = parameters.get(name).unwrap_or(&Value::Null);
            match value {
                Value::Null => String::new(),
                Value::String(value) => value.clone(),
                other => other.to_string(),
            }
        })
        .collect::<Vec<_>>();
    let mut command = if main_type == "bat" {
        batch_command(&component, &args)?
    } else {
        let mut command = Command::new(&component);
        command.args(&args);
        command
    };
    command.current_dir(plugin_dir).stdin(Stdio::null());

    let wait = method
        .extensions
        .get("wait")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if wait {
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| NativeError::Process(error.to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| NativeError::Process("child stdout was not captured".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| NativeError::Process("child stderr was not captured".into()))?;
        let stdout_reader = thread::spawn(move || read_bounded(stdout));
        let stderr_reader = thread::spawn(move || read_bounded(stderr));
        let status = child
            .wait()
            .map_err(|error| NativeError::Process(error.to_string()))?;
        let (stdout, stdout_truncated) = join_output_reader(stdout_reader, "stdout")?;
        let (stderr, stderr_truncated) = join_output_reader(stderr_reader, "stderr")?;
        let mut result = Map::new();
        result.insert(
            "ReturnValue".into(),
            Value::Number(status.code().unwrap_or(-1).into()),
        );
        result.insert(
            "stdout".into(),
            Value::String(String::from_utf8_lossy(&stdout).into_owned()),
        );
        result.insert(
            "stderr".into(),
            Value::String(String::from_utf8_lossy(&stderr).into_owned()),
        );
        result.insert("stdoutTruncated".into(), Value::Bool(stdout_truncated));
        result.insert("stderrTruncated".into(), Value::Bool(stderr_truncated));
        Ok(InvokeResponse::success(result))
    } else {
        command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| NativeError::Process(error.to_string()))?;
        Ok(InvokeResponse::success(Value::String("success".into())))
    }
}

fn read_bounded(mut reader: impl Read) -> std::io::Result<(Vec<u8>, bool)> {
    let mut retained = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = MAX_PROCESS_OUTPUT_BYTES.saturating_sub(retained.len());
        let retain = count.min(remaining);
        retained.extend_from_slice(&buffer[..retain]);
        truncated |= retain < count;
    }
    Ok((retained, truncated))
}

fn join_output_reader(
    reader: thread::JoinHandle<std::io::Result<(Vec<u8>, bool)>>,
    stream: &str,
) -> Result<(Vec<u8>, bool), NativeError> {
    reader
        .join()
        .map_err(|_| NativeError::Process(format!("child {stream} reader panicked")))?
        .map_err(|error| NativeError::Process(format!("failed to read child {stream}: {error}")))
}

#[cfg(windows)]
fn batch_command(component: &std::path::Path, args: &[String]) -> Result<Command, NativeError> {
    if contains_cmd_control(&component.to_string_lossy())
        || args.iter().any(|arg| contains_cmd_control(arg))
    {
        return Err(NativeError::InvalidParameter {
            name: "bat args".into(),
            message: "batch arguments may not contain command control characters".into(),
        });
    }
    let mut command = Command::new("cmd.exe");
    command.args(["/D", "/S", "/C"]);
    command.arg(component);
    command.args(args);
    Ok(command)
}

#[cfg(not(windows))]
fn batch_command(_component: &std::path::Path, _args: &[String]) -> Result<Command, NativeError> {
    Err(NativeError::Unsupported(
        "BAT execution is only available on Windows".into(),
    ))
}

#[cfg(windows)]
fn contains_cmd_control(value: &str) -> bool {
    value.chars().any(|character| {
        matches!(
            character,
            '&' | '|' | '<' | '>' | '^' | '%' | '!' | '"' | '(' | ')' | '\r' | '\n'
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_output_is_retained_with_a_hard_limit() {
        let input = vec![b'x'; MAX_PROCESS_OUTPUT_BYTES + 10];
        let (output, truncated) = read_bounded(input.as_slice()).unwrap();

        assert_eq!(output.len(), MAX_PROCESS_OUTPUT_BYTES);
        assert!(truncated);
    }

    #[cfg(windows)]
    #[test]
    fn batch_arguments_reject_cmd_metacharacters() {
        for value in ["safe & unsafe", "quoted\"value", "$(group)", "%PATH%"] {
            assert!(contains_cmd_control(value));
        }
        assert!(!contains_cmd_control("ordinary argument with spaces"));
    }
}
