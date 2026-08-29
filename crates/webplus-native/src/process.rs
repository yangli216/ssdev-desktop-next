use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use webplus_plugin_config::{MethodDefinition, ServiceDefinition};
use webplus_protocol::{InvokeResponse, NATIVE_RETURN_VALUE_FIELD};

use crate::{resolve_component_with_extension, NativeError};

const MAX_PROCESS_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_PROCESS_ENTRY_BYTES: u64 = 1024 * 1024 * 1024;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
#[cfg(windows)]
const FILE_SHARE_READ: u32 = 0x0000_0001;

pub(crate) struct ProcessAdapter {
    verified_files: Option<HashMap<String, String>>,
    pinned: HashMap<PathBuf, PinnedProcess>,
}

struct PinnedProcess {
    expected_sha256: String,
    _lifetime_guard: File,
}

impl ProcessAdapter {
    pub(crate) fn unverified() -> Self {
        Self {
            verified_files: None,
            pinned: HashMap::new(),
        }
    }

    pub(crate) fn new(
        verified_files: Option<BTreeMap<String, String>>,
    ) -> Result<Self, NativeError> {
        let verified_files = verified_files
            .map(|files| {
                let mut normalized = HashMap::with_capacity(files.len());
                for (path, sha256) in files {
                    let key = verified_file_key(&path)?;
                    if !is_lowercase_sha256(&sha256) {
                        return Err(NativeError::Process(
                            "verified runtime file inventory contains an invalid digest".into(),
                        ));
                    }
                    if normalized.insert(key, sha256).is_some() {
                        return Err(NativeError::Process(
                            "verified runtime file inventory contains a case-colliding path".into(),
                        ));
                    }
                }
                Ok(normalized)
            })
            .transpose()?;
        Ok(Self {
            verified_files,
            pinned: HashMap::new(),
        })
    }

    pub(crate) fn preflight(
        &mut self,
        plugin_dir: &Path,
        service: &ServiceDefinition,
    ) -> Result<(), NativeError> {
        let main_type = service.resolved_main_type().to_ascii_lowercase();
        let component =
            resolve_component_with_extension(plugin_dir, &service.main_class, &main_type)?;
        let mut guard = open_lifetime_guard(&component)?;
        let actual_sha256 = hash_open_file(&component, &mut guard)?;
        let key = component_key(plugin_dir, &component)?;
        let expected_sha256 = match &self.verified_files {
            Some(files) => files.get(&key).cloned().ok_or_else(|| {
                NativeError::Process(
                    "native process entry is absent from the verified file inventory".into(),
                )
            })?,
            None => actual_sha256.clone(),
        };
        if actual_sha256 != expected_sha256 {
            return Err(NativeError::Process(
                "native process entry does not match the verified file inventory".into(),
            ));
        }
        if let Some(existing) = self.pinned.get(&component) {
            if existing.expected_sha256 != expected_sha256 {
                return Err(NativeError::Process(
                    "native process entry has conflicting verified identities".into(),
                ));
            }
            return Ok(());
        }
        self.pinned.insert(
            component,
            PinnedProcess {
                expected_sha256,
                _lifetime_guard: guard,
            },
        );
        Ok(())
    }

    pub(crate) fn invoke(
        &mut self,
        plugin_dir: &Path,
        service: &ServiceDefinition,
        method: &MethodDefinition,
        parameters: &Map<String, Value>,
    ) -> Result<InvokeResponse, NativeError> {
        let main_type = service.resolved_main_type().to_ascii_lowercase();
        let component =
            resolve_component_with_extension(plugin_dir, &service.main_class, &main_type)?;
        let expected_sha256 = self
            .pinned
            .get(&component)
            .ok_or_else(|| NativeError::Process("native process entry was not preflighted".into()))?
            .expected_sha256
            .clone();
        let mut launch_guard = open_lifetime_guard(&component)?;
        if hash_open_file(&component, &mut launch_guard)? != expected_sha256 {
            return Err(NativeError::Process(
                "native process entry changed after preflight".into(),
            ));
        }

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
        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);

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
            drop(launch_guard);
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
                NATIVE_RETURN_VALUE_FIELD.into(),
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
            drop(launch_guard);
            Ok(InvokeResponse::success(Value::String("success".into())))
        }
    }
}

fn open_lifetime_guard(component: &Path) -> Result<File, NativeError> {
    let metadata = std::fs::symlink_metadata(component)
        .map_err(|_| NativeError::MissingComponent(component.to_path_buf()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_PROCESS_ENTRY_BYTES
    {
        return Err(NativeError::Process(
            "native process entry must be a bounded regular non-symlink file".into(),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    options.share_mode(FILE_SHARE_READ);
    let file = options
        .open(component)
        .map_err(|error| NativeError::Process(error.to_string()))?;
    let opened = file
        .metadata()
        .map_err(|error| NativeError::Process(error.to_string()))?;
    if !opened.is_file() || opened.len() > MAX_PROCESS_ENTRY_BYTES {
        return Err(NativeError::Process(
            "opened native process entry is not a bounded regular file".into(),
        ));
    }
    Ok(file)
}

fn hash_open_file(component: &Path, file: &mut File) -> Result<String, NativeError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| NativeError::Process(error.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| NativeError::Process(error.to_string()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        NativeError::Process(format!(
            "failed to rewind native process entry {component:?}: {error}"
        ))
    })?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn component_key(plugin_dir: &Path, component: &Path) -> Result<String, NativeError> {
    let root = plugin_dir
        .canonicalize()
        .map_err(|_| NativeError::MissingComponent(plugin_dir.to_path_buf()))?;
    let relative = component
        .strip_prefix(root)
        .map_err(|_| NativeError::PathEscape(component.to_path_buf()))?;
    let mut parts = Vec::new();
    for part in relative.components() {
        let Component::Normal(part) = part else {
            return Err(NativeError::PathEscape(component.to_path_buf()));
        };
        parts.push(part.to_str().ok_or_else(|| {
            NativeError::Process("native process entry path is not valid UTF-8".into())
        })?);
    }
    if parts.is_empty() {
        return Err(NativeError::PathEscape(component.to_path_buf()));
    }
    Ok(parts.join("/").to_ascii_lowercase())
}

fn verified_file_key(path: &str) -> Result<String, NativeError> {
    if path.is_empty()
        || path.contains('\\')
        || Path::new(path).is_absolute()
        || !Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(NativeError::Process(
            "verified runtime file inventory contains an unsafe path".into(),
        ));
    }
    Ok(path.to_ascii_lowercase())
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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
    use std::fs;

    use serde_json::json;

    use super::*;

    fn process_service() -> ServiceDefinition {
        serde_json::from_value(json!({
            "serviceId": "process.probe",
            "mainClass": "probe.exe",
            "mainType": "exe",
            "architecture": "x64",
            "methods": [{"name": "run"}]
        }))
        .unwrap()
    }

    #[cfg(windows)]
    fn batch_service() -> ServiceDefinition {
        serde_json::from_value(json!({
            "serviceId": "process.batch",
            "mainClass": "probe.bat",
            "mainType": "bat",
            "architecture": "x64",
            "methods": [{"name": "run", "wait": true}]
        }))
        .unwrap()
    }

    fn digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    #[test]
    fn process_output_is_retained_with_a_hard_limit() {
        let input = vec![b'x'; MAX_PROCESS_OUTPUT_BYTES + 10];
        let (output, truncated) = read_bounded(input.as_slice()).unwrap();

        assert_eq!(output.len(), MAX_PROCESS_OUTPUT_BYTES);
        assert!(truncated);
    }

    #[test]
    fn verified_process_preflight_rejects_unapproved_content() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("probe.exe"), b"unexpected").unwrap();
        let mut files = BTreeMap::new();
        files.insert("probe.exe".into(), digest(b"approved"));
        let mut adapter = ProcessAdapter::new(Some(files)).unwrap();

        let error = adapter
            .preflight(directory.path(), &process_service())
            .unwrap_err();

        assert!(matches!(error, NativeError::Process(_)));
    }

    #[cfg(not(windows))]
    #[test]
    fn process_invocation_rechecks_content_after_preflight() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("probe.exe"), b"approved").unwrap();
        let service = process_service();
        let mut adapter = ProcessAdapter::new(None).unwrap();
        adapter.preflight(directory.path(), &service).unwrap();
        fs::write(directory.path().join("probe.exe"), b"modified").unwrap();

        let error = adapter
            .invoke(directory.path(), &service, &service.methods[0], &Map::new())
            .unwrap_err();

        assert!(matches!(error, NativeError::Process(_)));
    }

    #[cfg(windows)]
    #[test]
    fn process_preflight_holds_a_non_writable_lifetime_guard() {
        let directory = tempfile::tempdir().unwrap();
        let component = directory.path().join("probe.exe");
        fs::write(&component, b"approved").unwrap();
        let mut adapter = ProcessAdapter::new(None).unwrap();
        adapter
            .preflight(directory.path(), &process_service())
            .unwrap();

        assert!(fs::write(&component, b"modified").is_err());
        drop(adapter);
        fs::write(&component, b"modified").unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn guarded_batch_entry_can_still_execute() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("probe.bat"), b"@exit /b 0\r\n").unwrap();
        let service = batch_service();
        let mut adapter = ProcessAdapter::new(None).unwrap();
        adapter.preflight(directory.path(), &service).unwrap();

        let response = adapter
            .invoke(directory.path(), &service, &service.methods[0], &Map::new())
            .unwrap();

        assert_eq!(response.res_code, 0);
        assert_eq!(response.res_data[NATIVE_RETURN_VALUE_FIELD], 0);
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
