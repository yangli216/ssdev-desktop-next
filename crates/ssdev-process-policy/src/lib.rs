use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use webplus_plugin_trust::{DetachedSignatureDocument, TrustError, TrustPurpose, TrustStore};

const MAX_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_PROCESSES: usize = 64;
const PROCESS_POLICY_DOMAIN: &[u8] = b"SSDEV-PROCESS-POLICY\0";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedProcess {
    pub id: String,
    pub executable: PathBuf,
    pub sha256: String,
    #[serde(default)]
    pub arguments: Vec<String>,
    #[serde(default)]
    pub working_directory: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub singleton: bool,
}

#[derive(Debug, Clone)]
pub struct ProcessPolicy {
    processes: HashMap<String, ManagedProcess>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchFailure {
    pub process_id: String,
    pub error: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaunchReport {
    pub started: Vec<String>,
    pub already_running: Vec<String>,
    pub failures: Vec<LaunchFailure>,
}

impl ProcessPolicy {
    pub fn load(
        policy_path: &Path,
        signature_path: &Path,
        trust_store: &TrustStore,
    ) -> Result<Self, PolicyError> {
        let bytes = read_limited(policy_path, MAX_POLICY_BYTES)?;
        let signature_bytes = read_limited(signature_path, MAX_POLICY_BYTES)?;
        let signature: DetachedSignatureDocument = serde_json::from_slice(&signature_bytes)
            .map_err(|source| PolicyError::Json {
                path: signature_path.to_path_buf(),
                source,
            })?;
        signature.validate()?;
        trust_store.verify_detached(
            TrustPurpose::ProcessPolicy,
            &signature.key_id,
            &signing_payload(&bytes),
            &signature.signature,
        )?;

        Self::from_unsigned_bytes_at(&bytes, policy_path)
    }

    /// Validates an unsigned policy before it is sent to an external signer.
    pub fn from_unsigned_bytes(bytes: &[u8]) -> Result<Self, PolicyError> {
        Self::from_unsigned_bytes_at(bytes, Path::new("process-policy.json"))
    }

    pub fn launch_selected(&self, selected: &[String]) -> LaunchReport {
        let mut report = LaunchReport::default();
        let mut seen = HashSet::new();
        for process_id in selected {
            if !seen.insert(process_id) {
                continue;
            }
            let Some(process) = self.processes.get(process_id) else {
                report.failures.push(LaunchFailure {
                    process_id: process_id.clone(),
                    error: "process ID is not present in the signed policy".into(),
                });
                continue;
            };
            match launch(process) {
                Ok(LaunchDisposition::Started) => report.started.push(process_id.clone()),
                Ok(LaunchDisposition::AlreadyRunning) => {
                    report.already_running.push(process_id.clone())
                }
                Err(error) => report.failures.push(LaunchFailure {
                    process_id: process_id.clone(),
                    error: error.to_string(),
                }),
            }
        }
        report
    }

    pub fn len(&self) -> usize {
        self.processes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.processes.is_empty()
    }

    fn from_unsigned_bytes_at(bytes: &[u8], path: &Path) -> Result<Self, PolicyError> {
        if bytes.len() as u64 > MAX_POLICY_BYTES {
            return Err(PolicyError::Invalid(format!(
                "process policy exceeds {MAX_POLICY_BYTES} bytes"
            )));
        }
        let document: PolicyDocument =
            serde_json::from_slice(bytes).map_err(|source| PolicyError::Json {
                path: path.to_path_buf(),
                source,
            })?;
        if document.schema_version != 1 {
            return Err(PolicyError::Invalid(format!(
                "unsupported process policy schema [{}]",
                document.schema_version
            )));
        }
        if document.processes.len() > MAX_PROCESSES {
            return Err(PolicyError::Invalid(format!(
                "process policy contains more than {MAX_PROCESSES} entries"
            )));
        }
        let mut processes = HashMap::new();
        for process in document.processes {
            validate_process(&process)?;
            if processes.insert(process.id.clone(), process).is_some() {
                return Err(PolicyError::Invalid("duplicate process ID".into()));
            }
        }
        Ok(Self { processes })
    }
}

pub fn signing_payload(policy_bytes: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(policy_bytes);
    let mut payload = Vec::with_capacity(PROCESS_POLICY_DOMAIN.len() + digest.len());
    payload.extend_from_slice(PROCESS_POLICY_DOMAIN);
    payload.extend_from_slice(&digest);
    payload
}

fn validate_process(process: &ManagedProcess) -> Result<(), PolicyError> {
    if process.id.is_empty()
        || process.id.len() > 64
        || process.id.starts_with('.')
        || !process
            .id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(PolicyError::Invalid(format!(
            "process ID [{}] is not portable",
            process.id
        )));
    }
    if !process.executable.is_absolute() {
        return Err(PolicyError::Invalid(format!(
            "process [{}] executable path must be absolute",
            process.id
        )));
    }
    if process.sha256.len() != 64
        || !process
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PolicyError::Invalid(format!(
            "process [{}] SHA-256 must be 64 lowercase hexadecimal characters",
            process.id
        )));
    }
    if process.arguments.len() > 32
        || process
            .arguments
            .iter()
            .any(|argument| argument.len() > 4096 || argument.contains('\0'))
    {
        return Err(PolicyError::Invalid(format!(
            "process [{}] contains too many or oversized arguments",
            process.id
        )));
    }
    if process
        .working_directory
        .as_ref()
        .is_some_and(|path| !path.is_absolute())
    {
        return Err(PolicyError::Invalid(format!(
            "process [{}] working directory must be absolute",
            process.id
        )));
    }
    Ok(())
}

enum LaunchDisposition {
    Started,
    AlreadyRunning,
}

fn launch(process: &ManagedProcess) -> Result<LaunchDisposition, PolicyError> {
    let executable = process
        .executable
        .canonicalize()
        .map_err(|source| PolicyError::Io {
            path: process.executable.clone(),
            source,
        })?;
    verify_executable(&executable, &process.sha256)?;
    if process.singleton && process_is_running(&executable)? {
        return Ok(LaunchDisposition::AlreadyRunning);
    }

    let mut command = Command::new(&executable);
    command
        .args(&process.arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(working_directory) = &process.working_directory {
        let working_directory =
            working_directory
                .canonicalize()
                .map_err(|source| PolicyError::Io {
                    path: working_directory.clone(),
                    source,
                })?;
        if !working_directory.is_dir() {
            return Err(PolicyError::Invalid(format!(
                "working directory {working_directory:?} is not a directory"
            )));
        }
        command.current_dir(working_directory);
    }
    command.spawn().map_err(|source| PolicyError::Io {
        path: executable,
        source,
    })?;
    Ok(LaunchDisposition::Started)
}

fn verify_executable(path: &Path, expected: &str) -> Result<(), PolicyError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| PolicyError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() || metadata.len() > MAX_EXECUTABLE_BYTES {
        return Err(PolicyError::Invalid(format!(
            "managed executable {path:?} is not a regular file or exceeds the size limit"
        )));
    }
    let mut file = File::open(path).map_err(|source| PolicyError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher).map_err(|source| PolicyError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let actual = format!("{:x}", hasher.finalize());
    if actual != expected {
        return Err(PolicyError::Invalid(format!(
            "managed executable {path:?} does not match its signed SHA-256"
        )));
    }
    Ok(())
}

#[cfg(not(windows))]
fn process_is_running(_executable: &Path) -> Result<bool, PolicyError> {
    Ok(false)
}

#[cfg(windows)]
fn process_is_running(executable: &Path) -> Result<bool, PolicyError> {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let expected = executable.to_string_lossy().to_lowercase();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(PolicyError::Platform(
                "failed to enumerate processes".into(),
            ));
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut has_entry = Process32FirstW(snapshot, &mut entry) != 0;
        while has_entry {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32ProcessID);
            if !process.is_null() {
                let mut path = vec![0_u16; 32_768];
                let mut size = path.len() as u32;
                if QueryFullProcessImageNameW(
                    process,
                    PROCESS_NAME_WIN32,
                    path.as_mut_ptr(),
                    &mut size,
                ) != 0
                {
                    let running = String::from_utf16_lossy(&path[..size as usize]).to_lowercase();
                    CloseHandle(process);
                    if running == expected {
                        CloseHandle(snapshot);
                        return Ok(true);
                    }
                } else {
                    CloseHandle(process);
                }
            }
            has_entry = Process32NextW(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
    }
    Ok(false)
}

fn read_limited(path: &Path, limit: u64) -> Result<Vec<u8>, PolicyError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| PolicyError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(PolicyError::Invalid(format!(
            "file {path:?} is not a regular file or exceeds {limit} bytes"
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|source| PolicyError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(bytes)
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyDocument {
    schema_version: u8,
    processes: Vec<ManagedProcess>,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("process policy is invalid: {0}")]
    Invalid(String),
    #[error("failed to access {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid JSON at {path:?}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("process policy trust error: {0}")]
    Trust(#[from] TrustError),
    #[error("platform process inspection failed: {0}")]
    Platform(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::tempdir;

    fn fixture() -> (tempfile::TempDir, TrustStore, PathBuf, PathBuf) {
        let root = tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[19_u8; 32]);
        let trust_path = root.path().join("trust.json");
        fs::write(
            &trust_path,
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "keys": [{
                    "keyId": "process-key",
                    "algorithm": "ed25519",
                    "publicKey": BASE64.encode(signing_key.verifying_key().to_bytes()),
                    "purposes": ["process-policy"]
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let policy_path = root.path().join("process-policy.json");
        let policy = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "processes": [{
                "id": "helper",
                "executable": if cfg!(windows) { "C:\\\\SSDEV\\\\helper.exe" } else { "/opt/ssdev/helper" },
                "sha256": "00".repeat(32),
                "arguments": ["--managed"],
                "singleton": true
            }]
        }))
        .unwrap();
        fs::write(&policy_path, &policy).unwrap();
        let signature_path = root.path().join("process-policy.sig.json");
        let signature = signing_key.sign(&signing_payload(&policy));
        fs::write(
            &signature_path,
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 1,
                "keyId": "process-key",
                "algorithm": "ed25519",
                "signature": BASE64.encode(signature.to_bytes())
            }))
            .unwrap(),
        )
        .unwrap();
        let trust = TrustStore::load(&trust_path).unwrap();
        (root, trust, policy_path, signature_path)
    }

    #[test]
    fn loads_a_signed_fixed_process_policy() {
        let (_root, trust, policy, signature) = fixture();
        let loaded = ProcessPolicy::load(&policy, &signature, &trust).unwrap();
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn rejects_policy_changes_after_signing() {
        let (_root, trust, policy, signature) = fixture();
        fs::write(&policy, br#"{"schemaVersion":1,"processes":[]}"#).unwrap();
        assert!(ProcessPolicy::load(&policy, &signature, &trust).is_err());
    }

    #[test]
    fn unknown_selected_process_is_not_spawned() {
        let (_root, trust, policy, signature) = fixture();
        let loaded = ProcessPolicy::load(&policy, &signature, &trust).unwrap();
        let report = loaded.launch_selected(&["missing".into()]);
        assert_eq!(report.failures.len(), 1);
        assert!(report.started.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn policy_reader_rejects_symbolic_links() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let target = root.path().join("target.json");
        let link = root.path().join("process-policy.json");
        fs::write(&target, b"{}").unwrap();
        symlink(&target, &link).unwrap();
        assert!(read_limited(&link, MAX_POLICY_BYTES).is_err());
    }
}
