use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;
use uuid::Uuid;
use webplus_protocol::InvokeRequest;

const SCHEMA_VERSION: u8 = 1;
const SNAPSHOT_FILE: &str = "operations.snapshot.jsonl";
const JOURNAL_FILE: &str = "operations.journal.jsonl";
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 1024;
pub const MAX_DURABLE_OPERATIONS: usize = 65_536;
pub const MAX_DURABLE_OPERATIONS_PER_SCOPE: usize = 16_384;
const COMPACT_JOURNAL_BYTES: u64 = 8 * 1024 * 1024;
pub const COMPLETED_OPERATION_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
pub const INDETERMINATE_OPERATION_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

const SCOPE_DOMAIN: &[u8] = b"SSDEV-INVOKE-SCOPE\0";
const AUTHORIZATION_DOMAIN: &[u8] = b"SSDEV-INVOKE-AUTHORIZATION\0";
const REQUEST_DOMAIN: &[u8] = b"SSDEV-INVOKE-REQUEST\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationIdentity {
    operation_id: String,
    scope_hash: String,
    request_hash: String,
    authorization_hash: String,
}

impl OperationIdentity {
    pub fn for_request(
        operation_id: &str,
        origin: &str,
        request: &InvokeRequest,
    ) -> Result<Self, LedgerError> {
        let operation_id = validate_operation_id(operation_id)?;
        let request_bytes = serde_json::to_vec(request)?;
        Ok(Self {
            operation_id,
            scope_hash: hash_parts(SCOPE_DOMAIN, &[origin.as_bytes()]),
            request_hash: hash_parts(REQUEST_DOMAIN, &[&request_bytes]),
            authorization_hash: hash_parts(
                AUTHORIZATION_DOMAIN,
                &[
                    origin.as_bytes(),
                    request.service_id.as_bytes(),
                    request.method.as_bytes(),
                ],
            ),
        })
    }

    pub fn lookup(&self) -> OperationLookup {
        OperationLookup {
            operation_id: self.operation_id.clone(),
            scope_hash: self.scope_hash.clone(),
            authorization_hash: self.authorization_hash.clone(),
        }
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn runtime_key(&self) -> String {
        format!("{}:{}", self.scope_hash, self.operation_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationLookup {
    operation_id: String,
    scope_hash: String,
    authorization_hash: String,
}

impl OperationLookup {
    pub fn for_route(
        operation_id: &str,
        origin: &str,
        service_id: &str,
        method: &str,
    ) -> Result<Self, LedgerError> {
        Ok(Self {
            operation_id: validate_operation_id(operation_id)?,
            scope_hash: hash_parts(SCOPE_DOMAIN, &[origin.as_bytes()]),
            authorization_hash: hash_parts(
                AUTHORIZATION_DOMAIN,
                &[origin.as_bytes(), service_id.as_bytes(), method.as_bytes()],
            ),
        })
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn runtime_key(&self) -> String {
        format!("{}:{}", self.scope_hash, self.operation_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeginDecision {
    Started,
    Indeterminate,
    CompletedWithoutResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableStatus {
    Unknown,
    Indeterminate,
    CompletedWithoutResult,
}

pub struct InvocationLedger {
    inner: Mutex<LedgerInner>,
}

struct LedgerInner {
    directory: PathBuf,
    snapshot_path: PathBuf,
    journal_path: PathBuf,
    journal: File,
    journal_bytes: u64,
    operations: HashMap<OperationKey, StoredOperation>,
    scope_counts: HashMap<String, usize>,
    next_prune_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OperationKey {
    operation_id: String,
    scope_hash: String,
}

#[derive(Debug, Clone)]
struct StoredOperation {
    request_hash: String,
    authorization_hash: String,
    state: StoredState,
    recorded_at_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredState {
    Accepted,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LedgerRecord {
    schema_version: u8,
    operation_id: String,
    scope_hash: String,
    request_hash: String,
    authorization_hash: String,
    state: StoredState,
    recorded_at_unix_ms: u64,
}

impl InvocationLedger {
    pub fn open(directory: impl Into<PathBuf>, now: SystemTime) -> Result<Self, LedgerError> {
        let directory = directory.into();
        create_private_directory(&directory)?;
        let snapshot_path = directory.join(SNAPSHOT_FILE);
        let journal_path = directory.join(JOURNAL_FILE);
        let mut operations = HashMap::new();
        load_records(&snapshot_path, &mut operations)?;
        load_records(&journal_path, &mut operations)?;
        let now = unix_millis(now)?;
        prune_expired(&mut operations, now);
        let scope_counts = rebuild_scope_counts(&operations);
        let next_prune_at_unix_ms = next_expiration(&operations);
        write_snapshot(&directory, &snapshot_path, &operations)?;
        let journal = open_empty_journal(&journal_path)?;
        Ok(Self {
            inner: Mutex::new(LedgerInner {
                directory,
                snapshot_path,
                journal_path,
                journal,
                journal_bytes: 0,
                operations,
                scope_counts,
                next_prune_at_unix_ms,
            }),
        })
    }

    pub fn begin(
        &self,
        identity: &OperationIdentity,
        now: SystemTime,
    ) -> Result<BeginDecision, LedgerError> {
        let now = unix_millis(now)?;
        let mut inner = self.inner.lock().unwrap_or_else(|lock| lock.into_inner());
        maintain_expirations(&mut inner, now)?;
        let key = identity_key(identity);
        if let Some(existing) = inner.operations.get(&key) {
            ensure_same_operation(existing, identity)?;
            return Ok(match existing.state {
                StoredState::Accepted => BeginDecision::Indeterminate,
                StoredState::Completed => BeginDecision::CompletedWithoutResult,
            });
        }
        ensure_capacity(
            inner.operations.len(),
            inner
                .scope_counts
                .get(&identity.scope_hash)
                .copied()
                .unwrap_or_default(),
        )?;
        let record = record_from_identity(identity, StoredState::Accepted, now);
        append_record(&mut inner, &record)?;
        let stored = stored_from_record(&record);
        inner.next_prune_at_unix_ms = inner
            .next_prune_at_unix_ms
            .min(expiration_at(&stored).unwrap_or(u64::MAX));
        inner.operations.insert(key, stored);
        *inner
            .scope_counts
            .entry(identity.scope_hash.clone())
            .or_default() += 1;
        maybe_compact(&mut inner)?;
        Ok(BeginDecision::Started)
    }

    pub fn complete(
        &self,
        identity: &OperationIdentity,
        now: SystemTime,
    ) -> Result<(), LedgerError> {
        let now = unix_millis(now)?;
        let mut inner = self.inner.lock().unwrap_or_else(|lock| lock.into_inner());
        let key = identity_key(identity);
        let existing = inner
            .operations
            .get(&key)
            .ok_or(LedgerError::MissingAcceptedOperation)?;
        ensure_same_operation(existing, identity)?;
        if existing.state == StoredState::Completed {
            return Ok(());
        }
        let record = record_from_identity(identity, StoredState::Completed, now);
        append_record(&mut inner, &record)?;
        let stored = stored_from_record(&record);
        inner.next_prune_at_unix_ms = inner
            .next_prune_at_unix_ms
            .min(expiration_at(&stored).unwrap_or(u64::MAX));
        inner.operations.insert(key, stored);
        maybe_compact(&mut inner)
    }

    pub fn status(
        &self,
        lookup: &OperationLookup,
        now: SystemTime,
    ) -> Result<DurableStatus, LedgerError> {
        let now = unix_millis(now)?;
        let mut inner = self.inner.lock().unwrap_or_else(|lock| lock.into_inner());
        maintain_expirations(&mut inner, now)?;
        let key = OperationKey {
            operation_id: lookup.operation_id.clone(),
            scope_hash: lookup.scope_hash.clone(),
        };
        let Some(operation) = inner.operations.get(&key) else {
            return Ok(DurableStatus::Unknown);
        };
        if operation.authorization_hash != lookup.authorization_hash {
            return Err(LedgerError::OperationConflict);
        }
        Ok(match operation.state {
            StoredState::Accepted => DurableStatus::Indeterminate,
            StoredState::Completed => DurableStatus::CompletedWithoutResult,
        })
    }

    pub fn operation_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|lock| lock.into_inner())
            .operations
            .len()
    }
}

fn create_private_directory(directory: &Path) -> Result<(), LedgerError> {
    fs::create_dir_all(directory).map_err(|source| LedgerError::Io {
        path: directory.to_path_buf(),
        source,
    })?;
    let metadata = fs::symlink_metadata(directory).map_err(|source| LedgerError::Io {
        path: directory.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_dir() {
        return Err(LedgerError::UnsafePath(directory.to_path_buf()));
    }
    Ok(())
}

fn load_records(
    path: &Path,
    operations: &mut HashMap<OperationKey, StoredOperation>,
) -> Result<(), LedgerError> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path).map_err(|source| LedgerError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_FILE_BYTES {
        return Err(LedgerError::UnsafePath(path.to_path_buf()));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|file| file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|source| LedgerError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(LedgerError::TooLarge(path.to_path_buf()));
    }
    let terminated = bytes.ends_with(b"\n");
    let lines = bytes.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    for (index, line) in lines.iter().enumerate() {
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_RECORD_BYTES {
            return Err(LedgerError::InvalidRecord {
                path: path.to_path_buf(),
                line: index + 1,
            });
        }
        let record = match serde_json::from_slice::<LedgerRecord>(line) {
            Ok(record) => record,
            Err(_) if !terminated && index + 1 == lines.len() => break,
            Err(_) => {
                return Err(LedgerError::InvalidRecord {
                    path: path.to_path_buf(),
                    line: index + 1,
                });
            }
        };
        validate_record(&record).map_err(|_| LedgerError::InvalidRecord {
            path: path.to_path_buf(),
            line: index + 1,
        })?;
        let key = OperationKey {
            operation_id: record.operation_id.clone(),
            scope_hash: record.scope_hash.clone(),
        };
        if let Some(existing) = operations.get(&key) {
            if existing.request_hash != record.request_hash
                || existing.authorization_hash != record.authorization_hash
            {
                return Err(LedgerError::OperationConflict);
            }
        }
        operations.insert(key, stored_from_record(&record));
        if operations.len() > MAX_DURABLE_OPERATIONS {
            return Err(LedgerError::Capacity(MAX_DURABLE_OPERATIONS));
        }
    }
    Ok(())
}

fn validate_record(record: &LedgerRecord) -> Result<(), LedgerError> {
    if record.schema_version != SCHEMA_VERSION
        || validate_operation_id(&record.operation_id)? != record.operation_id
        || !is_sha256(&record.scope_hash)
        || !is_sha256(&record.request_hash)
        || !is_sha256(&record.authorization_hash)
    {
        return Err(LedgerError::InvalidIdentity);
    }
    Ok(())
}

fn append_record(inner: &mut LedgerInner, record: &LedgerRecord) -> Result<(), LedgerError> {
    let mut bytes = serde_json::to_vec(record)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_RECORD_BYTES
        || inner.journal_bytes.saturating_add(bytes.len() as u64) > MAX_FILE_BYTES
    {
        compact(inner)?;
    }
    if inner.journal_bytes.saturating_add(bytes.len() as u64) > MAX_FILE_BYTES {
        return Err(LedgerError::TooLarge(inner.journal_path.clone()));
    }
    inner
        .journal
        .write_all(&bytes)
        .and_then(|_| inner.journal.flush())
        .and_then(|_| inner.journal.sync_data())
        .map_err(|source| LedgerError::Io {
            path: inner.journal_path.clone(),
            source,
        })?;
    inner.journal_bytes += bytes.len() as u64;
    Ok(())
}

fn maybe_compact(inner: &mut LedgerInner) -> Result<(), LedgerError> {
    if inner.journal_bytes >= COMPACT_JOURNAL_BYTES {
        compact(inner)?;
    }
    Ok(())
}

fn compact(inner: &mut LedgerInner) -> Result<(), LedgerError> {
    write_snapshot(&inner.directory, &inner.snapshot_path, &inner.operations)?;
    inner
        .journal
        .set_len(0)
        .and_then(|_| inner.journal.seek(SeekFrom::Start(0)).map(|_| ()))
        .and_then(|_| inner.journal.sync_all())
        .map_err(|source| LedgerError::Io {
            path: inner.journal_path.clone(),
            source,
        })?;
    inner.journal_bytes = 0;
    Ok(())
}

fn write_snapshot(
    directory: &Path,
    path: &Path,
    operations: &HashMap<OperationKey, StoredOperation>,
) -> Result<(), LedgerError> {
    let mut temporary = NamedTempFile::new_in(directory).map_err(|source| LedgerError::Io {
        path: directory.to_path_buf(),
        source,
    })?;
    let mut ordered = operations.iter().collect::<Vec<_>>();
    ordered.sort_by(|(left, _), (right, _)| {
        left.scope_hash
            .cmp(&right.scope_hash)
            .then(left.operation_id.cmp(&right.operation_id))
    });
    for (key, operation) in ordered {
        let record = LedgerRecord {
            schema_version: SCHEMA_VERSION,
            operation_id: key.operation_id.clone(),
            scope_hash: key.scope_hash.clone(),
            request_hash: operation.request_hash.clone(),
            authorization_hash: operation.authorization_hash.clone(),
            state: operation.state,
            recorded_at_unix_ms: operation.recorded_at_unix_ms,
        };
        let mut bytes = serde_json::to_vec(&record)?;
        bytes.push(b'\n');
        temporary
            .write_all(&bytes)
            .map_err(|source| LedgerError::Io {
                path: path.to_path_buf(),
                source,
            })?;
    }
    if temporary.as_file().metadata()?.len() > MAX_FILE_BYTES {
        return Err(LedgerError::TooLarge(path.to_path_buf()));
    }
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| LedgerError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    temporary.persist(path).map_err(|error| LedgerError::Io {
        path: path.to_path_buf(),
        source: error.error,
    })?;
    sync_directory(directory)?;
    Ok(())
}

fn open_empty_journal(path: &Path) -> Result<File, LedgerError> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path).map_err(|source| LedgerError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if !metadata.file_type().is_file() {
            return Err(LedgerError::UnsafePath(path.to_path_buf()));
        }
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)
        .map_err(|source| LedgerError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    file.set_len(0).map_err(|source| LedgerError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| LedgerError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(file)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), LedgerError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| LedgerError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), LedgerError> {
    Ok(())
}

fn maintain_expirations(inner: &mut LedgerInner, now: u64) -> Result<(), LedgerError> {
    if now < inner.next_prune_at_unix_ms {
        return Ok(());
    }
    let changed = prune_expired(&mut inner.operations, now);
    inner.scope_counts = rebuild_scope_counts(&inner.operations);
    inner.next_prune_at_unix_ms = next_expiration(&inner.operations);
    if changed {
        compact(inner)?;
    }
    Ok(())
}

fn prune_expired(operations: &mut HashMap<OperationKey, StoredOperation>, now: u64) -> bool {
    let before = operations.len();
    operations.retain(|_, operation| !is_expired(operation, now));
    operations.len() != before
}

fn is_expired(operation: &StoredOperation, now: u64) -> bool {
    expiration_at(operation).is_some_and(|expiration| now >= expiration)
}

fn expiration_at(operation: &StoredOperation) -> Option<u64> {
    let retention = match operation.state {
        StoredState::Accepted => INDETERMINATE_OPERATION_RETENTION,
        StoredState::Completed => COMPLETED_OPERATION_RETENTION,
    };
    operation
        .recorded_at_unix_ms
        .checked_add(retention.as_millis() as u64)?
        .checked_add(1)
}

fn next_expiration(operations: &HashMap<OperationKey, StoredOperation>) -> u64 {
    operations
        .values()
        .filter_map(expiration_at)
        .min()
        .unwrap_or(u64::MAX)
}

fn rebuild_scope_counts(
    operations: &HashMap<OperationKey, StoredOperation>,
) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for key in operations.keys() {
        *counts.entry(key.scope_hash.clone()).or_default() += 1;
    }
    counts
}

fn ensure_capacity(operation_count: usize, scope_count: usize) -> Result<(), LedgerError> {
    if scope_count >= MAX_DURABLE_OPERATIONS_PER_SCOPE {
        return Err(LedgerError::ScopeCapacity(MAX_DURABLE_OPERATIONS_PER_SCOPE));
    }
    if operation_count >= MAX_DURABLE_OPERATIONS {
        return Err(LedgerError::Capacity(MAX_DURABLE_OPERATIONS));
    }
    Ok(())
}

fn ensure_same_operation(
    existing: &StoredOperation,
    identity: &OperationIdentity,
) -> Result<(), LedgerError> {
    if existing.request_hash != identity.request_hash
        || existing.authorization_hash != identity.authorization_hash
    {
        return Err(LedgerError::OperationConflict);
    }
    Ok(())
}

fn identity_key(identity: &OperationIdentity) -> OperationKey {
    OperationKey {
        operation_id: identity.operation_id.clone(),
        scope_hash: identity.scope_hash.clone(),
    }
}

fn record_from_identity(
    identity: &OperationIdentity,
    state: StoredState,
    recorded_at_unix_ms: u64,
) -> LedgerRecord {
    LedgerRecord {
        schema_version: SCHEMA_VERSION,
        operation_id: identity.operation_id.clone(),
        scope_hash: identity.scope_hash.clone(),
        request_hash: identity.request_hash.clone(),
        authorization_hash: identity.authorization_hash.clone(),
        state,
        recorded_at_unix_ms,
    }
}

fn stored_from_record(record: &LedgerRecord) -> StoredOperation {
    StoredOperation {
        request_hash: record.request_hash.clone(),
        authorization_hash: record.authorization_hash.clone(),
        state: record.state,
        recorded_at_unix_ms: record.recorded_at_unix_ms,
    }
}

fn validate_operation_id(value: &str) -> Result<String, LedgerError> {
    let parsed = Uuid::parse_str(value).map_err(|_| LedgerError::InvalidOperationId)?;
    let canonical = parsed.hyphenated().to_string();
    if parsed.get_version_num() != 4 || value != canonical {
        return Err(LedgerError::InvalidOperationId);
    }
    Ok(canonical)
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update((*part).len().to_le_bytes());
        hasher.update(part);
    }
    format!("{:x}", hasher.finalize())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn unix_millis(now: SystemTime) -> Result<u64, LedgerError> {
    let millis = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LedgerError::InvalidClock)?
        .as_millis();
    u64::try_from(millis).map_err(|_| LedgerError::InvalidClock)
}

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("operation ID must be a canonical lowercase UUID v4")]
    InvalidOperationId,
    #[error("operation identity is invalid")]
    InvalidIdentity,
    #[error("operation ID was already used for a different request or authorization scope")]
    OperationConflict,
    #[error("operation ledger reached its bounded capacity of {0} entries")]
    Capacity(usize),
    #[error("operation scope reached its isolated capacity of {0} entries")]
    ScopeCapacity(usize),
    #[error("operation must be durably accepted before it can complete")]
    MissingAcceptedOperation,
    #[error("system clock precedes the Unix epoch or exceeds the supported range")]
    InvalidClock,
    #[error("operation ledger path is not a bounded regular file or directory: {0:?}")]
    UnsafePath(PathBuf),
    #[error("operation ledger file exceeds its size limit: {0:?}")]
    TooLarge(PathBuf),
    #[error("operation ledger contains an invalid record at {path:?}:{line}")]
    InvalidRecord { path: PathBuf, line: usize },
    #[error("operation ledger I/O failed at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("operation ledger JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl LedgerError {
    pub fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::InvalidOperationId => "invalid-operation-id",
            Self::InvalidIdentity => "invalid-operation-identity",
            Self::OperationConflict => "operation-conflict",
            Self::Capacity(_) => "operation-ledger-capacity",
            Self::ScopeCapacity(_) => "operation-ledger-scope-capacity",
            Self::MissingAcceptedOperation => "operation-not-accepted",
            Self::InvalidClock => "operation-ledger-clock",
            Self::UnsafePath(_) => "operation-ledger-path",
            Self::TooLarge(_) => "operation-ledger-size",
            Self::InvalidRecord { .. } => "operation-ledger-corrupt",
            Self::Io { .. } => "operation-ledger-io",
            Self::Json(_) => "operation-ledger-json",
        }
    }
}

impl From<std::io::Error> for LedgerError {
    fn from(source: std::io::Error) -> Self {
        Self::Io {
            path: PathBuf::from("operation-ledger"),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Map};
    use tempfile::tempdir;

    const OPERATION_ID: &str = "123e4567-e89b-42d3-a456-426614174000";

    fn request(value: i64) -> InvokeRequest {
        InvokeRequest {
            service_id: "printer".into(),
            method: "print".into(),
            parameters: Map::from_iter([("copies".into(), json!(value))]),
        }
    }

    #[test]
    fn accepts_once_and_recovers_without_replaying_after_restart() {
        let root = tempdir().unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let identity =
            OperationIdentity::for_request(OPERATION_ID, "https://business.example", &request(1))
                .unwrap();
        {
            let ledger = InvocationLedger::open(root.path(), now).unwrap();
            assert_eq!(
                ledger.begin(&identity, now).unwrap(),
                BeginDecision::Started
            );
            assert_eq!(
                ledger.begin(&identity, now).unwrap(),
                BeginDecision::Indeterminate
            );
        }

        let recovered = InvocationLedger::open(root.path(), now).unwrap();
        assert_eq!(
            recovered.begin(&identity, now).unwrap(),
            BeginDecision::Indeterminate
        );
        assert_eq!(recovered.operation_count(), 1);
        assert_eq!(
            recovered
                .inner
                .lock()
                .unwrap_or_else(|lock| lock.into_inner())
                .scope_counts
                .get(&identity.scope_hash),
            Some(&1)
        );
    }

    #[test]
    fn completed_operation_never_reexecutes_when_result_is_not_persisted() {
        let root = tempdir().unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let identity =
            OperationIdentity::for_request(OPERATION_ID, "https://business.example", &request(1))
                .unwrap();
        let ledger = InvocationLedger::open(root.path(), now).unwrap();
        assert_eq!(
            ledger.begin(&identity, now).unwrap(),
            BeginDecision::Started
        );
        ledger.complete(&identity, now).unwrap();
        drop(ledger);

        let recovered = InvocationLedger::open(root.path(), now).unwrap();
        assert_eq!(
            recovered.begin(&identity, now).unwrap(),
            BeginDecision::CompletedWithoutResult
        );
        assert_eq!(
            recovered.status(&identity.lookup(), now).unwrap(),
            DurableStatus::CompletedWithoutResult
        );
    }

    #[test]
    fn same_id_with_different_parameters_is_a_hard_conflict() {
        let root = tempdir().unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let first =
            OperationIdentity::for_request(OPERATION_ID, "https://business.example", &request(1))
                .unwrap();
        let second =
            OperationIdentity::for_request(OPERATION_ID, "https://business.example", &request(2))
                .unwrap();
        let ledger = InvocationLedger::open(root.path(), now).unwrap();
        ledger.begin(&first, now).unwrap();

        assert!(matches!(
            ledger.begin(&second, now),
            Err(LedgerError::OperationConflict)
        ));
    }

    #[test]
    fn journal_contains_only_hashes_and_operation_metadata() {
        let root = tempdir().unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let identity = OperationIdentity::for_request(
            OPERATION_ID,
            "https://secret-hospital.example",
            &request(7),
        )
        .unwrap();
        let ledger = InvocationLedger::open(root.path(), now).unwrap();
        ledger.begin(&identity, now).unwrap();
        drop(ledger);
        let journal = fs::read_to_string(root.path().join(JOURNAL_FILE)).unwrap();

        assert!(journal.contains(OPERATION_ID));
        assert!(!journal.contains("secret-hospital"));
        assert!(!journal.contains("printer"));
        assert!(!journal.contains("copies"));
    }

    #[test]
    fn ignores_only_a_partial_trailing_crash_record() {
        let root = tempdir().unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        fs::create_dir_all(root.path()).unwrap();
        fs::write(root.path().join(JOURNAL_FILE), b"{\"schemaVersion\":1").unwrap();

        let ledger = InvocationLedger::open(root.path(), now).unwrap();
        assert_eq!(ledger.operation_count(), 0);
    }

    #[test]
    fn rejects_noncanonical_or_nonrandom_operation_ids() {
        for invalid in [
            "123e4567-e89b-12d3-a456-426614174000",
            "123E4567-E89B-42D3-A456-426614174000",
            "not-a-uuid",
        ] {
            assert!(matches!(
                OperationIdentity::for_request(invalid, "https://business.example", &request(1)),
                Err(LedgerError::InvalidOperationId)
            ));
        }
    }

    #[test]
    fn retention_is_explicit_and_state_dependent() {
        let root = tempdir().unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let identity =
            OperationIdentity::for_request(OPERATION_ID, "https://business.example", &request(1))
                .unwrap();
        let ledger = InvocationLedger::open(root.path(), now).unwrap();
        ledger.begin(&identity, now).unwrap();
        let after_29_days = now + Duration::from_secs(29 * 24 * 60 * 60);
        assert_eq!(
            ledger.status(&identity.lookup(), after_29_days).unwrap(),
            DurableStatus::Indeterminate
        );
        let after_31_days = now + Duration::from_secs(31 * 24 * 60 * 60);
        assert_eq!(
            ledger.status(&identity.lookup(), after_31_days).unwrap(),
            DurableStatus::Unknown
        );
    }

    #[test]
    fn expired_identity_is_compacted_before_rebinding_and_survives_restart() {
        let root = tempdir().unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let first =
            OperationIdentity::for_request(OPERATION_ID, "https://business.example", &request(1))
                .unwrap();
        let second =
            OperationIdentity::for_request(OPERATION_ID, "https://business.example", &request(2))
                .unwrap();
        let later = now + COMPLETED_OPERATION_RETENTION + Duration::from_secs(1);
        {
            let ledger = InvocationLedger::open(root.path(), now).unwrap();
            ledger.begin(&first, now).unwrap();
            ledger.complete(&first, now).unwrap();
            assert_eq!(
                ledger.begin(&second, later).unwrap(),
                BeginDecision::Started
            );
        }

        let recovered = InvocationLedger::open(root.path(), later).unwrap();
        assert_eq!(
            recovered.begin(&second, later).unwrap(),
            BeginDecision::Indeterminate
        );
    }

    #[test]
    fn capacity_is_isolated_per_authorized_origin_scope() {
        let scope_error = ensure_capacity(100, MAX_DURABLE_OPERATIONS_PER_SCOPE).unwrap_err();
        assert!(matches!(
            scope_error,
            LedgerError::ScopeCapacity(MAX_DURABLE_OPERATIONS_PER_SCOPE)
        ));
        assert_eq!(
            scope_error.diagnostic_code(),
            "operation-ledger-scope-capacity"
        );

        let global_error = ensure_capacity(MAX_DURABLE_OPERATIONS, 0).unwrap_err();
        assert!(matches!(
            global_error,
            LedgerError::Capacity(MAX_DURABLE_OPERATIONS)
        ));
        assert_eq!(global_error.diagnostic_code(), "operation-ledger-capacity");

        let root = tempdir().unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let identity =
            OperationIdentity::for_request(OPERATION_ID, "https://business.example", &request(1))
                .unwrap();
        let ledger = InvocationLedger::open(root.path(), now).unwrap();
        ledger
            .inner
            .lock()
            .unwrap_or_else(|lock| lock.into_inner())
            .scope_counts
            .insert(
                identity.scope_hash.clone(),
                MAX_DURABLE_OPERATIONS_PER_SCOPE,
            );
        let error = ledger.begin(&identity, now).unwrap_err();
        assert!(matches!(
            error,
            LedgerError::ScopeCapacity(MAX_DURABLE_OPERATIONS_PER_SCOPE)
        ));
        assert_eq!(ledger.operation_count(), 0);
        assert!(fs::read(root.path().join(JOURNAL_FILE)).unwrap().is_empty());
    }

    #[test]
    fn expiration_maintenance_tracks_the_next_deadline_and_rebuilds_scope_counts() {
        let root = tempdir().unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let completed_at = now + Duration::from_secs(60);
        let identity =
            OperationIdentity::for_request(OPERATION_ID, "https://business.example", &request(1))
                .unwrap();
        let ledger = InvocationLedger::open(root.path(), now).unwrap();
        assert_eq!(
            ledger
                .inner
                .lock()
                .unwrap_or_else(|lock| lock.into_inner())
                .next_prune_at_unix_ms,
            u64::MAX
        );

        ledger.begin(&identity, now).unwrap();
        {
            let inner = ledger.inner.lock().unwrap_or_else(|lock| lock.into_inner());
            assert_eq!(inner.scope_counts.get(&identity.scope_hash), Some(&1));
            assert_eq!(
                inner.next_prune_at_unix_ms,
                unix_millis(now).unwrap()
                    + INDETERMINATE_OPERATION_RETENTION.as_millis() as u64
                    + 1
            );
        }

        ledger.complete(&identity, completed_at).unwrap();
        let completed_expiration = unix_millis(completed_at).unwrap()
            + COMPLETED_OPERATION_RETENTION.as_millis() as u64
            + 1;
        assert_eq!(
            ledger
                .inner
                .lock()
                .unwrap_or_else(|lock| lock.into_inner())
                .next_prune_at_unix_ms,
            completed_expiration
        );
        assert_eq!(
            ledger
                .status(
                    &identity.lookup(),
                    completed_at + COMPLETED_OPERATION_RETENTION,
                )
                .unwrap(),
            DurableStatus::CompletedWithoutResult
        );
        assert_eq!(
            ledger
                .status(
                    &identity.lookup(),
                    completed_at + COMPLETED_OPERATION_RETENTION + Duration::from_millis(1),
                )
                .unwrap(),
            DurableStatus::Unknown
        );
        let inner = ledger.inner.lock().unwrap_or_else(|lock| lock.into_inner());
        assert!(inner.scope_counts.is_empty());
        assert_eq!(inner.next_prune_at_unix_ms, u64::MAX);
    }
}
