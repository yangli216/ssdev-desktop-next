use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tempfile::NamedTempFile;
use thiserror::Error;
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::Layer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::Registry;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const LOG_FILE_NAME: &str = "ssdev.log";
const DEFAULT_MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;
const DEFAULT_BACKUP_FILES: usize = 5;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_EXPORT_BYTES: u64 = 32 * 1024 * 1024;
const OVERSIZED_EVENT: &[u8] =
    b"{\"level\":\"WARN\",\"event_code\":\"diagnostic-event-oversized\"}\n";

#[derive(Clone)]
pub struct DiagnosticsState {
    log_dir: PathBuf,
    shared: Arc<WriterShared>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsStats {
    pub log_files: usize,
    pub log_bytes: u64,
    pub oversized_events: u64,
    pub write_failures: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticContext {
    pub app_version: String,
    pub os: String,
    pub architecture: String,
    pub protocol_version: u16,
    pub plugin_host_protocol_version: u16,
    pub service_count: usize,
    pub plugin_count: usize,
    pub quarantined_plugin_count: usize,
    pub recovered_plugin_transaction_count: usize,
    pub preflighted_plugin_host_count: usize,
    pub plugin_preflight_failure_count: usize,
    pub trust_key_count: usize,
    pub active_trust_key_count: usize,
    pub retired_trust_key_count: usize,
    pub revoked_trust_key_count: usize,
    pub process_policy_entries: usize,
    pub managed_process_failures: usize,
    pub origin_policy_enforced: bool,
    pub business_origin_count: usize,
    pub business_window_count: usize,
    pub business_loading_window_count: usize,
    pub business_navigating_window_count: usize,
    pub business_ready_window_count: usize,
    pub business_timed_out_window_count: usize,
    pub business_frontend_timeout_count: u64,
    pub business_frontend_recovery_count: u64,
    pub origin_service_grant_count: usize,
    pub origin_method_grant_count: usize,
    pub max_in_flight_invocations: usize,
    pub in_flight_invocations: usize,
    pub rejected_invocations: u64,
    pub caller_detachment_count: u64,
    pub shutdown_rejected_invocation_count: u64,
    pub execution_lane_timeout_count: u64,
    pub maintenance_rejected_invocation_count: u64,
    pub plugin_maintenance_active: bool,
    pub global_plugin_maintenance_active: bool,
    pub active_plugin_maintenance_count: usize,
    pub accepting_plugin_invocations: bool,
    pub tracked_invocations_available: bool,
    pub tracked_invocations_accepting: bool,
    pub tracked_invocations_error: Option<String>,
    pub tracked_runtime_operation_count: usize,
    pub tracked_pending_operation_count: usize,
    pub tracked_retained_result_count: usize,
    pub tracked_durable_operation_count: usize,
    pub tracked_persistence_failure_count: u64,
    pub active_plugin_host_count: usize,
    pub plugin_host_start_count: u64,
    pub plugin_host_start_failure_count: u64,
    pub navigation_origin_count: usize,
    pub external_origin_count: usize,
    pub insecure_http_allowed: bool,
    pub app_update_configured: bool,
    pub auto_start_enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticManifest<'a> {
    schema_version: u8,
    generated_at_unix_ms: u128,
    #[serde(flatten)]
    context: &'a DiagnosticContext,
    diagnostics: DiagnosticsStats,
}

impl DiagnosticsState {
    pub fn initialize(log_dir: &Path) -> Result<Self, DiagnosticsError> {
        Self::initialize_with_limits(log_dir, DEFAULT_MAX_FILE_BYTES, DEFAULT_BACKUP_FILES)
    }

    fn initialize_with_limits(
        log_dir: &Path,
        max_file_bytes: u64,
        backup_files: usize,
    ) -> Result<Self, DiagnosticsError> {
        fs::create_dir_all(log_dir).map_err(|source| DiagnosticsError::Io {
            operation: "create-log-directory",
            source,
        })?;
        let shared = Arc::new(WriterShared {
            state: Mutex::new(LogState::open(
                log_dir.to_path_buf(),
                max_file_bytes,
                backup_files,
            )?),
            oversized_events: AtomicU64::new(0),
            write_failures: AtomicU64::new(0),
        });
        let writer = RotatingMakeWriter {
            shared: Arc::clone(&shared),
        };
        tracing_subscriber::registry()
            .with(diagnostics_layer(writer))
            .try_init()
            .map_err(|_| DiagnosticsError::SubscriberUnavailable)?;
        Ok(Self {
            log_dir: log_dir.to_path_buf(),
            shared,
        })
    }

    pub fn stats(&self) -> DiagnosticsStats {
        let mut log_files = 0;
        let mut log_bytes = 0_u64;
        for index in 0..=DEFAULT_BACKUP_FILES {
            let path = log_path(&self.log_dir, index);
            if let Ok(metadata) = fs::metadata(path) {
                if metadata.is_file() {
                    log_files += 1;
                    log_bytes = log_bytes.saturating_add(metadata.len());
                }
            }
        }
        DiagnosticsStats {
            log_files,
            log_bytes,
            oversized_events: self.shared.oversized_events.load(Ordering::Relaxed),
            write_failures: self.shared.write_failures.load(Ordering::Relaxed),
        }
    }

    pub fn export(
        &self,
        destination: &Path,
        context: &DiagnosticContext,
    ) -> Result<u64, DiagnosticsError> {
        if !destination.is_absolute()
            || destination.extension().and_then(|value| value.to_str()) != Some("zip")
        {
            return Err(DiagnosticsError::InvalidDestination);
        }
        if destination.exists() {
            return Err(DiagnosticsError::DestinationExists);
        }
        let parent = destination
            .parent()
            .filter(|path| path.is_dir())
            .ok_or(DiagnosticsError::InvalidDestination)?;
        let temporary = NamedTempFile::new_in(parent).map_err(|source| DiagnosticsError::Io {
            operation: "create-export",
            source,
        })?;
        let mut zip = ZipWriter::new(temporary);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o600);
        let manifest = DiagnosticManifest {
            schema_version: 1,
            generated_at_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            context,
            diagnostics: self.stats(),
        };
        let manifest = serde_json::to_vec_pretty(&manifest)?;
        zip.start_file("manifest.json", options)?;
        zip.write_all(&manifest)
            .map_err(|source| DiagnosticsError::Io {
                operation: "write-manifest",
                source,
            })?;

        let mut exported_bytes = manifest.len() as u64;
        for index in 0..=DEFAULT_BACKUP_FILES {
            let path = log_path(&self.log_dir, index);
            let Some(log) = open_bounded_log(&path)? else {
                continue;
            };
            let remaining = MAX_EXPORT_BYTES.saturating_sub(exported_bytes);
            if remaining == 0 {
                break;
            }
            let take = remaining.min(DEFAULT_MAX_FILE_BYTES);
            let mut bytes = Vec::with_capacity(take.min(1024 * 1024) as usize);
            log.take(take)
                .read_to_end(&mut bytes)
                .map_err(|source| DiagnosticsError::Io {
                    operation: "read-log",
                    source,
                })?;
            exported_bytes = exported_bytes.saturating_add(bytes.len() as u64);
            zip.start_file(format!("logs/{}", archive_log_name(index)), options)?;
            zip.write_all(&bytes)
                .map_err(|source| DiagnosticsError::Io {
                    operation: "write-log",
                    source,
                })?;
        }
        let temporary = zip.finish()?;
        temporary
            .persist_noclobber(destination)
            .map_err(|error| DiagnosticsError::Io {
                operation: "persist-export",
                source: error.error,
            })?;
        let size = fs::metadata(destination)
            .map_err(|source| DiagnosticsError::Io {
                operation: "inspect-export",
                source,
            })?
            .len();
        Ok(size)
    }
}

fn diagnostics_layer(writer: RotatingMakeWriter) -> impl Layer<Registry> + Send + Sync + 'static {
    let targets = Targets::new()
        .with_target("ssdev_desktop_core", Level::INFO)
        .with_target("ssdev_diagnostics", Level::INFO)
        .with_target("webplus_controller", Level::INFO)
        .with_target("webplus_plugin_package", Level::INFO);
    tracing_subscriber::fmt::layer()
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_target(false)
        .with_writer(writer)
        .with_filter(targets)
}

fn open_bounded_log(path: &Path) -> Result<Option<File>, DiagnosticsError> {
    ensure_regular_file_or_missing(path)?;
    match File::open(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(DiagnosticsError::Io {
            operation: "open-log",
            source,
        }),
    }
}

fn ensure_regular_file_or_missing(path: &Path) -> Result<(), DiagnosticsError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(DiagnosticsError::UnsafeLogEntry),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(DiagnosticsError::Io {
            operation: "inspect-log-entry",
            source,
        }),
    }
}

fn archive_log_name(index: usize) -> String {
    if index == 0 {
        LOG_FILE_NAME.into()
    } else {
        format!("{LOG_FILE_NAME}.{index}")
    }
}

fn log_path(log_dir: &Path, index: usize) -> PathBuf {
    log_dir.join(archive_log_name(index))
}

struct WriterShared {
    state: Mutex<LogState>,
    oversized_events: AtomicU64,
    write_failures: AtomicU64,
}

#[derive(Clone)]
struct RotatingMakeWriter {
    shared: Arc<WriterShared>,
}

impl<'a> MakeWriter<'a> for RotatingMakeWriter {
    type Writer = EventBuffer;

    fn make_writer(&'a self) -> Self::Writer {
        EventBuffer {
            shared: Arc::clone(&self.shared),
            bytes: Vec::with_capacity(512),
            oversized: false,
        }
    }
}

struct EventBuffer {
    shared: Arc<WriterShared>,
    bytes: Vec<u8>,
    oversized: bool,
}

impl Write for EventBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > MAX_EVENT_BYTES {
            self.oversized = true;
        } else if !self.oversized {
            self.bytes.extend_from_slice(bytes);
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for EventBuffer {
    fn drop(&mut self) {
        let bytes = if self.oversized {
            self.shared.oversized_events.fetch_add(1, Ordering::Relaxed);
            OVERSIZED_EVENT
        } else {
            &self.bytes
        };
        if bytes.is_empty() {
            return;
        }
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.append_event(bytes).is_err() {
            self.shared.write_failures.fetch_add(1, Ordering::Relaxed);
        }
    }
}

struct LogState {
    log_dir: PathBuf,
    file: Option<File>,
    current_bytes: u64,
    max_file_bytes: u64,
    backup_files: usize,
}

impl LogState {
    fn open(
        log_dir: PathBuf,
        max_file_bytes: u64,
        backup_files: usize,
    ) -> Result<Self, DiagnosticsError> {
        if max_file_bytes < 1024 || backup_files == 0 || backup_files > 20 {
            return Err(DiagnosticsError::InvalidLimits);
        }
        let path = log_path(&log_dir, 0);
        ensure_regular_file_or_missing(&path)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|source| DiagnosticsError::Io {
                operation: "open-current-log",
                source,
            })?;
        let current_bytes = file
            .metadata()
            .map_err(|source| DiagnosticsError::Io {
                operation: "inspect-current-log",
                source,
            })?
            .len();
        let mut state = Self {
            log_dir,
            file: Some(file),
            current_bytes,
            max_file_bytes,
            backup_files,
        };
        if state.current_bytes >= state.max_file_bytes {
            state.rotate()?;
        }
        Ok(state)
    }

    fn append_event(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.current_bytes > 0
            && self.current_bytes.saturating_add(bytes.len() as u64) > self.max_file_bytes
        {
            self.rotate_io()?;
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("current diagnostics log is not open"))?;
        file.write_all(bytes)?;
        file.flush()?;
        self.current_bytes = self.current_bytes.saturating_add(bytes.len() as u64);
        Ok(())
    }

    fn rotate(&mut self) -> Result<(), DiagnosticsError> {
        self.rotate_io().map_err(|source| DiagnosticsError::Io {
            operation: "rotate-log",
            source,
        })
    }

    fn rotate_io(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush()?;
            drop(file);
        }
        let oldest = log_path(&self.log_dir, self.backup_files);
        match fs::remove_file(oldest) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        for index in (1..self.backup_files).rev() {
            let source = log_path(&self.log_dir, index);
            let destination = log_path(&self.log_dir, index + 1);
            match fs::rename(source, destination) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        let current = log_path(&self.log_dir, 0);
        let first = log_path(&self.log_dir, 1);
        match fs::rename(&current, first) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        self.file = Some(OpenOptions::new().create(true).append(true).open(current)?);
        self.current_bytes = 0;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum DiagnosticsError {
    #[error("diagnostics I/O operation [{operation}] failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("diagnostics subscriber is already installed")]
    SubscriberUnavailable,
    #[error("diagnostics log limits are invalid")]
    InvalidLimits,
    #[error("diagnostics log entry is not a regular file")]
    UnsafeLogEntry,
    #[error("diagnostics export destination must be a new absolute .zip path")]
    InvalidDestination,
    #[error("diagnostics export destination already exists")]
    DestinationExists,
    #[error("diagnostics JSON encoding failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("diagnostics ZIP encoding failed: {0}")]
    Zip(#[from] zip::result::ZipError),
}

impl DiagnosticsError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "diagnostics-io-failure",
            Self::SubscriberUnavailable => "diagnostics-subscriber-unavailable",
            Self::InvalidLimits => "diagnostics-invalid-limits",
            Self::UnsafeLogEntry => "diagnostics-unsafe-log-entry",
            Self::InvalidDestination => "diagnostics-invalid-destination",
            Self::DestinationExists => "diagnostics-destination-exists",
            Self::Json(_) => "diagnostics-json-failure",
            Self::Zip(_) => "diagnostics-zip-failure",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use tempfile::tempdir;
    use tracing_subscriber::prelude::*;
    use zip::ZipArchive;

    use super::*;

    fn context() -> DiagnosticContext {
        DiagnosticContext {
            app_version: "1.2.3".into(),
            os: "windows".into(),
            architecture: "x86_64".into(),
            protocol_version: 1,
            plugin_host_protocol_version: 1,
            service_count: 3,
            plugin_count: 2,
            quarantined_plugin_count: 1,
            recovered_plugin_transaction_count: 2,
            preflighted_plugin_host_count: 5,
            plugin_preflight_failure_count: 1,
            trust_key_count: 4,
            active_trust_key_count: 2,
            retired_trust_key_count: 1,
            revoked_trust_key_count: 1,
            process_policy_entries: 1,
            managed_process_failures: 0,
            origin_policy_enforced: true,
            business_origin_count: 2,
            business_window_count: 2,
            business_loading_window_count: 0,
            business_navigating_window_count: 0,
            business_ready_window_count: 2,
            business_timed_out_window_count: 0,
            business_frontend_timeout_count: 1,
            business_frontend_recovery_count: 1,
            origin_service_grant_count: 4,
            origin_method_grant_count: 8,
            max_in_flight_invocations: 8,
            in_flight_invocations: 2,
            rejected_invocations: 3,
            caller_detachment_count: 4,
            shutdown_rejected_invocation_count: 5,
            execution_lane_timeout_count: 6,
            maintenance_rejected_invocation_count: 7,
            plugin_maintenance_active: false,
            global_plugin_maintenance_active: false,
            active_plugin_maintenance_count: 0,
            accepting_plugin_invocations: true,
            tracked_invocations_available: true,
            tracked_invocations_accepting: true,
            tracked_invocations_error: None,
            tracked_runtime_operation_count: 3,
            tracked_pending_operation_count: 1,
            tracked_retained_result_count: 2,
            tracked_durable_operation_count: 9,
            tracked_persistence_failure_count: 0,
            active_plugin_host_count: 2,
            plugin_host_start_count: 7,
            plugin_host_start_failure_count: 1,
            navigation_origin_count: 1,
            external_origin_count: 1,
            insecure_http_allowed: false,
            app_update_configured: true,
            auto_start_enabled: Some(false),
        }
    }

    #[test]
    fn rotation_keeps_whole_events_and_a_fixed_file_count() {
        let root = tempdir().unwrap();
        let shared = Arc::new(WriterShared {
            state: Mutex::new(LogState::open(root.path().to_path_buf(), 1024, 2).unwrap()),
            oversized_events: AtomicU64::new(0),
            write_failures: AtomicU64::new(0),
        });
        let writer = RotatingMakeWriter {
            shared: Arc::clone(&shared),
        };
        for index in 0..20 {
            let mut event = writer.make_writer();
            writeln!(
                event,
                "{{\"event_code\":\"test-{index}\",\"padding\":\"{}\"}}",
                "x".repeat(160)
            )
            .unwrap();
        }
        let files = fs::read_dir(root.path()).unwrap().count();
        assert!(files <= 3);
        assert_eq!(shared.write_failures.load(Ordering::Relaxed), 0);
        for entry in fs::read_dir(root.path()).unwrap() {
            let text = fs::read_to_string(entry.unwrap().path()).unwrap();
            for line in text.lines() {
                serde_json::from_str::<serde_json::Value>(line).unwrap();
            }
        }
    }

    #[test]
    fn subscriber_writes_only_allowed_info_events() {
        let root = tempdir().unwrap();
        let shared = Arc::new(WriterShared {
            state: Mutex::new(LogState::open(root.path().to_path_buf(), 4096, 2).unwrap()),
            oversized_events: AtomicU64::new(0),
            write_failures: AtomicU64::new(0),
        });
        let writer = RotatingMakeWriter {
            shared: Arc::clone(&shared),
        };
        let subscriber = tracing_subscriber::registry().with(diagnostics_layer(writer));

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                event_code = "safe-test-event",
                plugin_count = 2,
                "diagnostic-event"
            );
            tracing::debug!(event_code = "debug-event", "diagnostic-event");
            tracing::info!(
                target: "untrusted_dependency",
                event_code = "dependency-event",
                "diagnostic-event"
            );
        });

        let text = fs::read_to_string(log_path(root.path(), 0)).unwrap();
        let events = text
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event_code"], "safe-test-event");
        assert_eq!(events[0]["plugin_count"], 2);
        assert!(!text.contains("debug-event"));
        assert!(!text.contains("dependency-event"));
    }

    #[test]
    fn exported_bundle_contains_only_bounded_logs_and_safe_manifest_fields() {
        let root = tempdir().unwrap();
        let log_dir = root.path().join("logs");
        fs::create_dir(&log_dir).unwrap();
        fs::write(
            log_dir.join(LOG_FILE_NAME),
            b"{\"event_code\":\"app-started\"}\n",
        )
        .unwrap();
        let shared = Arc::new(WriterShared {
            state: Mutex::new(
                LogState::open(
                    log_dir.clone(),
                    DEFAULT_MAX_FILE_BYTES,
                    DEFAULT_BACKUP_FILES,
                )
                .unwrap(),
            ),
            oversized_events: AtomicU64::new(0),
            write_failures: AtomicU64::new(0),
        });
        let state = DiagnosticsState { log_dir, shared };
        let destination = root.path().join("support.zip");
        state.export(&destination, &context()).unwrap();

        let mut archive = ZipArchive::new(File::open(destination).unwrap()).unwrap();
        assert_eq!(archive.len(), 2);
        let mut manifest = String::new();
        archive
            .by_name("manifest.json")
            .unwrap()
            .read_to_string(&mut manifest)
            .unwrap();
        for forbidden in [
            "tenant",
            "businessUrl",
            "parameters",
            "resData",
            "operationId",
            "username",
            "absolutePath",
        ] {
            assert!(!manifest.contains(forbidden));
        }
        assert!(manifest.contains("\"serviceCount\": 3"));
        assert!(manifest.contains("\"protocolVersion\": 1"));
        assert!(manifest.contains("\"pluginHostProtocolVersion\": 1"));
        assert!(manifest.contains("\"originServiceGrantCount\": 4"));
        assert!(manifest.contains("\"originMethodGrantCount\": 8"));
        assert!(manifest.contains("\"maxInFlightInvocations\": 8"));
        assert!(manifest.contains("\"inFlightInvocations\": 2"));
        assert!(manifest.contains("\"rejectedInvocations\": 3"));
        assert!(manifest.contains("\"callerDetachmentCount\": 4"));
        assert!(manifest.contains("\"shutdownRejectedInvocationCount\": 5"));
        assert!(manifest.contains("\"executionLaneTimeoutCount\": 6"));
        assert!(manifest.contains("\"maintenanceRejectedInvocationCount\": 7"));
        assert!(manifest.contains("\"pluginMaintenanceActive\": false"));
        assert!(manifest.contains("\"globalPluginMaintenanceActive\": false"));
        assert!(manifest.contains("\"activePluginMaintenanceCount\": 0"));
        assert!(manifest.contains("\"trackedInvocationsAvailable\": true"));
        assert!(manifest.contains("\"trackedInvocationsAccepting\": true"));
        assert!(manifest.contains("\"trackedDurableOperationCount\": 9"));
        assert!(manifest.contains("\"trackedPersistenceFailureCount\": 0"));
        assert!(manifest.contains("\"acceptingPluginInvocations\": true"));
        assert!(manifest.contains("\"activePluginHostCount\": 2"));
        assert!(manifest.contains("\"pluginHostStartCount\": 7"));
        assert!(manifest.contains("\"pluginHostStartFailureCount\": 1"));
        assert!(manifest.contains("\"recoveredPluginTransactionCount\": 2"));
        assert!(manifest.contains("\"preflightedPluginHostCount\": 5"));
        assert!(manifest.contains("\"pluginPreflightFailureCount\": 1"));
        assert!(archive.by_name("logs/ssdev.log").is_ok());
    }

    #[test]
    fn export_refuses_relative_or_existing_destinations() {
        let root = tempdir().unwrap();
        let shared = Arc::new(WriterShared {
            state: Mutex::new(
                LogState::open(
                    root.path().to_path_buf(),
                    DEFAULT_MAX_FILE_BYTES,
                    DEFAULT_BACKUP_FILES,
                )
                .unwrap(),
            ),
            oversized_events: AtomicU64::new(0),
            write_failures: AtomicU64::new(0),
        });
        let state = DiagnosticsState {
            log_dir: root.path().to_path_buf(),
            shared,
        };
        assert!(matches!(
            state.export(Path::new("relative.zip"), &context()),
            Err(DiagnosticsError::InvalidDestination)
        ));
        let existing = root.path().join("existing.zip");
        fs::write(&existing, b"keep").unwrap();
        assert!(matches!(
            state.export(&existing, &context()),
            Err(DiagnosticsError::DestinationExists)
        ));
        assert_eq!(fs::read(existing).unwrap(), b"keep");
    }

    #[cfg(unix)]
    #[test]
    fn export_refuses_symbolic_link_log_entries() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let log_dir = root.path().join("logs");
        fs::create_dir(&log_dir).unwrap();
        let private_file = root.path().join("private.txt");
        fs::write(&private_file, b"must-not-be-exported").unwrap();
        symlink(&private_file, log_dir.join(format!("{LOG_FILE_NAME}.1"))).unwrap();
        let shared = Arc::new(WriterShared {
            state: Mutex::new(
                LogState::open(
                    log_dir.clone(),
                    DEFAULT_MAX_FILE_BYTES,
                    DEFAULT_BACKUP_FILES,
                )
                .unwrap(),
            ),
            oversized_events: AtomicU64::new(0),
            write_failures: AtomicU64::new(0),
        });
        let state = DiagnosticsState { log_dir, shared };
        let destination = root.path().join("support.zip");

        assert!(matches!(
            state.export(&destination, &context()),
            Err(DiagnosticsError::UnsafeLogEntry)
        ));
        assert!(!destination.exists());
    }

    #[test]
    fn production_tracing_events_do_not_record_sensitive_runtime_values() {
        let sources = [
            include_str!("../../../apps/desktop/src-tauri/src/lib.rs"),
            include_str!("../../../apps/desktop/src-tauri/src/app_update.rs"),
            include_str!("../../../apps/desktop/src-tauri/src/capture.rs"),
            include_str!("../../../apps/desktop/src-tauri/src/desktop.rs"),
            include_str!("../../../apps/desktop/src-tauri/src/shortcuts.rs"),
            include_str!("../../../apps/desktop/src-tauri/src/sso.rs"),
            include_str!("../../webplus-controller/src/lib.rs"),
            include_str!("../../webplus-plugin-package/src/lib.rs"),
        ];
        let forbidden = [
            "%error",
            "?error",
            "parameters =",
            "res_data =",
            "request =",
            "response =",
            "website =",
            "tenant =",
            "path =",
            "executable =",
            "url =",
            "arguments =",
            "payload =",
        ];
        for source in sources {
            for block in tracing_macro_blocks(source) {
                for token in forbidden {
                    assert!(
                        !block.contains(token),
                        "diagnostic tracing event contains forbidden token [{token}]: {block}"
                    );
                }
            }
        }
    }

    fn tracing_macro_blocks(source: &str) -> Vec<&str> {
        let mut blocks = Vec::new();
        let mut remaining = source;
        while let Some(start) = [
            "tracing::info!(",
            "tracing::warn!(",
            "tracing::error!(",
            "info!(",
            "warn!(",
            "error!(",
        ]
        .iter()
        .filter_map(|needle| remaining.find(needle))
        .min()
        {
            let candidate = &remaining[start..];
            let Some(end) = candidate.find(");") else {
                break;
            };
            blocks.push(&candidate[..end + 2]);
            remaining = &candidate[end + 2..];
        }
        blocks
    }
}
