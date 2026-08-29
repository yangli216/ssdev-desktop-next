use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tempfile::NamedTempFile;
use thiserror::Error;
use url::Url;

const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(default)]
    pub environments: Vec<EnvironmentConfig>,
    #[serde(default = "default_true")]
    pub allow_switch: bool,
    #[serde(default)]
    pub auto_close: bool,
    #[serde(default)]
    pub auto_start: bool,
    #[serde(default)]
    pub tenant_id: String,
    /// Legacy Electron paths are retained for migration visibility but are never executed.
    #[serde(default)]
    pub processes: Vec<String>,
    /// IDs selected from the signed process policy bundled by the administrator.
    #[serde(default)]
    pub managed_processes: Vec<String>,
    #[serde(default = "default_key_bindings")]
    pub key_bindings: Vec<KeyBindingConfig>,
    /// Additional navigation origins needed by SSO or federated identity providers.
    #[serde(default)]
    pub trusted_origins: Vec<String>,
    /// Origins that business pages may deliberately open in the system browser.
    #[serde(default)]
    pub external_origins: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_catalog_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_catalog_signature_url: Option<String>,
    #[serde(default = "default_true")]
    pub feedback: bool,
    #[serde(flatten)]
    pub extensions: Map<String, Value>,
}

impl Default for DesktopConfig {
    fn default() -> Self {
        Self {
            website: None,
            environments: Vec::new(),
            allow_switch: true,
            auto_close: false,
            auto_start: false,
            tenant_id: String::new(),
            processes: Vec::new(),
            managed_processes: Vec::new(),
            key_bindings: default_key_bindings(),
            trusted_origins: Vec::new(),
            external_origins: Vec::new(),
            plugin_catalog_url: None,
            plugin_catalog_signature_url: None,
            feedback: true,
            extensions: Map::new(),
        }
    }
}

impl DesktopConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        let encoded = serde_json::to_vec(self).map_err(|error| {
            ConfigError::Validation(format!("desktop config cannot be encoded: {error}"))
        })?;
        if encoded.len() as u64 > MAX_CONFIG_FILE_BYTES {
            return Err(ConfigError::Validation(format!(
                "desktop config exceeds the {} byte limit",
                MAX_CONFIG_FILE_BYTES
            )));
        }
        if let Some(website) = self
            .website
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            parse_website(website)?;
        }
        if self.environments.len() > 32 {
            return Err(ConfigError::Validation(
                "at most 32 business environments are allowed".into(),
            ));
        }
        let mut names = BTreeSet::new();
        let mut urls = BTreeSet::new();
        for environment in &self.environments {
            if environment.name.trim().is_empty() || environment.name.chars().count() > 128 {
                return Err(ConfigError::Validation(
                    "environment name must contain 1 to 128 characters".into(),
                ));
            }
            if !names.insert(environment.name.trim().to_owned()) {
                return Err(ConfigError::Validation(format!(
                    "duplicate environment name [{}]",
                    environment.name
                )));
            }
            let url = parse_website(&environment.url)?;
            if !urls.insert(url.as_str().trim_end_matches('/').to_owned()) {
                return Err(ConfigError::Validation(format!(
                    "duplicate environment URL [{}]",
                    environment.url
                )));
            }
        }
        for origin in &self.trusted_origins {
            parse_website(origin)?;
        }
        for origin in &self.external_origins {
            parse_website(origin)?;
        }
        match (
            self.plugin_catalog_url.as_deref(),
            self.plugin_catalog_signature_url.as_deref(),
        ) {
            (None, None) => {}
            (Some(catalog), Some(signature)) => {
                parse_https_url(catalog)?;
                parse_https_url(signature)?;
            }
            _ => {
                return Err(ConfigError::Validation(
                    "plugin catalog URL and signature URL must be configured together".into(),
                ));
            }
        }
        if self.key_bindings.len() > 32 {
            return Err(ConfigError::Validation(
                "at most 32 desktop key bindings are allowed".into(),
            ));
        }
        let mut shortcuts = BTreeSet::new();
        for binding in &self.key_bindings {
            let shortcut = binding.shortcut.trim();
            if shortcut.is_empty()
                || shortcut.len() > 64
                || !shortcut.bytes().all(|byte| byte.is_ascii_graphic())
            {
                return Err(ConfigError::Validation(
                    "shortcuts must contain 1 to 64 printable ASCII characters without spaces"
                        .into(),
                ));
            }
            if binding.enabled && !shortcuts.insert(shortcut.to_ascii_lowercase()) {
                return Err(ConfigError::Validation(format!(
                    "duplicate desktop shortcut [{}]",
                    binding.shortcut
                )));
            }
        }
        if self.managed_processes.len() > 64 {
            return Err(ConfigError::Validation(
                "at most 64 managed processes may be selected".into(),
            ));
        }
        let mut processes = BTreeSet::new();
        for process_id in &self.managed_processes {
            if process_id.is_empty()
                || process_id.len() > 64
                || process_id.starts_with('.')
                || !process_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            {
                return Err(ConfigError::Validation(format!(
                    "managed process ID [{process_id}] is not portable"
                )));
            }
            if !processes.insert(process_id) {
                return Err(ConfigError::Validation(format!(
                    "duplicate managed process ID [{process_id}]"
                )));
            }
        }
        Ok(())
    }

    pub fn website_url(&self) -> Result<Option<Url>, ConfigError> {
        self.website
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(parse_website)
            .transpose()
    }

    pub fn environment_url(&self, requested_name: &str) -> Result<Option<Url>, ConfigError> {
        let requested_name = requested_name.trim();
        self.environments
            .iter()
            .find(|environment| environment.name.trim() == requested_name)
            .map(|environment| parse_website(&environment.url))
            .transpose()
    }

    pub fn business_origins(&self) -> Result<BTreeSet<String>, ConfigError> {
        let mut origins = BTreeSet::new();
        if let Some(url) = self.website_url()? {
            origins.insert(url.origin().ascii_serialization());
        }
        for environment in &self.environments {
            origins.insert(
                parse_website(&environment.url)?
                    .origin()
                    .ascii_serialization(),
            );
        }
        Ok(origins)
    }

    pub fn allowed_origins(&self) -> Result<BTreeSet<String>, ConfigError> {
        let mut origins = self.business_origins()?;
        for origin in &self.trusted_origins {
            origins.insert(parse_website(origin)?.origin().ascii_serialization());
        }
        Ok(origins)
    }

    pub fn external_url_origins(&self) -> Result<BTreeSet<String>, ConfigError> {
        let mut origins = self.business_origins()?;
        for origin in &self.external_origins {
            origins.insert(parse_website(origin)?.origin().ascii_serialization());
        }
        Ok(origins)
    }

    pub fn plugin_catalog_urls(&self) -> Result<Option<(Url, Url)>, ConfigError> {
        match (
            self.plugin_catalog_url.as_deref(),
            self.plugin_catalog_signature_url.as_deref(),
        ) {
            (Some(catalog), Some(signature)) => Ok(Some((
                parse_https_url(catalog)?,
                parse_https_url(signature)?,
            ))),
            (None, None) => Ok(None),
            _ => Err(ConfigError::Validation(
                "plugin catalog URL and signature URL must be configured together".into(),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DesktopAction {
    OpenBusinessWindow,
    CaptureBusinessWindow,
    CaptureRegion,
    ResetBusinessZoom,
    FindInBusinessWindow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyBindingConfig {
    pub shortcut: String,
    pub action: DesktopAction,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_key_bindings() -> Vec<KeyBindingConfig> {
    vec![
        KeyBindingConfig {
            shortcut: "control+shift+n".into(),
            action: DesktopAction::OpenBusinessWindow,
            enabled: true,
        },
        KeyBindingConfig {
            shortcut: "control+shift+c".into(),
            action: DesktopAction::CaptureBusinessWindow,
            enabled: true,
        },
        KeyBindingConfig {
            shortcut: "control+shift+a".into(),
            action: DesktopAction::CaptureRegion,
            enabled: true,
        },
        KeyBindingConfig {
            shortcut: "control+0".into(),
            action: DesktopAction::ResetBusinessZoom,
            enabled: true,
        },
        KeyBindingConfig {
            shortcut: "control+f".into(),
            action: DesktopAction::FindInBusinessWindow,
            enabled: true,
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentConfig {
    pub name: String,
    pub url: String,
    #[serde(flatten)]
    pub extensions: Map<String, Value>,
}

pub struct ConfigStore {
    path: PathBuf,
    value: RwLock<DesktopConfig>,
    migration_sources: Vec<PathBuf>,
    migration_warnings: Vec<String>,
}

impl ConfigStore {
    pub fn open(
        path: impl Into<PathBuf>,
        legacy_candidates: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Self, ConfigError> {
        let path = path.into();
        let (value, migration_sources, migration_warnings) = if path.is_file() {
            (load(&path)?, Vec::new(), Vec::new())
        } else {
            merge_legacy_sources(legacy_candidates)?
        };
        value.validate()?;
        persist(&path, &value)?;
        Ok(Self {
            path,
            value: RwLock::new(value),
            migration_sources,
            migration_warnings,
        })
    }

    pub fn snapshot(&self) -> DesktopConfig {
        self.value
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn replace(&self, value: DesktopConfig) -> Result<(), ConfigError> {
        value.validate()?;
        persist(&self.path, &value)?;
        *self
            .value
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn migrated_from(&self) -> Option<&Path> {
        self.migration_sources.first().map(PathBuf::as_path)
    }

    pub fn migration_sources(&self) -> &[PathBuf] {
        &self.migration_sources
    }

    pub fn migration_warnings(&self) -> &[String] {
        &self.migration_warnings
    }
}

pub fn parse_website(value: &str) -> Result<Url, ConfigError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ConfigError::Validation("website must not be empty".into()));
    }
    if value.len() > 4096 {
        return Err(ConfigError::Validation(
            "website URL must not exceed 4096 bytes".into(),
        ));
    }
    let normalized = if value.contains("://") {
        value.to_owned()
    } else {
        format!("http://{value}")
    };
    let url = Url::parse(&normalized)
        .map_err(|error| ConfigError::Validation(format!("invalid website [{value}]: {error}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ConfigError::Validation(format!(
            "website scheme [{}] is not allowed",
            url.scheme()
        )));
    }
    if url.host_str().is_none() {
        return Err(ConfigError::Validation(format!(
            "website [{value}] has no host"
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConfigError::Validation(
            "website credentials must not be embedded in the URL".into(),
        ));
    }
    Ok(url)
}

fn parse_https_url(value: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(value.trim()).map_err(|error| {
        ConfigError::Validation(format!("invalid HTTPS URL [{value}]: {error}"))
    })?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ConfigError::Validation(format!(
            "URL [{value}] must be absolute HTTPS without credentials or fragments"
        )));
    }
    Ok(url)
}

fn load(path: &Path) -> Result<DesktopConfig, ConfigError> {
    let bytes = read_bounded_regular_file(path)?;
    serde_json::from_slice(&bytes).map_err(|source| ConfigError::Json {
        path: path.to_path_buf(),
        source,
    })
}

pub fn load_config_file(path: &Path) -> Result<DesktopConfig, ConfigError> {
    let config = load(path)?;
    config.validate()?;
    Ok(config)
}

pub fn export_config_file(path: &Path, config: &DesktopConfig) -> Result<(), ConfigError> {
    config.validate()?;
    persist(path, config)
}

fn merge_legacy_sources(
    candidates: impl IntoIterator<Item = PathBuf>,
) -> Result<(DesktopConfig, Vec<PathBuf>, Vec<String>), ConfigError> {
    let mut seen = BTreeSet::new();
    let mut documents = Vec::new();
    let mut warnings = Vec::new();
    for path in candidates {
        let identity = path.to_string_lossy().to_lowercase();
        if !seen.insert(identity) || !path.is_file() {
            continue;
        }
        match load_object(&path) {
            Ok(document) => documents.push((path, document)),
            Err(error) => warnings.push(error.to_string()),
        }
    }
    if documents.is_empty() {
        return Ok((DesktopConfig::default(), Vec::new(), warnings));
    }

    // Candidates are ordered from highest to lowest precedence. Apply lower-priority
    // documents first so an explicitly present value in the preferred source wins.
    let mut merged = Map::new();
    for (_, document) in documents.iter().rev() {
        for (key, value) in document {
            merged.insert(key.clone(), value.clone());
        }
    }

    // Legacy process paths are never executed, but retaining the union makes the
    // later signed-policy conversion auditable instead of silently dropping entries.
    let mut process_paths = Vec::new();
    let mut seen_process_paths = BTreeSet::new();
    for (path, document) in &documents {
        let Some(value) = document.get("processes") else {
            continue;
        };
        let Some(items) = value.as_array() else {
            warnings.push(format!(
                "legacy config {path:?} has a non-array processes field"
            ));
            continue;
        };
        for item in items {
            let Some(item) = item.as_str() else {
                warnings.push(format!(
                    "legacy config {path:?} contains a non-string process path"
                ));
                continue;
            };
            let item = item.trim();
            if !item.is_empty() && seen_process_paths.insert(item.to_ascii_lowercase()) {
                process_paths.push(Value::String(item.to_owned()));
            }
        }
    }
    if !process_paths.is_empty() {
        merged.insert("processes".into(), Value::Array(process_paths));
    }

    let primary_path = documents[0].0.clone();
    let value =
        serde_json::from_value(Value::Object(merged)).map_err(|source| ConfigError::Json {
            path: primary_path,
            source,
        })?;
    let sources = documents.into_iter().map(|(path, _)| path).collect();
    Ok((value, sources, warnings))
}

fn load_object(path: &Path) -> Result<Map<String, Value>, ConfigError> {
    let bytes = read_bounded_regular_file(path)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|source| ConfigError::Json {
        path: path.to_path_buf(),
        source,
    })?;
    value.as_object().cloned().ok_or_else(|| {
        ConfigError::Validation(format!("legacy config {path:?} must contain a JSON object"))
    })
}

fn read_bounded_regular_file(path: &Path) -> Result<Vec<u8>, ConfigError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ConfigError::Validation(format!(
            "config path {path:?} must be a regular file and not a symbolic link"
        )));
    }
    if metadata.len() > MAX_CONFIG_FILE_BYTES {
        return Err(ConfigError::Validation(format!(
            "config file {path:?} exceeds the {} byte limit",
            MAX_CONFIG_FILE_BYTES
        )));
    }
    let bytes = fs::read(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if bytes.len() as u64 > MAX_CONFIG_FILE_BYTES {
        return Err(ConfigError::Validation(format!(
            "config file {path:?} changed while reading or exceeds the size limit"
        )));
    }
    Ok(bytes)
}

fn persist(path: &Path, value: &DesktopConfig) -> Result<(), ConfigError> {
    let parent = path
        .parent()
        .ok_or_else(|| ConfigError::Validation("config path has no parent".into()))?;
    fs::create_dir_all(parent).map_err(|source| ConfigError::Write {
        path: parent.to_path_buf(),
        source,
    })?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(|source| ConfigError::Write {
        path: parent.to_path_buf(),
        source,
    })?;
    serde_json::to_writer_pretty(&mut temporary, value).map_err(|source| ConfigError::Json {
        path: path.to_path_buf(),
        source,
    })?;
    temporary
        .write_all(b"\n")
        .map_err(|source| ConfigError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| ConfigError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    temporary
        .persist(path)
        .map_err(|error| ConfigError::Write {
            path: path.to_path_buf(),
            source: error.error,
        })?;
    Ok(())
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config {path:?}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write config {path:?}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid config JSON at {path:?}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid desktop config: {0}")]
    Validation(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn migrates_legacy_config_and_preserves_unknown_fields() {
        let directory = tempdir().unwrap();
        let legacy = directory.path().join("legacy.json");
        let target = directory.path().join("next/config.json");
        fs::write(
            &legacy,
            serde_json::to_vec(&json!({
                "website": "intranet.example.test/app",
                "tenantId": "hospital-a",
                "customFlag": 7
            }))
            .unwrap(),
        )
        .unwrap();

        let store = ConfigStore::open(&target, [legacy.clone()]).unwrap();

        assert_eq!(store.migrated_from(), Some(legacy.as_path()));
        assert_eq!(store.snapshot().tenant_id, "hospital-a");
        assert_eq!(store.snapshot().extensions["customFlag"], 7);
        assert!(target.is_file());
    }

    #[test]
    fn merges_all_legacy_sources_without_losing_process_inventory() {
        let directory = tempdir().unwrap();
        let preferred = directory.path().join("portable.json");
        let electron_store = directory.path().join("electron-store.json");
        let malformed = directory.path().join("malformed.json");
        let target = directory.path().join("next/config.json");
        fs::write(
            &preferred,
            serde_json::to_vec(&json!({
                "website": "https://preferred.example.test/app",
                "allowSwitch": false,
                "processes": ["C:\\Preferred\\helper.exe"],
                "preferredOnly": true
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            &electron_store,
            serde_json::to_vec(&json!({
                "website": "https://lower.example.test/app",
                "tenantId": "hospital-a",
                "processes": [
                    "C:\\Lower\\reader.exe",
                    "c:\\preferred\\HELPER.exe"
                ],
                "lowerOnly": 9
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(&malformed, b"not-json").unwrap();

        let store = ConfigStore::open(
            &target,
            [preferred.clone(), electron_store.clone(), malformed],
        )
        .unwrap();
        let config = store.snapshot();

        assert_eq!(
            config.website.as_deref(),
            Some("https://preferred.example.test/app")
        );
        assert!(!config.allow_switch);
        assert_eq!(config.tenant_id, "hospital-a");
        assert_eq!(config.processes.len(), 2);
        assert_eq!(config.extensions["preferredOnly"], true);
        assert_eq!(config.extensions["lowerOnly"], 9);
        assert_eq!(store.migration_sources(), &[preferred, electron_store]);
        assert_eq!(store.migration_warnings().len(), 1);
    }

    #[test]
    fn rejects_non_web_and_credential_urls() {
        assert!(parse_website("file:///etc/passwd").is_err());
        assert!(parse_website("https://user:secret@example.test").is_err());
        assert!(parse_website("example.test").is_ok());

        let mut config = DesktopConfig {
            plugin_catalog_url: Some("http://plugins.example.test/catalog.json".into()),
            plugin_catalog_signature_url: Some(
                "https://plugins.example.test/catalog.sig.json".into(),
            ),
            ..DesktopConfig::default()
        };
        assert!(config.validate().is_err());
        config.plugin_catalog_url = Some("https://plugins.example.test/catalog.json".into());
        assert!(config.validate().is_ok());
        config.plugin_catalog_signature_url = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn duplicate_environment_urls_are_rejected() {
        let config = DesktopConfig {
            environments: vec![
                EnvironmentConfig {
                    name: "A".into(),
                    url: "https://example.test/a".into(),
                    extensions: Map::new(),
                },
                EnvironmentConfig {
                    name: "B".into(),
                    url: "https://example.test/a".into(),
                    extensions: Map::new(),
                },
            ],
            ..DesktopConfig::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn environment_count_and_name_length_are_bounded() {
        let environment = |index: usize| EnvironmentConfig {
            name: format!("environment-{index}"),
            url: format!("https://environment-{index}.example.test"),
            extensions: Map::new(),
        };
        let too_many = DesktopConfig {
            environments: (0..33).map(environment).collect(),
            ..DesktopConfig::default()
        };
        assert!(too_many.validate().is_err());

        let long_name = DesktopConfig {
            environments: vec![EnvironmentConfig {
                name: "环".repeat(129),
                url: "https://example.test".into(),
                extensions: Map::new(),
            }],
            ..DesktopConfig::default()
        };
        assert!(long_name.validate().is_err());
    }

    #[test]
    fn named_environment_lookup_uses_the_same_url_normalization_as_validation() {
        let config = DesktopConfig {
            environments: vec![EnvironmentConfig {
                name: " 内网 ".into(),
                url: "example.test/app".into(),
                extensions: Map::new(),
            }],
            ..DesktopConfig::default()
        };

        assert_eq!(
            config.environment_url("内网").unwrap().unwrap().as_str(),
            "http://example.test/app"
        );
        assert!(config.environment_url("不存在").unwrap().is_none());
    }

    #[test]
    fn config_file_import_is_bounded_and_export_is_round_trippable() {
        let directory = tempdir().unwrap();
        let exported = directory.path().join("exported.json");
        let config = DesktopConfig {
            website: Some("https://example.test/app".into()),
            tenant_id: "hospital-a".into(),
            ..DesktopConfig::default()
        };
        export_config_file(&exported, &config).unwrap();
        assert_eq!(load_config_file(&exported).unwrap(), config);

        let oversized = directory.path().join("oversized.json");
        fs::write(&oversized, vec![b' '; MAX_CONFIG_FILE_BYTES as usize + 1]).unwrap();
        assert!(load_config_file(&oversized).is_err());

        let mut oversized_config = DesktopConfig::default();
        oversized_config.extensions.insert(
            "large".into(),
            Value::String("x".repeat(MAX_CONFIG_FILE_BYTES as usize)),
        );
        assert!(oversized_config.validate().is_err());
    }

    #[test]
    fn sso_navigation_origins_do_not_become_business_origins() {
        let config = DesktopConfig {
            website: Some("https://business.example.test/app".into()),
            trusted_origins: vec!["https://sso.example.test/login".into()],
            ..DesktopConfig::default()
        };

        assert!(config
            .business_origins()
            .unwrap()
            .contains("https://business.example.test"));
        assert!(!config
            .business_origins()
            .unwrap()
            .contains("https://sso.example.test"));
        assert!(config
            .allowed_origins()
            .unwrap()
            .contains("https://sso.example.test"));
    }

    #[test]
    fn declarative_key_bindings_reject_duplicates_and_script_fields() {
        let mut duplicate = DesktopConfig::default();
        duplicate.key_bindings.push(KeyBindingConfig {
            shortcut: "CONTROL+SHIFT+N".into(),
            action: DesktopAction::FindInBusinessWindow,
            enabled: true,
        });
        assert!(duplicate.validate().is_err());

        let parsed = serde_json::from_value::<DesktopConfig>(json!({
            "keyBindings": [{
                "shortcut": "control+k",
                "action": "find-in-business-window",
                "enabled": true,
                "snippet": "dangerous()"
            }]
        }));
        assert!(parsed.is_err());

        let mut invalid_disabled = DesktopConfig::default();
        invalid_disabled.key_bindings.push(KeyBindingConfig {
            shortcut: "not a shortcut".into(),
            action: DesktopAction::OpenBusinessWindow,
            enabled: false,
        });
        assert!(invalid_disabled.validate().is_err());
    }
}
