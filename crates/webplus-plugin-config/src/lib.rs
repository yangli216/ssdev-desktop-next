use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use webplus_protocol::PluginArchitecture;

pub const API_FILENAME: &str = "api.json";
pub const PLUGIN_METADATA_FILENAME: &str = "plugin.json";
const MAX_API_BYTES: usize = 4 * 1024 * 1024;
const MAX_SERVICES: usize = 1024;
const MAX_METHODS_PER_SERVICE: usize = 1024;
const MAX_PARAMETERS_PER_METHOD: usize = 256;
const MAX_DEPENDENCIES_PER_SERVICE: usize = 256;

#[derive(Debug, Clone)]
pub struct PluginManifest {
    pub plugin_id: String,
    pub plugin_dir: PathBuf,
    pub metadata: Option<PluginMetadata>,
    pub services: Vec<ServiceDefinition>,
}

impl PluginManifest {
    pub fn load(
        plugin_id: impl Into<String>,
        plugin_dir: impl Into<PathBuf>,
    ) -> Result<Self, ConfigError> {
        let plugin_id = plugin_id.into();
        let plugin_dir = plugin_dir.into();
        let metadata = PluginMetadata::load_optional(&plugin_dir)?;
        if metadata
            .as_ref()
            .is_some_and(|metadata| metadata.plugin_id != plugin_id)
        {
            return Err(ConfigError::Validation(format!(
                "plugin metadata ID does not match directory ID [{plugin_id}]"
            )));
        }
        let api_path = plugin_dir.join(API_FILENAME);
        let bytes = fs::read(&api_path).map_err(|source| ConfigError::Read {
            path: api_path.clone(),
            source,
        })?;
        if bytes.len() > MAX_API_BYTES {
            return Err(ConfigError::TooLarge {
                path: api_path,
                actual: bytes.len(),
                limit: MAX_API_BYTES,
            });
        }
        let document: ApiDocument =
            serde_json::from_slice(&bytes).map_err(|source| ConfigError::Json {
                path: api_path,
                source,
            })?;
        let services = document.into_services();
        validate_manifest(&plugin_id, &services)?;
        Ok(Self {
            plugin_id,
            plugin_dir,
            metadata,
            services,
        })
    }

    pub fn service(&self, service_id: &str) -> Option<&ServiceDefinition> {
        self.services
            .iter()
            .find(|service| service.service_id == service_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginMetadata {
    pub schema_version: u8,
    pub plugin_id: String,
    pub version: semver::Version,
    #[serde(default)]
    pub display_name: String,
}

impl PluginMetadata {
    pub fn load_optional(plugin_dir: &Path) -> Result<Option<Self>, ConfigError> {
        let path = plugin_dir.join(PLUGIN_METADATA_FILENAME);
        if !path.is_file() {
            return Ok(None);
        }
        let bytes = fs::read(&path).map_err(|source| ConfigError::Read {
            path: path.clone(),
            source,
        })?;
        if bytes.len() > 64 * 1024 {
            return Err(ConfigError::TooLarge {
                path,
                actual: bytes.len(),
                limit: 64 * 1024,
            });
        }
        let metadata: Self =
            serde_json::from_slice(&bytes).map_err(|source| ConfigError::Json {
                path: path.clone(),
                source,
            })?;
        if metadata.schema_version != 1 {
            return Err(ConfigError::Validation(format!(
                "unsupported plugin metadata schema [{}]",
                metadata.schema_version
            )));
        }
        validate_plugin_id(&metadata.plugin_id)?;
        if metadata.display_name.chars().count() > 128 {
            return Err(ConfigError::Validation(
                "plugin display name must not exceed 128 characters".into(),
            ));
        }
        Ok(Some(metadata))
    }
}

#[derive(Debug, Default)]
pub struct DiscoveryReport {
    pub manifests: Vec<PluginManifest>,
    pub failures: Vec<PluginLoadFailure>,
}

#[derive(Debug)]
pub struct PluginLoadFailure {
    pub plugin_id: String,
    pub path: PathBuf,
    pub error: ConfigError,
}

pub fn discover_plugins(root: &Path) -> Result<DiscoveryReport, ConfigError> {
    let entries = fs::read_dir(root).map_err(|source| ConfigError::ReadDirectory {
        path: root.to_path_buf(),
        source,
    })?;
    let mut report = DiscoveryReport::default();
    for entry in entries {
        let entry = entry.map_err(|source| ConfigError::ReadDirectory {
            path: root.to_path_buf(),
            source,
        })?;
        let file_type = entry
            .file_type()
            .map_err(|source| ConfigError::ReadDirectory {
                path: entry.path(),
                source,
            })?;
        if !file_type.is_dir() {
            continue;
        }
        let plugin_id = entry.file_name().to_string_lossy().into_owned();
        if plugin_id.starts_with('.') {
            continue;
        }
        let path = entry.path();
        match PluginManifest::load(plugin_id.clone(), &path) {
            Ok(manifest) => report.manifests.push(manifest),
            Err(error) => report.failures.push(PluginLoadFailure {
                plugin_id,
                path,
                error,
            }),
        }
    }
    report
        .manifests
        .sort_by(|left, right| left.plugin_id.cmp(&right.plugin_id));
    report
        .failures
        .sort_by(|left, right| left.plugin_id.cmp(&right.plugin_id));
    Ok(report)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum ApiDocument {
    Many(Vec<ServiceDefinition>),
    One(Box<ServiceDefinition>),
}

impl ApiDocument {
    fn into_services(self) -> Vec<ServiceDefinition> {
        match self {
            Self::Many(services) => services,
            Self::One(service) => vec![*service],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDefinition {
    #[serde(rename = "serviceId")]
    pub service_id: String,
    #[serde(rename = "mainClass")]
    pub main_class: String,
    #[serde(rename = "mainType", default)]
    pub main_type: String,
    #[serde(default = "default_architecture", alias = "arch")]
    pub architecture: PluginArchitecture,
    #[serde(default)]
    pub charset: String,
    #[serde(rename = "callingConvention", default = "default_calling_convention")]
    pub calling_convention: String,
    #[serde(default)]
    pub cacheable: bool,
    #[serde(default)]
    pub timeout: u64,
    #[serde(default)]
    pub deps: Vec<String>,
    #[serde(default)]
    pub methods: Vec<MethodDefinition>,
    #[serde(flatten)]
    pub extensions: HashMap<String, Value>,
}

impl ServiceDefinition {
    pub fn resolved_main_type(&self) -> &str {
        if !self.main_type.trim().is_empty() {
            return self.main_type.trim();
        }
        Path::new(&self.main_class)
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("")
    }

    pub fn method(&self, requested_name: &str) -> Option<&MethodDefinition> {
        self.methods.iter().find(|method| {
            method.name == requested_name || method.alias.as_deref() == Some(requested_name)
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodDefinition {
    pub name: String,
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub timeout: u64,
    #[serde(rename = "returnType", default)]
    pub return_type: String,
    #[serde(default)]
    pub parameters: Vec<ParameterDefinition>,
    #[serde(default)]
    pub props: Vec<String>,
    #[serde(flatten)]
    pub extensions: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ParameterDefinition {
    Name(String),
    Detailed(ParameterDetail),
}

impl ParameterDefinition {
    pub fn name(&self) -> &str {
        match self {
            Self::Name(name) => name,
            Self::Detailed(detail) => &detail.name,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterDetail {
    pub name: String,
    #[serde(rename = "type", default = "default_parameter_type")]
    pub parameter_type: String,
    #[serde(
        default = "default_buffer_length",
        deserialize_with = "deserialize_buffer_length"
    )]
    pub len: usize,
    #[serde(default)]
    pub charset: Option<String>,
    #[serde(default)]
    pub decode: Option<String>,
    #[serde(flatten)]
    pub extensions: HashMap<String, Value>,
}

fn default_architecture() -> PluginArchitecture {
    PluginArchitecture::X86
}

fn default_parameter_type() -> String {
    "string".into()
}

fn default_calling_convention() -> String {
    "system".into()
}

fn default_buffer_length() -> usize {
    1024
}

fn deserialize_buffer_length<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Length {
        Number(usize),
        Text(String),
    }

    match Length::deserialize(deserializer)? {
        Length::Number(value) => Ok(value),
        Length::Text(value) => value.parse().map_err(serde::de::Error::custom),
    }
}

fn validate_manifest(plugin_id: &str, services: &[ServiceDefinition]) -> Result<(), ConfigError> {
    validate_plugin_id(plugin_id)?;
    if services.is_empty() {
        return Err(ConfigError::Validation(format!(
            "plugin [{plugin_id}] does not define any services"
        )));
    }
    if services.len() > MAX_SERVICES {
        return Err(ConfigError::Validation(format!(
            "plugin [{plugin_id}] defines too many services"
        )));
    }
    let mut service_ids = HashSet::new();
    for service in services {
        validate_service(plugin_id, service, &mut service_ids)?;
    }
    Ok(())
}

fn validate_plugin_id(plugin_id: &str) -> Result<(), ConfigError> {
    let plugin_id_path = Path::new(plugin_id);
    if plugin_id.trim().is_empty()
        || plugin_id.starts_with('.')
        || plugin_id.chars().count() > 128
        || plugin_id.chars().any(char::is_control)
        || plugin_id.contains(['/', '\\'])
        || plugin_id_path.components().count() != 1
        || !matches!(
            plugin_id_path.components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err(ConfigError::Validation(
            "plugin ID must contain 1 to 128 characters".into(),
        ));
    }
    Ok(())
}

fn validate_service<'a>(
    plugin_id: &str,
    service: &'a ServiceDefinition,
    service_ids: &mut HashSet<&'a str>,
) -> Result<(), ConfigError> {
    if service.service_id.trim().is_empty() || service.service_id.chars().count() > 256 {
        return Err(ConfigError::Validation(format!(
            "plugin [{plugin_id}] contains an empty serviceId"
        )));
    }
    if !service_ids.insert(service.service_id.as_str()) {
        return Err(ConfigError::Validation(format!(
            "plugin [{plugin_id}] contains duplicate serviceId [{}]",
            service.service_id
        )));
    }
    if service.main_class.trim().is_empty() {
        return Err(ConfigError::Validation(format!(
            "service [{}] has an empty mainClass",
            service.service_id
        )));
    }
    if service.main_class.len() > 4096 {
        return Err(ConfigError::Validation(format!(
            "service [{}] mainClass is too long",
            service.service_id
        )));
    }
    let main_type = service.resolved_main_type().to_ascii_lowercase();
    if !matches!(main_type.as_str(), "dll" | "exe" | "bat" | "ocx" | "com") {
        return Err(ConfigError::Validation(format!(
            "service [{}] has unsupported main type [{}]",
            service.service_id, main_type
        )));
    }
    if matches!(main_type.as_str(), "dll" | "exe" | "bat")
        && !is_safe_relative_component(&service.main_class)
    {
        return Err(ConfigError::Validation(format!(
            "service [{}] mainClass must stay inside its plugin directory",
            service.service_id
        )));
    }
    if service.deps.len() > MAX_DEPENDENCIES_PER_SERVICE {
        return Err(ConfigError::Validation(format!(
            "service [{}] defines too many dependencies",
            service.service_id
        )));
    }
    for dependency in &service.deps {
        if dependency.trim().is_empty() || dependency.len() > 4096 {
            return Err(ConfigError::Validation(format!(
                "service [{}] dependency path is empty or too long",
                service.service_id
            )));
        }
        if dependency != "*" && !is_safe_relative_component(dependency) {
            return Err(ConfigError::Validation(format!(
                "service [{}] dependency [{}] escapes its plugin directory",
                service.service_id, dependency
            )));
        }
    }
    let mut method_names = HashSet::new();
    if service.methods.len() > MAX_METHODS_PER_SERVICE {
        return Err(ConfigError::Validation(format!(
            "service [{}] defines too many methods",
            service.service_id
        )));
    }
    for method in &service.methods {
        if method.name.trim().is_empty() || method.name.chars().count() > 256 {
            return Err(ConfigError::Validation(format!(
                "service [{}] contains an empty method name",
                service.service_id
            )));
        }
        if !method_names.insert(method.name.as_str()) {
            return Err(ConfigError::Validation(format!(
                "service [{}] contains duplicate method [{}]",
                service.service_id, method.name
            )));
        }
        if let Some(alias) = method.alias.as_deref() {
            if alias.trim().is_empty() || alias.chars().count() > 256 || !method_names.insert(alias)
            {
                return Err(ConfigError::Validation(format!(
                    "service [{}] contains an empty or duplicate method alias [{}]",
                    service.service_id, alias
                )));
            }
        }
        let mut parameter_names = HashSet::new();
        if method.parameters.len() > MAX_PARAMETERS_PER_METHOD {
            return Err(ConfigError::Validation(format!(
                "method [{}] defines too many parameters",
                method.name
            )));
        }
        for parameter in &method.parameters {
            let parameter_name = parameter.name();
            let normalized_name = parameter_name.strip_prefix('$').unwrap_or(parameter_name);
            if normalized_name.trim().is_empty()
                || normalized_name.chars().count() > 256
                || !parameter_names.insert(normalized_name)
            {
                return Err(ConfigError::Validation(format!(
                    "method [{}] contains an empty or duplicate parameter [{}]",
                    method.name, parameter_name
                )));
            }
        }
    }
    Ok(())
}

fn is_safe_relative_component(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read plugin directory {path:?}: {source}")]
    ReadDirectory {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to read plugin manifest {path:?}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid plugin manifest {path:?}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("plugin manifest {path:?} is {actual} bytes; limit is {limit}")]
    TooLarge {
        path: PathBuf,
        actual: usize,
        limit: usize,
    },
    #[error("invalid plugin manifest: {0}")]
    Validation(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn reads_legacy_single_service_and_defaults_to_x86() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join(API_FILENAME),
            r#"{
              "serviceId": "reader.card",
              "mainClass": "reader.dll",
              "charset": "GBK",
              "methods": [{
                "name": "ReadCard",
                "alias": "read",
                "parameters": ["timeout", {"name":"$cardNo","len":"256"}]
              }]
            }"#,
        )
        .unwrap();

        let manifest = PluginManifest::load("reader", root.path()).unwrap();
        let service = manifest.service("reader.card").unwrap();
        assert_eq!(service.architecture, PluginArchitecture::X86);
        assert_eq!(service.resolved_main_type(), "dll");
        assert_eq!(service.method("read").unwrap().name, "ReadCard");
        match &service.methods[0].parameters[1] {
            ParameterDefinition::Detailed(detail) => assert_eq!(detail.len, 256),
            ParameterDefinition::Name(_) => panic!("expected detailed parameter"),
        }
    }

    #[test]
    fn discovers_valid_plugins_without_hiding_invalid_ones() {
        let root = tempdir().unwrap();
        let valid = root.path().join("valid");
        let invalid = root.path().join("invalid");
        fs::create_dir_all(&valid).unwrap();
        fs::create_dir_all(&invalid).unwrap();
        fs::write(
            valid.join(API_FILENAME),
            r#"[{"serviceId":"svc","mainClass":"tool.exe","methods":[]}]"#,
        )
        .unwrap();
        fs::write(invalid.join(API_FILENAME), "not-json").unwrap();

        let report = discover_plugins(root.path()).unwrap();
        assert_eq!(report.manifests.len(), 1);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].plugin_id, "invalid");
    }

    #[test]
    fn duplicate_service_ids_are_rejected() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join(API_FILENAME),
            r#"[
              {"serviceId":"same","mainClass":"a.dll"},
              {"serviceId":"same","mainClass":"b.dll"}
            ]"#,
        )
        .unwrap();

        let error = PluginManifest::load("duplicate", root.path()).unwrap_err();
        assert!(matches!(error, ConfigError::Validation(_)));
    }

    #[test]
    fn component_paths_cannot_escape_the_plugin_directory() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join(API_FILENAME),
            r#"{"serviceId":"escape","mainClass":"../reader.dll"}"#,
        )
        .unwrap();

        let error = PluginManifest::load("escape", root.path()).unwrap_err();
        assert!(matches!(error, ConfigError::Validation(_)));
    }

    #[test]
    fn loads_semantic_plugin_metadata_and_rejects_id_mismatch() {
        let directory = tempdir().unwrap();
        let plugin = directory.path().join("reader-plugin");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join(API_FILENAME),
            r#"{"serviceId":"reader","mainClass":"reader.dll"}"#,
        )
        .unwrap();
        fs::write(
            plugin.join(PLUGIN_METADATA_FILENAME),
            r#"{"schemaVersion":1,"pluginId":"reader-plugin","version":"2.1.0"}"#,
        )
        .unwrap();

        let manifest = PluginManifest::load("reader-plugin", &plugin).unwrap();
        assert_eq!(
            manifest.metadata.unwrap().version,
            semver::Version::new(2, 1, 0)
        );

        fs::write(
            plugin.join(PLUGIN_METADATA_FILENAME),
            r#"{"schemaVersion":1,"pluginId":"other-plugin","version":"2.1.0"}"#,
        )
        .unwrap();
        assert!(PluginManifest::load("reader-plugin", plugin).is_err());
    }
}
