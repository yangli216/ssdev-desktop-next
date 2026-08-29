use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use webplus_protocol::{PluginArchitecture, NATIVE_RETURN_VALUE_FIELD};

pub const API_FILENAME: &str = "api.json";
pub const PLUGIN_METADATA_FILENAME: &str = "plugin.json";
pub const LOCAL_MAPPING_INTEGRITY_FILENAME: &str = "local-mapping-integrity.json";
const MAX_API_BYTES: usize = 4 * 1024 * 1024;
const MAX_LOCAL_MAPPING_INTEGRITY_BYTES: usize = 4 * 1024 * 1024;
const MAX_LOCAL_MAPPING_INTEGRITY_FILES: usize = 512;
const MAX_LOCAL_MAPPING_INTEGRITY_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_SERVICES: usize = 1024;
const MAX_METHODS_PER_SERVICE: usize = 1024;
const MAX_PARAMETERS_PER_METHOD: usize = 256;
const MAX_PROPERTIES_PER_METHOD: usize = 256;
const MAX_DEPENDENCIES_PER_SERVICE: usize = 256;
const MAX_DLL_ARGUMENTS: usize = 12;

#[derive(Debug, Clone, PartialEq)]
pub struct PluginManifest {
    pub plugin_id: String,
    pub plugin_dir: PathBuf,
    pub metadata: Option<PluginMetadata>,
    pub services: Vec<ServiceDefinition>,
    /// SHA-256 of the verified local integrity document. `None` identifies a
    /// normal signed plugin or a legacy local mapping without content pinning.
    pub local_mapping_integrity_sha256: Option<String>,
}

/// Generates the public TypeScript client for a validated plugin service set.
///
/// Keeping this generator beside the manifest schema ensures the desktop
/// mapping workbench and headless release tooling expose identical method
/// names, result fields, and route literals.
pub fn generate_typescript_client(
    display_name: &str,
    services: &[ServiceDefinition],
) -> Result<String, serde_json::Error> {
    let mut output = String::from(
        "// Generated from an SSDEV plugin manifest. Regenerate after API changes.\n\
import type { InvokeResponse, JsonObject, JsonValue, PluginInvoker } from '@bsoft/ssdev-web-bridge'\n\n",
    );
    let methods = typescript_method_plans(services);
    for plan in &methods {
        output.push_str(&format!(
            "export type {} = JsonObject & {{\n",
            plan.parameters_type
        ));
        for parameter in plan
            .method
            .parameters
            .iter()
            .filter(|parameter| !parameter.name().starts_with('$'))
        {
            output.push_str(&format!(
                "  {}: {}\n",
                serde_json::to_string(parameter.name())?,
                typescript_parameter_type(parameter)
            ));
        }
        output.push_str("}\n\n");
        output.push_str(&format!(
            "export type {} = JsonObject & {{\n",
            plan.data_type
        ));
        output.push_str(&format!(
            "  {}: {}\n",
            NATIVE_RETURN_VALUE_FIELD,
            typescript_native_type(&plan.method.return_type)
        ));
        for parameter in plan
            .method
            .parameters
            .iter()
            .filter(|parameter| parameter.name().starts_with('$'))
        {
            output.push_str(&format!(
                "  {}: {}\n",
                serde_json::to_string(parameter.name().trim_start_matches('$'))?,
                typescript_parameter_type(parameter)
            ));
        }
        for property in &plan.method.props {
            output.push_str(&format!(
                "  {}: JsonValue\n",
                serde_json::to_string(property)?
            ));
        }
        output.push_str("}\n\n");
    }
    output.push_str(&format!(
        "export class {}Client {{\n  constructor(private readonly bridge: PluginInvoker) {{}}\n\n",
        typescript_pascal_identifier(display_name)
    ));
    for plan in methods {
        let default_parameters = if plan.has_input_parameters {
            ""
        } else {
            " = {}"
        };
        output.push_str(&format!(
            "  {}(parameters: {}{}): Promise<InvokeResponse<{}>> {{\n    return this.bridge.invokePlugin<{}>({}, {}, parameters)\n  }}\n\n",
            plan.client_method,
            plan.parameters_type,
            default_parameters,
            plan.data_type,
            plan.data_type,
            serde_json::to_string(&plan.service.service_id)?,
            serde_json::to_string(plan.request_name)?,
        ));
    }
    output.push_str("}\n");
    Ok(output)
}

struct TypeScriptMethodPlan<'a> {
    service: &'a ServiceDefinition,
    method: &'a MethodDefinition,
    request_name: &'a str,
    client_method: String,
    parameters_type: String,
    data_type: String,
    has_input_parameters: bool,
}

fn typescript_method_plans(services: &[ServiceDefinition]) -> Vec<TypeScriptMethodPlan<'_>> {
    let mut simple_name_counts = HashMap::new();
    for service in services {
        for method in &service.methods {
            let request_name = method.alias.as_deref().unwrap_or(&method.name);
            *simple_name_counts
                .entry(typescript_camel_identifier(request_name))
                .or_insert(0_usize) += 1;
        }
    }

    let mut used_names = HashSet::new();
    let mut plans = Vec::new();
    for service in services {
        for method in &service.methods {
            let request_name = method.alias.as_deref().unwrap_or(&method.name);
            let simple_name = typescript_camel_identifier(request_name);
            let mut base_name = if simple_name_counts.get(&simple_name) == Some(&1) {
                simple_name
            } else {
                format!(
                    "{}{}",
                    typescript_camel_identifier(&service.service_id),
                    typescript_pascal_identifier(request_name)
                )
            };
            if matches!(base_name.as_str(), "constructor" | "bridge") {
                base_name = format!("invoke{}", typescript_pascal_identifier(&base_name));
            }
            let client_method = unique_typescript_identifier(base_name, &mut used_names);
            let stem = typescript_pascal_identifier(&client_method);
            plans.push(TypeScriptMethodPlan {
                service,
                method,
                request_name,
                parameters_type: format!("{stem}Parameters"),
                data_type: format!("{stem}Data"),
                client_method,
                has_input_parameters: method
                    .parameters
                    .iter()
                    .any(|parameter| !parameter.name().starts_with('$')),
            });
        }
    }
    plans
}

fn unique_typescript_identifier(base: String, used: &mut HashSet<String>) -> String {
    if used.insert(base.clone()) {
        return base;
    }
    let mut suffix = 2_usize;
    loop {
        let candidate = format!("{base}{suffix}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
        suffix = suffix.saturating_add(1);
    }
}

fn typescript_parameter_type(parameter: &ParameterDefinition) -> &'static str {
    match parameter {
        ParameterDefinition::Name(_) => "JsonValue",
        ParameterDefinition::Detailed(detail) => typescript_native_type(&detail.parameter_type),
    }
}

fn typescript_native_type(native: &str) -> &'static str {
    match native.trim().to_ascii_lowercase().as_str() {
        "string" => "string",
        "bool" | "boolean" => "boolean",
        "int" | "int32" | "long" | "uint" | "uint32" | "dword" | "float" | "double" => "number",
        "void" => "null",
        _ => "JsonValue",
    }
}

fn typescript_pascal_identifier(value: &str) -> String {
    let mut output = String::new();
    let mut uppercase = true;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            if uppercase {
                output.push(character.to_ascii_uppercase());
                uppercase = false;
            } else {
                output.push(character);
            }
        } else {
            uppercase = true;
        }
    }
    if output.is_empty() || output.starts_with(|character: char| character.is_ascii_digit()) {
        output.insert_str(0, "Generated");
    }
    output
}

fn typescript_camel_identifier(value: &str) -> String {
    let mut output = typescript_pascal_identifier(value);
    if let Some(first) = output.get_mut(0..1) {
        first.make_ascii_lowercase();
    }
    output
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
        let integrity_path = plugin_dir.join(LOCAL_MAPPING_INTEGRITY_FILENAME);
        let local_mapping_integrity_sha256 = if integrity_path.exists() {
            Some(verify_local_mapping_integrity(&plugin_dir, &services)?)
        } else {
            None
        };
        Ok(Self {
            plugin_id,
            plugin_dir,
            metadata,
            services,
            local_mapping_integrity_sha256,
        })
    }

    pub fn service(&self, service_id: &str) -> Option<&ServiceDefinition> {
        self.services
            .iter()
            .find(|service| service.service_id == service_id)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalMappingIntegrityDocument {
    schema_version: u8,
    files: Vec<LocalMappingIntegrityFile>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalMappingIntegrityFile {
    path: String,
    size: u64,
    sha256: String,
}

/// Builds a deterministic integrity document for immutable local-mapping
/// runtime inputs. The caller persists the returned bytes atomically.
pub fn build_local_mapping_integrity(
    plugin_dir: &Path,
    services: &[ServiceDefinition],
) -> Result<Vec<u8>, ConfigError> {
    let paths = local_mapping_protected_paths(services)?;
    let mut files = Vec::with_capacity(paths.len());
    let mut total = 0_u64;
    for path in paths.values() {
        let full_path = plugin_dir.join(path);
        let metadata = fs::symlink_metadata(&full_path).map_err(|source| ConfigError::Read {
            path: full_path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ConfigError::Validation(format!(
                "protected local mapping path must be a regular non-symlink file [{}]",
                path.display()
            )));
        }
        total = total.checked_add(metadata.len()).ok_or_else(|| {
            ConfigError::Validation("local mapping protected byte count overflowed".into())
        })?;
        if total > MAX_LOCAL_MAPPING_INTEGRITY_TOTAL_BYTES {
            return Err(ConfigError::Validation(
                "local mapping protected files exceed 1 GiB".into(),
            ));
        }
        files.push(LocalMappingIntegrityFile {
            path: path_to_document_string(path)?,
            size: metadata.len(),
            sha256: hash_regular_file(&full_path)?,
        });
    }
    let mut bytes = serde_json::to_vec_pretty(&LocalMappingIntegrityDocument {
        schema_version: 1,
        files,
    })
    .map_err(|source| ConfigError::Json {
        path: plugin_dir.join(LOCAL_MAPPING_INTEGRITY_FILENAME),
        source,
    })?;
    bytes.push(b'\n');
    if bytes.len() > MAX_LOCAL_MAPPING_INTEGRITY_BYTES {
        return Err(ConfigError::TooLarge {
            path: plugin_dir.join(LOCAL_MAPPING_INTEGRITY_FILENAME),
            actual: bytes.len(),
            limit: MAX_LOCAL_MAPPING_INTEGRITY_BYTES,
        });
    }
    Ok(bytes)
}

/// Verifies the persisted document and every protected runtime file, then
/// returns the document identity used to pin controller-to-host restarts.
pub fn verify_local_mapping_integrity(
    plugin_dir: &Path,
    services: &[ServiceDefinition],
) -> Result<String, ConfigError> {
    verify_local_mapping_integrity_with_files(plugin_dir, services)
        .map(|verified| verified.document_sha256)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLocalMappingIntegrity {
    pub document_sha256: String,
    /// Portable relative path to the SHA-256 approved by the local mapping
    /// integrity document.
    pub files: BTreeMap<String, String>,
}

/// Verifies a local mapping and returns both its pinned document identity and
/// the file digests needed by the isolated native host.
pub fn verify_local_mapping_integrity_with_files(
    plugin_dir: &Path,
    services: &[ServiceDefinition],
) -> Result<VerifiedLocalMappingIntegrity, ConfigError> {
    let integrity_path = plugin_dir.join(LOCAL_MAPPING_INTEGRITY_FILENAME);
    let bytes = fs::read(&integrity_path).map_err(|source| ConfigError::Read {
        path: integrity_path.clone(),
        source,
    })?;
    if bytes.len() > MAX_LOCAL_MAPPING_INTEGRITY_BYTES {
        return Err(ConfigError::TooLarge {
            path: integrity_path,
            actual: bytes.len(),
            limit: MAX_LOCAL_MAPPING_INTEGRITY_BYTES,
        });
    }
    let document: LocalMappingIntegrityDocument =
        serde_json::from_slice(&bytes).map_err(|source| ConfigError::Json {
            path: integrity_path,
            source,
        })?;
    if document.schema_version != 1 {
        return Err(ConfigError::Validation(format!(
            "unsupported local mapping integrity schema [{}]",
            document.schema_version
        )));
    }
    if document.files.len() > MAX_LOCAL_MAPPING_INTEGRITY_FILES {
        return Err(ConfigError::Validation(format!(
            "local mapping integrity contains more than {MAX_LOCAL_MAPPING_INTEGRITY_FILES} files"
        )));
    }
    let expected = local_mapping_protected_paths(services)?;
    let mut actual = BTreeMap::new();
    for file in document.files {
        let relative = document_path(&file.path)?;
        let key = file.path.to_ascii_lowercase();
        if actual.insert(key, (relative, file)).is_some() {
            return Err(ConfigError::Validation(
                "local mapping integrity contains duplicate or case-colliding paths".into(),
            ));
        }
    }
    if actual.len() != expected.len() || actual.keys().ne(expected.keys()) {
        return Err(ConfigError::Validation(
            "local mapping integrity file set does not match the runtime declaration".into(),
        ));
    }
    let mut total = 0_u64;
    let mut verified_files = BTreeMap::new();
    for (key, expected_path) in expected {
        let (relative, entry) = actual.remove(&key).expect("sets were compared");
        if relative != expected_path {
            return Err(ConfigError::Validation(format!(
                "local mapping integrity path spelling does not match declaration [{}]",
                entry.path
            )));
        }
        if entry.sha256.len() != 64 || !entry.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ConfigError::Validation(format!(
                "local mapping integrity contains an invalid SHA-256 [{}]",
                entry.path
            )));
        }
        let full_path = plugin_dir.join(&relative);
        let metadata = fs::symlink_metadata(&full_path).map_err(|source| ConfigError::Read {
            path: full_path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ConfigError::Validation(format!(
                "protected local mapping path must be a regular non-symlink file [{}]",
                entry.path
            )));
        }
        if metadata.len() != entry.size {
            return Err(ConfigError::Validation(format!(
                "protected local mapping file size changed [{}]",
                entry.path
            )));
        }
        total = total.checked_add(metadata.len()).ok_or_else(|| {
            ConfigError::Validation("local mapping protected byte count overflowed".into())
        })?;
        if total > MAX_LOCAL_MAPPING_INTEGRITY_TOTAL_BYTES {
            return Err(ConfigError::Validation(
                "local mapping protected files exceed 1 GiB".into(),
            ));
        }
        if hash_regular_file(&full_path)? != entry.sha256.to_ascii_lowercase() {
            return Err(ConfigError::Validation(format!(
                "protected local mapping file content changed [{}]",
                entry.path
            )));
        }
        verified_files.insert(entry.path, entry.sha256.to_ascii_lowercase());
    }
    Ok(VerifiedLocalMappingIntegrity {
        document_sha256: hex_sha256(&bytes),
        files: verified_files,
    })
}

fn local_mapping_protected_paths(
    services: &[ServiceDefinition],
) -> Result<BTreeMap<String, PathBuf>, ConfigError> {
    let mut paths = BTreeMap::new();
    for fixed in [API_FILENAME, PLUGIN_METADATA_FILENAME] {
        insert_protected_path(&mut paths, fixed)?;
    }
    for service in services {
        let main_type = service.resolved_main_type().to_ascii_lowercase();
        if matches!(main_type.as_str(), "dll" | "exe" | "bat") {
            insert_protected_path(&mut paths, &service.main_class)?;
        }
        for dependency in &service.deps {
            insert_protected_path(&mut paths, dependency)?;
        }
    }
    if paths.len() > MAX_LOCAL_MAPPING_INTEGRITY_FILES {
        return Err(ConfigError::Validation(format!(
            "local mapping protects more than {MAX_LOCAL_MAPPING_INTEGRITY_FILES} files"
        )));
    }
    Ok(paths)
}

fn insert_protected_path(
    paths: &mut BTreeMap<String, PathBuf>,
    value: &str,
) -> Result<(), ConfigError> {
    let path = document_path(value)?;
    let rendered = path_to_document_string(&path)?;
    let key = rendered.to_ascii_lowercase();
    if let Some(existing) = paths.insert(key, path.clone()) {
        if existing != path {
            return Err(ConfigError::Validation(
                "local mapping runtime paths collide by ASCII case".into(),
            ));
        }
    }
    Ok(())
}

fn document_path(value: &str) -> Result<PathBuf, ConfigError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.contains('\\')
        || path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(ConfigError::Validation(format!(
            "local mapping protected path is unsafe [{value}]"
        )));
    }
    Ok(path.to_path_buf())
}

fn path_to_document_string(path: &Path) -> Result<String, ConfigError> {
    path.to_str()
        .map(|value| value.replace('\\', "/"))
        .ok_or_else(|| ConfigError::Validation("local mapping path is not UTF-8".into()))
}

fn hash_regular_file(path: &Path) -> Result<String, ConfigError> {
    let mut file = fs::File::open(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginMetadata {
    pub schema_version: u8,
    pub plugin_id: String,
    pub version: semver::Version,
    #[serde(default)]
    pub desktop_version_requirement: Option<semver::VersionReq>,
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
        if metadata
            .desktop_version_requirement
            .as_ref()
            .is_some_and(|requirement| requirement.to_string().len() > 128)
        {
            return Err(ConfigError::Validation(
                "desktop version requirement must not exceed 128 characters".into(),
            ));
        }
        Ok(Some(metadata))
    }

    pub fn supports_desktop_version(&self, version: &semver::Version) -> bool {
        self.desktop_version_requirement
            .as_ref()
            .is_some_and(|requirement| requirement.matches(version))
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// Stable, path-free description of one public Web Bridge contract change.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicApiChange {
    pub code: String,
    pub service_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate: Option<String>,
}

/// Compares every runtime-visible method name and alias without loading native
/// code. Breaking changes remove or narrow an existing Web Bridge contract;
/// review changes retain the public shape but alter native execution details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicApiCompatibility {
    pub compatible: bool,
    pub baseline_route_count: usize,
    pub candidate_route_count: usize,
    pub breaking_changes: Vec<PublicApiChange>,
    pub review_changes: Vec<PublicApiChange>,
    pub additions: Vec<PublicApiChange>,
}

pub fn compare_public_api(
    baseline: &[ServiceDefinition],
    candidate: &[ServiceDefinition],
) -> PublicApiCompatibility {
    let baseline_services = baseline
        .iter()
        .map(|service| (service.service_id.as_str(), service))
        .collect::<BTreeMap<_, _>>();
    let candidate_services = candidate
        .iter()
        .map(|service| (service.service_id.as_str(), service))
        .collect::<BTreeMap<_, _>>();
    let mut changes = ApiComparisonChanges::default();

    for (service_id, baseline_service) in &baseline_services {
        let Some(candidate_service) = candidate_services.get(service_id) else {
            changes.breaking.push(public_api_change(
                "service-removed",
                service_id,
                None,
                None,
                None,
                None,
            ));
            continue;
        };
        compare_service_execution_contract(
            baseline_service,
            candidate_service,
            &mut changes.review,
        );
        let baseline_routes = public_routes(baseline_service);
        let candidate_routes = public_routes(candidate_service);
        for (route, baseline_method) in &baseline_routes {
            let Some(candidate_method) = candidate_routes.get(route) else {
                changes.breaking.push(public_api_change(
                    "route-removed",
                    service_id,
                    Some(route),
                    None,
                    None,
                    None,
                ));
                continue;
            };
            compare_method_contract(
                baseline_service,
                baseline_method,
                candidate_service,
                candidate_method,
                route,
                &mut changes,
            );
        }
        for route in candidate_routes.keys() {
            if !baseline_routes.contains_key(route) {
                changes.additions.push(public_api_change(
                    "route-added",
                    service_id,
                    Some(route),
                    None,
                    None,
                    None,
                ));
            }
        }
    }
    for service_id in candidate_services.keys() {
        if !baseline_services.contains_key(service_id) {
            changes.additions.push(public_api_change(
                "service-added",
                service_id,
                None,
                None,
                None,
                None,
            ));
        }
    }

    for items in [
        &mut changes.breaking,
        &mut changes.review,
        &mut changes.additions,
    ] {
        items.sort();
        items.dedup();
    }
    PublicApiCompatibility {
        compatible: changes.breaking.is_empty(),
        baseline_route_count: service_route_count(baseline),
        candidate_route_count: service_route_count(candidate),
        breaking_changes: changes.breaking,
        review_changes: changes.review,
        additions: changes.additions,
    }
}

/// Validates a persisted or generated service contract without requiring a
/// plugin directory. Runtime baselines use this before trusting serialized
/// API declarations that were written by an earlier desktop process.
pub fn validate_plugin_services(
    plugin_id: &str,
    services: &[ServiceDefinition],
) -> Result<(), ConfigError> {
    validate_manifest(plugin_id, services)
}

#[derive(Default)]
struct ApiComparisonChanges {
    breaking: Vec<PublicApiChange>,
    review: Vec<PublicApiChange>,
    additions: Vec<PublicApiChange>,
}

fn public_routes(service: &ServiceDefinition) -> BTreeMap<&str, &MethodDefinition> {
    let mut routes = BTreeMap::new();
    for method in &service.methods {
        routes.insert(method.name.as_str(), method);
        if let Some(alias) = method.alias.as_deref() {
            routes.insert(alias, method);
        }
    }
    routes
}

fn service_route_count(services: &[ServiceDefinition]) -> usize {
    services
        .iter()
        .map(|service| public_routes(service).len())
        .sum()
}

fn compare_service_execution_contract(
    baseline: &ServiceDefinition,
    candidate: &ServiceDefinition,
    review: &mut Vec<PublicApiChange>,
) {
    let native_binding_changed = baseline.main_class != candidate.main_class
        || !baseline
            .resolved_main_type()
            .eq_ignore_ascii_case(candidate.resolved_main_type())
        || baseline.architecture != candidate.architecture
        || !baseline
            .charset
            .trim()
            .eq_ignore_ascii_case(candidate.charset.trim())
        || !baseline
            .calling_convention
            .trim()
            .eq_ignore_ascii_case(candidate.calling_convention.trim())
        || baseline.cacheable != candidate.cacheable
        || baseline.deps != candidate.deps
        || baseline.extensions != candidate.extensions;
    if native_binding_changed {
        review.push(public_api_change(
            "service-native-binding-changed",
            &baseline.service_id,
            None,
            None,
            None,
            None,
        ));
    }
    if baseline.timeout != candidate.timeout {
        review.push(public_api_change(
            "service-timeout-changed",
            &baseline.service_id,
            None,
            None,
            Some(baseline.timeout.to_string()),
            Some(candidate.timeout.to_string()),
        ));
    }
}

fn compare_method_contract(
    baseline_service: &ServiceDefinition,
    baseline: &MethodDefinition,
    candidate_service: &ServiceDefinition,
    candidate: &MethodDefinition,
    route: &str,
    changes: &mut ApiComparisonChanges,
) {
    let baseline_inputs = method_input_contract(baseline);
    let candidate_inputs = method_input_contract(candidate);
    for (field, baseline_type) in &baseline_inputs {
        match candidate_inputs.get(field) {
            None => changes.breaking.push(public_api_change(
                "input-removed",
                &baseline_service.service_id,
                Some(route),
                Some(field),
                Some(baseline_type.clone()),
                None,
            )),
            Some(candidate_type) if candidate_type != baseline_type => {
                changes.breaking.push(public_api_change(
                    "input-type-changed",
                    &baseline_service.service_id,
                    Some(route),
                    Some(field),
                    Some(baseline_type.clone()),
                    Some(candidate_type.clone()),
                ));
            }
            Some(_) => {}
        }
    }
    for (field, candidate_type) in &candidate_inputs {
        if !baseline_inputs.contains_key(field) {
            changes.breaking.push(public_api_change(
                "required-input-added",
                &baseline_service.service_id,
                Some(route),
                Some(field),
                None,
                Some(candidate_type.clone()),
            ));
        }
    }

    let baseline_responses = method_response_contract(baseline_service, baseline);
    let candidate_responses = method_response_contract(candidate_service, candidate);
    for (field, baseline_type) in &baseline_responses {
        match candidate_responses.get(field) {
            None => changes.breaking.push(public_api_change(
                "response-field-removed",
                &baseline_service.service_id,
                Some(route),
                Some(field),
                Some(baseline_type.clone()),
                None,
            )),
            Some(candidate_type) if candidate_type != baseline_type => {
                changes.breaking.push(public_api_change(
                    "response-type-changed",
                    &baseline_service.service_id,
                    Some(route),
                    Some(field),
                    Some(baseline_type.clone()),
                    Some(candidate_type.clone()),
                ));
            }
            Some(_) => {}
        }
    }
    for (field, candidate_type) in &candidate_responses {
        if !baseline_responses.contains_key(field) {
            changes.additions.push(public_api_change(
                "response-field-added",
                &baseline_service.service_id,
                Some(route),
                Some(field),
                None,
                Some(candidate_type.clone()),
            ));
        }
    }

    if baseline.name != candidate.name {
        changes.review.push(public_api_change(
            "route-native-target-changed",
            &baseline_service.service_id,
            Some(route),
            None,
            Some(baseline.name.clone()),
            Some(candidate.name.clone()),
        ));
    }
    if baseline.timeout != candidate.timeout {
        changes.review.push(public_api_change(
            "method-timeout-changed",
            &baseline_service.service_id,
            Some(route),
            None,
            Some(baseline.timeout.to_string()),
            Some(candidate.timeout.to_string()),
        ));
    }
    let baseline_order = baseline
        .parameters
        .iter()
        .map(ParameterDefinition::name)
        .collect::<Vec<_>>();
    let candidate_order = candidate
        .parameters
        .iter()
        .map(ParameterDefinition::name)
        .collect::<Vec<_>>();
    if baseline_order != candidate_order {
        let same_fields = baseline_order.len() == candidate_order.len()
            && baseline_order.iter().collect::<BTreeSet<_>>()
                == candidate_order.iter().collect::<BTreeSet<_>>();
        changes.review.push(public_api_change(
            if same_fields {
                "native-parameter-order-changed"
            } else {
                "native-parameter-layout-changed"
            },
            &baseline_service.service_id,
            Some(route),
            None,
            None,
            None,
        ));
    }
    if baseline_order == candidate_order
        && baseline.parameters != candidate.parameters
        && baseline_inputs == candidate_inputs
        && baseline_responses == candidate_responses
    {
        changes.review.push(public_api_change(
            "native-parameter-options-changed",
            &baseline_service.service_id,
            Some(route),
            None,
            None,
            None,
        ));
    }
    if baseline.props != candidate.props && baseline_responses == candidate_responses {
        changes.review.push(public_api_change(
            "native-property-order-changed",
            &baseline_service.service_id,
            Some(route),
            None,
            None,
            None,
        ));
    }
    if baseline.extensions != candidate.extensions {
        changes.review.push(public_api_change(
            "method-extension-changed",
            &baseline_service.service_id,
            Some(route),
            None,
            None,
            None,
        ));
    }
}

fn method_input_contract(method: &MethodDefinition) -> BTreeMap<String, String> {
    method
        .parameters
        .iter()
        .filter(|parameter| !parameter.name().starts_with('$'))
        .map(|parameter| {
            (
                parameter.name().to_owned(),
                parameter_contract_type(parameter, false),
            )
        })
        .collect()
}

fn method_response_contract(
    service: &ServiceDefinition,
    method: &MethodDefinition,
) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::from([(
        NATIVE_RETURN_VALUE_FIELD.to_owned(),
        return_contract_type(service, &method.return_type),
    )]);
    for parameter in method
        .parameters
        .iter()
        .filter(|parameter| parameter.name().starts_with('$'))
    {
        fields.insert(
            parameter.name().trim_start_matches('$').to_owned(),
            parameter_contract_type(parameter, true),
        );
    }
    for property in &method.props {
        fields.insert(property.clone(), "json".into());
    }
    fields
}

fn parameter_contract_type(parameter: &ParameterDefinition, output: bool) -> String {
    let declared = match parameter {
        ParameterDefinition::Name(_) => "inferred",
        ParameterDefinition::Detailed(detail) => detail.parameter_type.trim(),
    };
    match declared.to_ascii_lowercase().as_str() {
        "" | "inferred" if output => "string".into(),
        "" | "inferred" => "inferred".into(),
        "string" | "buffer" => "string".into(),
        "bool" | "boolean" => "boolean".into(),
        "int" | "int32" | "long" => "int32".into(),
        "uint" | "uint32" | "dword" => "uint32".into(),
        "float" | "double" => "number".into(),
        other => other.to_owned(),
    }
}

fn return_contract_type(service: &ServiceDefinition, declared: &str) -> String {
    match declared.trim().to_ascii_lowercase().as_str() {
        "" if service.resolved_main_type().eq_ignore_ascii_case("dll") => "int32".into(),
        "" => "json".into(),
        "void" => "null".into(),
        "string" | "char*" | "pointer_string" => "string".into(),
        "bool" | "boolean" => "boolean".into(),
        "int" | "int32" | "long" => "int32".into(),
        "uint" | "uint32" | "dword" => "uint32".into(),
        "float" | "double" => "number".into(),
        "pointer" | "uintptr" | "usize" => "pointer".into(),
        other => other.to_owned(),
    }
}

fn public_api_change(
    code: &str,
    service_id: &str,
    route: Option<&str>,
    field: Option<&str>,
    baseline: Option<String>,
    candidate: Option<String>,
) -> PublicApiChange {
    PublicApiChange {
        code: code.into(),
        service_id: service_id.into(),
        route: route.map(str::to_owned),
        field: field.map(str::to_owned),
        baseline,
        candidate,
    }
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

/// Validates the bounded word-based DLL ABI implemented by `webplus-native`.
///
/// This check is intentionally platform-independent so plugin preparation,
/// signing, desktop loading, and the native host all reject the same
/// declarations before any vendor export is called.
pub fn validate_dll_abi(service: &ServiceDefinition) -> Result<(), String> {
    match service
        .calling_convention
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "c" | "cdecl" | "system" | "stdcall" | "winapi" => {}
        other => return Err(format!("unsupported DLL calling convention [{other}]")),
    }
    for method in &service.methods {
        if !method.props.is_empty() {
            return Err(format!(
                "DLL method [{}] cannot declare COM properties",
                method.name
            ));
        }
        if method.parameters.len() > MAX_DLL_ARGUMENTS {
            return Err(format!(
                "DLL method [{}] has {} arguments; maximum is {MAX_DLL_ARGUMENTS}",
                method.name,
                method.parameters.len()
            ));
        }
        match method.return_type.trim().to_ascii_lowercase().as_str() {
            "" | "void" | "string" | "char*" | "pointer_string" | "bool" | "boolean" | "int"
            | "int32" | "long" | "uint" | "uint32" | "dword" | "pointer" | "uintptr" | "usize" => {}
            "float" | "double" => {
                return Err(format!(
                    "DLL method [{}] uses a floating-point return that requires a typed ABI",
                    method.name
                ));
            }
            other => {
                return Err(format!(
                    "DLL method [{}] has unsupported return type [{other}]",
                    method.name
                ));
            }
        }
        for parameter in &method.parameters {
            let name = parameter.name();
            if name
                .strip_prefix('$')
                .is_some_and(|output| output.is_empty() || output.starts_with('$'))
            {
                return Err(format!(
                    "DLL method [{}] parameter [{}] has an invalid output name",
                    method.name, name
                ));
            }
            let ParameterDefinition::Detailed(detail) = parameter else {
                continue;
            };
            let output = detail.name.starts_with('$');
            let kind = detail.parameter_type.trim().to_ascii_lowercase();
            let supported = if output {
                matches!(
                    kind.as_str(),
                    "" | "inferred" | "string" | "buffer" | "int" | "int32" | "long"
                ) && (!matches!(kind.as_str(), "" | "inferred" | "string" | "buffer")
                    || (1..=1024 * 1024).contains(&detail.len))
            } else {
                matches!(
                    kind.as_str(),
                    "" | "inferred"
                        | "string"
                        | "bool"
                        | "int"
                        | "int32"
                        | "long"
                        | "uint"
                        | "uint32"
                )
            };
            if !supported {
                return Err(format!(
                    "DLL method [{}] parameter [{}] has an unsupported ABI declaration",
                    method.name, detail.name
                ));
            }
        }
    }
    Ok(())
}

/// Validates the scalar/BSTR `IDispatch` parameter model implemented by the
/// COM adapter without instantiating or invoking the declared component.
pub fn validate_com_automation(service: &ServiceDefinition) -> Result<(), String> {
    for method in &service.methods {
        for parameter in &method.parameters {
            let ParameterDefinition::Detailed(detail) = parameter else {
                continue;
            };
            let kind = detail.parameter_type.trim().to_ascii_lowercase();
            let supported = matches!(
                kind.as_str(),
                "" | "inferred"
                    | "string"
                    | "buffer"
                    | "bool"
                    | "boolean"
                    | "int"
                    | "int32"
                    | "long"
                    | "uint"
                    | "uint32"
                    | "dword"
                    | "float"
                    | "double"
            );
            if !supported {
                return Err(format!(
                    "COM method [{}] parameter [{}] has an unsupported automation type [{}]",
                    method.name, detail.name, kind
                ));
            }
        }
    }
    Ok(())
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
        let mut response_field_names = HashSet::from([NATIVE_RETURN_VALUE_FIELD]);
        if method.parameters.len() > MAX_PARAMETERS_PER_METHOD {
            return Err(ConfigError::Validation(format!(
                "method [{}] defines too many parameters",
                method.name
            )));
        }
        for parameter in &method.parameters {
            let parameter_name = parameter.name();
            let normalized_name = parameter_name.strip_prefix('$').unwrap_or(parameter_name);
            if normalized_name.starts_with('$') {
                return Err(ConfigError::Validation(format!(
                    "method [{}] output parameter [{}] must use exactly one leading $",
                    method.name, parameter_name
                )));
            }
            if normalized_name.trim().is_empty()
                || normalized_name.chars().count() > 256
                || !parameter_names.insert(normalized_name)
            {
                return Err(ConfigError::Validation(format!(
                    "method [{}] contains an empty or duplicate parameter [{}]",
                    method.name, parameter_name
                )));
            }
            if parameter_name.starts_with('$') && !response_field_names.insert(normalized_name) {
                return Err(ConfigError::Validation(format!(
                    "method [{}] output parameter [{}] conflicts with reserved or duplicate ResData field [{}]",
                    method.name, parameter_name, normalized_name
                )));
            }
        }
        if method.props.len() > MAX_PROPERTIES_PER_METHOD {
            return Err(ConfigError::Validation(format!(
                "method [{}] defines too many COM properties",
                method.name
            )));
        }
        for property in &method.props {
            if property.trim().is_empty() || property.chars().count() > 256 {
                return Err(ConfigError::Validation(format!(
                    "method [{}] contains an empty or too long COM property",
                    method.name
                )));
            }
            if !response_field_names.insert(property.as_str()) {
                return Err(ConfigError::Validation(format!(
                    "method [{}] COM property [{}] conflicts with a reserved, output-parameter, or duplicate ResData field",
                    method.name, property
                )));
            }
        }
        if !method.props.is_empty() && !matches!(main_type.as_str(), "dll" | "com" | "ocx") {
            return Err(ConfigError::Validation(format!(
                "method [{}] cannot declare COM properties for main type [{}]",
                method.name, main_type
            )));
        }
    }
    match main_type.as_str() {
        "dll" => validate_dll_abi(service).map_err(ConfigError::Validation)?,
        "com" | "ocx" => validate_com_automation(service).map_err(ConfigError::Validation)?,
        _ => {}
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

    fn write_integrity_fixture(root: &Path) -> Vec<ServiceDefinition> {
        fs::create_dir_all(root.join("components")).unwrap();
        fs::write(
            root.join(API_FILENAME),
            r#"[{"serviceId":"reader.card","mainClass":"components/reader.dll","mainType":"dll","methods":[]}]"#,
        )
        .unwrap();
        fs::write(
            root.join(PLUGIN_METADATA_FILENAME),
            r#"{"schemaVersion":1,"pluginId":"reader","version":"0.0.0-local","displayName":"Reader"}"#,
        )
        .unwrap();
        fs::write(root.join("components/reader.dll"), b"fixture-binary").unwrap();
        let services: ApiDocument =
            serde_json::from_slice(&fs::read(root.join(API_FILENAME)).unwrap()).unwrap();
        services.into_services()
    }

    #[test]
    fn generated_typescript_client_uses_public_routes_and_stable_types() {
        let services: Vec<ServiceDefinition> = serde_json::from_value(serde_json::json!([{
            "serviceId": "reader.card",
            "mainClass": "reader.dll",
            "mainType": "dll",
            "architecture": "x64",
            "methods": [{
                "name": "ReadCard",
                "alias": "read",
                "returnType": "uint32",
                "parameters": [
                    { "name": "port", "type": "string" },
                    { "name": "$cardNo", "type": "string", "len": 256 }
                ]
            }]
        }, {
            "serviceId": "reader.status",
            "mainClass": "Scripting.Dictionary",
            "mainType": "com",
            "architecture": "x86",
            "methods": [{
                "name": "Read",
                "alias": "read",
                "returnType": "void",
                "parameters": [],
                "props": ["Count"]
            }]
        }]))
        .unwrap();

        let source = generate_typescript_client("Card Reader", &services).unwrap();
        assert!(source.contains("export class CardReaderClient"));
        assert!(source.contains("readerCardRead(parameters: ReaderCardReadParameters)"));
        assert!(source.contains("\"port\": string"));
        assert!(source.contains("\"cardNo\": string"));
        assert!(source.contains("ReturnValue: number"));
        assert!(source.contains("readerStatusRead(parameters: ReaderStatusReadParameters = {})"));
        assert!(source.contains("\"Count\": JsonValue"));
        assert!(source.contains("ReturnValue: null"));
        assert!(source.contains("invokePlugin<ReaderCardReadData>(\"reader.card\", \"read\""));
        assert!(!source.contains("$cardNo"));
    }

    #[test]
    fn public_api_comparison_blocks_removed_aliases_and_shape_changes() {
        let baseline: Vec<ServiceDefinition> = serde_json::from_value(serde_json::json!([{
            "serviceId": "reader.card",
            "mainClass": "reader.dll",
            "mainType": "dll",
            "methods": [{
                "name": "ReadCard",
                "alias": "read",
                "parameters": ["timeout", {"name":"$cardNo","type":"string"}]
            }]
        }]))
        .unwrap();
        let candidate: Vec<ServiceDefinition> = serde_json::from_value(serde_json::json!([{
            "serviceId": "reader.card",
            "mainClass": "reader.dll",
            "mainType": "dll",
            "methods": [{
                "name": "ReadCard",
                "returnType": "string",
                "parameters": [{"name":"timeout","type":"int32"}, {"name":"mode","type":"string"}]
            }]
        }]))
        .unwrap();

        let report = compare_public_api(&baseline, &candidate);
        assert!(!report.compatible);
        assert_eq!(report.baseline_route_count, 2);
        assert_eq!(report.candidate_route_count, 1);
        for code in [
            "route-removed",
            "input-type-changed",
            "required-input-added",
            "response-field-removed",
            "response-type-changed",
        ] {
            assert!(report
                .breaking_changes
                .iter()
                .any(|change| change.code == code));
        }
    }

    #[test]
    fn public_api_comparison_allows_additions_but_flags_native_review() {
        let baseline: Vec<ServiceDefinition> = serde_json::from_value(serde_json::json!([{
            "serviceId": "reader.card",
            "mainClass": "reader.dll",
            "mainType": "dll",
            "methods": [{"name":"ReadCard","parameters":["timeout"]}]
        }]))
        .unwrap();
        let candidate: Vec<ServiceDefinition> = serde_json::from_value(serde_json::json!([{
            "serviceId": "reader.card",
            "mainClass": "reader-v2.dll",
            "mainType": "dll",
            "methods": [{
                "name": "ReadCard",
                "alias": "read",
                "parameters": [{"name":"timeout","type":"inferred"}, {"name":"$status","type":"int32"}]
            }]
        }]))
        .unwrap();

        let report = compare_public_api(&baseline, &candidate);
        assert!(report.compatible);
        assert!(report
            .additions
            .iter()
            .any(|change| change.code == "route-added"));
        assert!(report
            .additions
            .iter()
            .any(|change| change.code == "response-field-added"));
        assert!(report
            .review_changes
            .iter()
            .any(|change| change.code == "service-native-binding-changed"));
        assert!(report
            .review_changes
            .iter()
            .any(|change| change.code == "native-parameter-layout-changed"));
    }

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
    fn local_mapping_integrity_pins_runtime_files_and_document_identity() {
        let root = tempdir().unwrap();
        let services = write_integrity_fixture(root.path());
        let bytes = build_local_mapping_integrity(root.path(), &services).unwrap();
        fs::write(root.path().join(LOCAL_MAPPING_INTEGRITY_FILENAME), &bytes).unwrap();

        let digest = verify_local_mapping_integrity(root.path(), &services).unwrap();
        assert_eq!(digest.len(), 64);
        let verified = verify_local_mapping_integrity_with_files(root.path(), &services).unwrap();
        assert_eq!(verified.document_sha256, digest);
        assert_eq!(verified.files.len(), 3);
        assert_eq!(
            verified.files.get("components/reader.dll"),
            Some(&hash_regular_file(&root.path().join("components/reader.dll")).unwrap())
        );
        let manifest = PluginManifest::load("reader", root.path()).unwrap();
        assert_eq!(
            manifest.local_mapping_integrity_sha256.as_deref(),
            Some(digest.as_str())
        );

        fs::write(root.path().join("components/reader.dll"), b"changed-binary").unwrap();
        assert!(PluginManifest::load("reader", root.path()).is_err());
    }

    #[test]
    fn local_mapping_integrity_rejects_manifest_file_set_drift() {
        let root = tempdir().unwrap();
        let services = write_integrity_fixture(root.path());
        let bytes = build_local_mapping_integrity(root.path(), &services).unwrap();
        let mut document: LocalMappingIntegrityDocument = serde_json::from_slice(&bytes).unwrap();
        document.files.pop();
        fs::write(
            root.path().join(LOCAL_MAPPING_INTEGRITY_FILENAME),
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();

        assert!(verify_local_mapping_integrity(root.path(), &services).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn local_mapping_integrity_rejects_protected_symlinks() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let services = write_integrity_fixture(root.path());
        fs::rename(
            root.path().join("components/reader.dll"),
            root.path().join("reader.real"),
        )
        .unwrap();
        symlink(
            root.path().join("reader.real"),
            root.path().join("components/reader.dll"),
        )
        .unwrap();

        assert!(build_local_mapping_integrity(root.path(), &services).is_err());
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
    fn native_response_fields_cannot_shadow_return_value_or_each_other() {
        let cases = [
            (
                r#"{"serviceId":"reader","mainClass":"reader.dll","methods":[{"name":"read","parameters":["$ReturnValue"]}]}"#,
                "output parameter [$ReturnValue] conflicts",
            ),
            (
                r#"{"serviceId":"reader","mainClass":"Reader.Dictionary","mainType":"com","methods":[{"name":"read","props":["ReturnValue"]}]}"#,
                "COM property [ReturnValue] conflicts",
            ),
            (
                r#"{"serviceId":"reader","mainClass":"Reader.Dictionary","mainType":"com","methods":[{"name":"read","parameters":["$Count"],"props":["Count"]}]}"#,
                "COM property [Count] conflicts",
            ),
            (
                r#"{"serviceId":"reader","mainClass":"Reader.Dictionary","mainType":"com","methods":[{"name":"read","props":["Count","Count"]}]}"#,
                "COM property [Count] conflicts",
            ),
        ];

        for (api, expected) in cases {
            let root = tempdir().unwrap();
            fs::write(root.path().join(API_FILENAME), api).unwrap();

            let error = PluginManifest::load("reader", root.path()).unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "expected [{expected}] in [{error}]"
            );
        }
    }

    #[test]
    fn distinct_com_outputs_and_properties_remain_valid() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join(API_FILENAME),
            r#"{"serviceId":"reader","mainClass":"Reader.Dictionary","mainType":"com","methods":[{"name":"read","parameters":["$Status"],"props":["Count"]}]}"#,
        )
        .unwrap();

        let manifest = PluginManifest::load("reader", root.path()).unwrap();
        assert_eq!(manifest.services[0].methods[0].props, ["Count"]);
    }

    #[test]
    fn dll_abi_rejects_shapes_the_word_call_stub_cannot_express() {
        let cases = [
            (
                r#"{"serviceId":"reader","mainClass":"reader.dll","callingConvention":"vectorcall","methods":[{"name":"read"}]}"#,
                "unsupported DLL calling convention",
            ),
            (
                r#"{"serviceId":"reader","mainClass":"reader.dll","methods":[{"name":"read","returnType":"double"}]}"#,
                "floating-point return",
            ),
            (
                r#"{"serviceId":"reader","mainClass":"reader.dll","methods":[{"name":"read","parameters":[{"name":"ratio","type":"double"}]}]}"#,
                "unsupported ABI declaration",
            ),
            (
                r#"{"serviceId":"reader","mainClass":"reader.dll","methods":[{"name":"read","parameters":[{"name":"$ready","type":"bool"}]}]}"#,
                "unsupported ABI declaration",
            ),
            (
                r#"{"serviceId":"reader","mainClass":"reader.dll","methods":[{"name":"read","parameters":[{"name":"$text","type":"buffer","len":0}]}]}"#,
                "unsupported ABI declaration",
            ),
            (
                r#"{"serviceId":"reader","mainClass":"reader.dll","methods":[{"name":"read","parameters":["a","b","c","d","e","f","g","h","i","j","k","l","m"]}]}"#,
                "maximum is 12",
            ),
            (
                r#"{"serviceId":"reader","mainClass":"reader.dll","methods":[{"name":"read","parameters":["$$status"]}]}"#,
                "must use exactly one leading $",
            ),
            (
                r#"{"serviceId":"reader","mainClass":"reader.dll","methods":[{"name":"read","props":["Count"]}]}"#,
                "cannot declare COM properties",
            ),
        ];

        for (api, expected) in cases {
            let root = tempdir().unwrap();
            fs::write(root.path().join(API_FILENAME), api).unwrap();

            let error = PluginManifest::load("reader", root.path()).unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "expected [{expected}] in [{error}]"
            );
        }
    }

    #[test]
    fn dll_abi_normalizes_supported_type_spelling_cross_platform() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join(API_FILENAME),
            r#"{"serviceId":"reader","mainClass":"reader.dll","callingConvention":" CDECL ","methods":[{"name":"read","returnType":" POINTER ","parameters":[{"name":"value","type":" InFeRrEd "},{"name":"$text","type":" STRING ","len":32},{"name":"$code","type":" INT32 "}]}]}"#,
        )
        .unwrap();

        let manifest = PluginManifest::load("reader", root.path()).unwrap();
        validate_dll_abi(&manifest.services[0]).unwrap();
    }

    #[test]
    fn com_automation_rejects_unsupported_parameter_types_cross_platform() {
        for api in [
            r#"{"serviceId":"reader","mainClass":"Vendor.Reader","mainType":"com","methods":[{"name":"read","parameters":[{"name":"input","type":"pointer"}]}]}"#,
            r#"{"serviceId":"reader","mainClass":"Vendor.Reader","mainType":"ocx","methods":[{"name":"read","parameters":[{"name":"$output","type":"struct"}]}]}"#,
        ] {
            let root = tempdir().unwrap();
            fs::write(root.path().join(API_FILENAME), api).unwrap();

            let error = PluginManifest::load("reader", root.path()).unwrap_err();
            assert!(error.to_string().contains("unsupported automation type"));
        }
    }

    #[test]
    fn com_automation_accepts_the_complete_scalar_and_bstr_contract() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join(API_FILENAME),
            r#"{"serviceId":"reader","mainClass":"Vendor.Reader","mainType":"com","methods":[{"name":"read","parameters":[{"name":"text","type":" STRING "},{"name":"flag","type":"boolean"},{"name":"signed","type":"int32"},{"name":"unsigned","type":"uint32"},{"name":"ratio","type":"double"},{"name":"$buffer","type":"buffer"},{"name":"$status","type":"dword"}],"props":["Count"]}]}"#,
        )
        .unwrap();

        let manifest = PluginManifest::load("reader", root.path()).unwrap();
        validate_com_automation(&manifest.services[0]).unwrap();
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
            r#"{"schemaVersion":1,"pluginId":"reader-plugin","version":"2.1.0","desktopVersionRequirement":">=0.1.0, <0.2.0"}"#,
        )
        .unwrap();

        let manifest = PluginManifest::load("reader-plugin", &plugin).unwrap();
        let metadata = manifest.metadata.unwrap();
        assert_eq!(metadata.version, semver::Version::new(2, 1, 0));
        assert!(metadata.supports_desktop_version(&semver::Version::new(0, 1, 9)));
        assert!(!metadata.supports_desktop_version(&semver::Version::new(0, 2, 0)));

        fs::write(
            plugin.join(PLUGIN_METADATA_FILENAME),
            r#"{"schemaVersion":1,"pluginId":"reader-plugin","version":"2.1.0"}"#,
        )
        .unwrap();
        let legacy = PluginManifest::load("reader-plugin", &plugin).unwrap();
        assert!(!legacy
            .metadata
            .unwrap()
            .supports_desktop_version(&semver::Version::new(0, 1, 0)));

        fs::write(
            plugin.join(PLUGIN_METADATA_FILENAME),
            r#"{"schemaVersion":1,"pluginId":"other-plugin","version":"2.1.0"}"#,
        )
        .unwrap();
        assert!(PluginManifest::load("reader-plugin", plugin).is_err());
    }
}
