#[cfg(any(windows, test))]
mod arguments;
mod com;
mod dll;
mod process;

use std::collections::BTreeMap;

use thiserror::Error;
use webplus_plugin_config::PluginManifest;
use webplus_protocol::{InvokeRequest, InvokeResponse, PluginArchitecture};

pub struct NativePlugin {
    manifest: PluginManifest,
    com: com::ComAdapter,
    dll: dll::DllAdapter,
    process: process::ProcessAdapter,
}

impl NativePlugin {
    pub fn new(manifest: PluginManifest) -> Self {
        Self {
            manifest,
            com: com::ComAdapter::new(),
            dll: dll::DllAdapter::new(),
            process: process::ProcessAdapter::new(None)
                .expect("an unverified process adapter has no inventory to validate"),
        }
    }

    /// Constructs a native adapter whose process entries must match a file
    /// inventory already authenticated by the caller.
    pub fn new_verified(
        manifest: PluginManifest,
        verified_files: BTreeMap<String, String>,
    ) -> Result<Self, NativeError> {
        Ok(Self {
            manifest,
            com: com::ComAdapter::new(),
            dll: dll::DllAdapter::new(),
            process: process::ProcessAdapter::new(Some(verified_files))?,
        })
    }

    /// Pumps pending messages for apartment-threaded COM components.
    ///
    /// The plugin host calls this while its dedicated native thread is idle.
    pub fn pump_messages(&mut self) {
        self.com.pump_messages();
    }

    /// Initializes every service assigned to one native host architecture
    /// without executing a declared business method.
    ///
    /// DLLs and dependencies are loaded and every export is resolved; COM/OCX
    /// classes are instantiated and their declared members are resolved; EXE
    /// and BAT entries are path-checked but never launched.
    pub fn preflight(&mut self, architecture: PluginArchitecture) -> Result<usize, NativeError> {
        let services = self
            .manifest
            .services
            .iter()
            .filter(|service| service.architecture == architecture)
            .cloned()
            .collect::<Vec<_>>();
        if services.is_empty() {
            return Err(NativeError::Unsupported(format!(
                "plugin does not declare services for {architecture:?}"
            )));
        }
        for service in &services {
            match service.resolved_main_type().to_ascii_lowercase().as_str() {
                "dll" => self.dll.preflight(&self.manifest.plugin_dir, service)?,
                "exe" | "bat" => self.process.preflight(&self.manifest.plugin_dir, service)?,
                "ocx" | "com" => self.com.preflight(service)?,
                other => {
                    return Err(NativeError::Unsupported(format!(
                        "mainClass type [{other}] is not supported"
                    )))
                }
            }
        }
        Ok(services.len())
    }

    pub fn invoke(&mut self, request: &InvokeRequest) -> InvokeResponse {
        match self.try_invoke(request) {
            Ok(response) => response,
            Err(error) => InvokeResponse::error(error.code(), error.to_string()),
        }
    }

    fn try_invoke(&mut self, request: &InvokeRequest) -> Result<InvokeResponse, NativeError> {
        request
            .validate()
            .map_err(|error| NativeError::InvalidRequest(error.to_string()))?;
        let service = self
            .manifest
            .service(&request.service_id)
            .ok_or_else(|| NativeError::ServiceNotFound(request.service_id.clone()))?;
        let method =
            service
                .method(&request.method)
                .ok_or_else(|| NativeError::MethodNotFound {
                    service_id: request.service_id.clone(),
                    method: request.method.clone(),
                })?;

        match service.resolved_main_type().to_ascii_lowercase().as_str() {
            "dll" => self.dll.invoke(
                &self.manifest.plugin_dir,
                service,
                method,
                &request.parameters,
            ),
            "exe" | "bat" => self.process.invoke(
                &self.manifest.plugin_dir,
                service,
                method,
                &request.parameters,
            ),
            "ocx" | "com" => self.com.invoke(service, method, &request.parameters),
            other => Err(NativeError::Unsupported(format!(
                "mainClass type [{other}] is not supported"
            ))),
        }
    }
}

#[derive(Debug, Error)]
pub enum NativeError {
    #[error("invalid invoke request: {0}")]
    InvalidRequest(String),
    #[error("service [{0}] could not find!")]
    ServiceNotFound(String),
    #[error("method [{method}] does not exist on service [{service_id}]")]
    MethodNotFound { service_id: String, method: String },
    #[error("native component path escaped the plugin directory: {0:?}")]
    PathEscape(std::path::PathBuf),
    #[error("native component does not exist: {0:?}")]
    MissingComponent(std::path::PathBuf),
    #[error("invalid parameter [{name}]: {message}")]
    InvalidParameter { name: String, message: String },
    #[error("unsupported native operation: {0}")]
    Unsupported(String),
    #[error("native DLL error: {0}")]
    Dll(String),
    #[error("native COM/OCX error: {0}")]
    Com(String),
    #[error("native process error: {0}")]
    Process(String),
}

impl NativeError {
    fn code(&self) -> i32 {
        match self {
            Self::InvalidRequest(_) | Self::InvalidParameter { .. } => -32602,
            Self::ServiceNotFound(_) | Self::MethodNotFound { .. } => -32601,
            Self::Unsupported(_) => -32004,
            Self::PathEscape(_)
            | Self::MissingComponent(_)
            | Self::Dll(_)
            | Self::Com(_)
            | Self::Process(_) => -32005,
        }
    }
}

fn resolve_component(
    plugin_dir: &std::path::Path,
    main_class: &str,
) -> Result<std::path::PathBuf, NativeError> {
    let root = plugin_dir
        .canonicalize()
        .map_err(|_| NativeError::MissingComponent(plugin_dir.to_path_buf()))?;
    let candidate = plugin_dir.join(main_class);
    let component = candidate
        .canonicalize()
        .map_err(|_| NativeError::MissingComponent(candidate.clone()))?;
    if !component.starts_with(&root) {
        return Err(NativeError::PathEscape(component));
    }
    Ok(component)
}

fn resolve_component_with_extension(
    plugin_dir: &std::path::Path,
    main_class: &str,
    extension: &str,
) -> Result<std::path::PathBuf, NativeError> {
    let direct = plugin_dir.join(main_class);
    if direct.is_file()
        || main_class
            .to_ascii_lowercase()
            .ends_with(&format!(".{extension}"))
    {
        return resolve_component(plugin_dir, main_class);
    }
    resolve_component(plugin_dir, &format!("{main_class}.{extension}"))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn resolves_legacy_component_names_without_an_extension() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("reader.dll"), b"fixture").unwrap();

        let component =
            resolve_component_with_extension(directory.path(), "reader", "dll").unwrap();

        assert!(component.ends_with("reader.dll"));
    }

    #[test]
    fn process_preflight_checks_files_without_executing_them() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("executed");
        let component = directory.path().join("probe.exe");
        fs::write(&component, format!("touch {}", marker.display())).unwrap();
        fs::write(
            directory.path().join("api.json"),
            r#"{"serviceId":"process.probe","mainClass":"probe.exe","mainType":"exe","architecture":"x64","methods":[{"name":"run"}]}"#,
        )
        .unwrap();
        let manifest = PluginManifest::load("process-probe", directory.path()).unwrap();
        let mut plugin = NativePlugin::new(manifest);

        assert_eq!(plugin.preflight(PluginArchitecture::X64).unwrap(), 1);
        assert!(!marker.exists());
        assert!(plugin.preflight(PluginArchitecture::X86).is_err());
    }
}
