use serde_json::{Map, Value};
use webplus_plugin_config::{validate_dll_abi, MethodDefinition, ServiceDefinition};
use webplus_protocol::InvokeResponse;

use crate::NativeError;

pub(crate) struct DllAdapter {
    platform: platform::DllAdapter,
}

impl DllAdapter {
    pub(crate) fn new() -> Self {
        Self {
            platform: platform::DllAdapter::new(),
        }
    }

    pub(crate) fn invoke(
        &mut self,
        plugin_dir: &std::path::Path,
        service: &ServiceDefinition,
        method: &MethodDefinition,
        parameters: &Map<String, Value>,
    ) -> Result<InvokeResponse, NativeError> {
        validate_dll_declaration(service)?;
        self.platform
            .invoke(plugin_dir, service, method, parameters)
    }

    pub(crate) fn preflight(
        &mut self,
        plugin_dir: &std::path::Path,
        service: &ServiceDefinition,
    ) -> Result<(), NativeError> {
        validate_dll_declaration(service)?;
        self.platform.preflight(plugin_dir, service)
    }
}

fn validate_dll_declaration(service: &ServiceDefinition) -> Result<(), NativeError> {
    validate_dll_abi(service).map_err(NativeError::Dll)
}

#[cfg(not(windows))]
mod platform {
    use super::*;

    pub struct DllAdapter;

    impl DllAdapter {
        pub fn new() -> Self {
            Self
        }

        pub fn invoke(
            &mut self,
            _plugin_dir: &std::path::Path,
            _service: &ServiceDefinition,
            _method: &MethodDefinition,
            _parameters: &Map<String, Value>,
        ) -> Result<InvokeResponse, NativeError> {
            Err(NativeError::Unsupported(
                "DLL invocation is only available on Windows".into(),
            ))
        }

        pub fn preflight(
            &mut self,
            _plugin_dir: &std::path::Path,
            _service: &ServiceDefinition,
        ) -> Result<(), NativeError> {
            Err(NativeError::Unsupported(
                "DLL preflight is only available on Windows".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preflight_rejects_abi_shapes_the_runtime_cannot_call() {
        let float_return: ServiceDefinition = serde_json::from_value(serde_json::json!({
            "serviceId": "fixture",
            "mainClass": "fixture.dll",
            "methods": [{"name": "Read", "returnType": "double"}]
        }))
        .unwrap();
        assert!(validate_dll_declaration(&float_return).is_err());

        let too_many: ServiceDefinition = serde_json::from_value(serde_json::json!({
            "serviceId": "fixture",
            "mainClass": "fixture.dll",
            "methods": [{
                "name": "Read",
                "parameters": ["a","b","c","d","e","f","g","h","i","j","k","l","m"]
            }]
        }))
        .unwrap();
        assert!(validate_dll_declaration(&too_many).is_err());
    }
}

#[cfg(windows)]
mod platform {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    use super::*;
    use encoding_rs::GBK;
    use libloading::os::windows::{Library, Symbol, LOAD_WITH_ALTERED_SEARCH_PATH};
    use serde_json::Number;

    use crate::arguments::{result_data, PreparedArguments};
    use crate::{resolve_component, resolve_component_with_extension};

    const MAX_RETURN_STRING_BYTES: usize = 1024 * 1024;

    macro_rules! word_type {
        ($index:tt) => {
            usize
        };
    }

    macro_rules! invoke_symbol {
        ($library:expr, $name:expr, $abi:literal, $args:expr, ($($index:tt),*)) => {{
            type Function = unsafe extern $abi fn($(word_type!($index)),*) -> usize;
            let function: Symbol<Function> = unsafe {
                $library
                    .get($name)
                    .map_err(|error| NativeError::Dll(error.to_string()))?
            };
            unsafe { function($($args[$index]),*) }
        }};
    }

    macro_rules! call_with_abi {
        ($library:expr, $name:expr, $args:expr, $abi:literal) => {{
            let args: &[usize] = $args;
            let value = match args.len() {
                0 => invoke_symbol!($library, $name, $abi, args, ()),
                1 => invoke_symbol!($library, $name, $abi, args, (0)),
                2 => invoke_symbol!($library, $name, $abi, args, (0, 1)),
                3 => invoke_symbol!($library, $name, $abi, args, (0, 1, 2)),
                4 => invoke_symbol!($library, $name, $abi, args, (0, 1, 2, 3)),
                5 => invoke_symbol!($library, $name, $abi, args, (0, 1, 2, 3, 4)),
                6 => invoke_symbol!($library, $name, $abi, args, (0, 1, 2, 3, 4, 5)),
                7 => invoke_symbol!($library, $name, $abi, args, (0, 1, 2, 3, 4, 5, 6)),
                8 => invoke_symbol!($library, $name, $abi, args, (0, 1, 2, 3, 4, 5, 6, 7)),
                9 => invoke_symbol!($library, $name, $abi, args, (0, 1, 2, 3, 4, 5, 6, 7, 8)),
                10 => invoke_symbol!($library, $name, $abi, args, (0, 1, 2, 3, 4, 5, 6, 7, 8, 9)),
                11 => invoke_symbol!(
                    $library,
                    $name,
                    $abi,
                    args,
                    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
                ),
                12 => invoke_symbol!(
                    $library,
                    $name,
                    $abi,
                    args,
                    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
                ),
                count => {
                    return Err(NativeError::Dll(format!(
                        "method [{}] has {count} arguments; maximum is 12",
                        String::from_utf8_lossy($name)
                    )))
                }
            };
            Ok(value)
        }};
    }

    pub struct DllAdapter {
        dependencies: HashMap<PathBuf, Library>,
        libraries: HashMap<PathBuf, Library>,
    }

    impl DllAdapter {
        pub fn new() -> Self {
            Self {
                dependencies: HashMap::new(),
                libraries: HashMap::new(),
            }
        }

        pub fn preflight(
            &mut self,
            plugin_dir: &Path,
            service: &ServiceDefinition,
        ) -> Result<(), NativeError> {
            let library = self.library_for(plugin_dir, service)?;
            for method in &service.methods {
                let _: Symbol<*const ()> = unsafe {
                    library
                        .get(method.name.as_bytes())
                        .map_err(|error| NativeError::Dll(error.to_string()))?
                };
            }
            Ok(())
        }

        pub fn invoke(
            &mut self,
            plugin_dir: &Path,
            service: &ServiceDefinition,
            method: &MethodDefinition,
            parameters: &Map<String, Value>,
        ) -> Result<InvokeResponse, NativeError> {
            let library = self.library_for(plugin_dir, service)?;
            let prepared = PreparedArguments::build(service, method, parameters)?;
            let convention = service.calling_convention.trim().to_ascii_lowercase();
            let return_word = match convention.as_str() {
                "c" | "cdecl" => {
                    call_with_abi!(library, method.name.as_bytes(), &prepared.words, "C")
                }
                "" | "system" | "stdcall" | "winapi" => {
                    call_with_abi!(library, method.name.as_bytes(), &prepared.words, "system")
                }
                other => {
                    return Err(NativeError::Dll(format!(
                        "unsupported calling convention [{other}]"
                    )))
                }
            }?;
            let return_value =
                convert_return_value(return_word, &method.return_type, &service.charset)?;
            Ok(InvokeResponse::success(result_data(
                return_value,
                prepared.collect_outputs()?,
            )?))
        }

        fn library_for(
            &mut self,
            plugin_dir: &Path,
            service: &ServiceDefinition,
        ) -> Result<&Library, NativeError> {
            self.preload_dependencies(plugin_dir, service)?;
            let component =
                resolve_component_with_extension(plugin_dir, &service.main_class, "dll")?;
            if !self.libraries.contains_key(&component) {
                let library = unsafe {
                    Library::load_with_flags(&component, LOAD_WITH_ALTERED_SEARCH_PATH)
                        .map_err(|error| NativeError::Dll(error.to_string()))?
                };
                self.libraries.insert(component.clone(), library);
            }
            Ok(self
                .libraries
                .get(&component)
                .expect("library was inserted before lookup"))
        }

        fn preload_dependencies(
            &mut self,
            plugin_dir: &Path,
            service: &ServiceDefinition,
        ) -> Result<(), NativeError> {
            for dependency in dependency_paths(plugin_dir, &service.deps)? {
                if self.dependencies.contains_key(&dependency) {
                    continue;
                }
                let library = unsafe {
                    Library::load_with_flags(&dependency, LOAD_WITH_ALTERED_SEARCH_PATH).map_err(
                        |error| {
                            NativeError::Dll(format!(
                                "failed to preload dependency {dependency:?}: {error}"
                            ))
                        },
                    )?
                };
                self.dependencies.insert(dependency, library);
            }
            Ok(())
        }
    }

    fn dependency_paths(plugin_dir: &Path, deps: &[String]) -> Result<Vec<PathBuf>, NativeError> {
        let mut paths = Vec::new();
        for dependency in deps {
            if dependency == "*" {
                let mut discovered = Vec::new();
                collect_dlls(plugin_dir, &mut discovered)?;
                discovered.sort();
                for path in discovered {
                    if !paths.contains(&path) {
                        paths.push(path);
                    }
                }
            } else {
                let path = resolve_component(plugin_dir, dependency)?;
                if !paths.contains(&path) {
                    paths.push(path);
                }
            }
        }
        Ok(paths)
    }

    fn collect_dlls(directory: &Path, paths: &mut Vec<PathBuf>) -> Result<(), NativeError> {
        let entries = std::fs::read_dir(directory).map_err(|error| {
            NativeError::Dll(format!(
                "failed to enumerate dependency directory {directory:?}: {error}"
            ))
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                NativeError::Dll(format!(
                    "failed to enumerate dependency directory {directory:?}: {error}"
                ))
            })?;
            let file_type = entry.file_type().map_err(|error| {
                NativeError::Dll(format!(
                    "failed to inspect dependency {:?}: {error}",
                    entry.path()
                ))
            })?;
            if file_type.is_dir() {
                collect_dlls(&entry.path(), paths)?;
            } else if file_type.is_file()
                && entry
                    .path()
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("dll"))
            {
                paths.push(resolve_component(
                    directory,
                    &entry.file_name().to_string_lossy(),
                )?);
            }
        }
        Ok(())
    }

    fn convert_return_value(
        word: usize,
        return_type: &str,
        charset: &str,
    ) -> Result<Value, NativeError> {
        match return_type.trim().to_ascii_lowercase().as_str() {
            "void" => Ok(Value::Null),
            "string" | "char*" | "pointer_string" => {
                if word == 0 {
                    return Ok(Value::Null);
                }
                let bytes = unsafe { read_bounded_c_string(word as *const u8) };
                let text = match charset.trim().to_ascii_uppercase().as_str() {
                    "GBK" | "GBK_1" | "GBK_2" | "GB2312" => GBK.decode(bytes).0.into_owned(),
                    _ => String::from_utf8_lossy(bytes).into_owned(),
                };
                Ok(Value::String(text))
            }
            "bool" | "boolean" => Ok(Value::Bool(word != 0)),
            "" | "int" | "int32" | "long" => Ok(Value::Number(Number::from(word as i32))),
            "uint" | "uint32" | "dword" => Ok(Value::Number(Number::from(word as u32))),
            "pointer" | "uintptr" | "usize" => Ok(Value::Number(Number::from(word as u64))),
            "float" | "double" => Err(NativeError::Dll(
                "floating-point returns require a typed ABI signature and are not inferred".into(),
            )),
            other => Err(NativeError::Dll(format!(
                "unsupported DLL return type [{other}]"
            ))),
        }
    }

    unsafe fn read_bounded_c_string(pointer: *const u8) -> &'static [u8] {
        let mut length = 0;
        while length < MAX_RETURN_STRING_BYTES && unsafe { *pointer.add(length) } != 0 {
            length += 1;
        }
        unsafe { std::slice::from_raw_parts(pointer, length) }
    }
}
