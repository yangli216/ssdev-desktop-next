use serde::Serialize;
use webplus_protocol::PluginArchitecture;

const MAX_QUERY_CHARS: usize = 128;
#[cfg(windows)]
const MAX_RESULTS: usize = 100;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ComDiscoveryResult {
    pub components: Vec<ComComponent>,
    pub scanned: usize,
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ComComponent {
    pub clsid: String,
    pub prog_id: Option<String>,
    pub version_independent_prog_id: Option<String>,
    pub display_name: String,
    pub architecture: PluginArchitecture,
    pub component_type: &'static str,
    pub server_type: &'static str,
}

pub(crate) fn discover(
    query: &str,
    architecture: PluginArchitecture,
) -> Result<ComDiscoveryResult, String> {
    let query = query.trim();
    if query.chars().count() < 2 || query.chars().count() > MAX_QUERY_CHARS {
        return Err("COM 搜索词必须是 2 到 128 个字符".into());
    }
    if query.chars().any(char::is_control) {
        return Err("COM 搜索词不能包含控制字符".into());
    }

    #[cfg(windows)]
    {
        platform::discover(query, architecture)
    }
    #[cfg(not(windows))]
    {
        let _ = architecture;
        Err("COM/OCX 自动发现仅在 Windows 上可用".into())
    }
}

#[cfg(windows)]
mod platform {
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, WIN32_ERROR,
    };
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CLASSES_ROOT,
        KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_EXPAND_SZ, REG_SAM_FLAGS, REG_SZ,
        REG_VALUE_TYPE,
    };

    use super::*;

    const MAX_REGISTRY_NAME_CHARS: usize = 512;
    const MAX_REGISTRY_VALUE_BYTES: u32 = 16 * 1024;
    const MAX_SCANNED_CLASSES: usize = 50_000;

    struct RegistryKey(HKEY);

    impl RegistryKey {
        fn open(root: HKEY, path: &str, view: REG_SAM_FLAGS) -> Result<Self, WIN32_ERROR> {
            let path = wide_nul(path);
            let mut key = HKEY::default();
            let status = unsafe {
                RegOpenKeyExW(root, PCWSTR(path.as_ptr()), None, KEY_READ | view, &mut key)
            };
            if status == ERROR_SUCCESS {
                Ok(Self(key))
            } else {
                Err(status)
            }
        }

        fn open_child(&self, path: &str, view: REG_SAM_FLAGS) -> Result<Self, WIN32_ERROR> {
            Self::open(self.0, path, view)
        }

        fn has_child(&self, path: &str, view: REG_SAM_FLAGS) -> bool {
            self.open_child(path, view).is_ok()
        }

        fn default_string(&self) -> Option<String> {
            let mut kind = REG_VALUE_TYPE::default();
            let mut bytes = 0_u32;
            let status = unsafe {
                RegQueryValueExW(
                    self.0,
                    PCWSTR::null(),
                    None,
                    Some(&mut kind),
                    None,
                    Some(&mut bytes),
                )
            };
            if status != ERROR_SUCCESS
                || !matches!(kind, REG_SZ | REG_EXPAND_SZ)
                || bytes == 0
                || bytes > MAX_REGISTRY_VALUE_BYTES
            {
                return None;
            }
            let mut value = vec![0_u16; (bytes as usize).div_ceil(2)];
            let status = unsafe {
                RegQueryValueExW(
                    self.0,
                    PCWSTR::null(),
                    None,
                    Some(&mut kind),
                    Some(value.as_mut_ptr().cast()),
                    Some(&mut bytes),
                )
            };
            if status != ERROR_SUCCESS || !matches!(kind, REG_SZ | REG_EXPAND_SZ) {
                return None;
            }
            let length = value
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(value.len());
            let value = String::from_utf16_lossy(&value[..length]).trim().to_owned();
            (!value.is_empty()).then_some(value)
        }
    }

    impl Drop for RegistryKey {
        fn drop(&mut self) {
            let _ = unsafe { RegCloseKey(self.0) };
        }
    }

    pub(super) fn discover(
        query: &str,
        architecture: PluginArchitecture,
    ) -> Result<ComDiscoveryResult, String> {
        let view = match architecture {
            PluginArchitecture::X86 => KEY_WOW64_32KEY,
            PluginArchitecture::X64 => KEY_WOW64_64KEY,
        };
        let root = RegistryKey::open(HKEY_CLASSES_ROOT, "CLSID", view).map_err(|status| {
            format!(
                "无法读取 {} COM 注册视图（Windows 错误 {}）",
                architecture_label(architecture),
                status.0
            )
        })?;
        let needle = query.to_lowercase();
        let mut components = Vec::new();
        let mut scanned = 0_usize;
        let mut index = 0_u32;
        let mut truncated = false;

        while scanned < MAX_SCANNED_CLASSES {
            let mut name = vec![0_u16; MAX_REGISTRY_NAME_CHARS];
            let mut length = name.len() as u32;
            let status = unsafe {
                RegEnumKeyExW(
                    root.0,
                    index,
                    Some(PWSTR(name.as_mut_ptr())),
                    &mut length,
                    None,
                    None,
                    None,
                    None,
                )
            };
            index = index.saturating_add(1);
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status == ERROR_MORE_DATA {
                continue;
            }
            if status != ERROR_SUCCESS {
                continue;
            }
            scanned = scanned.saturating_add(1);
            let clsid = String::from_utf16_lossy(&name[..length as usize]);
            let Ok(class_key) = root.open_child(&clsid, view) else {
                continue;
            };
            let display_name = class_key.default_string().unwrap_or_default();
            let prog_id = child_default(&class_key, "ProgID", view);
            let version_independent_prog_id =
                child_default(&class_key, "VersionIndependentProgID", view);
            if !matches_query(
                &needle,
                &clsid,
                &display_name,
                prog_id.as_deref(),
                version_independent_prog_id.as_deref(),
            ) {
                continue;
            }
            let component_type = if class_key.has_child("Control", view) {
                "ocx"
            } else {
                "com"
            };
            let server_type = if class_key.has_child("InprocServer32", view) {
                "in-process"
            } else if class_key.has_child("LocalServer32", view) {
                "local-process"
            } else {
                "unknown"
            };
            components.push(ComComponent {
                clsid,
                prog_id,
                version_independent_prog_id,
                display_name,
                architecture,
                component_type,
                server_type,
            });
            if components.len() == MAX_RESULTS {
                truncated = true;
                break;
            }
        }
        if scanned == MAX_SCANNED_CLASSES {
            truncated = true;
        }
        components.sort_by(|left, right| {
            left.prog_id
                .as_deref()
                .unwrap_or(&left.clsid)
                .to_ascii_lowercase()
                .cmp(
                    &right
                        .prog_id
                        .as_deref()
                        .unwrap_or(&right.clsid)
                        .to_ascii_lowercase(),
                )
        });
        Ok(ComDiscoveryResult {
            components,
            scanned,
            truncated,
        })
    }

    fn child_default(parent: &RegistryKey, path: &str, view: REG_SAM_FLAGS) -> Option<String> {
        parent
            .open_child(path, view)
            .ok()
            .and_then(|key| key.default_string())
    }

    fn matches_query(
        needle: &str,
        clsid: &str,
        display_name: &str,
        prog_id: Option<&str>,
        version_independent_prog_id: Option<&str>,
    ) -> bool {
        [
            Some(clsid),
            Some(display_name),
            prog_id,
            version_independent_prog_id,
        ]
        .into_iter()
        .flatten()
        .any(|value| value.to_lowercase().contains(needle))
    }

    fn architecture_label(architecture: PluginArchitecture) -> &'static str {
        match architecture {
            PluginArchitecture::X86 => "x86",
            PluginArchitecture::X64 => "x64",
        }
    }

    fn wide_nul(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_terms_are_bounded_before_platform_access() {
        assert!(discover("x", PluginArchitecture::X64).is_err());
        assert!(discover(&"x".repeat(129), PluginArchitecture::X86).is_err());
        assert!(discover("line\nbreak", PluginArchitecture::X64).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn finds_the_standard_scripting_dictionary_in_both_registry_views() {
        for architecture in [PluginArchitecture::X86, PluginArchitecture::X64] {
            let result = discover("Scripting.Dictionary", architecture).unwrap();
            assert!(result.components.iter().any(|component| {
                component
                    .prog_id
                    .as_deref()
                    .is_some_and(|prog_id| prog_id.eq_ignore_ascii_case("Scripting.Dictionary"))
            }));
        }
    }
}
