//! Reference native plugin that wraps a small, read-only subset of Win32.
//!
//! The exported ABI is intentionally limited to the scalar values, UTF-8
//! strings, and caller-owned output buffers supported by `webplus-native`.

use std::ptr;

const OUTPUT_CAPACITY: usize = 512;
const MAX_INPUT_BYTES: usize = 32 * 1024;
const ERROR_SUCCESS: usize = 0;
#[cfg(not(windows))]
const ERROR_NOT_SUPPORTED: usize = 50;
const ERROR_INVALID_PARAMETER: usize = 87;
const ERROR_INSUFFICIENT_BUFFER: usize = 122;

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;

    #[repr(C)]
    #[derive(Default)]
    struct SystemInfo {
        processor_architecture: u16,
        reserved: u16,
        page_size: u32,
        minimum_application_address: *mut c_void,
        maximum_application_address: *mut c_void,
        active_processor_mask: usize,
        number_of_processors: u32,
        processor_type: u32,
        allocation_granularity: u32,
        processor_level: u16,
        processor_revision: u16,
    }

    #[repr(C)]
    struct MemoryStatusEx {
        length: u32,
        memory_load: u32,
        total_physical: u64,
        available_physical: u64,
        total_page_file: u64,
        available_page_file: u64,
        total_virtual: u64,
        available_virtual: u64,
        available_extended_virtual: u64,
    }

    impl Default for MemoryStatusEx {
        fn default() -> Self {
            Self {
                length: std::mem::size_of::<Self>() as u32,
                memory_load: 0,
                total_physical: 0,
                available_physical: 0,
                total_page_file: 0,
                available_page_file: 0,
                total_virtual: 0,
                available_virtual: 0,
                available_extended_virtual: 0,
            }
        }
    }

    #[link(name = "kernel32")]
    extern "system" {
        #[link_name = "GetCurrentProcessId"]
        fn get_current_process_id() -> u32;
        #[link_name = "GetDiskFreeSpaceExW"]
        fn get_disk_free_space(
            directory_name: *const u16,
            free_bytes_available: *mut u64,
            total_bytes: *mut u64,
            total_free_bytes: *mut u64,
        ) -> i32;
        #[link_name = "GetLastError"]
        fn get_last_error() -> u32;
        #[link_name = "GetNativeSystemInfo"]
        fn get_native_system_info(system_info: *mut SystemInfo);
        #[link_name = "GetTickCount"]
        fn get_tick_count() -> u32;
        #[link_name = "GlobalMemoryStatusEx"]
        fn global_memory_status(status: *mut MemoryStatusEx) -> i32;
    }

    #[link(name = "user32")]
    extern "system" {
        #[link_name = "MessageBoxW"]
        fn message_box(
            window: *mut c_void,
            text: *const u16,
            caption: *const u16,
            message_type: u32,
        ) -> i32;
    }

    pub fn current_process_id() -> usize {
        unsafe { get_current_process_id() as usize }
    }

    pub fn tick_count_ms() -> usize {
        unsafe { get_tick_count() as usize }
    }

    pub fn system_info_json() -> String {
        let mut info = SystemInfo::default();
        unsafe { get_native_system_info(&mut info) };
        let architecture = match info.processor_architecture {
            0 => "x86",
            5 => "arm",
            6 => "ia64",
            9 => "x64",
            12 => "arm64",
            _ => "unknown",
        };
        format!(
            "{{\"architecture\":\"{architecture}\",\"logicalProcessors\":{},\"pageSize\":{},\"allocationGranularity\":{}}}",
            info.number_of_processors, info.page_size, info.allocation_granularity
        )
    }

    pub fn memory_status_json() -> Result<String, usize> {
        let mut status = MemoryStatusEx::default();
        if unsafe { global_memory_status(&mut status) } == 0 {
            return Err(unsafe { get_last_error() as usize });
        }
        Ok(format!(
            "{{\"loadPercent\":{},\"totalPhysicalBytes\":{},\"availablePhysicalBytes\":{}}}",
            status.memory_load, status.total_physical, status.available_physical
        ))
    }

    pub fn disk_space_json(path: &str) -> Result<String, usize> {
        let path = wide_nul(path);
        let mut available = 0_u64;
        let mut total = 0_u64;
        let mut free = 0_u64;
        if unsafe { get_disk_free_space(path.as_ptr(), &mut available, &mut total, &mut free) } == 0
        {
            return Err(unsafe { get_last_error() as usize });
        }
        Ok(format!(
            "{{\"totalBytes\":{total},\"availableBytes\":{available},\"freeBytes\":{free}}}"
        ))
    }

    pub fn show_message(title: &str, message: &str) -> usize {
        const MESSAGE_STYLE: u32 = 0x0000_0040;
        let title = wide_nul(title);
        let message = wide_nul(message);
        unsafe {
            message_box(
                std::ptr::null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MESSAGE_STYLE,
            ) as usize
        }
    }

    fn wide_nul(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

#[cfg(not(windows))]
mod platform {
    use super::ERROR_NOT_SUPPORTED;

    pub fn current_process_id() -> usize {
        std::process::id() as usize
    }

    pub fn tick_count_ms() -> usize {
        0
    }

    pub fn system_info_json() -> String {
        "{\"error\":\"windows-only\"}".into()
    }

    pub fn memory_status_json() -> Result<String, usize> {
        Err(ERROR_NOT_SUPPORTED)
    }

    pub fn disk_space_json(_path: &str) -> Result<String, usize> {
        Err(ERROR_NOT_SUPPORTED)
    }

    pub fn show_message(_title: &str, _message: &str) -> usize {
        ERROR_NOT_SUPPORTED
    }
}

#[export_name = "SsdevGetTickCountMs"]
pub extern "C" fn ssdev_get_tick_count_ms() -> usize {
    platform::tick_count_ms()
}

#[export_name = "SsdevGetCurrentProcessId"]
pub extern "C" fn ssdev_get_current_process_id() -> usize {
    platform::current_process_id()
}

/// Writes a JSON object describing native architecture and processor geometry.
///
/// # Safety
///
/// `output` must point to the 512-byte writable buffer declared in `api.json`.
#[export_name = "SsdevGetSystemInfo"]
pub unsafe extern "C" fn ssdev_get_system_info(output: *mut u8) -> usize {
    unsafe { write_output(output, &platform::system_info_json()) }
}

/// Writes physical memory counters as JSON.
///
/// # Safety
///
/// `output` must point to the 512-byte writable buffer declared in `api.json`.
#[export_name = "SsdevGetMemoryStatus"]
pub unsafe extern "C" fn ssdev_get_memory_status(output: *mut u8) -> usize {
    match platform::memory_status_json() {
        Ok(json) => unsafe { write_output(output, &json) },
        Err(code) => code,
    }
}

/// Reads disk capacity for a UTF-8 path and writes the counters as JSON.
///
/// # Safety
///
/// `path` must be a NUL-terminated UTF-8 string and `output` must point to the
/// 512-byte writable buffer declared in `api.json`.
#[export_name = "SsdevGetDiskSpace"]
pub unsafe extern "C" fn ssdev_get_disk_space(path: *const u8, output: *mut u8) -> usize {
    let path = match unsafe { read_utf8(path) } {
        Ok(path) => path,
        Err(code) => return code,
    };
    match platform::disk_space_json(&path) {
        Ok(json) => unsafe { write_output(output, &json) },
        Err(code) => code,
    }
}

/// Opens a native informational message box to demonstrate a visible Win32
/// side effect. The return value is the Win32 dialog result (`IDOK` is 1).
///
/// # Safety
///
/// `title` and `message` must be NUL-terminated UTF-8 strings.
#[export_name = "SsdevShowMessage"]
pub unsafe extern "C" fn ssdev_show_message(title: *const u8, message: *const u8) -> usize {
    let title = match unsafe { read_utf8(title) } {
        Ok(title) => title,
        Err(code) => return code,
    };
    let message = match unsafe { read_utf8(message) } {
        Ok(message) => message,
        Err(code) => return code,
    };
    platform::show_message(&title, &message)
}

unsafe fn write_output(output: *mut u8, value: &str) -> usize {
    if output.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let bytes = value.as_bytes();
    if bytes.len().saturating_add(1) > OUTPUT_CAPACITY {
        return ERROR_INSUFFICIENT_BUFFER;
    }
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
        *output.add(bytes.len()) = 0;
    }
    ERROR_SUCCESS
}

unsafe fn read_utf8(input: *const u8) -> Result<String, usize> {
    if input.is_null() {
        return Err(ERROR_INVALID_PARAMETER);
    }
    for length in 0..MAX_INPUT_BYTES {
        if unsafe { *input.add(length) } == 0 {
            return std::str::from_utf8(unsafe { std::slice::from_raw_parts(input, length) })
                .map(str::to_owned)
                .map_err(|_| ERROR_INVALID_PARAMETER);
        }
    }
    Err(ERROR_INVALID_PARAMETER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_writer_uses_the_declared_nul_terminated_buffer_contract() {
        let mut output = [0x7f_u8; OUTPUT_CAPACITY];
        assert_eq!(unsafe { write_output(output.as_mut_ptr(), "example") }, 0);
        assert_eq!(&output[..8], b"example\0");
    }

    #[test]
    fn x86_and_x64_templates_expose_the_same_bounded_contract() {
        let templates = [
            (
                "x86",
                include_str!("../../../examples/windows-system-plugin/api.x86.json"),
            ),
            (
                "x64",
                include_str!("../../../examples/windows-system-plugin/api.x64.json"),
            ),
        ];
        for (architecture, document) in templates {
            let value: serde_json::Value = serde_json::from_str(document).unwrap();
            let service = &value[0];
            assert_eq!(service["serviceId"], "windows.system");
            assert_eq!(service["architecture"], architecture);
            assert_eq!(service["callingConvention"], "cdecl");
            let methods = service["methods"].as_array().unwrap();
            assert_eq!(methods.len(), 6);
            assert!(methods
                .iter()
                .any(|method| method["alias"] == "showMessage"));
            for method in methods {
                for parameter in method["parameters"].as_array().unwrap() {
                    if parameter["name"].as_str().unwrap().starts_with('$') {
                        assert_eq!(parameter["len"], OUTPUT_CAPACITY);
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn win32_system_and_memory_exports_return_valid_json() {
        let mut output = [0_u8; OUTPUT_CAPACITY];
        assert_eq!(unsafe { ssdev_get_system_info(output.as_mut_ptr()) }, 0);
        let end = output.iter().position(|byte| *byte == 0).unwrap();
        let system: serde_json::Value = serde_json::from_slice(&output[..end]).unwrap();
        assert!(system["logicalProcessors"].as_u64().unwrap() >= 1);

        output.fill(0);
        assert_eq!(unsafe { ssdev_get_memory_status(output.as_mut_ptr()) }, 0);
        let end = output.iter().position(|byte| *byte == 0).unwrap();
        let memory: serde_json::Value = serde_json::from_slice(&output[..end]).unwrap();
        assert!(memory["totalPhysicalBytes"].as_u64().unwrap() > 0);
    }
}
