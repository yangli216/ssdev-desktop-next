use serde_json::{Map, Value};
use webplus_plugin_config::{MethodDefinition, ServiceDefinition};
use webplus_protocol::InvokeResponse;
#[cfg(windows)]
use webplus_protocol::NATIVE_RETURN_VALUE_FIELD;

#[cfg(windows)]
use crate::arguments::insert_result_field;
use crate::NativeError;

pub(crate) struct ComAdapter {
    #[cfg(windows)]
    platform: platform::WindowsComAdapter,
}

impl ComAdapter {
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(windows)]
            platform: platform::WindowsComAdapter::new(),
        }
    }

    pub(crate) fn invoke(
        &mut self,
        service: &ServiceDefinition,
        method: &MethodDefinition,
        parameters: &Map<String, Value>,
    ) -> Result<InvokeResponse, NativeError> {
        #[cfg(windows)]
        {
            self.platform.invoke(service, method, parameters)
        }
        #[cfg(not(windows))]
        {
            let _ = (service, method, parameters);
            Err(NativeError::Unsupported(
                "COM/OCX invocation is only available on Windows".into(),
            ))
        }
    }

    pub(crate) fn preflight(&mut self, service: &ServiceDefinition) -> Result<(), NativeError> {
        #[cfg(windows)]
        {
            self.platform.preflight(service)
        }
        #[cfg(not(windows))]
        {
            let _ = service;
            Err(NativeError::Unsupported(
                "COM/OCX preflight is only available on Windows".into(),
            ))
        }
    }

    pub(crate) fn pump_messages(&mut self) {
        #[cfg(windows)]
        self.platform.pump_messages();
    }
}

#[cfg(windows)]
mod platform {
    use std::collections::HashMap;
    use std::mem::ManuallyDrop;
    use std::ptr;

    use serde_json::{json, Number};
    use windows::core::{BSTR, GUID, PCWSTR};
    use windows::Win32::Foundation::VARIANT_BOOL;
    use windows::Win32::System::Com::{
        CLSIDFromProgID, CLSIDFromString, CoCreateInstance, CoInitializeEx, CoUninitialize,
        IDispatch, CLSCTX_ALL, COINIT_APARTMENTTHREADED, DISPATCH_METHOD, DISPATCH_PROPERTYGET,
        DISPPARAMS, EXCEPINFO,
    };
    use windows::Win32::System::Variant::{
        VARENUM, VARIANT, VARIANT_0, VARIANT_0_0, VARIANT_0_0_0, VT_BOOL, VT_BSTR, VT_BYREF,
        VT_DATE, VT_EMPTY, VT_ERROR, VT_I1, VT_I2, VT_I4, VT_I8, VT_INT, VT_NULL, VT_R4, VT_R8,
        VT_UI1, VT_UI2, VT_UI4, VT_UI8, VT_UINT,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
    };

    use super::*;
    use webplus_plugin_config::{ParameterDefinition, ParameterDetail};

    const LOCALE_USER_DEFAULT: u32 = 0x0400;

    pub(super) struct WindowsComAdapter {
        initialized: bool,
        cache: HashMap<String, IDispatch>,
    }

    impl WindowsComAdapter {
        pub(super) fn new() -> Self {
            Self {
                initialized: false,
                cache: HashMap::new(),
            }
        }

        pub(super) fn invoke(
            &mut self,
            service: &ServiceDefinition,
            method: &MethodDefinition,
            parameters: &Map<String, Value>,
        ) -> Result<InvokeResponse, NativeError> {
            self.ensure_sta()?;
            let dispatch = self.dispatch_for(service)?;
            let mut prepared = PreparedComArguments::build(method, parameters)?;
            let return_value = invoke_member(
                &dispatch,
                &method.name,
                DISPATCH_METHOD,
                &mut prepared.arguments,
            )?;

            let mut data = prepared.collect_outputs()?;
            insert_result_field(
                &mut data,
                NATIVE_RETURN_VALUE_FIELD,
                variant_to_json(&return_value)?,
                "COM return value",
            )?;
            for property in &method.props {
                let value = invoke_member(&dispatch, property, DISPATCH_PROPERTYGET, &mut [])?;
                insert_result_field(
                    &mut data,
                    property,
                    variant_to_json(&value)?,
                    "COM property",
                )?;
            }
            Ok(InvokeResponse::success(Value::Object(data)))
        }

        pub(super) fn preflight(&mut self, service: &ServiceDefinition) -> Result<(), NativeError> {
            self.ensure_sta()?;
            let dispatch = self.dispatch_for(service)?;
            for method in &service.methods {
                resolve_member(&dispatch, &method.name)?;
                for property in &method.props {
                    resolve_member(&dispatch, property)?;
                }
            }
            Ok(())
        }

        pub(super) fn pump_messages(&mut self) {
            if !self.initialized {
                return;
            }
            unsafe {
                let mut message = MSG::default();
                while PeekMessageW(&mut message, None, 0, 0, PM_REMOVE).as_bool() {
                    let _ = TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
            }
        }

        fn ensure_sta(&mut self) -> Result<(), NativeError> {
            if self.initialized {
                return Ok(());
            }
            unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }
                .ok()
                .map_err(|error| NativeError::Com(format!("failed to initialize STA: {error}")))?;
            self.initialized = true;
            Ok(())
        }

        fn dispatch_for(&mut self, service: &ServiceDefinition) -> Result<IDispatch, NativeError> {
            if service.cacheable {
                if let Some(dispatch) = self.cache.get(&service.main_class) {
                    return Ok(dispatch.clone());
                }
            }
            let class_id = resolve_class_id(&service.main_class)?;
            let dispatch: IDispatch = unsafe { CoCreateInstance(&class_id, None, CLSCTX_ALL) }
                .map_err(|error| {
                    NativeError::Com(format!("create [{}]: {error}", service.main_class))
                })?;
            if service.cacheable {
                self.cache
                    .insert(service.main_class.clone(), dispatch.clone());
            }
            Ok(dispatch)
        }
    }

    fn resolve_class_id(identifier: &str) -> Result<GUID, NativeError> {
        let identifier = identifier.trim();
        let wide = wide_nul(identifier)?;
        let result = if identifier.starts_with('{') && identifier.ends_with('}') {
            unsafe { CLSIDFromString(PCWSTR(wide.as_ptr())) }
        } else {
            unsafe { CLSIDFromProgID(PCWSTR(wide.as_ptr())) }
        };
        result.map_err(|error| {
            NativeError::Com(format!("resolve ProgID/CLSID [{identifier}]: {error}"))
        })
    }

    impl Drop for WindowsComAdapter {
        fn drop(&mut self) {
            self.cache.clear();
            if self.initialized {
                unsafe { CoUninitialize() };
            }
        }
    }

    struct PreparedComArguments {
        // COM automation requires arguments in reverse order.
        arguments: Vec<VARIANT>,
        outputs: Vec<OutputBinding>,
    }

    impl PreparedComArguments {
        fn build(
            method: &MethodDefinition,
            values: &Map<String, Value>,
        ) -> Result<Self, NativeError> {
            let mut arguments = Vec::with_capacity(method.parameters.len());
            let mut outputs = Vec::new();
            for definition in &method.parameters {
                let raw_name = definition.name();
                if let Some(name) = raw_name.strip_prefix('$') {
                    let mut output = OutputBinding::new(name, declared_type(definition))?;
                    arguments.push(output.byref_variant());
                    outputs.push(output);
                } else {
                    let value = values.get(raw_name).unwrap_or(&Value::Null);
                    arguments.push(json_to_variant(raw_name, declared_type(definition), value)?);
                }
            }
            arguments.reverse();
            Ok(Self { arguments, outputs })
        }

        fn collect_outputs(&self) -> Result<Map<String, Value>, NativeError> {
            let mut values = Map::new();
            for output in &self.outputs {
                insert_result_field(
                    &mut values,
                    &output.name,
                    output.value()?,
                    "COM output parameter",
                )?;
            }
            Ok(values)
        }
    }

    enum OutputStorage {
        I32(Box<i32>),
        F64(Box<f64>),
        Bool(Box<VARIANT_BOOL>),
        String(Box<BSTR>),
    }

    struct OutputBinding {
        name: String,
        storage: OutputStorage,
    }

    impl OutputBinding {
        fn new(name: &str, parameter_type: &str) -> Result<Self, NativeError> {
            let storage = match parameter_type.trim().to_ascii_lowercase().as_str() {
                "int" | "int32" | "long" => OutputStorage::I32(Box::new(0)),
                "float" | "double" => OutputStorage::F64(Box::new(0.0)),
                "bool" | "boolean" => OutputStorage::Bool(Box::new(VARIANT_BOOL(0))),
                "" | "inferred" | "string" | "buffer" => {
                    OutputStorage::String(Box::new(BSTR::new()))
                }
                other => {
                    return Err(NativeError::InvalidParameter {
                        name: name.into(),
                        message: format!("unsupported COM output type [{other}]"),
                    });
                }
            };
            Ok(Self {
                name: name.into(),
                storage,
            })
        }

        fn byref_variant(&mut self) -> VARIANT {
            match &mut self.storage {
                OutputStorage::I32(value) => byref_variant(VT_I4, value.as_mut() as *mut i32),
                OutputStorage::F64(value) => byref_variant(VT_R8, value.as_mut() as *mut f64),
                OutputStorage::Bool(value) => {
                    byref_variant(VT_BOOL, value.as_mut() as *mut VARIANT_BOOL)
                }
                OutputStorage::String(value) => byref_variant(VT_BSTR, value.as_mut() as *mut BSTR),
            }
        }

        fn value(&self) -> Result<Value, NativeError> {
            match &self.storage {
                OutputStorage::I32(value) => Ok(json!(**value)),
                OutputStorage::F64(value) => Number::from_f64(**value)
                    .map(Value::Number)
                    .ok_or_else(|| NativeError::Com("COM output was NaN or infinite".into())),
                OutputStorage::Bool(value) => Ok(Value::Bool(value.0 != 0)),
                OutputStorage::String(value) => Ok(Value::String(value.to_string())),
            }
        }
    }

    fn byref_variant<T>(base_type: VARENUM, pointer: *mut T) -> VARIANT {
        VARIANT {
            Anonymous: VARIANT_0 {
                Anonymous: ManuallyDrop::new(VARIANT_0_0 {
                    vt: base_type | VT_BYREF,
                    wReserved1: 0,
                    wReserved2: 0,
                    wReserved3: 0,
                    Anonymous: VARIANT_0_0_0 {
                        byref: pointer.cast(),
                    },
                }),
            },
        }
    }

    fn declared_type(definition: &ParameterDefinition) -> &str {
        match definition {
            ParameterDefinition::Name(_) => "inferred",
            ParameterDefinition::Detailed(ParameterDetail { parameter_type, .. }) => parameter_type,
        }
    }

    fn json_to_variant(
        name: &str,
        declared_type: &str,
        value: &Value,
    ) -> Result<VARIANT, NativeError> {
        let kind = declared_type.trim().to_ascii_lowercase();
        match (kind.as_str(), value) {
            (_, Value::Null) => Ok(VARIANT::from("")),
            ("string" | "buffer", Value::String(value)) => Ok(VARIANT::from(value.as_str())),
            ("bool" | "boolean", Value::Bool(value)) => Ok(VARIANT::from(*value)),
            ("int" | "int32" | "long", Value::Number(value)) => value
                .as_i64()
                .and_then(|value| i32::try_from(value).ok())
                .map(VARIANT::from)
                .ok_or_else(|| invalid_value(name, "expected a 32-bit integer")),
            ("float" | "double", Value::Number(value)) => value
                .as_f64()
                .map(VARIANT::from)
                .ok_or_else(|| invalid_value(name, "expected a number")),
            ("" | "inferred", Value::String(value)) => Ok(VARIANT::from(value.as_str())),
            ("" | "inferred", Value::Bool(value)) => Ok(VARIANT::from(*value)),
            ("" | "inferred", Value::Number(value)) => value
                .as_f64()
                .map(VARIANT::from)
                .ok_or_else(|| invalid_value(name, "expected a finite number")),
            (_, _) => Err(invalid_value(
                name,
                &format!("value does not match COM parameter type [{declared_type}]"),
            )),
        }
    }

    fn invalid_value(name: &str, message: &str) -> NativeError {
        NativeError::InvalidParameter {
            name: name.into(),
            message: message.into(),
        }
    }

    fn invoke_member(
        dispatch: &IDispatch,
        member: &str,
        flags: windows::Win32::System::Com::DISPATCH_FLAGS,
        arguments: &mut [VARIANT],
    ) -> Result<VARIANT, NativeError> {
        let dispatch_id = resolve_member(dispatch, member)?;
        let iid_null = GUID::zeroed();

        let parameters = DISPPARAMS {
            rgvarg: arguments.as_mut_ptr(),
            rgdispidNamedArgs: ptr::null_mut(),
            cArgs: arguments.len() as u32,
            cNamedArgs: 0,
        };
        let mut result = VARIANT::default();
        let mut exception = EXCEPINFO::default();
        let mut argument_error = 0;
        let invoke_result = unsafe {
            dispatch.Invoke(
                dispatch_id,
                &iid_null,
                LOCALE_USER_DEFAULT,
                flags,
                &parameters,
                Some(&mut result),
                Some(&mut exception),
                Some(&mut argument_error),
            )
        };
        let exception_text = take_exception_text(&mut exception);
        invoke_result.map_err(|error| {
            let detail = exception_text.unwrap_or_else(|| error.to_string());
            NativeError::Com(format!(
                "invoke member [{member}] failed at argument {argument_error}: {detail}"
            ))
        })?;
        Ok(result)
    }

    fn resolve_member(dispatch: &IDispatch, member: &str) -> Result<i32, NativeError> {
        let member_name = wide_nul(member)?;
        let name = PCWSTR(member_name.as_ptr());
        let mut dispatch_id = 0;
        let iid_null = GUID::zeroed();
        unsafe {
            dispatch.GetIDsOfNames(&iid_null, &name, 1, LOCALE_USER_DEFAULT, &mut dispatch_id)
        }
        .map_err(|error| NativeError::Com(format!("resolve member [{member}]: {error}")))?;
        Ok(dispatch_id)
    }

    fn take_exception_text(exception: &mut EXCEPINFO) -> Option<String> {
        let source = exception.bstrSource.to_string();
        let description = exception.bstrDescription.to_string();
        unsafe {
            ManuallyDrop::drop(&mut exception.bstrSource);
            ManuallyDrop::drop(&mut exception.bstrDescription);
            ManuallyDrop::drop(&mut exception.bstrHelpFile);
        }
        match (source.is_empty(), description.is_empty()) {
            (true, true) => None,
            (false, true) => Some(source),
            (true, false) => Some(description),
            (false, false) => Some(format!("{source}: {description}")),
        }
    }

    fn variant_to_json(value: &VARIANT) -> Result<Value, NativeError> {
        let vt = value.vt();
        let raw = unsafe { &value.Anonymous.Anonymous.Anonymous };
        match vt {
            VT_EMPTY | VT_NULL => Ok(Value::Null),
            VT_BSTR => Ok(Value::String(unsafe { raw.bstrVal.to_string() })),
            VT_BOOL => Ok(Value::Bool(unsafe { raw.boolVal.0 != 0 })),
            VT_I1 => Ok(json!(unsafe { raw.cVal })),
            VT_UI1 => Ok(json!(unsafe { raw.bVal })),
            VT_I2 => Ok(json!(unsafe { raw.iVal })),
            VT_UI2 => Ok(json!(unsafe { raw.uiVal })),
            VT_I4 | VT_INT => Ok(json!(unsafe { raw.lVal })),
            VT_UI4 | VT_UINT => Ok(json!(unsafe { raw.ulVal })),
            VT_I8 => Ok(json!(unsafe { raw.llVal })),
            VT_UI8 => Ok(json!(unsafe { raw.ullVal })),
            VT_R4 => finite_number(f64::from(unsafe { raw.fltVal })),
            VT_R8 | VT_DATE => finite_number(unsafe { raw.dblVal }),
            VT_ERROR => Ok(json!({ "comError": unsafe { raw.scode } })),
            other => Err(NativeError::Com(format!(
                "unsupported COM VARIANT return type {}",
                other.0
            ))),
        }
    }

    fn finite_number(value: f64) -> Result<Value, NativeError> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| NativeError::Com("COM returned NaN or infinity".into()))
    }

    fn wide_nul(value: &str) -> Result<Vec<u16>, NativeError> {
        if value.encode_utf16().any(|unit| unit == 0) {
            return Err(NativeError::Com("COM name contains an embedded NUL".into()));
        }
        Ok(value.encode_utf16().chain(std::iter::once(0)).collect())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn accepts_a_clsid_identifier_without_registry_prog_id_resolution() {
            let resolved = resolve_class_id("{00000000-0000-0000-C000-000000000046}").unwrap();
            assert_eq!(
                resolved,
                GUID::from_u128(0x00000000_0000_0000_c000_000000000046)
            );
        }
    }
}
