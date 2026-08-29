use encoding_rs::GBK;
use serde_json::{Map, Number, Value};
use webplus_plugin_config::{
    MethodDefinition, ParameterDefinition, ParameterDetail, ServiceDefinition,
};
use webplus_protocol::NATIVE_RETURN_VALUE_FIELD;

use crate::NativeError;

const MAX_OUTPUT_BUFFER: usize = 1024 * 1024;

pub(crate) struct PreparedArguments {
    pub words: Vec<usize>,
    allocations: Vec<Allocation>,
    outputs: Vec<OutputBinding>,
}

enum Allocation {
    Bytes(Vec<u8>),
    I32(Box<i32>),
}

struct OutputBinding {
    name: String,
    allocation_index: usize,
    encoding: TextEncoding,
}

#[derive(Clone, Copy)]
enum TextEncoding {
    Utf8,
    Gbk,
}

impl PreparedArguments {
    pub fn build(
        service: &ServiceDefinition,
        method: &MethodDefinition,
        values: &Map<String, Value>,
    ) -> Result<Self, NativeError> {
        let mut prepared = Self {
            words: Vec::with_capacity(method.parameters.len()),
            allocations: Vec::new(),
            outputs: Vec::new(),
        };
        for definition in &method.parameters {
            prepared.push(service, definition, values)?;
        }
        Ok(prepared)
    }

    pub fn collect_outputs(&self) -> Result<Map<String, Value>, NativeError> {
        let mut result = Map::new();
        for output in &self.outputs {
            let value = match &self.allocations[output.allocation_index] {
                Allocation::Bytes(bytes) => {
                    let end = bytes
                        .iter()
                        .position(|byte| *byte == 0)
                        .unwrap_or(bytes.len());
                    Value::String(output.encoding.decode(&bytes[..end]))
                }
                Allocation::I32(value) => Value::Number(Number::from(**value)),
            };
            insert_result_field(&mut result, &output.name, value, "output parameter")?;
        }
        Ok(result)
    }

    fn push(
        &mut self,
        service: &ServiceDefinition,
        definition: &ParameterDefinition,
        values: &Map<String, Value>,
    ) -> Result<(), NativeError> {
        let (raw_name, parameter_type, length, charset) = match definition {
            ParameterDefinition::Name(name) => (
                name.as_str(),
                "inferred",
                1024,
                TextEncoding::from_name(&service.charset),
            ),
            ParameterDefinition::Detailed(detail) => (
                detail.name.as_str(),
                detail.parameter_type.as_str(),
                detail.len,
                TextEncoding::for_parameter(service, detail),
            ),
        };

        if let Some(name) = raw_name.strip_prefix('$') {
            return self.push_output(name, parameter_type, length, charset);
        }
        let value = values.get(raw_name).unwrap_or(&Value::Null);
        self.push_input(raw_name, parameter_type, value, charset)
    }

    fn push_output(
        &mut self,
        name: &str,
        parameter_type: &str,
        length: usize,
        encoding: TextEncoding,
    ) -> Result<(), NativeError> {
        let allocation = match parameter_type.to_ascii_lowercase().as_str() {
            "int" | "int32" | "long" => Allocation::I32(Box::new(0)),
            "string" | "buffer" | "inferred" | "" => {
                if length == 0 || length > MAX_OUTPUT_BUFFER {
                    return Err(NativeError::InvalidParameter {
                        name: name.into(),
                        message: format!(
                            "output buffer length must be between 1 and {MAX_OUTPUT_BUFFER}"
                        ),
                    });
                }
                Allocation::Bytes(vec![0; length])
            }
            other => {
                return Err(NativeError::InvalidParameter {
                    name: name.into(),
                    message: format!("unsupported output type [{other}]"),
                })
            }
        };
        let word = allocation.pointer_word();
        let allocation_index = self.allocations.len();
        self.allocations.push(allocation);
        self.outputs.push(OutputBinding {
            name: name.into(),
            allocation_index,
            encoding,
        });
        self.words.push(word);
        Ok(())
    }

    fn push_input(
        &mut self,
        name: &str,
        parameter_type: &str,
        value: &Value,
        encoding: TextEncoding,
    ) -> Result<(), NativeError> {
        let resolved_type = if parameter_type == "inferred" || parameter_type.is_empty() {
            match value {
                Value::String(_) | Value::Null => "string",
                Value::Bool(_) => "bool",
                Value::Number(_) => "int",
                _ => "unsupported",
            }
        } else {
            parameter_type
        };
        match resolved_type.to_ascii_lowercase().as_str() {
            "string" => {
                let text = value.as_str().unwrap_or_default();
                let allocation = Allocation::Bytes(encoding.encode_nul_terminated(text)?);
                let word = allocation.pointer_word();
                self.allocations.push(allocation);
                self.words.push(word);
            }
            "bool" => self
                .words
                .push(usize::from(value.as_bool().unwrap_or(false))),
            "int" | "int32" | "long" | "uint" | "uint32" => {
                let number = value
                    .as_i64()
                    .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
                    .ok_or_else(|| NativeError::InvalidParameter {
                        name: name.into(),
                        message: "expected an integer".into(),
                    })?;
                self.words.push(number as usize);
            }
            "float" | "double" => {
                return Err(NativeError::InvalidParameter {
                    name: name.into(),
                    message: "floating-point ABI requires a typed signature and is not inferred"
                        .into(),
                })
            }
            other => {
                return Err(NativeError::InvalidParameter {
                    name: name.into(),
                    message: format!("unsupported input type [{other}]"),
                })
            }
        }
        Ok(())
    }
}

impl Allocation {
    fn pointer_word(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.as_ptr() as usize,
            Self::I32(value) => (&**value as *const i32) as usize,
        }
    }
}

impl TextEncoding {
    fn from_name(name: &str) -> Self {
        match name.trim().to_ascii_uppercase().as_str() {
            "GBK" | "GBK_1" | "GBK_2" | "GB2312" => Self::Gbk,
            _ => Self::Utf8,
        }
    }

    fn for_parameter(service: &ServiceDefinition, detail: &ParameterDetail) -> Self {
        detail
            .charset
            .as_deref()
            .or(detail.decode.as_deref())
            .map(Self::from_name)
            .unwrap_or_else(|| Self::from_name(&service.charset))
    }

    fn encode_nul_terminated(self, value: &str) -> Result<Vec<u8>, NativeError> {
        let mut bytes = match self {
            Self::Utf8 => value.as_bytes().to_vec(),
            Self::Gbk => {
                let (encoded, _, had_errors) = GBK.encode(value);
                if had_errors {
                    return Err(NativeError::InvalidParameter {
                        name: "string".into(),
                        message: "text cannot be represented in GBK".into(),
                    });
                }
                encoded.into_owned()
            }
        };
        if bytes.contains(&0) {
            return Err(NativeError::InvalidParameter {
                name: "string".into(),
                message: "embedded NUL byte is not allowed".into(),
            });
        }
        bytes.push(0);
        Ok(bytes)
    }

    fn decode(self, bytes: &[u8]) -> String {
        match self {
            Self::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
            Self::Gbk => GBK.decode(bytes).0.into_owned(),
        }
    }
}

pub(crate) fn insert_result_field(
    data: &mut Map<String, Value>,
    name: &str,
    value: Value,
    source: &str,
) -> Result<(), NativeError> {
    if data.contains_key(name) {
        return Err(NativeError::InvalidParameter {
            name: name.into(),
            message: format!("{source} conflicts with an existing ResData field"),
        });
    }
    data.insert(name.into(), value);
    Ok(())
}

pub(crate) fn result_data(
    return_value: Value,
    mut outputs: Map<String, Value>,
) -> Result<Value, NativeError> {
    insert_result_field(
        &mut outputs,
        NATIVE_RETURN_VALUE_FIELD,
        return_value,
        "native return value",
    )?;
    Ok(Value::Object(outputs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn definitions() -> (ServiceDefinition, MethodDefinition) {
        let service: ServiceDefinition = serde_json::from_value(json!({
            "serviceId": "reader",
            "mainClass": "reader.dll",
            "charset": "GBK",
            "methods": []
        }))
        .unwrap();
        let method: MethodDefinition = serde_json::from_value(json!({
            "name": "Read",
            "parameters": [
                { "name": "timeout", "type": "int32" },
                { "name": "$cardNo", "type": "string", "len": 128 }
            ]
        }))
        .unwrap();
        (service, method)
    }

    #[test]
    fn prepares_integer_and_output_buffer_without_losing_storage() {
        let (service, method) = definitions();
        let values = json!({"timeout": 30}).as_object().unwrap().clone();
        let prepared = PreparedArguments::build(&service, &method, &values).unwrap();

        assert_eq!(prepared.words[0], 30);
        assert_ne!(prepared.words[1], 0);
        assert_eq!(prepared.collect_outputs().unwrap()["cardNo"], "");
    }

    #[test]
    fn refuses_untyped_float_abi() {
        let (service, mut method) = definitions();
        method.parameters = vec![ParameterDefinition::Detailed(ParameterDetail {
            name: "ratio".into(),
            parameter_type: "double".into(),
            len: 8,
            charset: None,
            decode: None,
            extensions: std::collections::HashMap::new(),
        })];
        let values = json!({"ratio": 1.5}).as_object().unwrap().clone();

        assert!(PreparedArguments::build(&service, &method, &values).is_err());
    }

    #[test]
    fn refuses_to_overwrite_native_return_value_at_runtime() {
        let error = result_data(
            json!(42),
            Map::from_iter([(NATIVE_RETURN_VALUE_FIELD.into(), json!("shadow"))]),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            NativeError::InvalidParameter { ref name, .. }
                if name == NATIVE_RETURN_VALUE_FIELD
        ));
    }

    #[test]
    fn refuses_duplicate_dynamic_result_fields_at_runtime() {
        let mut data = Map::new();
        insert_result_field(&mut data, "Count", json!(1), "output parameter").unwrap();

        let error = insert_result_field(&mut data, "Count", json!(2), "COM property").unwrap_err();

        assert!(matches!(
            error,
            NativeError::InvalidParameter { ref name, .. } if name == "Count"
        ));
        assert_eq!(data["Count"], 1);
    }
}
