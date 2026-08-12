use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

/// Version of the private controller <-> plugin-host framed IPC protocol.
/// This is intentionally independent from the public business Web Bridge.
pub const HOST_PROTOCOL_VERSION: u16 = 1;
pub const MAX_INVOKE_PARAMETERS_BYTES: usize = 8 * 1024 * 1024;
const MAX_ROUTING_FIELD_CHARS: usize = 256;
const MAX_PARAMETER_COUNT: usize = 256;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvokeRequest {
    #[serde(rename = "serviceId")]
    pub service_id: String,
    pub method: String,
    #[serde(default)]
    pub parameters: Map<String, Value>,
}

impl InvokeRequest {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.service_id.trim().is_empty() {
            return Err(ValidationError::EmptyServiceId);
        }
        if self.method.trim().is_empty() {
            return Err(ValidationError::EmptyMethod);
        }
        if self.service_id.chars().count() > MAX_ROUTING_FIELD_CHARS {
            return Err(ValidationError::ServiceIdTooLong);
        }
        if self.method.chars().count() > MAX_ROUTING_FIELD_CHARS {
            return Err(ValidationError::MethodTooLong);
        }
        if self.parameters.len() > MAX_PARAMETER_COUNT {
            return Err(ValidationError::TooManyParameters);
        }
        let parameter_bytes = serde_json::to_vec(&self.parameters)
            .map_err(|error| ValidationError::InvalidParameters(error.to_string()))?
            .len();
        if parameter_bytes > MAX_INVOKE_PARAMETERS_BYTES {
            return Err(ValidationError::ParametersTooLarge {
                actual: parameter_bytes,
                limit: MAX_INVOKE_PARAMETERS_BYTES,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvokeResponse {
    #[serde(rename = "ResCode")]
    pub res_code: i32,
    #[serde(rename = "ResData")]
    pub res_data: Value,
}

impl InvokeResponse {
    pub fn success(data: impl Into<Value>) -> Self {
        Self {
            res_code: 0,
            res_data: data.into(),
        }
    }

    pub fn error(code: i32, message: impl Into<String>) -> Self {
        Self {
            res_code: code,
            res_data: Value::String(message.into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginArchitecture {
    X86,
    X64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostRequest {
    pub protocol_version: u16,
    pub request_id: u64,
    #[serde(flatten)]
    pub command: HostCommand,
}

impl HostRequest {
    pub fn new(request_id: u64, command: HostCommand) -> Self {
        Self {
            protocol_version: HOST_PROTOCOL_VERSION,
            request_id,
            command,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum HostCommand {
    Health,
    Invoke {
        plugin_id: String,
        request: InvokeRequest,
    },
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostResponse {
    pub protocol_version: u16,
    pub request_id: u64,
    #[serde(flatten)]
    pub result: HostResult,
}

impl HostResponse {
    pub fn ok(request_id: u64, payload: HostPayload) -> Self {
        Self {
            protocol_version: HOST_PROTOCOL_VERSION,
            request_id,
            result: HostResult::Ok { payload },
        }
    }

    pub fn error(request_id: u64, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            protocol_version: HOST_PROTOCOL_VERSION,
            request_id,
            result: HostResult::Error {
                error: HostError {
                    code: code.into(),
                    message: message.into(),
                },
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HostResult {
    Ok { payload: HostPayload },
    Error { error: HostError },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostPayload {
    Health { plugin_id: String },
    Invoke { response: InvokeResponse },
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("serviceId must not be empty")]
    EmptyServiceId,
    #[error("method must not be empty")]
    EmptyMethod,
    #[error("serviceId must not exceed 256 characters")]
    ServiceIdTooLong,
    #[error("method must not exceed 256 characters")]
    MethodTooLong,
    #[error("an invoke request may contain at most 256 parameters")]
    TooManyParameters,
    #[error("invoke parameters are not valid JSON: {0}")]
    InvalidParameters(String),
    #[error("invoke parameters size {actual} exceeds limit {limit}")]
    ParametersTooLarge { actual: usize, limit: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_legacy_request_shape() {
        let request: InvokeRequest = serde_json::from_value(json!({
            "serviceId": "card-reader",
            "method": "readCard",
            "parameters": { "timeout": 30 }
        }))
        .unwrap();

        assert_eq!(request.service_id, "card-reader");
        assert_eq!(request.parameters["timeout"], 30);
        assert_eq!(request.validate(), Ok(()));
    }

    #[test]
    fn preserves_legacy_response_field_names() {
        let value = serde_json::to_value(InvokeResponse::success(json!({
            "ReturnValue": 42
        })))
        .unwrap();

        assert_eq!(value["ResCode"], 0);
        assert_eq!(value["ResData"]["ReturnValue"], 42);
        assert!(value.get("res_code").is_none());
    }

    #[test]
    fn rejects_empty_routing_fields() {
        let request = InvokeRequest {
            service_id: " ".into(),
            method: "read".into(),
            parameters: Map::new(),
        };

        assert_eq!(request.validate(), Err(ValidationError::EmptyServiceId));
    }

    #[test]
    fn host_envelope_is_versioned_and_correlated() {
        let message = HostRequest::new(
            17,
            HostCommand::Invoke {
                plugin_id: "reader".into(),
                request: InvokeRequest {
                    service_id: "reader.card".into(),
                    method: "read".into(),
                    parameters: Map::new(),
                },
            },
        );
        let value = serde_json::to_value(message).unwrap();

        assert_eq!(value["protocol_version"], HOST_PROTOCOL_VERSION);
        assert_eq!(value["request_id"], 17);
        assert_eq!(value["command"], "invoke");
    }

    #[test]
    fn rejects_oversized_invoke_parameters_before_process_ipc() {
        let request = InvokeRequest {
            service_id: "reader".into(),
            method: "read".into(),
            parameters: Map::from_iter([(
                "payload".into(),
                Value::String("x".repeat(MAX_INVOKE_PARAMETERS_BYTES)),
            )]),
        };

        assert!(matches!(
            request.validate(),
            Err(ValidationError::ParametersTooLarge { .. })
        ));
    }
}
