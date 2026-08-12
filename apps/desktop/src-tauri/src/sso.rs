use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager};
use url::Url;

use crate::desktop::{self, DesktopState};

const MAX_SSO_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_SSO_REQUEST_FIELD_BYTES: usize = 1024;
const MAX_SSO_RESPONSE_FIELD_BYTES: usize = 16 * 1024;
const SSO_STATUS_EVENT: &str = "desktop://sso-status";

#[derive(Default)]
pub(crate) struct SsoRuntimeState {
    inner: Mutex<SsoRuntime>,
}

#[derive(Default)]
struct SsoRuntime {
    active: bool,
    last_error: Option<&'static str>,
}

impl SsoRuntimeState {
    pub(crate) fn status(&self) -> (bool, Option<&'static str>) {
        let runtime = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (runtime.active, runtime.last_error)
    }

    fn active(&self) -> bool {
        self.status().0
    }

    fn try_begin(&self) -> bool {
        let mut runtime = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if runtime.active {
            return false;
        }
        runtime.active = true;
        runtime.last_error = None;
        true
    }

    fn finish(&self, error: Option<&'static str>) {
        let mut runtime = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        runtime.active = false;
        runtime.last_error = error;
    }

    fn record_error(&self, error: &'static str) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .last_error = Some(error);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SsoArguments {
    login_name: String,
    rid: Option<String>,
    department_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SsoRequest<'a> {
    tenant_id: &'a str,
    login_name: &'a str,
    rid: Option<&'a str>,
    dept_id: Option<&'a str>,
}

#[derive(Deserialize)]
struct SsoEnvelope {
    body: SsoResponse,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SsoResponse {
    uid: Value,
    urt: Value,
    urt_dept: Value,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SsoStatusEvent {
    code: &'static str,
    active: bool,
}

pub(crate) fn start_from_process_arguments(app: &AppHandle) {
    start_from_arguments(app, std::env::args());
}

pub(crate) fn start_from_arguments(app: &AppHandle, arguments: impl IntoIterator<Item = String>) {
    let arguments = match parse_arguments(arguments) {
        Ok(Some(arguments)) => arguments,
        Ok(None) => return,
        Err(()) => {
            record_error(app, "sso-arguments-invalid");
            emit_status(app, "sso-arguments-invalid");
            tracing::warn!(
                event_code = "sso-arguments-invalid",
                "SSO process arguments are invalid"
            );
            return;
        }
    };
    if !try_begin(app) {
        emit_status(app, "sso-already-running");
        tracing::warn!(
            event_code = "sso-already-running",
            "concurrent SSO launch was rejected"
        );
        return;
    }
    emit_status(app, "sso-login-started");
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        match perform(&app, arguments).await {
            Ok(()) => finish(&app, None, "sso-login-succeeded"),
            Err(_) => {
                finish(&app, Some("sso-login-failed"), "sso-login-failed");
                tracing::warn!(event_code = "sso-login-failed", "SSO login failed");
            }
        }
    });
}

fn try_begin(app: &AppHandle) -> bool {
    app.try_state::<SsoRuntimeState>()
        .is_none_or(|state| state.try_begin())
}

fn record_error(app: &AppHandle, error: &'static str) {
    if let Some(state) = app.try_state::<SsoRuntimeState>() {
        state.record_error(error);
    }
}

fn finish(app: &AppHandle, error: Option<&'static str>, event: &'static str) {
    if let Some(state) = app.try_state::<SsoRuntimeState>() {
        state.finish(error);
    }
    emit_status(app, event);
}

fn emit_status(app: &AppHandle, status: &'static str) {
    let active = app
        .try_state::<SsoRuntimeState>()
        .is_some_and(|state| state.active());
    let _ = app.emit(
        SSO_STATUS_EVENT,
        SsoStatusEvent {
            code: status,
            active,
        },
    );
}

async fn perform(app: &AppHandle, arguments: SsoArguments) -> Result<(), String> {
    let state = app.state::<DesktopState>();
    let config = state.config.snapshot();
    let website = config
        .website_url()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "SSO 启动参数存在，但尚未配置业务地址".to_owned())?;
    let endpoint = append_path(&website, "logon/ssoLogin")?;
    require_secure_sso_endpoint(&endpoint)?;
    validate_request_field(&config.tenant_id, true)?;
    validate_request_field(&arguments.login_name, false)?;
    if let Some(value) = &arguments.rid {
        validate_request_field(value, false)?;
    }
    if let Some(value) = &arguments.department_id {
        validate_request_field(value, false)?;
    }
    let client = reqwest::Client::builder()
        .https_only(true)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| error.to_string())?;
    let mut response = client
        .post(endpoint)
        .json(&SsoRequest {
            tenant_id: &config.tenant_id,
            login_name: &arguments.login_name,
            rid: arguments.rid.as_deref(),
            dept_id: arguments.department_id.as_deref(),
        })
        .send()
        .await
        .map_err(|error| format!("SSO 请求失败: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("SSO 服务返回非成功状态 {}", response.status()));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_SSO_RESPONSE_BYTES as u64)
    {
        return Err("SSO 响应超过安全上限".into());
    }
    let mut response_bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("读取 SSO 响应失败: {error}"))?
    {
        append_response_bytes(&mut response_bytes, &chunk)?;
    }
    let response: SsoEnvelope = serde_json::from_slice(&response_bytes)
        .map_err(|error| format!("SSO 响应格式无效: {error}"))?;
    let login_url = build_login_url(&website, &response.body)?;
    desktop::open_business_at(app, &state, login_url)?;
    Ok(())
}

fn append_response_bytes(output: &mut Vec<u8>, chunk: &[u8]) -> Result<(), String> {
    if output.len().saturating_add(chunk.len()) > MAX_SSO_RESPONSE_BYTES {
        return Err("SSO 响应超过安全上限".into());
    }
    output.extend_from_slice(chunk);
    Ok(())
}

fn require_secure_sso_endpoint(endpoint: &Url) -> Result<(), String> {
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
    {
        return Err("SSO 接口必须是无凭据、无片段的 HTTPS URL".into());
    }
    Ok(())
}

fn validate_request_field(value: &str, allow_empty: bool) -> Result<(), String> {
    if (!allow_empty && value.is_empty())
        || value.len() > MAX_SSO_REQUEST_FIELD_BYTES
        || value.chars().any(char::is_control)
    {
        return Err("SSO 请求字段为空、过长或包含控制字符".into());
    }
    Ok(())
}

fn parse_arguments(
    arguments: impl IntoIterator<Item = String>,
) -> Result<Option<SsoArguments>, ()> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    let login_name = unique_value_after(&arguments, "--uid")?;
    let rid = unique_value_after(&arguments, "--rid")?;
    let department_id = unique_value_after(&arguments, "--deptId")?;
    let Some(login_name) = login_name else {
        if rid.is_some() || department_id.is_some() {
            return Err(());
        }
        return Ok(None);
    };
    Ok(Some(SsoArguments {
        login_name,
        rid,
        department_id,
    }))
}

fn unique_value_after(arguments: &[String], name: &str) -> Result<Option<String>, ()> {
    let mut positions = arguments
        .iter()
        .enumerate()
        .filter_map(|(index, argument)| (argument == name).then_some(index));
    let Some(index) = positions.next() else {
        return Ok(None);
    };
    if positions.next().is_some() {
        return Err(());
    }
    let value = arguments.get(index + 1).ok_or(())?;
    if value.starts_with("--") || validate_request_field(value, false).is_err() {
        return Err(());
    }
    Ok(Some(value.clone()))
}

fn append_path(base: &Url, path: &str) -> Result<Url, String> {
    let mut base = base.clone();
    if !base.path().ends_with('/') {
        base.set_path(&format!("{}/", base.path()));
    }
    base.join(path).map_err(|error| error.to_string())
}

fn build_login_url(base: &Url, response: &SsoResponse) -> Result<Url, String> {
    let mut url = append_path(base, "")?;
    url.query_pairs_mut()
        .append_pair("autoLogin", "true")
        .append_pair("uid", &json_scalar(&response.uid)?)
        .append_pair("urt", &json_scalar(&response.urt)?)
        .append_pair("urtDept", &json_scalar(&response.urt_dept)?);
    Ok(url)
}

fn json_scalar(value: &Value) -> Result<String, String> {
    let value = match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        _ => return Err("SSO 响应中的身份字段不是标量".into()),
    };
    if value.is_empty()
        || value.len() > MAX_SSO_RESPONSE_FIELD_BYTES
        || value.chars().any(char::is_control)
    {
        return Err("SSO 响应中的身份字段为空、过长或包含控制字符".into());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_legacy_process_arguments_without_logging_secrets() {
        let parsed = parse_arguments([
            "ssdev.exe".into(),
            "--uid".into(),
            "doctor-a".into(),
            "--rid".into(),
            "role-1".into(),
            "--deptId".into(),
            "dept-2".into(),
        ])
        .unwrap()
        .unwrap();

        assert_eq!(parsed.login_name, "doctor-a");
        assert_eq!(parsed.department_id.as_deref(), Some("dept-2"));
    }

    #[test]
    fn rejects_ambiguous_or_incomplete_sso_process_arguments() {
        assert!(parse_arguments(["ssdev.exe".into()]).unwrap().is_none());
        assert!(parse_arguments(["ssdev.exe".into(), "--uid".into()]).is_err());
        assert!(parse_arguments([
            "ssdev.exe".into(),
            "--uid".into(),
            "--rid".into(),
            "role-1".into(),
        ])
        .is_err());
        assert!(parse_arguments([
            "ssdev.exe".into(),
            "--uid".into(),
            "doctor-a".into(),
            "--uid".into(),
            "doctor-b".into(),
        ])
        .is_err());
        assert!(parse_arguments(["ssdev.exe".into(), "--rid".into(), "role-1".into(),]).is_err());
    }

    #[test]
    fn constructs_encoded_login_url_under_the_configured_base_path() {
        let response = SsoResponse {
            uid: json!("a+b"),
            urt: json!("token&value"),
            urt_dept: json!(7),
        };
        let url = build_login_url(
            &Url::parse("https://example.test/product").unwrap(),
            &response,
        )
        .unwrap();

        assert_eq!(url.path(), "/product/");
        assert!(url.as_str().contains("uid=a%2Bb"));
        assert!(url.as_str().contains("urt=token%26value"));
    }

    #[test]
    fn sso_transport_requires_https_without_url_credentials_or_fragments() {
        assert!(require_secure_sso_endpoint(
            &Url::parse("https://example.test/product/logon/ssoLogin").unwrap()
        )
        .is_ok());
        assert!(require_secure_sso_endpoint(
            &Url::parse("http://example.test/product/logon/ssoLogin").unwrap()
        )
        .is_err());
        assert!(require_secure_sso_endpoint(
            &Url::parse("https://user:secret@example.test/logon/ssoLogin").unwrap()
        )
        .is_err());
        assert!(require_secure_sso_endpoint(
            &Url::parse("https://example.test/logon/ssoLogin#fragment").unwrap()
        )
        .is_err());
    }

    #[test]
    fn sso_request_and_response_fields_are_bounded() {
        assert!(validate_request_field("doctor-a", false).is_ok());
        assert!(validate_request_field("", false).is_err());
        assert!(validate_request_field("", true).is_ok());
        assert!(
            validate_request_field(&"x".repeat(MAX_SSO_REQUEST_FIELD_BYTES + 1), false).is_err()
        );
        assert!(json_scalar(&json!("token")).is_ok());
        assert!(json_scalar(&json!("")).is_err());
        assert!(json_scalar(&json!("x".repeat(MAX_SSO_RESPONSE_FIELD_BYTES + 1))).is_err());
        assert!(json_scalar(&json!({"nested": true})).is_err());

        let mut response = vec![b'x'; MAX_SSO_RESPONSE_BYTES - 1];
        assert!(append_response_bytes(&mut response, b"x").is_ok());
        assert!(append_response_bytes(&mut response, b"x").is_err());
        assert_eq!(response.len(), MAX_SSO_RESPONSE_BYTES);
    }

    #[test]
    fn sso_runtime_state_retains_only_a_generic_error_code() {
        let state = SsoRuntimeState::default();
        assert_eq!(state.status(), (false, None));
        assert!(state.try_begin());
        assert_eq!(state.status(), (true, None));
        assert!(!state.try_begin());
        state.finish(Some("sso-login-failed"));
        assert_eq!(state.status(), (false, Some("sso-login-failed")));
        assert!(state.try_begin());
        assert_eq!(state.status(), (true, None));
    }
}
