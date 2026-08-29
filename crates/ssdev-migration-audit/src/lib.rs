use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::Serialize;
use serde_json::Value;
use ssdev_config::DesktopConfig;
use ssdev_origin_policy::OriginPolicy;
use webplus_plugin_config::PluginManifest;

const MAX_INPUT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_HAR_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BROWSER_ASSET_BYTES: u64 = 4 * 1024 * 1024;
const MAX_BROWSER_ASSET_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
const MAX_BROWSER_ASSET_FILES: usize = 20_000;
const MAX_HAR_REQUESTS: usize = 100_000;

#[derive(Debug, Default)]
pub struct AuditInputs {
    pub configs: Vec<PathBuf>,
    pub plugin_roots: Vec<PathBuf>,
    pub keymaps: Vec<PathBuf>,
    pub browser_asset_roots: Vec<PathBuf>,
    pub browser_hars: Vec<PathBuf>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditReport {
    pub schema_version: u8,
    pub summary: AuditSummary,
    pub configs: Vec<ConfigAudit>,
    pub plugins: Vec<PluginAudit>,
    pub key_bindings: Vec<KeyBindingAudit>,
    pub browser_compatibility: BrowserCompatibilityAudit,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_policy: Option<OriginPolicyAudit>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OriginPolicyAudit {
    pub document_sha256: String,
    pub insecure_http_origin_count: usize,
    pub authorized_insecure_http_origin_count: usize,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditSummary {
    pub config_files: usize,
    pub plugin_directories: usize,
    pub services: usize,
    pub key_bindings: usize,
    pub browser_asset_files: usize,
    pub browser_har_requests: usize,
    pub legacy_http_evidence: usize,
    pub critical_findings: usize,
    pub warning_findings: usize,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserCompatibilityAudit {
    pub asset_roots: usize,
    pub asset_files_scanned: usize,
    pub asset_files_skipped: usize,
    pub asset_bytes_scanned: u64,
    pub har_files: usize,
    pub har_requests_scanned: usize,
    pub har_requests_skipped: usize,
    pub webplus_static_reference_files: usize,
    pub webplus_runtime_requests: usize,
    pub desktop_callback_static_reference_files: usize,
    pub desktop_callback_runtime_requests: usize,
    pub evidence_counts: BTreeMap<String, usize>,
    pub webplus_http_evidence: EvidenceLevel,
    pub desktop_callback_http_evidence: EvidenceLevel,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EvidenceLevel {
    ConfirmedRuntime,
    StaticReferences,
    #[default]
    NotObserved,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigAudit {
    pub source: PathBuf,
    pub readable: bool,
    pub website_configured: bool,
    pub environment_count: usize,
    pub legacy_process_count: usize,
    pub insecure_http_origin_count: usize,
    pub authorized_insecure_http_origin_count: usize,
    pub origin_policy_authorized: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginAudit {
    pub plugin_id: String,
    pub source: PathBuf,
    pub parseable_by_next: bool,
    pub parse_error: Option<String>,
    pub has_legacy_license: bool,
    pub has_version_metadata: bool,
    pub has_signature_envelope: bool,
    pub services: Vec<ServiceAudit>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAudit {
    pub service_id: String,
    pub main_type: String,
    pub declared_architecture: String,
    pub detected_pe_architecture: Option<String>,
    pub method_count: usize,
    pub has_install_run: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyBindingAudit {
    pub source: PathBuf,
    pub name: String,
    pub old_key: String,
    pub new_key: String,
    pub active: bool,
    pub contains_script: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub severity: Severity,
    pub code: &'static str,
    pub source: PathBuf,
    pub message: String,
    pub remediation: &'static str,
}

pub fn audit(inputs: &AuditInputs) -> AuditReport {
    audit_inner(inputs, None)
}

pub fn audit_with_verified_origin_policy(
    inputs: &AuditInputs,
    policy: &OriginPolicy,
    document_sha256: String,
) -> AuditReport {
    audit_inner(inputs, Some((policy, document_sha256)))
}

fn audit_inner(
    inputs: &AuditInputs,
    verified_origin_policy: Option<(&OriginPolicy, String)>,
) -> AuditReport {
    let mut report = AuditReport {
        schema_version: 3,
        summary: AuditSummary::default(),
        configs: Vec::new(),
        plugins: Vec::new(),
        key_bindings: Vec::new(),
        browser_compatibility: BrowserCompatibilityAudit::default(),
        origin_policy: None,
        findings: Vec::new(),
    };
    for path in &inputs.configs {
        audit_config(
            path,
            verified_origin_policy.as_ref().map(|(policy, _)| *policy),
            &mut report,
        );
    }
    for root in &inputs.plugin_roots {
        audit_plugin_root(root, &mut report);
    }
    for path in &inputs.keymaps {
        audit_keymap(path, &mut report);
    }
    let mut browser_compatibility = BrowserCompatibilityAudit {
        asset_roots: inputs.browser_asset_roots.len(),
        har_files: inputs.browser_hars.len(),
        ..BrowserCompatibilityAudit::default()
    };
    for root in &inputs.browser_asset_roots {
        audit_browser_asset_root(root, &mut browser_compatibility, &mut report.findings);
    }
    for path in &inputs.browser_hars {
        audit_browser_har(path, &mut browser_compatibility, &mut report.findings);
    }
    finalize_browser_compatibility(inputs, &mut browser_compatibility, &mut report.findings);
    report.browser_compatibility = browser_compatibility;
    report.summary.config_files = report.configs.len();
    report.summary.plugin_directories = report.plugins.len();
    report.summary.services = report
        .plugins
        .iter()
        .map(|plugin| plugin.services.len())
        .sum();
    report.summary.key_bindings = report.key_bindings.len();
    report.summary.browser_asset_files = report.browser_compatibility.asset_files_scanned;
    report.summary.browser_har_requests = report.browser_compatibility.har_requests_scanned;
    report.summary.legacy_http_evidence = report
        .browser_compatibility
        .evidence_counts
        .values()
        .copied()
        .sum();
    report.summary.critical_findings = report
        .findings
        .iter()
        .filter(|finding| finding.severity == Severity::Critical)
        .count();
    report.summary.warning_findings = report
        .findings
        .iter()
        .filter(|finding| finding.severity == Severity::Warning)
        .count();
    if let Some((_, document_sha256)) = verified_origin_policy {
        report.origin_policy = Some(OriginPolicyAudit {
            document_sha256,
            insecure_http_origin_count: report
                .configs
                .iter()
                .map(|config| config.insecure_http_origin_count)
                .sum(),
            authorized_insecure_http_origin_count: report
                .configs
                .iter()
                .map(|config| config.authorized_insecure_http_origin_count)
                .sum(),
        });
    }
    report
}

fn audit_browser_asset_root(
    root: &Path,
    audit: &mut BrowserCompatibilityAudit,
    findings: &mut Vec<Finding>,
) {
    let mut stack = vec![root.to_path_buf()];
    let skipped_before = audit.asset_files_skipped;
    let mut limit_reached = false;
    while let Some(path) = stack.pop() {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => {
                audit.asset_files_skipped += 1;
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            audit.asset_files_skipped += 1;
            continue;
        }
        if metadata.is_dir() {
            let mut entries = match fs::read_dir(&path) {
                Ok(entries) => entries.filter_map(Result::ok).collect::<Vec<_>>(),
                Err(_) => {
                    audit.asset_files_skipped += 1;
                    continue;
                }
            };
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries.into_iter().rev() {
                stack.push(entry.path());
            }
            continue;
        }
        if !metadata.is_file() || !is_browser_asset(&path) {
            continue;
        }
        if audit.asset_files_scanned >= MAX_BROWSER_ASSET_FILES
            || audit.asset_bytes_scanned.saturating_add(metadata.len())
                > MAX_BROWSER_ASSET_TOTAL_BYTES
        {
            audit.asset_files_skipped += 1;
            limit_reached = true;
            continue;
        }
        if metadata.len() > MAX_BROWSER_ASSET_BYTES {
            audit.asset_files_skipped += 1;
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => {
                audit.asset_files_skipped += 1;
                continue;
            }
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            audit.asset_files_skipped += 1;
            continue;
        };
        audit.asset_files_scanned += 1;
        audit.asset_bytes_scanned = audit.asset_bytes_scanned.saturating_add(bytes.len() as u64);
        let capabilities = classify_static_browser_text(text);
        if capabilities.iter().any(is_webplus_capability) {
            audit.webplus_static_reference_files += 1;
        }
        if capabilities.iter().any(is_desktop_callback_capability) {
            audit.desktop_callback_static_reference_files += 1;
        }
        add_evidence_counts(&mut audit.evidence_counts, capabilities);
    }
    if limit_reached || audit.asset_files_skipped > skipped_before {
        findings.push(Finding {
            severity: Severity::Warning,
            code: "browser-asset-scan-incomplete",
            source: root.to_path_buf(),
            message: format!(
                "浏览器资源审计跳过了 {} 个符号链接、不可读、非 UTF-8、超限或超出总预算的文件；报告不会输出文件名或内容",
                audit.asset_files_skipped - skipped_before
            ),
            remediation: "提供未加密且单文件不超过 4 MiB 的构建产物或源码，并用 HAR 覆盖关键业务流程",
        });
    }
}

fn audit_browser_har(
    path: &Path,
    audit: &mut BrowserCompatibilityAudit,
    findings: &mut Vec<Finding>,
) {
    let skipped_before = audit.har_requests_skipped;
    let document = match read_json_with_limit(path, MAX_HAR_BYTES) {
        Ok(document) => document,
        Err(error) => {
            findings.push(Finding {
                severity: Severity::Critical,
                code: "browser-har-unreadable",
                source: path.to_path_buf(),
                message: format!("无法安全读取浏览器 HAR: {error}"),
                remediation:
                    "导出不超过 64 MiB 的标准 HAR；报告只统计本地端点类别，不复制请求地址或内容",
            });
            return;
        }
    };
    let Some(entries) = document
        .get("log")
        .and_then(|log| log.get("entries"))
        .and_then(Value::as_array)
    else {
        findings.push(Finding {
            severity: Severity::Critical,
            code: "browser-har-invalid-shape",
            source: path.to_path_buf(),
            message: "HAR 不包含 log.entries 数组".into(),
            remediation: "使用 Chrome/Edge DevTools 导出标准 HAR 后重新审计",
        });
        return;
    };
    if entries.len() > MAX_HAR_REQUESTS {
        findings.push(Finding {
            severity: Severity::Critical,
            code: "browser-har-request-limit",
            source: path.to_path_buf(),
            message: format!("HAR 包含超过 {MAX_HAR_REQUESTS} 个请求，已拒绝不完整审计"),
            remediation: "按业务流程拆分 HAR，确保每个文件不超过请求上限",
        });
        return;
    }
    for entry in entries {
        let Some(request_url) = entry
            .get("request")
            .and_then(|request| request.get("url"))
            .and_then(Value::as_str)
        else {
            audit.har_requests_skipped += 1;
            continue;
        };
        let Some(runtime) = classify_runtime_url(request_url) else {
            audit.har_requests_skipped += 1;
            continue;
        };
        audit.har_requests_scanned += 1;
        if runtime.iter().any(is_webplus_capability) {
            audit.webplus_runtime_requests += 1;
        }
        if runtime.iter().any(is_desktop_callback_capability) {
            audit.desktop_callback_runtime_requests += 1;
        }
        add_evidence_counts(&mut audit.evidence_counts, runtime);
    }
    if audit.har_requests_skipped > skipped_before {
        findings.push(Finding {
            severity: Severity::Warning,
            code: "browser-har-scan-incomplete",
            source: path.to_path_buf(),
            message: format!(
                "浏览器 HAR 跳过了 {} 个缺少绝对请求 URL 或 URL 无效的条目；报告不会输出 URL 或请求内容",
                audit.har_requests_skipped - skipped_before
            ),
            remediation: "重新从 Chrome/Edge DevTools 导出完整 HAR，确保每个 log.entries 条目都包含可解析的绝对 request.url",
        });
    }
}

fn finalize_browser_compatibility(
    inputs: &AuditInputs,
    audit: &mut BrowserCompatibilityAudit,
    findings: &mut Vec<Finding>,
) {
    audit.webplus_http_evidence = evidence_level(
        audit.webplus_runtime_requests,
        audit.webplus_static_reference_files,
    );
    audit.desktop_callback_http_evidence = evidence_level(
        audit.desktop_callback_runtime_requests,
        audit.desktop_callback_static_reference_files,
    );
    if inputs.browser_asset_roots.is_empty() && inputs.browser_hars.is_empty() {
        findings.push(Finding {
            severity: Severity::Warning,
            code: "browser-http-evidence-not-supplied",
            source: PathBuf::from("browser-evidence"),
            message: "尚未提供业务前端资源或浏览器 HAR，无法证明外部浏览器已停止依赖本地 HTTP".into(),
            remediation: "传入 --browser-assets 和覆盖关键业务流程的 --browser-har，再决定是否交付独立兼容适配器",
        });
        return;
    }
    if inputs.browser_asset_roots.is_empty() {
        findings.push(Finding {
            severity: Severity::Warning,
            code: "browser-assets-not-supplied",
            source: PathBuf::from("browser-evidence"),
            message: "尚未提供业务前端源码或构建产物；HAR 只能证明已执行样本，不能发现未覆盖分支中的本地 HTTP 静态引用".into(),
            remediation: "同时传入代表性业务前端构建产物或源码，并继续用 HAR 覆盖关键业务流程",
        });
    }
    if inputs.browser_hars.is_empty() {
        findings.push(Finding {
            severity: Severity::Warning,
            code: "browser-har-not-supplied",
            source: PathBuf::from("browser-evidence"),
            message: "尚未提供真实业务流程 HAR；静态资源扫描无法证明本地 HTTP 代码路径是否实际执行"
                .into(),
            remediation: "在代表性账号、设备和关键业务流程中导出 HAR 后重新审计",
        });
    }
    push_compatibility_finding(
        audit.webplus_http_evidence,
        "webplus",
        audit.webplus_static_reference_files,
        audit.webplus_runtime_requests,
        findings,
    );
    push_compatibility_finding(
        audit.desktop_callback_http_evidence,
        "desktop-callback",
        audit.desktop_callback_static_reference_files,
        audit.desktop_callback_runtime_requests,
        findings,
    );
}

fn push_compatibility_finding(
    level: EvidenceLevel,
    family: &'static str,
    static_files: usize,
    runtime_requests: usize,
    findings: &mut Vec<Finding>,
) {
    let (label, runtime_code, static_code) = if family == "webplus" {
        (
            "WebPlus 7711/本地插件 HTTP",
            "legacy-browser-webplus-runtime-dependency",
            "legacy-browser-webplus-static-reference",
        )
    } else {
        (
            "旧桌面 45121 回调 HTTP",
            "legacy-browser-desktop-callback-runtime-dependency",
            "legacy-browser-desktop-callback-static-reference",
        )
    };
    match level {
        EvidenceLevel::ConfirmedRuntime => findings.push(Finding {
            severity: Severity::Critical,
            code: runtime_code,
            source: PathBuf::from("browser-evidence"),
            message: format!(
                "HAR 确认 {runtime_requests} 个 {label} 请求；报告不会输出 URL、查询参数或请求内容"
            ),
            remediation:
                "优先把调用方迁移到 Tauri Web Bridge；无法同时切换的外部浏览器才进入独立适配器设计",
        }),
        EvidenceLevel::StaticReferences => findings.push(Finding {
            severity: Severity::Critical,
            code: static_code,
            source: PathBuf::from("browser-evidence"),
            message: format!(
                "在 {static_files} 个浏览器资源文件中发现 {label} 引用；报告不会输出文件名或源码"
            ),
            remediation: "确认引用是否可达并迁移；使用 HAR 证明运行时已不再请求本地 HTTP",
        }),
        EvidenceLevel::NotObserved => findings.push(Finding {
            severity: Severity::Info,
            code: if family == "webplus" {
                "legacy-browser-webplus-not-observed"
            } else {
                "legacy-browser-desktop-callback-not-observed"
            },
            source: PathBuf::from("browser-evidence"),
            message: format!("本次输入未观察到 {label}；这不是不存在依赖的充分证明"),
            remediation: "在代表性账号、设备和关键业务流程上重复 HAR 采集后再关闭兼容评审项",
        }),
    }
}

fn evidence_level(runtime_requests: usize, static_files: usize) -> EvidenceLevel {
    if runtime_requests > 0 {
        EvidenceLevel::ConfirmedRuntime
    } else if static_files > 0 {
        EvidenceLevel::StaticReferences
    } else {
        EvidenceLevel::NotObserved
    }
}

fn is_browser_asset(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "html"
                    | "htm"
                    | "js"
                    | "mjs"
                    | "cjs"
                    | "ts"
                    | "tsx"
                    | "jsx"
                    | "vue"
                    | "json"
                    | "css"
            )
        })
}

fn classify_static_browser_text(text: &str) -> BTreeSet<&'static str> {
    let lower = text.to_ascii_lowercase();
    let endpoints = endpoint_capabilities(&lower);
    let mut capabilities = BTreeSet::new();
    let has_webplus_origin = contains_loopback_port(&lower, 7711);
    let has_desktop_callback_origin = contains_loopback_port(&lower, 45121);
    if has_webplus_origin {
        capabilities.insert("webplus-local-origin");
        capabilities.extend(endpoints.iter().copied().filter(is_webplus_capability));
    }
    if has_desktop_callback_origin {
        capabilities.insert("desktop-callback-local-origin");
        capabilities.extend(
            endpoints
                .iter()
                .copied()
                .filter(is_desktop_callback_capability),
        );
    }
    capabilities
}

fn classify_runtime_url(value: &str) -> Option<BTreeSet<&'static str>> {
    let Ok(url) = url::Url::parse(value) else {
        return None;
    };
    if !matches!(url.scheme(), "http" | "https" | "ws" | "wss") {
        return Some(BTreeSet::new());
    }
    let host = url.host_str()?;
    let loopback = host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1";
    if !loopback {
        return Some(BTreeSet::new());
    }
    let path = url.path().to_ascii_lowercase();
    let mut capabilities = endpoint_capabilities(&path);
    if url.port_or_known_default() == Some(7711) || capabilities.iter().any(is_webplus_capability) {
        capabilities.insert("webplus-local-origin");
    }
    if url.port_or_known_default() == Some(45121)
        || capabilities.iter().any(is_desktop_callback_capability)
    {
        capabilities.insert("desktop-callback-local-origin");
    }
    Some(capabilities)
}

fn endpoint_capabilities(value: &str) -> BTreeSet<&'static str> {
    let mut capabilities = BTreeSet::new();
    for (needle, capability) in [
        ("/plugin/invoke", "plugin-invoke"),
        ("/plugin/install", "plugin-management"),
        ("/plugin/local", "plugin-management"),
        ("/plugin/installed", "plugin-management"),
        ("/plugin/reload", "plugin-management"),
        ("/system/openurl", "system-open-url"),
        ("/system/command", "system-command"),
        ("/static/", "static-files"),
        ("/heartbeat", "heartbeat"),
        ("/ws/slave", "sandbox-websocket"),
        ("/desktop/notice", "desktop-notice"),
        ("/desktop/cache", "desktop-cache"),
    ] {
        if value.contains(needle) {
            capabilities.insert(capability);
        }
    }
    if value == "/system" || value.contains("\"/system\"") || value.contains("'/system'") {
        capabilities.insert("system-info");
    }
    capabilities
}

fn contains_loopback_port(value: &str, port: u16) -> bool {
    ["localhost", "127.0.0.1", "[::1]"]
        .iter()
        .any(|host| value.contains(&format!("{host}:{port}")))
}

fn is_webplus_capability(capability: &&str) -> bool {
    matches!(
        *capability,
        "webplus-local-origin"
            | "plugin-invoke"
            | "plugin-management"
            | "system-open-url"
            | "system-command"
            | "system-info"
            | "static-files"
            | "heartbeat"
            | "sandbox-websocket"
    )
}

fn is_desktop_callback_capability(capability: &&str) -> bool {
    matches!(
        *capability,
        "desktop-callback-local-origin" | "desktop-notice" | "desktop-cache"
    )
}

fn add_evidence_counts(counts: &mut BTreeMap<String, usize>, capabilities: BTreeSet<&'static str>) {
    for capability in capabilities {
        *counts.entry(capability.into()).or_default() += 1;
    }
}

fn audit_config(path: &Path, origin_policy: Option<&OriginPolicy>, report: &mut AuditReport) {
    let document = read_json(path);
    match document {
        Ok(document) => {
            let process_count = document
                .get("processes")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            let insecure_http_origin_count = insecure_http_origin_count(&document);
            let origin_policy_authorized = origin_policy.is_some_and(|policy| {
                serde_json::from_value::<DesktopConfig>(document.clone())
                    .ok()
                    .filter(|config| config.validate().is_ok())
                    .is_some_and(|config| policy.authorize(&config).is_ok())
            });
            let authorized_insecure_http_origin_count =
                if insecure_http_origin_count > 0 && origin_policy_authorized {
                    insecure_http_origin_count
                } else {
                    0
                };
            report.configs.push(ConfigAudit {
                source: path.to_path_buf(),
                readable: true,
                website_configured: document
                    .get("website")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty()),
                environment_count: document
                    .get("environments")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len),
                legacy_process_count: process_count,
                insecure_http_origin_count,
                authorized_insecure_http_origin_count,
                origin_policy_authorized,
            });
            if process_count > 0 {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    code: "legacy-arbitrary-processes",
                    source: path.to_path_buf(),
                    message: format!(
                        "发现 {process_count} 个旧版任意进程路径；审计报告不会输出或执行这些路径"
                    ),
                    remediation: "逐项核对文件摘要和固定参数，再生成组织签名的进程策略",
                });
            }
            if insecure_http_origin_count > 0 {
                if authorized_insecure_http_origin_count == insecure_http_origin_count {
                    report.findings.push(Finding {
                        severity: Severity::Info,
                        code: "legacy-insecure-business-origin-authorized",
                        source: path.to_path_buf(),
                        message: format!(
                            "发现 {insecure_http_origin_count} 个旧版 HTTP 业务来源，均已由当前签名来源策略授权；报告不会输出具体地址"
                        ),
                        remediation: "保留签名策略与本次迁移证据的摘要绑定，并在后续条件允许时迁移为 HTTPS",
                    });
                } else {
                    report.findings.push(Finding {
                        severity: Severity::Critical,
                        code: "legacy-insecure-business-origin",
                        source: path.to_path_buf(),
                        message: format!(
                            "发现 {insecure_http_origin_count} 个旧版 HTTP 业务来源，但当前签名来源策略未完整授权；报告不会输出具体地址"
                        ),
                        remediation: "优先迁移为 HTTPS；无法立即升级时，必须由发布方在签名来源策略中逐项批准 HTTP 例外",
                    });
                }
            } else if origin_policy.is_some() && !origin_policy_authorized {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    code: "business-origin-policy-mismatch",
                    source: path.to_path_buf(),
                    message: "当前签名来源策略未完整授权该配置中的业务、导航或外链来源；报告不会输出具体地址".into(),
                    remediation: "使用候选安装包将携带的精确签名来源策略重新审计迁移配置",
                });
            }
        }
        Err(error) => {
            report.configs.push(ConfigAudit {
                source: path.to_path_buf(),
                readable: false,
                website_configured: false,
                environment_count: 0,
                legacy_process_count: 0,
                insecure_http_origin_count: 0,
                authorized_insecure_http_origin_count: 0,
                origin_policy_authorized: false,
            });
            push_read_error(path, error, report);
        }
    }
}

fn insecure_http_origin_count(document: &Value) -> usize {
    let website = document.get("website").and_then(Value::as_str).into_iter();
    let environments = document
        .get("environments")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|environment| environment.get("url").and_then(Value::as_str));
    website
        .chain(environments)
        .filter(|value| value.trim().to_ascii_lowercase().starts_with("http://"))
        .count()
}

fn audit_plugin_root(root: &Path, report: &mut AuditReport) {
    let mut entries = match fs::read_dir(root) {
        Ok(entries) => entries.filter_map(Result::ok).collect::<Vec<_>>(),
        Err(error) => {
            push_read_error(root, error.to_string(), report);
            return;
        }
    };
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let plugin_id = entry.file_name().to_string_lossy().into_owned();
        if plugin_id.starts_with('.') {
            continue;
        }
        let source = entry.path();
        let has_legacy_license = source.join("license.dat").is_file();
        let has_version_metadata = source.join("plugin.json").is_file();
        let has_signature_envelope = source.join("plugin-signature.json").is_file();
        match PluginManifest::load(plugin_id.clone(), &source) {
            Ok(manifest) => {
                let services = manifest
                    .services
                    .iter()
                    .map(|service| {
                        let main_type = service.resolved_main_type().to_ascii_lowercase();
                        let detected = safe_component(&service.main_class)
                            .then(|| detect_pe_architecture(&source.join(&service.main_class)))
                            .flatten();
                        let declared = serde_json::to_value(service.architecture)
                            .ok()
                            .and_then(|value| value.as_str().map(str::to_owned))
                            .unwrap_or_else(|| "unknown".into());
                        let has_install_run = service
                            .extensions
                            .get("installRun")
                            .and_then(Value::as_str)
                            .is_some_and(|value| !value.trim().is_empty());
                        if has_install_run {
                            report.findings.push(Finding {
                                severity: Severity::Critical,
                                code: "legacy-install-run",
                                source: source.join("api.json"),
                                message: format!(
                                    "服务 [{}] 定义了安装后自动执行程序",
                                    service.service_id
                                ),
                                remediation:
                                    "拆除 installRun；如确有需要，迁移为经过摘要校验的签名部署步骤",
                            });
                        }
                        if detected.as_deref().is_some_and(|value| value != declared) {
                            report.findings.push(Finding {
                                severity: Severity::Critical,
                                code: "architecture-mismatch",
                                source: source.join(&service.main_class),
                                message: format!(
                                    "服务 [{}] 声明为 {declared}，PE 文件实际为 {}",
                                    service.service_id,
                                    detected.as_deref().unwrap_or("unknown")
                                ),
                                remediation: "修正 architecture 后分别用 x86/x64 宿主运行黄金回归",
                            });
                        }
                        ServiceAudit {
                            service_id: service.service_id.clone(),
                            main_type,
                            declared_architecture: declared,
                            detected_pe_architecture: detected,
                            method_count: service.methods.len(),
                            has_install_run,
                        }
                    })
                    .collect();
                report.plugins.push(PluginAudit {
                    plugin_id: plugin_id.clone(),
                    source: source.clone(),
                    parseable_by_next: true,
                    parse_error: None,
                    has_legacy_license,
                    has_version_metadata,
                    has_signature_envelope,
                    services,
                });
                if !has_version_metadata || !has_signature_envelope {
                    report.findings.push(Finding {
                        severity: Severity::Warning,
                        code: "plugin-requires-signing",
                        source,
                        message: format!("插件 [{plugin_id}] 缺少新格式版本元数据或完整文件签名"),
                        remediation:
                            "补充 plugin.json SemVer 元数据，按新格式打包并执行真实插件黄金矩阵",
                    });
                } else {
                    report.findings.push(Finding {
                        severity: Severity::Info,
                        code: "plugin-signature-present-unverified",
                        source,
                        message: format!("插件 [{plugin_id}] 存在签名封套，本次只读审计未传入生产信任库，未验证签名真伪"),
                        remediation: "使用生产信任库运行插件黄金矩阵完成双重验签和行为验证",
                    });
                }
            }
            Err(error) => {
                report.plugins.push(PluginAudit {
                    plugin_id: plugin_id.clone(),
                    source: source.clone(),
                    parseable_by_next: false,
                    parse_error: Some(error.to_string()),
                    has_legacy_license,
                    has_version_metadata,
                    has_signature_envelope,
                    services: Vec::new(),
                });
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    code: "plugin-manifest-incompatible",
                    source,
                    message: format!("插件 [{plugin_id}] 无法按新宿主规则解析: {error}"),
                    remediation: "人工修复 api.json 的入口、路径、服务 ID 或参数定义后再签名",
                });
            }
        }
    }
}

fn audit_keymap(path: &Path, report: &mut AuditReport) {
    let document = match read_json(path) {
        Ok(document) => document,
        Err(error) => {
            push_read_error(path, error, report);
            return;
        }
    };
    let entries = document
        .get("keymap")
        .and_then(Value::as_array)
        .or_else(|| document.as_array());
    let Some(entries) = entries else {
        report.findings.push(Finding {
            severity: Severity::Critical,
            code: "invalid-keymap-shape",
            source: path.to_path_buf(),
            message: "快捷键文件既不是数组，也不包含 keymap 数组".into(),
            remediation: "导出旧版 keymap.json 并人工映射为四种声明式桌面动作",
        });
        return;
    };
    for entry in entries {
        let contains_script = entry
            .get("snippet")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty());
        let active = entry
            .get("active")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let binding = KeyBindingAudit {
            source: path.to_path_buf(),
            name: string_field(entry, "name"),
            old_key: string_field(entry, "oldKey"),
            new_key: string_field(entry, "newKey"),
            active,
            contains_script,
        };
        if active && contains_script {
            report.findings.push(Finding {
                severity: Severity::Critical,
                code: "legacy-eval-shortcut",
                source: path.to_path_buf(),
                message: format!("启用的快捷键 [{}] 包含旧版脚本；报告不会输出或执行脚本内容", binding.new_key),
            remediation: "只映射为 open-business-window、capture-business-window、capture-region、reset-business-zoom 或 find-in-business-window",
            });
        }
        report.key_bindings.push(binding);
    }
}

fn read_json(path: &Path) -> Result<Value, String> {
    read_json_with_limit(path, MAX_INPUT_BYTES)
}

fn read_json_with_limit(path: &Path, max_bytes: u64) -> Result<Value, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err("拒绝读取符号链接".into());
    }
    if !metadata.is_file() {
        return Err("输入不是普通文件".into());
    }
    if metadata.len() > max_bytes {
        return Err(format!(
            "文件大小 {} 超过 {} 字节上限",
            metadata.len(),
            max_bytes
        ));
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn push_read_error(path: &Path, error: String, report: &mut AuditReport) {
    report.findings.push(Finding {
        severity: Severity::Critical,
        code: "input-unreadable",
        source: path.to_path_buf(),
        message: format!("无法安全读取输入: {error}"),
        remediation: "确认路径、权限、JSON 格式及文件大小后重新审计",
    });
}

fn string_field(value: &Value, field: &str) -> String {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn safe_component(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn detect_pe_architecture(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    if bytes.len() < 64 || bytes.get(0..2)? != b"MZ" {
        return None;
    }
    let offset = u32::from_le_bytes(bytes.get(0x3c..0x40)?.try_into().ok()?) as usize;
    if bytes.get(offset..offset.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let machine = u16::from_le_bytes(bytes.get(offset + 4..offset + 6)?.try_into().ok()?);
    match machine {
        0x014c => Some("x86".into()),
        0x8664 => Some("x64".into()),
        other => Some(format!("pe-0x{other:04x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn http_policy(origin: &str) -> OriginPolicy {
        OriginPolicy::from_unsigned_bytes(
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "businessGrants": [{
                    "origin": origin,
                    "services": [{"serviceId": "reader", "methods": ["read"]}]
                }],
                "navigationOrigins": [],
                "externalOrigins": [],
                "allowInsecureHttp": true
            }))
            .unwrap()
            .as_slice(),
        )
        .unwrap()
    }

    #[test]
    fn signed_policy_coverage_resolves_only_the_exact_http_business_origin() {
        let directory = tempdir().unwrap();
        let config = directory.path().join("config.json");
        fs::write(&config, r#"{"website":"http://10.17.5.57/project"}"#).unwrap();
        let inputs = AuditInputs {
            configs: vec![config],
            ..AuditInputs::default()
        };

        let authorized = audit_with_verified_origin_policy(
            &inputs,
            &http_policy("http://10.17.5.57"),
            "a".repeat(64),
        );
        assert_eq!(authorized.schema_version, 3);
        assert_eq!(
            authorized.configs[0].authorized_insecure_http_origin_count,
            1
        );
        assert!(authorized.findings.iter().any(|finding| {
            finding.code == "legacy-insecure-business-origin-authorized"
                && finding.severity == Severity::Info
        }));
        assert!(!authorized
            .findings
            .iter()
            .any(|finding| finding.code == "legacy-insecure-business-origin"));

        let unauthorized = audit_with_verified_origin_policy(
            &inputs,
            &http_policy("http://10.17.5.58"),
            "b".repeat(64),
        );
        assert_eq!(
            unauthorized.configs[0].authorized_insecure_http_origin_count,
            0
        );
        assert!(unauthorized.findings.iter().any(|finding| {
            finding.code == "legacy-insecure-business-origin"
                && finding.severity == Severity::Critical
        }));
    }

    #[test]
    fn reports_scripts_processes_and_install_run_without_exposing_values() {
        let directory = tempdir().unwrap();
        let config = directory.path().join("config.json");
        fs::write(
            &config,
            r#"{"website":"https://example.test","processes":["C:\\\\secret.exe"]}"#,
        )
        .unwrap();
        let keymap = directory.path().join("keymap.json");
        fs::write(&keymap, r#"{"keymap":[{"name":"legacy","newKey":"Ctrl+K","active":true,"snippet":"secret()"}]}"#).unwrap();
        let plugin_root = directory.path().join("plugins");
        let plugin = plugin_root.join("reader");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("api.json"),
            r#"{"serviceId":"reader","mainClass":"reader.dll","mainType":"dll","installRun":"setup.exe","methods":[{"name":"read"}]}"#,
        ).unwrap();

        let report = audit(&AuditInputs {
            configs: vec![config],
            plugin_roots: vec![plugin_root],
            keymaps: vec![keymap],
            ..AuditInputs::default()
        });
        assert_eq!(report.summary.plugin_directories, 1);
        assert_eq!(report.summary.services, 1);
        assert_eq!(report.summary.key_bindings, 1);
        assert!(report.summary.critical_findings >= 3);
        let output = serde_json::to_string(&report).unwrap();
        assert!(!output.contains("secret.exe"));
        assert!(!output.contains("secret()"));
    }

    #[test]
    fn detects_pe_machine_without_loading_the_binary() {
        let directory = tempdir().unwrap();
        let file = directory.path().join("fixture.dll");
        let mut bytes = vec![0_u8; 128];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&64_u32.to_le_bytes());
        bytes[64..68].copy_from_slice(b"PE\0\0");
        bytes[68..70].copy_from_slice(&0x8664_u16.to_le_bytes());
        fs::write(&file, bytes).unwrap();
        assert_eq!(detect_pe_architecture(&file).as_deref(), Some("x64"));
    }

    #[test]
    fn reports_insecure_business_origins_without_copying_addresses() {
        let directory = tempdir().unwrap();
        let config = directory.path().join("config.json");
        fs::write(
            &config,
            r#"{
              "website":"http://private-his.example/app",
              "environments":[
                {"name":"legacy","url":"HTTP://private-backup.example/app"},
                {"name":"secure","url":"https://secure.example/app"}
              ]
            }"#,
        )
        .unwrap();

        let report = audit(&AuditInputs {
            configs: vec![config],
            ..AuditInputs::default()
        });
        assert_eq!(report.configs[0].insecure_http_origin_count, 2);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "legacy-insecure-business-origin"));
        let output = serde_json::to_string(&report).unwrap();
        assert!(!output.contains("private-his"));
        assert!(!output.contains("private-backup"));
    }

    #[test]
    fn classifies_static_and_runtime_browser_http_without_copying_sensitive_data() {
        let directory = tempdir().unwrap();
        let assets = directory.path().join("assets");
        fs::create_dir_all(&assets).unwrap();
        fs::write(
            assets.join("business.js"),
            r#"const token = "patient-secret";
               fetch("http://localhost:7711/plugin/invoke?patient=hidden");
               fetch("http://127.0.0.1:45121/desktop/notice");
               const system = "/system";
               const resource = "/static/reader/index.html";"#,
        )
        .unwrap();
        let har = directory.path().join("business.har");
        fs::write(
            &har,
            r#"{"log":{"entries":[
                {"request":{"url":"http://127.0.0.1:7711/plugin/invoke?token=har-secret"}},
                {"request":{"url":"http://localhost:45121/desktop/cache?patient=hidden"}},
                {"request":{"url":"https://remote.example/plugin/invoke"}}
            ]}}"#,
        )
        .unwrap();

        let report = audit(&AuditInputs {
            browser_asset_roots: vec![assets],
            browser_hars: vec![har],
            ..AuditInputs::default()
        });

        assert_eq!(
            report.browser_compatibility.webplus_http_evidence,
            EvidenceLevel::ConfirmedRuntime
        );
        assert_eq!(
            report.browser_compatibility.desktop_callback_http_evidence,
            EvidenceLevel::ConfirmedRuntime
        );
        assert_eq!(report.browser_compatibility.har_requests_scanned, 3);
        assert_eq!(report.browser_compatibility.har_requests_skipped, 0);
        assert_eq!(report.browser_compatibility.webplus_runtime_requests, 1);
        assert_eq!(
            report
                .browser_compatibility
                .desktop_callback_runtime_requests,
            1
        );
        assert_eq!(
            report
                .browser_compatibility
                .evidence_counts
                .get("system-info"),
            Some(&1)
        );
        assert_eq!(
            report
                .browser_compatibility
                .evidence_counts
                .get("static-files"),
            Some(&1)
        );
        assert!(report
            .findings
            .iter()
            .any(|finding| { finding.code == "legacy-browser-webplus-runtime-dependency" }));
        assert!(report.findings.iter().any(|finding| {
            finding.code == "legacy-browser-desktop-callback-runtime-dependency"
        }));
        let output = serde_json::to_string(&report).unwrap();
        for sensitive in [
            "patient-secret",
            "har-secret",
            "patient=hidden",
            "remote.example",
            "http://localhost:7711",
            "business.js",
        ] {
            assert!(!output.contains(sensitive));
        }
    }

    #[test]
    fn static_references_are_not_reported_as_runtime_confirmation() {
        let directory = tempdir().unwrap();
        let asset = directory.path().join("legacy.js");
        fs::write(&asset, "fetch('http://localhost:7711/heartbeat')").unwrap();

        let report = audit(&AuditInputs {
            browser_asset_roots: vec![asset],
            ..AuditInputs::default()
        });

        assert_eq!(
            report.browser_compatibility.webplus_http_evidence,
            EvidenceLevel::StaticReferences
        );
        assert_eq!(report.browser_compatibility.webplus_runtime_requests, 0);
        assert!(report
            .findings
            .iter()
            .any(|finding| { finding.code == "legacy-browser-webplus-static-reference" }));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "browser-har-not-supplied"));
    }

    #[test]
    fn remote_routes_in_har_do_not_count_as_local_http_dependencies() {
        let directory = tempdir().unwrap();
        let har = directory.path().join("remote.har");
        fs::write(
            &har,
            r#"{"log":{"entries":[{"request":{"url":"https://business.example/plugin/invoke"}}]}}"#,
        )
        .unwrap();

        let report = audit(&AuditInputs {
            browser_hars: vec![har],
            ..AuditInputs::default()
        });

        assert_eq!(
            report.browser_compatibility.webplus_http_evidence,
            EvidenceLevel::NotObserved
        );
        assert!(report.browser_compatibility.evidence_counts.is_empty());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "browser-assets-not-supplied"));
    }

    #[test]
    fn malformed_har_entries_are_not_counted_as_covered_requests() {
        let directory = tempdir().unwrap();
        let har = directory.path().join("incomplete.har");
        fs::write(
            &har,
            r#"{"log":{"entries":[
                {"request":{"url":"https://business.example/health"}},
                {"request":{"url":"data:text/plain,local"}},
                {"request":{}},
                {"request":{"url":"/relative/request"}},
                {"request":{"url":"not a url patient-secret"}}
            ]}}"#,
        )
        .unwrap();

        let report = audit(&AuditInputs {
            browser_hars: vec![har],
            ..AuditInputs::default()
        });

        assert_eq!(report.browser_compatibility.har_requests_scanned, 2);
        assert_eq!(report.browser_compatibility.har_requests_skipped, 3);
        assert_eq!(report.summary.browser_har_requests, 2);
        assert!(report.findings.iter().any(|finding| {
            finding.code == "browser-har-scan-incomplete" && finding.severity == Severity::Warning
        }));
        let output = serde_json::to_string(&report).unwrap();
        assert!(!output.contains("patient-secret"));
        assert!(!output.contains("business.example"));
    }

    #[test]
    fn relative_routes_in_assets_do_not_count_without_a_local_origin() {
        let directory = tempdir().unwrap();
        let asset = directory.path().join("remote-api.js");
        fs::write(
            &asset,
            "fetch('/plugin/invoke'); fetch('/system'); fetch('/desktop/cache')",
        )
        .unwrap();

        let report = audit(&AuditInputs {
            browser_asset_roots: vec![asset],
            ..AuditInputs::default()
        });

        assert_eq!(
            report.browser_compatibility.webplus_http_evidence,
            EvidenceLevel::NotObserved
        );
        assert_eq!(
            report.browser_compatibility.desktop_callback_http_evidence,
            EvidenceLevel::NotObserved
        );
        assert!(report.browser_compatibility.evidence_counts.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn browser_asset_scan_does_not_follow_symbolic_links() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let outside = directory.path().join("outside.js");
        fs::write(&outside, "http://localhost:7711/plugin/invoke").unwrap();
        let assets = directory.path().join("assets");
        fs::create_dir(&assets).unwrap();
        symlink(&outside, assets.join("linked.js")).unwrap();

        let report = audit(&AuditInputs {
            browser_asset_roots: vec![assets],
            ..AuditInputs::default()
        });

        assert_eq!(report.browser_compatibility.asset_files_scanned, 0);
        assert_eq!(report.browser_compatibility.asset_files_skipped, 1);
        assert_eq!(
            report.browser_compatibility.webplus_http_evidence,
            EvidenceLevel::NotObserved
        );
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "browser-asset-scan-incomplete"));
    }
}
