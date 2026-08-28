use std::fs;
use std::io::Write;
use std::path::Path;

use serde::Serialize;

const EXPORT_SCHEMA_VERSION: u16 = 1;
const MAX_EXPORT_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct DeploymentCheckFacts {
    pub(crate) is_windows: bool,
    pub(crate) config_error: Option<String>,
    pub(crate) business_origin_count: usize,
    pub(crate) origin_policy_error: Option<String>,
    pub(crate) allow_insecure_http: bool,
    pub(crate) plugin_trust_mode: &'static str,
    pub(crate) active_trust_keys: usize,
    pub(crate) plugin_count: usize,
    pub(crate) service_count: usize,
    pub(crate) active_service_count: usize,
    pub(crate) active_manifests_match: bool,
    pub(crate) plugin_route_count: usize,
    pub(crate) evaluated_policy_grants: usize,
    pub(crate) authorized_policy_grants: usize,
    pub(crate) uncovered_business_origins: usize,
    pub(crate) uncovered_plugin_routes: usize,
    pub(crate) route_policy_error: Option<String>,
    pub(crate) plugin_inventory_error: Option<String>,
    pub(crate) plugin_load_failures: usize,
    pub(crate) plugin_preflight_failures: usize,
    pub(crate) x86_host_available: bool,
    pub(crate) x64_host_available: bool,
    pub(crate) tracked_invocations_available: bool,
    pub(crate) tracked_invocations_accepting: bool,
    pub(crate) tracked_persistence_failures: u64,
    pub(crate) diagnostics_available: bool,
    pub(crate) managed_process_failures: usize,
    pub(crate) app_update_configured: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeploymentCheckReport {
    pub(crate) ready: bool,
    pub(crate) passed: usize,
    pub(crate) warnings: usize,
    pub(crate) failures: usize,
    pub(crate) items: Vec<DeploymentCheckItem>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeploymentCheckItem {
    pub(crate) id: &'static str,
    pub(crate) label: &'static str,
    pub(crate) status: DeploymentCheckStatus,
    pub(crate) summary: String,
    pub(crate) action: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DeploymentCheckStatus {
    Pass,
    Warning,
    Fail,
    Info,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeploymentCheckExportDocument<'a> {
    schema_version: u16,
    generated_at_unix_ms: u64,
    desktop_version: &'a str,
    os: &'a str,
    architecture: &'a str,
    evidence_level: &'static str,
    report: &'a DeploymentCheckReport,
}

pub(crate) fn encode_export_document(
    report: &DeploymentCheckReport,
    generated_at_unix_ms: u64,
    desktop_version: &str,
    os: &str,
    architecture: &str,
) -> Result<Vec<u8>, String> {
    if generated_at_unix_ms == 0
        || desktop_version.is_empty()
        || desktop_version.len() > 128
        || os.is_empty()
        || os.len() > 32
        || architecture.is_empty()
        || architecture.len() > 32
    {
        return Err("部署自检记录元数据无效".into());
    }
    let document = DeploymentCheckExportDocument {
        schema_version: EXPORT_SCHEMA_VERSION,
        generated_at_unix_ms,
        desktop_version,
        os,
        architecture,
        evidence_level: "unsigned-local-record",
        report,
    };
    let mut bytes = serde_json::to_vec_pretty(&document)
        .map_err(|error| format!("无法生成部署自检记录: {error}"))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_EXPORT_BYTES {
        return Err("部署自检记录超过大小限制".into());
    }
    Ok(bytes)
}

pub(crate) fn persist_export_document(destination: &Path, bytes: &[u8]) -> Result<u64, String> {
    if !destination.is_absolute() || bytes.is_empty() || bytes.len() > MAX_EXPORT_BYTES {
        return Err("部署自检记录目标或内容无效".into());
    }
    let parent = destination
        .parent()
        .ok_or_else(|| "部署自检记录缺少父目录".to_owned())?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("无法检查部署自检记录目录: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("部署自检记录目录必须是已存在的普通目录".into());
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| format!("无法创建部署自检记录暂存文件: {error}"))?;
    temporary
        .write_all(bytes)
        .and_then(|_| temporary.as_file_mut().sync_all())
        .map_err(|error| format!("无法写入部署自检记录: {error}"))?;
    temporary
        .persist_noclobber(destination)
        .map_err(|error| format!("无法保存部署自检记录（不会覆盖已有文件）: {}", error.error))?;
    u64::try_from(bytes.len()).map_err(|_| "部署自检记录大小无效".to_owned())
}

pub(crate) fn evaluate(facts: &DeploymentCheckFacts) -> DeploymentCheckReport {
    let mut items = Vec::with_capacity(12);

    items.push(item(
        "webview-runtime",
        "WebView2 运行环境",
        DeploymentCheckStatus::Pass,
        "控制台已通过 WebView 到达 Rust 原生 IPC，运行环境可用。",
        None,
    ));

    match (&facts.config_error, facts.business_origin_count) {
        (Some(_), _) => items.push(item(
            "project-config",
            "项目配置",
            DeploymentCheckStatus::Fail,
            "当前配置未通过校验。",
            Some("进入“项目配置”修正地址或重复项，然后保存配置。"),
        )),
        (None, 0) => items.push(item(
            "project-config",
            "项目配置",
            DeploymentCheckStatus::Fail,
            "尚未配置可启动的业务地址。",
            Some("进入“项目配置”填写默认业务地址或业务环境。"),
        )),
        (None, count) => items.push(item(
            "project-config",
            "项目配置",
            DeploymentCheckStatus::Pass,
            format!("已配置并校验 {count} 个业务来源。"),
            None,
        )),
    }

    if facts.origin_policy_error.is_some() {
        items.push(item(
            "origin-policy",
            "业务来源策略",
            DeploymentCheckStatus::Fail,
            "当前项目配置未获部署策略授权。",
            Some("核对项目地址和签名来源策略；普通内网 HTTP 地址应来自当前项目配置。"),
        ));
    } else {
        items.push(item(
            "origin-policy",
            "业务来源策略",
            DeploymentCheckStatus::Pass,
            if facts.allow_insecure_http {
                "来源策略有效，并允许当前项目使用内网 HTTP。"
            } else {
                "来源策略有效，当前仅允许 HTTPS。"
            },
            None,
        ));
    }

    if facts.plugin_trust_mode == "ed25519-strict" && facts.active_trust_keys > 0 {
        items.push(item(
            "plugin-trust",
            "插件签名信任",
            DeploymentCheckStatus::Pass,
            format!(
                "严格签名模式已启用，{} 把活动密钥可用。",
                facts.active_trust_keys
            ),
            None,
        ));
    } else if facts.plugin_trust_mode == "ed25519-strict" {
        items.push(item(
            "plugin-trust",
            "插件签名信任",
            DeploymentCheckStatus::Fail,
            "严格签名模式没有可用的活动密钥。",
            Some("随安装包部署有效的 plugin-trust.json，并确认密钥处于 active 状态。"),
        ));
    } else {
        items.push(item(
            "plugin-trust",
            "插件签名信任",
            DeploymentCheckStatus::Warning,
            "当前处于仅供开发使用的未签名插件模式。",
            Some("正式交付前关闭未签名模式并重新启动客户端。"),
        ));
    }

    if !facts.is_windows {
        items.push(item(
            "plugin-hosts",
            "Windows 插件宿主",
            DeploymentCheckStatus::Info,
            "当前不是 Windows，跳过 x86/x64 宿主文件检查。",
            None,
        ));
    } else if facts.x86_host_available && facts.x64_host_available {
        items.push(item(
            "plugin-hosts",
            "Windows 插件宿主",
            DeploymentCheckStatus::Pass,
            "x86 与 x64 隔离宿主均已安装。",
            None,
        ));
    } else {
        let missing = match (facts.x86_host_available, facts.x64_host_available) {
            (false, false) => "x86、x64",
            (false, true) => "x86",
            (true, false) => "x64",
            (true, true) => unreachable!(),
        };
        items.push(item(
            "plugin-hosts",
            "Windows 插件宿主",
            DeploymentCheckStatus::Fail,
            format!("缺少 {missing} 插件宿主。"),
            Some("使用正式 Windows 安装包修复安装，不要单独复制主程序。"),
        ));
    }

    if facts.plugin_inventory_error.is_some() {
        items.push(item(
            "plugin-inventory",
            "插件与服务",
            DeploymentCheckStatus::Fail,
            "无法读取当前插件清单。",
            Some("检查插件数据目录权限和磁盘状态，然后重新启动客户端。"),
        ));
    } else if facts.plugin_load_failures > 0 {
        items.push(item(
            "plugin-inventory",
            "插件与服务",
            DeploymentCheckStatus::Fail,
            format!("有 {} 个插件加载失败或被隔离。", facts.plugin_load_failures),
            Some("进入“插件管理”查看隔离原因，修复依赖、架构或签名问题。"),
        ));
    } else if facts.service_count != facts.active_service_count {
        items.push(item(
            "plugin-inventory",
            "插件与服务",
            DeploymentCheckStatus::Fail,
            format!(
                "磁盘插件声明 {} 个服务，但控制器当前只有 {} 个活动服务。",
                facts.service_count, facts.active_service_count
            ),
            Some("进入“插件管理”重新加载插件；若仍不一致，请导出诊断包后重启客户端。"),
        ));
    } else if !facts.active_manifests_match {
        items.push(item(
            "plugin-inventory",
            "插件与服务",
            DeploymentCheckStatus::Fail,
            "磁盘插件清单与控制器当前活动清单不一致。",
            Some("进入“插件管理”执行安全重新扫描；若仍不一致，请导出诊断包后重启客户端。"),
        ));
    } else if facts.service_count == 0 {
        items.push(item(
            "plugin-inventory",
            "插件与服务",
            DeploymentCheckStatus::Warning,
            "当前没有已注册的原生服务。",
            Some("安装签名插件或在“原生映射”中创建项目能力。"),
        ));
    } else {
        items.push(item(
            "plugin-inventory",
            "插件与服务",
            DeploymentCheckStatus::Pass,
            format!(
                "{} 个插件提供 {} 个原生服务。",
                facts.plugin_count, facts.service_count
            ),
            None,
        ));
    }

    if facts.route_policy_error.is_some() {
        items.push(item(
            "plugin-route-policy",
            "业务与原生能力授权",
            DeploymentCheckStatus::Fail,
            "无法核对业务来源与插件方法授权。",
            Some("修正项目配置或签名来源策略，再重新执行部署自检。"),
        ));
    } else if facts.plugin_route_count == 0 {
        items.push(item(
            "plugin-route-policy",
            "业务与原生能力授权",
            DeploymentCheckStatus::Info,
            "当前没有需要核对授权的插件调用路由。",
            None,
        ));
    } else if facts.uncovered_business_origins > 0 || facts.uncovered_plugin_routes > 0 {
        items.push(item(
            "plugin-route-policy",
            "业务与原生能力授权",
            DeploymentCheckStatus::Fail,
            format!(
                "有 {} 个业务来源无法调用任何已安装能力，另有 {} 条插件调用路由未被任何当前业务来源授权。",
                facts.uncovered_business_origins, facts.uncovered_plugin_routes
            ),
            Some("按项目实际调用范围更新并重新签署来源策略；不要用通配授权绕过漏项。"),
        ));
    } else {
        items.push(item(
            "plugin-route-policy",
            "业务与原生能力授权",
            DeploymentCheckStatus::Pass,
            format!(
                "已核对 {} 条来源/插件授权组合，其中 {} 条获得授权；每个业务来源和插件路由均有有效覆盖。",
                facts.evaluated_policy_grants, facts.authorized_policy_grants
            ),
            None,
        ));
    }

    if !facts.tracked_invocations_available {
        items.push(item(
            "tracked-invocations",
            "持久调用账本",
            DeploymentCheckStatus::Fail,
            "持久调用协调不可用，防重放与结果找回无法保证。",
            Some("检查应用数据目录权限和磁盘状态，然后重新启动客户端。"),
        ));
    } else if !facts.tracked_invocations_accepting || facts.tracked_persistence_failures > 0 {
        items.push(item(
            "tracked-invocations",
            "持久调用账本",
            DeploymentCheckStatus::Warning,
            format!(
                "账本当前{}，累计 {} 次落盘异常。",
                if facts.tracked_invocations_accepting {
                    "可用"
                } else {
                    "正在排空"
                },
                facts.tracked_persistence_failures
            ),
            Some("导出诊断包并检查磁盘空间、目录权限和安全软件拦截。"),
        ));
    } else {
        items.push(item(
            "tracked-invocations",
            "持久调用账本",
            DeploymentCheckStatus::Pass,
            "防重放、状态查询和结果找回可用。",
            None,
        ));
    }

    if facts.plugin_preflight_failures > 0 {
        items.push(item(
            "plugin-preflight",
            "插件安装预检",
            DeploymentCheckStatus::Warning,
            format!(
                "本次运行累计 {} 次宿主预检失败。",
                facts.plugin_preflight_failures
            ),
            Some("进入“插件管理”确认目标插件架构、依赖和入口定义。"),
        ));
    } else {
        items.push(item(
            "plugin-preflight",
            "插件安装预检",
            DeploymentCheckStatus::Pass,
            "本次运行没有宿主预检失败。",
            None,
        ));
    }

    if facts.managed_process_failures > 0 {
        items.push(item(
            "managed-processes",
            "项目辅助进程",
            DeploymentCheckStatus::Fail,
            format!(
                "有 {} 个受控辅助进程启动失败。",
                facts.managed_process_failures
            ),
            Some("检查签名进程策略、程序文件和当前用户权限。"),
        ));
    } else {
        items.push(item(
            "managed-processes",
            "项目辅助进程",
            DeploymentCheckStatus::Pass,
            "受控辅助进程没有启动失败。",
            None,
        ));
    }

    items.push(if facts.diagnostics_available {
        item(
            "diagnostics",
            "隐私诊断",
            DeploymentCheckStatus::Pass,
            "结构化日志和脱敏诊断包可用。",
            None,
        )
    } else {
        item(
            "diagnostics",
            "隐私诊断",
            DeploymentCheckStatus::Warning,
            "诊断日志不可用，不影响调用但会降低故障定位能力。",
            Some("检查应用日志目录权限和磁盘空间。"),
        )
    });

    items.push(item(
        "app-update",
        "客户端更新",
        DeploymentCheckStatus::Info,
        if facts.app_update_configured {
            "签名应用更新已配置。"
        } else {
            "未配置在线更新；可继续使用离线安装包维护。"
        },
        None,
    ));

    let passed = items
        .iter()
        .filter(|check| check.status == DeploymentCheckStatus::Pass)
        .count();
    let warnings = items
        .iter()
        .filter(|check| check.status == DeploymentCheckStatus::Warning)
        .count();
    let failures = items
        .iter()
        .filter(|check| check.status == DeploymentCheckStatus::Fail)
        .count();
    DeploymentCheckReport {
        ready: failures == 0,
        passed,
        warnings,
        failures,
        items,
    }
}

fn item(
    id: &'static str,
    label: &'static str,
    status: DeploymentCheckStatus,
    summary: impl Into<String>,
    action: Option<&'static str>,
) -> DeploymentCheckItem {
    DeploymentCheckItem {
        id,
        label,
        status,
        summary: summary.into(),
        action,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_facts() -> DeploymentCheckFacts {
        DeploymentCheckFacts {
            is_windows: true,
            config_error: None,
            business_origin_count: 2,
            origin_policy_error: None,
            allow_insecure_http: true,
            plugin_trust_mode: "ed25519-strict",
            active_trust_keys: 1,
            plugin_count: 2,
            service_count: 4,
            active_service_count: 4,
            active_manifests_match: true,
            plugin_route_count: 6,
            evaluated_policy_grants: 12,
            authorized_policy_grants: 6,
            uncovered_business_origins: 0,
            uncovered_plugin_routes: 0,
            route_policy_error: None,
            plugin_inventory_error: None,
            plugin_load_failures: 0,
            plugin_preflight_failures: 0,
            x86_host_available: true,
            x64_host_available: true,
            tracked_invocations_available: true,
            tracked_invocations_accepting: true,
            tracked_persistence_failures: 0,
            diagnostics_available: true,
            managed_process_failures: 0,
            app_update_configured: false,
        }
    }

    #[test]
    fn healthy_offline_windows_deployment_is_ready() {
        let report = evaluate(&healthy_facts());
        assert!(report.ready);
        assert_eq!(report.failures, 0);
        assert!(report.passed >= 8);
        assert_eq!(report.warnings, 0);
    }

    #[test]
    fn missing_project_hosts_and_ledger_block_delivery() {
        let mut facts = healthy_facts();
        facts.business_origin_count = 0;
        facts.x86_host_available = false;
        facts.tracked_invocations_available = false;

        let report = evaluate(&facts);
        assert!(!report.ready);
        assert_eq!(report.failures, 3);
        assert!(report.items.iter().any(|item| {
            item.id == "plugin-hosts" && item.status == DeploymentCheckStatus::Fail
        }));
    }

    #[test]
    fn optional_operational_gaps_are_warnings_not_false_failures() {
        let mut facts = healthy_facts();
        facts.service_count = 0;
        facts.active_service_count = 0;
        facts.plugin_route_count = 0;
        facts.plugin_count = 0;
        facts.plugin_preflight_failures = 2;
        facts.diagnostics_available = false;

        let report = evaluate(&facts);
        assert!(report.ready);
        assert_eq!(report.failures, 0);
        assert_eq!(report.warnings, 3);
    }

    #[test]
    fn non_windows_development_skips_host_file_gate() {
        let mut facts = healthy_facts();
        facts.is_windows = false;
        facts.x86_host_available = false;
        facts.x64_host_available = false;

        let report = evaluate(&facts);
        assert!(report.ready);
        assert!(report.items.iter().any(|item| {
            item.id == "plugin-hosts" && item.status == DeploymentCheckStatus::Info
        }));
    }

    #[test]
    fn route_drift_and_policy_gaps_block_false_delivery_readiness() {
        let mut route_drift = healthy_facts();
        route_drift.active_service_count = 3;
        let report = evaluate(&route_drift);
        assert!(!report.ready);
        assert!(report.items.iter().any(|item| {
            item.id == "plugin-inventory" && item.status == DeploymentCheckStatus::Fail
        }));

        let mut same_count_drift = healthy_facts();
        same_count_drift.active_manifests_match = false;
        let report = evaluate(&same_count_drift);
        assert!(!report.ready);
        assert!(report.items.iter().any(|item| {
            item.id == "plugin-inventory"
                && item.status == DeploymentCheckStatus::Fail
                && item.summary.contains("活动清单不一致")
        }));

        let mut policy_gap = healthy_facts();
        policy_gap.uncovered_business_origins = 1;
        policy_gap.uncovered_plugin_routes = 2;
        let report = evaluate(&policy_gap);
        assert!(!report.ready);
        assert!(report.items.iter().any(|item| {
            item.id == "plugin-route-policy" && item.status == DeploymentCheckStatus::Fail
        }));
    }

    #[test]
    fn report_does_not_return_sensitive_error_details() {
        let mut facts = healthy_facts();
        facts.config_error = Some("invalid http://private.example/app".to_owned());
        facts.origin_policy_error = Some("unauthorized http://private.example".to_owned());
        facts.plugin_inventory_error = Some("failed at C:\\private\\plugins".to_owned());
        facts.route_policy_error = Some("reader.secretMethod is unauthorized".to_owned());

        let encoded = serde_json::to_string(&evaluate(&facts)).unwrap();
        assert!(!encoded.contains("private.example"));
        assert!(!encoded.contains("private\\\\plugins"));
        assert!(!encoded.contains("secretMethod"));
    }

    #[test]
    fn exported_field_record_is_bounded_and_explicitly_unsigned() {
        let mut facts = healthy_facts();
        facts.config_error = Some("invalid http://private.example/app".to_owned());
        let report = evaluate(&facts);
        let bytes =
            encode_export_document(&report, 1_786_000_000_000, "0.1.0", "windows", "x86_64")
                .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["evidenceLevel"], "unsigned-local-record");
        assert_eq!(value["desktopVersion"], "0.1.0");
        assert_eq!(value["report"]["ready"], false);
        assert!(bytes.len() < MAX_EXPORT_BYTES);
        assert!(!String::from_utf8(bytes)
            .unwrap()
            .contains("private.example"));
    }

    #[test]
    fn field_record_export_never_overwrites_an_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("deployment-check.json");
        let report = evaluate(&healthy_facts());
        let bytes = encode_export_document(&report, 1, "0.1.0", "windows", "x86_64").unwrap();

        assert_eq!(
            persist_export_document(&destination, &bytes).unwrap(),
            u64::try_from(bytes.len()).unwrap()
        );
        assert!(persist_export_document(&destination, &bytes).is_err());
        assert_eq!(fs::read(destination).unwrap(), bytes);
        assert!(persist_export_document(Path::new("relative.json"), &bytes).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn field_record_export_refuses_a_symbolic_link_parent() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let actual = directory.path().join("actual");
        let linked = directory.path().join("linked");
        fs::create_dir(&actual).unwrap();
        symlink(&actual, &linked).unwrap();
        let report = evaluate(&healthy_facts());
        let bytes = encode_export_document(&report, 1, "0.1.0", "macos", "aarch64").unwrap();

        assert!(persist_export_document(&linked.join("deployment-check.json"), &bytes).is_err());
        assert!(!actual.join("deployment-check.json").exists());
    }
}
