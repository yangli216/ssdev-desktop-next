use serde::Serialize;

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

pub(crate) fn evaluate(facts: &DeploymentCheckFacts) -> DeploymentCheckReport {
    let mut items = Vec::with_capacity(10);

    items.push(item(
        "webview-runtime",
        "WebView2 运行环境",
        DeploymentCheckStatus::Pass,
        "控制台已通过 WebView 到达 Rust 原生 IPC，运行环境可用。",
        None,
    ));

    match (&facts.config_error, facts.business_origin_count) {
        (Some(error), _) => items.push(item(
            "project-config",
            "项目配置",
            DeploymentCheckStatus::Fail,
            format!("当前配置未通过校验：{error}"),
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

    if let Some(error) = &facts.origin_policy_error {
        items.push(item(
            "origin-policy",
            "业务来源策略",
            DeploymentCheckStatus::Fail,
            format!("当前项目配置未获部署策略授权：{error}"),
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

    if facts.plugin_load_failures > 0 {
        items.push(item(
            "plugin-inventory",
            "插件与服务",
            DeploymentCheckStatus::Fail,
            format!("有 {} 个插件加载失败或被隔离。", facts.plugin_load_failures),
            Some("进入“插件管理”查看隔离原因，修复依赖、架构或签名问题。"),
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
}
