use std::fs;
use std::io::Write;
use std::path::Path;

use serde::Serialize;

const EXPORT_SCHEMA_VERSION: u16 = 1;
const MAX_EXPORT_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct DeploymentCheckFacts {
    pub(crate) is_windows: bool,
    pub(crate) deep_preflight: bool,
    pub(crate) deep_preflighted_hosts: usize,
    pub(crate) deep_preflight_failure: Option<DeploymentPreflightFailure>,
    pub(crate) config_error: Option<String>,
    pub(crate) project_identity_configured: bool,
    pub(crate) business_origin_count: usize,
    pub(crate) business_window_count: usize,
    pub(crate) business_loading_windows: usize,
    pub(crate) business_navigating_windows: usize,
    pub(crate) business_ready_windows: usize,
    pub(crate) business_timed_out_windows: usize,
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
    pub(crate) managed_process_restart_required: bool,
    pub(crate) app_update_configured: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct DeploymentPreflightFailure {
    pub(crate) plugin_id: Option<String>,
    pub(crate) architecture: Option<&'static str>,
    pub(crate) diagnostic_code: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeploymentCheckReport {
    pub(crate) deep: bool,
    pub(crate) deep_available: bool,
    pub(crate) ready: bool,
    pub(crate) delivery_ready: bool,
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
    let mut items = Vec::with_capacity(14);

    items.push(item(
        "webview-runtime",
        "WebView2 运行环境",
        DeploymentCheckStatus::Pass,
        "控制台已通过 WebView 到达 Rust 原生 IPC，运行环境可用。",
        None,
    ));

    if facts.business_timed_out_windows > 0 {
        items.push(item(
            "business-frontend",
            "业务页面就绪",
            DeploymentCheckStatus::Fail,
            format!(
                "有 {} 个业务窗口未在 30 秒内到达原生 IPC。",
                facts.business_timed_out_windows
            ),
            Some("检查业务地址、网络、代理和证书；修复后重新加载窗口，必要时导出诊断包。"),
        ));
    } else if facts.business_ready_windows > 0 {
        items.push(item(
            "business-frontend",
            "业务页面就绪",
            DeploymentCheckStatus::Pass,
            format!(
                "{} 个活动业务窗口中有 {} 个页面已到达原生 IPC。",
                facts.business_window_count, facts.business_ready_windows
            ),
            None,
        ));
    } else if facts.deep_preflight {
        items.push(item(
            "business-frontend",
            "业务页面就绪",
            DeploymentCheckStatus::Fail,
            if facts.business_window_count == 0 {
                "深度交付检查要求至少启动一个真实业务页面并完成原生 IPC 握手。".into()
            } else {
                format!(
                    "业务页面尚未就绪（加载中 {} 个，登录跳转中 {} 个）。",
                    facts.business_loading_windows, facts.business_navigating_windows
                )
            },
            Some("启动目标业务环境，等待首页显示“已连接”后重新执行深度检查。"),
        ));
    } else if facts.business_window_count > 0 {
        items.push(item(
            "business-frontend",
            "业务页面就绪",
            DeploymentCheckStatus::Warning,
            format!(
                "业务页面尚未就绪（加载中 {} 个，登录跳转中 {} 个）。",
                facts.business_loading_windows, facts.business_navigating_windows
            ),
            Some("等待页面完成加载；超过 30 秒时按客户端提示检查网络和证书。"),
        ));
    } else {
        items.push(item(
            "business-frontend",
            "业务页面就绪",
            DeploymentCheckStatus::Info,
            "尚未启动业务窗口；日常检查不阻断，正式交付前应执行深度检查。",
            None,
        ));
    }

    if facts.project_identity_configured {
        items.push(item(
            "project-identity",
            "项目身份",
            DeploymentCheckStatus::Pass,
            "项目名称和稳定标识已配置。",
            None,
        ));
    } else {
        items.push(item(
            "project-identity",
            "项目身份",
            DeploymentCheckStatus::Fail,
            "尚未配置可复核的项目名称和稳定标识。",
            Some("进入“项目配置”同时填写项目名称和项目标识，然后保存并重新检查。"),
        ));
    }

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
        let missing = if !facts.x86_host_available && !facts.x64_host_available {
            "x86、x64"
        } else if !facts.x86_host_available {
            "x86"
        } else {
            "x64"
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

    if let (true, Some(failure)) = (facts.deep_preflight, facts.deep_preflight_failure.as_ref()) {
        let summary = match &failure.plugin_id {
            Some(plugin_id) => format!(
                "插件 [{}]{} 未能通过隔离宿主 Health 预检 ({})。",
                plugin_id,
                failure
                    .architecture
                    .map_or_else(String::new, |architecture| format!(" {architecture}")),
                failure.diagnostic_code
            ),
            None => format!(
                "当前插件未能通过隔离宿主 Health 预检 ({})。",
                failure.diagnostic_code
            ),
        };
        items.push(item(
            "plugin-preflight",
            "当前插件宿主深度预检",
            DeploymentCheckStatus::Fail,
            summary,
            Some(preflight_failure_action(failure.diagnostic_code)),
        ));
    } else if facts.deep_preflight {
        items.push(item(
            "plugin-preflight",
            "当前插件宿主深度预检",
            DeploymentCheckStatus::Pass,
            if facts.deep_preflighted_hosts == 0 {
                "已完成深度检查，当前没有需要启动的插件宿主。".to_owned()
            } else {
                format!(
                    "当前插件已在 {} 个架构宿主中完成 Health 预检。",
                    facts.deep_preflighted_hosts
                )
            },
            None,
        ));
    } else if facts.plugin_preflight_failures > 0 {
        items.push(item(
            "plugin-preflight",
            "插件宿主历史预检",
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
            "当前插件宿主深度预检",
            DeploymentCheckStatus::Info,
            "快速检查不会主动启动插件宿主。",
            Some("正式交付或导出现场记录前执行一次深度自检。"),
        ));
    }

    if facts.managed_process_restart_required {
        items.push(item(
            "managed-processes",
            "项目辅助进程",
            DeploymentCheckStatus::Fail,
            "当前配置的受控辅助进程与本次启动已加载的选择不一致。",
            Some("退出并重新启动客户端，然后重新执行部署自检。"),
        ));
    } else if facts.managed_process_failures > 0 {
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
    let ready = failures == 0;
    DeploymentCheckReport {
        deep: facts.deep_preflight,
        deep_available: facts.is_windows,
        ready,
        delivery_ready: facts.is_windows && facts.deep_preflight && ready,
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

fn preflight_failure_action(code: &str) -> &'static str {
    match code {
        "native-component-missing" => "重新验签或安装目标插件，并确认入口及依赖文件完整。",
        "native-path-escape" => "修正越过插件目录的原生路径或重新打包；重复重试不会修复。",
        "native-dll-preflight-failed" => {
            "核对 DLL 位数、依赖文件和声明导出；修复后重新执行深度自检。"
        }
        "native-com-preflight-failed" => {
            "核对对应位数的 COM/OCX 注册、类和成员声明；修复后重新执行深度自检。"
        }
        "native-process-preflight-failed" => "核对 EXE/BAT 入口完整性，文件变化时重新打包或安装。",
        "native-operation-unsupported" | "host-architecture-mismatch" => {
            "检查组件类型、x86/x64 架构和静态 ABI 声明。"
        }
        "host-spawn-failed" => "确认客户端安装完整，并检查终端防护是否阻止插件宿主启动。",
        "plugin-trust-store-changed" => {
            "停止原生能力调用，使用组织发布的完整安装包修复客户端并重新启动。"
        }
        "host-protocol-version-mismatch" | "protocol-version-mismatch" => {
            "修复或重新安装当前 Desktop，确保主程序与插件宿主版本一致。"
        }
        "plugin-state-drifted-during-preflight" => {
            "插件在检查期间发生变化；重新扫描插件后再次执行深度自检。"
        }
        "plugin-inventory-unavailable" => "先修复插件目录或验签错误，再重新执行深度自检。",
        _ => "进入“插件管理”核对目标插件架构、依赖和入口定义；修复后重新执行深度自检。",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_facts() -> DeploymentCheckFacts {
        DeploymentCheckFacts {
            is_windows: true,
            deep_preflight: true,
            deep_preflighted_hosts: 3,
            deep_preflight_failure: None,
            config_error: None,
            project_identity_configured: true,
            business_origin_count: 2,
            business_window_count: 1,
            business_loading_windows: 0,
            business_navigating_windows: 0,
            business_ready_windows: 1,
            business_timed_out_windows: 0,
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
            managed_process_restart_required: false,
            app_update_configured: false,
        }
    }

    #[test]
    fn healthy_offline_windows_deployment_is_ready() {
        let report = evaluate(&healthy_facts());
        assert!(report.deep);
        assert!(report.deep_available);
        assert!(report.ready);
        assert!(report.delivery_ready);
        assert_eq!(report.failures, 0);
        assert!(report.passed >= 8);
        assert_eq!(report.warnings, 0);
    }

    #[test]
    fn unnamed_legacy_project_can_run_but_cannot_be_reported_as_deliverable() {
        let mut facts = healthy_facts();
        facts.project_identity_configured = false;

        let report = evaluate(&facts);

        assert!(!report.ready);
        assert!(!report.delivery_ready);
        assert!(report.items.iter().any(|item| {
            item.id == "project-identity"
                && item.status == DeploymentCheckStatus::Fail
                && item.action.is_some()
        }));
    }

    #[test]
    fn missing_project_hosts_and_ledger_block_delivery() {
        let mut facts = healthy_facts();
        facts.business_origin_count = 0;
        facts.x86_host_available = false;
        facts.tracked_invocations_available = false;

        let report = evaluate(&facts);
        assert!(!report.ready);
        assert!(!report.delivery_ready);
        assert_eq!(report.failures, 3);
        assert!(report.items.iter().any(|item| {
            item.id == "plugin-hosts" && item.status == DeploymentCheckStatus::Fail
        }));
    }

    #[test]
    fn changed_managed_process_selection_requires_restart_before_delivery() {
        let mut facts = healthy_facts();
        facts.managed_process_restart_required = true;

        let report = evaluate(&facts);

        assert!(!report.ready);
        assert!(!report.delivery_ready);
        assert!(report.items.iter().any(|item| {
            item.id == "managed-processes"
                && item.status == DeploymentCheckStatus::Fail
                && item.summary.contains("本次启动")
        }));
    }

    #[test]
    fn optional_operational_gaps_are_warnings_not_false_failures() {
        let mut facts = healthy_facts();
        facts.deep_preflight = false;
        facts.deep_preflighted_hosts = 0;
        facts.service_count = 0;
        facts.active_service_count = 0;
        facts.plugin_route_count = 0;
        facts.plugin_count = 0;
        facts.plugin_preflight_failures = 2;
        facts.diagnostics_available = false;

        let report = evaluate(&facts);
        assert!(report.ready);
        assert!(!report.delivery_ready);
        assert_eq!(report.failures, 0);
        assert_eq!(report.warnings, 3);
    }

    #[test]
    fn non_windows_development_skips_host_file_gate() {
        let mut facts = healthy_facts();
        facts.is_windows = false;
        facts.deep_preflight = false;
        facts.deep_preflighted_hosts = 0;
        facts.x86_host_available = false;
        facts.x64_host_available = false;

        let report = evaluate(&facts);
        assert!(report.ready);
        assert!(!report.deep_available);
        assert!(!report.delivery_ready);
        assert!(report.items.iter().any(|item| {
            item.id == "plugin-hosts" && item.status == DeploymentCheckStatus::Info
        }));
    }

    #[test]
    fn quick_check_does_not_claim_current_hosts_were_preflighted() {
        let mut facts = healthy_facts();
        facts.deep_preflight = false;
        facts.deep_preflighted_hosts = 0;

        let report = evaluate(&facts);

        assert!(!report.deep);
        assert!(report.deep_available);
        assert!(report.ready);
        assert!(!report.delivery_ready);
        assert!(report.items.iter().any(|item| {
            item.id == "plugin-preflight"
                && item.status == DeploymentCheckStatus::Info
                && item.summary.contains("快速检查")
        }));
    }

    #[test]
    fn deep_check_requires_a_real_business_page_handshake() {
        let mut facts = healthy_facts();
        facts.business_window_count = 0;
        facts.business_ready_windows = 0;

        let report = evaluate(&facts);

        assert!(!report.ready);
        assert!(!report.delivery_ready);
        assert!(report.items.iter().any(|item| {
            item.id == "business-frontend" && item.status == DeploymentCheckStatus::Fail
        }));
    }

    #[test]
    fn quick_check_without_a_business_window_remains_a_daily_readiness_check() {
        let mut facts = healthy_facts();
        facts.deep_preflight = false;
        facts.deep_preflighted_hosts = 0;
        facts.business_window_count = 0;
        facts.business_ready_windows = 0;

        let report = evaluate(&facts);

        assert!(report.ready);
        assert!(!report.delivery_ready);
        assert!(report.items.iter().any(|item| {
            item.id == "business-frontend" && item.status == DeploymentCheckStatus::Info
        }));
    }

    #[test]
    fn an_active_business_page_timeout_blocks_readiness() {
        let mut facts = healthy_facts();
        facts.business_ready_windows = 0;
        facts.business_timed_out_windows = 1;

        let report = evaluate(&facts);

        assert!(!report.ready);
        assert!(report.items.iter().any(|item| {
            item.id == "business-frontend"
                && item.status == DeploymentCheckStatus::Fail
                && item.summary.contains("30 秒")
        }));
    }

    #[test]
    fn failed_deep_host_preflight_blocks_delivery() {
        let mut facts = healthy_facts();
        facts.deep_preflight_failure = Some(DeploymentPreflightFailure {
            plugin_id: Some("reader-plugin".into()),
            architecture: Some("x86"),
            diagnostic_code: "native-dll-preflight-failed",
        });
        facts.deep_preflighted_hosts = 0;

        let report = evaluate(&facts);

        assert!(report.deep);
        assert!(!report.ready);
        assert!(!report.delivery_ready);
        assert!(report.items.iter().any(|item| {
            item.id == "plugin-preflight"
                && item.status == DeploymentCheckStatus::Fail
                && item.summary.contains("reader-plugin")
                && item.summary.contains("x86")
                && item.summary.contains("native-dll-preflight-failed")
                && item.action.is_some_and(|action| action.contains("DLL"))
        }));
    }

    #[test]
    fn changed_plugin_trust_has_a_specific_repair_action() {
        let action = preflight_failure_action("plugin-trust-store-changed");
        assert!(action.contains("停止原生能力调用"));
        assert!(action.contains("完整安装包"));
        assert!(action.contains("重新启动"));
        assert!(!action.contains('/') && !action.contains('\\'));
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
        assert_eq!(value["report"]["deliveryReady"], false);
        assert_eq!(value["report"]["deepAvailable"], true);
        assert!(bytes.len() < MAX_EXPORT_BYTES);
        assert!(!String::from_utf8(bytes)
            .unwrap()
            .contains("private.example"));
    }

    #[test]
    fn exported_deep_record_satisfies_the_production_windows_evidence_contract() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("deployment-check.json");
        let report = evaluate(&healthy_facts());
        let bytes =
            encode_export_document(&report, 1_786_000_000_000, "1.2.3", "windows", "x86_64")
                .unwrap();
        persist_export_document(&destination, &bytes).unwrap();

        let (record, digest) =
            ssdev_cutover_evidence::load_delivery_ready_deployment_check(&destination, "1.2.3")
                .unwrap();
        assert_eq!(digest, ssdev_cutover_evidence::sha256_bytes(&bytes));
        assert!(record.report.delivery_ready);
        assert!(record.report.items.iter().any(|item| {
            item.id == "business-frontend"
                && item.status == ssdev_cutover_evidence::DeploymentCheckRecordStatus::Pass
        }));
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
