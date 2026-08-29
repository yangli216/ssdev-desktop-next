use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tempfile::Builder as TempBuilder;
use thiserror::Error;
pub use webplus_plugin_config::PublicApiChange as ApiCompatibilityChange;
use webplus_plugin_config::{
    compare_public_api, discover_plugins, generate_typescript_client, PluginManifest,
    PluginMetadata, ServiceDefinition, API_FILENAME,
};
use webplus_plugin_package::{create_deterministic_package, PreparedPlugin};
use webplus_plugin_repository::{
    encode_catalog_document_with_withdrawals, CatalogEntry, CatalogWithdrawal,
};
use webplus_plugin_trust::{
    encode_signature_document, portable_plugin_path, prepare_signing_material, TrustPurpose,
    TrustStore, SIGNATURE_FILENAME,
};
use webplus_protocol::{
    contains_draft_placeholder, InvokeRequest, InvokeResponse, PluginArchitecture,
    DRAFT_INPUT_PLACEHOLDER, DRAFT_RESPONSE_PLACEHOLDER,
};

const MAX_PLUGIN_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PLUGIN_FILES: usize = 4096;
const MAX_SIGNING_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 1024;
const MAX_MATRIX_CASES: usize = 1024;
const MAX_MATRIX_PLUGINS: usize = 256;
const MAX_MATRIX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_WEB_KIT_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_WEB_KIT_TYPESCRIPT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_TRUST_STORE_BYTES: u64 = 256 * 1024;
const MAX_RELEASE_SET_SPEC_BYTES: u64 = 256 * 1024;
const MAX_CATALOG_SPEC_BYTES: u64 = 1024 * 1024;
const MAX_CATALOG_PACKAGES: usize = 4096;
const MAX_PE_EXPORTS: usize = 4096;
const MAX_PE_OPTIONAL_HEADER_BYTES: usize = 4096;
const MAX_PE_SECTIONS: usize = 96;
const MAX_PE_EXPORT_NAME_BYTES: usize = 1024;
const PLUGIN_METADATA_FILENAME: &str = "plugin.json";
const WEB_KIT_CLIENT_FILENAME: &str = "client.ts";
const WEB_KIT_FIXTURES_FILENAME: &str = "fixtures.ts";
const WEB_KIT_MANIFEST_FILENAME: &str = "ssdev-web-kit.json";
const LEGACY_LICENSE_FILENAME: &str = "license.dat";
const RELEASE_SET_MATERIALIZATION_MARKER: &str = ".release-set-materializing.json";

#[derive(Debug, Clone)]
pub struct PrepareOptions<'a> {
    pub source: &'a Path,
    pub staging: &'a Path,
    pub request: &'a Path,
    pub matrix_template: &'a Path,
    pub plugin_id: &'a str,
    pub version: &'a str,
    pub desktop_version_requirement: &'a str,
    pub display_name: &'a str,
    pub key_id: &'a str,
    pub trust_store: &'a Path,
    pub matrix_seed: Option<&'a Path>,
}

#[derive(Debug, Clone)]
pub struct FinalizeOptions<'a> {
    pub staging: &'a Path,
    pub request: &'a Path,
    pub signature: &'a Path,
    pub trust_store: &'a Path,
    pub package: &'a Path,
}

#[derive(Debug, Clone)]
pub struct CatalogOptions<'a> {
    pub spec: &'a Path,
    pub trust_store: &'a Path,
    pub catalog: &'a Path,
    pub now: SystemTime,
}

#[derive(Debug, Clone)]
pub struct MaterializeReleaseSetOptions<'a> {
    pub spec: &'a Path,
    pub trust_store: &'a Path,
    pub matrix: &'a Path,
    pub plugin_root: &'a Path,
}

#[derive(Debug, Clone)]
pub struct GenerateClientOptions<'a> {
    pub source: &'a Path,
    pub plugin_id: &'a str,
    pub display_name: Option<&'a str>,
    pub output: &'a Path,
}

#[derive(Debug, Clone)]
pub struct GenerateWebFixturesOptions<'a> {
    pub plugin_root: Option<&'a Path>,
    pub plugin_dir: Option<&'a Path>,
    pub matrix: &'a Path,
    pub output: &'a Path,
}

#[derive(Debug, Clone)]
pub struct GenerateWebKitOptions<'a> {
    pub plugin_dir: &'a Path,
    pub matrix: &'a Path,
    pub destination: &'a Path,
}

#[derive(Debug, Clone)]
pub struct InitDllPluginOptions<'a> {
    pub destination: &'a Path,
    pub plugin_id: &'a str,
    pub service_id: &'a str,
    pub display_name: &'a str,
    pub architecture: &'a str,
}

#[derive(Debug, Clone)]
pub struct SourceCheckOptions<'a> {
    pub source: &'a Path,
    pub plugin_id: &'a str,
}

#[derive(Debug, Clone)]
pub struct ApiCheckOptions<'a> {
    pub baseline_package: &'a Path,
    pub candidate_source: &'a Path,
    pub plugin_id: &'a str,
    pub trust_store: &'a Path,
    pub report: &'a Path,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareReport {
    pub schema_version: u8,
    pub plugin_id: String,
    pub version: String,
    pub desktop_version_requirement: String,
    pub key_id: String,
    pub service_count: usize,
    pub method_count: usize,
    pub signed_file_count: usize,
    pub payload_sha256: String,
    pub legacy_license_excluded: bool,
    pub matrix_seeded: bool,
    pub matrix_case_count: usize,
    pub matrix_placeholder_case_count: usize,
    pub matrix_review_required_case_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizeReport {
    pub schema_version: u8,
    pub plugin_id: String,
    pub version: String,
    pub desktop_version_requirement: String,
    pub key_id: String,
    pub signed_file_count: usize,
    pub payload_sha256: String,
    pub package_sha256: String,
    pub package_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyReport {
    pub schema_version: u8,
    pub plugin_id: String,
    pub version: String,
    pub desktop_version_requirement: Option<String>,
    pub key_id: String,
    pub service_count: usize,
    pub package_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseCheckReport {
    pub schema_version: u8,
    pub plugin_id: String,
    pub version: String,
    pub desktop_version_requirement: String,
    pub key_id: String,
    pub package_sha256: String,
    pub trust_store_sha256: String,
    pub matrix_sha256: String,
    pub service_count: usize,
    pub method_count: usize,
    pub case_count: usize,
    pub enabled_case_count: usize,
    pub package_verified: bool,
    pub matrix_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleasePackageReport {
    pub plugin_id: String,
    pub version: String,
    pub desktop_version_requirement: String,
    pub key_id: String,
    pub package_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseSetCheckReport {
    pub schema_version: u8,
    pub spec_sha256: String,
    pub package_set_sha256: String,
    pub trust_store_sha256: String,
    pub matrix_sha256: String,
    pub packages: Vec<ReleasePackageReport>,
    pub plugin_count: usize,
    pub service_count: usize,
    pub method_count: usize,
    pub case_count: usize,
    pub enabled_case_count: usize,
    pub packages_verified: bool,
    pub matrix_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MaterializeReleaseSetReport {
    pub schema_version: u8,
    pub spec_sha256: String,
    pub package_set_sha256: String,
    pub trust_store_sha256: String,
    pub matrix_sha256: String,
    pub plugin_count: usize,
    pub service_count: usize,
    pub method_count: usize,
    pub case_count: usize,
    pub enabled_case_count: usize,
    pub packages_verified: bool,
    pub matrix_verified: bool,
    pub root_verified: bool,
    pub materialized: bool,
}

struct CheckedReleasePackages {
    packages: Vec<ReleasePackageReport>,
    package_set_sha256: String,
    trust_store_sha256: String,
    matrix_sha256: String,
    matrix_report: MatrixCheckReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogReport {
    pub schema_version: u8,
    pub issued_at: u64,
    pub expires_at: u64,
    pub package_count: usize,
    pub withdrawal_count: usize,
    pub api_comparison_count: usize,
    pub api_compatibility_verified: bool,
    pub catalog_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateClientReport {
    pub schema_version: u8,
    pub plugin_id: String,
    pub display_name: String,
    pub service_count: usize,
    pub method_count: usize,
    pub output: PathBuf,
    pub output_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateWebFixturesReport {
    pub schema_version: u8,
    pub plugin_count: usize,
    pub service_count: usize,
    pub method_count: usize,
    pub fixture_count: usize,
    pub matrix_sha256: String,
    pub output: PathBuf,
    pub output_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateWebKitReport {
    pub schema_version: u8,
    pub plugin_id: String,
    pub plugin_version: String,
    pub service_count: usize,
    pub method_count: usize,
    pub fixture_count: usize,
    pub file_count: usize,
    pub api_sha256: String,
    pub plugin_metadata_sha256: String,
    pub matrix_sha256: String,
    pub client_sha256: String,
    pub fixtures_sha256: String,
    pub manifest_sha256: String,
    pub destination: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebKitCheckReport {
    pub schema_version: u8,
    pub plugin_id: String,
    pub plugin_version: String,
    pub service_count: usize,
    pub method_count: usize,
    pub fixture_count: usize,
    pub file_count: usize,
    pub api_sha256: String,
    pub plugin_metadata_sha256: String,
    pub matrix_sha256: String,
    pub client_sha256: String,
    pub fixtures_sha256: String,
    pub manifest_sha256: String,
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitDllPluginReport {
    pub schema_version: u8,
    pub plugin_id: String,
    pub service_id: String,
    pub display_name: String,
    pub architecture: PluginArchitecture,
    pub rust_crate_name: String,
    pub native_library: String,
    pub file_count: usize,
    pub destination: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceCheckReport {
    pub schema_version: u8,
    pub plugin_id: String,
    pub service_count: usize,
    pub method_count: usize,
    pub x86_service_count: usize,
    pub x64_service_count: usize,
    pub dll_service_count: usize,
    pub com_service_count: usize,
    pub process_service_count: usize,
    pub source_file_count: usize,
    pub source_bytes: u64,
    pub legacy_license_excluded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiCompatibilityReport {
    pub schema_version: u8,
    pub plugin_id: String,
    pub baseline_version: String,
    pub baseline_package_sha256: String,
    pub candidate_source_sha256: String,
    pub trust_store_sha256: String,
    pub compatible: bool,
    pub baseline_service_count: usize,
    pub candidate_service_count: usize,
    pub baseline_route_count: usize,
    pub candidate_route_count: usize,
    pub breaking_change_count: usize,
    pub review_change_count: usize,
    pub addition_count: usize,
    pub breaking_changes: Vec<ApiCompatibilityChange>,
    pub review_changes: Vec<ApiCompatibilityChange>,
    pub additions: Vec<ApiCompatibilityChange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SigningRequest {
    schema_version: u8,
    plugin_id: String,
    version: String,
    desktop_version_requirement: String,
    key_id: String,
    algorithm: String,
    files: BTreeMap<String, String>,
    payload_base64: String,
    payload_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseSetSpec {
    schema_version: u8,
    packages: Vec<PathBuf>,
}

struct ReleaseSetInputs {
    spec: PathBuf,
    spec_sha256: String,
    packages: Vec<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginMatrix {
    pub schema_version: u8,
    pub draft: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plugins: Vec<PluginMatrixTarget>,
    pub cases: Vec<PluginMatrixCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginMatrixTarget {
    pub plugin_id: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginMatrixCase {
    pub name: String,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub review_required: bool,
    pub request: InvokeRequest,
    pub expected: InvokeResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MatrixCheckReport {
    pub schema_version: u8,
    pub plugin_count: usize,
    pub service_count: usize,
    pub method_count: usize,
    pub case_count: usize,
    pub enabled_case_count: usize,
    pub identity_bound: bool,
}

fn enabled_by_default() -> bool {
    true
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CatalogSpec {
    schema_version: u8,
    issued_at: u64,
    expires_at: u64,
    packages: Vec<CatalogPackageSpec>,
    #[serde(default)]
    withdrawals: Vec<CatalogWithdrawal>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CatalogPackageSpec {
    package: PathBuf,
    url: url::Url,
}

struct CatalogVerifiedPackage {
    path: PathBuf,
    plugin_id: String,
    portable_plugin_id: String,
    version: Version,
    size: u64,
    sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GeneratedWebFixture {
    service_id: String,
    method: String,
    parameters: Map<String, Value>,
    response: InvokeResponse,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WebKitManifest {
    schema_version: u8,
    plugin_id: String,
    plugin_version: String,
    display_name: String,
    api_sha256: String,
    plugin_metadata_sha256: String,
    matrix_sha256: String,
    service_count: usize,
    method_count: usize,
    fixture_count: usize,
    files: WebKitFiles,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WebKitFiles {
    client: WebKitFile,
    fixtures: WebKitFile,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WebKitFile {
    path: String,
    sha256: String,
}

/// Creates a minimal, buildable Windows DLL plugin workspace for the common
/// UTF-8 input + caller-owned output-buffer ABI. Complex vendor ABIs still
/// require an explicit adapter design rather than additional scaffold flags.
pub fn init_dll_plugin(
    options: &InitDllPluginOptions<'_>,
) -> Result<InitDllPluginReport, ToolError> {
    ensure_fresh_output(options.destination, "plugin workspace")?;
    let destination = normalized_new_path(options.destination)?;
    let architecture = match options.architecture.trim().to_ascii_lowercase().as_str() {
        "x86" => PluginArchitecture::X86,
        "x64" => PluginArchitecture::X64,
        _ => {
            return Err(ToolError::Invalid(
                "DLL plugin architecture must be x86 or x64".into(),
            ))
        }
    };
    let display_name = checked_scaffold_text(options.display_name, "display name", 128)?;
    let service_id = checked_scaffold_text(options.service_id, "service ID", 256)?;
    let crate_name = scaffold_crate_name(options.plugin_id);
    let native_library = format!("{crate_name}.dll");
    let target = match architecture {
        PluginArchitecture::X86 => "i686-pc-windows-msvc",
        PluginArchitecture::X64 => "x86_64-pc-windows-msvc",
    };

    with_fresh_directory(&destination, "plugin workspace", |workspace| {
        for directory in [
            workspace.join("native/src"),
            workspace.join("release-source/bin"),
            workspace.join("web"),
        ] {
            fs::create_dir_all(&directory).map_err(|source| ToolError::Io {
                path: directory,
                source,
            })?;
        }

        let api = serde_json::json!([{
            "serviceId": service_id,
            "mainClass": format!("bin/{native_library}"),
            "mainType": "dll",
            "architecture": architecture,
            "charset": "utf8",
            "callingConvention": "cdecl",
            "cacheable": true,
            "timeout": 30_000,
            "deps": [],
            "methods": [{
                "name": "SsdevEcho",
                "alias": "echo",
                "returnType": "int",
                "parameters": [
                    { "name": "input", "type": "string" },
                    { "name": "$value", "type": "string", "len": 1024 }
                ]
            }]
        }]);
        write_new_json(workspace.join("release-source/api.json"), &api)?;

        let cargo_manifest = format!(
            "[package]\nname = {crate_name:?}\nversion = \"0.1.0\"\nedition = \"2021\"\npublish = false\n\n[lib]\ncrate-type = [\"cdylib\"]\n\n[workspace]\n"
        );
        write_new_bytes(
            &workspace.join("native/Cargo.toml"),
            cargo_manifest.as_bytes(),
        )?;
        let cargo_lock = format!(
            "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = {crate_name:?}\nversion = \"0.1.0\"\n"
        );
        write_new_bytes(&workspace.join("native/Cargo.lock"), cargo_lock.as_bytes())?;
        write_new_bytes(
            &workspace.join("native/src/lib.rs"),
            DLL_SCAFFOLD_RUST.as_bytes(),
        )?;

        let build_script = format!(
            "param()\n\n$ErrorActionPreference = \"Stop\"\nSet-StrictMode -Version Latest\n\n$root = $PSScriptRoot\n$target = \"{target}\"\n$library = \"{native_library}\"\n$manifest = Join-Path $root \"native/Cargo.toml\"\n$destination = Join-Path $root \"release-source/bin/$library\"\n\nrustup target add $target\nif ($LASTEXITCODE -ne 0) {{ throw \"rustup failed with exit code $LASTEXITCODE\" }}\ncargo build --locked --release --manifest-path $manifest --target $target\nif ($LASTEXITCODE -ne 0) {{ throw \"native plugin build failed with exit code $LASTEXITCODE\" }}\nCopy-Item -LiteralPath (Join-Path $root \"native/target/$target/release/$library\") -Destination $destination -Force\nWrite-Host \"Built plugin source: $destination\"\n"
        );
        write_new_bytes(&workspace.join("build.ps1"), build_script.as_bytes())?;

        let manifest = PluginManifest::load(options.plugin_id, workspace.join("release-source"))?;
        let client = generate_typescript_client(&display_name, &manifest.services)?;
        write_new_bytes(&workspace.join("web/client.ts"), client.as_bytes())?;
        let matrix = serde_json::json!({
            "schemaVersion": 1,
            "draft": true,
            "cases": [{
                "name": format!("{}.echo synthetic", service_id),
                "enabled": true,
                "reviewRequired": true,
                "request": {
                    "serviceId": service_id,
                    "method": "echo",
                    "parameters": { "input": "SSDEV_TEST" }
                },
                "expected": {
                    "ResCode": 0,
                    "ResData": { "ReturnValue": 0, "value": "SSDEV_TEST" }
                }
            }]
        });
        write_new_json(workspace.join("matrix-seed.json"), &matrix)?;

        let readme = scaffold_readme(
            options.plugin_id,
            &display_name,
            &service_id,
            architecture,
            &native_library,
        );
        write_new_bytes(&workspace.join("README.md"), readme.as_bytes())?;
        Ok(())
    })?;

    Ok(InitDllPluginReport {
        schema_version: 1,
        plugin_id: options.plugin_id.to_owned(),
        service_id,
        display_name,
        architecture,
        rust_crate_name: crate_name,
        native_library,
        file_count: 8,
        destination,
    })
}

fn checked_scaffold_text(value: &str, role: &str, limit: usize) -> Result<String, ToolError> {
    if value.trim() != value
        || value.is_empty()
        || value.chars().count() > limit
        || value.chars().any(char::is_control)
    {
        return Err(ToolError::Invalid(format!(
            "plugin {role} must be trimmed, non-empty, and at most {limit} safe characters"
        )));
    }
    Ok(value.to_owned())
}

fn scaffold_crate_name(plugin_id: &str) -> String {
    let mut stem = String::new();
    let mut separator = false;
    for character in plugin_id.chars() {
        if character.is_ascii_alphanumeric() {
            if separator && !stem.is_empty() {
                stem.push('_');
            }
            stem.push(character.to_ascii_lowercase());
            separator = false;
        } else {
            separator = true;
        }
        if stem.len() >= 40 {
            break;
        }
    }
    while stem.ends_with('_') {
        stem.pop();
    }
    if stem.is_empty() {
        stem.push_str("plugin");
    }
    let identity = sha256_hex(plugin_id.as_bytes());
    format!("ssdev_{stem}_{}_native", &identity[..8])
}

fn scaffold_readme(
    plugin_id: &str,
    display_name: &str,
    service_id: &str,
    architecture: PluginArchitecture,
    native_library: &str,
) -> String {
    let architecture = match architecture {
        PluginArchitecture::X86 => "x86",
        PluginArchitecture::X64 => "x64",
    };
    format!(
        "# {display_name}\n\nSSDEV DLL 插件脚手架。插件 ID：`{plugin_id}`；服务：`{service_id}`；架构：`{architecture}`。\n\n## 1. 构建 DLL\n\n在 Windows PowerShell 中运行：\n\n```powershell\n./build.ps1\n```\n\n脚本使用锁定依赖构建 `native` crate，并把 `{native_library}` 复制到 `release-source/bin`。修改导出函数后必须同步评审 `release-source/api.json`。\n\n## 2. 检查和本地调试\n\n先运行 `ssdev-plugin-tool source-check --source release-source --plugin-id {plugin_id}`。该命令不加载 DLL、不执行方法，也不需要签名密钥；它会用正式准备流程的同一规则检查文件边界、PE 位数、声明导出和 ABI。随后在 SSDEV Desktop 的“原生映射”工作台中选择 `release-source/bin/{native_library}`，按照 `release-source/api.json` 配置 `SsdevEcho`，然后使用输入 `SSDEV_TEST` 调用 `echo`。不要把生产账号、患者数据或不可逆设备操作放入调试用例。\n\n## 3. Web 接入\n\n`web/client.ts` 由共享清单生成器产生，依赖 `@bsoft/ssdev-web-bridge`。业务代码创建桌面连接后，把 `connection.bridge` 传给生成的客户端；`api.json` 变化后重新运行 `ssdev-plugin-tool client`，输出到一个新的临时文件，评审差异后替换业务制品。正式矩阵完成脱敏和实机复核后，使用 `ssdev-plugin-tool web-kit --plugin-dir <规范插件目录> --matrix <定稿矩阵> --destination <新目录>` 原子生成客户端、fixture 和摘要清单，再把整个接入包交给业务项目；业务 CI 使用 `ssdev-plugin-tool web-kit-check --kit <接入包目录>` 拒绝文件集或摘要漂移。\n\n## 4. 签名发布\n\n先运行 `ssdev-plugin-tool prepare --source release-source ... --matrix-seed matrix-seed.json`。矩阵种子保持 `draft: true` 和 `reviewRequired: true`；必须在 Windows 测试环境核对完整响应后才可解除这两项门禁。随后由组织 KMS/HSM 签名，并使用 `finalize` 生成 `.ssdev-plugin`。私钥、真实硬件数据和业务 Web 源码都不能放入 `release-source`。\n\n此模板只覆盖 UTF-8 字符串输入和 1 KiB 调用方输出缓冲区。结构体、回调、浮点 ABI、厂商内存释放或线程绑定组件需要单独设计 Rust 适配器，不能通过修改 JSON 猜测。\n"
    )
}

const DLL_SCAFFOLD_RUST: &str = r#"//! Minimal SSDEV native adapter for the bounded DLL ABI.

const OUTPUT_CAPACITY: usize = 1024;
const MAX_INPUT_BYTES: usize = 32 * 1024;
const ERROR_SUCCESS: usize = 0;
const ERROR_INVALID_PARAMETER: usize = 87;
const ERROR_INSUFFICIENT_BUFFER: usize = 122;

/// Echoes one NUL-terminated UTF-8 input into the caller-owned output buffer.
///
/// # Safety
///
/// `input` must point to a readable NUL-terminated string no longer than
/// `MAX_INPUT_BYTES`. `output` must point to the 1024-byte writable buffer
/// declared in `release-source/api.json`.
#[export_name = "SsdevEcho"]
pub unsafe extern "C" fn ssdev_echo(input: *const u8, output: *mut u8) -> usize {
    let value = match unsafe { read_utf8(input) } {
        Ok(value) => value,
        Err(code) => return code,
    };
    unsafe { write_output(output, value.as_bytes()) }
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

unsafe fn write_output(output: *mut u8, value: &[u8]) -> usize {
    if output.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    if value.len() >= OUTPUT_CAPACITY {
        return ERROR_INSUFFICIENT_BUFFER;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(value.as_ptr(), output, value.len());
        output.add(value.len()).write(0);
    }
    ERROR_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echoes_utf8_into_the_declared_buffer() {
        let input = b"SSDEV_TEST\0";
        let mut output = [0_u8; OUTPUT_CAPACITY];
        let code = unsafe { ssdev_echo(input.as_ptr(), output.as_mut_ptr()) };
        assert_eq!(code, ERROR_SUCCESS);
        assert_eq!(&output[..10], b"SSDEV_TEST");
        assert_eq!(output[10], 0);
    }
}
"#;

/// Performs the structural and native-file checks used by `prepare` without
/// requiring a trust store, signing identity, or any output path. Native code
/// is never loaded or executed.
pub fn check_source(options: &SourceCheckOptions<'_>) -> Result<SourceCheckReport, ToolError> {
    let source = canonical_real_directory(options.source)?;
    let temporary = tempfile::tempdir().map_err(|source| ToolError::Io {
        path: std::env::temp_dir(),
        source,
    })?;
    let snapshot = temporary.path().join("source-check");
    fs::create_dir(&snapshot).map_err(|source| ToolError::Io {
        path: snapshot.clone(),
        source,
    })?;
    let copy = copy_legacy_plugin(&source, &snapshot)?;
    let manifest = PluginManifest::load(options.plugin_id, &snapshot)?;
    validate_release_manifest(&manifest)?;

    let mut x86_service_count = 0;
    let mut x64_service_count = 0;
    let mut dll_service_count = 0;
    let mut com_service_count = 0;
    let mut process_service_count = 0;
    for service in &manifest.services {
        match service.architecture {
            PluginArchitecture::X86 => x86_service_count += 1,
            PluginArchitecture::X64 => x64_service_count += 1,
        }
        match service.resolved_main_type().to_ascii_lowercase().as_str() {
            "dll" => dll_service_count += 1,
            "com" | "ocx" => com_service_count += 1,
            "exe" | "bat" => process_service_count += 1,
            _ => unreachable!("manifest validation accepts only known service types"),
        }
    }
    Ok(SourceCheckReport {
        schema_version: 1,
        plugin_id: manifest.plugin_id,
        service_count: manifest.services.len(),
        method_count: manifest
            .services
            .iter()
            .map(|service| service.methods.len())
            .sum(),
        x86_service_count,
        x64_service_count,
        dll_service_count,
        com_service_count,
        process_service_count,
        source_file_count: copy.files,
        source_bytes: copy.bytes,
        legacy_license_excluded: copy.legacy_license_excluded,
    })
}

/// Verifies a previously signed package, validates the candidate with the same
/// rules as `prepare`, and rejects public Web Bridge contract regressions. The
/// deterministic report is written before an incompatibility error is
/// returned so CI and release reviewers can inspect stable change codes.
pub fn check_api_compatibility(
    options: &ApiCheckOptions<'_>,
) -> Result<ApiCompatibilityReport, ToolError> {
    ensure_fresh_output(options.report, "API compatibility report")?;
    let candidate_source = canonical_real_directory(options.candidate_source)?;
    let report_path = normalized_new_path(options.report)?;
    if report_path.starts_with(&candidate_source) {
        return Err(ToolError::Invalid(
            "API compatibility report must stay outside the candidate source directory".into(),
        ));
    }

    let trust_store = TrustStore::load(options.trust_store)?;
    let trust_store_sha256 = sha256_file_bounded(options.trust_store, MAX_TRUST_STORE_BYTES)?;
    let baseline_package_sha256 = sha256_file(options.baseline_package)?;
    let baseline_root = tempfile::tempdir().map_err(|source| ToolError::Io {
        path: std::env::temp_dir(),
        source,
    })?;
    let baseline =
        PreparedPlugin::prepare(options.baseline_package, baseline_root.path(), &trust_store)?;
    if baseline.identity().plugin_id != options.plugin_id {
        return Err(ToolError::Invalid(format!(
            "baseline package plugin ID [{}] does not match requested plugin ID [{}]",
            baseline.identity().plugin_id,
            options.plugin_id
        )));
    }

    let candidate_root = tempfile::tempdir().map_err(|source| ToolError::Io {
        path: std::env::temp_dir(),
        source,
    })?;
    let candidate_snapshot = candidate_root.path().join("candidate");
    fs::create_dir(&candidate_snapshot).map_err(|source| ToolError::Io {
        path: candidate_snapshot.clone(),
        source,
    })?;
    copy_legacy_plugin(&candidate_source, &candidate_snapshot)?;
    let candidate = PluginManifest::load(options.plugin_id, &candidate_snapshot)?;
    validate_release_manifest(&candidate)?;
    let candidate_material =
        prepare_signing_material(&candidate_snapshot, options.plugin_id, "api-check")?;
    let candidate_source_sha256 = sha256_hex(&candidate_material.payload);

    let report = compare_api_contracts(
        baseline.manifest(),
        &candidate,
        baseline.metadata().version.to_string(),
        baseline_package_sha256,
        candidate_source_sha256,
        trust_store_sha256,
    );
    write_new_json(&report_path, &report)?;
    if !report.compatible {
        return Err(ToolError::ApiIncompatible {
            breaking_change_count: report.breaking_change_count,
            report: report_path,
        });
    }
    Ok(report)
}

/// Generates the same typed Web Bridge client used by the desktop mapping
/// workbench, without requiring an interactive desktop session.
pub fn generate_client(
    options: &GenerateClientOptions<'_>,
) -> Result<GenerateClientReport, ToolError> {
    ensure_fresh_output(options.output, "typed client output")?;
    let source = canonical_real_directory(options.source)?;
    let output = normalized_new_path(options.output)?;
    if output.starts_with(&source) {
        return Err(ToolError::Invalid(
            "typed client output must stay outside the signed plugin source directory".into(),
        ));
    }
    let manifest = PluginManifest::load(options.plugin_id, &source)?;
    let display_name = options
        .display_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .or_else(|| {
            manifest
                .metadata
                .as_ref()
                .map(|metadata| metadata.display_name.trim())
                .filter(|name| !name.is_empty())
        })
        .unwrap_or(options.plugin_id)
        .to_owned();
    if display_name.chars().count() > 128 {
        return Err(ToolError::Invalid(
            "plugin display name must not exceed 128 characters".into(),
        ));
    }
    let client = generate_typescript_client(&display_name, &manifest.services)?;
    write_new_bytes(&output, client.as_bytes())?;
    Ok(GenerateClientReport {
        schema_version: 1,
        plugin_id: manifest.plugin_id,
        display_name,
        service_count: manifest.services.len(),
        method_count: manifest
            .services
            .iter()
            .map(|service| service.methods.len())
            .sum(),
        output,
        output_sha256: sha256_hex(client.as_bytes()),
    })
}

/// Generates strict business-frontend fixtures from the same structurally
/// complete executable matrix used by release and hardware gates. Disabled
/// scenarios are intentionally omitted. Passing this check does not prove that
/// hardware execution or organizational approval occurred. Public aliases are
/// normalized to the route emitted by the typed client generator.
pub fn generate_web_fixtures(
    options: &GenerateWebFixturesOptions<'_>,
) -> Result<GenerateWebFixturesReport, ToolError> {
    ensure_fresh_output(options.output, "Web fixture output")?;
    if options.output.extension().and_then(|value| value.to_str()) != Some("ts") {
        return Err(ToolError::Invalid(
            "Web fixture output must use the .ts extension".into(),
        ));
    }
    let output = normalized_new_path(options.output)?;
    let (input_root, manifests) = match (options.plugin_root, options.plugin_dir) {
        (Some(plugin_root), None) => {
            let input_root = canonical_real_directory(plugin_root)?;
            let manifests = discover_clean_plugin_root(&input_root)?;
            (input_root, manifests)
        }
        (None, Some(plugin_dir)) => {
            let input_root = canonical_real_directory(plugin_dir)?;
            let metadata = PluginMetadata::load_optional(&input_root)?.ok_or_else(|| {
                ToolError::Invalid(
                    "Web fixture plugin directory must contain normalized plugin.json".into(),
                )
            })?;
            let manifest = PluginManifest::load(metadata.plugin_id, &input_root)?;
            (input_root, vec![manifest])
        }
        _ => {
            return Err(ToolError::Invalid(
                "Web fixture generation requires exactly one plugin root or plugin directory"
                    .into(),
            ))
        }
    };
    if output.starts_with(&input_root) {
        return Err(ToolError::Invalid(
            "Web fixture output must stay outside the verified plugin input".into(),
        ));
    }

    let matrix_sha256 = sha256_file(options.matrix)?;
    let (matrix, matrix_report) = validate_executable_matrix(options.matrix, &manifests)?;
    if sha256_file(options.matrix)? != matrix_sha256 {
        return Err(ToolError::Invalid(
            "executable matrix changed while Web fixtures were being generated".into(),
        ));
    }
    if !matrix_report.identity_bound {
        return Err(ToolError::Invalid(
            "Web fixture matrix must bind the exact plugin identities and versions".into(),
        ));
    }
    let services = manifests
        .iter()
        .flat_map(|manifest| manifest.services.iter())
        .map(|service| (service.service_id.as_str(), service))
        .collect::<BTreeMap<_, _>>();
    let mut identities = BTreeSet::new();
    let mut fixtures = Vec::with_capacity(matrix_report.enabled_case_count);
    for case in matrix.cases.into_iter().filter(|case| case.enabled) {
        let service = services
            .get(case.request.service_id.as_str())
            .copied()
            .ok_or_else(|| ToolError::Invalid("validated matrix service disappeared".into()))?;
        let method = service
            .method(&case.request.method)
            .ok_or_else(|| ToolError::Invalid("validated matrix method disappeared".into()))?;
        let public_method = method.alias.as_deref().unwrap_or(&method.name).to_owned();
        if case
            .request
            .parameters
            .values()
            .any(|value| !web_fixture_value_is_javascript_safe(value))
            || !web_fixture_value_is_javascript_safe(&case.expected.res_data)
        {
            return Err(ToolError::Invalid(format!(
                "executable matrix route [{}/{}] contains an integer outside the JavaScript safe range; encode exact 64-bit values as strings",
                case.request.service_id, public_method
            )));
        }
        let identity = serde_json::to_vec(&(
            case.request.service_id.as_str(),
            public_method.as_str(),
            &case.request.parameters,
        ))?;
        if !identities.insert(identity) {
            return Err(ToolError::Invalid(format!(
                "executable matrix contains duplicate Web fixture input for route [{}/{}]; split alternative device states into separate fixture modules",
                case.request.service_id, public_method
            )));
        }
        fixtures.push(GeneratedWebFixture {
            service_id: case.request.service_id,
            method: public_method,
            parameters: case.request.parameters,
            response: case.expected,
        });
    }

    let fixtures_json = serde_json::to_string_pretty(&fixtures)?;
    let source = format!(
        "// Generated from a structurally valid SSDEV executable matrix.\n\
// Matrix SHA-256: {matrix_sha256}\n\
// This does not prove hardware approval. Review exact data before committing.\n\
import type {{ PluginInvocationFixture }} from '@bsoft/ssdev-web-bridge'\n\n\
export const pluginFixtures = {fixtures_json} satisfies readonly PluginInvocationFixture[]\n"
    );
    write_new_bytes(&output, source.as_bytes())?;
    Ok(GenerateWebFixturesReport {
        schema_version: 1,
        plugin_count: matrix_report.plugin_count,
        service_count: matrix_report.service_count,
        method_count: matrix_report.method_count,
        fixture_count: fixtures.len(),
        matrix_sha256,
        output,
        output_sha256: sha256_hex(source.as_bytes()),
    })
}

/// Atomically creates the version-bound handoff consumed by a business Web
/// project. The client and fixtures are generated from one plugin snapshot and
/// a complete executable matrix, while the manifest binds every source and
/// generated file digest. This remains a source artifact and does not prove
/// that hardware approval occurred.
pub fn generate_web_kit(
    options: &GenerateWebKitOptions<'_>,
) -> Result<GenerateWebKitReport, ToolError> {
    let plugin_dir = canonical_real_directory(options.plugin_dir)?;
    let destination = normalized_new_path(options.destination)?;
    if destination.starts_with(&plugin_dir) {
        return Err(ToolError::Invalid(
            "Web kit destination must stay outside the verified plugin input".into(),
        ));
    }

    let api_path = plugin_dir.join(API_FILENAME);
    let plugin_metadata_path = plugin_dir.join(PLUGIN_METADATA_FILENAME);
    let api_sha256 = sha256_file(&api_path)?;
    let plugin_metadata_sha256 = sha256_file(&plugin_metadata_path)?;
    let matrix_sha256 = sha256_file_bounded(options.matrix, MAX_MATRIX_BYTES)?;
    let metadata = PluginMetadata::load_optional(&plugin_dir)?.ok_or_else(|| {
        ToolError::Invalid("Web kit plugin directory must contain normalized plugin.json".into())
    })?;
    let manifest = PluginManifest::load(metadata.plugin_id.clone(), &plugin_dir)?;
    let plugin_id = metadata.plugin_id;
    let plugin_version = metadata.version.to_string();
    let display_name = if metadata.display_name.trim().is_empty() {
        plugin_id.clone()
    } else {
        metadata.display_name
    };
    let service_count = manifest.services.len();
    let method_count = manifest
        .services
        .iter()
        .map(|service| service.methods.len())
        .sum();
    let generated_client = generate_typescript_client(&display_name, &manifest.services)?;
    let client = format!(
        "// Web kit plugin: {plugin_id}@{plugin_version}\n\
// API SHA-256: {api_sha256}\n\
{generated_client}"
    );

    with_fresh_directory(&destination, "Web kit destination", |destination| {
        let fixtures_path = destination.join(WEB_KIT_FIXTURES_FILENAME);
        let fixtures = generate_web_fixtures(&GenerateWebFixturesOptions {
            plugin_root: None,
            plugin_dir: Some(&plugin_dir),
            matrix: options.matrix,
            output: &fixtures_path,
        })?;
        if fixtures.plugin_count != 1 || fixtures.matrix_sha256 != matrix_sha256 {
            return Err(ToolError::Invalid(
                "Web kit fixture generation no longer matches the checked plugin snapshot".into(),
            ));
        }

        let client_path = destination.join(WEB_KIT_CLIENT_FILENAME);
        write_new_bytes(&client_path, client.as_bytes())?;
        let client_sha256 = sha256_hex(client.as_bytes());
        let fixtures_sha256 = fixtures.output_sha256;
        let kit_manifest = WebKitManifest {
            schema_version: 1,
            plugin_id: plugin_id.clone(),
            plugin_version: plugin_version.clone(),
            display_name: display_name.clone(),
            api_sha256: api_sha256.clone(),
            plugin_metadata_sha256: plugin_metadata_sha256.clone(),
            matrix_sha256: matrix_sha256.clone(),
            service_count,
            method_count,
            fixture_count: fixtures.fixture_count,
            files: WebKitFiles {
                client: WebKitFile {
                    path: WEB_KIT_CLIENT_FILENAME.into(),
                    sha256: client_sha256.clone(),
                },
                fixtures: WebKitFile {
                    path: WEB_KIT_FIXTURES_FILENAME.into(),
                    sha256: fixtures_sha256.clone(),
                },
            },
        };
        let manifest_path = destination.join(WEB_KIT_MANIFEST_FILENAME);
        write_new_json(&manifest_path, &kit_manifest)?;
        let manifest_sha256 = sha256_file(&manifest_path)?;

        if sha256_file(&api_path)? != api_sha256
            || sha256_file(&plugin_metadata_path)? != plugin_metadata_sha256
            || sha256_file_bounded(options.matrix, MAX_MATRIX_BYTES)? != matrix_sha256
        {
            return Err(ToolError::Invalid(
                "plugin API, metadata, or executable matrix changed while the Web kit was generated"
                    .into(),
            ));
        }

        Ok(GenerateWebKitReport {
            schema_version: 1,
            plugin_id: plugin_id.clone(),
            plugin_version: plugin_version.clone(),
            service_count,
            method_count,
            fixture_count: fixtures.fixture_count,
            file_count: 3,
            api_sha256: api_sha256.clone(),
            plugin_metadata_sha256: plugin_metadata_sha256.clone(),
            matrix_sha256: matrix_sha256.clone(),
            client_sha256,
            fixtures_sha256,
            manifest_sha256,
            destination: destination.to_path_buf(),
        })
    })
}

/// Verifies the fixed Web handoff file set without needing native components,
/// signing keys, or the original matrix. This detects accidental or unreviewed
/// drift after generation; it does not authenticate the publisher or prove the
/// source plugin and hardware evidence.
pub fn check_web_kit(kit: &Path) -> Result<WebKitCheckReport, ToolError> {
    let kit = canonical_real_directory(kit)?;
    let actual_files = fs::read_dir(&kit)
        .map_err(|source| ToolError::Io {
            path: kit.clone(),
            source,
        })?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .map_err(|source| ToolError::Io {
                    path: kit.clone(),
                    source,
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_files = BTreeSet::from([
        WEB_KIT_CLIENT_FILENAME.to_owned(),
        WEB_KIT_FIXTURES_FILENAME.to_owned(),
        WEB_KIT_MANIFEST_FILENAME.to_owned(),
    ]);
    if actual_files != expected_files {
        return Err(ToolError::Invalid(
            "Web kit must contain exactly client.ts, fixtures.ts, and ssdev-web-kit.json".into(),
        ));
    }

    let manifest_path = kit.join(WEB_KIT_MANIFEST_FILENAME);
    let manifest: WebKitManifest = read_bounded_json(&manifest_path, MAX_WEB_KIT_MANIFEST_BYTES)?;
    let version = Version::parse(&manifest.plugin_version).map_err(|error| {
        ToolError::Invalid(format!("Web kit plugin version is not SemVer: {error}"))
    })?;
    if manifest.schema_version != 1
        || manifest.plugin_id.trim() != manifest.plugin_id
        || Path::new(&manifest.plugin_id).components().count() != 1
        || portable_plugin_path(Path::new(&manifest.plugin_id))? != manifest.plugin_id
        || version.to_string() != manifest.plugin_version
    {
        return Err(ToolError::Invalid(
            "Web kit identity must use schema 1, a canonical portable plugin ID, and SemVer".into(),
        ));
    }
    if manifest.display_name.trim() != manifest.display_name
        || manifest.display_name.is_empty()
        || manifest.display_name.chars().count() > 128
        || manifest.display_name.chars().any(char::is_control)
    {
        return Err(ToolError::Invalid(
            "Web kit display name must be trimmed, non-empty, and at most 128 safe characters"
                .into(),
        ));
    }
    if manifest.service_count == 0
        || manifest.service_count > manifest.method_count
        || manifest.method_count > manifest.fixture_count
        || manifest.fixture_count > MAX_MATRIX_CASES
    {
        return Err(ToolError::Invalid(
            "Web kit coverage counts are inconsistent or exceed the matrix limit".into(),
        ));
    }
    if manifest.files.client.path != WEB_KIT_CLIENT_FILENAME
        || manifest.files.fixtures.path != WEB_KIT_FIXTURES_FILENAME
    {
        return Err(ToolError::Invalid(
            "Web kit manifest must reference the fixed TypeScript filenames".into(),
        ));
    }
    for digest in [
        &manifest.api_sha256,
        &manifest.plugin_metadata_sha256,
        &manifest.matrix_sha256,
        &manifest.files.client.sha256,
        &manifest.files.fixtures.sha256,
    ] {
        if !is_lowercase_sha256(digest) {
            return Err(ToolError::Invalid(
                "Web kit manifest digests must use 64 lowercase hexadecimal characters".into(),
            ));
        }
    }

    let client_path = kit.join(WEB_KIT_CLIENT_FILENAME);
    let fixtures_path = kit.join(WEB_KIT_FIXTURES_FILENAME);
    let client_bytes = read_bounded_file(&client_path, MAX_WEB_KIT_TYPESCRIPT_BYTES)?;
    let fixtures_bytes = read_bounded_file(&fixtures_path, MAX_WEB_KIT_TYPESCRIPT_BYTES)?;
    let client_sha256 = sha256_hex(&client_bytes);
    let fixtures_sha256 = sha256_hex(&fixtures_bytes);
    if client_sha256 != manifest.files.client.sha256
        || fixtures_sha256 != manifest.files.fixtures.sha256
    {
        return Err(ToolError::Invalid(
            "Web kit TypeScript content does not match its manifest digests".into(),
        ));
    }
    let client = std::str::from_utf8(&client_bytes)
        .map_err(|_| ToolError::Invalid("Web kit client.ts must be UTF-8".into()))?;
    let fixtures = std::str::from_utf8(&fixtures_bytes)
        .map_err(|_| ToolError::Invalid("Web kit fixtures.ts must be UTF-8".into()))?;
    let expected_client_header = format!(
        "// Web kit plugin: {}@{}\n// API SHA-256: {}\n",
        manifest.plugin_id, manifest.plugin_version, manifest.api_sha256
    );
    let expected_fixtures_header = format!(
        "// Generated from a structurally valid SSDEV executable matrix.\n// Matrix SHA-256: {}\n",
        manifest.matrix_sha256
    );
    if !client.starts_with(&expected_client_header)
        || !fixtures.starts_with(&expected_fixtures_header)
    {
        return Err(ToolError::Invalid(
            "Web kit TypeScript headers do not match the manifest identity and source digests"
                .into(),
        ));
    }

    Ok(WebKitCheckReport {
        schema_version: 1,
        plugin_id: manifest.plugin_id,
        plugin_version: manifest.plugin_version,
        service_count: manifest.service_count,
        method_count: manifest.method_count,
        fixture_count: manifest.fixture_count,
        file_count: 3,
        api_sha256: manifest.api_sha256,
        plugin_metadata_sha256: manifest.plugin_metadata_sha256,
        matrix_sha256: manifest.matrix_sha256,
        client_sha256,
        fixtures_sha256,
        manifest_sha256: sha256_file_bounded(&manifest_path, MAX_WEB_KIT_MANIFEST_BYTES)?,
        verified: true,
    })
}

fn web_fixture_value_is_javascript_safe(value: &Value) -> bool {
    const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => true,
        Value::Number(number) if number.is_i64() => number
            .as_i64()
            .is_some_and(|value| (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value)),
        Value::Number(number) if number.is_u64() => number
            .as_u64()
            .is_some_and(|value| value <= MAX_SAFE_INTEGER as u64),
        Value::Number(number) => number.as_f64().is_some_and(f64::is_finite),
        Value::Array(values) => values.iter().all(web_fixture_value_is_javascript_safe),
        Value::Object(values) => values.values().all(web_fixture_value_is_javascript_safe),
    }
}

pub fn prepare(options: &PrepareOptions<'_>) -> Result<PrepareReport, ToolError> {
    ensure_fresh_output(options.staging, "staging directory")?;
    ensure_fresh_output(options.request, "signing request")?;
    ensure_fresh_output(options.matrix_template, "matrix template")?;
    let trust_store = TrustStore::load(options.trust_store)?;
    trust_store.ensure_key_can_issue(TrustPurpose::Plugin, options.key_id)?;
    let source = canonical_real_directory(options.source)?;
    let matrix_seed = options
        .matrix_seed
        .map(|path| canonical_real_file(path, MAX_MATRIX_BYTES))
        .transpose()?;
    if matrix_seed
        .as_ref()
        .is_some_and(|matrix_seed| matrix_seed.starts_with(&source))
    {
        return Err(ToolError::Invalid(
            "matrix seed must stay outside the signed source directory".into(),
        ));
    }
    let staging = normalized_new_path(options.staging)?;
    let request = normalized_new_path(options.request)?;
    let matrix_template = normalized_new_path(options.matrix_template)?;
    for (role, path) in [
        ("staging directory", &staging),
        ("signing request", &request),
        ("matrix template", &matrix_template),
    ] {
        if path.starts_with(&source) {
            return Err(ToolError::Invalid(format!(
                "{role} must be outside the legacy source directory"
            )));
        }
    }
    if request.starts_with(&staging) || matrix_template.starts_with(&staging) {
        return Err(ToolError::Invalid(
            "signing request and matrix template must stay outside the signed staging directory"
                .into(),
        ));
    }

    let version = Version::parse(options.version)
        .map_err(|error| ToolError::Invalid(format!("plugin version is not SemVer: {error}")))?;
    if options.desktop_version_requirement.len() > 128 {
        return Err(ToolError::Invalid(
            "desktop version requirement must not exceed 128 characters".into(),
        ));
    }
    let desktop_version_requirement = VersionReq::parse(options.desktop_version_requirement)
        .map_err(|error| {
            ToolError::Invalid(format!(
                "desktop version requirement is not a SemVer requirement: {error}"
            ))
        })?;
    fs::create_dir(&staging).map_err(|source| ToolError::Io {
        path: staging.clone(),
        source,
    })?;
    let prepared = (|| {
        let copy = copy_legacy_plugin(&source, &staging)?;
        let metadata = PluginMetadata {
            schema_version: 1,
            plugin_id: options.plugin_id.to_owned(),
            version: version.clone(),
            desktop_version_requirement: Some(desktop_version_requirement.clone()),
            display_name: options.display_name.to_owned(),
        };
        write_new_json(staging.join(PLUGIN_METADATA_FILENAME), &metadata)?;

        let manifest = PluginManifest::load(options.plugin_id, &staging)?;
        validate_release_manifest(&manifest)?;
        let material = prepare_signing_material(&staging, options.plugin_id, options.key_id)?;
        let payload_sha256 = sha256_hex(&material.payload);
        let signing_request = SigningRequest {
            schema_version: 1,
            plugin_id: material.plugin_id.clone(),
            version: version.to_string(),
            desktop_version_requirement: desktop_version_requirement.to_string(),
            key_id: material.key_id.clone(),
            algorithm: "ed25519".into(),
            files: material.files.clone(),
            payload_base64: BASE64.encode(&material.payload),
            payload_sha256: payload_sha256.clone(),
        };
        let matrix = match matrix_seed.as_deref() {
            Some(path) => load_matrix_seed(path, &manifest)?,
            None => draft_matrix(&manifest)?,
        };
        Ok::<_, ToolError>((
            copy,
            manifest,
            material,
            payload_sha256,
            signing_request,
            matrix,
        ))
    })();
    let (copy, manifest, material, payload_sha256, signing_request, matrix) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }
    };
    if let Err(error) =
        write_external_outputs(&request, &signing_request, &matrix_template, &matrix)
    {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }

    Ok(PrepareReport {
        schema_version: 1,
        plugin_id: options.plugin_id.to_owned(),
        version: version.to_string(),
        desktop_version_requirement: desktop_version_requirement.to_string(),
        key_id: options.key_id.to_owned(),
        service_count: manifest.services.len(),
        method_count: manifest
            .services
            .iter()
            .map(|service| service.methods.len())
            .sum(),
        signed_file_count: material.files.len(),
        payload_sha256,
        legacy_license_excluded: copy.legacy_license_excluded,
        matrix_seeded: matrix_seed.is_some(),
        matrix_case_count: matrix.cases.len(),
        matrix_placeholder_case_count: matrix
            .cases
            .iter()
            .filter(|case| matrix_case_has_draft_placeholder(case))
            .count(),
        matrix_review_required_case_count: matrix
            .cases
            .iter()
            .filter(|case| case.review_required)
            .count(),
    })
}

pub fn finalize(options: &FinalizeOptions<'_>) -> Result<FinalizeReport, ToolError> {
    ensure_fresh_output(options.package, "plugin package")?;
    let staging = canonical_real_directory(options.staging)?;
    let request: SigningRequest = read_bounded_json(options.request, MAX_SIGNING_REQUEST_BYTES)?;
    if request.schema_version != 1 || request.algorithm != "ed25519" {
        return Err(ToolError::Invalid(
            "signing request must use schema 1 and Ed25519".into(),
        ));
    }
    let manifest = PluginManifest::load(&request.plugin_id, &staging)?;
    let staged_metadata = manifest
        .metadata
        .as_ref()
        .ok_or_else(|| ToolError::Invalid("staging directory must contain plugin.json".into()))?;
    if request.version != staged_metadata.version.to_string()
        || staged_metadata
            .desktop_version_requirement
            .as_ref()
            .map(ToString::to_string)
            .as_deref()
            != Some(request.desktop_version_requirement.as_str())
    {
        return Err(ToolError::Invalid(
            "signing request version or desktop compatibility does not match staged plugin metadata"
                .into(),
        ));
    }
    let material = prepare_signing_material(&staging, &request.plugin_id, &request.key_id)?;
    if request.files != material.files
        || request.payload_base64 != BASE64.encode(&material.payload)
        || request.payload_sha256 != sha256_hex(&material.payload)
    {
        return Err(ToolError::Invalid(
            "staging directory changed after the signing request was created".into(),
        ));
    }
    let signature = read_signature(options.signature)?;
    let envelope = encode_signature_document(&material, &signature)?;
    let trust_store = TrustStore::load(options.trust_store)?;
    trust_store.verify_detached_for_issuance(
        TrustPurpose::Plugin,
        &material.key_id,
        &material.payload,
        &signature,
    )?;
    let signature_path = staging.join(SIGNATURE_FILENAME);
    match fs::symlink_metadata(&signature_path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file()
                || fs::read(&signature_path).map_err(|source| ToolError::Io {
                    path: signature_path.clone(),
                    source,
                })? != envelope
            {
                return Err(ToolError::Invalid(
                    "staging directory already contains a different or unsafe signature envelope"
                        .into(),
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_new_bytes(&signature_path, &envelope)?;
        }
        Err(source) => {
            return Err(ToolError::Io {
                path: signature_path,
                source,
            })
        }
    }

    trust_store.verify_for_issuance(&manifest)?;
    create_deterministic_package(&staging, options.package, &trust_store)?;

    let verification_root = tempfile::tempdir().map_err(|source| ToolError::Io {
        path: std::env::temp_dir(),
        source,
    })?;
    let verified =
        PreparedPlugin::prepare(options.package, verification_root.path(), &trust_store)?;
    let metadata = verified.metadata();
    let package_sha256 = sha256_file(options.package)?;
    Ok(FinalizeReport {
        schema_version: 1,
        plugin_id: verified.identity().plugin_id.clone(),
        version: metadata.version.to_string(),
        desktop_version_requirement: request.desktop_version_requirement.clone(),
        key_id: verified.identity().key_id.clone(),
        signed_file_count: material.files.len(),
        payload_sha256: request.payload_sha256,
        package_sha256,
        package_verified: true,
    })
}

pub fn verify(package: &Path, trust_store: &Path) -> Result<VerifyReport, ToolError> {
    let trust_store = TrustStore::load(trust_store)?;
    let verification_root = tempfile::tempdir().map_err(|source| ToolError::Io {
        path: std::env::temp_dir(),
        source,
    })?;
    let prepared = PreparedPlugin::prepare(package, verification_root.path(), &trust_store)?;
    let package_sha256 = sha256_file(package)?;
    Ok(VerifyReport {
        schema_version: 1,
        plugin_id: prepared.identity().plugin_id.clone(),
        version: prepared.metadata().version.to_string(),
        desktop_version_requirement: prepared
            .metadata()
            .desktop_version_requirement
            .as_ref()
            .map(ToString::to_string),
        key_id: prepared.identity().key_id.clone(),
        service_count: prepared.manifest().services.len(),
        package_sha256,
    })
}

pub fn check_release_candidate(
    package: &Path,
    trust_store: &Path,
    matrix: &Path,
) -> Result<ReleaseCheckReport, ToolError> {
    let checked = check_release_packages(&[package.to_path_buf()], trust_store, matrix)?;
    let package = checked
        .packages
        .into_iter()
        .next()
        .ok_or_else(|| ToolError::Invalid("release candidate package is missing".into()))?;
    Ok(ReleaseCheckReport {
        schema_version: 1,
        plugin_id: package.plugin_id,
        version: package.version,
        desktop_version_requirement: package.desktop_version_requirement,
        key_id: package.key_id,
        package_sha256: package.package_sha256,
        trust_store_sha256: checked.trust_store_sha256,
        matrix_sha256: checked.matrix_sha256,
        service_count: checked.matrix_report.service_count,
        method_count: checked.matrix_report.method_count,
        case_count: checked.matrix_report.case_count,
        enabled_case_count: checked.matrix_report.enabled_case_count,
        package_verified: true,
        matrix_verified: true,
    })
}

pub fn check_release_set(
    spec: &Path,
    trust_store: &Path,
    matrix: &Path,
) -> Result<ReleaseSetCheckReport, ToolError> {
    let inputs = load_release_set_inputs(spec)?;
    check_release_set_inputs(&inputs, trust_store, matrix)
}

fn load_release_set_inputs(spec: &Path) -> Result<ReleaseSetInputs, ToolError> {
    let spec = canonical_real_file(spec, MAX_RELEASE_SET_SPEC_BYTES)?;
    let spec_sha256 = sha256_file_bounded(&spec, MAX_RELEASE_SET_SPEC_BYTES)?;
    let document: ReleaseSetSpec = read_bounded_json(&spec, MAX_RELEASE_SET_SPEC_BYTES)?;
    if document.schema_version != 1
        || document.packages.is_empty()
        || document.packages.len() > MAX_MATRIX_PLUGINS
    {
        return Err(ToolError::Invalid(format!(
            "release set spec must use schema 1 and contain 1 to {MAX_MATRIX_PLUGINS} packages"
        )));
    }
    let parent = spec
        .parent()
        .ok_or_else(|| ToolError::Invalid("release set spec has no parent directory".into()))?;
    let package_paths = document
        .packages
        .into_iter()
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                parent.join(path)
            }
        })
        .collect::<Vec<_>>();
    Ok(ReleaseSetInputs {
        spec,
        spec_sha256,
        packages: package_paths,
    })
}

fn check_release_set_inputs(
    inputs: &ReleaseSetInputs,
    trust_store: &Path,
    matrix: &Path,
) -> Result<ReleaseSetCheckReport, ToolError> {
    let checked = check_release_packages(&inputs.packages, trust_store, matrix)?;
    if inputs.spec_sha256 != sha256_file_bounded(&inputs.spec, MAX_RELEASE_SET_SPEC_BYTES)? {
        return Err(ToolError::Invalid(
            "release set spec changed while it was checked".into(),
        ));
    }
    Ok(ReleaseSetCheckReport {
        schema_version: 1,
        spec_sha256: inputs.spec_sha256.clone(),
        package_set_sha256: checked.package_set_sha256,
        trust_store_sha256: checked.trust_store_sha256,
        matrix_sha256: checked.matrix_sha256,
        plugin_count: checked.matrix_report.plugin_count,
        service_count: checked.matrix_report.service_count,
        method_count: checked.matrix_report.method_count,
        case_count: checked.matrix_report.case_count,
        enabled_case_count: checked.matrix_report.enabled_case_count,
        packages: checked.packages,
        packages_verified: true,
        matrix_verified: true,
    })
}

pub fn materialize_release_set(
    options: &MaterializeReleaseSetOptions<'_>,
) -> Result<MaterializeReleaseSetReport, ToolError> {
    let plugin_root = normalized_new_path(options.plugin_root)?;
    let inputs = load_release_set_inputs(options.spec)?;
    let approved = check_release_set_inputs(&inputs, options.trust_store, options.matrix)?;
    with_fresh_directory(&plugin_root, "materialized plugin root", |plugin_root| {
        materialize_release_set_into(
            plugin_root,
            &inputs,
            &approved,
            options.trust_store,
            options.matrix,
        )
    })
}

fn materialize_release_set_into(
    plugin_root: &Path,
    inputs: &ReleaseSetInputs,
    approved: &ReleaseSetCheckReport,
    trust_store: &Path,
    matrix: &Path,
) -> Result<MaterializeReleaseSetReport, ToolError> {
    write_new_json(
        plugin_root.join(RELEASE_SET_MATERIALIZATION_MARKER),
        &serde_json::json!({
            "schemaVersion": 1,
            "specSha256": approved.spec_sha256,
            "packageSetSha256": approved.package_set_sha256
        }),
    )?;
    let trust = TrustStore::load(trust_store)?;
    for package in &inputs.packages {
        let prepared = PreparedPlugin::prepare(package, plugin_root, &trust)?;
        trust.verify_for_issuance(prepared.manifest())?;
        prepared.activate()?.commit()?;
    }
    fs::remove_file(plugin_root.join(RELEASE_SET_MATERIALIZATION_MARKER)).map_err(|source| {
        ToolError::Io {
            path: plugin_root.join(RELEASE_SET_MATERIALIZATION_MARKER),
            source,
        }
    })?;

    let verified = check_release_root_against_set(plugin_root, &inputs.spec, trust_store, matrix)?;
    if &verified != approved {
        return Err(ToolError::Invalid(
            "materialized plugin root no longer matches the approved release set".into(),
        ));
    }
    Ok(MaterializeReleaseSetReport {
        schema_version: 1,
        spec_sha256: verified.spec_sha256,
        package_set_sha256: verified.package_set_sha256,
        trust_store_sha256: verified.trust_store_sha256,
        matrix_sha256: verified.matrix_sha256,
        plugin_count: verified.plugin_count,
        service_count: verified.service_count,
        method_count: verified.method_count,
        case_count: verified.case_count,
        enabled_case_count: verified.enabled_case_count,
        packages_verified: verified.packages_verified,
        matrix_verified: verified.matrix_verified,
        root_verified: true,
        materialized: true,
    })
}

pub fn check_release_root_against_set(
    plugin_root: &Path,
    spec: &Path,
    trust_store: &Path,
    matrix: &Path,
) -> Result<ReleaseSetCheckReport, ToolError> {
    let release_set = check_release_set(spec, trust_store, matrix)?;
    let manifests = discover_clean_plugin_root(plugin_root)?;
    let trust = TrustStore::load(trust_store)?;
    for manifest in &manifests {
        trust.verify_for_issuance(manifest)?;
    }
    let (_, coverage) = validate_executable_matrix(matrix, &manifests)?;
    if coverage.plugin_count != release_set.plugin_count
        || coverage.service_count != release_set.service_count
        || coverage.method_count != release_set.method_count
        || coverage.enabled_case_count != release_set.enabled_case_count
    {
        return Err(ToolError::Invalid(
            "tested plugin root coverage does not match the release set".into(),
        ));
    }
    verify_release_packages_match_manifests(&release_set, &manifests, &trust)?;
    Ok(release_set)
}

fn verify_release_packages_match_manifests(
    release_set: &ReleaseSetCheckReport,
    manifests: &[PluginManifest],
    trust_store: &TrustStore,
) -> Result<(), ToolError> {
    if release_set.packages.len() != manifests.len() {
        return Err(ToolError::Invalid(
            "release set package count does not match the tested plugin root".into(),
        ));
    }
    let packages = release_set
        .packages
        .iter()
        .map(|package| (package.plugin_id.as_str(), package))
        .collect::<BTreeMap<_, _>>();
    if packages.len() != manifests.len() {
        return Err(ToolError::Invalid(
            "release set contains duplicate plugin identities".into(),
        ));
    }
    let rebuilt = tempfile::tempdir().map_err(|source| ToolError::Io {
        path: std::env::temp_dir(),
        source,
    })?;
    for manifest in manifests {
        let metadata = manifest.metadata.as_ref().ok_or_else(|| {
            ToolError::Invalid(
                "tested plugin root contains a plugin without version metadata".into(),
            )
        })?;
        let expected = packages.get(manifest.plugin_id.as_str()).ok_or_else(|| {
            ToolError::Invalid("tested plugin root is not the approved release set".into())
        })?;
        if expected.version != metadata.version.to_string() {
            return Err(ToolError::Invalid(
                "tested plugin version is not the approved release set version".into(),
            ));
        }
        let package_path = rebuilt
            .path()
            .join(format!("{}.ssdev-plugin", manifest.plugin_id));
        let identity =
            create_deterministic_package(&manifest.plugin_dir, &package_path, trust_store)?;
        if identity.key_id != expected.key_id
            || sha256_file(&package_path)? != expected.package_sha256
        {
            return Err(ToolError::Invalid(
                "tested plugin bytes do not match the approved release package".into(),
            ));
        }
    }
    Ok(())
}

fn check_release_packages(
    packages: &[PathBuf],
    trust_store: &Path,
    matrix: &Path,
) -> Result<CheckedReleasePackages, ToolError> {
    if packages.is_empty() || packages.len() > MAX_MATRIX_PLUGINS {
        return Err(ToolError::Invalid(format!(
            "release candidate must contain 1 to {MAX_MATRIX_PLUGINS} packages"
        )));
    }
    let mut package_paths = HashSet::new();
    let mut package_inputs = Vec::with_capacity(packages.len());
    for package in packages {
        let package = canonical_real_file(package, MAX_PLUGIN_BYTES)?;
        if package.extension().and_then(|value| value.to_str()) != Some("ssdev-plugin") {
            return Err(ToolError::Invalid(
                "release candidate packages must use the .ssdev-plugin extension".into(),
            ));
        }
        if !package_paths.insert(package.clone()) {
            return Err(ToolError::Invalid(
                "release candidate contains the same package path more than once".into(),
            ));
        }
        let digest = sha256_file(&package)?;
        package_inputs.push((package, digest));
    }

    let trust_store_sha256 = sha256_file_bounded(trust_store, MAX_TRUST_STORE_BYTES)?;
    let matrix_sha256 = sha256_file_bounded(matrix, MAX_MATRIX_BYTES)?;
    let trust = TrustStore::load(trust_store)?;
    let verification_root = tempfile::tempdir().map_err(|source| ToolError::Io {
        path: std::env::temp_dir(),
        source,
    })?;
    let mut prepared = Vec::with_capacity(package_inputs.len());
    for (package, _) in &package_inputs {
        let candidate = PreparedPlugin::prepare(package, verification_root.path(), &trust)?;
        trust.verify_for_issuance(candidate.manifest())?;
        prepared.push(candidate);
    }
    let manifests = prepared
        .iter()
        .map(|candidate| candidate.manifest().clone())
        .collect::<Vec<_>>();
    let (_, matrix_report) = validate_executable_matrix(matrix, &manifests)?;
    if !matrix_report.identity_bound {
        return Err(ToolError::Invalid(
            "release candidate matrix must bind the exact plugin IDs and versions".into(),
        ));
    }

    for (package, digest) in &package_inputs {
        if digest != &sha256_file(package)? {
            return Err(ToolError::Invalid(
                "release candidate package changed while it was checked".into(),
            ));
        }
    }
    if trust_store_sha256 != sha256_file_bounded(trust_store, MAX_TRUST_STORE_BYTES)?
        || matrix_sha256 != sha256_file_bounded(matrix, MAX_MATRIX_BYTES)?
    {
        return Err(ToolError::Invalid(
            "release candidate trust store or matrix changed while it was checked".into(),
        ));
    }

    let mut package_reports = prepared
        .iter()
        .zip(&package_inputs)
        .map(|(candidate, (_, package_sha256))| {
            let desktop_version_requirement = candidate
                .metadata()
                .desktop_version_requirement
                .as_ref()
                .ok_or_else(|| {
                    ToolError::Invalid(format!(
                        "release plugin [{}] does not declare desktop compatibility",
                        candidate.identity().plugin_id
                    ))
                })?
                .to_string();
            Ok(ReleasePackageReport {
                plugin_id: candidate.identity().plugin_id.clone(),
                version: candidate.metadata().version.to_string(),
                desktop_version_requirement,
                key_id: candidate.identity().key_id.clone(),
                package_sha256: package_sha256.clone(),
            })
        })
        .collect::<Result<Vec<_>, ToolError>>()?;
    package_reports.sort_by(|left, right| {
        left.plugin_id
            .to_ascii_lowercase()
            .cmp(&right.plugin_id.to_ascii_lowercase())
            .then_with(|| left.version.cmp(&right.version))
    });
    let package_bytes = serde_json::to_vec(&package_reports)?;
    let mut package_set_payload = b"SSDEV-PLUGIN-RELEASE-SET\0".to_vec();
    package_set_payload.extend_from_slice(&package_bytes);
    Ok(CheckedReleasePackages {
        packages: package_reports,
        package_set_sha256: sha256_hex(&package_set_payload),
        trust_store_sha256,
        matrix_sha256,
        matrix_report,
    })
}

pub fn create_catalog(options: &CatalogOptions<'_>) -> Result<CatalogReport, ToolError> {
    ensure_fresh_output(options.catalog, "plugin catalog")?;
    let spec: CatalogSpec = read_bounded_json(options.spec, MAX_CATALOG_SPEC_BYTES)?;
    if spec.schema_version != 1 {
        return Err(ToolError::Invalid(format!(
            "unsupported catalog build spec schema [{}]",
            spec.schema_version
        )));
    }
    if spec.packages.len() > MAX_CATALOG_PACKAGES {
        return Err(ToolError::Invalid(format!(
            "catalog build spec contains more than {MAX_CATALOG_PACKAGES} packages"
        )));
    }
    if spec.withdrawals.len() > MAX_CATALOG_PACKAGES {
        return Err(ToolError::Invalid(format!(
            "catalog build spec contains more than {MAX_CATALOG_PACKAGES} withdrawals"
        )));
    }
    let spec_parent = canonical_real_directory(output_parent(options.spec))?;
    let trust_store = TrustStore::load(options.trust_store)?;
    let verification_root = tempfile::tempdir().map_err(|source| ToolError::Io {
        path: std::env::temp_dir(),
        source,
    })?;
    let mut package_paths = HashSet::new();
    let mut package_urls = HashSet::new();
    let mut portable_plugin_ids = BTreeMap::new();
    let mut release_identities = BTreeSet::new();
    let mut verified_packages = Vec::with_capacity(spec.packages.len());
    let mut entries = Vec::with_capacity(spec.packages.len());
    for package_spec in spec.packages {
        let package_path = if package_spec.package.is_absolute() {
            package_spec.package
        } else {
            spec_parent.join(package_spec.package)
        };
        let metadata = fs::symlink_metadata(&package_path).map_err(|source| ToolError::Io {
            path: package_path.clone(),
            source,
        })?;
        if !metadata.file_type().is_file() {
            return Err(ToolError::Invalid(
                "catalog package inputs must be regular files, not links".into(),
            ));
        }
        let package_path = package_path
            .canonicalize()
            .map_err(|source| ToolError::Io {
                path: package_path.clone(),
                source,
            })?;
        if !package_paths.insert(package_path.clone()) {
            return Err(ToolError::Invalid(
                "catalog build spec contains a duplicate package path".into(),
            ));
        }
        if !package_urls.insert(package_spec.url.as_str().to_owned()) {
            return Err(ToolError::Invalid(
                "catalog build spec contains a duplicate package URL".into(),
            ));
        }
        let size_before = metadata.len();
        let digest_before = sha256_file(&package_path)?;
        let prepared =
            PreparedPlugin::prepare(&package_path, verification_root.path(), &trust_store)?;
        let identity = prepared.identity().clone();
        let metadata = prepared.metadata();
        let version = metadata.version.clone();
        let desktop_version_requirement = metadata
            .desktop_version_requirement
            .as_ref()
            .ok_or_else(|| {
                ToolError::Invalid(format!(
                    "catalog plugin [{}] does not declare desktop compatibility",
                    identity.plugin_id
                ))
            })?
            .clone();
        let portable_plugin_id = identity.plugin_id.to_ascii_lowercase();
        if let Some(existing) =
            portable_plugin_ids.insert(portable_plugin_id.clone(), identity.plugin_id.clone())
        {
            if existing != identity.plugin_id {
                return Err(ToolError::Invalid(format!(
                    "catalog plugin ID [{}] uses inconsistent ASCII casing across releases",
                    identity.plugin_id
                )));
            }
        }
        if !release_identities.insert((portable_plugin_id.clone(), version.clone())) {
            return Err(ToolError::Invalid(format!(
                "catalog contains duplicate portable plugin release [{} {}]",
                identity.plugin_id, version
            )));
        }
        drop(prepared);
        let metadata_after =
            fs::symlink_metadata(&package_path).map_err(|source| ToolError::Io {
                path: package_path.clone(),
                source,
            })?;
        let digest_after = sha256_file(&package_path)?;
        if !metadata_after.file_type().is_file()
            || metadata_after.len() != size_before
            || digest_after != digest_before
        {
            return Err(ToolError::Invalid(
                "plugin package changed while the catalog was being created".into(),
            ));
        }
        verified_packages.push(CatalogVerifiedPackage {
            path: package_path,
            plugin_id: identity.plugin_id.clone(),
            portable_plugin_id,
            version: version.clone(),
            size: size_before,
            sha256: digest_before.clone(),
        });
        entries.push(CatalogEntry {
            plugin_id: identity.plugin_id,
            version,
            desktop_version_requirement: Some(desktop_version_requirement),
            url: package_spec.url,
            sha256: digest_before,
            size: size_before,
        });
    }
    let api_comparison_count = verify_catalog_api_compatibility(
        &mut verified_packages,
        &trust_store,
        verification_root.path(),
    )?;
    let withdrawal_count = spec.withdrawals.len();
    let bytes = encode_catalog_document_with_withdrawals(
        spec.issued_at,
        spec.expires_at,
        entries,
        spec.withdrawals,
        options.now,
    )?;
    let catalog_sha256 = sha256_hex(&bytes);
    write_new_bytes(options.catalog, &bytes)?;
    Ok(CatalogReport {
        schema_version: 1,
        issued_at: spec.issued_at,
        expires_at: spec.expires_at,
        package_count: package_urls.len(),
        withdrawal_count,
        api_comparison_count,
        api_compatibility_verified: true,
        catalog_sha256,
    })
}

fn verify_catalog_api_compatibility(
    packages: &mut [CatalogVerifiedPackage],
    trust_store: &TrustStore,
    verification_root: &Path,
) -> Result<usize, ToolError> {
    packages.sort_by(|left, right| {
        left.portable_plugin_id
            .cmp(&right.portable_plugin_id)
            .then_with(|| left.version.cmp(&right.version))
    });

    let mut comparison_count = 0;
    let mut previous: Option<(String, String, Version, Vec<ServiceDefinition>)> = None;
    for package in packages {
        ensure_catalog_package_unchanged(package)?;
        let prepared = PreparedPlugin::prepare(&package.path, verification_root, trust_store)?;
        if prepared.identity().plugin_id != package.plugin_id
            || prepared.metadata().version != package.version
        {
            return Err(ToolError::Invalid(
                "plugin package identity changed while the catalog was being created".into(),
            ));
        }
        let services = prepared.manifest().services.clone();
        ensure_catalog_package_unchanged(package)?;

        if let Some((
            previous_portable_plugin_id,
            previous_plugin_id,
            previous_version,
            previous_services,
        )) = &previous
        {
            if previous_portable_plugin_id == &package.portable_plugin_id {
                let compatibility = compare_public_api(previous_services, &services);
                comparison_count += 1;
                if !compatibility.compatible {
                    return Err(ToolError::Invalid(format!(
                        "catalog plugin [{}] version [{}] breaks {} public Web Bridge contract(s) from version [{}]; publish an incompatible API under a new plugin ID and run api-check for the detailed report",
                        previous_plugin_id,
                        package.version,
                        compatibility.breaking_changes.len(),
                        previous_version
                    )));
                }
            }
        }
        previous = Some((
            package.portable_plugin_id.clone(),
            package.plugin_id.clone(),
            package.version.clone(),
            services,
        ));
    }
    Ok(comparison_count)
}

fn ensure_catalog_package_unchanged(package: &CatalogVerifiedPackage) -> Result<(), ToolError> {
    let metadata = fs::symlink_metadata(&package.path).map_err(|source| ToolError::Io {
        path: package.path.clone(),
        source,
    })?;
    if !metadata.file_type().is_file()
        || metadata.len() != package.size
        || sha256_file(&package.path)? != package.sha256
    {
        return Err(ToolError::Invalid(
            "plugin package changed while the catalog was being created".into(),
        ));
    }
    Ok(())
}

#[derive(Default)]
struct CopyReport {
    legacy_license_excluded: bool,
    files: usize,
    bytes: u64,
    portable_paths: HashSet<String>,
}

fn copy_legacy_plugin(source: &Path, destination: &Path) -> Result<CopyReport, ToolError> {
    let mut report = CopyReport::default();
    copy_directory(source, source, destination, &mut report)?;
    Ok(report)
}

fn copy_directory(
    root: &Path,
    directory: &Path,
    destination: &Path,
    report: &mut CopyReport,
) -> Result<(), ToolError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|source| ToolError::Io {
            path: directory.to_path_buf(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| ToolError::Io {
            path: directory.to_path_buf(),
            source,
        })?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let file_type = entry.file_type().map_err(|source| ToolError::Io {
            path: entry.path(),
            source,
        })?;
        if file_type.is_symlink() {
            return Err(ToolError::Invalid(
                "legacy plugin contains a symbolic link".into(),
            ));
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| {
                ToolError::Invalid("legacy plugin entry escaped its source directory".into())
            })?
            .to_path_buf();
        let portable = portable_plugin_path(&relative)?;
        let normalized = portable.to_ascii_lowercase();
        if !report.portable_paths.insert(normalized) {
            return Err(ToolError::Invalid(format!(
                "legacy plugin contains a case-insensitive duplicate path: {portable}"
            )));
        }
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if name == LEGACY_LICENSE_FILENAME {
            report.legacy_license_excluded = true;
            continue;
        }
        if relative.components().count() == 1
            && (name == PLUGIN_METADATA_FILENAME || name == SIGNATURE_FILENAME)
        {
            continue;
        }
        let target = destination.join(&relative);
        if file_type.is_dir() {
            fs::create_dir(&target).map_err(|source| ToolError::Io {
                path: target.clone(),
                source,
            })?;
            copy_directory(root, &entry.path(), destination, report)?;
        } else if file_type.is_file() {
            let length = entry
                .metadata()
                .map_err(|source| ToolError::Io {
                    path: entry.path(),
                    source,
                })?
                .len();
            report.files += 1;
            report.bytes = report.bytes.saturating_add(length);
            if report.files > MAX_PLUGIN_FILES || report.bytes > MAX_PLUGIN_BYTES {
                return Err(ToolError::Invalid(
                    "legacy plugin exceeds the file-count or byte limit".into(),
                ));
            }
            fs::copy(entry.path(), &target).map_err(|source| ToolError::Io {
                path: target,
                source,
            })?;
        } else {
            return Err(ToolError::Invalid(
                "legacy plugin may contain only regular files and directories".into(),
            ));
        }
    }
    Ok(())
}

fn validate_release_manifest(manifest: &PluginManifest) -> Result<(), ToolError> {
    let method_count = manifest
        .services
        .iter()
        .map(|service| service.methods.len())
        .sum::<usize>();
    if method_count > MAX_MATRIX_CASES {
        return Err(ToolError::Invalid(format!(
            "plugin defines {method_count} methods; one release matrix supports at most {MAX_MATRIX_CASES}"
        )));
    }
    for service in &manifest.services {
        if service
            .extensions
            .get("installRun")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Err(ToolError::Invalid(format!(
                "service [{}] still declares legacy installRun",
                service.service_id
            )));
        }
        if service.methods.is_empty() {
            return Err(ToolError::Invalid(format!(
                "service [{}] has no callable methods",
                service.service_id
            )));
        }
        let main_type = service.resolved_main_type().to_ascii_lowercase();
        if matches!(main_type.as_str(), "dll" | "exe" | "bat") {
            let component =
                resolve_component(&manifest.plugin_dir, &service.main_class, &main_type)?;
            if matches!(main_type.as_str(), "dll" | "exe") {
                let inspection = inspect_pe_file(&component)?;
                let actual = inspection.architecture.ok_or_else(|| {
                    ToolError::Invalid(format!(
                        "service [{}] entry is not a supported PE file",
                        service.service_id
                    ))
                })?;
                if actual != service.architecture {
                    return Err(ToolError::Invalid(format!(
                        "service [{}] declares {:?} but its PE entry is {:?}",
                        service.service_id, service.architecture, actual
                    )));
                }
                if main_type == "dll" {
                    for method in &service.methods {
                        if inspection
                            .exports
                            .binary_search_by(|export| export.as_str().cmp(&method.name))
                            .is_err()
                        {
                            return Err(ToolError::Invalid(format!(
                                "DLL service [{}] does not export declared method [{}]",
                                service.service_id, method.name
                            )));
                        }
                    }
                }
            }
        }
        for dependency in &service.deps {
            if dependency != "*" && !manifest.plugin_dir.join(dependency).is_file() {
                return Err(ToolError::Invalid(format!(
                    "service [{}] dependency is missing: {dependency}",
                    service.service_id
                )));
            }
        }
    }
    Ok(())
}

fn compare_api_contracts(
    baseline: &PluginManifest,
    candidate: &PluginManifest,
    baseline_version: String,
    baseline_package_sha256: String,
    candidate_source_sha256: String,
    trust_store_sha256: String,
) -> ApiCompatibilityReport {
    let compatibility = compare_public_api(&baseline.services, &candidate.services);
    ApiCompatibilityReport {
        schema_version: 1,
        plugin_id: baseline.plugin_id.clone(),
        baseline_version,
        baseline_package_sha256,
        candidate_source_sha256,
        trust_store_sha256,
        compatible: compatibility.compatible,
        baseline_service_count: baseline.services.len(),
        candidate_service_count: candidate.services.len(),
        baseline_route_count: compatibility.baseline_route_count,
        candidate_route_count: compatibility.candidate_route_count,
        breaking_change_count: compatibility.breaking_changes.len(),
        review_change_count: compatibility.review_changes.len(),
        addition_count: compatibility.additions.len(),
        breaking_changes: compatibility.breaking_changes,
        review_changes: compatibility.review_changes,
        additions: compatibility.additions,
    }
}

fn resolve_component(root: &Path, main_class: &str, extension: &str) -> Result<PathBuf, ToolError> {
    let direct = root.join(main_class);
    let candidate = if direct.is_file()
        || main_class
            .to_ascii_lowercase()
            .ends_with(&format!(".{extension}"))
    {
        direct
    } else {
        root.join(format!("{main_class}.{extension}"))
    };
    if !candidate.is_file() {
        return Err(ToolError::Invalid(format!(
            "native component is missing: {main_class}"
        )));
    }
    let root = root.canonicalize().map_err(|source| ToolError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    let component = candidate.canonicalize().map_err(|source| ToolError::Io {
        path: candidate,
        source,
    })?;
    if !component.starts_with(root) {
        return Err(ToolError::Invalid(
            "native component escaped the plugin directory".into(),
        ));
    }
    Ok(component)
}

struct PeFileInspection {
    architecture: Option<PluginArchitecture>,
    exports: Vec<String>,
}

fn inspect_pe_file(path: &Path) -> Result<PeFileInspection, ToolError> {
    let mut file = File::open(path).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut dos = [0_u8; 64];
    file.read_exact(&mut dos).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if &dos[0..2] != b"MZ" {
        return Ok(PeFileInspection {
            architecture: None,
            exports: Vec::new(),
        });
    }
    let offset = u32::from_le_bytes(dos[0x3c..0x40].try_into().expect("fixed slice")) as u64;
    let length = file
        .metadata()
        .map_err(|source| ToolError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    if offset > length.saturating_sub(24) {
        return Ok(PeFileInspection {
            architecture: None,
            exports: Vec::new(),
        });
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| ToolError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let mut header = [0_u8; 24];
    file.read_exact(&mut header)
        .map_err(|source| ToolError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if &header[0..4] != b"PE\0\0" {
        return Ok(PeFileInspection {
            architecture: None,
            exports: Vec::new(),
        });
    }
    let architecture = match u16::from_le_bytes([header[4], header[5]]) {
        0x014c => Some(PluginArchitecture::X86),
        0x8664 => Some(PluginArchitecture::X64),
        _ => None,
    };
    let section_count = u16::from_le_bytes([header[6], header[7]]) as usize;
    if section_count == 0 || section_count > MAX_PE_SECTIONS {
        return Err(ToolError::Invalid(format!(
            "PE file has an invalid section count; maximum is {MAX_PE_SECTIONS}"
        )));
    }
    let optional_size = u16::from_le_bytes([header[20], header[21]]) as usize;
    if optional_size == 0 || optional_size > MAX_PE_OPTIONAL_HEADER_BYTES {
        return Err(ToolError::Invalid(format!(
            "PE optional header exceeds {MAX_PE_OPTIONAL_HEADER_BYTES} bytes"
        )));
    }
    let mut optional = vec![0_u8; optional_size];
    file.read_exact(&mut optional)
        .map_err(|source| ToolError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let magic = pe_u16(&optional, 0)?;
    let data_directory = match magic {
        0x10b => 96,
        0x20b => 112,
        _ => {
            return Err(ToolError::Invalid(
                "PE optional header type is unsupported".into(),
            ))
        }
    };
    let data_directory_count = pe_u32(&optional, data_directory - 4)?;
    if data_directory_count == 0 {
        return Ok(PeFileInspection {
            architecture,
            exports: Vec::new(),
        });
    }
    let export_rva = pe_u32(&optional, data_directory)?;
    let section_bytes = section_count
        .checked_mul(40)
        .ok_or_else(|| ToolError::Invalid("PE section table byte count overflowed".into()))?;
    let mut raw_sections = vec![0_u8; section_bytes];
    file.read_exact(&mut raw_sections)
        .map_err(|source| ToolError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let sections = (0..section_count)
        .map(|index| {
            let base = index * 40;
            Ok((
                pe_u32(&raw_sections, base + 12)?,
                pe_u32(&raw_sections, base + 8)?,
                pe_u32(&raw_sections, base + 20)?,
                pe_u32(&raw_sections, base + 16)?,
            ))
        })
        .collect::<Result<Vec<_>, ToolError>>()?;
    if export_rva == 0 {
        return Ok(PeFileInspection {
            architecture,
            exports: Vec::new(),
        });
    }
    let export_offset = pe_rva_to_offset(export_rva, &sections, length)?;
    let mut export_directory = [0_u8; 40];
    read_pe_at(&mut file, path, export_offset, &mut export_directory)?;
    let export_count = pe_u32(&export_directory, 24)? as usize;
    if export_count > MAX_PE_EXPORTS {
        return Err(ToolError::Invalid(format!(
            "PE file declares more than {MAX_PE_EXPORTS} named exports"
        )));
    }
    if export_count == 0 {
        return Ok(PeFileInspection {
            architecture,
            exports: Vec::new(),
        });
    }
    let names_rva = pe_u32(&export_directory, 32)?;
    let names_offset = pe_rva_to_offset(names_rva, &sections, length)?;
    let names_bytes = export_count
        .checked_mul(4)
        .ok_or_else(|| ToolError::Invalid("PE export name table byte count overflowed".into()))?;
    let mut name_table = vec![0_u8; names_bytes];
    read_pe_at(&mut file, path, names_offset, &mut name_table)?;
    let mut exports = Vec::with_capacity(export_count);
    for index in 0..export_count {
        let name_rva = pe_u32(&name_table, index * 4)?;
        let name_offset = pe_rva_to_offset(name_rva, &sections, length)?;
        exports.push(read_pe_export_name(&mut file, path, name_offset, length)?);
    }
    exports.sort();
    exports.dedup();
    Ok(PeFileInspection {
        architecture,
        exports,
    })
}

fn pe_u16(bytes: &[u8], offset: usize) -> Result<u16, ToolError> {
    let value = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or_else(|| ToolError::Invalid("PE header is truncated".into()))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn pe_u32(bytes: &[u8], offset: usize) -> Result<u32, ToolError> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| ToolError::Invalid("PE header is truncated".into()))?;
    Ok(u32::from_le_bytes(value.try_into().expect("fixed slice")))
}

fn pe_rva_to_offset(
    rva: u32,
    sections: &[(u32, u32, u32, u32)],
    file_length: u64,
) -> Result<u64, ToolError> {
    for (virtual_address, virtual_size, raw_offset, raw_size) in sections {
        let span = (*virtual_size).max(*raw_size);
        if rva >= *virtual_address && rva < virtual_address.saturating_add(span) {
            let delta = rva - virtual_address;
            if delta >= *raw_size {
                return Err(ToolError::Invalid(
                    "PE data directory is not backed by file bytes".into(),
                ));
            }
            let offset = raw_offset
                .checked_add(delta)
                .map(u64::from)
                .ok_or_else(|| ToolError::Invalid("PE file offset overflowed".into()))?;
            if offset < file_length {
                return Ok(offset);
            }
        }
    }
    Err(ToolError::Invalid(
        "PE data directory is outside the file".into(),
    ))
}

fn read_pe_at(
    file: &mut File,
    path: &Path,
    offset: u64,
    buffer: &mut [u8],
) -> Result<(), ToolError> {
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.read_exact(buffer))
        .map_err(|source| ToolError::Io {
            path: path.to_path_buf(),
            source,
        })
}

fn read_pe_export_name(
    file: &mut File,
    path: &Path,
    offset: u64,
    file_length: u64,
) -> Result<String, ToolError> {
    let available = file_length.saturating_sub(offset);
    let read_length = available.min(MAX_PE_EXPORT_NAME_BYTES as u64) as usize;
    if read_length == 0 {
        return Err(ToolError::Invalid(
            "PE export name is outside the file".into(),
        ));
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| ToolError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let mut bytes = vec![0_u8; read_length];
    file.read_exact(&mut bytes)
        .map_err(|source| ToolError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if let Some(end) = bytes.iter().position(|byte| *byte == 0) {
        if end == 0 {
            return Err(ToolError::Invalid("PE export name is empty".into()));
        }
        bytes.truncate(end);
        return String::from_utf8(bytes)
            .map_err(|_| ToolError::Invalid("PE export name is not valid UTF-8".into()));
    }
    if available < MAX_PE_EXPORT_NAME_BYTES as u64 {
        return Err(ToolError::Invalid(
            "PE export name is not NUL-terminated".into(),
        ));
    }
    Err(ToolError::Invalid(format!(
        "PE export name exceeds {MAX_PE_EXPORT_NAME_BYTES} bytes"
    )))
}

fn draft_matrix(manifest: &PluginManifest) -> Result<PluginMatrix, ToolError> {
    let cases = manifest
        .services
        .iter()
        .flat_map(|service| {
            service.methods.iter().map(move |method| {
                let mut parameters = Map::new();
                for parameter in method
                    .parameters
                    .iter()
                    .filter(|parameter| !parameter.name().starts_with('$'))
                {
                    parameters.insert(
                        parameter.name().trim_start_matches('$').to_owned(),
                        Value::String(DRAFT_INPUT_PLACEHOLDER.into()),
                    );
                }
                PluginMatrixCase {
                    name: format!("{}.{}", service.service_id, method.name),
                    enabled: true,
                    review_required: true,
                    request: InvokeRequest {
                        service_id: service.service_id.clone(),
                        method: method.name.clone(),
                        parameters,
                    },
                    expected: InvokeResponse::success(DRAFT_RESPONSE_PLACEHOLDER),
                }
            })
        })
        .collect::<Vec<_>>();
    Ok(PluginMatrix {
        schema_version: 1,
        draft: true,
        plugins: vec![matrix_target(manifest)?],
        cases,
    })
}

fn matrix_case_has_draft_placeholder(case: &PluginMatrixCase) -> bool {
    case.request
        .parameters
        .values()
        .any(contains_draft_placeholder)
        || contains_draft_placeholder(&case.expected.res_data)
}

fn load_matrix_seed(path: &Path, manifest: &PluginManifest) -> Result<PluginMatrix, ToolError> {
    let mut matrix: PluginMatrix = read_bounded_json(path, MAX_MATRIX_BYTES)?;
    if matrix.schema_version != 1 || !matrix.draft {
        return Err(ToolError::Invalid(
            "matrix seed must use schema 1 and remain draft=true".into(),
        ));
    }
    if matrix.cases.is_empty() || matrix.cases.len() > MAX_MATRIX_CASES {
        return Err(ToolError::Invalid(format!(
            "matrix seed must contain 1 to {MAX_MATRIX_CASES} cases"
        )));
    }
    let required = manifest
        .services
        .iter()
        .flat_map(|service| {
            service
                .methods
                .iter()
                .map(move |method| (service.service_id.clone(), method.name.clone()))
        })
        .collect::<BTreeSet<_>>();
    let mut covered = BTreeSet::new();
    let mut names = BTreeSet::new();
    for case in &matrix.cases {
        if case.name.trim() != case.name
            || case.name.is_empty()
            || case.name.chars().count() > 256
            || case.name.chars().any(char::is_control)
            || !names.insert(case.name.as_str())
        {
            return Err(ToolError::Invalid(
                "matrix seed case names must be unique, trimmed, and at most 256 safe characters"
                    .into(),
            ));
        }
        case.request.validate().map_err(|error| {
            ToolError::Invalid(format!("matrix seed request is invalid: {error}"))
        })?;
        let service = manifest
            .services
            .iter()
            .find(|service| service.service_id == case.request.service_id)
            .ok_or_else(|| {
                ToolError::Invalid(format!(
                    "matrix seed case [{}] targets an unknown service",
                    case.name
                ))
            })?;
        let method = service.method(&case.request.method).ok_or_else(|| {
            ToolError::Invalid(format!(
                "matrix seed case [{}] targets an unknown method",
                case.name
            ))
        })?;
        let allowed_parameters = method
            .parameters
            .iter()
            .map(|parameter| parameter.name())
            .filter(|name| !name.starts_with('$'))
            .collect::<HashSet<_>>();
        if let Some(unexpected) = case
            .request
            .parameters
            .keys()
            .find(|name| !allowed_parameters.contains(name.as_str()))
        {
            return Err(ToolError::Invalid(format!(
                "matrix seed case [{}] contains undeclared input parameter [{unexpected}]",
                case.name
            )));
        }
        if let Some(missing) = allowed_parameters
            .iter()
            .find(|name| !case.request.parameters.contains_key(**name))
        {
            return Err(ToolError::Invalid(format!(
                "matrix seed case [{}] is missing declared input parameter [{missing}]",
                case.name
            )));
        }
        if case.enabled {
            covered.insert((service.service_id.clone(), method.name.clone()));
        }
    }
    if covered != required {
        return Err(ToolError::Invalid(format!(
            "enabled matrix seed cases do not cover {} declared method(s)",
            required.difference(&covered).count()
        )));
    }
    validate_matrix_targets(&matrix.plugins, std::slice::from_ref(manifest))?;
    matrix.plugins = vec![matrix_target(manifest)?];
    Ok(matrix)
}

pub fn check_executable_matrix_root(
    plugin_root: &Path,
    matrix_path: &Path,
) -> Result<MatrixCheckReport, ToolError> {
    let manifests = discover_clean_plugin_root(plugin_root)?;
    let (_, report) = validate_executable_matrix(matrix_path, &manifests)?;
    Ok(report)
}

fn discover_clean_plugin_root(plugin_root: &Path) -> Result<Vec<PluginManifest>, ToolError> {
    let plugin_root = canonical_real_directory(plugin_root)?;
    match fs::symlink_metadata(plugin_root.join(RELEASE_SET_MATERIALIZATION_MARKER)) {
        Ok(_) => {
            return Err(ToolError::Invalid(
                "plugin root contains an incomplete release set materialization marker".into(),
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ToolError::Io {
                path: plugin_root.join(RELEASE_SET_MATERIALIZATION_MARKER),
                source,
            })
        }
    }
    let discovery = discover_plugins(&plugin_root)?;
    if !discovery.failures.is_empty() {
        let first = &discovery.failures[0];
        return Err(ToolError::Invalid(format!(
            "plugin root contains {} invalid plugin director{}; first failure [{}]: {}",
            discovery.failures.len(),
            if discovery.failures.len() == 1 {
                "y"
            } else {
                "ies"
            },
            first.plugin_id,
            first.error
        )));
    }
    Ok(discovery.manifests)
}

pub fn check_executable_matrix_plugin(
    plugin_dir: &Path,
    matrix_path: &Path,
) -> Result<MatrixCheckReport, ToolError> {
    let plugin_dir = canonical_real_directory(plugin_dir)?;
    let metadata = PluginMetadata::load_optional(&plugin_dir)?.ok_or_else(|| {
        ToolError::Invalid("plugin directory must contain normalized plugin.json".into())
    })?;
    let manifest = PluginManifest::load(metadata.plugin_id, &plugin_dir)?;
    let (_, report) = validate_executable_matrix(matrix_path, &[manifest])?;
    Ok(report)
}

fn matrix_target(manifest: &PluginManifest) -> Result<PluginMatrixTarget, ToolError> {
    let metadata = manifest.metadata.as_ref().ok_or_else(|| {
        ToolError::Invalid("matrix identity binding requires normalized plugin.json".into())
    })?;
    Ok(PluginMatrixTarget {
        plugin_id: metadata.plugin_id.clone(),
        version: metadata.version.to_string(),
    })
}

fn validate_matrix_targets(
    targets: &[PluginMatrixTarget],
    manifests: &[PluginManifest],
) -> Result<bool, ToolError> {
    if targets.is_empty() {
        return Ok(false);
    }
    if targets.len() > MAX_MATRIX_PLUGINS {
        return Err(ToolError::Invalid(format!(
            "matrix identity binding contains more than {MAX_MATRIX_PLUGINS} plugins"
        )));
    }

    let mut expected = BTreeMap::new();
    for manifest in manifests {
        let target = matrix_target(manifest)?;
        expected.insert(
            target.plugin_id.to_ascii_lowercase(),
            (target.plugin_id, target.version),
        );
    }
    let mut actual = BTreeMap::new();
    for target in targets {
        let path = Path::new(&target.plugin_id);
        let version = Version::parse(&target.version).map_err(|error| {
            ToolError::Invalid(format!(
                "matrix plugin target version is not SemVer: {error}"
            ))
        })?;
        if target.plugin_id.trim() != target.plugin_id
            || path.components().count() != 1
            || portable_plugin_path(path)? != target.plugin_id
            || version.to_string() != target.version
        {
            return Err(ToolError::Invalid(
                "matrix plugin targets must use canonical portable IDs and SemVer versions".into(),
            ));
        }
        if actual
            .insert(
                target.plugin_id.to_ascii_lowercase(),
                (target.plugin_id.clone(), target.version.clone()),
            )
            .is_some()
        {
            return Err(ToolError::Invalid(
                "matrix identity binding contains a duplicate portable plugin ID".into(),
            ));
        }
    }
    if actual != expected {
        return Err(ToolError::Invalid(
            "matrix plugin identities or versions do not exactly match the checked plugins".into(),
        ));
    }
    Ok(true)
}

pub fn validate_executable_matrix(
    matrix_path: &Path,
    manifests: &[PluginManifest],
) -> Result<(PluginMatrix, MatrixCheckReport), ToolError> {
    let matrix: PluginMatrix = read_bounded_json(matrix_path, MAX_MATRIX_BYTES)?;
    if matrix.schema_version != 1
        || matrix.cases.is_empty()
        || matrix.cases.len() > MAX_MATRIX_CASES
    {
        return Err(ToolError::Invalid(format!(
            "executable matrix must use schema 1 and contain 1 to {MAX_MATRIX_CASES} cases"
        )));
    }
    if matrix.draft {
        return Err(ToolError::Invalid(
            "executable matrix is still marked as draft".into(),
        ));
    }
    let mut services = BTreeMap::new();
    let mut required = BTreeSet::new();
    let mut plugin_ids = BTreeSet::new();
    for manifest in manifests {
        if !plugin_ids.insert(manifest.plugin_id.to_ascii_lowercase()) {
            return Err(ToolError::Invalid(format!(
                "verified plugin manifests contain duplicate portable plugin ID [{}]",
                manifest.plugin_id
            )));
        }
        for service in &manifest.services {
            if services
                .insert(service.service_id.as_str(), service)
                .is_some()
            {
                return Err(ToolError::Invalid(format!(
                    "verified plugin manifests declare duplicate serviceId [{}]",
                    service.service_id
                )));
            }
            for method in &service.methods {
                required.insert((service.service_id.as_str(), method.name.as_str()));
            }
        }
    }
    if required.is_empty() {
        return Err(ToolError::Invalid(
            "verified plugin manifests do not declare callable methods".into(),
        ));
    }
    let identity_bound = validate_matrix_targets(&matrix.plugins, manifests)?;

    let mut names = BTreeSet::new();
    let mut covered = BTreeSet::new();
    let mut enabled_case_count = 0_usize;
    for case in &matrix.cases {
        if case.name.trim() != case.name
            || case.name.is_empty()
            || case.name.chars().count() > 256
            || case.name.chars().any(char::is_control)
            || !names.insert(case.name.as_str())
        {
            return Err(ToolError::Invalid(
                "matrix case names must be unique, trimmed, and at most 256 safe characters".into(),
            ));
        }
        case.request.validate().map_err(|error| {
            ToolError::Invalid(format!(
                "matrix case [{}] contains an invalid invoke request: {error}",
                case.name
            ))
        })?;
        let service = services
            .get(case.request.service_id.as_str())
            .copied()
            .ok_or_else(|| {
                ToolError::Invalid(format!(
                    "matrix case [{}] targets an unknown service",
                    case.name
                ))
            })?;
        let method = service.method(&case.request.method).ok_or_else(|| {
            ToolError::Invalid(format!(
                "matrix case [{}] targets an unknown method",
                case.name
            ))
        })?;
        let declared_inputs = method
            .parameters
            .iter()
            .map(|parameter| parameter.name())
            .filter(|name| !name.starts_with('$'))
            .collect::<BTreeSet<_>>();
        let provided_inputs = case
            .request
            .parameters
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if provided_inputs != declared_inputs {
            return Err(ToolError::Invalid(format!(
                "matrix case [{}] inputs do not exactly match the declared method inputs",
                case.name
            )));
        }
        if !case.enabled {
            continue;
        }
        enabled_case_count = enabled_case_count.saturating_add(1);
        if case.review_required {
            return Err(ToolError::Invalid(format!(
                "matrix case [{}] still requires exact response review",
                case.name
            )));
        }
        if matrix_case_has_draft_placeholder(case) {
            return Err(ToolError::Invalid(format!(
                "matrix case [{}] still contains a generated draft placeholder",
                case.name
            )));
        }
        covered.insert((service.service_id.as_str(), method.name.as_str()));
    }
    if enabled_case_count == 0 {
        return Err(ToolError::Invalid(
            "executable matrix must contain at least one enabled case".into(),
        ));
    }
    if covered != required {
        return Err(ToolError::Invalid(format!(
            "enabled matrix cases do not cover {} declared method(s)",
            required.difference(&covered).count()
        )));
    }

    let report = MatrixCheckReport {
        schema_version: 1,
        plugin_count: manifests.len(),
        service_count: services.len(),
        method_count: required.len(),
        case_count: matrix.cases.len(),
        enabled_case_count,
        identity_bound,
    };
    Ok((matrix, report))
}

fn write_external_outputs(
    request_path: &Path,
    request: &SigningRequest,
    matrix_path: &Path,
    matrix: &PluginMatrix,
) -> Result<(), ToolError> {
    write_new_json(request_path, request)?;
    if let Err(error) = write_new_json(matrix_path, matrix) {
        let _ = fs::remove_file(request_path);
        return Err(error);
    }
    Ok(())
}

fn write_new_json(path: impl AsRef<Path>, value: &impl Serialize) -> Result<(), ToolError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_new_bytes(path.as_ref(), &bytes)
}

fn write_new_bytes(path: &Path, bytes: &[u8]) -> Result<(), ToolError> {
    let parent = output_parent(path);
    let mut temporary = TempBuilder::new()
        .prefix(".ssdev-write-")
        .tempfile_in(parent)
        .map_err(|source| ToolError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    temporary
        .write_all(bytes)
        .and_then(|_| temporary.flush())
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|source| ToolError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| ToolError::Io {
            path: path.to_path_buf(),
            source: error.error,
        })?;
    Ok(())
}

fn read_bounded_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    limit: u64,
) -> Result<T, ToolError> {
    let bytes = read_bounded_file(path, limit)?;
    serde_json::from_slice(&bytes).map_err(ToolError::from)
}

fn read_signature(path: &Path) -> Result<String, ToolError> {
    let bytes = read_bounded_file(path, MAX_SIGNATURE_BYTES)?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| ToolError::Invalid("signature file must contain UTF-8 base64".into()))?
        .trim();
    if value.is_empty() || value.lines().count() != 1 {
        return Err(ToolError::Invalid(
            "signature file must contain exactly one base64 value".into(),
        ));
    }
    Ok(value.to_owned())
}

fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>, ToolError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() || metadata.len() > limit {
        return Err(ToolError::Invalid(format!(
            "input must be a regular file no larger than {limit} bytes"
        )));
    }
    fs::read(path).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn canonical_real_directory(path: &Path) -> Result<PathBuf, ToolError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_dir() {
        return Err(ToolError::Invalid("input must be a real directory".into()));
    }
    path.canonicalize().map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn canonical_real_file(path: &Path, limit: u64) -> Result<PathBuf, ToolError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() || metadata.len() > limit {
        return Err(ToolError::Invalid(format!(
            "input must be a real file no larger than {limit} bytes"
        )));
    }
    path.canonicalize().map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn normalized_new_path(path: &Path) -> Result<PathBuf, ToolError> {
    let parent = output_parent(path);
    let metadata = fs::symlink_metadata(parent).map_err(|source| ToolError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_dir() {
        return Err(ToolError::Invalid(
            "output parent must be an existing real directory".into(),
        ));
    }
    let parent = parent.canonicalize().map_err(|source| ToolError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    let name = path.file_name().ok_or_else(|| {
        ToolError::Invalid("output path must have a file or directory name".into())
    })?;
    Ok(parent.join(name))
}

fn ensure_fresh_output(path: &Path, role: &str) -> Result<(), ToolError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(ToolError::Invalid(format!("{role} already exists"))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ToolError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn with_fresh_directory<T>(
    path: &Path,
    role: &str,
    operation: impl FnOnce(&Path) -> Result<T, ToolError>,
) -> Result<T, ToolError> {
    ensure_fresh_output(path, role)?;
    fs::create_dir(path).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let result = operation(path);
    if result.is_err() {
        if let Err(source) = fs::remove_dir_all(path) {
            return Err(ToolError::Invalid(format!(
                "{role} operation failed and its incomplete directory could not be removed: {source}"
            )));
        }
    }
    result
}

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest_hex(Sha256::digest(bytes))
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_file(path: &Path) -> Result<String, ToolError> {
    sha256_file_bounded(path, MAX_PLUGIN_BYTES)
}

fn sha256_file_bounded(path: &Path, limit: u64) -> Result<String, ToolError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() || metadata.len() > limit {
        return Err(ToolError::Invalid(format!(
            "digest input must be a regular file no larger than {limit} bytes"
        )));
    }
    let mut file = File::open(path).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer).map_err(|source| ToolError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if total > limit {
            return Err(ToolError::Invalid(format!(
                "digest input exceeds {limit} bytes while being read"
            )));
        }
        hasher.update(&buffer[..count]);
    }
    Ok(digest_hex(hasher.finalize()))
}

fn digest_hex(digest: impl AsRef<[u8]>) -> String {
    let digest = digest.as_ref();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("invalid plugin release input: {0}")]
    Invalid(String),
    #[error(
        "plugin API compatibility check found {breaking_change_count} breaking change(s); report written to {report:?}"
    )]
    ApiIncompatible {
        breaking_change_count: usize,
        report: PathBuf,
    },
    #[error("filesystem operation failed at {path:?}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("JSON encoding or decoding failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("plugin manifest is invalid: {0}")]
    Manifest(#[from] webplus_plugin_config::ConfigError),
    #[error("plugin signature is invalid: {0}")]
    Trust(#[from] webplus_plugin_trust::TrustError),
    #[error("plugin package is invalid: {0}")]
    Package(#[from] webplus_plugin_package::PackageError),
    #[error("plugin catalog is invalid: {0}")]
    Catalog(#[from] webplus_plugin_repository::RepositoryError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use std::time::{Duration, UNIX_EPOCH};

    fn pe(machine: u16, exports: &[&str]) -> Vec<u8> {
        let mut bytes = vec![0_u8; 1536];
        bytes[0..2].copy_from_slice(b"MZ");
        let pe_offset = 0x80_usize;
        bytes[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
        bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
        let coff = pe_offset + 4;
        bytes[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes());
        let (optional_size, magic, data_directory) = if machine == 0x8664 {
            (240_u16, 0x20b_u16, 112_usize)
        } else {
            (224_u16, 0x10b_u16, 96_usize)
        };
        bytes[coff + 16..coff + 18].copy_from_slice(&optional_size.to_le_bytes());
        let optional = coff + 20;
        bytes[optional..optional + 2].copy_from_slice(&magic.to_le_bytes());
        bytes[optional + data_directory - 4..optional + data_directory]
            .copy_from_slice(&1_u32.to_le_bytes());
        bytes[optional + data_directory..optional + data_directory + 4]
            .copy_from_slice(&0x1000_u32.to_le_bytes());
        let section = optional + optional_size as usize;
        bytes[section + 8..section + 12].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x400_u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x200_u32.to_le_bytes());
        let export_directory = 0x200_usize;
        bytes[export_directory + 24..export_directory + 28]
            .copy_from_slice(&(exports.len() as u32).to_le_bytes());
        bytes[export_directory + 32..export_directory + 36]
            .copy_from_slice(&0x1040_u32.to_le_bytes());
        let names = 0x240_usize;
        let mut string_offset = 0x280_usize;
        for (index, export) in exports.iter().enumerate() {
            let rva = 0x1000_u32 + (string_offset as u32 - 0x200);
            bytes[names + index * 4..names + index * 4 + 4].copy_from_slice(&rva.to_le_bytes());
            let end = string_offset + export.len();
            bytes[string_offset..end].copy_from_slice(export.as_bytes());
            bytes[end] = 0;
            string_offset = end + 1;
        }
        bytes
    }

    fn source(root: &Path) -> PathBuf {
        let source = root.join("legacy");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("api.json"),
            r#"{"serviceId":"reader","mainClass":"reader.dll","architecture":"x86","methods":[{"name":"read","parameters":["timeout"]}]}"#,
        )
        .unwrap();
        fs::write(source.join("reader.dll"), pe(0x014c, &["read"])).unwrap();
        fs::write(source.join("license.dat"), b"legacy private-key envelope").unwrap();
        source
    }

    fn trust_store(root: &Path, signing_key: &SigningKey, status: Option<&str>) -> PathBuf {
        let path = root.join("trust.json");
        let mut key = json!({
            "keyId": "test-key",
            "algorithm": "ed25519",
            "publicKey": BASE64.encode(signing_key.verifying_key().to_bytes()),
            "purposes": ["plugin"]
        });
        if let Some(status) = status {
            key["status"] = Value::String(status.to_owned());
        }
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "schemaVersion": 2,
                "keys": [key]
            }))
            .unwrap(),
        )
        .unwrap();
        path
    }

    fn signed_package(
        root: &Path,
        source: &Path,
        prefix: &str,
        plugin_id: &str,
        version: &str,
        trust_store: &Path,
        signing_key: &SigningKey,
    ) -> PathBuf {
        let staging = root.join(format!("{prefix}-stage"));
        let request = root.join(format!("{prefix}-request.json"));
        let matrix = root.join(format!("{prefix}-draft-matrix.json"));
        prepare(&PrepareOptions {
            source,
            staging: &staging,
            request: &request,
            matrix_template: &matrix,
            plugin_id,
            version,
            desktop_version_requirement: ">=0.1.0, <0.2.0",
            display_name: plugin_id,
            key_id: "test-key",
            trust_store,
            matrix_seed: None,
        })
        .unwrap();
        let signing_request: SigningRequest =
            serde_json::from_slice(&fs::read(&request).unwrap()).unwrap();
        let payload = BASE64.decode(signing_request.payload_base64).unwrap();
        let signature = root.join(format!("{prefix}-signature.txt"));
        fs::write(
            &signature,
            BASE64.encode(signing_key.sign(&payload).to_bytes()),
        )
        .unwrap();
        let package = root.join(format!("{prefix}.ssdev-plugin"));
        finalize(&FinalizeOptions {
            staging: &staging,
            request: &request,
            signature: &signature,
            trust_store,
            package: &package,
        })
        .unwrap();
        package
    }

    fn matrix_file(root: &Path, name: &str, value: Value) -> PathBuf {
        let path = root.join(name);
        fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        path
    }

    fn executable_matrix(case: Value) -> Value {
        json!({
            "schemaVersion": 1,
            "draft": false,
            "cases": [case]
        })
    }

    fn bound_executable_matrix(case: Value, plugin_id: &str, version: &str) -> Value {
        json!({
            "schemaVersion": 1,
            "draft": false,
            "plugins": [{
                "pluginId": plugin_id,
                "version": version
            }],
            "cases": [case]
        })
    }

    fn executable_case() -> Value {
        json!({
            "name": "reader.read verified",
            "reviewRequired": false,
            "request": {
                "serviceId": "reader",
                "method": "read",
                "parameters": { "timeout": 5 }
            },
            "expected": {
                "ResCode": 0,
                "ResData": { "ReturnValue": 0 }
            }
        })
    }

    #[test]
    fn generates_a_typed_client_without_mutating_the_signed_source() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let output = root.path().join("reader-client.ts");

        let report = generate_client(&GenerateClientOptions {
            source: &source,
            plugin_id: "reader",
            display_name: Some("Patient Reader"),
            output: &output,
        })
        .unwrap();
        let generated = fs::read_to_string(&output).unwrap();
        assert_eq!(report.plugin_id, "reader");
        assert_eq!(report.display_name, "Patient Reader");
        assert_eq!(report.service_count, 1);
        assert_eq!(report.method_count, 1);
        assert_eq!(report.output_sha256, sha256_hex(generated.as_bytes()));
        assert!(generated.contains("export class PatientReaderClient"));
        assert!(generated.contains("invokePlugin<ReadData>(\"reader\", \"read\""));
        assert!(generated.contains("\"timeout\": JsonValue"));
        assert!(generate_client(&GenerateClientOptions {
            source: &source,
            plugin_id: "reader",
            display_name: None,
            output: &output,
        })
        .unwrap_err()
        .to_string()
        .contains("already exists"));
    }

    #[test]
    fn initializes_a_bounded_buildable_dll_plugin_workspace() {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("card-reader");
        let report = init_dll_plugin(&InitDllPluginOptions {
            destination: &destination,
            plugin_id: "hospital.card-reader",
            service_id: "device.card",
            display_name: "Card Reader",
            architecture: "x64",
        })
        .unwrap();

        assert_eq!(report.architecture, PluginArchitecture::X64);
        assert_eq!(report.file_count, 8);
        assert!(report
            .rust_crate_name
            .starts_with("ssdev_hospital_card_reader_"));
        assert!(report.native_library.ends_with("_native.dll"));
        let manifest =
            PluginManifest::load("hospital.card-reader", destination.join("release-source"))
                .unwrap();
        let service = manifest.service("device.card").unwrap();
        assert_eq!(service.architecture, PluginArchitecture::X64);
        assert_eq!(service.main_class, format!("bin/{}", report.native_library));
        assert_eq!(service.method("echo").unwrap().name, "SsdevEcho");
        let client = fs::read_to_string(destination.join("web/client.ts")).unwrap();
        assert!(client.contains("export class CardReaderClient"));
        assert!(client.contains("invokePlugin<EchoData>(\"device.card\", \"echo\""));
        let build = fs::read_to_string(destination.join("build.ps1")).unwrap();
        assert!(build.contains("x86_64-pc-windows-msvc"));
        assert!(build.contains("cargo build --locked --release"));
        let readme = fs::read_to_string(destination.join("README.md")).unwrap();
        assert!(readme.contains("ssdev-plugin-tool web-kit"));
        let matrix: PluginMatrix =
            serde_json::from_slice(&fs::read(destination.join("matrix-seed.json")).unwrap())
                .unwrap();
        assert!(matrix.draft);
        assert!(matrix.cases[0].review_required);
        assert_eq!(
            matrix.cases[0].request.parameters["input"],
            Value::String("SSDEV_TEST".into())
        );
        assert!(init_dll_plugin(&InitDllPluginOptions {
            destination: &destination,
            plugin_id: "hospital.card-reader",
            service_id: "device.card",
            display_name: "Card Reader",
            architecture: "x64",
        })
        .unwrap_err()
        .to_string()
        .contains("already exists"));
    }

    #[test]
    fn invalid_dll_scaffold_input_leaves_no_partial_workspace() {
        let root = tempfile::tempdir().unwrap();
        let invalid_architecture = root.path().join("invalid-architecture");
        assert!(init_dll_plugin(&InitDllPluginOptions {
            destination: &invalid_architecture,
            plugin_id: "reader",
            service_id: "reader",
            display_name: "Reader",
            architecture: "arm64",
        })
        .unwrap_err()
        .to_string()
        .contains("x86 or x64"));
        assert!(!invalid_architecture.exists());

        let invalid_plugin = root.path().join("invalid-plugin");
        assert!(init_dll_plugin(&InitDllPluginOptions {
            destination: &invalid_plugin,
            plugin_id: "../reader",
            service_id: "reader",
            display_name: "Reader",
            architecture: "x86",
        })
        .is_err());
        assert!(!invalid_plugin.exists());
    }

    #[test]
    fn source_check_is_read_only_and_reports_the_prepare_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let report = check_source(&SourceCheckOptions {
            source: &source,
            plugin_id: "reader-plugin",
        })
        .unwrap();
        assert_eq!(report.plugin_id, "reader-plugin");
        assert_eq!(report.service_count, 1);
        assert_eq!(report.method_count, 1);
        assert_eq!(report.x86_service_count, 1);
        assert_eq!(report.x64_service_count, 0);
        assert_eq!(report.dll_service_count, 1);
        assert_eq!(report.com_service_count, 0);
        assert_eq!(report.process_service_count, 0);
        assert_eq!(report.source_file_count, 2);
        assert!(report.source_bytes > 0);
        assert!(report.legacy_license_excluded);
        assert!(source.join("license.dat").is_file());
        assert!(!source.join("plugin.json").exists());
    }

    #[test]
    fn source_check_and_prepare_reject_missing_dll_exports_before_signing() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        fs::write(
            source.join("api.json"),
            r#"{"serviceId":"reader","mainClass":"reader.dll","architecture":"x86","methods":[{"name":"MissingExport","parameters":["timeout"]}]}"#,
        )
        .unwrap();
        let error = check_source(&SourceCheckOptions {
            source: &source,
            plugin_id: "reader-plugin",
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("does not export declared method"));

        let signing_key = SigningKey::from_bytes(&[41; 32]);
        let trust = trust_store(root.path(), &signing_key, None);
        let staging = root.path().join("stage");
        let request = root.path().join("request.json");
        let matrix = root.path().join("matrix.json");
        let error = prepare(&PrepareOptions {
            source: &source,
            staging: &staging,
            request: &request,
            matrix_template: &matrix,
            plugin_id: "reader-plugin",
            version: "1.0.0",
            desktop_version_requirement: ">=0.1.0, <0.2.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust,
            matrix_seed: None,
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("does not export declared method"));
        assert!(!staging.exists());
        assert!(!request.exists());
        assert!(!matrix.exists());
    }

    #[test]
    fn api_check_accepts_additions_and_reports_native_review_changes() {
        let root = tempfile::tempdir().unwrap();
        let baseline_source = source(root.path());
        let signing_key = SigningKey::from_bytes(&[42; 32]);
        let trust = trust_store(root.path(), &signing_key, None);
        let baseline_package = signed_package(
            root.path(),
            &baseline_source,
            "baseline-api",
            "reader-plugin",
            "1.0.0",
            &trust,
            &signing_key,
        );
        let candidate = root.path().join("candidate-api");
        fs::create_dir(&candidate).unwrap();
        fs::write(
            candidate.join("api.json"),
            r#"{"serviceId":"reader","mainClass":"reader.dll","architecture":"x86","timeout":2000,"methods":[{"name":"read","alias":"readCard","parameters":[{"name":"timeout","type":"inferred"},{"name":"$status","type":"int32"}]}]}"#,
        )
        .unwrap();
        fs::write(candidate.join("reader.dll"), pe(0x014c, &["read"])).unwrap();
        let report_path = root.path().join("compatible-api-report.json");

        let report = check_api_compatibility(&ApiCheckOptions {
            baseline_package: &baseline_package,
            candidate_source: &candidate,
            plugin_id: "reader-plugin",
            trust_store: &trust,
            report: &report_path,
        })
        .unwrap();
        assert!(report.compatible);
        assert_eq!(report.baseline_version, "1.0.0");
        assert_eq!(report.baseline_package_sha256.len(), 64);
        assert_eq!(report.candidate_source_sha256.len(), 64);
        assert_eq!(report.trust_store_sha256.len(), 64);
        assert_eq!(report.baseline_route_count, 1);
        assert_eq!(report.candidate_route_count, 2);
        assert!(report
            .additions
            .iter()
            .any(|change| change.code == "route-added"
                && change.route.as_deref() == Some("readCard")));
        assert!(report.additions.iter().any(|change| {
            change.code == "response-field-added" && change.field.as_deref() == Some("status")
        }));
        assert!(report
            .review_changes
            .iter()
            .any(|change| change.code == "service-timeout-changed"));
        assert!(report
            .review_changes
            .iter()
            .any(|change| change.code == "native-parameter-layout-changed"));
        let persisted: ApiCompatibilityReport =
            serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
        assert_eq!(persisted, report);
        assert!(!candidate.join("plugin.json").exists());
    }

    #[test]
    fn api_check_rejects_breaking_input_and_response_changes_but_persists_report() {
        let root = tempfile::tempdir().unwrap();
        let baseline_source = source(root.path());
        let signing_key = SigningKey::from_bytes(&[43; 32]);
        let trust = trust_store(root.path(), &signing_key, None);
        let baseline_package = signed_package(
            root.path(),
            &baseline_source,
            "breaking-baseline-api",
            "reader-plugin",
            "1.0.0",
            &trust,
            &signing_key,
        );
        let candidate = root.path().join("breaking-candidate-api");
        fs::create_dir(&candidate).unwrap();
        fs::write(
            candidate.join("api.json"),
            r#"{"serviceId":"reader","mainClass":"reader.dll","architecture":"x86","methods":[{"name":"read","returnType":"string","parameters":[{"name":"timeout","type":"int32"},{"name":"mode","type":"string"}]}]}"#,
        )
        .unwrap();
        fs::write(candidate.join("reader.dll"), pe(0x014c, &["read"])).unwrap();
        let report_path = root.path().join("breaking-api-report.json");

        let error = check_api_compatibility(&ApiCheckOptions {
            baseline_package: &baseline_package,
            candidate_source: &candidate,
            plugin_id: "reader-plugin",
            trust_store: &trust,
            report: &report_path,
        })
        .unwrap_err();
        assert!(matches!(
            error,
            ToolError::ApiIncompatible {
                breaking_change_count: 3,
                ..
            }
        ));
        let persisted: ApiCompatibilityReport =
            serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
        assert!(!persisted.compatible);
        assert_eq!(persisted.breaking_change_count, 3);
        assert!(persisted
            .breaking_changes
            .iter()
            .any(|change| change.code == "input-type-changed"));
        assert!(persisted
            .breaking_changes
            .iter()
            .any(|change| change.code == "required-input-added"));
        assert!(persisted
            .breaking_changes
            .iter()
            .any(|change| change.code == "response-type-changed"));
        assert!(check_api_compatibility(&ApiCheckOptions {
            baseline_package: &baseline_package,
            candidate_source: &candidate,
            plugin_id: "reader-plugin",
            trust_store: &trust,
            report: &report_path,
        })
        .unwrap_err()
        .to_string()
        .contains("already exists"));
    }

    #[test]
    fn api_contract_treats_native_names_and_aliases_as_public_routes() {
        let root = tempfile::tempdir().unwrap();
        let baseline_source = source(root.path());
        fs::write(
            baseline_source.join("api.json"),
            r#"{"serviceId":"reader","mainClass":"reader.dll","architecture":"x86","methods":[{"name":"read","alias":"readCard","parameters":["timeout"]}]}"#,
        )
        .unwrap();
        let baseline = PluginManifest::load("reader-plugin", &baseline_source).unwrap();
        let candidate_source = root.path().join("alias-candidate");
        fs::create_dir(&candidate_source).unwrap();
        fs::write(
            candidate_source.join("api.json"),
            r#"{"serviceId":"reader","mainClass":"reader.dll","architecture":"x86","methods":[{"name":"read","parameters":["timeout"]}]}"#,
        )
        .unwrap();
        fs::write(candidate_source.join("reader.dll"), pe(0x014c, &["read"])).unwrap();
        let candidate = PluginManifest::load("reader-plugin", &candidate_source).unwrap();

        let report = compare_api_contracts(
            &baseline,
            &candidate,
            "1.0.0".into(),
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
        );
        assert!(!report.compatible);
        assert_eq!(report.baseline_route_count, 2);
        assert_eq!(report.candidate_route_count, 1);
        assert!(report.breaking_changes.iter().any(|change| {
            change.code == "route-removed" && change.route.as_deref() == Some("readCard")
        }));
    }

    #[test]
    fn typed_client_cannot_be_written_into_the_signed_source() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let error = generate_client(&GenerateClientOptions {
            source: &source,
            plugin_id: "reader",
            display_name: None,
            output: &source.join("generated-client.ts"),
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("outside the signed plugin source"));
        assert!(!source.join("generated-client.ts").exists());
    }

    #[test]
    fn executable_matrix_check_is_cross_platform_and_reports_exact_coverage() {
        let root = tempfile::tempdir().unwrap();
        let plugin_dir = source(root.path());
        let matrix = matrix_file(
            root.path(),
            "executable-matrix.json",
            executable_matrix(executable_case()),
        );
        let manifest = PluginManifest::load("reader", plugin_dir).unwrap();

        let (parsed, report) = validate_executable_matrix(&matrix, &[manifest]).unwrap();

        assert_eq!(parsed.cases.len(), 1);
        assert_eq!(report.plugin_count, 1);
        assert_eq!(report.service_count, 1);
        assert_eq!(report.method_count, 1);
        assert_eq!(report.case_count, 1);
        assert_eq!(report.enabled_case_count, 1);
        assert!(!report.identity_bound);
        assert_eq!(
            check_executable_matrix_root(root.path(), &matrix).unwrap(),
            report
        );

        let staging = root.path().join("arbitrary-release-staging-name");
        fs::create_dir(&staging).unwrap();
        fs::copy(
            root.path().join("legacy/api.json"),
            staging.join("api.json"),
        )
        .unwrap();
        fs::copy(
            root.path().join("legacy/reader.dll"),
            staging.join("reader.dll"),
        )
        .unwrap();
        fs::write(
            staging.join("plugin.json"),
            serde_json::to_vec(&json!({
                "schemaVersion": 1,
                "pluginId": "reader",
                "version": "1.0.0",
                "displayName": "Reader"
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            check_executable_matrix_plugin(&staging, &matrix).unwrap(),
            report
        );
    }

    #[test]
    fn web_fixtures_use_public_aliases_and_only_enabled_bound_cases() {
        let root = tempfile::tempdir().unwrap();
        let plugin_dir = root.path().join("reader-plugin");
        fs::create_dir(&plugin_dir).unwrap();
        fs::write(
            plugin_dir.join("api.json"),
            r#"{"serviceId":"reader","mainClass":"reader.dll","architecture":"x86","methods":[{"name":"read","alias":"readCard","parameters":["timeout"]}]}"#,
        )
        .unwrap();
        fs::write(plugin_dir.join("reader.dll"), pe(0x014c, &["read"])).unwrap();
        fs::write(
            plugin_dir.join("plugin.json"),
            serde_json::to_vec(&json!({
                "schemaVersion": 1,
                "pluginId": "reader-plugin",
                "version": "1.0.0",
                "displayName": "Reader"
            }))
            .unwrap(),
        )
        .unwrap();
        let matrix = matrix_file(
            root.path(),
            "web-fixture-matrix.json",
            json!({
                "schemaVersion": 1,
                "draft": false,
                "plugins": [{
                    "pluginId": "reader-plugin",
                    "version": "1.0.0"
                }],
                "cases": [{
                    "name": "reviewed-success",
                    "request": {
                        "serviceId": "reader",
                        "method": "read",
                        "parameters": { "timeout": 5 }
                    },
                    "expected": {
                        "ResCode": 0,
                        "ResData": { "ReturnValue": 0, "cardNumber": "TEST-001" }
                    }
                }, {
                    "name": "disabled-draft-scenario",
                    "enabled": false,
                    "reviewRequired": true,
                    "request": {
                        "serviceId": "reader",
                        "method": "readCard",
                        "parameters": { "timeout": 9 }
                    },
                    "expected": {
                        "ResCode": 0,
                        "ResData": DRAFT_RESPONSE_PLACEHOLDER
                    }
                }]
            }),
        );
        let output = root.path().join("reader-fixtures.ts");

        let report = generate_web_fixtures(&GenerateWebFixturesOptions {
            plugin_root: None,
            plugin_dir: Some(&plugin_dir),
            matrix: &matrix,
            output: &output,
        })
        .unwrap();
        let generated = fs::read_to_string(&output).unwrap();
        assert_eq!(report.plugin_count, 1);
        assert_eq!(report.service_count, 1);
        assert_eq!(report.method_count, 1);
        assert_eq!(report.fixture_count, 1);
        assert_eq!(report.matrix_sha256, sha256_file(&matrix).unwrap());
        assert_eq!(report.output_sha256, sha256_hex(generated.as_bytes()));
        assert!(generated.contains(&format!("Matrix SHA-256: {}", report.matrix_sha256)));
        assert!(generated.contains("import type { PluginInvocationFixture }"));
        assert!(generated.contains("\"method\": \"readCard\""));
        assert!(!generated.contains("\"method\": \"read\""));
        assert!(!generated.contains(DRAFT_RESPONSE_PLACEHOLDER));
        assert!(!generated.contains("reviewed-success"));
        assert!(generate_web_fixtures(&GenerateWebFixturesOptions {
            plugin_root: None,
            plugin_dir: Some(&plugin_dir),
            matrix: &matrix,
            output: &output,
        })
        .unwrap_err()
        .to_string()
        .contains("already exists"));

        let unbound_matrix = matrix_file(
            root.path(),
            "unbound-web-fixture-matrix.json",
            executable_matrix(executable_case()),
        );
        let unbound_output = root.path().join("unbound-fixtures.ts");
        assert!(generate_web_fixtures(&GenerateWebFixturesOptions {
            plugin_root: None,
            plugin_dir: Some(&plugin_dir),
            matrix: &unbound_matrix,
            output: &unbound_output,
        })
        .unwrap_err()
        .to_string()
        .contains("bind the exact plugin"));
        assert!(!unbound_output.exists());

        let unsafe_number_matrix = matrix_file(
            root.path(),
            "unsafe-number-web-fixture-matrix.json",
            json!({
                "schemaVersion": 1,
                "draft": false,
                "plugins": [{
                    "pluginId": "reader-plugin",
                    "version": "1.0.0"
                }],
                "cases": [{
                    "name": "unsafe-javascript-integer",
                    "request": {
                        "serviceId": "reader",
                        "method": "readCard",
                        "parameters": { "timeout": 5 }
                    },
                    "expected": {
                        "ResCode": 0,
                        "ResData": { "sequence": 9_007_199_254_740_992_u64 }
                    }
                }]
            }),
        );
        let unsafe_number_output = root.path().join("unsafe-number-fixtures.ts");
        assert!(generate_web_fixtures(&GenerateWebFixturesOptions {
            plugin_root: None,
            plugin_dir: Some(&plugin_dir),
            matrix: &unsafe_number_matrix,
            output: &unsafe_number_output,
        })
        .unwrap_err()
        .to_string()
        .contains("outside the JavaScript safe range"));
        assert!(!unsafe_number_output.exists());

        let inside_output = plugin_dir.join("fixtures.ts");
        assert!(generate_web_fixtures(&GenerateWebFixturesOptions {
            plugin_root: None,
            plugin_dir: Some(&plugin_dir),
            matrix: &matrix,
            output: &inside_output,
        })
        .unwrap_err()
        .to_string()
        .contains("outside the verified plugin input"));
        assert!(!inside_output.exists());
    }

    #[test]
    fn web_fixtures_reject_ambiguous_device_states_after_alias_normalization() {
        let root = tempfile::tempdir().unwrap();
        let plugin_dir = root.path().join("reader-plugin");
        fs::create_dir(&plugin_dir).unwrap();
        fs::write(
            plugin_dir.join("api.json"),
            r#"{"serviceId":"reader","mainClass":"reader.dll","architecture":"x86","methods":[{"name":"read","alias":"readCard","parameters":["timeout"]}]}"#,
        )
        .unwrap();
        fs::write(plugin_dir.join("reader.dll"), pe(0x014c, &["read"])).unwrap();
        fs::write(
            plugin_dir.join("plugin.json"),
            serde_json::to_vec(&json!({
                "schemaVersion": 1,
                "pluginId": "reader-plugin",
                "version": "1.0.0",
                "displayName": "Reader"
            }))
            .unwrap(),
        )
        .unwrap();
        let matrix = matrix_file(
            root.path(),
            "ambiguous-web-fixture-matrix.json",
            json!({
                "schemaVersion": 1,
                "draft": false,
                "plugins": [{
                    "pluginId": "reader-plugin",
                    "version": "1.0.0"
                }],
                "cases": [{
                    "name": "native-route",
                    "request": {
                        "serviceId": "reader",
                        "method": "read",
                        "parameters": { "timeout": 5 }
                    },
                    "expected": { "ResCode": 0, "ResData": { "ReturnValue": 0 } }
                }, {
                    "name": "alias-route-same-input",
                    "request": {
                        "serviceId": "reader",
                        "method": "readCard",
                        "parameters": { "timeout": 5 }
                    },
                    "expected": { "ResCode": 1, "ResData": { "ReturnValue": 1 } }
                }]
            }),
        );
        let output = root.path().join("ambiguous-fixtures.ts");

        let error = generate_web_fixtures(&GenerateWebFixturesOptions {
            plugin_root: None,
            plugin_dir: Some(&plugin_dir),
            matrix: &matrix,
            output: &output,
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("duplicate Web fixture input for route [reader/readCard]"));
        assert!(!output.exists());
    }

    #[test]
    fn web_kit_atomically_binds_client_fixtures_and_source_digests() {
        let root = tempfile::tempdir().unwrap();
        let plugin_dir = root.path().join("reader-plugin");
        fs::create_dir(&plugin_dir).unwrap();
        fs::write(
            plugin_dir.join("api.json"),
            r#"{"serviceId":"reader","mainClass":"reader.dll","architecture":"x86","methods":[{"name":"read","alias":"readCard","parameters":["timeout"]}]}"#,
        )
        .unwrap();
        fs::write(plugin_dir.join("reader.dll"), pe(0x014c, &["read"])).unwrap();
        fs::write(
            plugin_dir.join("plugin.json"),
            serde_json::to_vec(&json!({
                "schemaVersion": 1,
                "pluginId": "reader-plugin",
                "version": "2.3.1",
                "displayName": "Patient Reader"
            }))
            .unwrap(),
        )
        .unwrap();
        let matrix = matrix_file(
            root.path(),
            "web-kit-matrix.json",
            bound_executable_matrix(
                json!({
                    "name": "reviewed-read",
                    "request": {
                        "serviceId": "reader",
                        "method": "read",
                        "parameters": { "timeout": 5 }
                    },
                    "expected": {
                        "ResCode": 0,
                        "ResData": { "ReturnValue": 0, "cardNumber": "TEST-001" }
                    }
                }),
                "reader-plugin",
                "2.3.1",
            ),
        );
        let destination = root.path().join("reader-web-kit");

        let report = generate_web_kit(&GenerateWebKitOptions {
            plugin_dir: &plugin_dir,
            matrix: &matrix,
            destination: &destination,
        })
        .unwrap();
        assert_eq!(report.plugin_id, "reader-plugin");
        assert_eq!(report.plugin_version, "2.3.1");
        assert_eq!(report.service_count, 1);
        assert_eq!(report.method_count, 1);
        assert_eq!(report.fixture_count, 1);
        assert_eq!(report.file_count, 3);
        assert_eq!(
            report.api_sha256,
            sha256_file(&plugin_dir.join("api.json")).unwrap()
        );
        assert_eq!(
            report.plugin_metadata_sha256,
            sha256_file(&plugin_dir.join("plugin.json")).unwrap()
        );
        assert_eq!(report.matrix_sha256, sha256_file(&matrix).unwrap());
        assert_eq!(report.destination, destination.canonicalize().unwrap());

        let client = fs::read_to_string(destination.join(WEB_KIT_CLIENT_FILENAME)).unwrap();
        let fixtures = fs::read_to_string(destination.join(WEB_KIT_FIXTURES_FILENAME)).unwrap();
        assert!(client.contains("Web kit plugin: reader-plugin@2.3.1"));
        assert!(client.contains(&format!("API SHA-256: {}", report.api_sha256)));
        assert!(client.contains("export class PatientReaderClient"));
        assert!(client.contains("invokePlugin<ReadCardData>(\"reader\", \"readCard\""));
        assert!(fixtures.contains("\"method\": \"readCard\""));
        assert_eq!(report.client_sha256, sha256_hex(client.as_bytes()));
        assert_eq!(report.fixtures_sha256, sha256_hex(fixtures.as_bytes()));

        let kit_manifest_path = destination.join(WEB_KIT_MANIFEST_FILENAME);
        let kit_manifest_bytes = fs::read(&kit_manifest_path).unwrap();
        let kit_manifest: Value = serde_json::from_slice(&kit_manifest_bytes).unwrap();
        assert_eq!(kit_manifest["pluginId"], "reader-plugin");
        assert_eq!(kit_manifest["pluginVersion"], "2.3.1");
        assert_eq!(kit_manifest["matrixSha256"], report.matrix_sha256);
        assert_eq!(
            kit_manifest["files"]["client"]["path"],
            WEB_KIT_CLIENT_FILENAME
        );
        assert_eq!(
            kit_manifest["files"]["client"]["sha256"],
            report.client_sha256
        );
        assert_eq!(
            kit_manifest["files"]["fixtures"]["sha256"],
            report.fixtures_sha256
        );
        assert_eq!(
            report.manifest_sha256,
            sha256_file(&destination.join(WEB_KIT_MANIFEST_FILENAME)).unwrap()
        );
        assert_eq!(fs::read_dir(&destination).unwrap().count(), 3);
        assert!(!client.contains(plugin_dir.to_string_lossy().as_ref()));
        assert!(!fixtures.contains(plugin_dir.to_string_lossy().as_ref()));
        assert!(!serde_json::to_string(&kit_manifest)
            .unwrap()
            .contains(plugin_dir.to_string_lossy().as_ref()));

        let checked = check_web_kit(&destination).unwrap();
        assert!(checked.verified);
        assert_eq!(checked.plugin_id, report.plugin_id);
        assert_eq!(checked.plugin_version, report.plugin_version);
        assert_eq!(checked.service_count, report.service_count);
        assert_eq!(checked.method_count, report.method_count);
        assert_eq!(checked.fixture_count, report.fixture_count);
        assert_eq!(checked.api_sha256, report.api_sha256);
        assert_eq!(
            checked.plugin_metadata_sha256,
            report.plugin_metadata_sha256
        );
        assert_eq!(checked.matrix_sha256, report.matrix_sha256);
        assert_eq!(checked.client_sha256, report.client_sha256);
        assert_eq!(checked.fixtures_sha256, report.fixtures_sha256);
        assert_eq!(checked.manifest_sha256, report.manifest_sha256);
        assert!(!serde_json::to_string(&checked)
            .unwrap()
            .contains(root.path().to_string_lossy().as_ref()));

        let error = generate_web_kit(&GenerateWebKitOptions {
            plugin_dir: &plugin_dir,
            matrix: &matrix,
            destination: &destination,
        })
        .unwrap_err();
        assert!(error.to_string().contains("already exists"));

        let inside_destination = plugin_dir.join("web-kit");
        let error = generate_web_kit(&GenerateWebKitOptions {
            plugin_dir: &plugin_dir,
            matrix: &matrix,
            destination: &inside_destination,
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("outside the verified plugin input"));
        assert!(!inside_destination.exists());

        let client_path = destination.join(WEB_KIT_CLIENT_FILENAME);
        fs::write(&client_path, format!("{client}// drift\n")).unwrap();
        assert!(check_web_kit(&destination)
            .unwrap_err()
            .to_string()
            .contains("does not match its manifest digests"));
        fs::write(&client_path, &client).unwrap();

        let extra = destination.join("notes.txt");
        fs::write(&extra, "unreviewed").unwrap();
        assert!(check_web_kit(&destination)
            .unwrap_err()
            .to_string()
            .contains("must contain exactly"));
        fs::remove_file(extra).unwrap();

        let mut unknown_field_manifest = kit_manifest.clone();
        unknown_field_manifest["unreviewed"] = Value::Bool(true);
        fs::write(
            &kit_manifest_path,
            serde_json::to_vec_pretty(&unknown_field_manifest).unwrap(),
        )
        .unwrap();
        assert!(check_web_kit(&destination).is_err());
        fs::write(&kit_manifest_path, &kit_manifest_bytes).unwrap();

        let mut uppercase_digest_manifest = kit_manifest.clone();
        uppercase_digest_manifest["apiSha256"] =
            Value::String(report.api_sha256.to_ascii_uppercase());
        fs::write(
            &kit_manifest_path,
            serde_json::to_vec_pretty(&uppercase_digest_manifest).unwrap(),
        )
        .unwrap();
        assert!(check_web_kit(&destination)
            .unwrap_err()
            .to_string()
            .contains("lowercase hexadecimal"));
        fs::write(&kit_manifest_path, &kit_manifest_bytes).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let fixtures_path = destination.join(WEB_KIT_FIXTURES_FILENAME);
            fs::remove_file(&fixtures_path).unwrap();
            symlink(&client_path, &fixtures_path).unwrap();
            assert!(check_web_kit(&destination).is_err());
        }
    }

    #[test]
    fn failed_web_kit_generation_leaves_no_partial_handoff() {
        let root = tempfile::tempdir().unwrap();
        let plugin_dir = root.path().join("reader-plugin");
        fs::create_dir(&plugin_dir).unwrap();
        fs::write(
            plugin_dir.join("api.json"),
            r#"{"serviceId":"reader","mainClass":"reader.dll","architecture":"x86","methods":[{"name":"read","parameters":["timeout"]}]}"#,
        )
        .unwrap();
        fs::write(plugin_dir.join("reader.dll"), pe(0x014c, &["read"])).unwrap();
        fs::write(
            plugin_dir.join("plugin.json"),
            r#"{"schemaVersion":1,"pluginId":"reader-plugin","version":"1.0.0","displayName":"Reader"}"#,
        )
        .unwrap();
        let draft_matrix = matrix_file(
            root.path(),
            "draft-web-kit-matrix.json",
            json!({
                "schemaVersion": 1,
                "draft": true,
                "plugins": [{ "pluginId": "reader-plugin", "version": "1.0.0" }],
                "cases": [executable_case()]
            }),
        );
        let destination = root.path().join("incomplete-web-kit");

        let error = generate_web_kit(&GenerateWebKitOptions {
            plugin_dir: &plugin_dir,
            matrix: &draft_matrix,
            destination: &destination,
        })
        .unwrap_err();
        assert!(error.to_string().contains("still marked as draft"));
        assert!(!destination.exists());
    }

    #[test]
    fn executable_matrix_check_rejects_every_unfinished_hardware_gate() {
        let root = tempfile::tempdir().unwrap();
        let plugin_dir = source(root.path());
        let manifest = PluginManifest::load("reader", plugin_dir).unwrap();

        let mut draft = executable_matrix(executable_case());
        draft["draft"] = Value::Bool(true);
        let error = validate_executable_matrix(
            &matrix_file(root.path(), "draft.json", draft),
            std::slice::from_ref(&manifest),
        )
        .unwrap_err();
        assert!(error.to_string().contains("marked as draft"));

        let mut review = executable_case();
        review["reviewRequired"] = Value::Bool(true);
        let error = validate_executable_matrix(
            &matrix_file(root.path(), "review.json", executable_matrix(review)),
            std::slice::from_ref(&manifest),
        )
        .unwrap_err();
        assert!(error.to_string().contains("requires exact response review"));

        let mut placeholder = executable_case();
        placeholder["expected"]["ResData"] = Value::String(DRAFT_RESPONSE_PLACEHOLDER.into());
        let error = validate_executable_matrix(
            &matrix_file(
                root.path(),
                "placeholder.json",
                executable_matrix(placeholder),
            ),
            std::slice::from_ref(&manifest),
        )
        .unwrap_err();
        assert!(error.to_string().contains("draft placeholder"));

        let mut incomplete = executable_case();
        incomplete["request"]["parameters"] = json!({});
        let error = validate_executable_matrix(
            &matrix_file(
                root.path(),
                "incomplete.json",
                executable_matrix(incomplete),
            ),
            &[manifest],
        )
        .unwrap_err();
        assert!(error.to_string().contains("exactly match"));
    }

    #[test]
    fn executable_matrix_check_rejects_route_and_coverage_drift() {
        let root = tempfile::tempdir().unwrap();
        let plugin_dir = source(root.path());
        let mut manifest = PluginManifest::load("reader", plugin_dir).unwrap();

        let mut unknown = executable_case();
        unknown["request"]["method"] = Value::String("missing".into());
        let error = validate_executable_matrix(
            &matrix_file(root.path(), "unknown.json", executable_matrix(unknown)),
            std::slice::from_ref(&manifest),
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown method"));

        let mut reset = manifest.services[0].methods[0].clone();
        reset.name = "reset".into();
        reset.alias = None;
        reset.parameters.clear();
        manifest.services[0].methods.push(reset);
        let matrix = matrix_file(
            root.path(),
            "incomplete-coverage.json",
            executable_matrix(executable_case()),
        );
        let error =
            validate_executable_matrix(&matrix, std::slice::from_ref(&manifest)).unwrap_err();
        assert!(error.to_string().contains("do not cover 1"));

        let error =
            validate_executable_matrix(&matrix, &[manifest.clone(), manifest.clone()]).unwrap_err();
        assert!(error.to_string().contains("duplicate portable plugin ID"));

        let mut duplicate = manifest.clone();
        duplicate.plugin_id = "duplicate-reader".into();
        let error = validate_executable_matrix(&matrix, &[manifest, duplicate]).unwrap_err();
        assert!(error.to_string().contains("duplicate serviceId"));
    }

    #[test]
    fn release_set_check_verifies_every_bound_package_as_one_candidate() {
        let root = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[51; 32]);
        let trust = trust_store(root.path(), &signing_key, None);

        let reader_source = source(root.path());
        let reader_package = signed_package(
            root.path(),
            &reader_source,
            "reader",
            "reader-plugin",
            "1.2.3",
            &trust,
            &signing_key,
        );
        let printer_root = root.path().join("printer-source-root");
        fs::create_dir(&printer_root).unwrap();
        let printer_source = source(&printer_root);
        fs::write(
            printer_source.join("api.json"),
            r#"{"serviceId":"printer","mainClass":"reader.dll","architecture":"x86","methods":[{"name":"read","parameters":["timeout"]}]}"#,
        )
        .unwrap();
        let printer_package = signed_package(
            root.path(),
            &printer_source,
            "printer",
            "printer-plugin",
            "2.0.0",
            &trust,
            &signing_key,
        );

        let reader_case = executable_case();
        let mut printer_case = executable_case();
        printer_case["name"] = Value::String("printer.read verified".into());
        printer_case["request"]["serviceId"] = Value::String("printer".into());
        let matrix = matrix_file(
            root.path(),
            "release-set-matrix.json",
            json!({
                "schemaVersion": 1,
                "draft": false,
                "plugins": [
                    { "pluginId": "reader-plugin", "version": "1.2.3" },
                    { "pluginId": "printer-plugin", "version": "2.0.0" }
                ],
                "cases": [reader_case, printer_case]
            }),
        );
        let spec = matrix_file(
            root.path(),
            "release-set.json",
            json!({
                "schemaVersion": 1,
                "packages": [
                    reader_package.file_name().unwrap().to_string_lossy(),
                    printer_package.file_name().unwrap().to_string_lossy()
                ]
            }),
        );

        let report = check_release_set(&spec, &trust, &matrix).unwrap();
        assert_eq!(report.plugin_count, 2);
        assert_eq!(report.service_count, 2);
        assert_eq!(report.method_count, 2);
        assert_eq!(report.case_count, 2);
        assert_eq!(report.enabled_case_count, 2);
        assert_eq!(
            report
                .packages
                .iter()
                .map(|package| package.plugin_id.as_str())
                .collect::<Vec<_>>(),
            ["printer-plugin", "reader-plugin"]
        );
        assert_eq!(report.spec_sha256.len(), 64);
        assert_eq!(report.package_set_sha256.len(), 64);
        assert!(report.packages_verified);
        assert!(report.matrix_verified);

        let reversed_spec = matrix_file(
            root.path(),
            "reversed-release-set.json",
            json!({
                "schemaVersion": 1,
                "packages": [
                    printer_package.file_name().unwrap().to_string_lossy(),
                    reader_package.file_name().unwrap().to_string_lossy()
                ]
            }),
        );
        let reversed = check_release_set(&reversed_spec, &trust, &matrix).unwrap();
        assert_eq!(reversed.package_set_sha256, report.package_set_sha256);
        assert_eq!(reversed.packages, report.packages);

        let plugin_root = root.path().join("tested-plugin-root");
        let materialized = materialize_release_set(&MaterializeReleaseSetOptions {
            spec: &spec,
            trust_store: &trust,
            matrix: &matrix,
            plugin_root: &plugin_root,
        })
        .unwrap();
        assert!(materialized.materialized);
        assert!(materialized.root_verified);
        assert_eq!(materialized.plugin_count, 2);
        assert_eq!(materialized.package_set_sha256, report.package_set_sha256);
        let rooted = check_release_root_against_set(&plugin_root, &spec, &trust, &matrix).unwrap();
        assert_eq!(rooted.package_set_sha256, report.package_set_sha256);

        let error = materialize_release_set(&MaterializeReleaseSetOptions {
            spec: &spec,
            trust_store: &trust,
            matrix: &matrix,
            plugin_root: &plugin_root,
        })
        .unwrap_err();
        assert!(error.to_string().contains("already exists"));
        check_release_root_against_set(&plugin_root, &spec, &trust, &matrix).unwrap();

        fs::write(
            plugin_root.join(RELEASE_SET_MATERIALIZATION_MARKER),
            b"incomplete",
        )
        .unwrap();
        let error =
            check_release_root_against_set(&plugin_root, &spec, &trust, &matrix).unwrap_err();
        assert!(error.to_string().contains("incomplete release set"));
        fs::remove_file(plugin_root.join(RELEASE_SET_MATERIALIZATION_MARKER)).unwrap();

        fs::write(plugin_root.join("reader-plugin/reader.dll"), b"tampered").unwrap();
        let error =
            check_release_root_against_set(&plugin_root, &spec, &trust, &matrix).unwrap_err();
        assert!(error.to_string().contains("signature"));

        let duplicate_spec = matrix_file(
            root.path(),
            "duplicate-release-set.json",
            json!({
                "schemaVersion": 1,
                "packages": [
                    reader_package.file_name().unwrap().to_string_lossy(),
                    reader_package.file_name().unwrap().to_string_lossy()
                ]
            }),
        );
        let error = check_release_set(&duplicate_spec, &trust, &matrix).unwrap_err();
        assert!(error.to_string().contains("same package path"));
        let rejected_root = root.path().join("rejected-plugin-root");
        materialize_release_set(&MaterializeReleaseSetOptions {
            spec: &duplicate_spec,
            trust_store: &trust,
            matrix: &matrix,
            plugin_root: &rejected_root,
        })
        .unwrap_err();
        assert!(!rejected_root.exists());

        let copied_package = root.path().join("reader-copy.ssdev-plugin");
        fs::copy(&reader_package, &copied_package).unwrap();
        let duplicate_identity_spec = matrix_file(
            root.path(),
            "duplicate-identity-release-set.json",
            json!({
                "schemaVersion": 1,
                "packages": [
                    reader_package.file_name().unwrap().to_string_lossy(),
                    copied_package.file_name().unwrap().to_string_lossy()
                ]
            }),
        );
        let error = check_release_set(&duplicate_identity_spec, &trust, &matrix).unwrap_err();
        assert!(error.to_string().contains("duplicate portable plugin ID"));
    }

    #[test]
    fn prepares_signs_packages_and_verifies_without_copying_legacy_license() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let staging = root.path().join("stage");
        let request = root.path().join("request.json");
        let matrix = root.path().join("matrix.json");
        let signing_key = SigningKey::from_bytes(&[33; 32]);
        let trust_path = trust_store(root.path(), &signing_key, None);
        let report = prepare(&PrepareOptions {
            source: &source,
            staging: &staging,
            request: &request,
            matrix_template: &matrix,
            plugin_id: "reader-plugin",
            version: "1.2.3",
            desktop_version_requirement: ">=0.1.0, <0.2.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust_path,
            matrix_seed: None,
        })
        .unwrap();
        assert!(report.legacy_license_excluded);
        assert_eq!(report.desktop_version_requirement, ">=0.1.0, <0.2.0");
        assert!(!report.matrix_seeded);
        assert_eq!(report.matrix_case_count, 1);
        assert_eq!(report.matrix_placeholder_case_count, 1);
        assert_eq!(report.matrix_review_required_case_count, 1);
        assert!(!staging.join("license.dat").exists());
        let generated_metadata: PluginMetadata =
            serde_json::from_slice(&fs::read(staging.join(PLUGIN_METADATA_FILENAME)).unwrap())
                .unwrap();
        assert!(generated_metadata.supports_desktop_version(&Version::new(0, 1, 7)));
        assert!(!generated_metadata.supports_desktop_version(&Version::new(0, 2, 0)));
        let generated_matrix: Value = serde_json::from_slice(&fs::read(&matrix).unwrap()).unwrap();
        assert!(generated_matrix["draft"].as_bool().unwrap());
        assert_eq!(
            generated_matrix["plugins"][0],
            json!({ "pluginId": "reader-plugin", "version": "1.2.3" })
        );

        let signing_request: SigningRequest =
            serde_json::from_slice(&fs::read(&request).unwrap()).unwrap();
        let payload = BASE64.decode(signing_request.payload_base64).unwrap();
        let signature_path = root.path().join("signature.txt");
        fs::write(
            &signature_path,
            BASE64.encode(signing_key.sign(&payload).to_bytes()),
        )
        .unwrap();
        let package = root.path().join("reader.ssdev-plugin");
        let finalized = finalize(&FinalizeOptions {
            staging: &staging,
            request: &request,
            signature: &signature_path,
            trust_store: &trust_path,
            package: &package,
        })
        .unwrap();
        assert!(finalized.package_verified);
        assert_eq!(finalized.payload_sha256, report.payload_sha256);
        let verified = verify(&package, &trust_path).unwrap();
        assert_eq!(verified.plugin_id, "reader-plugin");
        assert_eq!(verified.package_sha256, finalized.package_sha256);

        let finalized_matrix = matrix_file(
            root.path(),
            "finalized-matrix.json",
            bound_executable_matrix(executable_case(), "reader-plugin", "1.2.3"),
        );
        let candidate = check_release_candidate(&package, &trust_path, &finalized_matrix).unwrap();
        assert_eq!(candidate.plugin_id, "reader-plugin");
        assert_eq!(candidate.version, "1.2.3");
        assert_eq!(candidate.package_sha256, finalized.package_sha256);
        assert_eq!(
            candidate.matrix_sha256,
            sha256_file(&finalized_matrix).unwrap()
        );
        assert_eq!(candidate.service_count, 1);
        assert_eq!(candidate.method_count, 1);
        assert_eq!(candidate.case_count, 1);
        assert_eq!(candidate.enabled_case_count, 1);
        assert!(candidate.package_verified);
        assert!(candidate.matrix_verified);

        let unbound_matrix = matrix_file(
            root.path(),
            "unbound-matrix.json",
            executable_matrix(executable_case()),
        );
        let error = check_release_candidate(&package, &trust_path, &unbound_matrix).unwrap_err();
        assert!(error.to_string().contains("bind the exact plugin"));

        let stale_matrix = matrix_file(
            root.path(),
            "stale-version-matrix.json",
            bound_executable_matrix(executable_case(), "reader-plugin", "1.2.2"),
        );
        let error = check_release_candidate(&package, &trust_path, &stale_matrix).unwrap_err();
        assert!(error.to_string().contains("do not exactly match"));

        let mut mismatched_case = executable_case();
        mismatched_case["request"]["method"] = Value::String("other-version-method".into());
        let mismatched_matrix = matrix_file(
            root.path(),
            "mismatched-matrix.json",
            bound_executable_matrix(mismatched_case, "reader-plugin", "1.2.3"),
        );
        let error = check_release_candidate(&package, &trust_path, &mismatched_matrix).unwrap_err();
        assert!(error.to_string().contains("unknown method"));

        trust_store(root.path(), &signing_key, Some("retired"));
        let error = check_release_candidate(&package, &trust_path, &finalized_matrix).unwrap_err();
        assert!(error.to_string().contains("retired"));
        trust_store(root.path(), &signing_key, None);

        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let spec = root.path().join("catalog-spec.json");
        fs::write(
            &spec,
            serde_json::to_vec_pretty(&json!({
                "schemaVersion": 1,
                "issuedAt": 1_699_999_940_u64,
                "expiresAt": 1_700_003_600_u64,
                "packages": [{
                    "package": "reader.ssdev-plugin",
                    "url": "https://plugins.example.test/reader.ssdev-plugin"
                }],
                "withdrawals": [{
                    "pluginId": "reader-plugin",
                    "version": "1.2.2",
                    "reason": "defective"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let catalog_path = root.path().join("catalog.json");
        let catalog_report = create_catalog(&CatalogOptions {
            spec: &spec,
            trust_store: &trust_path,
            catalog: &catalog_path,
            now,
        })
        .unwrap();
        assert_eq!(catalog_report.package_count, 1);
        assert_eq!(catalog_report.withdrawal_count, 1);
        assert_eq!(catalog_report.api_comparison_count, 0);
        assert!(catalog_report.api_compatibility_verified);
        let catalog_bytes = fs::read(&catalog_path).unwrap();
        assert_eq!(catalog_report.catalog_sha256, sha256_hex(&catalog_bytes));
        let catalog =
            webplus_plugin_repository::PluginCatalog::from_unsigned_bytes(&catalog_bytes, now)
                .unwrap();
        assert_eq!(catalog.entries()[0].plugin_id, "reader-plugin");
        assert_eq!(
            catalog.entries()[0].version,
            Version::parse("1.2.3").unwrap()
        );
        assert_eq!(
            catalog.entries()[0]
                .desktop_version_requirement
                .as_ref()
                .unwrap()
                .to_string(),
            ">=0.1.0, <0.2.0"
        );
        assert_eq!(catalog.entries()[0].sha256, finalized.package_sha256);
        assert_eq!(catalog.withdrawals().len(), 1);
        assert!(catalog
            .withdrawal("reader-plugin", &Version::parse("1.2.2").unwrap())
            .is_some());
    }

    #[test]
    fn catalog_verifies_compatible_versions_and_rejects_public_api_breaks() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let signing_key = SigningKey::from_bytes(&[91; 32]);
        let trust = trust_store(root.path(), &signing_key, None);
        let version_one = signed_package(
            root.path(),
            &source,
            "reader-v1",
            "reader-plugin",
            "1.0.0",
            &trust,
            &signing_key,
        );

        fs::write(
            source.join("api.json"),
            r#"{"serviceId":"reader","mainClass":"reader.dll","architecture":"x86","methods":[{"name":"read","parameters":["timeout"]},{"name":"status","parameters":[]}]}"#,
        )
        .unwrap();
        fs::write(source.join("reader.dll"), pe(0x014c, &["read", "status"])).unwrap();
        let version_two = signed_package(
            root.path(),
            &source,
            "reader-v2",
            "reader-plugin",
            "1.1.0",
            &trust,
            &signing_key,
        );

        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let compatible_spec = matrix_file(
            root.path(),
            "compatible-catalog-spec.json",
            json!({
                "schemaVersion": 1,
                "issuedAt": 1_699_999_940_u64,
                "expiresAt": 1_700_003_600_u64,
                "packages": [{
                    "package": version_two.file_name().unwrap().to_string_lossy(),
                    "url": "https://plugins.example.test/reader-v2.ssdev-plugin"
                }, {
                    "package": version_one.file_name().unwrap().to_string_lossy(),
                    "url": "https://plugins.example.test/reader-v1.ssdev-plugin"
                }]
            }),
        );
        let compatible_catalog = root.path().join("compatible-catalog.json");
        let report = create_catalog(&CatalogOptions {
            spec: &compatible_spec,
            trust_store: &trust,
            catalog: &compatible_catalog,
            now,
        })
        .unwrap();
        assert_eq!(report.package_count, 2);
        assert_eq!(report.api_comparison_count, 1);
        assert!(report.api_compatibility_verified);

        fs::write(
            source.join("api.json"),
            r#"{"serviceId":"reader","mainClass":"reader.dll","architecture":"x86","methods":[{"name":"status","parameters":[]}]}"#,
        )
        .unwrap();
        fs::write(source.join("reader.dll"), pe(0x014c, &["status"])).unwrap();
        let version_three = signed_package(
            root.path(),
            &source,
            "reader-v3",
            "reader-plugin",
            "1.2.0",
            &trust,
            &signing_key,
        );
        let breaking_spec = matrix_file(
            root.path(),
            "breaking-catalog-spec.json",
            json!({
                "schemaVersion": 1,
                "issuedAt": 1_699_999_940_u64,
                "expiresAt": 1_700_003_600_u64,
                "packages": [{
                    "package": version_two.file_name().unwrap().to_string_lossy(),
                    "url": "https://plugins.example.test/reader-v2.ssdev-plugin"
                }, {
                    "package": version_three.file_name().unwrap().to_string_lossy(),
                    "url": "https://plugins.example.test/reader-v3.ssdev-plugin"
                }]
            }),
        );
        let breaking_catalog = root.path().join("breaking-catalog.json");
        let error = create_catalog(&CatalogOptions {
            spec: &breaking_spec,
            trust_store: &trust,
            catalog: &breaking_catalog,
            now,
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("breaks 1 public Web Bridge contract(s)"));
        assert!(!breaking_catalog.exists());
    }

    #[test]
    fn prepare_rejects_an_invalid_desktop_version_range_before_staging() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let trust = trust_store(root.path(), &SigningKey::from_bytes(&[58; 32]), None);
        let staging = root.path().join("invalid-compat-stage");
        let error = prepare(&PrepareOptions {
            source: &source,
            staging: &staging,
            request: &root.path().join("invalid-compat-request.json"),
            matrix_template: &root.path().join("invalid-compat-matrix.json"),
            plugin_id: "reader-plugin",
            version: "1.0.0",
            desktop_version_requirement: "not a semver range",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust,
            matrix_seed: None,
        })
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("desktop version requirement is not a SemVer requirement"));
        assert!(!staging.exists());
    }

    #[test]
    fn prepare_validates_and_adopts_an_external_draft_matrix_seed() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let seed = root.path().join("release-matrix-seed.json");
        fs::write(
            &seed,
            serde_json::to_vec_pretty(&json!({
                "schemaVersion": 1,
                "draft": true,
                "cases": [{
                    "name": "known reader response",
                    "enabled": true,
                    "request": {
                        "serviceId": "reader",
                        "method": "read",
                        "parameters": { "timeout": 5 }
                    },
                    "expected": {
                        "ResCode": 0,
                        "ResData": { "ReturnValue": 0 }
                    }
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let matrix = root.path().join("matrix.json");
        let trust = trust_store(root.path(), &SigningKey::from_bytes(&[42; 32]), None);

        let report = prepare(&PrepareOptions {
            source: &source,
            staging: &root.path().join("stage"),
            request: &root.path().join("request.json"),
            matrix_template: &matrix,
            plugin_id: "reader-plugin",
            version: "1.0.0",
            desktop_version_requirement: ">=0.1.0, <0.2.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust,
            matrix_seed: Some(&seed),
        })
        .unwrap();

        assert!(report.matrix_seeded);
        assert_eq!(report.matrix_case_count, 1);
        assert_eq!(report.matrix_placeholder_case_count, 0);
        assert_eq!(report.matrix_review_required_case_count, 0);
        let generated: Value = serde_json::from_slice(&fs::read(matrix).unwrap()).unwrap();
        assert_eq!(generated["cases"][0]["name"], "known reader response");
        assert_eq!(generated["plugins"][0]["pluginId"], "reader-plugin");
        assert_eq!(generated["plugins"][0]["version"], "1.0.0");
        assert_eq!(
            generated["cases"][0]["expected"]["ResData"]["ReturnValue"],
            0
        );
    }

    #[test]
    fn prepare_rejects_a_matrix_seed_inside_the_signed_source() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let seed = source.join("matrix-seed.json");
        fs::write(&seed, b"{}").unwrap();
        let trust = trust_store(root.path(), &SigningKey::from_bytes(&[43; 32]), None);

        let error = prepare(&PrepareOptions {
            source: &source,
            staging: &root.path().join("stage"),
            request: &root.path().join("request.json"),
            matrix_template: &root.path().join("matrix.json"),
            plugin_id: "reader-plugin",
            version: "1.0.0",
            desktop_version_requirement: ">=0.1.0, <0.2.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust,
            matrix_seed: Some(&seed),
        })
        .unwrap_err();

        assert!(error.to_string().contains("outside the signed source"));
        assert!(!root.path().join("stage").exists());
    }

    #[test]
    fn prepare_rejects_undeclared_matrix_seed_inputs() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let seed = root.path().join("invalid-matrix-seed.json");
        fs::write(
            &seed,
            serde_json::to_vec(&json!({
                "schemaVersion": 1,
                "draft": true,
                "cases": [{
                    "name": "undeclared input",
                    "request": {
                        "serviceId": "reader",
                        "method": "read",
                        "parameters": { "secret": "must-not-pass" }
                    },
                    "expected": { "ResCode": 0, "ResData": null }
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let trust = trust_store(root.path(), &SigningKey::from_bytes(&[44; 32]), None);

        let error = prepare(&PrepareOptions {
            source: &source,
            staging: &root.path().join("stage"),
            request: &root.path().join("request.json"),
            matrix_template: &root.path().join("matrix.json"),
            plugin_id: "reader-plugin",
            version: "1.0.0",
            desktop_version_requirement: ">=0.1.0, <0.2.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust,
            matrix_seed: Some(&seed),
        })
        .unwrap_err();

        assert!(error.to_string().contains("undeclared input parameter"));
        assert!(!root.path().join("stage").exists());
    }

    #[test]
    fn prepare_rejects_missing_matrix_seed_inputs() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let seed = root.path().join("missing-input-matrix-seed.json");
        fs::write(
            &seed,
            serde_json::to_vec(&json!({
                "schemaVersion": 1,
                "draft": true,
                "cases": [{
                    "name": "missing timeout",
                    "request": {
                        "serviceId": "reader",
                        "method": "read",
                        "parameters": {}
                    },
                    "expected": { "ResCode": 0, "ResData": null }
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let trust = trust_store(root.path(), &SigningKey::from_bytes(&[45; 32]), None);

        let error = prepare(&PrepareOptions {
            source: &source,
            staging: &root.path().join("stage"),
            request: &root.path().join("request.json"),
            matrix_template: &root.path().join("matrix.json"),
            plugin_id: "reader-plugin",
            version: "1.0.0",
            desktop_version_requirement: ">=0.1.0, <0.2.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust,
            matrix_seed: Some(&seed),
        })
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("missing declared input parameter"));
        assert!(!root.path().join("stage").exists());
    }

    #[test]
    fn prepare_rejects_install_run_and_architecture_mismatch() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        fs::write(
            source.join("api.json"),
            r#"{"serviceId":"reader","mainClass":"reader.dll","architecture":"x64","installRun":"setup.exe","methods":[{"name":"read"}]}"#,
        )
        .unwrap();
        let trust = trust_store(root.path(), &SigningKey::from_bytes(&[35; 32]), None);
        let error = prepare(&PrepareOptions {
            source: &source,
            staging: &root.path().join("stage"),
            request: &root.path().join("request.json"),
            matrix_template: &root.path().join("matrix.json"),
            plugin_id: "reader-plugin",
            version: "1.0.0",
            desktop_version_requirement: ">=0.1.0, <0.2.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust,
            matrix_seed: None,
        })
        .unwrap_err();
        assert!(error.to_string().contains("installRun"));
        assert!(!root.path().join("stage").exists());
    }

    #[test]
    fn prepare_rejects_unsupported_dll_abi_before_signing_material_exists() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        fs::write(
            source.join("api.json"),
            r#"{"serviceId":"reader","mainClass":"reader.dll","architecture":"x86","methods":[{"name":"read","returnType":"double"}]}"#,
        )
        .unwrap();
        let trust = trust_store(root.path(), &SigningKey::from_bytes(&[47; 32]), None);
        let staging = root.path().join("stage");
        let request = root.path().join("request.json");
        let matrix = root.path().join("matrix.json");

        let error = prepare(&PrepareOptions {
            source: &source,
            staging: &staging,
            request: &request,
            matrix_template: &matrix,
            plugin_id: "reader-plugin",
            version: "1.0.0",
            desktop_version_requirement: ">=0.1.0, <0.2.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust,
            matrix_seed: None,
        })
        .unwrap_err();

        assert!(error.to_string().contains("floating-point return"));
        assert!(!staging.exists());
        assert!(!request.exists());
        assert!(!matrix.exists());
    }

    #[test]
    fn prepare_rejects_a_retired_key_before_creating_signing_material() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let trust = trust_store(
            root.path(),
            &SigningKey::from_bytes(&[38; 32]),
            Some("retired"),
        );
        let staging = root.path().join("stage");
        let request = root.path().join("request.json");

        let error = prepare(&PrepareOptions {
            source: &source,
            staging: &staging,
            request: &request,
            matrix_template: &root.path().join("matrix.json"),
            plugin_id: "reader-plugin",
            version: "1.0.0",
            desktop_version_requirement: ">=0.1.0, <0.2.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust,
            matrix_seed: None,
        })
        .unwrap_err();

        assert!(error.to_string().contains("retired"));
        assert!(!staging.exists());
        assert!(!request.exists());
    }

    #[test]
    fn finalize_rejects_a_changed_staging_directory_before_importing_signature() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let staging = root.path().join("stage");
        let request = root.path().join("request.json");
        let trust = trust_store(root.path(), &SigningKey::from_bytes(&[36; 32]), None);
        prepare(&PrepareOptions {
            source: &source,
            staging: &staging,
            request: &request,
            matrix_template: &root.path().join("matrix.json"),
            plugin_id: "reader-plugin",
            version: "1.0.0",
            desktop_version_requirement: ">=0.1.0, <0.2.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust,
            matrix_seed: None,
        })
        .unwrap();
        fs::write(staging.join("reader.dll"), pe(0x8664, &["read"])).unwrap();
        let signature = root.path().join("signature.txt");
        fs::write(&signature, BASE64.encode([0_u8; 64])).unwrap();
        let error = finalize(&FinalizeOptions {
            staging: &staging,
            request: &request,
            signature: &signature,
            trust_store: &root.path().join("missing-trust.json"),
            package: &root.path().join("reader.ssdev-plugin"),
        })
        .unwrap_err();
        assert!(error.to_string().contains("changed"));
        assert!(!staging.join(SIGNATURE_FILENAME).exists());
    }

    #[test]
    fn finalize_rejects_a_retired_plugin_signing_key() {
        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let staging = root.path().join("stage");
        let request = root.path().join("request.json");
        let signing_key = SigningKey::from_bytes(&[34; 32]);
        let trust_path = trust_store(root.path(), &signing_key, None);
        prepare(&PrepareOptions {
            source: &source,
            staging: &staging,
            request: &request,
            matrix_template: &root.path().join("matrix.json"),
            plugin_id: "reader-plugin",
            version: "1.0.0",
            desktop_version_requirement: ">=0.1.0, <0.2.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust_path,
            matrix_seed: None,
        })
        .unwrap();
        let signing_request: SigningRequest =
            serde_json::from_slice(&fs::read(&request).unwrap()).unwrap();
        let payload = BASE64.decode(signing_request.payload_base64).unwrap();
        let signature = root.path().join("signature.txt");
        fs::write(
            &signature,
            BASE64.encode(signing_key.sign(&payload).to_bytes()),
        )
        .unwrap();
        trust_store(root.path(), &signing_key, Some("retired"));
        let package = root.path().join("reader.ssdev-plugin");

        let error = finalize(&FinalizeOptions {
            staging: &staging,
            request: &request,
            signature: &signature,
            trust_store: &trust_path,
            package: &package,
        })
        .unwrap_err();

        assert!(error.to_string().contains("retired"));
        assert!(!package.exists());
        assert!(!staging.join(SIGNATURE_FILENAME).exists());
    }

    #[cfg(unix)]
    #[test]
    fn prepare_never_replaces_a_dangling_output_symlink() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let source = source(root.path());
        let staging = root.path().join("stage");
        symlink(root.path().join("missing"), &staging).unwrap();
        let trust = trust_store(root.path(), &SigningKey::from_bytes(&[37; 32]), None);

        let error = prepare(&PrepareOptions {
            source: &source,
            staging: &staging,
            request: &root.path().join("request.json"),
            matrix_template: &root.path().join("matrix.json"),
            plugin_id: "reader-plugin",
            version: "1.0.0",
            desktop_version_requirement: ">=0.1.0, <0.2.0",
            display_name: "Reader",
            key_id: "test-key",
            trust_store: &trust,
            matrix_seed: None,
        })
        .unwrap_err();

        assert!(error.to_string().contains("already exists"));
        assert!(fs::symlink_metadata(staging)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn failed_fresh_directory_operation_removes_partial_output() {
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("candidate-root");
        let result: Result<(), ToolError> =
            with_fresh_directory(&output, "candidate root", |candidate| {
                fs::write(candidate.join("partial"), b"partial").unwrap();
                Err(ToolError::Invalid("injected failure".into()))
            });

        assert!(result.unwrap_err().to_string().contains("injected failure"));
        assert!(!output.exists());
    }

    #[test]
    fn bare_output_names_use_the_current_directory() {
        assert_eq!(output_parent(Path::new("catalog.json")), Path::new("."));
    }
}
