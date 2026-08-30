# Windows 项目交付工具包

`ssdev-windows-delivery-tools-x64` 是面向项目实施、插件发布和 QA 的独立 Windows x64 命令行工具包。它不进入普通用户的 SSDEV Desktop 安装包，因此不会增加在线轻量版体积，也不会把发布、KMS/HSM 或生产切换权限带进业务终端。

工具包包含：

- `ssdev-pilot-readiness.exe`：建立、检查和复验真实试点材料；
- `ssdev-migration-audit.exe`：从已复验材料执行旧 WebPlus/Electron 迁移审计；
- `ssdev-plugin-tool.exe`：插件源检查、客户端/fixture、签名准备、封包和发布集合；
- `ssdev-release-signing.exe`：生成、完成和复验组织 detached 签名流程；
- `ssdev-cutover-evidence.exe`：生产策略、证据预检、Go/No-Go 和当前部署授权复验；
- `ssdev-release-manifest.exe`：创建或复验完整文件清单；
- `ssdev-plugin-matrix.exe` 与 `run-plugin-matrix.ps1`：在 Windows x64 实机调用候选安装包中的 x86/x64 宿主并生成黄金矩阵证据。

`sbom/` 还包含与上述 7 个可执行入口对应的、已移除工作区绝对路径和随机标识的 Windows x64 CycloneDX 1.5 JSON。它用于依赖审计和事件响应，不替代源码提交、二进制签名或最终归档签名。

## 使用前复验

解压后先在工具包目录执行：

```powershell
.\ssdev-release-manifest.exe verify . artifacts.json
Get-Content .\release.json
```

`artifacts.json` 覆盖 README、包装器、发布元数据、全部可执行文件和 SBOM；任何缺失、增加或字节变化都会失败。`release.json` 记录工具版本、完整源码提交、目标架构、SBOM 数量和 Authenticode 状态。生产工具包的所有 EXE 必须由组织 Windows 发布流程签名并显示 `authenticodeVerified: true`，最终目录归档还必须具有组织发布签名；未签名 JSON 清单本身不是发布信任根。GitHub Actions 中名称带 `unsigned` 的短期制品只用于验证构建链，不能进入生产交付。

工具包不含私钥、令牌、业务材料、插件包、黄金矩阵、信任库或 Windows 客户端安装包。组织公开信任库仍应从受保护发布渠道提供，KMS/HSM 私钥不得复制到工具目录。

## 推荐执行顺序

1. 用 `ssdev-pilot-readiness.exe` 初始化并复验试点材料集合；
2. 用 `ssdev-migration-audit.exe` 从同一已复验集合生成正式迁移报告和证据；
3. 用 `ssdev-plugin-tool.exe` 完成生产组件发布集合、Web 接入包和定稿矩阵；
4. 在批准的 Windows x64 设备运行黄金矩阵；
5. 用真实上一生产 bundle 完成 Windows 安装、升级、回退和目标业务页面深度检查；
6. 用 `ssdev-release-signing.exe` 和 `ssdev-cutover-evidence.exe` 完成职责分离签名与 Go/No-Go。

各命令的输入、输出和信任边界以仓库中的 `docs/pilot-readiness.md`、`docs/migration-audit.md`、`docs/plugin-release.md`、`docs/release-signing.md` 与 `docs/cutover-evidence.md` 为准。工具包减少 Rust 工具链安装，不缩减任何正式门禁。

## 无 Rust 的黄金矩阵

`run-plugin-matrix.ps1` 会先用同目录清单工具自动复验完整 `artifacts.json`，再使用同目录的 `ssdev-plugin-matrix.exe`，因此验证机无需安装 Rust。仍必须提供与候选版本完全一致的干净源码工作区：机器证据会绑定它的 Git 提交和 dirty 状态，不能只信任工具文件名。

```powershell
.\run-plugin-matrix.ps1 `
  -Workspace D:\controlled\ssdev-desktop-next `
  -PluginRoot D:\validation\plugins `
  -ReleaseSetSpec D:\approval\release-set.json `
  -TrustStore D:\approval\plugin-trust.json `
  -Matrix D:\approval\plugin-matrix.json `
  -X86Host D:\candidate\windows\webplus-plugin-host-x86.exe `
  -X64Host D:\candidate\windows\webplus-plugin-host-x64.exe `
  -EvidenceOutput D:\evidence\plugin-matrix.json `
  -EvidenceEnvironment qa-windows-hardware-a
```

插件根目录必须由已批准发布集合重新物化；两个宿主必须来自本次待交付 Windows bundle。运行器会在调用硬件前复验发布集合、插件签名、全方法覆盖和输入摘要，运行后再次复验全部输入。失败时不写证据，也不输出用例名称、参数、期望值或实际设备响应。

## 构建与签名

构建机必须使用锁定依赖，并预装精确版本 `cargo-cyclonedx 0.5.9`。脚本会拒绝构建前残留的目标 SBOM，生成后清理临时源文件，并在封装前再次确认提交未变化且工作区仍为 clean。CI 使用下面的测试模式生成独立无签名制品：

```powershell
.\scripts\build-windows-delivery-tools.ps1 `
  -OutputDirectory $env:RUNNER_TEMP\ssdev-windows-delivery-tools-x64 `
  -AllowUnsignedTestBuild
```

无签名模式仅在 `CI=true` 时允许。生产构建必须从 clean commit 执行，并提供包含 `%1` 文件占位符的组织签名命令和预期证书 Subject；脚本会逐个复验 Authenticode 后才生成最终清单：

```powershell
.\scripts\build-windows-delivery-tools.ps1 `
  -OutputDirectory D:\release\ssdev-windows-delivery-tools-x64 `
  -WindowsSignCommand 'organization-sign-tool.exe sign --file %1' `
  -ExpectedSignerSubject 'CN=Example Organization'
```

所有模式都要求 clean commit，输出目录必须位于源码工作区之外且尚不存在，脚本不会覆盖已有工具包。生产发布系统必须对最终目录归档建立组织级发布签名；逐文件清单和 Authenticode 不能替代归档签名或发布渠道访问控制。
