# 生产切换证据与 Go/No-Go

生产切换不以人工汇总日志中的 `PASS` 为依据。`ssdev-cutover-evidence` 严格读取三份不可覆盖且经 QA 环境签名的机器证据，绑定证据、签名封套、信任库和策略的 SHA-256，并生成一个确定的 `GO` 或 `NO-GO` 决策：

- 真实插件黄金矩阵证据：必须由 Windows x64 运行器产生，覆盖全部已声明 service/method；schema 2 同时绑定批准的发布集合规范、确定性包集合、实际插件载荷、信任库、矩阵和 x86/x64 待交付宿主。现场插件根目录必须能逐包重建出发布集合中的相同 SHA-256，证据中的发布集合规范、包集合、信任库及矩阵摘要还必须精确匹配生产策略，不能用另一套较小或不同输入但内部自洽的结果替代。
- 迁移审计证据：schema 3 必须从已复验的 schema 2 试点材料 manifest 精确派生全部输入，同时扫描业务前端静态资源和代表性真实 HAR，并绑定试点 `materialSetSha256` 以及通过 active 签名验证、实际授权全部迁移配置的来源策略 SHA-256；旧 WebPlus `7711` 与桌面回调 `45121` 均不得有静态或运行时证据，HTTP 业务来源必须全部获得该策略批准，且不能留有 critical 或 warning finding。配置文件、插件目录、服务、快捷键、前端资源和 HAR 的八类计数还必须达到项目策略批准的最低覆盖，避免用另一组较小或不同输入替代已移交材料。
- Windows 包证据：schema 4 必须验证 Authenticode、NSIS、实际启动事件，以及从指定上一生产版本升级并保留配置；证据绑定上一版本号、`release.json` 与已验签 `artifacts.json` 的 SHA-256，不能用任意更低版本或 CI 合成版本替代。它同时从实际安装目录记录插件信任库、来源策略和 x86/x64 插件宿主 SHA-256，最终判定要求来源策略与迁移审计及生产策略一致，信任库和宿主与真实硬件矩阵使用的输入逐字节一致。历史 MSI 字段仅为格式兼容保留，不参与新发布判定；旧 schema 包证据缺少这些身份，不能用于新决策。

三份证据必须指向策略指定的同一 Git 提交、全部为 clean source，并且不超过策略允许的年龄。schema 6 策略还绑定批准的试点材料集合、候选与上一生产版本、两者的 Windows 产物清单、上一版本发布元数据、来源策略，以及发布集合规范、确定性插件包集合、插件信任库和定稿黄金矩阵四个插件输入 SHA-256，并设置项目级迁移覆盖下限；它可以为项目确实不存在的旧资产类别显式填 `0`，但不能省略字段或用旧 schema 绕过确认。策略只能指定这些项目事实、目标提交、预期 SemVer、60 秒至 31 天的证据有效期，以及三类证据和最终审批各自预期的签名 `keyId`，不能关闭其他固化门禁。四个职责的 `keyId` 必须互不相同。

## 1. 准备策略

复制 [cutover-policy.example.json](cutover-policy.example.json)，把 `targetSourceRevision` 替换为待发布 clean commit 的完整小写 Git object ID，把 `expectedAppVersion` 替换为候选 Windows 包内 `release.json` 的版本，并填写已复验试点报告的 `materialSetSha256` 为 `expectedPilotMaterialSetSha256`。从试点材料中的上一生产 bundle 填写 `expectedPreviousAppVersion`、`expectedPreviousReleaseMetadataSha256` 和 `expectedPreviousWindowsArtifactManifestSha256`；上一版本必须低于候选版本，三个值都必须与 schema 4 Windows 证据逐项一致。再从批准候选包填写 `expectedWindowsArtifactManifestSha256` 与 `expectedOriginPolicySha256`；后者必须同时等于正式迁移证据和 Windows 包证据中的来源策略摘要。`expectedPluginReleaseSetSpecSha256`、`expectedPluginPackageSetSha256`、`expectedPluginTrustStoreSha256` 和 `expectedPluginMatrixSha256` 必须来自本次批准的发布集合及矩阵检查结果，不能照抄示例占位值。根据切换前冻结的旧资产清单填写 `migrationCoverageMinimums`；这些是最低覆盖而不是期望结果，某类资产确实不存在时显式填 `0` 并在审批记录中说明。最后填写实际负责三种验证环境及最终发布审批的四个不同签名 `keyId`。策略文件本身也会按原始字节计算 SHA-256 并写入最终决策。

## 2. 签署执行证据

每份证据生成后，由对应受控 QA 环境使用统一外部签名流程处理，三个 artifact kind 分别为 `plugin-matrix-evidence`、`migration-audit-evidence` 和 `windows-package-evidence`。例如：

```powershell
cargo run --locked -p ssdev-release-signing -- prepare `
  --kind plugin-matrix-evidence `
  --document D:\cutover-inputs\plugin-matrix-evidence.json `
  --key-id hospital-a-plugin-matrix-qa-2026 `
  --trust-store D:\cutover-inputs\evidence-trust.json `
  --request D:\cutover-output\plugin-matrix-evidence.request.json
```

签名密钥必须为 `active` 并显式具备 `cutover-evidence` 用途。KMS/HSM 返回签名后用 `finalize` 生成封套；三种证据使用不同域分隔 payload，不能相互替换。生产策略中的三个预期 `keyId` 应分别指向实际负责插件硬件、业务流程审计和 Windows 安装升级验收的环境密钥。

## 3. 汇总判定

```powershell
cargo run --locked -p ssdev-cutover-evidence -- decide `
  D:\cutover-inputs\production-policy.json `
  D:\cutover-inputs\evidence-trust.json `
  D:\cutover-inputs\plugin-matrix-evidence.json `
  D:\cutover-inputs\plugin-matrix-evidence.sig.json `
  D:\cutover-inputs\migration-evidence.json `
  D:\cutover-inputs\migration-evidence.sig.json `
  D:\cutover-inputs\windows-package-evidence.json `
  D:\cutover-inputs\windows-package-evidence.sig.json `
  D:\cutover-output\cutover-decision.json
```

输入必须是有大小上限的普通文件，决策输出的父目录必须预先存在且目标不能已存在。工具先按策略指定 `keyId` 和 `cutover-evidence` 用途验证三个 active-key 封套，再在读取前后重新计算全部摘要，拒绝执行中变化。插件矩阵只接受 schema 2，迁移审计只接受 schema 3，Windows 包只接受 schema 4；对应旧证据必须用已复验试点输入、指定上一生产 bundle 和实际候选包重新执行。`GO` 返回 0；`NO-GO` 仍以不覆盖方式写出排序后的稳定阻塞码，随后返回 3，便于 CI 阻断发布；输入损坏、签名/用途/keyId 不匹配、schema 不匹配或 I/O 失败返回 1。

常见阻塞码包括 dirty/source mismatch、证据过期或未来时间、试点材料集合不匹配、候选或上一生产 Windows 版本/产物清单/发布元数据不匹配、插件发布集合/信任库/矩阵不匹配、实机矩阵与安装包信任库或宿主不一致、迁移/安装/策略三方来源策略摘要不一致、HTTP 来源授权不完整、迁移资产计数低于策略、静态资源/HAR 未覆盖、旧本机 HTTP 仍被观察到、迁移 warning/critical 未清零，以及 Windows 签名、NSIS 安装、启动或升级未验证。

## 4. 独立审批签名

原始证据是测试执行器生成的事实记录，不等于审批。只有 `eligible: true` 的决策才能进入统一外部 Ed25519 签名流程：

```powershell
cargo run --locked -p ssdev-release-signing -- prepare `
  --kind cutover-decision `
  --document D:\cutover-output\cutover-decision.json `
  --key-id central-release-approval-2026 `
  --trust-store D:\cutover-inputs\release-trust.json `
  --request D:\cutover-output\cutover-decision.request.json
```

审批密钥必须为 `active`，显式声明独立的 `cutover-decision` 用途，并精确匹配策略写入决策的 `approvalSignerKeyId`；即使另一把 active key 也有相同用途，仍不能替代。插件、目录、来源策略、进程策略或 QA 证据密钥不能越权签发。KMS/HSM 返回签名后，使用 [统一发布文档签名](release-signing.md) 的 `finalize` 生成 detached 封套，再用 `verify --kind cutover-decision` 独立复验。签名域为 `SSDEV-CUTOVER-DECISION\0` 加决策原始字节 SHA-256，任何空白或字段变化都会使签名失效。

归档时必须一起保存策略、证据信任库、三份证据及其封套、迁移完整报告、决策、签名请求、审批系统审计 ID 和最终签名封套。验证方应按决策中的策略、信任库、三份证据和三个证据封套 SHA-256 找回全部原始输入，不能只保留签名后的摘要页。
