# 统一发布文档签名

`ssdev-release-signing` 为九类 detached Ed25519 发布制品提供同一条受控流水线：

| `--kind` | 信任用途 | 文档 |
| --- | --- | --- |
| `origin-policy` | `origin-policy` | `origin-policy.json` |
| `process-policy` | `process-policy` | `process-policy.json` |
| `plugin-catalog` | `plugin-catalog` | 插件仓库 `catalog.json` |
| `project-bundle` | `project-bundle` | 项目交付 `.ssdev-project` |
| `cutover-policy` | `cutover-decision` | 生产切换 `production-policy.json` |
| `cutover-decision` | `cutover-decision` | 生产切换 `cutover-decision.json` |
| `plugin-matrix-evidence` | `cutover-evidence` | 真实插件黄金矩阵证据 |
| `migration-audit-evidence` | `cutover-evidence` | 生产流程迁移审计证据 |
| `windows-package-evidence` | `cutover-evidence` | Windows 安装升级证据 |

工具不接收私钥。它只做文档语义校验、生成域分隔待签字节、导入外部签名、强制密钥用途隔离与生命周期状态并生成统一签名封套。生产私钥必须留在 KMS/HSM 或受控 CI。

进入任何签名步骤前可独立检查发布信任库：

```powershell
cargo run --locked -p ssdev-release-signing -- verify-trust-store `
  --trust-store C:\secure-build-inputs\plugin-trust.json `
  --required-purposes plugin,origin-policy,project-bundle
```

该入口使用运行时相同的严格 schema 解析，并要求列出的用途和信任库中其他已声明用途都至少有一把 `active` 密钥。Windows 构建与安装包验收直接复用它，不在 PowerShell 中复制状态判断。

## 1. 准备签名请求

以下以来源策略为例：

```powershell
cargo run --locked -p ssdev-release-signing -- prepare `
  --kind origin-policy `
  --document C:\secure-release\origin-policy.json `
  --key-id origin-policy-2026-01 `
  --trust-store C:\secure-build-inputs\plugin-trust.json `
  --request C:\secure-release\origin-policy.signing-request.json
```

`prepare` 会先确认指定 `keyId` 对当前用途为 `active`，再使用客户端相同的解析和约束验证文档，而不是让 KMS/HSM 为无效密钥或无效内容签名：

- 来源策略检查 schema 2、精确 origin/service/method、重复项、通配符和 HTTP 例外；
- 进程策略检查固定绝对路径、参数上限、SHA-256 格式、重复 ID 和条目上限；
- 插件目录检查 schema、SemVer、HTTPS URL、包大小/摘要、重复版本、结构化精确版本撤回，以及当前签发/过期时间和最长 31 天有效期。可安装条目不得与撤回身份重叠；目录本身应先由 `ssdev-plugin-tool catalog` 从已验签包和已审批撤回清单生成，避免人工录入包字段。
- 项目包先通过与客户端相同的受限 ZIP、配置、组件清单、大小和摘要校验，再对整个原始 `.ssdev-project` 文件建立独立域签名；审核摘要只公开创建版本、组件分类计数、包大小和 SHA-256。
- 生产策略检查严格 schema、目标提交、候选/上一版本、证据时效、全部项目输入摘要和四个互异职责 keyId；签名请求必须使用策略选定的最终审批 keyId 和策略已绑定的发布信任库。它与最终决策共享 `cutover-decision` 信任用途和审批职责，但使用独立 `SSDEV-CUTOVER-POLICY\0` 签名域。
- 切换决策检查严格 schema、源码提交、应用版本、策略/策略封套/两份信任库/三份证据/三个证据封套摘要和阻塞码一致性；只有 `eligible: true` 的 `GO` 决策可以进入签名请求，且请求、封套和独立验证的 keyId 都必须等于策略选定的 `approvalSignerKeyId`。`NO-GO` 决策只能归档，不能获准发布。
- 三类执行证据分别检查自身严格 schema、来源提交、执行环境、输入摘要、覆盖与结果一致性，并使用不同域分隔 payload；插件矩阵 schema 2 的审核摘要额外公开 `packageSetSha256`，把硬件结论绑定到批准的确定性包集合；迁移证据 schema 3 公开已复验试点材料集合、签名来源策略摘要以及发现/获准的 HTTP 来源计数；Windows 包 schema 4 公开最终产物清单、实际安装插件信任库、来源策略及 x86/x64 宿主 SHA-256，升级验收还公开上一版本号、发布元数据和产物清单摘要，使审批者能确认测试的是指定上一生产版本。它们共享 `cutover-evidence` 用途，但生产策略可为每类证据指定不同 `keyId` 以隔离 QA 职责。

请求文件明确记录 `artifactKind`、对应 `trustPurpose`、`keyId`、文档摘要、待签字节及其摘要，并给出不含敏感内容的审核摘要。来源策略摘要包含授权来源/服务/方法数量和 HTTP 例外状态；进程策略包含条目数；插件目录包含签发时间、过期时间和条目数；项目包包含创建版本、组件分类计数、包大小和摘要；执行证据包含源码提交与关键覆盖/结果计数；生产策略包含目标提交、候选/上一版本、证据时效和两份信任库摘要；切换决策包含源码提交、应用版本、判定时间和策略封套摘要。

项目包的发布审批必须把桌面端导出成功时显示的 SHA-256 与请求中的 `documentSha256` 逐字节核对。二者不同表示选错草稿或导出后文件发生变化，应废弃请求并从稳定项目包重新执行 `prepare`，不能只依据相同文件名继续签发。

所有输出必须是尚不存在的新文件，父目录必须预先存在且不能是符号链接。工具不会覆盖旧请求或封套。

## 2. 外部签名

签名服务 Base64 解码请求中的 `payloadBase64`，对得到的原始字节执行 Ed25519 签名，再把 64 字节签名编码为单行 Base64 文件。不要签 `payloadBase64` 文本，也不要直接签 JSON 文本。

审批记录至少保留：

- `artifactKind` 与 `trustPurpose`；
- `keyId`；
- `documentSha256` 与 `payloadSha256`；
- 请求中的审核摘要；
- 审批人、签名系统审计 ID 和发布时间窗。

## 3. 导入签名并复验

```powershell
cargo run --locked -p ssdev-release-signing -- finalize `
  --kind origin-policy `
  --document C:\secure-release\origin-policy.json `
  --request C:\secure-release\origin-policy.signing-request.json `
  --signature C:\secure-signing-output\origin-policy.sig.base64 `
  --trust-store C:\secure-build-inputs\plugin-trust.json `
  --envelope C:\secure-release\origin-policy.sig.json
```

`finalize` 会重新解析当前文档并逐字段核对原请求。即使文档改动后仍然语义合法，也会因为摘要和待签字节不一致而在写封套前失败。随后它确认签名是合法 Ed25519 长度，并只允许信任库中具备该文档精确用途且状态为 `active` 的公钥；`retired` 会停止官方新签发但为兼容仍被运行时接受，`revoked` 密钥完全拒绝。插件密钥不能签来源策略，来源策略密钥也不能签插件目录。成功写入封套后会从磁盘再次完成一次语义和签名验证。

收到已有文档和封套时可独立验证：

```powershell
cargo run --locked -p ssdev-release-signing -- verify `
  --kind origin-policy `
  --document C:\secure-release\origin-policy.json `
  --envelope C:\secure-release\origin-policy.sig.json `
  --trust-store C:\secure-build-inputs\plugin-trust.json
```

`prepare`、`finalize` 和 `verify` 都输出机器可读 JSON，便于发布平台直接归档摘要与审核计数。`verify` 也要求当前发布使用 `active` 密钥；检查仍由 `retired` 键维持兼容的产物时，应使用对应运行时解析器或目标旧客户端，不能把它重新纳入新发布包。由于 detached Ed25519 签名没有可信签发时间，`retired` 不能抵御旧私钥泄露，泄露处置必须改为 `revoked`。正式 Windows 构建和安装包验收都使用 `verify` 检查注入的来源策略和可选进程策略。

## 仍需独立验证的边界

- 进程策略签名只证明策略语义和固定摘要未被篡改。目标机器仍会在每次启动前读取实际可执行文件并重新计算 SHA-256；部署门禁必须验证目标绝对路径、权限和工作目录。
- 插件目录签名只证明索引本身。客户端仍会校验 HTTPS、下载字节数/摘要、插件内部签名、候选宿主预检和真实硬件黄金矩阵。
- 项目包签名绑定整个交付容器和发布者身份，但不会把本地映射提升为通用组织插件。客户端仍会验证每个签名插件、当前来源授权、联合路由、目标架构宿主，并在确认前保持目标机器不变。
- 应用更新与 bundle 产物使用 Tauri Minisign/Authenticode，不复用本工具的 Ed25519 封套或密钥。
- `cutover-policy` 签名证明最终审批职责授权了某一精确生产策略；`prepare`、`finalize`、`verify` 和后续 `decide` 都要求实际发布信任库摘要等于策略绑定值，同名 keyId 的替代库无效。策略签名不代表三类 QA 执行已经通过。
- `cutover-decision` 签名证明同一独立用途的审批密钥批准了某一精确 `GO` 文档；`prepare`、`finalize` 和 `verify` 都要求实际发布信任库摘要等于 schema 3 决策中的 `approvalTrustStoreSha256`，同名 keyId 的替代库无效。验证方仍应保留并按文档中的 SHA-256 复核原始策略、策略封套与三份证据。
