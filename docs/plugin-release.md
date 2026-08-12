# 旧 WebPlus 插件发布迁移

`ssdev-plugin-tool` 把旧插件目录转换为可审计、可重复的发布输入。它不会加载 DLL、注册 OCX、执行 EXE/BAT 或持有生产私钥。迁移先运行只读审计；处理完 `api.json`、`installRun` 和架构问题后，再进入这里的发布流程。

## 两阶段信任边界

发布被刻意拆成两个阶段：

1. `prepare` 在全新的暂存目录中复制普通文件，排除任意层级的旧 `license.dat`，重新生成规范化 `plugin.json`，校验新宿主清单、入口文件、显式依赖和 PE 架构，然后输出待签名字节。
2. 组织的 KMS/HSM 或受控 CI 对待签名字节执行 Ed25519 签名。`finalize` 只从单行 Base64 文件读取签名，重新计算并逐字节核对待签材料，用公开信任库验证签名，再生成确定性 `.ssdev-plugin`。

私钥不应传给本工具，也不能通过命令行参数、环境变量、源码或客户端安装包注入。签名请求包含文件相对路径、SHA-256 和待签字节，应按发布材料管理；它不包含文件内容。

## 1. 准备发布目录

所有输出都必须是尚不存在的新路径，并位于旧插件目录之外：

```powershell
cargo run --locked -p ssdev-plugin-tool -- prepare `
  --source C:\secure-migration\legacy\reader `
  --staging C:\secure-release\reader-2.3.1-stage `
  --request C:\secure-release\reader-2.3.1-signing-request.json `
  --matrix-template C:\secure-release\reader-2.3.1-matrix.json `
  --plugin-id reader-plugin `
  --version 2.3.1 `
  --display-name "读卡器插件" `
  --key-id production-2026-01 `
  --trust-store C:\secure-build-inputs\plugin-trust.json
```

准备阶段先确认指定 `keyId` 在信任库中具有 `plugin` 用途且状态为 `active`，避免 KMS/HSM 为已退役或吊销的键产生无效签名；随后会硬拒绝以下情况：

- 符号链接、Windows 不可移植路径、忽略大小写后的重复路径；
- 超过 4,096 个文件或 512 MiB；
- 非 SemVer 版本、无调用方法的服务、缺失入口或显式依赖；
- DLL/EXE 的 PE 位数与 `architecture` 不一致；
- 仍声明非空 `installRun` 的旧插件。

COM/OCX 的 ProgID 和真实注册状态无法在离线准备阶段验证，必须进入 Windows 候选宿主预检和真实黄金矩阵。

准备成功会生成：

- 暂存插件目录：包含规范化 `plugin.json`，但没有签名封套；
- 签名请求：显式记录 `pluginId`、`version` 和 `keyId`；`payloadBase64` 是 KMS/HSM 要签名的原始字节，`payloadSha256` 用于发布审批和审计；
- 黄金矩阵草稿：从每个 service/method 自动生成参数占位符。

黄金矩阵默认带有 `"draft": true`。运行器会在启动 controller 或接触硬件之前拒绝草稿；只有替换所有脱敏输入/预期响应并显式改为 `false` 后才会执行。暂不验证的用例可设置 `"enabled": false`，但正式切换时仍须覆盖全部生产能力。

## 2. 外部签名

签名系统 Base64 解码 `payloadBase64`，对得到的原始字节执行 Ed25519 签名，并把 64 字节签名的 Base64 文本写入一个只含单行值的文件。例如文件形式为：

```text
<base64-ed25519-signature>
```

不要对 `payloadBase64` 文本本身签名，也不要签名 JSON 文件的文本字节。审批系统应同时记录 `pluginId`、`version`、`keyId` 和 `payloadSha256`。

## 3. 导入签名并封包

```powershell
cargo run --locked -p ssdev-plugin-tool -- finalize `
  --staging C:\secure-release\reader-2.3.1-stage `
  --request C:\secure-release\reader-2.3.1-signing-request.json `
  --signature C:\secure-signing-output\reader-2.3.1.sig.base64 `
  --trust-store C:\secure-build-inputs\plugin-trust.json `
  --package C:\secure-release\reader-plugin-2.3.1.ssdev-plugin
```

`finalize` 会在导入签名前确认暂存目录与原签名请求完全一致。它只接受信任库中授权给 `plugin` 用途且状态为 `active` 的公钥；`retired` 会阻止官方工具制作新包但为兼容仍被运行时接受，`revoked` 密钥完全失败。写入签名后工具再次对完整目录验签。ZIP 使用固定的 1980-01-01 时间、固定权限、按路径排序和 Stored 压缩；相同输入会产生逐字节相同的包，便于制品摘要、复核和跨流水线复现。工具从不覆盖已有包。

封包完成后还会使用与桌面安装器相同的安全解包与验签路径重新读取产物。也可以独立检查收到的包：

```powershell
cargo run --locked -p ssdev-plugin-tool -- verify `
  --package C:\secure-release\reader-plugin-2.3.1.ssdev-plugin `
  --trust-store C:\secure-build-inputs\plugin-trust.json
```

`finalize` 和 `verify` 的 JSON 结果都会给出 `packageSha256`；`finalize` 还会回显签名审批使用的 `payloadSha256`。制品库应以这两个摘要把签名请求、审批记录和最终安装包关联起来。

多个已签名包进入插件仓库时，不要手工维护版本、大小和摘要。使用 [签名插件仓库协议](plugin-repository.md) 中的 `ssdev-plugin-tool catalog` 从这些包生成确定性目录，再通过统一发布签名工具签目录。

## 4. 实机门禁

确定性封包只证明身份、完整性、清单和离线架构一致，不证明厂商 ABI 或硬件副作用正确。把验证后的插件安装到受控插件根目录，完成矩阵中的脱敏输入/响应，然后运行：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/test-plugin-matrix.ps1 `
  -PluginRoot C:\secure-test-inputs\plugins `
  -TrustStore C:\secure-build-inputs\plugin-trust.json `
  -Matrix C:\secure-release\reader-2.3.1-matrix.json `
  -EvidenceOutput C:\secure-release\reader-2.3.1-evidence.json `
  -EvidenceEnvironment hospital-a-reader-lab
```

矩阵必须由启用用例覆盖插件集合声明的每个方法；alias 会归一到对应真实方法。工具只在全部用例通过后生成 schema 1 证据，并绑定源码提交、插件签名载荷集合、信任库、矩阵、x86/x64 宿主摘要及目标环境标签。任一输入在运行期间变化都会失败，已有证据文件不会被覆盖。

每个正式版本应归档签名请求、签名审批记录、`.ssdev-plugin` SHA-256、非草稿黄金矩阵、生成的机器证据和目标 Windows/硬件环境审批；生产 DLL、患者数据和私钥不进入本仓库。
