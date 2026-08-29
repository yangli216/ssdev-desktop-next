# 旧 WebPlus 插件发布迁移

`ssdev-plugin-tool` 把旧插件目录转换为可审计、可重复的发布输入。它不会加载 DLL、注册 OCX、执行 EXE/BAT 或持有生产私钥。迁移先运行只读审计；处理完 `api.json`、`installRun` 和架构问题后，再进入这里的发布流程。

控制台本地映射已经完成现场验证时，可在“原生映射”卡片点击“发布源”，选择一个受控父目录。桌面端会创建新的 `<pluginId>-release-source`，仅包含规范化 `api.json` 以及清单实际引用的组件和依赖；另在目录外生成 `<pluginId>-matrix-seed.json` 草稿，复用已保存的脱敏现场用例并为未覆盖方法补占位用例。待签名目录不会包含 `local-mapping.json`、合成调试用例、本地 `plugin.json`、旧签名或未引用文件。正式版本号、发布名称和签名 keyId 仍由发布流程明确提供，不能从现场配置静默继承。

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
  --desktop-version-requirement ">=0.1.0, <0.2.0" `
  --display-name "读卡器插件" `
  --key-id production-2026-01 `
  --trust-store C:\secure-build-inputs\plugin-trust.json
```

若来源是工作台导出，则把 `--source` 改为例如 `C:\secure-release-inputs\reader.local-release-source`，并追加 `--matrix-seed C:\secure-release-inputs\reader.local-matrix-seed.json`。`--matrix-seed` 是可选参数，仅适用于工作台导出的外部种子；其他旧插件可省略，由工具自动生成全方法占位草稿。发布工具会要求种子位于待签名源目录之外、使用 schema 1、保持 `draft: true`、只引用清单声明的输入与路由，并由启用用例覆盖全部方法。本地子集回归不能替代正式插件的完整 `ResData` 精确矩阵。

`--desktop-version-requirement` 是该插件经过真实矩阵验证的 SSDEV Desktop SemVer 范围。当前 `0.1.x` 客户端可使用 `>=0.1.0, <0.2.0`；跨越新的 Desktop 次版本前应重新执行兼容矩阵，不应无依据填写 `*`。

准备阶段先确认指定 `keyId` 在信任库中具有 `plugin` 用途且状态为 `active`，避免 KMS/HSM 为已退役或吊销的键产生无效签名；随后会硬拒绝以下情况：

- 符号链接、Windows 不可移植路径、忽略大小写后的重复路径；
- 超过 4,096 个文件或 512 MiB；
- 非 SemVer 版本、无效或超过 128 字符的 Desktop SemVer requirement、无调用方法的服务、缺失入口或显式依赖；
- DLL/EXE 的 PE 位数与 `architecture` 不一致；
- 超过 12 个机器字参数、浮点参数/返回、不受支持的输出缓冲区或调用约定等通用 DLL 适配器无法表达的静态 ABI；
- 仍声明非空 `installRun` 的旧插件。

COM/OCX 的 ProgID 和真实注册状态无法在离线准备阶段验证，必须进入 Windows 候选宿主预检和真实黄金矩阵。

准备成功会生成：

- 暂存插件目录：包含规范化 `plugin.json`，但没有签名封套；
- 签名请求：显式记录 `pluginId`、`version`、`desktopVersionRequirement` 和 `keyId`；`payloadBase64` 是 KMS/HSM 要签名的原始字节，`payloadSha256` 用于发布审批和审计；
- 黄金矩阵草稿：采用通过校验的外部种子，或从每个 service/method 自动生成参数占位符；准备报告会给出 `matrixSeeded`、`matrixCaseCount`、仍含保留占位符的 `matrixPlaceholderCaseCount` 和必须人工确认精确响应的 `matrixReviewRequiredCaseCount`。

黄金矩阵默认带有 `"draft": true`，并在 `plugins` 中固定本次 `pluginId` 与 SemVer 版本。自动生成或由工作台现场子集用例转换的条目还带有 `"reviewRequired": true`。运行器会在启动 controller 或接触硬件之前拒绝草稿；即使误把草稿改为 `false`，任何启用用例仍要求复核或存在生成器保留的输入/响应占位符也会失败关闭。只有补齐全部声明输入、把子集断言核对为完整精确响应、删除占位符、将每个已复核用例改为 `"reviewRequired": false`，并显式解除全局草稿后才会执行。暂不验证的用例可设置 `"enabled": false`，但正式切换时仍须由其他启用用例覆盖对应生产能力。

### 跨平台离线检查

矩阵定稿后先在任意开发平台运行语义检查，不需要启动 DLL、COM、插件宿主或真实硬件：

```powershell
cargo run --locked -p ssdev-plugin-tool -- matrix-check `
  --plugin-dir C:\secure-release\reader-2.3.1-stage `
  --matrix C:\secure-release\reader-2.3.1-matrix.json
```

`--plugin-dir` 用于检查一个包含规范化 `plugin.json` 的 `prepare` 暂存目录；多插件联合矩阵则改用 `--plugin-root C:\secure-test-inputs\plugins`，其直接子目录必须是各插件 ID。命令检查严格 schema、可选的插件身份/版本绑定、草稿/复核/占位符状态、全部用例路由、输入字段精确一致性、忽略 ASCII 大小写后的插件 ID 冲突、跨插件 `serviceId` 冲突和启用用例全方法覆盖，并输出插件、服务、方法、用例计数及 `identityBound`。旧矩阵可在缺少身份绑定时继续做语义和实机回归，但新的正式发布候选不能省略绑定。

这只是无需 Windows 的快速失败门禁：它会用共享规则拒绝通用适配器无法表达的静态 DLL ABI，但不能证明声明与厂商二进制真实签名一致，也不验证插件运行时签名状态或设备响应。正式 Windows 运行器会在验签插件后再次调用同一份规则，再启动 x86/x64 宿主，避免离线工具与实机规则漂移。

## 2. 外部签名

签名系统 Base64 解码 `payloadBase64`，对得到的原始字节执行 Ed25519 签名，并把 64 字节签名的 Base64 文本写入一个只含单行值的文件。例如文件形式为：

```text
<base64-ed25519-signature>
```

不要对 `payloadBase64` 文本本身签名，也不要签名 JSON 文件的文本字节。审批系统应同时记录 `pluginId`、`version`、`desktopVersionRequirement`、`keyId` 和 `payloadSha256`。

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

`finalize` 和 `verify` 的 JSON 结果都会给出 `desktopVersionRequirement` 与 `packageSha256`；`finalize` 还会回显签名审批使用的 `payloadSha256`。制品库应以这些字段把签名请求、审批记录、兼容范围和最终安装包关联起来。

正式发布候选还必须把定稿黄金矩阵与实际签名包联合检查，不能只分别验证暂存目录和包：

```powershell
cargo run --locked -p ssdev-plugin-tool -- release-check `
  --package C:\secure-release\reader-plugin-2.3.1.ssdev-plugin `
  --trust-store C:\secure-build-inputs\plugin-trust.json `
  --matrix C:\secure-release\reader-2.3.1-matrix.json
```

`release-check` 使用桌面安装路径同源的安全解包和运行时验签，再额外要求签名键仍为 `active`，要求矩阵 `plugins` 中的 `pluginId + version` 与包内元数据精确一致，并直接用包内清单执行完整矩阵语义检查。它在检查前后复核包、信任库和矩阵未变化，成功报告同时给出三份 SHA-256、插件身份、版本、覆盖方法数和用例数。发布审批应归档该报告；结构相同但属于旧版本的矩阵也无法通过。该命令仍不会安装插件、加载原生组件或接触硬件。

一个项目需要多个插件共同覆盖联合矩阵时，创建 [plugin-release-set.example.json](plugin-release-set.example.json) 形式的规范。`packages` 包含 1 到 256 个相对于规范文件的 `.ssdev-plugin` 路径，也可使用绝对路径，然后一次检查整个候选集合：

```powershell
cargo run --locked -p ssdev-plugin-tool -- release-set-check `
  --spec C:\secure-release\hospital-a-release-set.json `
  --trust-store C:\secure-build-inputs\plugin-trust.json `
  --matrix C:\secure-release\hospital-a-matrix.json
```

集合门禁逐包安全解压、验签并要求 active 发布键，拒绝重复包、忽略大小写后重复插件 ID、跨插件 `serviceId` 冲突、矩阵目标缺失/多余/错版以及任一方法未覆盖。成功报告按插件 ID 稳定排序，给出每个包的身份、版本、keyId 和摘要，以及域分隔的 `packageSetSha256`、规范/信任库/矩阵摘要和联合覆盖计数；规范、任一包、信任库或矩阵在检查过程中变化都会失败。这样多插件项目不再依赖人工拼接多份单包报告。

离线审批通过后，不要手工把多个包逐个解压或复制到验收目录。用同一规范一次生成全新的插件根目录：

```powershell
cargo run --locked -p ssdev-plugin-tool -- release-set-materialize `
  --spec C:\secure-release\hospital-a-release-set.json `
  --trust-store C:\secure-build-inputs\plugin-trust.json `
  --matrix C:\secure-release\hospital-a-matrix.json `
  --plugin-root C:\secure-test-inputs\hospital-a-plugins
```

`plugin-root` 的父目录必须已存在，目标自身必须不存在。工具先完成整个发布集合门禁，再通过桌面安装器同源的安全解包与事务激活路径逐包安装；全部安装后把每个插件重新确定性封包，逐项核对身份、版本、active keyId 和包 SHA-256，并再次检查规范、信任库和矩阵。普通失败会删除新建的半成品目录，已有路径永不覆盖；若进程崩溃或断电，目录会保留 `.release-set-materializing.json`，任何 `matrix-check` 或正式实机运行都会失败关闭。检查原因后删除该候选目录并重新物化，不能手工移除标记后继续使用。

多个已签名包进入插件仓库时，不要手工维护版本、大小和摘要。使用 [签名插件仓库协议](plugin-repository.md) 中的 `ssdev-plugin-tool catalog` 从这些包生成确定性目录，再通过统一发布签名工具签目录。

## 4. 实机门禁

确定性封包只证明身份、完整性、清单和离线架构一致，不证明厂商 ABI 或硬件副作用正确。把验证后的插件安装到受控插件根目录，完成矩阵中的脱敏输入/响应，然后运行：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/test-plugin-matrix.ps1 `
  -PluginRoot C:\secure-test-inputs\plugins `
  -ReleaseSetSpec C:\secure-release\hospital-a-release-set.json `
  -TrustStore C:\secure-build-inputs\plugin-trust.json `
  -Matrix C:\secure-release\reader-2.3.1-matrix.json `
  -EvidenceOutput C:\secure-release\reader-2.3.1-evidence.json `
  -EvidenceEnvironment hospital-a-reader-lab
```

`PluginRoot` 应直接使用上一节 `release-set-materialize` 生成的目录，并且必须是 `ReleaseSetSpec` 所批准包的精确安装结果，不能是另行复制或重新签名的暂存目录。运行器会逐项校验身份、版本、active 签名 keyId，并把根目录中的每个插件重新确定性封包；只有重建包 SHA-256 与发布集合完全相同才会接触硬件。因此，多包离线审批、现场安装内容和最终实机结论属于同一条可追溯链路。

矩阵必须由启用用例覆盖插件集合声明的每个方法；alias 会归一到对应真实方法。每个启用用例的输入字段必须与该方法声明的非 `$` 输入完全一致，未知字段、缺失字段和生成器保留占位符都会在宿主启动前失败。工具只在全部用例通过后生成 schema 2 证据，并绑定源码提交、发布集合规范与包集合、插件签名载荷集合、信任库、矩阵、x86/x64 宿主摘要及目标环境标签。任一输入在运行期间变化都会失败，已有证据文件不会被覆盖；旧 schema 1 插件矩阵证据不能人工升级，必须用批准的发布集合重新执行。

每个正式版本应归档签名请求、签名审批记录、`.ssdev-plugin` SHA-256、非草稿黄金矩阵、生成的机器证据和目标 Windows/硬件环境审批；生产 DLL、患者数据和私钥不进入本仓库。
