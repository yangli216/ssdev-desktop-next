# 真实项目试点材料预检

真实试点的第一步不是继续增加运行时能力，而是把另一名实施人员执行迁移、硬件矩阵、升级和恢复演练所需的材料收齐。`ssdev-pilot-readiness` 对一个独立材料目录做只读预检，并输出脱敏、不可覆盖的机器报告。

该报告只证明“声明的材料集合完整且在检查时可读取”，不证明 DLL/COM 可调用、HAR 覆盖充分、签名有效、安装包可升级或项目可以生产切换。报告固定包含 `downstreamValidationRequired: true`；正式结论仍由迁移审计、插件黄金矩阵、Windows 包验收和 Go/No-Go 证据给出。

## 1. 建立材料目录

复制 [试点材料清单示例](pilot-materials.example.json)，并把所有 `inputs` 写成材料根目录下的正斜杠相对路径。禁止绝对路径、`..`、反斜杠、符号链接和特殊文件。工具递归散列声明目录，但报告不会保存文件名、目录、项目标签或审批引用原文。

schema 2 manifest 还必须填写 `migrationAuditBindings`，明确正式迁移审计使用哪些配置、插件根目录、快捷键、业务前端、HAR，以及签名来源策略三件套。五类列表必须分别与 `legacy-config`、`production-native-assets`、`legacy-keymap`、`business-assets` 和 `business-hars` 的 `inputs` 精确相等；策略三件套必须与 `signed-origin-policy` 的三个输入精确相等。不能只交付一个更大的材料目录，再在正式审计时人工挑选较小或不同的样本。

十个类别必须提供真实输入，不能标记为不适用：

- `legacy-config`：当前使用的旧桌面配置样本；
- `production-native-assets`：生产 DLL、OCX、依赖、驱动安装材料或受控副本；
- `golden-cases`：覆盖公开方法的脱敏输入和期望输出草稿；
- `business-assets` 与 `business-hars`：实际业务前端构建产物和代表性账号/设备流程 HAR；
- `signed-origin-policy`：候选来源策略、旁签封套和发布信任库；
- `plugin-release-set`：批准发布集合规范及其确定性插件包目录；
- `organization-public-trust`：插件、策略、项目、应用更新、Authenticode 和三类 QA 证据所需的公钥、证书及流程说明，其中必须包含供 `prepare-policy` 精确选择的 evidence trust store。私钥、令牌和口令不得进入材料目录；工具会阻断常见私钥容器扩展名和 PEM 私钥标记，但这不是秘密扫描器，材料提供方仍需承担脱敏责任；
- `previous-windows-release`：上一正式版本的完整已验签 bundle 根目录，至少保留 `metadata/release.json`、`metadata/artifacts.json` 及其签名、NSIS 安装器和 updater 产物；不能只交一个安装器或从其他低版本临时补齐；
- `windows-hardware-plan`：x86/x64、COM/OCX、硬件/驱动、院内网络/证书、升级、回退和卸载的责任人及执行环境计划。

`legacy-keymap`、`legacy-processes` 和 `external-local-http-callers` 是条件类别。存在时提供输入；确认不存在时使用 `notApplicable`，同时填写只允许字母、数字、点、横线和下划线的审批引用。工具只在报告中保存该引用的 SHA-256，防止“不记得有没有”被当成零资产。

## 2. 执行预检

报告必须写到材料目录之外，且不会覆盖已有文件：

```powershell
cargo run --locked -p ssdev-pilot-readiness -- `
  create `
  D:\ssdev-pilot\materials `
  D:\ssdev-pilot\pilot-materials.json `
  D:\ssdev-pilot\reports\pilot-readiness.json
```

退出码 `0` 表示材料清单完整；`3` 表示报告已写出但仍有稳定阻断码；`1` 表示 manifest、路径或 I/O 本身无效。schema 2 报告会同时记录 `migrationAuditBindingsSha256`；材料内容、类别身份或审计角色变化都会改变总 `materialSetSha256`，后续移交应记录这个总摘要。

接收方不能只查看对方提供的摘要，应对收到的同一 manifest 和材料目录独立复验：

```powershell
cargo run --locked -p ssdev-pilot-readiness -- `
  verify `
  D:\ssdev-pilot\materials `
  D:\ssdev-pilot\pilot-materials.json `
  D:\ssdev-pilot\reports\pilot-readiness.json
```

`verify` 会先严格校验报告 schema、固定类别、排序阻断码和内部集合摘要，再重新扫描全部声明输入并逐字段比较；manifest、报告或任一材料在复验期间变化都会失败。完整报告复验成功返回 `0`；内容身份正确但报告本身记录为未齐全时仍返回 `3`，便于接收方确认“这是原报告”但继续阻断试点。报告必须位于材料目录之外。

预检通过后按顺序执行：

1. 把材料根目录、同一 manifest 和已复验报告三件套交给正式迁移审计；工具只从 `migrationAuditBindings` 派生输入和签名来源策略，并在审计完成后再次复验全部材料；
2. 对批准发布集合运行真实 x86/x64 插件黄金矩阵；
3. 使用上一正式版本和候选 NSIS 运行 Windows 升级、启动、回退与卸载验收；
4. 使用 `ssdev-cutover-evidence prepare-policy` 从同一试点三件套、候选 bundle、组织公开材料中的 QA 证据信任库和少量人工批准项自动生成生产策略，禁止手工复制材料、插件、版本或信任库摘要；
5. 对三份独立证据签名并运行生产 Go/No-Go。

材料报告不能代替以上任一步，也不应进入远程业务 WebView。
