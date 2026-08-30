# 生产切换证据与 Go/No-Go

生产切换不以人工汇总日志中的 `PASS` 为依据。`ssdev-cutover-evidence` 严格读取三份不可覆盖且经 QA 环境签名的机器证据，绑定证据、签名封套、信任库和策略的 SHA-256，并生成一个确定的 `GO` 或 `NO-GO` 决策：

- 真实插件黄金矩阵证据：必须由 Windows x64 运行器产生，覆盖全部已声明 service/method；schema 2 同时绑定批准的发布集合规范、确定性包集合、实际插件载荷、信任库、矩阵和 x86/x64 待交付宿主。现场插件根目录必须能逐包重建出发布集合中的相同 SHA-256，证据中的发布集合规范、包集合、信任库及矩阵摘要还必须精确匹配生产策略，不能用另一套较小或不同输入但内部自洽的结果替代。
- 迁移审计证据：schema 3 必须从已复验的 schema 2 试点材料 manifest 精确派生全部输入，同时扫描业务前端静态资源和代表性真实 HAR，并绑定试点 `materialSetSha256` 以及通过 active 签名验证、实际授权全部迁移配置的来源策略 SHA-256；旧 WebPlus `7711` 与桌面回调 `45121` 均不得有静态或运行时证据，HTTP 业务来源必须全部获得该策略批准，且不能留有 critical 或 warning finding。配置文件、插件目录、服务、快捷键、前端资源和 HAR 的八类计数还必须达到项目策略批准的最低覆盖，避免用另一组较小或不同输入替代已移交材料。
- Windows 包证据：schema 7 必须验证 Authenticode、NSIS、实际启动事件，以及从指定上一生产版本升级并保留配置字段与插件/本地映射数据根哨兵；随后必须卸载候选、回装同一输入 bundle 中的上一版本，再次验证上一版本签名、布局、启动和三类哨兵保留，最后完成卸载并复核数据根仍未被清理。`upgradeVerified`、`rollbackVerified` 与 `applicationStatePreservationVerified` 独立记录，任一缺失都会阻断生产切换；状态字段为真却没有 NSIS 和上一版本升级结果属于矛盾证据并直接拒绝。哨兵只证明客户端数据根保留，真实插件内容仍由签名发布集合和黄金矩阵验证。证据生成器在自身读取前后都按 `artifacts.json` 重新核对候选和上一版本完整 bundle，任何受清单覆盖文件的漂移都会在写出前失败。证据绑定上一版本号、`release.json` 与已验签 `artifacts.json` 的 SHA-256，不能用任意更低版本或 CI 合成版本替代。它同时从实际安装目录记录插件信任库、来源策略和 x86/x64 插件宿主 SHA-256，并可绑定一小时内由同版本 Windows 客户端导出的深度部署记录。该记录必须包含完整 13 项检查、真实业务页面到 Rust IPC 的 `pass` 和 `deliveryReady: true`。最终判定要求部署记录存在、来源策略与迁移审计及生产策略一致，信任库和宿主与真实硬件矩阵使用的输入逐字节一致。普通 CI 可以留下空部署记录以证明安装脚本本身，但这种包证据稳定返回 `windows-business-frontend-not-verified`，不能生产 GO。历史 MSI 字段仅为格式兼容保留，不参与新发布判定；旧 schema 包证据缺少独立状态保留结果，不能用于新决策。

三份证据必须指向策略指定的同一 Git 提交、全部为 clean source，并且不超过策略允许的年龄。schema 8 策略还绑定批准的试点材料集合、候选与上一生产版本、两者的 Windows 产物清单、上一版本发布元数据、来源策略、QA 证据信任库，以及发布集合规范、确定性插件包集合、插件发布/审批信任库和定稿黄金矩阵 SHA-256，并设置项目级迁移覆盖下限；它可以为项目确实不存在的旧资产类别显式填 `0`，但不能省略字段或用旧 schema 绕过确认。策略只能指定这些项目事实、目标提交、预期 SemVer、60 秒至 31 天的证据有效期、60 秒至 7 天的 GO 现场执行窗口，以及三类证据和最终审批各自预期的签名 `keyId`，不能关闭其他固化门禁。四个职责的 `keyId` 必须互不相同。生成后的策略还必须由最终审批职责签名；未签名策略不能进入判定。旧 schema 7 策略没有执行窗口，必须从已复验输入重新生成，不能继续签发新的 GO。

## 1. 准备策略

生产策略不再由人员逐项复制版本和摘要。先复制 [人工批准输入示例](cutover-policy-approval.example.json)，只填写证据有效期、GO 现场执行窗口、切换前冻结的八类迁移覆盖下限，以及负责三种验证环境和最终审批的四个不同签名 `keyId`。执行窗口建议设置为 24 小时，硬范围为 60 秒至 7 天；延期必须重新判定并审批，不能临时修改旧策略。覆盖下限是人工批准的最低覆盖；某类资产确实不存在时显式填 `0` 并在审批记录中说明。

然后从 clean 候选源码、已复验试点三件套、候选 Windows bundle、QA 证据信任库和人工批准输入生成不可覆盖的 schema 8 策略：

```powershell
cargo run --locked -p ssdev-cutover-evidence -- prepare-policy `
  C:\ssdev-source `
  D:\ssdev-pilot\materials `
  D:\ssdev-pilot\pilot-materials.json `
  D:\ssdev-pilot\reports\pilot-readiness.json `
  D:\candidate\bundle `
  D:\ssdev-pilot\materials\trust\public-material\evidence-trust.json `
  D:\cutover-inputs\policy-approval-inputs.json `
  D:\cutover-inputs\production-policy.json
```

工具会重新验证完整试点材料集合，从固定类别中确定发布集合规范、唯一插件包目录、唯一黄金矩阵和上一生产 bundle；QA 证据信任库必须来自 `organization-public-trust` 类别。候选与上一 bundle 的 `artifacts.json` 必须逐文件匹配，候选 `release.json` 必须匹配当前 clean 源码，上一版本必须低于候选版本。来源策略必须使用试点发布信任库中的 active `origin-policy` 密钥有效签名，插件发布集合则必须在批准包目录边界内通过同一信任库和黄金矩阵检查；三个 QA keyId 必须在证据信任库中是 active `cutover-evidence` 密钥，最终审批 keyId 必须在发布信任库中是 active `cutover-decision` 密钥。目标提交、候选/上一版本、两份产物清单、上一版发布元数据、来源策略、试点材料、发布集合、包集合、两份信任库和矩阵摘要都由这些已验证输入自动写入，人工批准文件不能覆盖它们。

写入前工具会再次检查源码、manifest、报告、材料、两个 bundle 和批准文件没有漂移；输出不得位于源码、材料或任一 bundle 内，且不能覆盖现有文件。[完整策略示例](cutover-policy.example.json) 只用于说明最终 schema 和测试，不应在生产中手工填写摘要。

## 2. 签署生产策略

策略生成后，使用策略中已批准的最终审批 `keyId` 和同一发布信任库创建签名请求：

```powershell
cargo run --locked -p ssdev-release-signing -- prepare `
  --kind cutover-policy `
  --document D:\cutover-inputs\production-policy.json `
  --key-id central-release-approval-2026 `
  --trust-store D:\cutover-inputs\release-trust.json `
  --request D:\cutover-output\production-policy.request.json
```

KMS/HSM 返回签名后生成策略封套：

```powershell
cargo run --locked -p ssdev-release-signing -- finalize `
  --kind cutover-policy `
  --document D:\cutover-inputs\production-policy.json `
  --request D:\cutover-output\production-policy.request.json `
  --signature D:\secure-signing-output\production-policy.sig.base64 `
  --trust-store D:\cutover-inputs\release-trust.json `
  --envelope D:\cutover-output\production-policy.sig.json
```

工具要求签名 keyId 等于策略中的 `cutoverDecisionSignerKeyId`，并要求传入信任库原始字节 SHA-256 等于策略已绑定的插件/发布信任库；同名 keyId 的替代公钥库不能签发。签名域是 `SSDEV-CUTOVER-POLICY\0` 加策略原始字节 SHA-256，与最终 GO 的签名域不同，因此两个封套不能互换。该步骤复用现有最终审批职责，不新增第五个签名职责。

## 3. 签署执行证据

Windows 包 QA 在目标网络中先启动实际业务环境，等待首页显示业务页面“已连接”，再从“安全与诊断”导出深度检查 JSON。随后把该文件传给包验收：

```powershell
scripts/test-windows-package.ps1 `
  -BundleRoot D:\candidate\bundle `
  -PreviousBundleRoot D:\previous\bundle `
  -DeploymentCheckRecord D:\field-evidence\deployment-check.json `
  -EvidenceOutput D:\field-evidence\windows-package-evidence.json `
  -EvidenceEnvironment hospital-a-windows-qa `
  -ExpectedAppUpdatePublicKey D:\trust\app-update.pub `
  -RequireAuthenticode `
  -ExpectedSignerSubject "CN=Approved Publisher"
```

工具只接受 schema 1、`unsigned-local-record`、Windows、候选版本一致、13 个固定检查项齐全且 `business-frontend` 为 `pass` 的深度记录；记录必须在包证据生成前一小时内产生。它会在读取前后复算摘要并把摘要及生成时间写入待签名的 schema 7 包证据，原始记录仍应随 QA 归档保存。未传参数时脚本显式写入空绑定，适用于普通 CI，但最终判定不会把它当作现场验收。

三份证据生成后、提交 QA KMS/HSM 签名前，先执行只读预检：

```powershell
cargo run --locked -p ssdev-cutover-evidence -- precheck `
  D:\cutover-inputs\production-policy.json `
  D:\cutover-output\production-policy.sig.json `
  D:\cutover-inputs\release-trust.json `
  D:\cutover-inputs\evidence-trust.json `
  D:\cutover-inputs\plugin-matrix-evidence.json `
  D:\cutover-inputs\migration-evidence.json `
  D:\cutover-inputs\windows-package-evidence.json
```

`precheck` 先验签生产策略并确认最终审批信任根，再检查策略指定的三个 QA keyId 在绑定的证据信任库中仍可签发，随后加载三份未签证据并直接复用最终 `evaluate_production_cutover` 的全部时效、来源、材料、发布集合、来源策略、宿主、升级回退和业务页门禁。检查前后会复算策略、策略封套、两份信任库和三份证据；任一输入漂移返回 `1`。无阻断输出 `READY-FOR-EVIDENCE-SIGNING` 并返回 `0`；存在业务阻断时，按排序稳定的每个阻断码输出一条固定、脱敏的 `action`，随后返回 `3`。命令不写决策、签名请求或其他文件，也不会把未签证据变成可审批事实。

预检只是当前时点的返工保护，不预留证据有效期，也不授权跳过签名。预检后任一证据变化都需要重新执行；最终 `decide` 仍会逐份验证策略和三个证据封套、签名 keyId、用途、信任库原始摘要和全部输入前后身份，并再次运行同一判定。只有最终带真实封套摘要的决策可以进入审批。

预检通过后，由对应受控 QA 环境使用统一外部签名流程处理，三个 artifact kind 分别为 `plugin-matrix-evidence`、`migration-audit-evidence` 和 `windows-package-evidence`。例如：

```powershell
cargo run --locked -p ssdev-release-signing -- prepare `
  --kind plugin-matrix-evidence `
  --document D:\cutover-inputs\plugin-matrix-evidence.json `
  --key-id hospital-a-plugin-matrix-qa-2026 `
  --trust-store D:\cutover-inputs\evidence-trust.json `
  --request D:\cutover-output\plugin-matrix-evidence.request.json
```

签名密钥必须为 `active` 并显式具备 `cutover-evidence` 用途。KMS/HSM 返回签名后用 `finalize` 生成封套；三种证据使用不同域分隔 payload，不能相互替换。生产策略中的三个预期 `keyId` 应分别指向实际负责插件硬件、业务流程审计和 Windows 安装升级验收的环境密钥，且 `decide` 使用的证据信任库原始字节 SHA-256 必须与 schema 8 策略一致。同名 keyId 的替代公钥库只能产生 `evidence-trust-store-mismatch`，不能生成 `GO`。

## 4. 汇总判定

```powershell
cargo run --locked -p ssdev-cutover-evidence -- decide `
  D:\cutover-inputs\production-policy.json `
  D:\cutover-output\production-policy.sig.json `
  D:\cutover-inputs\release-trust.json `
  D:\cutover-inputs\evidence-trust.json `
  D:\cutover-inputs\plugin-matrix-evidence.json `
  D:\cutover-inputs\plugin-matrix-evidence.sig.json `
  D:\cutover-inputs\migration-evidence.json `
  D:\cutover-inputs\migration-evidence.sig.json `
  D:\cutover-inputs\windows-package-evidence.json `
  D:\cutover-inputs\windows-package-evidence.sig.json `
  D:\cutover-output\cutover-decision.json
```

输入必须是有大小上限的普通文件，决策输出的父目录必须预先存在且目标不能已存在。工具先使用获准发布信任库验证策略的 `cutover-policy` 封套、keyId、用途和独立签名域，再按策略指定 `keyId` 和 `cutover-evidence` 用途验证三个 active-key 证据封套；所有策略、封套、信任库和证据都在读取前后重新计算摘要，执行中变化直接拒绝。插件矩阵只接受 schema 2，迁移审计只接受 schema 3，Windows 包只接受 schema 7；对应旧证据必须用已复验试点输入、指定上一生产 bundle 和实际候选包重新执行。schema 3 决策记录策略、策略封套、实际 QA 证据信任库和实际最终审批信任库摘要；旧 schema 2 GO 缺少策略授权身份，不能继续签发。`GO` 返回 0；`NO-GO` 仍以不覆盖方式写出排序后的稳定阻塞码，并为每项输出与 `precheck` 相同的固定处理动作，随后返回 3，便于现场修正和 CI 阻断发布。当前 schema 的决策只接受已有处理动作的阻断码，新增门禁若遗漏操作指引会失败关闭；输入损坏、签名/用途/keyId 不匹配、schema 不匹配或 I/O 失败返回 1。

常见阻塞码包括 dirty/source mismatch、证据过期或未来时间、试点材料集合不匹配、候选或上一生产 Windows 版本/产物清单/发布元数据不匹配、插件发布集合/信任库/矩阵不匹配、实机矩阵与安装包信任库或宿主不一致、迁移/安装/策略三方来源策略摘要不一致、HTTP 来源授权不完整、迁移资产计数低于策略、静态资源/HAR 未覆盖、旧本机 HTTP 仍被观察到、迁移 warning/critical 未清零，以及 Windows 签名、NSIS 安装、启动、升级、上一版本回装启动或应用状态保留未验证。`windows-rollback-not-verified` 不能由已有升级结果替代；`windows-application-state-preservation-not-verified` 也不能由回装启动替代，必须重新执行完整回退和三类哨兵复核并生成 schema 7 包证据。

`windows-business-frontend-not-verified` 表示 Windows QA 证据没有绑定合格的深度部署记录。它不能通过签名一个空字段消除；必须在目标网络重新打开实际业务页面、确认到达 Rust IPC、导出深度记录并重新生成/签署 Windows 包证据。

## 5. 独立审批签名

原始证据是测试执行器生成的事实记录，不等于审批。只有 `eligible: true` 的决策才能进入统一外部 Ed25519 签名流程：

```powershell
cargo run --locked -p ssdev-release-signing -- prepare `
  --kind cutover-decision `
  --document D:\cutover-output\cutover-decision.json `
  --key-id central-release-approval-2026 `
  --trust-store D:\cutover-inputs\release-trust.json `
  --request D:\cutover-output\cutover-decision.request.json
```

审批密钥必须为 `active`，显式声明独立的 `cutover-decision` 用途，并精确匹配策略写入决策的 `approvalSignerKeyId`；`prepare`、`finalize` 和 `verify` 还会把传入发布信任库的原始字节 SHA-256 与 schema 3 决策中的 `approvalTrustStoreSha256` 比较。即使替代库包含同名 active keyId，也不能签发或复验这份 GO。插件、目录、来源策略、进程策略或 QA 证据密钥不能越权签发。KMS/HSM 返回签名后，使用 [统一发布文档签名](release-signing.md) 的 `finalize` 生成 detached 封套；签名站可以先用 `verify --kind cutover-decision` 单独复验。签名域为 `SSDEV-CUTOVER-DECISION\0` 加决策原始字节 SHA-256，任何空白或字段变化都会使签名失效。

归档接收方应对完整输入执行一次只读复验，而不是手工逐个比较摘要：

```powershell
cargo run --locked -p ssdev-cutover-evidence -- verify-go `
  D:\cutover-output\cutover-decision.json `
  D:\cutover-output\cutover-decision.sig.json `
  D:\cutover-inputs\production-policy.json `
  D:\cutover-output\production-policy.sig.json `
  D:\cutover-inputs\release-trust.json `
  D:\cutover-inputs\evidence-trust.json `
  D:\cutover-inputs\plugin-matrix-evidence.json `
  D:\cutover-inputs\plugin-matrix-evidence.sig.json `
  D:\cutover-inputs\migration-evidence.json `
  D:\cutover-inputs\migration-evidence.sig.json `
  D:\cutover-inputs\windows-package-evidence.json `
  D:\cutover-inputs\windows-package-evidence.sig.json
```

`verify-go` 只接受可签发的 `eligible: true` schema 3 决策。它先验证最终审批封套、策略封套和三个 QA 封套的用途、keyId、公钥及信任库原始身份，再加载三份证据；十二个输入全部在验证前后复算 SHA-256。最后使用决策记录的 `evaluatedAtUnixSeconds` 重跑同一个生产判定器，要求策略、封套、两份信任库、证据、证据封套、版本、阻断集合和所有摘要逐字段重现原决策。这里使用获批决策时点是为了验证“当时签发的 GO 是否真实可重现”，不会把日后正常归档复验误判为证据过期；它不重新授权一次新的生产切换。任一替换、缺失、漂移或重放差异返回 `1`，完整通过输出 `VERIFIED-GO` 并返回 `0`，不写新文件。

真正开始现场部署前，把上一个命令中的操作名替换为 `check-current-go`，传入完全相同的十二个归档文件，并在末尾追加由组织当前受保护信任分发渠道取得的审批信任库、QA 证据信任库和现场准备实际安装的候选 Windows bundle 根目录：

```powershell
  D:\protected-current-trust\release-trust.json `
  D:\protected-current-trust\evidence-trust.json `
  D:\protected-release\candidate-bundle
```

这两份现行信任库不是归档副本，也不绑定进历史决策；它们是部署系统必须独立保护和提供的当前信任锚。命令先执行完整历史复验，再用现行审批库复验策略与 GO、用现行 QA 库复验三个证据封套，并对十二个归档输入及两份现行信任库执行前后摘要复核。现行库中的 `active` 或 `retired` 签名键可以验证已有签名，`revoked`、缺失或同 keyId 替换公钥会输出稳定 `cutover-current-trust-rejected` 并返回 `3`，从而让审批后发生的紧急吊销立即停止部署。不能从 GO 归档目录复制旧信任库冒充现行组织状态。

候选 bundle 必须是构建产出的完整根目录，不能只传 NSIS 安装器。命令在现行授权检查前后分别按 `metadata/artifacts.json` 对全部受清单覆盖文件重新计算大小和 SHA-256，并要求 `release.json`、产物清单、应用版本和源码提交与签名 Windows 证据及 GO 精确一致。完整但属于另一构建的 bundle、单独替换的安装器、缺失/额外文件或损坏清单都会输出稳定 `cutover-candidate-bundle-mismatch` 并返回 `3`；验证期间发生变化返回 `1`。`CURRENT-GO` 会输出获准产物清单摘要，实施人员必须立即从同一个受保护根目录启动其中的 NSIS，不能在检查后复制、重新打包或换用同名文件。命令仍不自动安装，因此其授权不会覆盖检查结束后的人工替换。

现行信任和候选 bundle 通过后，命令再以现场系统当前时间检查决策的 `evaluatedAtUnixSeconds` 是否位于签名策略的 `maximumCutoverDecisionAgeSeconds` 内。完整通过输出 `CURRENT-GO` 并返回 `0`；GO 超过窗口或比当前时间提前超过五分钟时，输出稳定 `cutover-decision-stale` 或 `cutover-decision-future-timestamp` 及固定处理动作并返回 `3`。归档签名、文件、schema、I/O 或验证期间输入漂移返回 `1`。它不写文件、不延长窗口且不启动安装；发生吊销、材料变更或需要延期时，必须解决信任事件并用当前证据重新执行 `decide`，取得新的最终审批签名。

归档时必须一起保存策略及其签名封套、发布和证据信任库、三份证据及其封套、迁移完整报告、决策、签名请求、审批系统审计 ID 和最终签名封套。验证方必须保留并传入决策绑定的全部原始字节，不能只保留签名后的摘要页。
