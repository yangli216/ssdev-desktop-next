# 旧资产只读迁移审计

`ssdev-migration-audit` 用于在正式迁移前建立旧 Electron/WebPlus 资产清单。它不会自动“修复”或激活任何旧资产，因为任意进程路径、`installRun` 和 `eval(snippet)` 都必须经过人工归类和组织签名。

## 正式输入与输出

正式迁移评审不能重新手工挑选输入。它必须使用已经由接收方复验通过的试点材料三件套：

```powershell
cargo run --locked -p ssdev-migration-audit -- `
  --pilot-materials-root D:/ssdev-pilot/materials `
  --pilot-manifest D:/ssdev-pilot/pilot-materials.json `
  --pilot-report D:/ssdev-pilot/reports/pilot-readiness.json `
  --workspace C:/src/ssdev-desktop/next `
  --report-output D:/cutover-evidence/migration-report.json `
  --evidence-output D:/cutover-evidence/migration-evidence.json `
  --evidence-environment hospital-a-production-workflows
```

工具先严格复验 schema 2 试点报告、manifest 与全部材料，要求 `intakeComplete: true`，再从 manifest 的 `migrationAuditBindings` 精确派生五类审计输入和签名来源策略三件套。正式模式禁止同时提供任何手工 `--config`、`--plugins`、`--keymap`、`--browser-assets`、`--browser-har` 或策略参数；审计完成后还会再次复验材料、报告、源码和策略输入，期间发生变化即失败。正式报告与证据必须同时位于源码工作区和试点材料根目录之外，且只创建、不覆盖。

schema 4 完整报告绑定 `materialSetSha256` 和 `migrationAuditBindingsSha256`。schema 3 迁移证据继续绑定完整报告和来源策略 SHA-256，并新增同一个试点材料集合摘要。后续 schema 6 Go/No-Go 策略必须精确指定该材料集合，Windows 包 schema 4 继续绑定同一来源策略并锁定上一生产 bundle，因此不能用一套材料完成移交、再用另一套较小样本或其他低版本通过审计与升级。

## 探索性盘点

尚未建立正式试点移交时，可以重复指定五类手工输入，并把完整 schema 4 JSON 报告写到标准输出：

```bash
cargo run --locked -p ssdev-migration-audit -- \
  --config C:/migration/config.json \
  --plugins C:/web-plus/plugins \
  --keymap D:/HIS/file-sync/keymap.json \
  --browser-assets D:/HIS/business-web/dist \
  --browser-har D:/HIS/evidence/critical-workflows.har \
  --origin-policy D:/release-inputs/origin-policy.json \
  --origin-policy-envelope D:/release-inputs/origin-policy.sig.json \
  --release-trust-store D:/release-inputs/plugin-trust.json
```

- `--config`：旧 Electron 配置，盘点业务地址、环境数、旧进程条目数和 HTTP 来源数量；报告不复制具体业务地址。
- `--plugins`：旧 WebPlus 的 `plugins` 根目录，读取每个 `api.json`，检查服务入口、声明架构、PE 实际架构、`installRun`、版本元数据和签名封套。
- `--keymap`：旧 `keymap.json`，盘点启用状态和是否包含脚本。
- `--browser-assets`：业务前端源码、构建目录或单个文本资源，检查是否静态引用 WebPlus `7711`、旧桌面 `45121` 及其已知端点。
- `--browser-har`：Chrome/Edge 在真实业务流程中导出的 HAR。只读取请求 URL 做本地端点分类，不读取请求体、响应体、Cookie 或 Header。
- 来源策略三项：探索时可省略，或全部提供以提前验证候选策略覆盖；正式模式只能从已复验 manifest 派生。

探索报告可用于收集和修复问题，但因为没有正式输出、clean source 身份和已复验材料绑定，不能进入生产 Go/No-Go。只有当前签名策略完整覆盖的 HTTP 业务来源才记录为信息项；缺少、错签或覆盖不完整仍是阻塞项。报告不是可直接安装的插件包、进程策略或新配置。

## 安全边界

- 单个 JSON 输入最多 4 MiB。
- 单个 HAR 最多 64 MiB、100,000 个请求；浏览器文本资源单文件最多 4 MiB、总计最多 128 MiB 和 20,000 个文件。
- HAR 的 `harRequestsScanned` 只统计 `log.entries` 中带可解析绝对 `request.url` 的条目；缺少 URL、相对 URL 或损坏 URL 计入 `harRequestsSkipped`，并产生 `browser-har-scan-incomplete` warning。有效的 `data:` 等非网络绝对 URL 可以完整计数但不会被误判为 HTTP 依赖。
- 浏览器资源扫描不跟随符号链接，只读取常见 HTML、JavaScript、TypeScript、Vue、JSON 和 CSS 文本文件。
- 不调用 DLL、COM、OCX、EXE 或 BAT；PE 架构仅通过读取文件头判断。
- 不执行 `installRun`，不解释或执行快捷键脚本。
- 不在报告中复制旧进程路径或脚本正文。
- 不在报告中复制浏览器资源文件名、源码、请求 URL、查询参数、Cookie、Header、请求体或响应体；只输出输入根路径、能力分类和计数。HAR 本身仍可能包含敏感数据，应在受控设备采集和保存，并在审计后按组织规则销毁。
- 不修改任何输入文件或插件目录。

## 结果处理

- `legacy-arbitrary-processes`：逐项核对程序来源、固定参数和 SHA-256，再生成签名进程策略。
- `legacy-insecure-business-origin`：优先把业务站点迁移到 HTTPS；暂时无法升级时，必须由发布方在签名来源策略中逐项批准 HTTP 例外。
- `legacy-insecure-business-origin-authorized`：HTTP 来源已由本次候选签名策略覆盖，不再单独阻断；仍需保留策略摘要绑定并完成其他 HAR、插件和 Windows 门禁。
- `business-origin-policy-mismatch`：即使配置只使用 HTTPS，候选签名策略也没有完整覆盖其业务、导航或外链来源；修正策略或配置后重跑正式审计。
- `legacy-eval-shortcut`：只能人工映射为新客户端支持的声明式动作，不能复制脚本。
- `legacy-install-run`：拆除安装后自动执行；确有需要时移入受控部署步骤。
- `architecture-mismatch`：修正 `architecture`，再分别使用 x86/x64 宿主跑黄金矩阵。
- `plugin-manifest-incompatible`：先修复 `api.json`，通过新宿主解析后才能签名。
- `plugin-requires-signing`：修复审计阻塞项后，用 `ssdev-plugin-tool prepare` 生成版本元数据、外部签名请求和草稿黄金矩阵，再由 `finalize` 验签并制作确定性 `.ssdev-plugin` 包；不要人工拼清单。
- `legacy-browser-*-runtime-dependency`：HAR 已确认外部浏览器在运行时调用本地 HTTP。优先迁移调用方；无法同步切换时，才设计独立、默认关闭且有会话认证的兼容适配器。
- `legacy-browser-*-static-reference`：资源中仍有静态引用，但尚不能证明代码路径实际执行。先定位和迁移，再用 HAR 验证。
- `legacy-browser-*-not-observed`：当前样本未发现依赖，不代表依赖不存在；必须覆盖代表性账号、设备和关键流程后才能关闭兼容评审项。
- `browser-assets-not-supplied` / `browser-har-not-supplied`：静态资源和运行时 HAR 是互补证据，缺少任一类都会保留警告；只有其中一种输入时不能关闭 HTTP 兼容评审项。
- `browser-har-scan-incomplete`：至少一个 HAR 条目缺少可安全分类的绝对请求 URL；重新从 Chrome/Edge DevTools 导出完整 HAR。跳过项不会冒充已覆盖请求，warning 未清零时生产 Go/No-Go 必须保持 `NO-GO`。
