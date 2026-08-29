# ssdev-desktop next

`next` 是 ssdev-desktop 的长期替代实现，采用 Tauri 2、Rust 和 Vue 3。

当前目录与旧 Electron 产品隔离，直到迁移门槛全部通过后才切换正式入口。新架构不以 localhost HTTP 作为 Tauri 内部通信方式：

```text
business webview -> narrow Tauri command -> Rust controller
  -> framed process IPC -> x86/x64 plugin host -> DLL/COM/EXE
```

## 不可妥协的设计约束

- Tauri 主进程永不加载第三方 DLL 或 OCX。
- 32 位和 64 位插件分别运行在对应架构的插件宿主中。
- 远程业务页面只能获得业务级命令，不能获得 Shell 或文件系统通用权限。
- 业务窗口创建后会自动验证真实页面已到达 Rust IPC；30 秒超时提供原生提示、部署门禁和脱敏诊断，SSO 跳转不会被误判。
- 新实现保持 `serviceId`、`method`、`parameters`、`ResCode`、`ResData` 语义兼容。
- 所有跨进程请求必须具有长度上限、超时、请求 ID 和确定的失败响应。
- 业务 Web Bridge 与 controller/plugin-host 私有 IPC 使用独立版本域，任一侧演进都不强迫另一侧同步升级。
- 每个签名插件必须声明经过验证的 Desktop SemVer 范围；安装、项目导入和应用更新都按该范围失败关闭。
- controller 最多接受 8 个在途插件调用；容量饱和时在进入原生宿主前快速拒绝，不建立无界等待队列。
- localhost HTTP 仅作为可关闭的旧浏览器兼容网关，不是新架构内部依赖。

每个提交由 `.github/workflows/ci.yml` 执行 Linux 质量门禁、Windows x86/x64 原生回归；Windows 门禁还会实际生成并构建两种架构的最小 DLL 插件脚手架，用公开 RFC 8032 测试向量制作两个仅供 CI 的签名包，经过正式发布集合检查和物化后，由生产黄金矩阵包装器分别拉起已经构建的 Release x86/x64 宿主完成调用并核对 schema 2 证据。随后分别为 x64 与 x86 桌面构建 `0.0.1` 合成旧版本和当前候选版本，对离线 NSIS 执行原位升级、配置保留、布局/架构检查、真实启动和卸载；再额外构建在线轻量 NSIS 并执行安装、启动和卸载冒烟。Linux DEB/AppImage 和 macOS DMG 仅在手动选择 `all` 平台时构建。CI 测试签名密钥、临时更新密钥均非生产信任材料，平台代码签名也被明确跳过，产物不能分发；生产硬件矩阵仍必须输入候选安装包构建留下的已签名宿主原文件，CI Release 宿主不能替代该身份门禁。平台支持边界见 [docs/platform-support.md](docs/platform-support.md)。

架构决策和迁移门槛见 [docs/adr/0001-target-architecture.md](docs/adr/0001-target-architecture.md)。

产品定位、迭代优先级和明确不投入的方向见 [docs/product-direction.md](docs/product-direction.md)。新能力进入核心运行时前应先符合其中的工作选择规则。

真实项目开始前可使用 [试点材料预检](docs/pilot-readiness.md) 收齐生产组件、黄金用例、业务 HAR、签名公钥材料、上一 Windows 安装包和实机计划。schema 2 manifest 还会把正式迁移审计的配置、插件、HAR 和签名策略角色精确绑定到这些材料；预检报告只输出摘要与稳定缺项，不复制路径或材料内容，也不替代后续迁移审计、硬件矩阵和 Go/No-Go。

业务页面从 localhost HTTP 切换到窄桥接接口的方式见 [docs/web-bridge-migration.md](docs/web-bridge-migration.md)。
业务前端应通过 [packages/web-bridge](packages/web-bridge/README.md) 的类型化协议适配层接入，不直接依赖 Tauri 内部 API。SDK 会运行时校验系统声明并提供稳定错误分类；当前能力 schema 严格验证，未来未知 schema 保留但不会被误判为已经支持。主分支 CI 还会生成并自检固定 `.tgz + 摘要清单` 的平台无关 SDK 制品，并在离线临时消费者中验证安装、ESM 运行和 TypeScript 类型，业务项目不再需要从源码目录人工打包。
打印、写卡等非幂等调用的持久操作 ID、防重放和崩溃后对账语义见 [docs/tracked-invocations.md](docs/tracked-invocations.md)。
插件完整性、公钥信任链以及可崩溃恢复的安装、更新和卸载生命周期见 [docs/plugin-signing.md](docs/plugin-signing.md)。
无需重新编译客户端的 DLL/COM 可视化配置、热加载、现场调试和本地映射包迁移见 [docs/local-mapping-studio.md](docs/local-mapping-studio.md)。未签名映射包先进行不加载原生代码的结构预检，用户确认信任后才复核状态、启动隔离宿主并原子热加载。
从 Rust 封装 Win32 API、x86/x64 映射、网页调用到外部签名封包和更新发布的完整示例见 [examples/windows-system-plugin](examples/windows-system-plugin/README.md)。
旧插件从安全暂存、外部签名、确定性封包到黄金矩阵草稿的发布流程见 [docs/plugin-release.md](docs/plugin-release.md)。
业务来源策略、受控进程策略、插件目录和项目部署包共用的外部 Ed25519 发布签名流程见 [docs/release-signing.md](docs/release-signing.md)。
签名插件仓库协议见 [docs/plugin-repository.md](docs/plugin-repository.md)。
控制台可从验签目录直接发现未安装插件并同时检查已安装更新；目录浏览不会下载或激活插件，只有明确版本和确认计划才能进入安装。
本地映射即使因定义损坏而被隔离，其规范化磁盘身份仍会参与仓库和本地包安装冲突检查；Windows 下仅大小写不同的同名目标也不会被当成可覆盖的空位。
对已安装签名插件执行精确仓库查询时，控制台还会提供当前 Desktop 兼容、未撤回的受控回退版本；回退必须单独确认并复用验签、宿主预检、状态绑定和原子激活，本地文件安装仍默认禁止降级。
本地签名包预检、仓库安装/更新/回退和管理员显式重扫还会在启动候选宿主前核对当前业务来源策略：正式签名插件的每条公开方法或 alias 至少要被一个当前配置来源授权，否则不进入激活流程。该门禁不阻断尚在开发调试的本地映射；项目包交付和部署自检仍对签名插件与本地映射执行严格联合覆盖检查。
同 ID 签名插件的本地安装、仓库更新/回退、项目导入和管理员重扫还会对比当前公共 Web Bridge 契约；删除 route/alias、改变输入输出或增加必填输入会失败关闭，安全新增和需要原生复核的变化以聚合计数进入预览。官方目录生成器也会按 SemVer 比较规格内同 ID 的可安装版本，在目录签名前阻止破坏性升级；只有一个目录版本时仍要求用上一批准包执行 `api-check`。本地动态映射保持开发期可编辑，不受发布兼容门禁限制。
上次受控激活的签名契约还会以无路径、无调用数据的有界本地基线保存；应用退出期间人工换入的同 ID 破坏性签名包会在下次启动被隔离，不能通过重启绕过兼容门禁。安装、卸载、项目导入和重扫在各自持久提交点前先写契约 pending，崩溃后依据已经恢复的插件目录确定性完成或撤销；普通变更保留离线缺失身份的墓碑，只有对应显式卸载成功才清除。
声明式快捷键与签名进程策略见 [docs/desktop-policies.md](docs/desktop-policies.md)。
业务 WebView 的发布方签名来源边界见 [docs/origin-policy.md](docs/origin-policy.md)：正式策略使用 schema 2，把权限精确收敛到 origin、service 和 method，拒绝无范围或通配授权。
SSO 的 HTTPS-only、禁止重定向、输入/响应上限和 WebView 权限隔离见 [docs/sso-security.md](docs/sso-security.md)。
当前完成范围、上线门槛和必须由真实环境验证的项目见 [docs/migration-readiness.md](docs/migration-readiness.md)。

分层完成度、原平台能力覆盖、DLL 映射可视化和更新机制评估见 [docs/completion-assessment.md](docs/completion-assessment.md)。
旧 Electron ssdev-desktop 的逐项替代决策见 [docs/electron-parity.md](docs/electron-parity.md)。
Go WebPlus 的逐项替代决策见 [docs/webplus-parity.md](docs/webplus-parity.md)。
旧配置、插件目录、脚本快捷键以及外部浏览器本地 HTTP 依赖的安全盘点方式见 [docs/migration-audit.md](docs/migration-audit.md)。
应用本体签名更新的发布与密钥要求见 [docs/app-updates.md](docs/app-updates.md)。
Windows 安装包与源码提交、锁文件和工具链的签名绑定见 [docs/release-provenance.md](docs/release-provenance.md)。
有界结构化日志、隐私契约和本地诊断包导出见 [docs/diagnostics.md](docs/diagnostics.md)。
Release 启动失败和控制页面空白由原生错误提示覆盖；正常控制台也可以直接打开当前用户的固定日志目录，不依赖终端窗口。
项目交付前的一键环境检查、阻塞条件和处理建议见 [docs/deployment-check.md](docs/deployment-check.md)。
将项目配置、签名插件、本地映射和联合路由作为一个有组织旁签、带导入差异计划且可崩溃恢复的原子单元迁移到目标机器，见 [docs/project-bundles.md](docs/project-bundles.md)。
单独保存或导入普通桌面配置同样采用只读变更预检和确认标识，确认时重新绑定候选文件与当前已保存状态，不再在选择文件后立即覆盖。业务来源集合发生变化时还会读取控制器当前活动插件清单，拒绝让任一现有签名路由失去全部授权来源；需要同时切换来源和插件时应使用原子项目部署包。仅修改快捷键、开机启动等非来源字段不会触发这项联动门禁。
本地 `.ssdev-plugin` 也采用相同的人机确认边界：选择文件只执行验签、兼容/路由检查和候选宿主预检；确认安装时重新读取候选并绑定目标插件当前状态，包或本机状态漂移会要求重新预检。
锁文件、官方 npm 源、固定 GitHub Action 提交和定期漏洞审计要求见 [docs/supply-chain-security.md](docs/supply-chain-security.md)。

仓库内的 `plugin-trust.json` 默认没有任何公钥，因此生产接入真实插件前必须由发布流水线注入组织公钥。每把公钥除用途外还具有 `active`、`retired` 或 `revoked` 生命周期；新发布只接受 active，retired 用于计划轮换并停止官方新签发，revoked 用于泄露后让运行时立即拒绝。旧版把 RSA 私钥放进客户端的 `license.dat` 校验方式不会沿用。

正式版配置固定写入 Tauri 的标准应用配置目录，插件固定安装到标准应用本地数据目录的 `plugins` 子目录，不写入安装目录或只读资源目录，也不接受启动环境替换这些根目录。旧配置只从操作系统标准配置目录和已知历史固定路径自动迁移；工作目录或便携版目录中的配置应先使用迁移审计工具显式盘点。Debug 构建可通过 `SSDEV_CONFIG_PATH` 和 `SSDEV_PLUGIN_DIR` 隔离测试数据；旧 WebPlus 插件必须先按新规范重新签名，不能原样静默迁移。

控制台可显式开启开机启动。该设置通过操作系统登录启动机制实现，不写入旧 Electron 的任意启动命令；保存配置、快捷键或系统启动状态中的任一步失败，都会恢复到保存前状态。

## 本地验证

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

依赖安全门禁可在安装固定版 `cargo-audit 0.22.2` 后运行：

```bash
bash scripts/audit-rust-windows.sh
npm audit --prefix apps/desktop --audit-level=high
npm audit --prefix packages/web-bridge --audit-level=high
```

Windows 原生 DLL 契约测试使用独立 fixture，必须分别在 x86 和 x64 Windows runner 上执行：

```powershell
cargo build -p webplus-native-fixture --target i686-pc-windows-msvc
cargo run -p webplus-native --example dll_roundtrip --target i686-pc-windows-msvc -- `
  target/i686-pc-windows-msvc/debug/webplus_native_fixture.dll

cargo build -p webplus-native-fixture --target x86_64-pc-windows-msvc
cargo run -p webplus-native --example dll_roundtrip --target x86_64-pc-windows-msvc -- `
  target/x86_64-pc-windows-msvc/debug/webplus_native_fixture.dll

# 使用 Windows 自带的 Scripting.Dictionary 验证 COM STA、对象缓存、方法和属性读取
cargo run -p webplus-native --example com_roundtrip --target i686-pc-windows-msvc
cargo run -p webplus-native --example com_roundtrip --target x86_64-pc-windows-msvc
```

完整 Windows 门禁可一次执行：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/test-windows.ps1
```

它会运行全工作区格式、测试与 Clippy，并分别执行 x86/x64 DLL、COM 和插件宿主进程回归。正式打包脚本会先自动执行这套门禁。

## 旧资产只读审计

正式迁移审计只接受已由接收方复验的试点材料三件套，并从 manifest 精确派生旧配置、插件目录、快捷键、业务前端、浏览器 HAR 和签名来源策略：

```bash
cargo run --locked -p ssdev-migration-audit -- \
  --pilot-materials-root /secure/pilot/materials \
  --pilot-manifest /secure/pilot/pilot-materials.json \
  --pilot-report /secure/pilot/reports/pilot-readiness.json \
  --workspace /path/to/ssdev-desktop/next \
  --report-output /secure/cutover/migration-report.json \
  --evidence-output /secure/cutover/migration-evidence.json \
  --evidence-environment hospital-a-production-workflows
```

工具只读取审计输入；不会加载原生组件、执行 `installRun` 或旧快捷键脚本。正式模式禁止混入手工路径，以不覆盖方式写出 schema 4 完整报告和 schema 3 精简证据，后者绑定源码提交、报告、试点材料集合、来源策略、覆盖计数及 HTTP 证据级别；输出必须在源码工作区之外。手工 `--config` 等参数只用于把报告写到标准输出的探索性盘点，不能生成正式证据。报告不复制源码、请求 URL、查询参数或 HAR 内容。HAR 覆盖只计入带可解析绝对 `request.url` 的条目，缺失、相对或损坏 URL 会单独计为跳过并产生阻断生产判定的 warning。

新插件可用 `ssdev-plugin-tool init` 生成固定 x86/x64 的最小 Rust DLL、清单、矩阵种子和 Web 客户端；DLL 构建或旧插件清理后先用 `source-check` 在不接触密钥的情况下检查文件边界、PE 位数、命名导出和 ABI。已有插件升级再用 `api-check` 对照上一份已验签包，阻止删除路由、增加必填输入或改变输入/响应类型，并把原生绑定变化列为黄金矩阵复核项；随后用 `client` 从同一份已校验 `api.json` 生成类型化 Web Bridge 客户端。SDK 的严格 fixture invoker 可把生成客户端直接用于无桌面、无硬件的业务前端单元测试；已脱敏并完成精确复核的正式矩阵还可用 `web-fixtures` 生成同路由测试数组，避免再次手抄。单插件正式交接推荐使用 `web-kit`，把同版本客户端、fixture 及 API/矩阵摘要清单原子写入一个新目录，业务 CI 再用 `web-kit-check` 拒绝文件集或摘要漂移，并用 `web-integration-consumer.mjs` 把精确 kit 与 SDK `.tgz` 放入离线临时项目完成严格编译和全路由运行冒烟，避免两份制品分别正确、组合后不可用；多插件项目通过重复 `--kit` 联合检查身份、公开路由、编译与共享 invoker，不创建额外集合格式。这些前端工具都不模拟持久调用或原生副作用。`prepare` 生成隔离暂存目录、外部 Ed25519 待签材料和不会误触硬件的草稿黄金矩阵；组织签名系统返回签名后，用 `finalize` 验签并制作可复现的 `.ssdev-plugin`。工作台和命令行共用客户端生成器，正式插件与现场映射不会出现两套方法命名。完整命令和信任边界见 [docs/plugin-release.md](docs/plugin-release.md)。

## Windows 安装包

正式桌面程序默认采用 x64 Tauri 主进程，同时随包携带 x86 与 x64 两个插件宿主；也可以用 `-DesktopTarget i686-pc-windows-msvc` 构建完整的 32 位兼容安装包。Windows 构建机安装 Rust MSVC 双目标、Node.js 与 WiX 后，在仓库根目录执行：

```powershell
$env:TAURI_SIGNING_PRIVATE_KEY="C:\secure-build-inputs\ssdev-update.key"
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD="<从 CI 密钥服务注入>"
powershell -ExecutionPolicy Bypass -File scripts/build-windows.ps1 `
  -PluginTrustStore C:\secure-build-inputs\plugin-trust.json `
  -ProcessPolicy C:\secure-build-inputs\process-policy.json `
  -ProcessPolicySignature C:\secure-build-inputs\process-policy.sig.json `
  -OriginPolicy C:\secure-build-inputs\origin-policy.json `
  -OriginPolicySignature C:\secure-build-inputs\origin-policy.sig.json `
  -AppUpdatePublicKey C:\secure-build-inputs\ssdev-update.key.pub `
  -AppUpdateEndpoint https://updates.example.internal/ssdev/latest.json `
  -Publisher "BSOFT" `
  -WindowsCertificateThumbprint "<40位代码签名证书指纹>" `
  -WindowsTimestampUrl https://timestamp.example.internal `
  -ExpectedSignerSubject "<完整证书主题 DN>"
```

Windows 只生成面向普通用户的 NSIS 安装器。默认离线版携带 WebView2 离线安装程序；大多数 Windows 10/11 设备已有 WebView2 时，可额外构建在线轻量版，已有运行时会直接复用，缺失时安装程序联网下载：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build-windows.ps1 `
  -PluginTrustStore C:\secure-build-inputs\plugin-trust.json `
  -OriginPolicy C:\secure-build-inputs\origin-policy.json `
  -OriginPolicySignature C:\secure-build-inputs\origin-policy.sig.json `
  -AppUpdatePublicKey C:\secure-build-inputs\ssdev-update.key.pub `
  -AppUpdateEndpoint https://updates.example.internal/ssdev/latest.json `
  -Publisher "BSOFT" `
  -WindowsCertificateThumbprint "<40位代码签名证书指纹>" `
  -WindowsTimestampUrl https://timestamp.example.internal `
  -ExpectedSignerSubject "<完整证书主题 DN>" `
  -WebViewInstallMode DownloadBootstrapper
```

在线轻量版要求安装时能够访问 Microsoft WebView2 下载服务；受限内网或完全离线设备仍应使用默认离线完整版。`DownloadBootstrapper` 与 `OfflineInstaller` 是构建期白名单，脚本不提供会在缺失 WebView2 时直接失败的 `skip` 模式。

正式构建强制要求经过组织 Ed25519 签名的业务来源策略。用户配置只能在该策略批准的业务、SSO 导航和系统浏览器外链来源内选择；HTTP 来源必须由签名策略显式启用。构建脚本只临时注入信任库、进程策略、来源策略和更新配置，结束或失败时会恢复工作区原始资源。

正式构建必须选择证书指纹或带 `%1` 文件占位符的 HSM/KMS 自定义签名命令。脚本会先对两个原生插件宿主做 Authenticode 签名和发布者校验，再放入只读资源目录；随后由 Tauri 签名主程序与 NSIS，并生成更新包及其 `.sig`。插件宿主进程会加入带 `KILL_ON_JOB_CLOSE` 的 Windows Job Object，主程序异常退出时不会遗留后台宿主。

构建后在隔离 Windows 验证账户执行：

```powershell
./scripts/test-windows-package.ps1 `
  -ExpectedAppUpdatePublicKey C:\release-inputs\app-update.pub `
  -EvidenceOutput D:\cutover-evidence\windows-package.json `
  -EvidenceEnvironment hospital-a-isolated-windows-lab `
  -RequireAuthenticode `
  -ExpectedSignerSubject "<完整证书主题 DN>"
```

该门禁先要求包内更新公钥与独立输入的组织公钥逐字节一致，再验证签名的全产物 SHA-256 清单、源码提交/锁文件/工具链溯源、Rust/npm CycloneDX SBOM、updater Minisign、信任密钥生命周期以及来源/可选进程策略的 active 密钥签名；随后安装 NSIS，验证 x64 主程序、x86/x64 宿主、注入策略及 Authenticode 发布者，启动到 `app-started` 诊断事件，最后静默卸载并确认程序与注册项清理完成。只有全部请求项成功后，才会以不覆盖方式在源码和 bundle 之外写出绑定发布元数据、产物清单、版本、实际安装插件信任库、来源策略与双宿主摘要、安装器覆盖、启动、升级和签名结果的 schema 4 Windows 包证据；使用上一生产 bundle 时还绑定其版本、`release.json` 和 `artifacts.json` 摘要。

若要验证覆盖升级，将上一正式版本解包目录作为额外输入：

```powershell
./scripts/test-windows-package.ps1 `
  -PreviousBundleRoot C:\release-inputs\previous\bundle `
  -ExpectedAppUpdatePublicKey C:\release-inputs\app-update.pub `
  -EvidenceOutput D:\cutover-evidence\windows-upgrade.json `
  -EvidenceEnvironment hospital-a-isolated-upgrade-lab `
  -RequireAuthenticode `
  -ExpectedSignerSubject "<当前完整证书主题 DN>" `
  -PreviousExpectedSignerSubject "<上一版本完整证书主题 DN>" `
  -PreviousExpectedAppUpdatePublicKey C:\release-inputs\previous\app-update.pub
```

脚本要求旧版本号严格低于候选版本；它只在确认测试账户没有既有应用数据后，向 Windows 标准应用配置目录写入升级哨兵，升级后同时验证新版本启动事件和未知配置字段保留，并清理由测试创建的数据。若未指定上一版本的证书主题或更新公钥，旧包默认必须与候选包使用相同信任材料；轮换时可分别通过 `-PreviousExpectedSignerSubject` 和 `-PreviousExpectedAppUpdatePublicKey` 显式提供旧信任锚。

## 真实插件黄金矩阵

仓库不会包含生产 DLL、OCX 或患者数据。`ssdev-plugin-tool prepare` 会按插件清单生成覆盖全部 service/method 的矩阵草稿；也可以从 [docs/plugin-matrix.example.json](docs/plugin-matrix.example.json) 手工建立。替换全部占位符并把 `draft` 改为 `false` 后，先用正式参数构建候选 Windows 安装包，再在 Windows x64 验证机让矩阵直接使用构建脚本已签名并复制进该安装包的宿主文件：

在占用 Windows 实机前，可先在任意开发平台运行 `ssdev-plugin-tool matrix-check --plugin-dir <prepare暂存目录> --matrix <定稿矩阵>`；多插件联合矩阵使用 `--plugin-root <插件根目录>`。封包后，单插件运行 `release-check --package ...`；多插件项目则用 [发布集合规范](docs/plugin-release-set.example.json) 运行 `release-set-check --spec ...`。两者都用实际包内清单联合验签并绑定包、信任库和矩阵摘要，与正式运行器共享 schema、路由、精确输入、占位符、复核标记和全方法覆盖规则，但不会加载组件或替代硬件验证。审批通过后使用 `release-set-materialize --spec ... --trust-store ... --matrix ... --plugin-root <全新目录>` 一次生成验收目录，避免人工逐包装载导致漏包或错版。

```powershell
powershell -ExecutionPolicy Bypass -File scripts/test-plugin-matrix.ps1 `
  -PluginRoot C:\secure-test-inputs\plugins `
  -ReleaseSetSpec C:\secure-release\hospital-a-release-set.json `
  -TrustStore C:\secure-test-inputs\plugin-trust.json `
  -Matrix C:\secure-test-inputs\plugin-matrix.json `
  -X86Host C:\ssdev-source\target\i686-pc-windows-msvc\release\webplus-plugin-host.exe `
  -X64Host C:\ssdev-source\target\x86_64-pc-windows-msvc\release\webplus-plugin-host.exe `
  -EvidenceOutput C:\secure-release\reader-lab-evidence.json `
  -EvidenceEnvironment hospital-a-reader-lab
```

矩阵运行器不会自行编译方便但不同字节的 Debug 宿主；`X86Host` 与 `X64Host` 必须是本次候选安装包构建留下的精确 Release/签名文件。运行器会在启动 controller 和接触硬件前拒绝草稿、尚未解除的 `reviewRequired`、生成器保留占位符、无效或不完整输入、重复名称、未知路由，或未覆盖任一已声明 service/method 的矩阵；还会把插件根目录中的每个已安装插件重新确定性封包，要求插件身份、版本、签名 keyId 和包 SHA-256 与批准的发布集合逐项一致。随后由 x64 控制器分别拉起这两个待交付宿主，逐项对 `ResCode` 和 `ResData` 做精确黄金比对。全部通过且源码、发布集合、插件、信任库、矩阵和两个宿主在执行前后保持一致时，才以不覆盖方式写出绑定这些 SHA-256、源码提交、环境标签和覆盖计数的 schema 2 机器证据。Windows 包验收的 schema 4 证据会从实际安装目录记录同一对宿主摘要；最终 Go/No-Go 要求二者逐字节一致。任何无效插件、签名问题、输入变化、宿主不一致、崩溃、超时或结果差异都会使门禁失败。

## 生产切换判定

正式迁移审计、真实插件矩阵和 Windows 包验收各自生成不可覆盖的精简证据，并由对应 QA 环境使用 `cutover-evidence` 用途密钥签名。使用 [生产切换证据与 Go/No-Go](docs/cutover-evidence.md) 中的严格判定器按策略指定 keyId 验证三份封套，确认三者来自同一 clean commit、仍在有效期内，最终 Windows 产物清单和插件发布集合、信任库、黄金矩阵精确匹配审批输入，实机测试信任库/宿主与安装包实际内容逐字节一致，旧配置/插件/快捷键/前端/HAR 覆盖达到项目下限，且 HTTP 清理、迁移 finding、NSIS 安装、签名、启动和跨版本升级全部满足。`NO-GO` 会留存阻塞码并返回非零状态；只有 `GO` 文档能由另一把具备独立 `cutover-decision` 用途的组织 KMS/HSM 密钥签发最终审批封套。

生产策略使用 `ssdev-cutover-evidence prepare-policy` 自动生成：版本、提交和全部材料/插件/bundle/信任库摘要来自已复验试点输入与候选包，人工只批准证据时效、迁移覆盖下限和四个职责签名人。schema 7 策略固定 QA 与最终审批信任库，并必须先由现有最终审批职责以独立 `cutover-policy` 域签名；`decide` 不接受未签名或被替换的策略。schema 3 GO 决策继续固定策略封套和实际两份信任库；同名 keyId 的替代公钥库不能通过判定或签发。工具在写入前二次复验输入且禁止覆盖，避免把复制错误或不匹配版本固化为看似有效的策略。
