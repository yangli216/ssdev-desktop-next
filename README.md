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
- 新实现保持 `serviceId`、`method`、`parameters`、`ResCode`、`ResData` 语义兼容。
- 所有跨进程请求必须具有长度上限、超时、请求 ID 和确定的失败响应。
- 业务 Web Bridge 与 controller/plugin-host 私有 IPC 使用独立版本域，任一侧演进都不强迫另一侧同步升级。
- 每个签名插件必须声明经过验证的 Desktop SemVer 范围；安装、项目导入和应用更新都按该范围失败关闭。
- controller 最多接受 8 个在途插件调用；容量饱和时在进入原生宿主前快速拒绝，不建立无界等待队列。
- localhost HTTP 仅作为可关闭的旧浏览器兼容网关，不是新架构内部依赖。

每个提交由 `.github/workflows/ci.yml` 执行 Linux 质量门禁、Windows x86/x64 原生回归，并分别为 x64 与 x86 桌面构建 `0.0.1` 合成旧版本和当前候选版本，对离线 NSIS 执行原位升级、配置保留、布局/架构检查、真实启动和卸载；随后额外构建在线轻量 NSIS 并执行安装、启动和卸载冒烟。Linux DEB/AppImage 和 macOS DMG 仅在手动选择 `all` 平台时构建。CI 使用临时更新密钥且明确跳过平台代码签名，只验证工程链路，产物不能分发。平台支持边界见 [docs/platform-support.md](docs/platform-support.md)。

架构决策和迁移门槛见 [docs/adr/0001-target-architecture.md](docs/adr/0001-target-architecture.md)。
业务页面从 localhost HTTP 切换到窄桥接接口的方式见 [docs/web-bridge-migration.md](docs/web-bridge-migration.md)。
业务前端应通过 [packages/web-bridge](packages/web-bridge/README.md) 的类型化协议适配层接入，不直接依赖 Tauri 内部 API。
打印、写卡等非幂等调用的持久操作 ID、防重放和崩溃后对账语义见 [docs/tracked-invocations.md](docs/tracked-invocations.md)。
插件完整性、公钥信任链以及可崩溃恢复的安装、更新和卸载生命周期见 [docs/plugin-signing.md](docs/plugin-signing.md)。
无需重新编译客户端的 DLL/COM 可视化配置、热加载、现场调试和本地映射包迁移见 [docs/local-mapping-studio.md](docs/local-mapping-studio.md)。
从 Rust 封装 Win32 API、x86/x64 映射、网页调用到外部签名封包和更新发布的完整示例见 [examples/windows-system-plugin](examples/windows-system-plugin/README.md)。
旧插件从安全暂存、外部签名、确定性封包到黄金矩阵草稿的发布流程见 [docs/plugin-release.md](docs/plugin-release.md)。
业务来源策略、受控进程策略、插件目录和项目部署包共用的外部 Ed25519 发布签名流程见 [docs/release-signing.md](docs/release-signing.md)。
签名插件仓库协议见 [docs/plugin-repository.md](docs/plugin-repository.md)。
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
单独导入普通桌面配置同样采用只读变更预检和确认标识，确认时重新绑定候选文件与当前已保存状态，不再在选择文件后立即覆盖。
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

迁移前可以同时传入多个旧配置、插件目录、快捷键文件、业务前端资源和浏览器 HAR：

```bash
cargo run --locked -p ssdev-migration-audit -- \
  --config /path/to/config.json \
  --plugins /path/to/web-plus/plugins \
  --keymap /path/to/keymap.json \
  --browser-assets /path/to/business-web/dist \
  --browser-har /path/to/critical-workflows.har \
  --workspace /path/to/ssdev-desktop/next \
  --report-output /secure/cutover/migration-report.json \
  --evidence-output /secure/cutover/migration-evidence.json \
  --evidence-environment hospital-a-production-workflows
```

工具只读取审计输入；不会加载原生组件、执行 `installRun` 或旧快捷键脚本。正式模式以不覆盖方式写出完整报告和绑定源码提交、报告 SHA-256、覆盖计数及 HTTP 证据级别的精简证据；输出必须在源码工作区之外。省略最后四个正式参数时，报告写到标准输出用于探索。报告不复制源码、请求 URL、查询参数或 HAR 内容。

完成只读审计并修复阻塞项后，使用 `ssdev-plugin-tool prepare` 生成隔离暂存目录、外部 Ed25519 待签材料和不会误触硬件的草稿黄金矩阵；组织签名系统返回签名后，再用 `finalize` 验签并制作可复现的 `.ssdev-plugin`。完整命令和信任边界见 [docs/plugin-release.md](docs/plugin-release.md)。

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

该门禁先要求包内更新公钥与独立输入的组织公钥逐字节一致，再验证签名的全产物 SHA-256 清单、源码提交/锁文件/工具链溯源、Rust/npm CycloneDX SBOM、updater Minisign、信任密钥生命周期以及来源/可选进程策略的 active 密钥签名；随后安装 NSIS，验证 x64 主程序、x86/x64 宿主、注入策略及 Authenticode 发布者，启动到 `app-started` 诊断事件，最后静默卸载并确认程序与注册项清理完成。只有全部请求项成功后，才会以不覆盖方式在源码和 bundle 之外写出绑定发布元数据、产物清单、版本、安装器覆盖、启动、升级和签名结果的 Windows 包证据。

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

仓库不会包含生产 DLL、OCX 或患者数据。`ssdev-plugin-tool prepare` 会按插件清单生成覆盖全部 service/method 的矩阵草稿；也可以从 [docs/plugin-matrix.example.json](docs/plugin-matrix.example.json) 手工建立。替换全部占位符并把 `draft` 改为 `false` 后，在 Windows x64 验证机执行：

在占用 Windows 实机前，可先在任意开发平台运行 `ssdev-plugin-tool matrix-check --plugin-dir <prepare暂存目录> --matrix <定稿矩阵>`；多插件联合矩阵使用 `--plugin-root <插件根目录>`。封包后，单插件运行 `release-check --package ...`；多插件项目则用 [发布集合规范](docs/plugin-release-set.example.json) 运行 `release-set-check --spec ...`。两者都用实际包内清单联合验签并绑定包、信任库和矩阵摘要，与正式运行器共享 schema、路由、精确输入、占位符、复核标记和全方法覆盖规则，但不会加载组件或替代硬件验证。审批通过后使用 `release-set-materialize --spec ... --trust-store ... --matrix ... --plugin-root <全新目录>` 一次生成验收目录，避免人工逐包装载导致漏包或错版。

```powershell
powershell -ExecutionPolicy Bypass -File scripts/test-plugin-matrix.ps1 `
  -PluginRoot C:\secure-test-inputs\plugins `
  -ReleaseSetSpec C:\secure-release\hospital-a-release-set.json `
  -TrustStore C:\secure-test-inputs\plugin-trust.json `
  -Matrix C:\secure-test-inputs\plugin-matrix.json `
  -EvidenceOutput C:\secure-release\reader-lab-evidence.json `
  -EvidenceEnvironment hospital-a-reader-lab
```

矩阵运行器会在启动 controller 和接触硬件前拒绝草稿、尚未解除的 `reviewRequired`、生成器保留占位符、无效或不完整输入、重复名称、未知路由，或未覆盖任一已声明 service/method 的矩阵；还会把插件根目录中的每个已安装插件重新确定性封包，要求插件身份、版本、签名 keyId 和包 SHA-256 与批准的发布集合逐项一致。随后由 x64 控制器分别拉起真实 x86/x64 宿主，逐项对 `ResCode` 和 `ResData` 做精确黄金比对。全部通过且源码、发布集合、插件、信任库、矩阵和两个宿主在执行前后保持一致时，才以不覆盖方式写出绑定这些 SHA-256、源码提交、环境标签和覆盖计数的 schema 2 机器证据。任何无效插件、签名问题、输入变化、宿主崩溃、超时或结果差异都会使门禁失败。

## 生产切换判定

正式迁移审计、真实插件矩阵和 Windows 包验收各自生成不可覆盖的精简证据，并由对应 QA 环境使用 `cutover-evidence` 用途密钥签名。使用 [生产切换证据与 Go/No-Go](docs/cutover-evidence.md) 中的严格判定器按策略指定 keyId 验证三份封套，确认三者来自同一 clean commit、仍在有效期内，且 HTTP 清理、迁移 finding、双安装器、签名、启动和跨版本升级全部满足。`NO-GO` 会留存阻塞码并返回非零状态；只有 `GO` 文档能由另一把具备独立 `cutover-decision` 用途的组织 KMS/HSM 密钥签发最终审批封套。
