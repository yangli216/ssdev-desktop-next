# 应用本体签名更新

SSDEV Desktop 的应用更新与插件更新是两条独立信任链：

- 应用安装包使用 Tauri Minisign 密钥签名，由桌面客户端内置的更新公钥验证。
- `.ssdev-plugin` 使用组织 Ed25519 插件信任库验证。
- Windows Authenticode 代码签名用于验证发布者身份和减少系统警告，不能替代前两者。

## 运行时流程

1. 只有本地 `control` 窗口能调用检查和安装命令，远程业务页没有更新权限。
2. 客户端通过最多四个 HTTPS 端点检查更高的 SemVer，默认不允许降级。
3. 检查更新时先用目标 Desktop SemVer 重新发现全部签名插件和本地映射；任何签名插件缺少明确兼容范围、范围不匹配，或任一能力存在完整性、定义一致性及插件 ID 冲突异常，都会作为阻塞项展示，不提供安装操作。
4. 可安装结果生成只用于本次确认的域分隔计划标识，绑定当前版本、目标版本、发布日期、目标平台、下载 URL、Minisign 签名、页面展示的发布说明，以及当前全部签名插件的身份、签名 keyId、完整文件载荷和本地映射的确定性内容包。开始新一轮检查时会先清除旧 pending，检查失败不能继续安装上一轮对象。
5. 用户确认安装时必须提交计划标识；客户端在插件安装锁内重新恢复事务、读取精确 pending 更新并重建完整能力集合摘要。pending 被另一轮检查替换，或签名插件、本地映射被安装、更新、删除及内容发生变化时，旧确认在下载前失败。
6. 更新包流式写入用户本地数据目录，最多 256 MiB；重定向和最终下载均受 HTTPS-only 客户端约束。
7. 下载过程中使用现代预哈希 Minisign 签名做流式验证，未通过验签不会进入安装阶段。验签并完整读取后再次验证目标 Desktop 兼容性和完整能力集合摘要，阻止下载期间发生的签名插件或本地映射漂移。
8. 二次复核成功后才关闭业务窗口并停止所有 DLL/COM 插件宿主，再启动系统安装程序。
9. Windows 安装器会退出当前客户端；macOS/Linux 安装完成后由客户端重启。

默认仓库中的 `resources/app-update.json` 明确关闭更新。正式构建脚本临时注入生产配置并在构建结束后恢复该文件，避免开发构建误连生产更新服务。

## 生成密钥

在隔离的发布环境生成 Tauri 更新签名密钥：

```powershell
npm run tauri --prefix apps/desktop -- signer generate --ci `
  -p "<强密码>" `
  -w C:\secure-build-inputs\ssdev-update.key
```

- `ssdev-update.key` 是私钥，只能进入 KMS/HSM 或受控 CI secret。
- `ssdev-update.key.pub` 是 Base64 编码的公钥封套，可作为构建输入。
- 私钥丢失后，已安装客户端无法信任新密钥。轮换时必须先发布一个仍由旧密钥签名、同时内置新公钥的过渡版本。

## 正式构建

```powershell
$env:TAURI_SIGNING_PRIVATE_KEY="C:\secure-build-inputs\ssdev-update.key"
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD="<由 CI secret 注入>"

./scripts/build-windows.ps1 `
  -PluginTrustStore C:\secure-build-inputs\plugin-trust.json `
  -OriginPolicy C:\secure-build-inputs\origin-policy.json `
  -OriginPolicySignature C:\secure-build-inputs\origin-policy.sig.json `
  -AppUpdatePublicKey C:\secure-build-inputs\ssdev-update.key.pub `
  -AppUpdateEndpoint https://updates.example.internal/ssdev/latest.json `
  -Publisher "BSOFT" `
  -WindowsCertificateThumbprint "<40位代码签名证书指纹>" `
  -WindowsTimestampUrl https://timestamp.example.internal `
  -ExpectedSignerSubject "<完整证书主题 DN>"
```

也可以用 `-WindowsSignCommand "artifact-signing-cli ... %1"` 接入 HSM/KMS；命令必须包含 Tauri 约定的 `%1` 文件占位符，并通过环境身份认证，不应把密钥写进命令行。证书模式会验证证书具有私钥、代码签名 EKU、未过期和时间戳端点；两种模式都会先签名 x86/x64 插件宿主，并在构建后验证全部 EXE 的 Authenticode 发布者。

Windows 发布机还必须安装固定版 `cargo-cyclonedx 0.5.9`。构建会为桌面主程序、x86/x64 插件宿主及 npm 前端生成 CycloneDX 1.5 SBOM，移除工作区绝对路径和随机标识；随后生成覆盖整个 bundle 的规范化路径、长度和 SHA-256 清单，并用同一受控 Tauri 更新密钥签名。发布清单不依赖包内自声明公钥建立信任，验收时必须通过 `-ExpectedAppUpdatePublicKey` 独立提供组织更新公钥；更新密钥轮换期间，上一包通过 `-PreviousExpectedAppUpdatePublicKey` 使用独立旧公钥验证。

Windows 构建只生成 NSIS。默认使用 `-WebViewInstallMode OfflineInstaller` 生成离线版；在线轻量渠道使用 `-WebViewInstallMode DownloadBootstrapper`，已有 WebView2 时复用系统运行时，缺失时安装过程需要访问 Microsoft 下载服务。构建只允许这两种 WebView2 策略，不开放可能在运行时缺失时直接启动失败的 `skip`。安装器类型、架构和 WebView2 模式写入 `metadata/package-profile.json` 并进入签名产物清单；验收脚本通过 `-ExpectedWebViewInstallMode` 与其精确匹配。

缺少更新公钥、HTTPS 端点、更新私钥或 Windows 代码签名配置时，正式打包脚本会直接失败。只有 `CI=true` 且显式传入 `-AllowUnsignedTestBuild` 时才能生成不可分发的未签名测试包。

更新服务可以返回 Tauri 静态 JSON，也可以使用动态端点。发布前必须验证目标键为 `windows-x86_64`，其中 `signature` 是生成的 `.sig` 文件内容，不是文件路径。

## 发布门禁

- 安装包版本必须高于当前版本，发布说明不得包含敏感信息。
- 发布 Desktop 前必须先保证每个仍需保留的签名插件已发布覆盖目标版本的兼容范围，并在代表性机器复核本地映射；客户端会阻止导致现有插件或映射被隔离的升级，不以“升级后再修能力”作为正常流程。
- 在隔离 Windows 账户运行 `scripts/test-windows-package.ps1 -ExpectedAppUpdatePublicKey <独立公钥文件> -EvidenceOutput <工作区和 bundle 外的新文件> -EvidenceEnvironment <验证环境标签> -RequireAuthenticode -ExpectedSignerSubject "<完整证书主题 DN>"`；门禁先验证签名的全产物清单、源码提交/锁文件/工具链溯源、SBOM、updater 包、信任密钥生命周期及来源/可选进程策略的 active 密钥签名，再要求 NSIS 通过安装、架构/资源/注入策略一致性/签名检查、启动诊断和卸载，且所有 Authenticode 签名者主题必须精确匹配；成功后才写出绑定本次结果且不可覆盖的包验收证据。
- CI 使用同一源码构建较低的 `0.0.1` 合成版本，对 NSIS 自动验证原位升级、候选版本启动和配置哨兵保留；正式发布还必须通过 `-PreviousBundleRoot` 输入真实上一生产版本重复该门禁。
- 先在隔离 Windows 验证机测试下载、签名错误、网络中断、安装失败和配置保留。
- 分批发布时由更新服务控制可见范围，不在客户端实现任意降级。
- 需要回滚时优先发布更高版本号的修复包；紧急降级必须通过重新构建的受控恢复安装包完成。
