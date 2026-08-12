# 平台支持与构建产物

## 支持级别

| 平台 | Actions 产物 | 支持级别 | WebPlus 原生能力 |
| --- | --- | --- | --- |
| Windows 10/11 x64 | NSIS、MSI、updater | 主要生产目标 | x86/x64 DLL、COM、EXE |
| Windows 10/11 x86 | NSIS、MSI、updater | 兼容目标 | x86 DLL、COM、EXE；包内仍携带双宿主 |
| Linux x64 | DEB、AppImage | 开发预览 | 不支持 Windows DLL/COM 和桌面截图 |
| macOS x64 | DMG | 开发预览 | 不支持 Windows DLL/COM |
| Windows 7/8/8.1 | 不发布 | 实验性研究 | 当前安全工具链不承诺支持 |

GitHub Actions 上传的安装包使用临时 updater 密钥且没有 Authenticode、Apple Developer ID 或 Linux 分发签名，只用于工程验证，不能作为正式发布包。生产 Windows 发布必须使用 `scripts/build-windows.ps1` 注入组织策略、更新公钥和代码签名材料。

## 为什么不承诺 Windows 7

当前固定的 Rust 1.91 MSVC 常规目标要求 Windows 10 或更高版本；微软当前支持的 WebView2 客户端系统也是 Windows 10/11。Tauri 的 `offlineInstaller` 会把 WebView2 引导程序带入安装包，解决离线安装和旧系统 TLS 下载问题，但不会改变 Rust 二进制或 WebView2 Runtime 的受支持系统范围。

若业务必须保留 Windows 7，需要建立单独的长期维护分支，冻结旧 Rust/Tauri/WebView2 依赖，禁用自动升级到不兼容运行时，并在真实 Win7 x86/x64 虚拟机和硬件环境执行安装、启动、DLL/COM、升级及卸载矩阵。该分支不能和当前安全更新主线共用支持承诺。

## 自动构建

`.github/workflows/ci.yml` 在主分支推送、Pull Request 和手动触发时运行：

- Linux 上执行 Rust 格式、Clippy、测试、桌面安全边界和前端/SDK 测试；
- Windows 上分别验证 x86/x64 DLL、COM 和插件宿主；
- 对 x64 与 x86 桌面各构建一套合成旧版本和当前版本，执行 NSIS/MSI 原位升级、启动、布局、架构与卸载验证；
- 构建 Linux DEB/AppImage 和 macOS DMG 开发预览包；
- 将通过门禁的未签名产物保存 14 天。

每周依赖审计由 `.github/workflows/supply-chain.yml` 执行。
