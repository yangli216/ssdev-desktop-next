# Windows 系统能力插件示例

这是一个可以编译、配置、签名、安装、更新并从业务网页调用的完整参考插件。它不是伪造返回值的演示：DLL 通过 Win32 ABI 直接调用 `kernel32.dll` 和 `user32.dll`，但仍运行在 SSDEV 的 x86/x64 隔离插件宿主中，不进入 Tauri 主进程。

## 展示的能力

| Web 方法 | Rust 导出 | Windows API | 效果 |
|---|---|---|---|
| `getTickCountMs` | `SsdevGetTickCountMs` | `GetTickCount` | 返回系统启动后的毫秒数 |
| `getCurrentProcessId` | `SsdevGetCurrentProcessId` | `GetCurrentProcessId` | 返回隔离插件宿主 PID，而不是网页或主程序 PID |
| `getSystemInfo` | `SsdevGetSystemInfo` | `GetNativeSystemInfo` | 返回原生架构、逻辑处理器数、页大小和分配粒度 |
| `getMemoryStatus` | `SsdevGetMemoryStatus` | `GlobalMemoryStatusEx` | 返回物理内存总量、可用量和负载 |
| `getDiskSpace` | `SsdevGetDiskSpace` | `GetDiskFreeSpaceExW` | 把 UTF-8 路径转换为 UTF-16 并返回磁盘容量 |
| `showMessage` | `SsdevShowMessage` | `MessageBoxW` | 从原生宿主显示一个可见窗口，直观展示本地副作用 |

源码在 [`crates/ssdev-windows-system-example`](../../crates/ssdev-windows-system-example)，x86/x64 插件映射分别在 [`api.x86.json`](api.x86.json) 和 [`api.x64.json`](api.x64.json)。配置覆盖了无参数整数返回、字符串输入、调用方分配的输出缓冲区、JSON 结果和可见原生 UI。

示例刻意不读取计算机名、用户名、注册表、环境变量、剪贴板或进程列表，也不提供任意文件、命令行或注册表写入。新增底层能力时仍应遵循最小授权原则，而不是把通用 Win32 代理暴露给网页。

## 1. 直接编译和本地调试

```powershell
rustup target add x86_64-pc-windows-msvc i686-pc-windows-msvc
cargo build --locked -p ssdev-windows-system-example --target x86_64-pc-windows-msvc
cargo build --locked -p ssdev-windows-system-example --target i686-pc-windows-msvc
```

输出位于：

```text
target/x86_64-pc-windows-msvc/debug/ssdev_windows_system_example.dll
target/i686-pc-windows-msvc/debug/ssdev_windows_system_example.dll
```

可以在控制台的“DLL 动态映射与调试”中选择其中一个 DLL，架构会自动识别。按对应 `api.x64.json` 或 `api.x86.json` 添加方法后即可运行测试，不需要重新编译桌面客户端。

仓库的 Windows 门禁会分别使用 x86/x64 DLL，通过真实 `webplus-native` 映射调用系统信息、内存、磁盘和进程 ID，防止示例源码与 `api.json` 漂移。

## 2. 准备正式签名包

信任库中的 `KeyId` 必须是状态为 `active`、用途包含 `plugin` 的 Ed25519 公钥。以下命令会编译选定架构，组装插件源目录，校验 PE 位数和全部方法，并生成外部签名请求及黄金矩阵草稿：

```powershell
./examples/windows-system-plugin/prepare-plugin.ps1 `
  -Architecture x64 `
  -Version 1.0.0 `
  -KeyId production-plugin-2026 `
  -TrustStore C:\secure-inputs\plugin-trust.json `
  -OutputRoot C:\secure-release\windows-system-example-x64-1.0.0
```

输出目录中的 `plugin-signing-request.json` 包含 `payloadBase64` 和 `payloadSha256`。由组织 KMS/HSM 对 Base64 解码后的原始字节执行 Ed25519 签名，把 64 字节签名写成单行 Base64 文件。私钥不能交给示例脚本或桌面客户端。

## 3. 导入签名并生成 `.ssdev-plugin`

```powershell
./examples/windows-system-plugin/finalize-plugin.ps1 `
  -Version 1.0.0 `
  -TrustStore C:\secure-inputs\plugin-trust.json `
  -Signature C:\secure-signing-output\windows-system-example.sig.base64 `
  -OutputRoot C:\secure-release\windows-system-example-x64-1.0.0
```

`finalize` 会确认暂存目录自签名请求生成后没有变化、用公开信任库验证签名，并输出确定性的 `windows-system-example-x64-1.0.0.ssdev-plugin`。在 SSDEV 控制台选择“安装签名插件”即可完成宿主预检和原子热加载。

x86 与 x64 示例使用不同插件 ID，但声明同一个 `windows.system` 服务，因此一台客户端只安装其中一个。SSDEV x64 安装包同时携带 x86/x64 宿主，需要验证 32 位能力时也可以选择 x86 包。

## 4. 网页调用

[`web-example.ts`](web-example.ts) 使用正式 `@bsoft/ssdev-web-bridge`，没有 localhost HTTP 回退：

```ts
const result = await bridge.invokePlugin('windows.system', 'getMemoryStatus', {})
// result.ResData:
// {
//   ReturnValue: 0,
//   value: '{"loadPercent":37,"totalPhysicalBytes":...,"availablePhysicalBytes":...}'
// }
```

`ReturnValue` 是 Win32 状态码；零表示成功，非零值可按 Windows System Error Codes 定位。最外层 `ResCode` 是 SSDEV 路由/宿主状态，二者不要混淆。`showMessage` 会阻塞该插件的串行执行通道直到用户关闭窗口，只能由明确的用户操作触发。

## 5. 加入签名更新仓库

正式包与普通 COM/DLL 插件使用同一更新机制：用 `ssdev-plugin-tool catalog` 从已验签包生成短期 HTTPS 目录，再用具有 `plugin-catalog` 用途的独立密钥签目录。客户端检查更新后显示更高 SemVer，用户确认后重新下载、验签、预检并原子替换；失败恢复旧包和旧路由。

本示例是能力和发布流程参考，不是建议把所有 Windows API 放进一个万能插件。生产插件应按业务域拆分服务，固定允许的方法、参数和副作用，并使用真实硬件黄金矩阵验收。
