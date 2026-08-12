# WebPlus 调用迁移

Tauri 内部不再通过 `http://127.0.0.1:7711` 调用客户端原生能力。新业务代码建议通过 `@bsoft/ssdev-web-bridge` 接入，以便统一检查协议版本并获得稳定类型：

```ts
import { connectDesktop } from '@bsoft/ssdev-web-bridge'

const { bridge, system, context } = await connectDesktop()
const result = await bridge.invokePlugin("card.reader", "readCard", { timeout: 30 })
```

受控业务窗口注入的底层等价入口如下：

```js
const result = await window.ssdevDesktop.invokePlugin(
  "card.reader",
  "readCard",
  { timeout: 30 },
)

// 便于旧页面做最小改造的别名
const sameResult = await window.webPlusInvoke(
  "card.reader",
  "readCard",
  { timeout: 30 },
)

// 最小系统声明：不包含用户名、BIOS、主板、磁盘、内存或网卡标识
const system = await window.ssdevDesktop.getSystemInfo()
// { os: "windows", architecture: "x86_64", appVersion: "0.1.0", protocolVersion: 1 }
```

这里的 `protocolVersion` 只表示业务 Web Bridge 契约版本，不是 controller 与 x86/x64 插件宿主之间的私有帧协议版本。业务 SDK 升级和内部宿主协议升级分别治理，不能用一个版本号同时代表两层边界。

同一窄桥接对象还提供经过来源与参数校验的桌面能力：

```js
// 在指定显示器打开同源或已授权来源窗口；screenIndex 越界时回退主屏
await window.ssdevDesktop.openWindow({
  url: "/portal/detail",
  title: "详情",
  screenIndex: 1,
  width: 1280,
  height: 800,
  context: { encounterId: "123" },
})

// 在系统默认浏览器中打开允许来源；默认仅允许当前业务来源
await window.ssdevDesktop.openExternal("https://help.example.internal/guide")

// context 在新窗口中只读暴露为 window.ssdevDesktopContext

await window.ssdevDesktop.showFloating({
  id: "notice-123",
  url: "/desktop/notice",
  durationMs: 5000,
  width: 330,
  height: 150,
  context: { message: "待处理事项" },
})

window.addEventListener("ssdev-floating-action", (event) => {
  console.log(event.detail)
})
```

`width`/`height` 与 `left`/`top` 都必须成对提供，并受尺寸和坐标上限约束；提供宽高时窗口不会自动最大化。Tauri 业务窗口本身就是无浏览器工具栏的应用窗口，因此不再接受旧 WebPlus 的 `browser` 可执行文件或 `appMode` 参数。需要普通系统浏览器时使用 `openExternal`，需要受控业务窗口时使用 `openWindow`。

悬浮窗只获得 `window.ssdevFloating.close()` 和 `window.ssdevFloating.resolve(payload)`，不能调用插件或创建其他窗口。窗口上下文与返回数据均限制为 64 KiB。

全局快捷键 `Ctrl+Shift+C` 会发送聚焦业务窗口截图，`Ctrl+Shift+A` 会先打开本地框选遮罩；两者确认后都通过 `ssdev-capture` 事件把 PNG Data URL 发送给原业务窗口：

```ts
window.addEventListener("ssdev-capture", (event) => {
  const pngDataUrl = (event as CustomEvent<string>).detail
  // 交给业务反馈或附件流程
})
```

区域截图的显示器原图只暂存在 Rust 内存和受限本地遮罩中，业务来源无法调用取得原图的命令。

请求和响应继续保持旧 WebPlus 语义：

```json
{
  "serviceId": "card.reader",
  "method": "readCard",
  "parameters": { "timeout": 30 }
}
```

```json
{
  "ResCode": 0,
  "ResData": {
    "ReturnValue": 1
  }
}
```

controller 对所有入口统一限制最多 8 个在途插件调用，不建立无界等待队列。容量饱和时返回：

```json
{
  "ResCode": -32001,
  "ResData": "native plugin invocation capacity is busy; retry later"
}
```

该响应在服务路由和插件宿主执行之前产生，因此本次请求保证没有执行。调用方只能对这个精确错误做有上限的退避重试；不要对超时或其他插件错误自动重试，以免非幂等硬件操作被重复执行。

调用一旦通过准入，就由 Rust controller 的独立监督任务持有。页面导航、WebView 销毁或 JavaScript 丢弃 Promise 只会脱离结果等待，不会取消已经开始的 DLL/COM/设备操作；监督任务仍执行到响应或受控超时，确保后续管道响应不会错配。业务端必须把这类结果未知的调用视为“可能已经执行”，不能自动重试。真正的设备取消只能在具体插件协议明确支持、且另行定义幂等与确认语义后增加。

对于打印、写卡等非幂等操作，新 SDK 还提供向后兼容的可选 `invokePluginTracked(operationId, serviceId, method, parameters)` 与 `getPluginInvocation(operationId, serviceId, method)`。操作 ID 在进入 controller 前先持久落盘，页面从落盘开始就不再拥有取消权；同来源、同完整请求的重复提交共享一次执行，同 ID 改参数或路由会失败。应用崩溃后可能返回 `indeterminate` 或 `completedWithoutResult`，两者都不能自动重放；详见 `tracked-invocations.md`。

不要只按 JavaScript 方法是否存在决定是否启用非幂等流程。新版 `getSystemInfo()` 会在可选 `capabilities.trackedInvocations` 中声明 `supported`、`available`、`accepting`、脱敏错误码和实现边界；SDK 使用 `supportsTrackedPluginInvocations(connection.bridge, connection.system)` 时会同时核对方法与运行时声明。旧客户端没有能力声明，因此可以继续使用基础桥接，但不应进入要求持久防重的流程。

客户端退出或更新重启会先关闭插件调用准入。尚未进入生命周期读锁的竞态请求返回 `ResCode=-32002`，保证未执行；普通退出为已经开始的调用提供最多 30 秒正常收尾时间，更新安装则等待调用自身的有界截止时间，以免在替换程序时遗留宿主。收到 `-32002` 后应终止当前页面流程并等待客户端重新启动，不要在旧进程中重试。

同一插件/架构宿主使用串行执行槽，避免不支持并发的厂商组件或单实例设备被同时调用。方法或服务的超时是统一截止时间：拿到宿主后，等待执行槽与实际管道调用共同消耗这段预算。截止时间耗尽但尚未拿到执行槽时返回 `ResCode=-32003`，保证该请求未执行，可做有上限的退避重试；一旦已经进入原生调用，超时仍返回一般宿主失败，不能自动重试。

签名插件安装或热更新进入按插件维护代次后，发往目标插件的新调用以 `ResCode=-32010` 快速返回并保证未执行，无关插件继续服务。目标插件已经开始的调用先完成，开始于旧代次但排在维护写锁之后的调用也会被拒绝，绝不会在新路由或新插件版本上“迟到执行”。显式完整重新扫描使用全局维护，因此可能暂时拒绝全部插件调用。维护结束后业务页可做有上限的退避重试。

## 安全边界

- 桥接只在 `website` 与 `environments` 的业务来源中启用，且这些来源必须同时拥有发布方签名的 schema 2 `origin-policy.json` 授权；每次插件调用还必须精确匹配该来源的 `serviceId` 和 `method`，不支持通配授权。
- 用户配置不能扩大发布策略；业务、SSO 导航和系统浏览器外链使用三组独立来源集合。
- 正式构建默认拒绝 HTTP。确需兼容院内旧 HTTP 站点时，发布方必须在已签名策略中列出精确来源并显式设置 `allowInsecureHttp`，控制台会展示该例外。
- HTTP 业务来源例外不适用于 SSO POST；登录标识、租户、角色和科室只发送到由主业务地址派生的 HTTPS 端点，且客户端不跟随重定向。
- `trustedOrigins` 只允许 SSO 页面完成导航，不会获得插件、截图或窗口能力。
- 页面导航到未授权来源时会被拦截。
- 插件命令会再次核对窗口标签和当前页面来源，不能仅靠伪造 JavaScript 对象绕过。
- Tauri 自身只为当前配置启用的精确业务来源注册七个窄应用命令；SSO 导航来源没有远程 ACL，业务页也拿不到控制台、插件安装、更新或诊断命令。
- 本地控制台与截图遮罩只接受精确内置页面 URL，导航到其他页面会被阻止且高权限命令会二次拒绝。
- 远程页面不获得 Shell、任意文件读写或通用 Tauri API 权限。
- 类型化 SDK 不实现 localhost HTTP 回退；桌面环境或协议不可用时会抛出明确错误。
- `getSystemInfo()` 只返回操作系统类别、CPU 架构、客户端版本和桥接协议版本，不构建设备指纹。
- 第三方 DLL/COM 仍只进入隔离的 x86/x64 插件宿主，不进入 Tauri 主进程。
- 已接纳的插件调用不依赖页面等待者存活；页面离开不会中断或重放潜在非幂等的原生操作。
- 非幂等流程可使用持久 UUID v4 操作 ID；同 ID 不会因页面刷新或进程恢复重复进入插件，崩溃窗口以明确的未知状态交给业务/设备对账。
- 正常退出先关闭新调用准入并有界排空在途调用；应用更新安装失败时会重新开放准入，避免留下只能重启恢复的半停机客户端。
- 插件安装和热更新使用按插件串行、取消安全的维护代次；只有目标插件的维护期请求被拒绝且不占用全局准入容量，无关插件继续服务，任何请求都不会跨版本执行。
- 新窗口和悬浮窗只能访问授权来源，弹窗默认拒绝继续创建窗口。
- 系统浏览器打开操作只接受 HTTP(S)，且来源必须属于业务来源或 `externalOrigins`；页面中的普通 `_blank` 链接不会绕过该策略。

## 仍需 HTTP 的情况

只有“普通 Chrome/Edge 页面需要调用客户端”时才需要兼容 HTTP 网关。该网关应作为单独、默认关闭的适配器提供，并至少具备来源白名单、会话挑战、请求大小限制和速率限制；Tauri 自己不依赖它。当前 `next` 实现有意没有启动 localhost 端口。
