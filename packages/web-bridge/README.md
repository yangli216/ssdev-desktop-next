# @bsoft/ssdev-web-bridge

业务前端使用的框架无关 SSDEV Desktop 桥接契约。该包只连接由受控 Tauri 业务窗口注入的 `window.ssdevDesktop`，不会尝试 localhost HTTP、WebSocket 或浏览器扩展回退。

```ts
import { connectDesktop } from '@bsoft/ssdev-web-bridge'

const { bridge, system, context } = await connectDesktop()
const result = await bridge.invokePlugin('card.reader', 'readCard', {
  timeout: 30,
})
```

`connectDesktop()` 会先读取最小系统声明并检查协议版本。页面不在授权桌面窗口中时抛出 `DesktopBridgeUnavailableError`；协议不兼容时抛出 `UnsupportedDesktopProtocolError`，业务代码不应静默切换到 HTTP。

SDK 显式导出 `CURRENT_BRIDGE_PROTOCOL_VERSION`；旧名称 `CURRENT_PROTOCOL_VERSION` 仅作为源码兼容别名保留。该版本只治理注入业务页面的公开桥接，不与 controller/plugin-host 的内部命名管道协议绑定。

插件调用容量饱和时返回 `{ ResCode: -32001, ResData: "native plugin invocation capacity is busy; retry later" }`。该请求保证未进入插件宿主；业务代码可以只对这个精确响应做有上限的退避重试，不能把其他超时或插件错误自动重试为潜在的重复硬件操作。

页面导航、组件卸载或业务代码丢弃 Promise 只会让页面停止等待结果，不会撤销已经被桌面端接纳的原生调用。桌面端会让该调用独立执行到正常响应或受控超时，以保持命名管道请求/响应顺序；调用方不得把“没有继续等待”视为“设备没有执行”，也不得因此自动重试。当前契约没有提供硬件操作取消能力。

对打印、写卡等非幂等操作，优先使用可选的 `invokePluginTracked` 和 `getPluginInvocation`。用 `createPluginOperationId()` 为一次逻辑动作生成 UUID v4，并在页面刷新、重复提交和查询时复用；桌面端会在执行前持久记录该 ID，相同来源和完整请求只执行一次，同 ID 改参数会失败。`indeterminate` 与 `completedWithoutResult` 都表示不能自动重放；保留窗口、崩溃边界和完整示例见 SSDEV Desktop 主仓库的 `docs/tracked-invocations.md`。

判断该能力时应使用 `supportsTrackedPluginInvocations(connection.bridge, connection.system)`，或把同样两个值传给 `requireTrackedPluginInvocations`。`system.capabilities.trackedInvocations` 会区分客户端是否支持、账本是否成功启动以及当前是否仍接收新操作，并声明容量和保留边界；省略 `system` 只能兼容性地检查方法是否存在，不能证明运行时可用。

桌面端进入退出或更新重启排空阶段后，新调用返回 `{ ResCode: -32002, ResData: "native plugin controller is stopping; request was not executed" }`，并保证没有进入插件。业务页应结束当前流程并等待客户端重新启动，不要在正在退出的进程内循环重试。

同一插件宿主会串行访问厂商组件。请求在其配置的统一截止时间内没有拿到执行槽时返回 `{ ResCode: -32003, ResData: "native plugin execution lane timed out; request was not executed" }`。这个响应也保证未执行，可以做有上限的退避重试；截止时间覆盖等待执行槽和实际 IPC 调用，不会在锁前无限排队。

签名插件安装或热更新排空期间，只有发往目标插件的新请求返回 `{ ResCode: -32010, ResData: "native plugin controller is reloading; request was not executed" }`，其他插件继续服务；显式完整重新扫描时该错误可能覆盖全部插件。请求不会跨越一次路由/插件版本切换后再意外执行；业务页可以在维护结束后重新发起，但必须有退避上限，不能持续轮询压测客户端。

发布到组织内部 npm 仓库前，将 `private` 改为 `false`，并由发布流水线执行 `npm test`、生成制品摘要和包签名。当前仓库保持私有，避免尚未完成生产版本治理时被误发布。
