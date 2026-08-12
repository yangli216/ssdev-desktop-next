# 持久原生调用与结果协调

`invokePlugin` 保留旧 WebPlus 兼容语义。对打印、写卡、签名、收费设备等不能盲目重试的操作，业务应优先使用可选的 `invokePluginTracked`：为一次逻辑副作用生成一个 UUID v4，并在所有网络重试、页面刷新和状态查询中复用同一个 ID。

```ts
import {
  connectDesktop,
  createPluginOperationId,
  requireTrackedPluginInvocations,
} from '@bsoft/ssdev-web-bridge'

const connection = await connectDesktop()
const bridge = requireTrackedPluginInvocations(
  connection.bridge,
  connection.system,
)
const operationId = createPluginOperationId()
const outcome = await bridge.invokePluginTracked(
  operationId,
  'printer',
  'print',
  { documentId: '业务侧引用' },
)

if (outcome.state === 'completed') {
  console.log(outcome.response)
}
```

操作 ID 必须由安全随机源生成，并由业务流程保存。一个 ID 只能绑定同一来源、`serviceId`、`method` 和完整参数；重复提交相同内容会等待或返回同一次执行结果，换参数、换方法或换授权范围会硬失败。不要为同一个业务动作在超时或刷新后自动生成新 ID。

## 状态语义

| 状态 | 含义 | 业务动作 |
| --- | --- | --- |
| `pending` | 当前进程中同一操作仍在执行 | 继续查询，不能生成新 ID 重试 |
| `completed` | 已得到插件响应；`durable=true` 表示完成标记也已落盘 | 按 `response.ResCode` 处理；安全重试错误也必须使用新操作 ID |
| `indeterminate` | 上一进程已持久接纳，但在崩溃前没有可靠完成标记 | 视为“可能已经执行”，通过设备或业务后端对账，不能自动重放 |
| `completedWithoutResult` | 已知操作完成或同 ID 已使用，但响应因重启、过期、过大或缓存淘汰不可恢复 | 通过业务/设备状态对账，不能重放 |
| `unknown` | 当前保留窗口内没有该操作的证据 | 不代表设备未执行；只能由业务规则决定是否创建新的逻辑操作 |

页面刷新后可以使用相同来源、路由和操作 ID 查询：

```ts
const status = await bridge.getPluginInvocation(
  operationId,
  'printer',
  'print',
)
```

## 崩溃一致性边界

协调器在进入 Rust controller 前同步写入并 `fsync` “已接纳”记录，然后由独立监督任务执行插件调用；页面导航、Promise 丢弃或 WebView 销毁不会取消这条链。响应产生后先写入完成标记，再通知等待者。进程可能在原生组件产生副作用与完成标记之间崩溃，因此系统不会虚假承诺物理设备的 exactly-once；它会恢复为 `indeterminate`，并阻止同 ID 自动重放。

正常退出和应用更新会先关闭持久调用准入，再排空 controller 中的原生调用，最后等待完成标记落盘后才退出或安装更新。更新安装失败时，controller 与持久协调器会一起恢复准入。若整个进程异常终止，或正常排空超过全局退出上限，已经接纳但来不及可靠落盘的操作仍按上述规则恢复为 `indeterminate`，不会自动重放。

账本不保存 origin、`serviceId`、`method`、参数或响应，只保存 UUID、域分离 SHA-256 和时间/状态。响应仅保留在内存：单项最多 512 KiB、最多 64 项、通常保留 10 分钟；容量不足时优先淘汰最旧的已完成结果，不会淘汰正在执行的操作。持久完成记录保留 24 小时，未知完成记录保留 30 天，全局最多 65,536 项、每个授权来源范围最多 16,384 项；单一业务来源不能耗尽其他来源的全部防重放容量。常态接纳只做 O(1) 的来源计数和下一到期时间判断，只有真正到达最早过期时间才扫描并压缩账本。超过明确边界时拒绝新的持久调用，不会静默失去防重放证据。

账本损坏、路径不安全或无法落盘时，持久调用接口会禁用并在本地控制台/诊断包中报告脱敏错误码；旧 `invokePlugin` 仍可用于明确幂等或已具备业务侧防重的调用，但不能把它当作持久协调接口。

这两个方法是桥接协议 1 的向后兼容可选能力。`getSystemInfo()` 的可选 `capabilities.trackedInvocations` 声明区分“方法存在”“账本当前可用”和“停机期仍接收新调用”，并公开与实现同源的容量及保留边界。业务应把 `connectDesktop()` 返回的 `bridge` 和 `system` 一起传给 `supportsTrackedPluginInvocations` 或 `requireTrackedPluginInvocations`；只传 bridge 时只能检查 API 形状，不能证明运行时账本可用。旧桌面客户端仍能使用原有桥接方法，不会因本次扩展被强制升级。
