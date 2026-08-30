# 持久原生调用与结果协调

`invokePlugin` 保留旧 WebPlus 兼容语义。对打印、写卡、签名、收费设备等不能盲目重试的操作，业务应优先使用可选的 `invokePluginTracked`：为一次逻辑副作用生成一个 UUID v4，并在所有网络重试、页面刷新和状态查询中复用同一个 ID。

```ts
import {
  connectDesktop,
  createPluginOperationId,
  parsePluginOperationId,
  requireTrackedPluginInvocations,
  settleTrackedInvocation,
} from '@bsoft/ssdev-web-bridge'

const connection = await connectDesktop()
const bridge = requireTrackedPluginInvocations(
  connection.bridge,
  connection.system,
)
const operationId = createPluginOperationId()
const settlement = await settleTrackedInvocation(
  bridge.invokePluginTracked(
    operationId,
    'printer',
    'print',
    { documentId: '业务侧引用' },
  ),
)

if (settlement.kind === 'status' && settlement.status.state === 'completed') {
  console.log(settlement.status.response)
}
```

操作 ID 必须由安全随机源生成，并由业务流程保存。一个 ID 只能绑定同一来源、`serviceId`、`method` 和完整参数；重复提交相同内容会等待或返回同一次执行结果，换参数、换方法或换授权范围会硬失败。不要为同一个业务动作在超时或刷新后自动生成新 ID。

`createPluginOperationId()` 返回带品牌的 `PluginOperationId`。页面刷新后，从 IndexedDB、业务后端或其他项目自有持久记录取回的值仍是未知输入，必须先调用 `parsePluginOperationId(restoredValue)`；它只接受规范小写、带连字符、版本 4 且为 RFC 4122 variant 的 UUID，并以不包含输入值的固定错误拒绝损坏记录。生成的 `create<Plugin>TrackedApi()` 只接受这一品牌类型，避免在业务代码中把订单号、空值或旧字段误当 operation ID；底层桥的 `string` 参数保持兼容。SDK 不提供通用存储层，也不会替项目决定 ID 应与哪一笔业务记录绑定。

## 状态语义

| 状态 | 含义 | 业务动作 |
| --- | --- | --- |
| `pending` | 当前进程中同一操作仍在执行 | 继续查询，不能生成新 ID 重试 |
| `completed` | 已得到插件响应；`durable=true` 表示完成标记也已落盘，`false` 表示本次响应有效但重启后的恢复证据未确认 | 按 `response.ResCode` 处理；`durable=false` 时同时记录恢复风险，任何新业务动作仍使用新操作 ID |
| `indeterminate` | 上一进程已持久接纳，但在崩溃前没有可靠完成标记 | 视为“可能已经执行”，通过设备或业务后端对账，不能自动重放 |
| `completedWithoutResult` | 已知操作完成或同 ID 已使用，但响应因重启、过期、过大或缓存淘汰不可恢复 | 通过业务/设备状态对账，不能重放 |
| `unknown` | 当前保留窗口内没有该操作的证据 | 不代表设备未执行；只能由业务规则决定是否创建新的逻辑操作 |

业务项目不需要重复手写这张状态表。`settleTrackedInvocation(directPromise)` 是默认入口：成功时返回类型化 `status` 和稳定 `disposition`，拒绝或损坏状态时只返回脱敏失败 disposition，不复制原异常。内部的 `parseTrackedInvocationStatus(value)` 会严格校验状态对应的精确字段；`completed` 必须带有合法 JSON `response` 和布尔 `durable`，其他状态只能包含 `state`。`classifyTrackedInvocationStatus(status)` 把 `pending` 导向查询同一 operation ID；可靠落盘的 `completed` 导向处理原响应，`durable=false` 则处理响应并记录恢复风险；`indeterminate` 和 `completedWithoutResult` 都要求先对账；`unknown` 进入项目自己的恢复策略。解析器和两个分类器仍可单独使用，但统一结算可避免项目漏写其中一支。所有结果都固定返回 `automaticReplay: 'forbidden'`。这些纯函数不保存 ID、不发起查询、不轮询，也不会依据 `ResCode` 替业务创建另一笔逻辑操作。传入结算器的应是生成 API 或底层桥的直接 Promise，不要先在 `.then()` 中执行订单写入等业务处理，以免把业务自身异常误归为调用失败。

## 命令拒绝

tracked 调用或状态查询的 Promise 拒绝不代表设备未执行。Desktop 以 schema 1 的 `trackedInvocationError` 对象返回固定 `phase` 和脱敏 `code`，phase 只允许 `authorization`、`runtime`、`availability`、`invoke`、`status`；对象没有消息、路径、来源、路由、operation ID 或底层错误字段。统一结算器会调用 `classifyTrackedInvocationFailure(error)` 严格检查版本、固定字段集、phase 和有界 code：合法对象得到 `query-same-operation-or-reconcile`，旧客户端字符串、普通 `Error`、额外字段或损坏状态统一得到 `treat-as-possibly-executed`；两者的 `automaticReplay` 都是 `forbidden`，结算结果不带原异常。业务可以显示稳定 code 对应的项目提示，但不得解析本地化文案或据此生成新 ID。

页面刷新后可以使用相同来源、路由和操作 ID 查询：

```ts
const statusSettlement = await settleTrackedInvocation(
  bridge.getPluginInvocation(operationId, 'printer', 'print'),
)
```

由本地映射工作台或 `ssdev-plugin-tool client/web-kit` 生成的 TypeScript 文件会额外导出 `create<Plugin>TrackedApi()`。将上面的 `bridge` 传给该工厂后，每个公开方法同时拥有类型化调用和状态查询入口，继续绑定清单中的 service/method 和参数/响应类型；普通 `<Plugin>Client` 与现有 fixture 用法保持不变。生成 API 不替业务保存 operation ID，也不自动轮询或重试。

## 崩溃一致性边界

协调器在进入 Rust controller 前同步写入并 `fsync` “已接纳”记录，然后由独立监督任务执行插件调用；页面导航、Promise 丢弃或 WebView 销毁不会取消这条链。响应产生后先写入完成标记，再通知等待者。监督层还会观察工作流任务本身：任务在持久接纳前异常终止时释放全部等待者并返回稳定失败，允许业务仍用同一操作 ID 重试；接纳后异常终止则根据账本发布 `indeterminate` 或 `completedWithoutResult`，不会永久停留在 `pending`，正常退出也不会被遗留计数拖住。若账本复核本身失败，结果保守收敛为 `indeterminate`。进程可能在原生组件产生副作用与完成标记之间崩溃，因此系统不会虚假承诺物理设备的 exactly-once；它会恢复为 `indeterminate`，并阻止同 ID 自动重放。

正常退出和应用更新会先关闭持久调用准入，再排空 controller 中的原生调用，最后等待完成标记落盘后才退出或安装更新。更新安装失败时，controller 与持久协调器会一起恢复准入，安装器接管前保留的原业务窗口可以继续工作，无需重新打开。若整个进程异常终止，或正常排空超过全局退出上限，已经接纳但来不及可靠落盘的操作仍按上述规则恢复为 `indeterminate`，不会自动重放。

账本不保存 origin、`serviceId`、`method`、参数或响应，只保存 UUID、域分离 SHA-256 和时间/状态。响应仅保留在内存：单项最多 512 KiB、最多 64 项、通常保留 10 分钟；容量不足时优先淘汰最旧的已完成结果，不会淘汰正在执行的操作。持久完成记录保留 24 小时，未知完成记录保留 30 天，全局最多 65,536 项、每个授权来源范围最多 16,384 项；单一业务来源不能耗尽其他来源的全部防重放容量。常态接纳只做 O(1) 的来源计数和下一到期时间判断，只有真正到达最早过期时间才扫描并压缩账本。超过明确边界时拒绝新的持久调用，不会静默失去防重放证据。

账本损坏、路径不安全、容量耗尽或无法落盘时，桌面与本地控制台仍会启动，持久调用接口则失败关闭；旧 `invokePlugin` 仍可用于明确幂等或已经具备业务侧防重的调用，但不能把它当作持久协调接口。首页会直接提示打印、写卡等非幂等流程暂停，安全页按脱敏稳定错误码给出磁盘/权限检查、导出诊断、备份现场或等待保留记录过期等建议，部署自检继续阻断交付。客户端不会自动删除或重建账本，因为其中的未完成记录可能代表已经发生但尚未完成业务对账的设备副作用；人工恢复前必须先保留现场并按项目规则对账。

这两个方法是桥接协议 1 的向后兼容可选能力。`getSystemInfo()` 的可选 `capabilities.trackedInvocations` 声明区分“方法存在”“账本当前可用”和“停机期仍接收新调用”，并公开与实现同源的容量及保留边界。业务应把 `connectDesktop()` 返回的 `bridge` 和 `system` 一起传给 `supportsTrackedPluginInvocations` 或 `requireTrackedPluginInvocations`；只传 bridge 时只能检查 API 形状，不能证明运行时账本可用。旧桌面客户端仍能使用原有桥接方法，不会因本次扩展被强制升级。
