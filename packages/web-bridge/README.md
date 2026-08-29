# @bsoft/ssdev-web-bridge

业务前端使用的框架无关 SSDEV Desktop 桥接契约。该包只连接由受控 Tauri 业务窗口注入的 `window.ssdevDesktop`，不会尝试 localhost HTTP、WebSocket 或浏览器扩展回退。

```ts
import { connectDesktop } from '@bsoft/ssdev-web-bridge'

const { bridge, system, context } = await connectDesktop()
const result = await bridge.invokePlugin('card.reader', 'readCard', {
  timeout: 30,
})
```

业务前端单元测试不需要伪造完整桌面对象。生成的插件客户端只依赖最小 `PluginInvoker`，可以注入 SDK 提供的严格 fixture invoker：

```ts
import { createPluginFixtureInvoker } from '@bsoft/ssdev-web-bridge'
import { ReaderPluginClient } from './generated/reader-plugin-client'

const invoker = createPluginFixtureInvoker([{
  serviceId: 'card.reader',
  method: 'readCard',
  parameters: { timeout: 30 },
  response: {
    ResCode: 0,
    ResData: { ReturnValue: 0, cardNumber: 'TEST-001' },
  },
}])
const reader = new ReaderPluginClient(invoker)
```

fixture 按 service、method 和完整 JSON 参数精确匹配，对象键顺序不影响结果；省略参数与 `{}` 等价。重复定义、非 JSON 数据、超出 JavaScript 安全范围的整数和未声明调用都会显式失败，错误不复制参数内容；精确 64 位整数应按插件契约使用字符串。每次调用返回独立副本，测试代码修改结果不会污染下一用例。该工具不会写入 `window.ssdevDesktop`，也不模拟持久操作 ID、超时、重试、DLL/COM 行为或硬件副作用，只用于业务前端单元测试，不能替代 Windows 插件黄金矩阵。

已经完成脱敏、精确响应复核并绑定插件版本的正式黄金矩阵，可以通过 `ssdev-plugin-tool web-fixtures` 生成上述数组，避免业务项目再次手抄 route 和数据。生成器拒绝草稿、占位符、未解除复核项和同输入多响应歧义；输出仍包含矩阵原始测试数据，提交前必须单独评审。

单插件正式交接优先使用 `ssdev-plugin-tool web-kit`，一次生成同版本的 `client.ts`、`fixtures.ts` 和 `ssdev-web-kit.json`。清单绑定插件 ID/版本、API、元数据、矩阵和两个 TypeScript 文件摘要，生成失败不会留下部分目录，避免业务项目把新版客户端与旧版 fixture 混用。业务 CI 使用 `ssdev-plugin-tool web-kit-check --kit <目录>` 拒绝缺失、额外、链接或摘要漂移文件；该检查只验证未签名目录相对自身清单的一致性。接入包是待代码评审的源码制品，不包含原生组件，也不替代插件签名或 Windows 实机验收。

接收 Web 接入包和 SDK 制品后，还应在二者对应的 SSDEV 源码提交中执行组合门禁：

```bash
node scripts/web-integration-consumer.mjs verify \
  --kit vendor/reader-2.3.1-web-kit \
  --sdk-directory artifacts/ssdev-web-bridge-sdk
```

该命令先复核 Web kit 固定文件集、摘要和来源头，再复核 SDK `.tgz`、当前锁定源码摘要及其已有消费者冒烟证据；随后只使用已校验的内存快照，在临时业务项目中禁用生命周期脚本并离线安装 SDK，以严格 NodeNext 配置编译 `client.ts + fixtures.ts`，最后通过 SDK fixture invoker 实际覆盖生成客户端的每个公开方法和每条 fixture route。成功报告绑定插件版本、kit 清单摘要、SDK 版本、归档/源码摘要与覆盖计数，不返回本机路径。它证明这两份精确制品当前可以组合消费，但二者仍是未签名的前端交接物，不能替代受保护分支评审、插件签名或 Windows 硬件矩阵。

真实业务项目包含多个插件时，不需要建立另一种集合制品；对同一 SDK 重复传入经过评审的 kit：

```bash
node scripts/web-integration-consumer.mjs verify-set \
  --kit vendor/reader-2.3.1-web-kit \
  --kit vendor/writer-1.4.0-web-kit \
  --sdk-directory artifacts/ssdev-web-bridge-sdk
```

联合门禁固定排序最多 64 个 kit，拒绝重复路径、ASCII 大小写归一后重复的插件 ID、超出总量边界以及跨插件重复 `serviceId/method`；全部源码在一个临时项目中用同一 SDK 编译，并由一个共享 fixture invoker 覆盖所有客户端。报告包含无路径的 kit 身份/版本/清单摘要列表及确定性集合摘要，可直接作为业务 CI 的精确依赖证据。

`connectDesktop()` 会先读取并运行时校验最小系统声明，再检查协议版本。页面不在授权桌面窗口中时抛出 `DesktopBridgeUnavailableError`；系统声明损坏或与当前能力 schema 自相矛盾时抛出带稳定 `reason` 的 `InvalidDesktopDeclarationError`；协议不兼容时抛出 `UnsupportedDesktopProtocolError`。业务代码应显示客户端升级或修复提示，不要把这些错误静默切换到 HTTP。

能力 schema 与桥接协议独立演进。SDK 对当前 schema 严格检查布尔状态、错误码和全部容量边界；遇到更高的未知 schema 时保留并冻结原声明，但 `getTrackedInvocationCapabilities()` 返回 `null`，不会仅因可选 JavaScript 方法存在就误报持久调用可用。升级 SDK 后才能使用新 schema 的能力。

SDK 显式导出 `CURRENT_BRIDGE_PROTOCOL_VERSION`；旧名称 `CURRENT_PROTOCOL_VERSION` 仅作为源码兼容别名保留。该版本只治理注入业务页面的公开桥接，不与 controller/plugin-host 的内部命名管道协议绑定。

不要在业务代码中散落 `-32001` 等魔法数字。SDK 的 `classifyPluginInvocationResponse()` 会把四种由 controller 在原生执行前产生的拒绝分类为 `execution: 'not-executed'`；这些代码由 controller 独占，宿主或厂商组件返回同码会被改写成执行状态未知的一般宿主失败。`canRetryPluginInvocationWithBackoff()` 只对容量饱和、执行槽截止和插件维护返回 `true`，退出排空返回 `retry: 'after-restart'`。其他成功、厂商错误、宿主错误和一般超时都返回 `retry: 'never-automatically'`。这些函数只分类，不会自动循环重试。

```ts
import {
  canRetryPluginInvocationWithBackoff,
  classifyPluginInvocationResponse,
} from '@bsoft/ssdev-web-bridge'

const response = await bridge.invokePlugin('card.reader', 'readCard', {})
const disposition = classifyPluginInvocationResponse(response)
if (canRetryPluginInvocationWithBackoff(response)) {
  // 由业务设置很小的次数和总时限；这里不会自动重试。
} else if (disposition.retry === 'after-restart') {
  // 结束当前流程，等待客户端重新启动。
}
```

插件调用容量饱和时返回 `{ ResCode: -32001, ResData: "native plugin invocation capacity is busy; retry later" }`。该请求保证未进入插件宿主；业务代码可以按上面的 SDK 分类结果做有上限的退避重试，不能把未被分类的超时或插件错误自动重试为潜在的重复硬件操作。

页面导航、组件卸载或业务代码丢弃 Promise 只会让页面停止等待结果，不会撤销已经被桌面端接纳的原生调用。桌面端会让该调用独立执行到正常响应或受控超时，以保持命名管道请求/响应顺序；调用方不得把“没有继续等待”视为“设备没有执行”，也不得因此自动重试。当前契约没有提供硬件操作取消能力。

对打印、写卡等非幂等操作，优先使用可选的 `invokePluginTracked` 和 `getPluginInvocation`。用 `createPluginOperationId()` 为一次逻辑动作生成 UUID v4，并在页面刷新、重复提交和查询时复用；桌面端会在执行前持久记录该 ID，相同来源和完整请求只执行一次，同 ID 改参数会失败。`indeterminate` 与 `completedWithoutResult` 都表示不能自动重放；保留窗口、崩溃边界和完整示例见 SSDEV Desktop 主仓库的 `docs/tracked-invocations.md`。

判断该能力时应使用 `supportsTrackedPluginInvocations(connection.bridge, connection.system)`，或把同样两个值传给 `requireTrackedPluginInvocations`。`system.capabilities.trackedInvocations` 会区分客户端是否支持、账本是否成功启动以及当前是否仍接收新操作，并声明容量和保留边界；省略 `system` 只能兼容性地检查方法是否存在，不能证明运行时可用。

桌面端进入退出或更新重启排空阶段后，新调用返回 `{ ResCode: -32002, ResData: "native plugin controller is stopping; request was not executed" }`，并保证没有进入插件。业务页应结束当前流程并等待客户端重新启动，不要在正在退出的进程内循环重试。

同一插件宿主会串行访问厂商组件。请求在其配置的统一截止时间内没有拿到执行槽时返回 `{ ResCode: -32003, ResData: "native plugin execution lane timed out; request was not executed" }`。这个响应也保证未执行，可以做有上限的退避重试；截止时间覆盖等待执行槽和实际 IPC 调用，不会在锁前无限排队。

签名插件安装或热更新排空期间，只有发往目标插件的新请求返回 `{ ResCode: -32010, ResData: "native plugin controller is reloading; request was not executed" }`，其他插件继续服务；显式完整重新扫描时该错误可能覆盖全部插件。请求不会跨越一次路由/插件版本切换后再意外执行；业务页可以在维护结束后重新发起，但必须有退避上限，不能持续轮询压测客户端。

尚未接入组织 npm 仓库时，主分支默认 CI 会上传保留 14 天的 `ssdev-web-bridge-sdk` 平台无关制品。目录固定只包含可安装 `.tgz` 和 `ssdev-web-bridge-sdk.json`，清单绑定包名、版本、大小、归档 SHA-256，以及 README、共享契约、锁文件、package manifest、TypeScript 源码和编译配置的有序联合摘要；Pull Request 只构建验证，不上传未合并制品。打包流程还会在临时业务项目中禁用生命周期脚本、强制离线安装刚生成的 `.tgz`，实际执行 ESM fixture 调用并用仓库锁定的 TypeScript 编译器检查公开类型，全部成功后才会原子发布目录，清单中的 `consumerSmokeVerified` 记录该次构建证据。业务项目应从目标提交对应的 Actions run 下载整个目录，核对清单后用 `.tgz` 安装，并把精确归档摘要纳入自己的依赖评审，不能只按仍处于开发期的 `0.1.0` 文件名判断内容。

本地或受控流水线可运行 `node scripts/web-bridge-package.mjs build --output <新目录>`；业务接收前用 `verify --directory <目录>` 重算固定文件集、归档和当前锁定源码摘要。构建器先执行 TypeScript 编译，使用 `npm pack` 生成可重复归档，在同一临时目录完成自检后才原子发布目标目录。SDK 回归仍会执行 `npm pack --dry-run`，固定包内只能包含 README、共享契约、编译后的 ESM/类型声明和 package manifest，不得夹带源码、测试或 `node_modules`。该 CI 制品没有组织签名，不是正式 npm 发布；发布到组织内部 npm 仓库前再由批准的版本治理变更移除 `private` 并接入组织签名，当前仓库保持 `private: true`，避免误发公共 registry。
