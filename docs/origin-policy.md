# 签名业务来源策略

业务页面能够间接调用本地 DLL，因此“页面从哪里加载”属于发布安全边界。严格模式由签名策略逐个批准来源；多项目兼容模式必须由签名策略显式开启，再由当前 `config.json`、受控 WebView 和已签名插件共同限定边界。正式构建必须携带 `origin-policy.json` 与对应 Ed25519 签名；签名只能由信任库中显式具备 `origin-policy` 用途的组织公钥验证，插件或目录签名密钥不能越权。

```json
{
  "schemaVersion": 2,
  "businessGrants": [
    {
      "origin": "https://his.example.internal",
      "services": [
        {
          "serviceId": "identity-card",
          "methods": ["read", "reset"]
        },
        {
          "serviceId": "receipt-printer",
          "methods": ["print"]
        }
      ]
    }
  ],
  "allowConfiguredBusinessOrigins": false,
  "navigationOrigins": ["https://sso.example.internal"],
  "externalOrigins": ["https://help.example.internal"],
  "allowInsecureHttp": false
}
```

- `businessGrants`：可以获得窄 Web Bridge 的页面来源，以及该来源能够调用的精确 `serviceId` 和 `method`；至少一项来源、每个来源至少一个服务、每个服务至少一个方法。
- `allowConfiguredBusinessOrigins`：兼容多项目内网部署。为 `true` 时，不再要求逐个预签名业务 IP、域名和端口；只有当前桌面配置明确列出的业务来源可获得桥接，并且只能调用已验签发布插件或由本机控制窗口明确创建/导入并成功预检的本地映射所声明的服务和方法。
- `navigationOrigins`：允许业务窗口在 SSO 流程中导航，但不会获得插件桥接。
- `externalOrigins`：业务页面可请求系统默认浏览器打开的额外来源。
- `allowInsecureHttp`：默认必须为 `false`。只有无法立即升级的院内旧站点才能显式启用；严格模式仍需逐个列出来源，兼容模式则以当前桌面配置为来源边界。

`allowConfiguredBusinessOrigins` 与 `allowInsecureHttp` 同时为 `true` 时，适用于地址随项目变化且无法部署 HTTPS 的院内系统。它们不会放宽 SSO POST；SSO 始终要求 HTTPS 且禁止重定向，具体边界见 [SSO 安全边界](sso-security.md)。

正式迁移审计必须从已复验试点 manifest 派生候选安装包将携带的这份策略、旁签和发布信任库，不能再用手工参数替换。审计使用运行时相同规则核对旧配置；获准保留的内网 HTTP 只以脱敏计数进入 schema 3 迁移证据。schema 7 生产切换策略与 schema 5 Windows 包证据随后共同绑定同一个策略 SHA-256，避免审计通过后换入另一份策略。

策略项必须是纯 origin，例如 `https://his.example.internal`；禁止凭据、路径、查询参数和片段。严格模式下，每类最多 128 项，每个业务来源最多 256 个服务、每个服务最多 256 个方法，来源、服务和方法都必须唯一。兼容模式不使用 `businessGrants` 限制具体项目地址或插件路由，而以当前用户配置、受控 WebView 和已签名插件清单作为边界。签名插件通过本地包、仓库安装/更新/回退或管理员显式重扫进入活动路由前，每条公开规范方法名及 alias 已经必须被至少一个当前配置来源授权；无需让每个来源都拥有每项插件能力。反向变更同样失败关闭：普通配置保存或导入只要改变业务来源集合，就从控制器读取一致、去重的当前活动插件清单，并拒绝让任一现有签名路由失去全部授权来源。只修改快捷键、开机启动等非来源字段不会被历史授权问题连带阻断；需要同时替换来源与插件的项目切换必须使用原子项目部署包。本地动态映射为保留实施调试流程而暂不受上述单项门禁阻断。项目包导出/导入和部署自检仍会把当前业务来源与签名插件及本地映射的全部公开路由联合对账：每个当前来源至少覆盖一条已安装路由，每条已安装路由至少由一个当前来源覆盖；否则即使策略签名和配置来源本身合法，也不能报告可交付。

schema 1 的 `businessOrigins` 属于无范围授权，正式客户端不再接受。新增插件、服务或方法不会自动授权给既有业务站点；发布方必须明确评审、更新 schema 2 策略并重新签名。

## Tauri IPC 双层授权

远程页面并不会因为被加载进 WebView 就自动获得 Tauri 命令。客户端启动或保存配置时，会为当前配置启用且符合所选策略模式的每个精确业务 origin 注册运行时 Tauri ACL：

- `business-*` 窗口只获得插件调用、最小系统声明、业务窗口截图、受控外链、新业务窗口、悬浮窗创建和关闭七类应用命令。严格模式按 origin 对 `serviceId` 和 `method` 做精确授权；兼容模式则要求 origin 仍在当前配置中，并由当前已验签发布插件及已预检本地映射的合并清单约束可调用路由。业务窗口本身没有创建、导入、修改、删除或调试本地映射的命令权限。
- `floating-*` 窗口只获得关闭自身和提交结果两类命令。
- SSO `navigationOrigins` 不注册远程 ACL，因此即使页面直接访问 `window.__TAURI_INTERNALS__` 也无法到达应用命令。
- 控制台与截图遮罩使用仅限本地内置页面的独立静态 capability；控制台禁止导航到其他页面，每次高权限调用仍会复核窗口标签和内置页面 URL。
- 内置页面启用 CSP 和原型冻结：生产环境只允许同包脚本与样式、Tauri IPC 和截图所需的 `data:` 图片，禁止对象、表单、frame、worker、媒体和任意外部网络连接。开发环境只额外允许固定 Vite HMR WebSocket。

Tauri ACL 是第一层；Rust 命令处理器仍会再次校验窗口标签、当前页面 origin、当前用户配置和插件签名。严格模式还复核来源与服务/方法授权。配置移除某个来源后，即使进程内曾为它注册过 ACL，Rust 层也会立即拒绝其后续调用；重启后只重新注册当前配置中的来源。

Release 固定读取安装包内的信任库、来源策略和策略签名，启动环境不能替换它们；相应环境变量只在 Debug 验证中生效。这同时阻止替换信任根和回放历史上签名有效但范围更宽的旧来源策略。

## 签名格式

签名文件格式与进程策略相同：

```json
{
  "schemaVersion": 1,
  "keyId": "production-2026-01",
  "algorithm": "ed25519",
  "signature": "<base64 signature>"
}
```

待签名字节为 `SSDEV-ORIGIN-POLICY`、一个 `0x00` 字节，再拼接 `origin-policy.json` 原始字节的 SHA-256。包括空白在内的策略改动都会使签名失效。生产签名应在 KMS/HSM 或受控发布流水线完成。不要人工拼接域分隔字节或签名封套；使用 [统一发布文档签名](release-signing.md) 中的 `ssdev-release-signing prepare/finalize`，私钥不进入工具。

构建前可使用统一入口离线验证：

```bash
cargo run --locked -p ssdev-release-signing -- verify \
  --kind origin-policy \
  --document origin-policy.json \
  --envelope origin-policy.sig.json \
  --trust-store plugin-trust.json
```

`scripts/build-windows.ps1` 会强制验证策略并临时注入资源；无论构建成功或失败，工作区中原有的资源文件都会恢复。
