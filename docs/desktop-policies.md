# 桌面动作与受控进程策略

## 声明式快捷键

快捷键保存在桌面配置的 `keyBindings` 中，只能绑定到客户端内置动作，不能包含 JavaScript、Rust 表达式、命令行或任意代码：

```json
{
  "keyBindings": [
    {
      "shortcut": "control+shift+n",
      "action": "open-business-window",
      "enabled": true
    },
    {
      "shortcut": "control+shift+c",
      "action": "capture-business-window",
      "enabled": true
    },
    {
      "shortcut": "control+shift+a",
      "action": "capture-region",
      "enabled": true
    }
  ]
}
```

允许的动作只有：

- `open-business-window`
- `capture-business-window`
- `capture-region`
- `reset-business-zoom`
- `find-in-business-window`

配置限制为 32 项，启用的快捷键不能重复。`capture-region` 打开只具备截图 IPC 的本地全屏遮罩，用户确认后只向原业务窗口发送裁剪后的 PNG。保存配置时会先尝试注册完整的新集合；任一项失败时恢复旧集合，配置文件也不会被替换。旧 `keymap.json` 中的 `snippet` 和 `eval(...)` 不会迁移。

## 签名进程策略

旧配置中的 `processes` 路径只为迁移审计保留，新客户端永远不会执行它们。可启动项由发布方提供 `process-policy.json` 和 `process-policy.sig.json`，用户配置仅通过 `managedProcesses` 选择策略 ID：

```json
{
  "schemaVersion": 1,
  "processes": [
    {
      "id": "device-helper",
      "executable": "C:\\Program Files\\Bsoft\\DeviceHelper.exe",
      "sha256": "<64 lowercase hex characters>",
      "arguments": ["--managed"],
      "workingDirectory": "C:\\Program Files\\Bsoft",
      "singleton": true
    }
  ]
}
```

签名文件使用同一生产信任库，但签名密钥必须显式具备 `process-policy` 用途；只有 `plugin` 或其他用途的密钥会被拒绝：

```json
{
  "schemaVersion": 1,
  "keyId": "production-2026-01",
  "algorithm": "ed25519",
  "signature": "<base64 ed25519 signature>"
}
```

签名输入是 ASCII 域分隔符 `SSDEV-PROCESS-POLICY`、一个 `0x00` 字节，再拼接 `process-policy.json` 原始字节的 SHA-256（32 个二进制字节）。因此包括空白在内的任何策略文件改动都会使签名失效。

使用 [统一发布文档签名](release-signing.md) 中的 `ssdev-release-signing prepare/finalize` 完成语义校验、外部签名和用途隔离验签，不要人工拼接待签字节或封套。工具的审核摘要只记录受控进程条目数，不复制命令参数或路径到额外日志。

客户端只接受绝对可执行文件路径、固定参数和固定工作目录。每次启动前都会重新计算可执行文件 SHA-256；不匹配则拒绝启动。启动使用直接进程 API，不拼接 Shell 命令。Windows 上 `singleton: true` 会按完整可执行文件路径检查正在运行的进程，避免旧版按文件名模糊匹配造成误判。

选择的受控进程只在客户端启动时按已保存配置拉起。运行中保存配置或导入项目改变 `managedProcesses` 后，控制台会明确显示“需要重启”，暂停新业务窗口、新原生调用和交付结论；托盘、快捷键与 SSO 入口也不能绕过该边界。退出并重新启动客户端后才按新集合执行策略。若在重启前把选择恢复为本次启动时的集合，等待重启状态会解除；集合顺序变化不产生误报。该机制不是通用进程热编排器，也不会保存或展示启动参数和路径到诊断日志。

项目配置页会把当前已验签策略中的进程 ID 展示为复选项，并标明是否为单实例。该目录按 ID 稳定排序，只进入本地控制窗口；可执行路径、哈希、固定参数和工作目录不会进入 WebView。策略未安装或未通过验证时页面只显示稳定处理方向。若当前配置仍选择了新策略中已经不存在的 ID，页面会保留一项警告供实施人员取消，但取消后不能重新勾选该未知 ID。保存选择仍走普通配置的完整校验和提交链，不能直接启动或停止进程。

生产构建时把两个策略文件放入 `src-tauri/resources/`。`SSDEV_PROCESS_POLICY` 和 `SSDEV_PROCESS_POLICY_SIGNATURE` 只供 Debug 验证使用；Release 固定读取安装包资源，避免启动环境回放历史上签名有效但权限更宽的旧策略。没有有效签名策略时，`managedProcesses` 中的任何选择都会失败关闭，不会回退执行旧 `processes`。
