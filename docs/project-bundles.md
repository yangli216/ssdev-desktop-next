# 项目部署包

`.ssdev-project` 是面向实施交付的项目迁移单元，包含当前有效桌面配置、所有已验证签名插件和本机动态映射。它解决的是配置机到目标 Windows 机器的可重复迁移，不替代客户端 NSIS 安装包。

## 控制台流程

1. 在配置机完成项目地址、签名插件和本地映射配置，并确保部署自检没有阻塞项。
2. 在“项目配置 → 项目部署包”导出当前项目草稿，并由组织发布系统生成同目录 detached 签名封套。
3. 将 `.ssdev-project` 和对应的 `.ssdev-project.sig.json` 一起交付，在目标机器选择项目包。此时只执行读取、组织签名、组件验签、路由检查和宿主预检，不修改当前项目。
4. 查看业务来源、插件、映射、服务和宿主预检数量后，确认导入。
5. 导入完成后重新执行部署自检并打开真实业务环境。

## 包结构与信任边界

项目包使用受限 ZIP 容器，固定包含：

- `project.json`：schema、创建客户端版本、配置摘要以及组件 ID、类型、版本、大小和 SHA-256；
- `config.json`：通过 `ssdev-config` 完整校验的桌面配置；
- `components/*.ssdev-plugin`：从已安装目录重新生成的确定性签名插件包；
- `components/*.ssdev-mapping`：本机管理员创建的动态映射及其组件。

项目包最多包含 128 个组件，单组件最大 1 GiB，容器及解压内容最大 4 GiB。读取过程拒绝覆盖、重复条目、未声明文件、路径穿越、符号链接、特殊文件、摘要不一致和非规范插件 ID。

项目包使用独立的 `project-bundle` 信任用途，签名 payload 为 ASCII `SSDEV-PROJECT-BUNDLE`、一个 `0x00` 字节，再拼接整个 `.ssdev-project` 原始文件的 SHA-256（二进制 32 字节）。因此配置、本地映射、内部签名插件、清单、ZIP 元数据或重新封包中的任意变化都会使旁签失效；内部签名插件仍会逐个执行自身的组织签名和完整文件清单验证，两层信任不能相互替代。

控制台只导出未签名草稿，不持有生产私钥。正式交付使用 [统一发布文档签名](release-signing.md) 的外部 KMS/HSM 流程：

```powershell
cargo run --locked -p ssdev-release-signing -- prepare `
  --kind project-bundle `
  --document C:\secure-release\clinic.ssdev-project `
  --key-id project-delivery-2026-01 `
  --trust-store C:\secure-build-inputs\plugin-trust.json `
  --request C:\secure-release\clinic.project.signing-request.json

# KMS/HSM 对请求中的 payloadBase64 解码结果签名后：
cargo run --locked -p ssdev-release-signing -- finalize `
  --kind project-bundle `
  --document C:\secure-release\clinic.ssdev-project `
  --request C:\secure-release\clinic.project.signing-request.json `
  --signature C:\secure-signing-output\clinic.project.sig.base64 `
  --trust-store C:\secure-build-inputs\plugin-trust.json `
  --envelope C:\secure-release\clinic.ssdev-project.sig.json
```

正式客户端按固定规则在项目包同目录查找 `<完整项目包文件名>.sig.json`，例如 `clinic.ssdev-project.sig.json`。缺少封套、用途不匹配、签名无效、密钥已吊销或项目包在读取期间变化时，预检会失败关闭；运行时为计划轮换继续接受 `retired` 有效签名。只有显式启用未签名插件的 Debug 模式可预检未签名项目包，不能用于正式交付。

## 预检与导入语义

只读预检在修改目标机器前完成以下工作：

- 校验项目配置和当前来源策略；
- 验证覆盖整个项目包的 `project-bundle` 组织签名；
- 核对组件清单、大小和 SHA-256；
- 验证每个发布插件的身份、版本、完整文件清单和签名密钥状态；
- 拒绝默认插件降级；
- 验证本地映射定义和组件路径；
- 拒绝同一 ID 在签名插件和本地映射之间隐式换型；
- 将项目组件与目标机器现有插件合并，检查服务路由冲突；
- 将目标配置中的全部业务来源与合并后的规范方法名和 alias 做双向授权覆盖核对；
- 启动候选 x86/x64 隔离宿主完成真实预检。

确认导入后，客户端先写入项目级持久事务，再进入一次全局维护窗口，将全部签名插件和本地映射切换到候选目录、重新发现联合清单并一次替换控制器路由，最后切换项目配置。任一组件、联合路由或配置切换失败都会按相反顺序恢复全部旧组件、旧路由和旧配置，不会留下“部分插件已升级但仍使用旧配置”的混合状态。

项目事务以一次原子重命名记录统一提交点。提交点之前崩溃或断电，下次启动恢复旧配置并回滚全部未提交组件；提交点之后崩溃，则保留新配置并完成全部组件事务清理。签名插件与本地映射都使用有界、单组件 ID 的持久日志，恢复过程可重复执行。运行中发现需要恢复旧配置的未提交项目事务时会要求重启，避免只修改磁盘配置而让内存配置继续停留在新版本。

导入不会删除项目包中未声明的现有插件。现阶段客户端按单项目工作区导出当前全部有效能力；后续如果引入明确的项目级插件选择，再增加受控的“同步并移除”模式，不能在缺少所有权信息时自动删除本机插件。
