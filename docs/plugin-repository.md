# 签名插件仓库协议 v1

插件仓库只负责发布不可变的 `.ssdev-plugin` 文件和短期有效索引。客户端不接受业务页面传入任意下载 URL；本地控制台只提交插件 ID，可选版本由签名索引解析。

## 索引

```json
{
  "schemaVersion": 1,
  "issuedAt": 1786377600,
  "expiresAt": 1786464000,
  "entries": [
    {
      "pluginId": "reader-plugin",
      "version": "2.3.1",
      "url": "https://plugins.example.internal/packages/reader-plugin-2.3.1.ssdev-plugin",
      "sha256": "<64 lowercase hex characters>",
      "size": 1234567
    }
  ]
}
```

- `issuedAt`、`expiresAt` 是 Unix 秒，索引有效期必须大于零且不超过 31 天。
- 同一 `pluginId + version` 不能重复；客户端未指定版本时选择最高 SemVer。
- 包 URL 必须是无凭据、无 fragment 的 HTTPS URL。
- 包大小为 1 字节到 512 MiB；下载字节数必须与签名值完全一致。

## 从已验签包生成目录

不要人工抄写 `pluginId`、`version`、`sha256` 或 `size`。先建立只包含本地包路径和最终 HTTPS URL 的构建规格；相对包路径以规格文件所在目录为基准：

```json
{
  "schemaVersion": 1,
  "issuedAt": 1786377600,
  "expiresAt": 1786464000,
  "packages": [
    {
      "package": "packages/reader-plugin-2.3.1.ssdev-plugin",
      "url": "https://plugins.example.internal/packages/reader-plugin-2.3.1.ssdev-plugin"
    }
  ]
}
```

然后生成确定性目录：

```powershell
cargo run --locked -p ssdev-plugin-tool -- catalog `
  --spec C:\secure-release\catalog-build.json `
  --trust-store C:\secure-build-inputs\plugin-trust.json `
  --catalog C:\secure-release\catalog.json
```

工具拒绝符号链接和重复包路径，用与桌面安装器相同的安全解包路径验证每个插件的内部签名，并从签名覆盖的 `plugin.json` 提取 ID/版本。它在验证前后分别计算包大小和 SHA-256，检测生成过程中的文件变化；URL 必须唯一，目录按 `pluginId + version` 排序，因此相同输入产生相同 JSON。输出报告包含目录 SHA-256，但不输出本地包路径。

目录生成后，再使用 [统一发布文档签名](release-signing.md) 的 `prepare/finalize --kind plugin-catalog` 交给 KMS/HSM 签名。目录文件或任一包在两步之间变化都会被后续摘要校验发现。

## 索引签名

```json
{
  "schemaVersion": 1,
  "keyId": "production-2026-01",
  "algorithm": "ed25519",
  "signature": "<base64 ed25519 signature>"
}
```

签名输入为 ASCII `SSDEV-PLUGIN-CATALOG`、一个 `0x00` 字节，再拼接索引原始字节的 SHA-256（二进制 32 字节）。密钥必须在生产信任库中显式声明 `plugin-catalog` 用途且状态为 `active`；只有 `plugin` 用途的包签名密钥不能签目录。两者应使用独立 `keyId` 便于隔离、轮换和撤销。目录短期过期不能替代密钥吊销：`retired` 只停止官方新签发，`revoked` 才会让客户端立即拒绝该键的所有目录。

使用 [统一发布文档签名](release-signing.md) 中的 `ssdev-release-signing prepare/finalize --kind plugin-catalog`。签名准备阶段会再次验证目录当前有效、有效期不超过 31 天、条目 SemVer/HTTPS/摘要/大小合法且没有重复版本；封包签名密钥不能越权签目录。

## 客户端校验顺序

1. 两个索引 URL 都必须使用 HTTPS，启用系统证书校验、连接/总超时和有限重定向。
2. 限制索引和签名各 4 MiB，再验证 Ed25519 和有效期。
3. 只按插件 ID/版本选择签名条目，流式下载到隐藏临时目录。
4. 同时限制实际下载大小并校验签名索引中的精确大小、SHA-256。
5. 解包后再次验证 `plugin.json` 的 ID/版本以及插件内部完整文件签名。
6. 在签名暂存目录中，为候选插件使用的每种 x86/x64 架构启动一次真实隔离宿主，完成认证管道、二次验签和 Health 往返后立即停止；预检不执行业务方法，也不停止当前健康宿主。失败时旧目录和旧路由完全不变。
7. 预检成功后进入目标插件自己的维护锁，只排空该插件的在途调用并停止它的活动宿主；其他插件继续服务。写入有界事务日志后原子切换目录，对目标目录再次验签并验证完整路由，失败则恢复旧目录。
8. 二次验签和路由验证成功后，只原子替换目标插件的路由；跨插件服务冲突在旧路由删除前失败。随后以原子重命名提交事务。崩溃后启动恢复器会回滚未提交事务，并清理已提交或废弃的暂存目录。

因此仓库 TLS、仓库索引签名、下载摘要和插件包签名是独立防线。索引过期、系统时钟异常、重放旧索引、内容替换、身份不一致或降级都会失败关闭。

桌面配置必须成对提供：

```json
{
  "pluginCatalogUrl": "https://plugins.example.internal/catalog.json",
  "pluginCatalogSignatureUrl": "https://plugins.example.internal/catalog.sig.json"
}
```
