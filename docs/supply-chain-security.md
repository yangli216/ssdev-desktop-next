# 依赖与构建供应链

## 不变量

- Rust 使用仓库内 `Cargo.lock`，CI、构建和测试命令必须携带 `--locked`。
- npm 只使用仓库内 `package-lock.json` 和 `npm ci`；锁文件 tarball 固定到 `https://registry.npmjs.org/` 并由 npm integrity 字段校验。
- npm 默认禁用依赖生命周期脚本。确实需要脚本的依赖必须先审查脚本内容，再在单个受控步骤中显式启用，不能全局放开。
- GitHub Actions 必须固定到完整提交 SHA，版本标签只作为行尾可读注释，不能直接执行可变标签。
- Cargo Git 依赖或 npm 非官方 registry、Git、文件 URL 不得静默引入；确需例外时必须记录来源、固定不可变提交或摘要，并在评审中说明退出方案。

## 自动门禁

`.github/workflows/ssdev-supply-chain.yml` 在依赖文件变更、手动触发和每周定时运行：

1. 使用固定版本的 `cargo-audit` 审计完整 `Cargo.lock`；漏洞直接失败。由于统一锁文件包含 Linux-only Tauri 依赖，脚本会继续把 `unmaintained`、`unsound` 等警告逐项反查 x86/x64 Windows 依赖图，只有两个生产图都不可达才允许通过。
2. 使用 npm 官方漏洞库审计桌面端和 Web Bridge 的完整锁文件，`high`/`critical` 漏洞使检查失败。
3. 所有门禁 Action 均固定到完整提交 SHA，避免上游标签被移动后改变执行代码。

Windows 发布包额外携带经路径脱敏的 CycloneDX 1.5 SBOM。Rust SBOM分别描述 x64 桌面主程序与 x86/x64 插件宿主的真实目标依赖图，npm SBOM从锁文件生成；安装验收不仅检查格式和目标三元组，还要求桌面 SBOM 明确包含持久调用账本与 controller、宿主 SBOM 包含原生执行与 IPC、npm SBOM 包含 Tauri API 与 Vue。schema 2 `release.json` 进一步绑定 Git 提交及脏状态、固定锁文件和配置摘要，以及 Rust/Node/npm/CycloneDX 工具版本；正式签名包拒绝脏源码和合成版本。所有溯源元数据、SBOM、安装器、更新包、签名和公开策略都被纳入同一份签名 SHA-256 产物清单。

当前不维护永久忽略列表。若公告确属不可达代码或上游暂时无修复，例外必须绑定具体公告编号、责任人和到期时间，不能只降低全局严重级别，也不能用 Cargo.lock 包含跨平台依赖作为笼统忽略理由。
