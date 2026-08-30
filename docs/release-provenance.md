# Windows 发布溯源元数据

每个 Windows bundle 的 `metadata/release.json` 使用 schema 2，并被纳入 `metadata/artifacts.json` 的完整文件清单，再由独立的 Tauri 更新密钥签名。它用于回答“这个安装包由哪次源码、哪些锁文件和什么工具链构建”，不依赖安装包文件名或 CI 日志猜测。

## 绑定内容

- 应用版本、产品名和应用标识；
- 是否要求 Authenticode，以及是否使用仅供 CI 升级测试的合成版本覆盖；
- Git `HEAD` 对象 ID 和工作区脏状态；
- `Cargo.lock`、`rust-toolchain.toml`、桌面端及 Web Bridge 的 `package-lock.json`、Tauri 配置的 SHA-256；
- `rustc`、`cargo`、Node.js、npm 和固定版 `cargo-cyclonedx` 的单行版本。

字段集合固定、JSON 拒绝未知字段，路径和本机身份不会写入元数据。锁文件或工具集合缺失、摘要格式错误、符号链接输入、非 SemVer 版本和控制字符都会失败关闭。

## 构建时序

`scripts/build-windows.ps1` 在复制生产信任库、来源策略和 x86/x64 宿主到 Tauri 资源目录之前调用 Rust 工具，因此记录的是原始源码状态，不会把构建脚本自身的临时注入误判为脏源码。生成文件先放在系统临时目录，构建成功后才复制到 bundle；失败和正常结束都会清理临时文件并恢复资源。成功构建在资源恢复后还会重新计算一次源码、固定输入和工具版本；任一值在构建期间变化都会使构建失败。

正式 Authenticode 构建必须满足：

- `sourceDirty` 为 `false`；
- 不使用 `-AppVersion` 合成覆盖；
- 所有固定输入和工具版本均可读取。

只有 `CI=true` 且显式启用 `-AllowUnsignedTestBuild` 的不可分发测试包才允许记录脏源码或合成版本。即使允许，真实状态仍会写入并进入签名产物清单，不会伪装为干净发布。

## 独立验证

仅验证签名清单中的元数据结构：

```powershell
cargo run --locked -p ssdev-release-manifest -- metadata-verify `
  C:\release\bundle\metadata\release.json
```

同时拥有对应源码检出时，可重新计算 Git 状态、输入摘要和工具版本：

```powershell
cargo run --locked -p ssdev-release-manifest -- metadata-verify `
  C:\release\bundle\metadata\release.json `
  C:\src\ssdev-desktop\next
```

Windows 安装包验收对候选包执行第二种验证；真实上一生产版本通常来自不同提交，因此不要求匹配当前源码，但必须验证其结构、签名清单和独立更新公钥锚定。机器证据生成器不会只比较 `artifacts.json` 自身摘要，而是在读取输入前后都用该清单重新扫描候选与上一版本完整 bundle，避免安装测试结束后文件漂移却仍签发旧清单结论。schema 7 Windows 证据记录上一版本号、`release.json`、`artifacts.json`、近期深度部署记录摘要以及独立的回退和应用状态保留结果；schema 8 生产策略逐项锁定发布身份和 GO 执行窗口，最终判定另要求部署记录、上一版本回装启动及数据根哨兵复核均通过，避免用另一个更低版本、只完成覆盖升级或只启动控制台替代真实演练。

## 边界

该文件提供项目内可验证溯源，但不单独证明 Git 提交已推送、代码评审已经完成或构建机未被攻破。正式发布仍需要受保护分支、受控构建身份、KMS/HSM 私钥、独立 Authenticode 发布者校验和制品库不可变策略。若以后接入组织级 SLSA/in-toto 服务，应以签名 `artifacts.json` 摘要作为 subject，不另建与实际 bundle 脱节的文件清单。
