# ADR-0005：正式发布采用 fail-closed Release Trust Gate

- 状态：接受
- 日期：2026-07-13

## 背景

满配构建曾把 data/connections.json 的真实密钥复制进安装包；tag 工作流直接发布，并下载 latest llama.cpp 二进制而不校验哈希。现存本地安装包未签名。

## 决策

- 所有发布变体的连接种子必须为空。
- 本地与 CI 均使用锁文件安装依赖并运行测试。
- 第三方二进制必须使用固定 HTTPS URL 和预审 SHA-256。
- 构建后运行密钥扫描和包结构验证。
- Windows/macOS stable/public 正式发布缺少签名凭据即失败。
- 机主明确选择的 early-access 轨可以暂不购买代码签名证书，但必须清楚标注“未签名测试版”，使用独立 Ed25519 更新信封、不可变版本资产、反回滚和用户确认；它不能冒充商店/stable，也不能绕过许可证、SBOM、最终扫描和干净构建门禁。
- 所有平台产出 SHA-256 清单；所有构建完成后才创建 Release。
- `generated-engine-integrity.ts` 与 `generated-update-trust.ts` 是发行参数派生源码，不得在 source-freeze 之后重写。生产与 early-access 流程必须先生成这两个固定路径文件，再写入 `nachuan.release-source-freeze/v2`；v2 在 Git 源码快照之外单独绑定它们的路径、SHA-256、大小和同机文件身份。它们从 Git 闭集枚举中精确剥离仅因属于派生源码，不能扩展成目录级排除，也不能脱离 v2 冻结证明。
- 冻结后的 `write-engine-digest.mjs check` 与 `write-update-trust.mjs check` 只能复算并比较预期字节；不一致时失败关闭，禁止“校验时顺手修复”。最终 source-freeze 复验同时要求字节与同机文件身份未变，跨 runner 的 portable 比较只放宽文件系统身份，不放宽路径、摘要或大小。
- 本地发布工具链不得继承机器上“碰巧可用”的 Node。仓库根目录 `node-runtime-lock.json` 精确绑定 Node `24.14.0` 的官方单文件 `win-x64/node.exe`、`SHASUMS256.txt` 行、SHA-256、大小、Authenticode 签名人与时间戳身份；`desktop/scripts/node-runtime-policy.mjs` 只允许 `nodejs.org` HTTPS 源，采用有界下载、候选目录和原子改名，生成闭集来源回执，并在每次使用前离线复验。系统 Node 仅可启动该引导策略，发布证据脚本必须由项目内已验证的 Node 子进程执行。
- CI 仍必须由 `actions/setup-node` 精确选择 `24.14.0` 并设置 `NACHUAN_RELEASE_NODE_PATH`；项目内运行时是本地发行闭环，不得被解释为放宽 CI 的精确版本门禁。
- `npm test` 必须先经 `node-runtime-policy.mjs` 进入固定 Node，再由 `vitest-isolated-runner.mjs` 为普通测试创建 `build/test-temp` 下的独占 `TEMP/TMP/TMPDIR`。离线私钥测试另用系统 TEMP 下的独占外部夹具根，以继续满足“私钥必须在仓库外”；两个根都只能按启动器冻结的父目录和前缀清理，测试结束不得留残余。
- Node `24.14.0` 在 Windows 中文仓库路径上递归 `fs.cpSync()` 可直接以 `0xC0000409` 终止进程；测试与发布夹具不得使用该组合，封闭文件集必须按冻结清单逐文件 `copyFileSync()`，且不得据此放宽真实签名、许可证或包内容校验。

## 后果

- 现存携密或未签名产物一律不可上架。
- 首次正式发布前必须配置代码签名证书和固定 llama 资产变量。
- early-access 的“允许未签名”只是发行轨差异，不会把未签名字节变成已认证或已通过恶意软件扫描。
- “开箱即用”改为安装后安全录入 BYOK，不再分发机主密钥。
- 发布构建不再因生成脚本在冻结后自修改源码而形成必然失败；但这只关闭了发布链内部矛盾，不代表签名、恶意软件扫描、许可证或上架门禁已经满足。
- 本机 Node 升级或降级不会静默改变纳川发布证据的解释器；锁文件、官方清单、实际字节、签名身份、版本探针或来源回执任一漂移都必须失败关闭。
- 全量测试不再与全机共享 TEMP 命名空间争用；测试耐久超时仍保持局部有界，临时根隔离不能被解释为放宽业务超时或发布门禁。
