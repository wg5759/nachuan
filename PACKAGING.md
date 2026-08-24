# 打包分发（M6）

> **重新生效（ADR-0015，2026-08-25）**：CLI + 本地 Web 仍是开源源码版主入口；普通用户桌面版和企业商用版
> 恢复为正式产品目标，并与开源版共享同一核心版本。本文的安装、签名、更新和闭包门禁重新约束二进制发行；
> 当前状态仍为 `NO-GO`，不得把重新生效理解为已有可交付安装包。

把"Python 引擎 + Electron 桌面端"打成一个**目标机无需安装 Python/uv/Node** 的安装包。

当前状态：本文描述构建合同，不代表现有 `dist/` 或 `desktop/release/` 已通过生产验收。历史产物不得复用；只有
绑定明确 commit、锁文件、native manifest、扫描报告和有效 Authenticode 签名的新产物才可上架。完整判定见
`docs/PRODUCTION_AUDIT_20260713.md`。

### 0.2.0 双轨更新合同

- `early-access` 协议是醒目标注的未签名体验通道设计，不是 stable/正式上架。未来开闸时，安装包名必须含
  `early-access-unsigned`，Ed25519 信封须精确绑定版本、sequence、channel、variant、平台/架构、文件名、大小和
  SHA-256；客户端持久反回滚，下载完成与用户确认安装前分别重新打开并复算文件。当前公共 publisher 无条件硬阻断，
  内部事务仅允许显式注入 transport 的两个数值回环测试端点，因此现在不能自动检查、下载或发布任何官方 EA 更新。
- `stable/public` 在上述检查之外，当前 EXE 与更新安装器还必须通过固定 publisher、证书指纹和可信时间戳的
  Authenticode；无证书时继续 fail-closed，early 通道不能解锁 stable workflow。
- 未来发布端必须先写版本化不可变资产，从公开只读地址逐项回读 hash/size，再写 channel yml，最后以 ETag/CAS 原子切换
  签名信封。发布 token 只存在发布机/受保护 workflow，绝不进入客户端。回退旧字节也必须签出更高 sequence。
- 当前私有仓库不能作为无 token 客户端的公开源。真正推送仍缺机主授权的公开只读 HTTPS 对象存储/CDN（或独立
  public repo）、对应写端权限/URL，以及安全保管的离线 Ed25519 私钥；缺任一项不生成可分发 early 包。

## 交付 SKU 边界

本文的安装包只交付 Electron 桌面端和 `resources/engine` 中的 Turn Engine/HTTP API。它不交付
Supervisor、`start_all.ps1`、微信 iLink runner 或飞书 runner，因此不能仅凭安装包宣称微信/飞书已开通。
这两个渠道当前是受审源码部署的独立运维形态；未来要进商店 SKU，必须先补齐独立低权限服务身份、签名制品、
安装/升级/卸载和真实渠道 E2E。Telegram runner 仍明确排除于正式包与 Supervisor 之外。

审计现场曾有 `C:\Program Files\aggregator-desktop` 下的 v0.1.0 旧安装及 Public Desktop/Common Start Menu 两个
快捷方式。主 EXE 与包内 engine 均未签名；固定 release-security scan 以 exit 1 拒绝旧 `resources`，并在种子连接
文件命中 2 个非空 API key（未读取/回显值）。取证后最新只读复核确认旧目录、两个快捷方式及该目录进程均已不存在；
本地入口清理完成，但所有命中或可能进入旧制品的 provider key 仍须在供应商侧轮换并证明旧值失效。

首次复扫的派生产物同样已判废：旧 `desktop/release` 含意外 `.icon-ico` 并使最终产物断言失败，历史
`win-unpacked` 命中 2 个非空 API key；当时的 engine/安装/卸载字节未签名且无 runtime manifest。随后完整构建已先
清理派生目录并从严格 lock 环境完成主构建；其中中文名 `73ba…` 安装器又因 electron-builder 更新元数据改名并丢失
lean/full 变体而被 metadata verifier 阻断，永久作废。制品名改为 ASCII
`nachuan-${version}-${variant}-${platform}`（产品显示名仍为“纳川”）后增量重打成功。当时的
`desktop/release/nachuan-0.1.0-lean-win.exe` 为 211,479,524 字节，SHA-256
`82860b5b4811783495cdcb06cfca6784205b27d7c3027cd014c58f7406c57c19`，metadata/variant/closed-set/package/
SHA256SUMS 均通过，但 Authenticode 为 `NotSigned`。晚期微信、Supervisor、运行目录 ACL、飞书可靠性与 Telegram
production gate 源码变更发生在
该构建之后，因此它现在只是一份历史检查点，不再绑定当前工作树。截至本文冻结没有当前候选；必须从最终 commit
重跑全量测试、完整构建和打包，产生新的哈希与签名证据后才可重新判定。

## 原理

- **引擎** → PyInstaller 打成单个可执行文件（`engine.exe` / `engine`）。
- **桌面端** → electron-builder 打成安装包，把引擎作为 `resources/engine/` 一并塞进去。
- **签名信任链** → 生产 CI 先对 PyInstaller `dist/engine.exe` 做 Authenticode 签名与时间戳验证，
  `write-engine-digest.mjs` 再把这些签名后的精确字节冻结为非可执行源名 `dist/engine.payload`，并将其 SHA-256
  写入 Electron main。electron-builder 只把它恢复命名为 `resources/engine/engine.exe`，不得再次签名改字节。
  pack gate 逐字节复核 payload/包内引擎/main 绑定，真实证书 CI 另对包内引擎、桌面 EXE 与安装器的
  publisher 和时间戳验真。本地无证书构建只能得到未签名待验候选，不是发布证据。
- **桌面完整性** → 启用 ASAR、embedded ASAR integrity 和 OnlyLoadAppFromAsar，禁 RunAsNode/NODE_OPTIONS/CLI inspect 等 Electron fuses；`_verify_pack.mjs` 从最终 Electron 可执行文件读回 fuse wire，不只相信 YAML。
- 运行时：主进程检测 `app.isPackaged`，生产环境只在 `resources/engine/` 恢复为“仅一个预期引擎文件”且哈希匹配后 spawn。端口由内核随机选择；引擎必须用随机 boot token 对每次 challenge 做 HMAC，并同时证明精确 child PID 与 database-ready，主窗口才创建。`USAGE_DB_PATH`/`DATA_DIR`、Agent workspaces 和 semcache 都显式写入 userData；开发环境才从仓库启动 Python。

## 构建步骤

### 1. 打引擎（机械/开发示例，不是发布 provenance；PyInstaller 不跨平台）

```bash
uv sync --locked --extra dev
uv run pyinstaller engine.spec --noconfirm --distpath dist --workpath build
# 生产 CI 在下一行前显式签名并验证 dist/engine.exe；本地示例不签名。
node desktop/scripts/write-engine-digest.mjs
# 产物：dist/engine.exe（Win）/ dist/engine（mac/linux，--add-data 用 ":" 分隔）
```

本轮工作树尚未把历史 `dist/engine.exe` 认定为可信证据。正式构建必须重新产出，并在隔离 userData 下验证
`/health`、`/v1/models`、无密钥启动失败路径和安装/卸载/回滚。
生产顺序必须是 **PyInstaller → 引擎 Authenticode+时间戳 → `engine.payload`/摘要 → Electron 构建 →
桌面/安装器签名 → 包内引擎字节+签名复验**。先写摘要再让 electron-builder 签名 engine.exe 会改变 PE 字节，
使验包和运行时必然失败；回归测试用确定性“伪 Authenticode 追加字节”在无真证书环境锁定该顺序。

`engine.spec` 不复制整个 `skills/`。它调用 `orchestrator/skill_bundle.py`，只在 `trusted-manifest.json` 的固定哈希、
6 个受信 `SKILL.md` 及 ATTRIBUTION/LICENSE/README 的预置哈希全部一致时把这些精确文件加入 PyInstaller；额外、
缺失、改写、越根或 reparse 都使构建失败。运行时继续校验同一 manifest。正式验包还必须证明最终签名 engine 内
这 6 个技能可见且没有 ambient/额外技能，不能只引用源码测试。

`视频工作流/` 是非生产本机存档，不属于 engine 或 Electron 输入。`.gitignore` 与发布扫描双重排除，扫描发现目录名
或隔离标记必须失败；不得为了保留旧功能把它复制进 `resources/`。其隔离测试只证明默认入口被阻断，旧脚本中的裸
PATH 媒体调用、外部 API/模型和历史依赖并未获得生产准入。同宿主最新只读复核另发现 32 个 `ep_render_*` 与 1 个
`story2video_net_daily` 计划任务：31 个 Disabled、`ep_render_0713_022459` Ready、`ep_render_0714_024635` Running，
动作指向用户 `.claude\skills\story2video`，属于独立的 `D:\AI视频制作` 项目，不是纳川任务、进程或打包输入。本审计
未也不得停用、注销或停止它们。它们不构成“纳川必须清零”的发布条件，但当前机器因此不能充当洁净构建/独占隔离
证据；发布须改用洁净 CI/测试机，或由双方 owner 形成经验证的共存边界，证明不共享凭据、可写路径、端口和进程控制。

### 2. 打桌面安装包

```bash
cd desktop
npm ci --ignore-scripts --registry=https://registry.npmjs.org  # 锁定依赖且不执行第三方 lifecycle
npm run typecheck
npm test
npm run package      # 仅开发便利入口；重建引擎+绑定哈希+验包，且 --publish never
# 产物：desktop/release/nachuan-<版本>-<variant>-win.exe（Win；产品显示名仍为“纳川”，文件名用 ASCII 保证更新元数据稳定）
```

`npm run package:*` 内部仍从调用者 PATH 解析 `uv`，没有独立证明 uv/Python/Node/npm 的精确版本，因此只产生开发待验制品，禁止发布。Windows 本地正式候选必须从仓库根运行 `scripts/build-local.ps1`；该脚本先清除 Node/npm/Electron/esbuild 的环境注入项，再以 `npm ci --ignore-scripts` 安装锁定依赖，随后显式准备并复核固定哈希的 Electron runtime 与完整许可证证据；工具只调用启动时一次解析的绝对路径，并严格核对 uv `0.11.3`、Python `3.12.9`、Node `24.14.0`、npm `11.12.1`。远程候选只走 `.github/workflows/release.yml`。

本轮第一次实际运行 `build-local.ps1 lean` 的全部输出/产物已作废：精确环境测试揭出 direct `cryptography` 缺失，
`engine.spec` 的项目 import root 错误，同时 PowerShell 5.1 不会因 native 命令 `$LASTEXITCODE` 非零自动抛异常，旧脚本
因此继续并假报 `[OK]`。当前已把 `cryptography>=49` 写为直接依赖并更新 lock，spec 以 `SPECPATH` 恢复项目根，
`Invoke-CheckedNative` 覆盖 uv/pytest/PyInstaller/node/npm/verifier 和最终产物门；定向 `31 passed`。只有从空
`dist/release` 重跑完整 lean 构建并让每一阶段/最终 verifier 自行 exit 0，才能把该修复视为有效。第二次完整重跑
已以 exit 0、1520.7s 通过：Python `860 passed, 7 warnings`，PyInstaller build complete，desktop 76 项
test/typecheck/build、release closed-set 与 `_verify_pack` 全绿；这关闭本机假绿回归，不替代干净 CI provenance。
随后 metadata verifier 阻断中文 artifact 名在 electron-builder 26.15.3 中被改写且丢失变体的问题；ASCII artifact/
workflow/gate 首轮修复以 7 Vitest + 4 pytest 通过；最终输出 gate 随后升级为对现有 `SHA256SUMS` 每项重算，最新
release Vitest 为 10 passed。Electron 增量重打 exit 0、182.5s，`lean.yml` URL/path 均为
`nachuan-0.1.0-lean-win.exe`，CLOSED_OK、`_verify_pack`、release-metadata、`SHA256SUMS` 后可重复 FINAL_OK。

当前 release workflow 会验证人工选择的既有 tag、tag/desktop version/HEAD 身份、锁文件、测试、包结构和签名，并上传短期候选 artifact；AV/SBOM/许可证证据门禁已经实现，但候选尚未全部通过，且干净虚拟机安装、真实微信与 soak 仍无机器证据，`publish` job 在创建 GitHub Release 前固定失败。候选 artifact 不是发行版，不得手工改名上传。

生产环境 secret 合同固定为：`WINDOWS_CSC_LINK` 是 base64 编码的 PFX（可带 `base64:` 前缀），
`WINDOWS_CSC_KEY_PASSWORD` 是其密码。工作流只在临时目录落一次 PFX，密码只进入 engine 签名和 Electron
签名两步；包后复验要求所有目标与预摘要 engine 的证书指纹完全一致，并在 `always()` 清理临时 PFX。

lean/full 当前都遵守 [Lean 文字优先发行边界](docs/LEAN_TEXT_FIRST_RELEASE.md)：语音与本地压缩只能用显式实验
extra 本机评估，许可证/原生闭包完成前不得进入发行 selector 或安装包。

仓库脚本的变体是显式合同：

```powershell
.\scripts\build-local.ps1 lean   # 云/BYOK；不含 llama/GGUF，不首启下载

$env:LLAMA_URL = '<固定官方 HTTPS 资产>'
$env:LLAMA_SHA256 = '<64 位预审 SHA-256>'
$env:MODELS_SRC = '<含至少一个已审 GGUF 的真实目录>'
$env:NACHUAN_FULL_RUNTIME_TRUST_MANIFEST = '<逐文件 path/role/hash/size/license/source 的预审 JSON>'
.\scripts\build-local.ps1 full   # 缺 runtime 或 GGUF 即失败
```

不要在没有 GGUF 时把包命名为 full；不要为了“构建成功”给 lean 混入构建机上的 `LLAMA_SRC`/`MODELS_SRC`。
`LLAMA_URL` 只接受官方 `https://github.com/ggml-org/llama.cpp/releases/download/` 路径；full 输入必须与预审 manifest
逐文件大小/SHA-256 完全一致，且许可证和来源非空，否则 early/full 与本地 full 都故障关闭。
当前 `.github/workflows/release.yml` 的官方候选构建只产出 lean，且发布作业仍硬失败。full 必须先为每个 GGUF/runtime 文件补齐固定来源、
许可证、SHA-256、SBOM、恶意软件扫描和签名证据，不能把本地开发构建直接上传商店。

### 供应链注意

发布构建固定官方 npm registry，禁止机器级镜像覆盖和 `npm install` 重解依赖。代理只负责传输，不能改写
registry 或关闭 TLS/integrity 校验。uv、Node、签名工具和所有预编译二进制必须预先固定版本并核验；构建脚本
不会下载后管道执行安装器。完整要求见 `docs/THIRD_PARTY_SECURITY.md`。

不要因旧 `uv.lock` 导出审计为 0 漏洞就复用漂移 `.venv`。严格重建前环境曾命中 `diskcache 5.6.3`、
`nltk 3.9.4`、`Pillow 12.2.0` 共 7 项漏洞；最新构建已执行 `uv sync --locked` 并通过精确环境测试，但 direct
dependency/lock 已更新。随后 dry-run 无变化、旧三包 absent、`cryptography=49.0.0`，更新后实际环境 pip-audit
覆盖 66 packages 并报告 0 漏洞，npm audit 也为 0。发布提交仍须重导出当前 lock、生成 SBOM 并在干净 CI 复扫。

### 本地运行态 manifest

`llama-server` 能启动不等于它可信。正式包必须为以下最终字节记录 canonical path、role、size、SHA-256、来源、
版本/revision 和许可证：

- `llama-server` 可执行文件；
- 与其同目录、可能被动态加载的 DLL；
- 随包 GGUF（如果该变体包含模型）；
- ffmpeg/ffprobe 以及任何随包 MCP/本地 CLI。

当前 `prepare-pack.mjs` 生成无时间戳、无绝对机器路径的确定性 `local-runtime-manifest.json`；条目只能是受控根下
的相对路径，`_verify_pack.mjs` 会复算最终包字节并要求 manifest 与包内 llama/runtime/model 文件集合精确相等。
Electron packaged 模式只在 manifest、llama-server 和 GGUF 同时存在时注入运行态路径。

运行时只接受与 manifest 或显式预审 SHA-256 匹配的 llama-server、相邻 DLL 和 GGUF；绝对路径、`..`、错误 role
根、缺失/额外文件或哈希变化都使本地模型隐藏，而不是降级为 PATH 搜索或联网补齐。loader 已对 manifest、binary、
GGUF、DLL 和全部父路径逐组件拒绝 symlink/junction/reparse，依赖枚举使用 `follow_symlinks=False`，通过同一打开句柄
验哈希并复核文件身份，且在 `Popen` 前二次执行完整 attestation；相关三文件定向为 `43 passed, 1 warning`。不过
`CreateProcess` 和 llama 子进程仍会按路径重新打开 executable/DLL/GGUF，源码检查不能证明理论换靶窗口完全消失。
最终包目录必须在运行期间不可被非受信更新路径改写，并以 ACL、目录闭包、签名/manifest 和换靶 smoke 证明；在此之前
lean 保持空 manifest，full/本地模型不得发布。
若某个媒体工具没有固定来源和 manifest，正式包也必须禁用对应能力或阻断发布。

LLMLingua ONNX/tokenizer 不属于 `dist/models` 本地运行时合同。曾由构建机未跟踪 `models/` 目录复制的该资产已从 `electron-builder` extraResources 删除，lean/full 均不携带；缺失时 `compress.py` 保留原文/安全降级。未来只有固定上游、许可证、逐文件 SHA-256 manifest 和 fresh-checkout 复现证据齐全才能恢复随包。

本轮已复核一组可用作后续准入的媒体候选字节：Gyan 8.0.1 essentials ZIP 与官方 checksum 相符，解压/Program Files 中的 `ffmpeg.exe` 和 `ffprobe.exe` 也逐字节一致，且候选 `bin` 只有三个静态 EXE、无相邻 DLL。精确哈希与来源见 `docs/THIRD_PARTY_SECURITY.md`。Supervisor 的固定 schema `data/media-binaries.json` 已绑定两个目标路径/哈希；每次启动/`Validate` 都复算真实 EXE，并要求同一非 reparse 目录只能出现 `ffmpeg.exe`、`ffplay.exe`、`ffprobe.exe`，gateway 每次调用再验目标 EXE。它们仍是包外运维配置且 Authenticode 为 `NotSigned`；packaged Electron 尚未注入该配置，最终包也没有许可证/native SBOM/签名/多引擎扫描证据，不得因此打开发布门禁。

## 跨平台

- 当前正式发布仅支持经过 DPAPI 与签名门禁验证的 Windows `.exe`。macOS/Linux 密钥存储适配及真机验收完成前，
  只能做实验构建，不得作为官方上架产物。

## Installation Root 安装钩子

Windows NSIS 通过 `desktop/build/installer.nsh` 在应用启动前直接调用随包
`engine.exe --nachuan-provision-installation-root`。该 frozen-only、提升权限、
无网络命令用 Known Folder API 创建/验证固定 ProgramData root，并把 Gateway
付费幂等账本绑定后停在等待 Desktop 的 `provisioning` 状态。升级只验证既有
identity；缺失、半对、损坏、retired 或 locked 状态全部中止安装，绝不重建。
失败会撤销本次应用目录/快捷方式/注册表但保留权威现场，普通卸载默认也保留
root、Gateway ledger 与 AppData。完整状态机、验证矩阵和干净 VM 待验项见
[`docs/INSTALLATION_ROOT_INSTALLER.md`](docs/INSTALLATION_ROOT_INSTALLER.md)。

当前钩子把 `StateRoot` 只授权给执行提升事务的管理员 SID 与 SYSTEM，所以只证明
安装/运行同 SID 的单用户现场。标准用户在 UAC 输入另一管理员凭据后运行，或同机
切换到另一 Windows 用户，都会被 ACL 拒绝；这不是可通过放宽到 `Users` 解决的
兼容性问题，而是当前 per-machine 设计的发布阻断项。正式支持须迁到独立低权限
Windows 服务 + 调用者鉴权 IPC，或完成可审计的目标运行用户绑定、升级和换用户协议；
在跨凭据/多用户 VM 矩阵通过前保持 `NO-GO`。

## 数据与安全

- 生产环境引擎数据（连接、用量库）写入系统 userData 目录，不在安装目录。
- packaged 引擎使用随机 loopback 端口，不复用固定 8080 上的既有服务；只有 boot token/challenge/PID/database-ready 全部匹配才显示主窗口。启动失败必须故障关闭，不连接“看起来健康”的未知端口。
- packaged 环境显式设置 `DATA_DIR=<userData>\data`、`AGENT_EXEC_WORKDIR=<userData>\workspaces`、`SEMCACHE_DB_DIR=<userData>\data\semcache` 和只用于边界判定的 `NACHUAN_GUARD_HOME`，避免 PyInstaller onefile `_MEI` 临时目录被误当持久目录。
- 引擎 Key 由桌面端生成、存 userData，不入包、不回显。
- 审批 Key 与引擎 Key 独立；只在 Electron main / Supervisor 信任域使用，不暴露给 renderer。
- 连接、微信 token、同步 token 和撤销签名材料使用 Windows DPAPI/safeStorage；保护失败时不得回退明文。
- 旧 live `data/sync.json` 与 desktop userData `config.json` 不能因“新代码支持迁移”自动视为安全。当前机器最新只读复核已确认前者为 `nachuan.protected-json.v1`/DPAPI、后者为 `nachuan.electron-secret-config.v1`/safeStorage，两者无明文 secret 字段、ACL 仅当前用户 + SYSTEM 且关闭继承；最新源码 gateway 已成功重启解密 sync 信封，第二个独立 packaged Electron 进程也在 config mtime 不变时存活并复用同一 safeStorage 信封，随后按精确 release 路径停止且无残留。两份本地迁移/重开闭环；原明文 sync/provider key 的供应商侧轮换/旧值失效仍无账户授权或证据，继续阻断发布。
- 微信运行态数据根中的 `weixin_outbox.db` 是业务数据，不进入安装包/诊断包；done 只在完整投递组终态后按 30 天默认保留清理，dead 立即脱敏墓碑并按 180 天/各 10,000 行默认上限维护，pending/processing 不清理。最终安装/渠道 smoke 要覆盖实际部署数据路径、旧库迁移和 partial-group 不误删。
- 飞书历史 SDK INFO 日志曾包含 WebSocket `access_key`/`ticket`，且当时 `data/logs` ACL 过宽。当前代码已补日志
  ERROR+脱敏、严格 access file、durable inbox/outbox、同 chat 顺序、claim fencing、重启续跑、终态有界维护/dead
  墓碑和 Supervisor 业务 readiness；发布仍须完成历史日志清理/旧会话失效、live ACL/reparse、最终全量/构建、live
  重启和真实账号 E2E，缺任一项就默认关闭飞书并保持 `NO-GO`。
- Telegram runner/bridge 不进入正式 engine/Electron 包，Supervisor 也不管理；默认/production 裸 runner 在读取凭据
  或联网前 exit 78。只有未来补齐 scoped key、durable delivery/health 与真实验收后才可修改发布闭集。
- packaged 桌面只运行 `resources/engine` 中随包引擎；目录必须只有预期 engine 且 SHA-256 与签名主进程内绑定相符。不得旁加载安装目录旁的源码、`.venv`、系统 `uv` 或额外 DLL/脚本。开发模式才允许从仓库运行 `uv run python -m gateway.app`。
- 安装包必须通过 ASAR integrity/OnlyLoadAppFromAsar 等全部预期 Electron fuse 的最终字节读回；仅检查 `electron-builder.yml` 不算证据。
- `media:save` 的 inline bytes 上限 32 MiB；远端下载要求 DNS 全部地址为公网并 pin 已审地址，每个重定向重新验、最多 4 跳、禁止 HTTPS 降级，Content-Length/未知长度流都受 512 MiB 累计 cap，30 秒 idle 与单一 10 分钟总 deadline 覆盖 DNS 和全部跳；临时文件成功后原子改名，失败清理。最终包仍需真实 CDN/代理/断网/磁盘满 smoke。
- Python 的 `/v1/videos/fetch`、webread、Studio、Claude 远程图片和微信/飞书媒体使用 `gateway/public_media.py`：每跳全 DNS 公网判定并把 socket 固定到已审 IP，HTTPS 仍按原 hostname 验证证书；只准 80/443，安全 header allowlist，禁 HTTPS 降级，响应类型/编码/声明长度/流累计、idle/总 deadline、DNS/HTTP slot 和失败临时文件均有界。预签名 POST 不重定向/重放。Bing 搜索固定精确 origin，外部网页只作为转义后的 user evidence，不进入 system role。
- 该 Python URL/提示注入组合在当前源码上独立复核为 `132 passed, 7 warnings`，9 个迁移模块 `py_compile` exit 0；这只是代码证据，不替代最终包真实 CDN/代理/slowloris/磁盘满 smoke。
- 通用 yt-dlp extractor 不属于上述固定-IP下载合同。`/v1/lapian/url` 生产默认 503；精确开发风险确认词开启后也只准静态 exact 官方 HTTPS/443 host，禁插件/JS/remote components/cache/external downloader/cookies，并要求逐次认证且同目录的 ffmpeg+ffprobe 作为 `ffmpeg_location`。但 yt-dlp 自身二次 DNS/extractor CDN 仍未 pin，正式包必须证明未设置该开关；低权限 worker + 出站策略前不得发布网址拉片。直接上传 `/v1/lapian` 保持可用。旧 `SYNC_SERVER_URL` 只保留陈旧配置检测：默认空，非空即拒绝 gateway 启动且不发请求；未来跨设备同步只能使用独立最小权限 sync credential、受控目标 fingerprint/epoch 和 DPAPI cloud_sync，不能恢复 owner runtime key 外发。
- `engine.spec` 只携带固定 verifier 认可的 manifest、6 个 `SKILL.md` 和 ATTRIBUTION/LICENSE/README；不携带整个用户技能目录。构建期与运行时双重哈希闭集已经实现，最终签名引擎仍需做技能可见性、无额外项和篡改故障关闭 smoke。
- packaged Electron 在 `<userData>/logs/desktop-main.jsonl` 写脱敏生命周期日志：当前文件最多 5 MiB、保留 3 个轮转备份，只记录版本、生命周期、PID、随机端口、退出/重启和错误类型等元数据，不记录 payload/key；写失败不阻断应用。engine stdout/stderr 仍只进 `console`。一键脱敏诊断导出、健康/版本/包哈希聚合是 P2；最终包仍需磁盘满/写失败 smoke。
- 源码树只支持非持久 Supervisor；旧 `LLMAggregator` 登录任务已删除，`InstallTask` 固定 exit 78。该事实不代表全机任务为空：当前同宿主有 33 个属于 `D:\AI视频制作` 的外部 story2video 任务，31 个 Disabled、1 个 Ready、1 个 Running；纳川审计只记录而不修改。正式登录自启只能由签名安装器从受保护、non-reparse、严 ACL 安装目录创建；安装/升级/卸载测试必须证明普通用户不可改写目标，且卸载会清理纳川自己的自启项。共存证明只在双方代码均受信时说明不共享凭据/路径/端口；同一 Windows SID 下的恶意进程仍可使用 owner 权限，必须迁入独立低权限身份/AppContainer/VM 或禁用，不能用 ACL/DPAPI/净化环境冒充隔离。

## 发布证据包

每次正式发布至少归档：

1. commit、干净工作树证明、源码 SHA256SUMS、`uv.lock`/`package-lock.json` 哈希和构建工具版本；
2. Python、npm、native/最终安装包 SBOM，以及许可证与 OSV/CVE 报告；
3. 所有下载 URL、不可变 revision、SHA-256、运行态 manifest 和构建日志；
4. 后端全量测试、desktop typecheck/test/build、release security 与包结构验证日志；
5. Defender（启用且签名最新）和第二独立引擎对最终安装包的扫描报告；
6. 安装器/EXE/DLL 的 Authenticode publisher、时间戳、撤销验证和 `SHA256SUMS`；
7. 空 userData 冷启动、伪 loopback 服务抢占、child 重启、数据持久化/升级迁移、Installation Root 同 SID/跨管理员 UAC 凭据/多用户切换矩阵、旧明文 sync/desktop config 的 envelope + ACL + 重启验证、微信终态队列 live 迁移/partial-group 保留、流式 error 可见性、Python/Electron pinned fetch 的真实网络/磁盘边界、洁净 CI/测试机或与同宿主外部 story2video 项目的共存隔离证据，以及旧 Program Files v0.1.0/快捷方式受控移除与相关 key 轮换证据；
8. 最终签名 engine 内 manifest、6 个 skills 与 notices 的精确集合/篡改拒绝证据，以及 userData 生命周期轮转日志证据；一键脱敏诊断导出作为 P2 单独跟踪；
9. 微信空 allowlist 的 degraded/access_locked + `/whoami` 明示失败、配置 owner allowlist 后的真实一发一收，以及其它启用渠道的真实 smoke、24 小时 soak 与回滚演练记录。

其中 Native CycloneDX 不能从预期文件名或 registry 单独生成：门禁先逐字节复验最终 `win-unpacked` 对 `WIN_UNPACKED_MANIFEST.json`，再把 manifest 中每个 `.exe/.dll/.node/.pyd/.so/.dylib/.gguf/.onnx` 的 path、SHA-256、size 与 packaged `NATIVE_PAYLOAD_LICENSES.json` 的许可证 component bom-ref 精确绑定，输出 `NATIVE_SBOM.cdx.json`。没有上游明确 purl 的组件不写 purl；发布复验会从最终字节重建 canonical SBOM，任何字节替换、未登记 native、manifest 或 SBOM 漂移都阻断。该机制已落代码门禁，但当前脏工作树尚未形成可归档的冻结候选 SBOM。

当前本机 MSERT 已命中 Defender 篡改注册表状态，且 Defender 平台登记仍损坏；当前用户证书库没有代码签名证书，
真实渠道凭据也未形成验收证据。主机重启/升级、平台恢复和复扫前不得把本机当干净构建机；当前 lock 的发布
SBOM/干净 CI 复审，以及旧制品命中/可能暴露 key 的供应商侧轮换仍未闭环。
旧 Program Files 安装、两个快捷方式及相关进程已从本机移除。同宿主 33 个外部 story2video 任务不归纳川处置，
但其并行持久化意味着本机不能提供洁净/独占宿主证明，须以洁净 CI 或经验证的共存隔离证据替代。
因此该 lean 文件只是一份历史检查点；当前候选为“无”，不能标为商店可发布版本。
