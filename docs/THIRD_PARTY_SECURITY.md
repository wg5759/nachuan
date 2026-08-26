# 纳川第三方供应链安全基线

最后复核：2026-08-24（Asia/Shanghai）

## 结论与边界

本项目针对记录快照完成过一次源码、锁文件、来源与可执行入口静态审查，并已故障关闭当时发现的“运行期下载后
直接执行”默认通道；这不是对当前及未来全部字节的完整供应链认证。
这不等于、也不得宣传为“无病毒/无木马”：源码、npm/Python 包、预编译二进制、模型权重、安装包和未来更新
是不同的证据对象。本机 Windows Defender 目前不可用，因而本轮没有“Defender 扫描通过”证据。正式上架必须
在干净 CI 中重新构建，对最终字节做多引擎恶意软件扫描、签名、SBOM 和哈希归档。

本文始终分别陈述三种结论：源码/合同测试是否通过、冻结候选是否满足发行门禁、最终字节是否取得恶意软件认证。
前一层为绿不能推出后一层为绿；公开漏洞库当前无命中也不能推出“无病毒、无木马或无后门”。

还必须区分“锁文件可审计”与“冻结候选已按锁重建”。direct `cryptography` 修复前，`.venv` 与 lock 闭包曾不一致，
实际环境命中过 `diskcache 5.6.3`、`nltk 3.9.4` 和 `Pillow 12.2.0` 的 7 项已知漏洞。2026-07-20 对当前脏快照执行
`uv lock --check`、locked dry-run、`uv pip check` 和实际环境 `pip-audit` 均 exit 0；npm 官方 registry audit 也 exit 0/0
known vulnerabilities。当前 lock 仍须在发布提交中重新导出并生成 SBOM；本机审计不替代干净 CI、原生载荷扫描或
最终安装包扫描。

证据时点必须冻结：历史 `860 passed`、1520.7s 和 SHA-256 `82860b…` 仍只属于旧检查点。2026-08-24 已从当前脏工作树
生成新的本地 lean 候选并完成远端干净机安装态 Engine smoke，但它不是 clean commit 的可复现发行冻结：安装包
173,748,429 bytes、SHA-256 `1C956C92689B282BA7DDF8A89DA1169F035D620EB77AFB5D520ED1A190FF3307`，App/Engine
均未签名，最终恶意软件扫描、正式 SBOM、真实升级/回滚和渠道长稳仍缺失。完整收据见
`data/test-evidence/build-local-lean-20260824-101110/final-package-evidence.json`。

静态审查能证明的是：在本次快照中没有发现第一方遥测 SDK或自动执行未固定远程脚本的必要路径；依赖安装和
第三方二进制仍需执行下述上架门禁。任何结论只覆盖被记录的 commit、lockfile 和 SHA-256，不覆盖同名仓库、
浮动分支、未来 registry 内容或旧的 `dist/`/`release/` 产物。

## 已实施的故障关闭策略

- 第三方插件：PK-006 只接受三文件闭集、canonical JSON、Ed25519 签名与绑定入口哈希的 manifest/SBOM；未知 publisher、撤销身份、加文件或改字节均在执行前拒绝。已验代码被复制到单次临时根，以无网络 capability 的 Windows AppContainer 和单进程/CPU/内存/kill-on-close Job Object 运行；启动器在恢复线程前验 `TokenIsAppContainer=1` 与固定 SID。专用 CPython 缓存每次对完整标准库/DLL 闭集重算路径、大小和 SHA-256；可信 `ready` 帧之后才发客户请求并开始插件墙钟限额。一次一帧 IPC 不携带父进程凭据，超时/协议/worker 异常按精确签名身份持久 quarantine。真实恶意样例已证明能正常 import `socket/subprocess` 但不能读宿主文件、写外部文件、连本机 TCP 或创建子进程；真 PyInstaller 冻结 Engine 也已验内层单进程 Job。此结论只覆盖该 Windows 代理路径，不把第三方字节宣传为“无病毒/无后门”，也不代替最终包 SBOM/漏洞/多引擎扫描。
- 企业 RAG 插件组合：PK-007 的 splitter/reranker/DLP/runtime 目前都是内置受信代码，embedder/candidate 无默认 provider，不会从环境扫描动态代码。分片插件不能改原文或跨权限同质边界；候选插件不获得正文；重排只获得已授权正文；DLP 默认 deny-all。tenant/Authz/content/fence/route/audit 对象不是插件 service，组件返回均由可信 runtime 做闭集/哈希/版本复验。这是源码组合边界，不是真实 ReBAC/ABAC、加密正文、向量库或 DLP 后端已准入；外部 RAG 组件在 PK-008 完成 typed isolated proxy/SDK 前不得 in-process 接入。
- 本地 GGUF：`gateway/local_model.py` 不再使用浮动 `resolve/master`。远程下载默认关闭；只有同时提供
  `NACHUAN_ENABLE_VERIFIED_MODEL_DOWNLOAD=1`、不可变 revision 和预审 SHA-256 时才下载，下载完成后先验
  SHA-256、GGUF 魔数和体积上限，匹配后才原子落盘。
- 本地 runtime 已逐路径组件拒绝 manifest/binary/GGUF/DLL 的 symlink/junction/reparse，依赖枚举不跟随链接，同一打开句柄验哈希并复核身份，且在 `Popen` 前二次完整 attestation；三文件定向为 `43 passed, 1 warning`。残余缺口是 `CreateProcess`/llama 子进程仍会按路径重新打开 executable/DLL/GGUF，不能仅凭源码测试宣称完全消除 TOCTOU。默认未配置继续 fail-closed；最终包目录 ACL/闭包、签名 manifest 和换靶 smoke 完成前不得启用本地模型。
- Embedding / Whisper / coordinator：运行期只加载本地目录，开启 Hugging Face 离线和禁遥测环境，禁止
  `trust_remote_code`，Transformers 权重只接受 safetensors。缺模型时降级，不联网补齐。
- LLMLingua：曾由构建机未跟踪 `models/` 目录旁加载的 ONNX/tokenizer 已从 `electron-builder` 资源清单移除；lean/full 都不携带这些浮动字节。`compress.py` 缺模型会保留原文/安全降级；只有固定上游、许可证、SHA-256 manifest 与 fresh-checkout 复现后才能恢复随包。
- MCP：历史 `npx`/`uvx` 预设只保留迁移说明；当前 `verified_mcp_enabled()` 与旧 break-glass 开关都恒定为 false，本进程不启动 stdio/remote MCP。重启用必须先建立与网关凭据隔离的低权限 worker，不得只恢复环境开关。
- 第三方模型 CLI：Claude 已从 active catalog、默认模型、failover、connections、xreview roster 和子进程环境转发中移除；残留兼容代码或历史数据拒绝逻辑不构成活动准入。Kimi K3 正式互审目前也只是候选：源码合同取得 xreview `31/31`、ACP fake `17/17`，独立复核关键集合 `24/24`、managed/tool/catalog 等 `171/171` 与 Desktop `12/12`，但这些都不是经正式 xreview 的真实 Kimi reviewer turn。Windows ACP helper 已用 suspended-before-Job 的 fake 子孙进程树回归关闭 Popen-to-assign 与 cleanup 直接子进程缺口；当前 `scripts/xreview.sh` 仍以 `-p PROMPT` 把提示放入 argv，ACP stdin helper 尚未接入正式 xreview。独立产品 subscription 文本回合虽已成功，仍没有正式受保护 launcher、四个独立连接域、actual-served reviewer 身份绑定，因此正式互审继续 `NO-GO`/fail-closed。
- 模型驱动的 `run_command`/`cli_hub`/`code_index`、Codex 执行与 MCP helper 继续故障关闭。fake ACP helper 对可执行路径/哈希、初始化/session/config、反向 RPC、工具调用、UTF-8/大小/超时/stderr 做了严格拒绝合同，但未接生产路由，也不提供同一 Windows SID 隔离；正式高保证形态仍需独立低权限身份或 VM/AppContainer。
- `codebase-memory-mcp`：当前运行时恒禁用，`.cbm/` 不发包。本轮仅验证了候选上游字节的官方 provenance，没有把它改写成可执行准入。
- 媒体工具：Supervisor 只接受固定 schema 的 `data/media-binaries.json`，复算 ffmpeg/ffprobe 的绝对普通路径与 SHA-256，要求两者同处非 reparse 目录，且目录只能含 `ffmpeg.exe`、`ffplay.exe`、`ffprobe.exe`；DLL、子目录、reparse 或其它 sidecar 均拒绝。ASR、Studio 与拉片再通过 `gateway/media_binary.py` 在每次调用前复验目标 EXE，子进程环境不含 PATH/密钥。该合同约束本机 Supervisor/源码运行形态，不代表媒体字节已进入最终安装包。
- 系统命令：Python secure store 用 `GetSystemDirectoryW` 取得 `whoami.exe`/`icacls.exe`；Electron 用 kernel SystemRoot 解析固定 `whoami`/`icacls`/`powershell`/`cmd`，逐级拒绝 reparse，并用不含 PATH、PSModulePath、代理和凭据的封闭环境启动。
- 桌面主应用：Electron 开启 ASAR、embedded ASAR integrity 与 OnlyLoadAppFromAsar，关闭 RunAsNode、NODE_OPTIONS 和 CLI inspect 等 fuses；pack gate 从最终 Electron 可执行文件读回 fuse wire。生产 CI 先签名并验证 `dist/engine.exe`，再冻结为非可执行源名 `engine.payload` 并把该签名后字节的 SHA-256 编译入主进程；electron-builder 恢复目标名 `resources/engine/engine.exe` 但不再改写字节。pack gate 与启动前复算同一摘要，发布 CI 再复核包内引擎的 Authenticode publisher/时间戳，并拒绝 engine 目录任何额外 sidecar。
- 付费媒体归档读取：`openAsset` 不再根据 inode/birthtime/mtime/ctime/大小组合身份命中进程内“已验”缓存后跳过内容校验。GitHub Windows runner 已实测同路径、同 inode、同大小、恢复 mtime 后连 `ctimeNs` 也可碰撞；确定性红测强制全部元数据等值时，旧代码会把已改坏 PNG 当成原 SHA-256 返回。现在每次开启钉住句柄后都完整读取，复算 SHA-256 并验魔数/结构，前后句柄身份仍必须一致。这用可接受的有界 I/O 换取不依赖文件系统时间精度的安全正确性。
- Agent skills：运行时只承认项目 `skills/trusted-manifest.json`；每个 `SKILL.md` 要求安全相对路径、名称、大小、non-reparse 和 SHA-256 一致，`SKILLS_DIRS`、`~/.claude/skills` 等 ambient 输入被忽略。`engine.spec` 通过 `orchestrator/skill_bundle.py` 在构建时只接纳固定 manifest SHA-256、6 个技能哈希和 ATTRIBUTION/LICENSE/README 哈希；额外、缺失、改写或 reparse 均阻断，运行时继续锁同一 manifest。最终 PyInstaller/签名引擎仍须验证实际内置集合。
- 桌面审计日志：packaged Electron 在 `<userData>/logs/desktop-main.jsonl` 写有界、脱敏的生命周期记录，当前文件上限 5 MiB 并保留 3 个备份；只记录事件、PID、随机端口、packaged 状态和错误类型，不记录 payload/key。日志写失败不影响应用可用性；一键脱敏诊断导出仍是 P2。
- 构建脚本：不再 `curl | sh` 或 `irm | iex` 自动安装 uv；只允许预装工具。正式 release workflow 与 `build-local.ps1` 固定 uv `0.11.3`、Python `3.12.9`、Node `24.14.0`、npm `11.12.1`，后者把工具一次解析为绝对路径后使用；Node 构建命令走 lockfile 本地 bin，`npm exec --offline` 禁止 npx 临时拉取。2026-08-24 当前候选的 12 步构建链全部 exit 0；Node runtime 临时锁只对 `EPERM/EACCES/EBUSY` 做 61×500ms 有界等待，避免安全软件短锁导致构建假失败。Python、npm、native 许可证 staging、Electron build、electron-builder、prune 和最终 verifier 均由同一收据串联；这仍是脏工作树本地候选，不构成 clean checkout provenance。`npm run package:*` 仍是 PATH 依赖开发入口；llama-server 必须固定 URL + SHA-256 后才解压。
- PyInstaller：关闭 UPX，避免构建机 PATH 中未固定的压缩器改写产物并减少启发式杀软误报。
- 自动更新协议分双轨：`0.2.0 early-access` 的未来设计允许未做 Authenticode 的醒目标注安装包，但仍须由独立 Ed25519 信封精确绑定 channel/variant/platform/arch/version/sequence/keyId/name/size/SHA-256，客户端反回滚、下载后与安装前各复算一次且安装需用户确认；stable/public 另要求固定 publisher/证书指纹/可信时间戳。当前 EA 公共入口和 stable publish 都硬失败，内部存储事务只可访问数值回环测试端点，因此现在不存在官方自动检查/下载或发布通道。
- 旧 live 密钥迁移：代码会在读取 `data/sync.json` 时原位写为当前用户 DPAPI envelope，desktop 首启会把旧 userData `config.json` 写为 safeStorage envelope，并验证 ACL 仅当前用户 + SYSTEM。当前现场两份信封/ACL、sync 重启解密及第二个独立 packaged Electron 对原 safeStorage 密文的无重写复用均已验证；这仍不替代曾明文凭据的供应商侧轮换。
- 源码树自启动：旧 `LLMAggregator` 登录任务已停用并删除；启动 BAT 只请求非持久 Supervisor，`InstallTask` 固定 exit 78，源码没有任务注册实现。该结论只覆盖 `LLMAggregator`，不是全机计划任务清单。生产自启必须由签名安装器从受保护、non-reparse、严 ACL 安装目录创建，不能把可被其他本机主体改写的工作区脚本注册为 owner 登录时执行。
- 仓库写执行：网关内 coding-team/arch-editor 入口保持 503；旧 `orchestrator.worktree` 的 Git 子进程实现已经退役，所有兼容入口在解析 Git 或接触仓库前 fail closed。未来只能由独立认证、低权限、禁 hooks、冻结输入和可撤销输出的执行 worker 恢复，不能通过删除 503 直接复活。
- AI 开发钩子：仓库内 Claude/Codex hooks 已清空，Claude Code 另由 ACL 保护的 `C:\Program Files\ClaudeCode\managed-settings.json` 强制 `disableAllHooks`/`allowManagedHooksOnly`；Codex 0.144.1 由 ACL 保护的 `%ProgramData%\OpenAI\Codex\requirements.toml` 强制 `allow_managed_hooks_only=true` 和 `[features].hooks=false`，新进程实测 `codex features list` 显示 `hooks stable false`。这是本开发机防止“仓库可写校验脚本被下一次编辑自动执行”的主机策略，不是应用安装包能力；换机必须重新部署并验 ACL/有效配置。
- 遗留视频工作流：`视频工作流/` 只作为非生产本机存档保留，整目录不进源码/发布包；release scan 拒绝目录名/隔离标记，doctor 修复入口和主要入口默认分别返回 2/78。最新同宿主只读复核另见 32 个 `ep_render_*` 与 1 个 `story2video_net_daily` 任务（31 Disabled、1 Ready、1 Running），动作指向用户 `.claude\skills\story2video`；它们属于独立的 `D:\AI视频制作` 项目，不是纳川任务、进程或包输入，本审计未也不得修改。不共享凭据、可写路径、端口和进程控制只在双方代码均明确受信时构成共存证据；同一 Windows SID 下的恶意进程仍可使用 owner 权限，ACL/DPAPI/净化环境不能隔离它。纳川存档旧脚本的裸 PATH 媒体调用与外部 API/模型路径没有获得准入；正式媒体边界只有 `gateway/media_binary.py`。

## 第三方清单与验证状态

| 类别 | 来源/证据 | 当前策略 | 尚需上架证据 |
|---|---|---|---|
| Python 依赖 | direct 修复前 lock/环境曾漂移并命中 3 包/7 漏洞；当前严格 sync dry-run 检查 48 packages 且无变化，实际环境路径 pip-audit 0 个已知漏洞 | 必须 `uv sync --locked` 且证明实际安装集合=lock；本机当前环境代码门禁闭环 | 当前 lock 在发布提交重导出、CycloneDX/SPDX SBOM、干净 CI 实际环境 OSV/CVE 与许可证清单 |
| npm 依赖 | `desktop/package-lock.json`；534 个 resolved 均为官方 npm registry 且有 integrity，官方源 audit 覆盖 540 依赖并报告 0 已知漏洞 | 所有 CI/本地候选统一 `npm ci --ignore-scripts`，禁止机器镜像覆盖；5 个 lifecycle 包不得在安装阶段执行 | npm SBOM、最终安装集合 `npm audit` 报告、显式二进制准备步骤的出站清单 |
| 模型协作 CLI | Claude 已退出全部活动配置；Kimi 正式互审仅有 test-only xreview/ACP 合同与独立源码复核；Windows fake 子孙进程树清理已验。独立产品 subscription 文本回合成功不计正式票 | 正式 xreview 保持 fail-closed，不调用真实 reviewer 模型 | 受保护 launcher、正式路径提示不进 argv、四独立连接域、actual-served reviewer 绑定与真实 Kimi 互审；Linux 若进入正式范围还需补 setsid/setpgid 逃逸与 zombie 回归 |
| GitHub Actions | workflow 中以完整 commit SHA 固定 | 禁止浮动 tag | 组织级 Actions allowlist、构建证明/日志归档 |
| PortableGit | `desktop/git-runtime-lock.json` 固定 Git for Windows `2.55.0.windows.2` 官方 release URL、59,005,448 字节、SHA-256/GitHub digest `b20d42da…` 与有效 Authenticode；解压后锁定 9,565 文件、407,888,629 字节和完整树摘要 `b64f6a79…` | release workflow 只经 `git-runtime-policy.mjs` 下载、复算、验签、封闭解压并验证 required files/运行树后使用；不接受 PATH Git 替代发布证明 | 归档 Git for Windows/Git 许可证与 notices、在最终 runner 重验时间戳/撤销状态、原生 SBOM 与多引擎扫描，并将证据绑定最终 commit/产物 |
| llama-server | 发布时由固定 URL + `LLAMA_SHA256` 注入 | 哈希不匹配即停止；全路径 non-reparse、稳定句柄验哈希和启动前二次 attestation 已回归，最终包路径重开窗口仍以禁用收口 | 固定上游 release/tag、许可证、最终文件哈希和签名/扫描；受保护包目录 ACL/闭包与安装后换靶 smoke |
| Electron/Chromium | `electron@39.8.10` lock + Electron 包内 checksums + 独立 runtime lock；2026-08-24 为关闭官方 audit 新增公告，从 39.8.5 升级并把无修复版的 `extract-zip@2.0.1` 精确 alias 到 Electron 官方、带 npm provenance 的 `@electron-internal/extract-zip@1.0.1` | 安装不运行 postinstall；显式下载固定官方 URL/大小/SHA-256，封闭解压树并生成 provenance；ASAR integrity/OnlyLoadAppFromAsar 等 fuses 在 pack gate 读回验证 | 升级后需重跑真实 Electron 39 Page Agent、最终原生文件清单和二进制扫描 |
| esbuild | lock 中固定平台包和 integrity | 只使用 lock 的 optional platform 包；安装禁 lifecycle，清除 `ESBUILD_BINARY_PATH`，禁止未审 fallback 下载 | 在 fresh runner 证明 typecheck/test/build 使用锁定平台包并归档实际文件哈希 |
| PyInstaller bootloader | uv lock 中固定 PyInstaller wheel | 干净 CI 构建、最终签名 | bootloader/native SBOM、哈希和恶意软件扫描 |
| tokenizers / CTranslate2 / ONNX Runtime | PyPI 原生 wheel，uv lock SHA-256 | 从 locked wheel 打包 | 原生 DLL/PYD 清单、CVE/许可证/扫描报告 |
| ffmpeg / ffprobe | 已验 Gyan 8.0.1 essentials 候选包；当前 lean 包实际携带 `resources/media/ffmpeg.exe` 与 `ffprobe.exe`，最终 verifier 复算固定哈希并绑定 native notice | Supervisor/gateway 源码路径和 packaged runtime 都拒绝 PATH fallback，并复验固定目标；最终包对两个 EXE、manifest 和 notices 做闭包检查 | 两个 EXE 未签名、无最终多引擎扫描；GPL corresponding source/逐库 notice 的法务闭包仍未完成，正式媒体发行继续 NO-GO |
| 本地模型/ASR/embedding | 用户或构建机提供的 GGUF/safetensors/ONNX | 不再运行期自动下载；未跟踪 LLMLingua ONNX/tokenizer 不进入任何发布变体，缺失时压缩降级 | 每个恢复随包的文件都需来源、revision、许可证/model card、SHA-256、模型扫描和 fresh-checkout 证据 |
| `codebase-memory-mcp` | 官方 v0.9.0 GitHub release；zip/checksums 均有 GitHub Sigstore/SLSA attestation | 当前运行时禁用；`.cbm/` 不发包；未来启用仍要求显式路径 + SHA-256 | 许可证、native SBOM/CVE、恶意软件扫描和低权限隔离运行证据 |
| 内置第三方 skills | `msitarzewski/agency-agents` | 固定 verified commit `00fb28a4…`，逐文件 Git blob 相符；build-time verifier 锁定 manifest、6 个技能与 notices 的精确哈希，运行时再验同一 manifest；不读取 ambient 用户目录 | 在最终签名 engine 中验证 6 个技能和 ATTRIBUTION/LICENSE/README 的精确可见性、无额外项及篡改故障关闭 |

### `codebase-memory-mcp` v0.9.0 来源溯源

- 官方发布：[`DeusData/codebase-memory-mcp` v0.9.0](https://github.com/DeusData/codebase-memory-mcp/releases/tag/v0.9.0)。
- 本地 `windows-amd64` zip SHA-256：
  `92f96896f952e539f0d6cb34d7892a25064b677ccbf808b8f8310ad897e86f2c`。
- 本地 `checksums.txt` SHA-256：
  `b7294616f22050124c8f2cf029cc9943e0b7d6e426fb9a0b95b1de9815c76e57`。
- 对 zip 和 `checksums.txt` 分别执行 `gh attestation verify`，两条命令均退出 0；签名身份为
  `https://github.com/DeusData/codebase-memory-mcp/.github/workflows/release.yml@refs/heads/main`，workflow SHA
  `b637e3330c96cfe452da623db068c241aaa3ec01`，builder 为 GitHub-hosted，Rekor 时间
  `2026-07-08T19:08:20+08:00`。

该证据证明被验字节的来源身份与官方发布工作流一致，不等于代码经过安全审计，也不等于“无病毒/无木马”。
本轮不会启用该运行时，仓库本机缓存 `.cbm/` 明确不进入发布包；未来启用前仍需验证许可证、native SBOM/CVE、
最终字节多引擎扫描、低权限进程边界和运行期出站行为。

### FFmpeg 8.0.1 候选字节证据

- 来源页：[Gyan FFmpeg builds](https://www.gyan.dev/ffmpeg/builds/)；官方 checksum：
  [`ffmpeg-8.0.1-essentials_build.zip.sha256`](https://www.gyan.dev/ffmpeg/builds/packages/ffmpeg-8.0.1-essentials_build.zip.sha256)。
- 当场重新下载的 `ffmpeg-8.0.1-essentials_build.zip` SHA-256 为
  `e2aaeaa0fdbc397d4794828086424d4aaa2102cef1fb6874f6ffd29c0b88b673`，与官方 checksum 一致。
- 解压 `ffmpeg.exe` SHA-256 为
  `5af82a0d4fe2b9eae211b967332ea97edfc51c6b328ca35b827e73eac560dc0d`；`ffprobe.exe` 为
  `192a1d6899059765ac8c39764fc3148d4e6049955956dc2029f81f4bd6a8972d`。两者与本机
  `C:\Program Files\ffmpeg\ffmpeg-8.0.1-essentials_build\bin\` 内已安装文件逐字节哈希一致。
- 已验候选 `bin` 在复核时只有 `ffmpeg.exe`、`ffplay.exe`、`ffprobe.exe` 三个普通文件，没有相邻 DLL。Supervisor 已把“两个目标同目录，目录只能出现这三个允许文件名且不能有目录/reparse/DLL sidecar”写入每次启动/`Validate` 的准入合同；`Validate -Json` 实跑返回上述两个精确哈希。`ffplay.exe` 只是允许存在，不会被纳川启动，也未作为目标哈希；这份本机运维合同尚未等同于最终安装包 manifest。
- 实测两个 EXE 的 Authenticode 状态均为 `NotSigned`；本机 Defender 不可用，也没有第二独立引擎报告。因此这份证据只证明“本机字节=重下载字节=官方 checksum 指向的候选包”，不证明无恶意、无漏洞或可上架。

#### 2026-08-18 许可证闭包终审裁定：维持 NO-GO

本轮复算 ZIP/双 EXE/LICENSE/README 五个 SHA-256 与 2026-07-16 来源回执逐字节一致；两个 EXE Authenticode 仍为
`NotSigned`；Gyan builds 页明示全部构建为 GPLv3 且 essentials 组合含 libx264/libx265 等 GPL 库；官方 checksum 端点
`.../ffmpeg-8.0.1-essentials_build.zip.sha256` 本轮实测已 404（该版本滚出当前 release 列表，来源可复核性降级）。
**裁定：production 与 early-access 均维持 NO-GO。** 精确理由与解除条件已归档为机器可读 receipt：
`安装与维护/构建输入/records/20260818T072454Z-ffmpeg-license-adjudication-e1d921702074168971312f209c918f0c.json`。
核心：GPLv3 静态组合体的对应源码/逐库 notice 未逐字节固定闭包；未签名；无多引擎扫描；官方校验端点已失效。
解除需：全库 corresponding source 固定闭包（或自建可重现 LGPL 最小闭环）+ 有效签名或书面风险接受 +
绑定 SHA-256 的多引擎扫描 + 纳入冻结候选三层 SBOM 后重跑发布门禁。本裁定只做来源/许可证闭包判断，
不宣称字节无漏洞或无后门。

npm 生命周期脚本的本次清单为 Electron、electron-winstaller、两套 esbuild（以及非 Windows 的 fsevents）。其中
Electron 会下载其平台运行时，但使用 npm 包自带 checksums；esbuild 在 optional 平台包缺失时含直接 registry
fallback。因此发布 CI 必须记录实际出站和安装后的原生文件哈希，不能仅凭 `package-lock.json` 宣称所有二进制已验。

## 网络与遥测边界

- 未发现第一方 Sentry/PostHog/Segment/Amplitude 等产品遥测接入。
- 模型加载设置 `HF_HUB_DISABLE_TELEMETRY=1`；受控 CLI 设置通用禁遥测变量。但第三方程序是否完全服从这些变量
  不能仅靠源码保证，仍应在隔离账户中做出站抓包。
- 模型供应商、微信/飞书、GitHub 更新、网页读取和视频下载本身是业务网络流量，不属于“纯离线”；Telegram 只在
  开发态精确风险确认后作为源码实验联网，不属于当前生产网络面。
  API 请求会把用户选择发送的内容交给对应第三方；隐私说明必须逐 provider 明示。
- 微信 durable outbox 的 pending/processing 业务数据为续跑所必需，不进入日志/安装包；done 只在完整投递组终态后按默认 30 天分批清理。dead 立即清空正文/context、哈希用户 ID、错误只留代码，再按默认 180 天和 inbound/outbound 各 10,000 行 cap 维护。该本地生命周期控制不改变微信平台或模型供应商自身的保存政策，也不证明第三方副作用 exactly-once。
- `scripts/watch_updates.py` 只读查询上游版本并生成报告，不安装、不更新。它已拒绝相对程序、PATH/PATHEXT/COMSPEC、`npm.cmd` 与链接/reparse 工具：项目 Python 走当前 `.venv` 绝对解释器，uv/gh 要求绝对路径 + SHA-256，npm 同时绑定 Node、`npm-cli.js` 和有界完整 npm 代码树；子进程环境不含 PATH、NODE_OPTIONS 或项目模型/渠道密钥。证据不全时对应栏目故障关闭；当前仍只允许人工前台运行，不得据此恢复计划任务。工具路径和摘要最终还须由受保护 launcher 提供，普通环境变量不是独立信任根。
- 媒体下载内容虽不作为程序直接启动，仍会交给 ffmpeg、图像/音频/ONNX 解析器；必须保留大小/超时限制，并在
  低权限进程中处理，以降低畸形媒体利用解析器漏洞的风险。
- desktop `media:save` 已改为封闭下载器：DNS 全部地址必须是窄化公网并 pin 已审地址，逐跳重验且禁 HTTPS 降级；Content-Length 与未知长度流都受累计 cap，单一总 deadline 覆盖 DNS/全部跳；临时文件失败清理、成功原子改名，inline bytes 另有上限。真实 CDN/代理/磁盘满仍需包后 smoke。
- `视频工作流/` 隔离回归（Python 两文件 `7 passed`、desktop release-security `6 passed`）只证明当前纳川源码默认不可运行、不可发布；它不会也无权改变独立 `D:\AI视频制作` 项目的 33 个同宿主任务。不得把该存档写成已通过病毒、依赖、许可证或媒体解析器安全审计。洁净 CI 可证明构建来源；生产共存只能在双方代码均受信时证明不共享路径/端口，不能冒充恶意同 SID 进程隔离。

### 所有公网客户端分类

| 信任类别 | 生产调用点 | 当前网络合同 | 判定/剩余门禁 |
|---|---|---|---|
| 不可信/上游返回的 URL（Python） | `/v1/videos/fetch`、webread、Studio 镜头、Claude 远程图片、微信生成媒体与官方 CDN GET/预签名 POST、飞书生成媒体 | `gateway/public_media.py` 每跳解析全部 DNS，混合/私网即拒绝；socket 固定到已审 IP，HTTPS 保留原 hostname 做 SNI/证书验证；只准 80/443、禁 HTTPS 降级；调用者 header 只准 Accept/Accept-Language/User-Agent，不能携带凭据；类型/编码/Content-Length/流式累计上限、idle 与单一墙钟 deadline、失败临时文件清理。DNS/HTTP 慢调用分别最多占 8/16 个 daemon slot；预签名请求体不跟随重定向、不重放 | 代码边界闭环后仍须真实 CDN、代理、断网、慢 DNS/slowloris、磁盘满 smoke；响应媒体随后进入解析器，仍需低权限隔离与解析器补丁管理 |
| 不可信 URL（Electron） | desktop `media:save` | 独立的主进程 pinned downloader；逐跳公网 DNS + IP pin、禁凭据/奇异端口/HTTPS 降级、32 MiB inline/512 MiB remote、idle/总 deadline、原子落盘 | 不复用浏览器导航或 PowerShell；最终安装版仍需上述真实网络/磁盘 smoke |
| 固定匿名上游 | `gateway/websearch.py` 的 Bing 搜索 | 只允许 `https://cn.bing.com/search` 精确 origin/path；复用 pinned text fetch，2 MiB cap。Bing/snippet/正文作为转义后的 `<untrusted_web_evidence>` 放在 user 数据块，另加静态可信 system policy，网页字节永不进入 system role | 搜索结果是待核验证据，不是指令；来源质量/版权和真实网络可用性仍需验收 |
| 固定平台 API/资源 | 微信 iLink、飞书固定资源下载与上传 | 平台 API 使用固定官方 HTTPS origin 和各自 token；微信预签名 CDN URL 每跳锁官方 host 并走 pinned helper；飞书 SDK/bridge 的固定平台资源不能换成任意 host，下载采用 Content-Type、Content-Length 与流累计 cap | 这是凭据型协议，不通过匿名 helper 转发 Authorization；真实账号、平台跳转/错误码和渠道可靠性仍是门禁。Telegram 生产禁用，不列入本行 |
| 配置型带密钥 provider | ConnectionStore 中的 OpenAI-compatible/Anthropic/Volcano 等、`watch_updates.py` 的 `/models` | 内置精确 host，或需运维精确 HTTPS allowlist；连接保存时 canonicalize、拒绝私网/metadata/奇异路径并绑定 target fingerprint。更新 watcher 只读复用受控连接，默认不作为发布服务启动 | 属于 owner 授权目标，不接收模型生成 URL；最终逐 provider 出站、TLS、额度/错误/重定向 smoke 和隐私披露仍必需 |
| Supabase/图床 | `orchestrator/cloud_sync.py`、`orchestrator/imagehost.py` | 默认只准 `https://<project>.supabase.co:443`；自托管需精确公网 allowlist；URL+anon key fingerprint 与 epoch/CAS 防换靶/ABA，换目标撤销 token/cursor | 本地 DPAPI/safeStorage 迁移、严 ACL 与重开复用已闭环；曾暴露凭据的供应商侧轮换/旧值失效和真实 RLS/tenant policy 仍未验 |
| 旧跨设备同步配置 | 陈旧 `SYNC_SERVER_URL` 设置 | 默认空；非空时 gateway lifespan 立即 `RuntimeError`，不再调用 `sync_cases_once` 或把 runtime Bearer 发到运维地址 | 代码闭环 stopgap；未来只能迁移到独立最小权限 sync credential + 目标 fingerprint/epoch + DPAPI 的 cloud_sync，不能恢复旧调用 |
| 固定来源 + 哈希下载 | ModelScope GGUF 显式下载、`build-local` llama runtime | GGUF 需显式开关、不可变 revision、预审 SHA-256；llama 需固定官方 HTTPS URL + SHA-256，哈希/格式不符不落盘/不解压 | 仍需许可证、模型卡、SBOM、签名/扫描与最终包 manifest；生产不做首启浮动下载 |
| 通用 extractor | `/v1/lapian/url` 的 yt-dlp | 生产默认 503，只有精确开发确认词 `NACHUAN_ENABLE_UNPINNED_YTDLP=I_ACCEPT_UNPINNED_YTDLP_NETWORK` 才进入；入口只准静态 exact 官方 host、HTTPS/443，环境不能扩 host；import 前强制禁插件，options 禁 JS runtime/remote components/cache/external downloader/cookies，并要求逐次认证的 ffmpeg+ffprobe 同目录作为 `ffmpeg_location` | 生产代码闭环 stopgap，直接上传 `/v1/lapian` 保持可用；**开发开关下 yt-dlp 仍会自行二次 DNS/跟随 extractor CDN，不是 pinned fetch**。正式包必须证明未设置风险开关；低权限 worker + 出站策略前不得把网址拉片列为生产能力 |
| 用户手动浏览 | Electron BrowserPane/webview | 用户交互导航，不是模型工具或后端下载器；sandbox/node off、权限拒绝、只准 http(s) 导航，模型 `TOOLS` 不暴露宿主浏览器 | 不能借它绕过媒体保存/网页读取策略；生产包不开 CDP |
| 禁用/非生产 | remote/stdio MCP、Codex 执行、`.cbm/`、`视频工作流/`、`scripts/_archive`/probe、`_setup_imagehost.py` | 运行时禁用、发布排除或仅显式运维/开发使用 | 不属于生产公网能力；若未来启用须重新做独立供应链、权限与出站审计 |

自动更新协议另属固定发行通道：early-access 设计依靠独立 Ed25519 信封、元数据闭包、双重复算与反回滚；stable/public
另加严格 Authenticode。未来 generic publisher 必须先写不可变版本资产并从公开只读 URL 回读 hash/size，最后才以
ETag/CAS 切换签名信封；客户端不带发布 token。当前公共 publisher 在读文件/联网前硬失败，内部事务只允许两个数值
回环测试 origin，签名 job 同身份隔离也未闭环，因此没有官方推送；stable workflow 同样固定失败。网关/bridge 对本机 engine 的 loopback 调用和本地模型探针不是公网客户端，
但仍受实例 key/PID/boot proof 与 loopback 目标合同约束。

上述 Python 不可信 URL 与 prompt-injection 边界曾用 11 个相关测试文件合并复核：当时 `132 passed, 7 warnings`、
pytest 自行 exit 0、9 个迁移模块 `py_compile` exit 0。晚期源码已经变化，该数字是历史攻击样本检查点；最终完整构建
必须重跑。即使重跑通过，也不替代最终安装包真实网络、解析器低权限隔离或第三方服务可用性验证，且不覆盖上表
明确单列的 yt-dlp。

## 正式上架门禁（全部满足才可发布）

1. 从干净、临时、受保护分支的 Windows runner 构建；checkout、setup、发布 Actions 全部固定完整 SHA。
2. `uv sync --locked` 与 `npm ci --ignore-scripts` 成功；证明实际安装集合与 lock 一致并对实际环境执行固定版本漏洞扫描；禁止自定义 registry/mirror、lockfile/环境漂移和安装期 lifecycle，所需原生载荷只能经独立固定来源/大小/哈希步骤准备。
3. 后端/桌面全量测试、类型检查、发布安全测试全部通过；秘密扫描确认种子配置和安装包内无真实凭据。
4. 生成并归档三层 SBOM：Python、npm、最终安装包/原生运行时；每项含版本、来源、许可证和 SHA-256。发布门禁会在重新验证最终 `win-unpacked` 与 `WIN_UNPACKED_MANIFEST.json` 完全一致后生成带官方 CycloneDX 1.5 `$schema` 标识的 `NATIVE_SBOM.cdx.json`。Native 闭包不再只信扩展名：除受审 EXE/DLL/NODE/PYD/SO/DYLIB/GGUF/ONNX 与当前 Electron PAK/DAT/BIN 外，任何文件名下检出的有效 PE（有界 `e_lfanew` + `PE\0\0`）、ELF、Mach-O/fat 或 WebAssembly magic 都必须进入许可证注册表，否则故障关闭；Electron/Chromium 的 locales、PAK、ICU data 与 V8 snapshot 也逐文件绑定最终 path/SHA-256/size。一个文件承载多项义务时只生成一个 parenthesized SPDX `AND` expression；标准 dependency graph 为 root → 已审 library/source component → 映射 file leaf，自定义反向 property 仅作可读证据。上游没有明确合法 purl 时省略，禁止从 URL 猜造。独立验证会从最终树和 packaged `NATIVE_PAYLOAD_LICENSES.json` 重建 canonical SBOM、验证 ref 闭包后逐字节比较。SBOM 与许可证清单只证明盘点/来源/义务绑定，绝不等价于杀毒或“无木马”结论；恶意软件扫描仍由第 6 项独立门禁承担。
5. 对 SBOM 跑 OSV/CVE 扫描；Critical/High 有修复版本时阻断，无修复版本必须形成书面风险接受和隔离措施。
6. 对所有预编译文件和最终安装包至少使用 Windows Defender（签名/引擎最新）及第二独立引擎扫描；报告绑定文件
   SHA-256。扫描不可用或样本超限即“不通过”，不得改写成“未发现病毒”。
7. 使用公司代码签名证书签署安装器、unpacked 主程序、随包 engine 及全部 EXE/DLL/PYD；逐个验证 publisher、时间戳链、撤销状态；生成并验证内容寻址 archive 与 candidate manifest 配对证据。
8. 生成构建 provenance（commit、runner 镜像、lockfile 哈希、工具版本、所有下载 URL+SHA、构建日志），与产物一同归档。
9. 对安装后的程序做最小权限、首次启动、断网、代理、升级/回滚、长稳压测和出站抓包；确认没有未声明域名或下载执行。
10. 发布前轮换所有曾进入旧安装包/日志/制品历史的 provider key并验证旧值失效；受控移除当前 Program Files v0.1.0 旧安装及两个系统快捷方式，复扫旧安装/全机制品无非空秘密；新包只含空连接种子。
11. 正式自启只由签名安装器从受保护路径创建，并验证卸载只清理纳川自有项；在洁净 CI/测试机完成验收。同宿主
    共存只在双方代码均受信时证明不共享凭据、可写路径、端口和进程控制；不可信组件必须迁入独立低权限账户、
    AppContainer、VM/独立宿主或禁用。不得把清理外部项目任务写成纳川发布动作。

建议的发布制品至少包括：内容寻址安装归档及其 candidate manifest、签名验证记录、Python/npm/native SBOM、漏洞扫描 JSON、
恶意软件扫描报告、许可证归档、第三方来源清单、构建 provenance 和发布审批单。

## 当前阻断项

- 当前审计对象仍不是冻结发布提交：`HEAD=5b8fa5e10c6d62e8a4a010d200cac6e6d0dd751d`，工作树有数百个 tracked/untracked 变更并且本轮仍在收敛。2026-08-24 候选只绑定被观测的脏快照和持久收据，不能当作可复现公开发行证明；必须形成唯一候选 commit，在 clean checkout 重新执行测试、SBOM、许可证、原生/安装包扫描、签名和哈希归档。
- 本机 Defender 未启用，尚无最终安装包的多引擎扫描证据。
- 构建前 `.venv` 漂移/7 漏洞已由严格 sync 和更新后实际环境 pip-audit 关闭；当前 `uv lock --check`、48 个实际安装包兼容性检查与官方 npm registry 审计均通过，npm 报告 0 个已知漏洞。高置信秘密模式仅命中 3 个测试文件，源码范围未发现 PEM/PFX/KEY 等密钥文件或 native 可执行载荷。源码已具备发布期 Native CycloneDX 生成与最终字节/许可证映射复验门禁，但当前没有冻结候选实际跑出的三层 SBOM；发布提交导出、干净 CI 实际环境审计及最终 native/安装包扫描仍缺失，本机依赖审计不能替代这些门禁。2026-08-18 起已有**盘点层**三层 SBOM：`scripts/export_sbom_layers.py`（合同测试 `tests/test_export_sbom_layers.py` 14 项）从 `uv.lock`/`desktop/package-lock.json`/三个 runtime lock 生成 CycloneDX 1.5 三层 + 输入输出哈希绑定 manifest，实际产物在 `data/test-evidence/sbom-20260818/`（Python 148、npm 540、第三方二进制 4 组件，FFmpeg 实文件复算通过）；它是来源/哈希/许可证清点，不是冻结候选发布级 SBOM，也不含漏洞扫描结论。
- release 测试合同现已核对精确的内容寻址 archive + candidate manifest 配对，归档名绑定 archive 哈希并拒绝旧名或额外 payload；这只是源码门禁回归，既没有生成冻结候选，也没有改变当前生产发布 `NO-GO`。
- 原生载荷的完整恶意软件证据、冻结候选三层 SBOM、本地权重逐文件来源/revision/许可证清单、FFmpeg 签名处置和项目根 `LICENSE`/`EULA`/`NOTICE` 均未闭环。`html-parse-stringify@3.0.1` 与 `lazy-val@1.0.5` 的固定提交树仍没有独立 LICENSE/COPYING 文件；2026-08-24 的打包门禁不再伪造该文件，而是使用 schema 2 `metadata-reconstructed-reviewed` 记录，绑定官方 npm registry integrity、精确上游 commit、package metadata、版权/许可证声明和复核哈希。两项已从“缺文件导致技术构建阻断”改为可审计的元数据重建证据，但不构成法律意见，不能被宣传成上游具有本来不存在的许可证正文。CPython notice 同时从错误的 python.org 安装器证据改绑到实际 uv-managed Astral python-build-standalone `20250317` 精确资产；该资产内 `python/LICENSE.txt` 与随包运行时逐字节一致。最终商业法务仍应在根许可证/EULA/NOTICE 审查中确认这些证据是否满足发行政策。
- 受限捕获当前源码证据为 operation store `24/24`、maintenance ticket store `40/40`、startup discovery/reconcile `6/6`、coordinator 关键集 `4/4`；这只关闭了有界发现与保守收敛的源码合同。生产生命周期接线、LocalService/真实 adapter、fresh-scan 调度和安装版 kill/power-loss 仍缺失，所以受限捕获继续 `NO-GO`。
- Microsoft Safety Scanner v1.455 的全盘扫描已于 2026-07-15 20:17:35 结束，return code 7；命中
  `VirTool:Win32/DefenderTamperingRestore`，对象为 `HKLM\SOFTWARE\Microsoft\Windows Defender\DisableAntiSpyware`，
  状态 `not removed`。它不是纳川项目文件命中，但证明主机存在 Defender 篡改状态，绝不能记作扫描通过。
  禁用 Defender/Windows Update 的 Local GPO、`NoAutoUpdate`、服务只读 ACL 和禁用任务已恢复并留存回执；
  `gpupdate` 成功。微软官方定义包 `1.455.155.0`（SHA-256
  `44f71152da7dc1f8d163b56e53ae6f19c7c5986fcc4e97903dd6de009a3977fc`）与平台包
  `4.18.26060.3008`（SHA-256 `3a431bac93a19172141589eba0cf1b88909bb93c479428349562445ca30a0649`）
  均为 non-reparse 且 Authenticode `Valid`，但执行都返回 `0x80070645/1605`，系统仍显示平台
  `4.18.2201.11`、签名 `0.0.0.0`。下一安全边界是重启刷新 SCM/策略镜像后恢复平台并重新执行全盘与项目定向扫描；
  在此之前 Defender 仍不可用，扫描结论仍为 `NOT CERTIFIED`。
- 主机是已结束支持的 Windows 11 Enterprise 22H2 `22621.1555`；Secure Boot 为真，但 TPM 设备未枚举且存在
  pending file rename。没有经验证的无重启修复路径；下一步需在维护窗备份、由用户明确授权重启并复验。若 Defender
  平台登记仍坏，必须用匹配 zh-CN/Enterprise 授权的微软官方受支持版介质做 compatibility scan 和保留应用的就地升级，
  不得解包硬拷平台文件、伪造产品登记或绕过 TPM/硬件资格。
- 首次 `dist/desktop/release` 含 `.icon-ico`、历史 `win-unpacked` 非空 key、未签名/无 manifest 等旧制品；清理重建后的中文名 `73ba…` 包又因 electron-builder 更新元数据改名并丢失变体而被 verifier 阻断，永久作废。ASCII 修复后的 `nachuan-0.1.0-lean-win.exe` 为 211,479,524 字节、SHA-256 `82860b5b4811783495cdcb06cfca6784205b27d7c3027cd014c58f7406c57c19`；lean.yml URL/path、runtime/model=0、seed empty、closed-set/package/metadata/SHA256SUMS 门禁曾通过，最终 gate 可在 checksum 存在后逐项复算并重复 FINAL_OK，但 Authenticode `NotSigned`。晚期源码已经变化，该文件只保留为历史 artifact，当前候选为“无”；历史 key 仍须轮换，不能安装或发布。
- 历史 `C:\Program Files\aggregator-desktop\纳川.exe` 为 v0.1.0、SHA-256 `f0682e1a470870ac94fb661f1fea44f6b23425b4e006e00061b7ec0ae4d7ff1c`、`NotSigned`，包内 engine 也未签名；其 `resources` 被固定 release-security scan 以 exit 1 拒绝，并在 `seed-connections.json` 命中 2 个非空 API key（未读取/回显值）。保留取证后，最新只读复核确认旧 Program Files 目录、Public Desktop/Common Start Menu 两个入口及该目录进程均不存在，本地入口清理闭环；命中或可能暴露的 provider key 仍须供应商侧轮换并证明旧值失效，同时复扫其它制品副本。
- 正式代码签名证书、时间戳和 GitHub release 变量属于外部状态，本地无法代替完成。
- 当前机器最新只读复核确认 `data/sync.json` 已是 `nachuan.protected-json.v1`/DPAPI，desktop userData `config.json` 已是 `nachuan.electron-secret-config.v1`/safeStorage；两者无明文 secret 字段、关闭继承且 ACL 仅当前用户 + SYSTEM。最新源码 gateway 启动成功证明 sync 信封可由当前用户重启解密；第二个独立 packaged Electron 进程也在 config mtime 不变时持续存活并复用原密文，测试进程随后精确停止且无残留。曾明文存在的 sync/provider key 还须供应商侧轮换并证明旧值失效；`connections.json` 与 `ilink_token.json` 也已是 DPAPI envelope/严 ACL。
- 当前 release workflow 只上传短期验证 artifact，publish job 固定失败；AV、SBOM、许可证、干净 VM 安装、真实微信与 soak 变成机器门禁前不存在正式发布通道。
- Agent skills 的源码/构建闭集已实现；仍须对最终 PyInstaller/签名引擎验证 manifest、6 个技能和 notices 的实际集合与篡改故障关闭，不能用源码测试替代成品验收，也不能从 ambient 用户目录补齐。
- lean 包不再自动下载模型；若商店文案承诺离线本地模型，必须先建立带许可证和 SHA-256 清单的模型发行流程。
- 本地模型 loader 的全路径 non-reparse、稳定句柄验哈希/身份和 `Popen` 前二次 attestation 已通过三文件 `43 passed`；路径式启动/加载的残余换靶风险仍是发布 P1。最终包目录 ACL/闭包、签名 manifest 和安装后换靶 smoke 前，lean 保持空 manifest，full/本地模型能力不得发布。
- desktop `media:save` 的 URL SSRF/内存放大代码边界与 7 项回归已闭环；最终安装版仍需真实 CDN、代理/断网、磁盘满和超大文件 smoke，不能把单元测试写成所有远端媒体可信。
- 网址 Lapian 默认 503 与开发风险边界以 `8 passed, 1 warning` 独立复核；正式构建/启动环境必须证明没有 `NACHUAN_ENABLE_UNPINNED_YTDLP`。开发确认词不把 yt-dlp 的二次 DNS/extractor CDN 变成 pinned 网络，不能作为生产豁免。
- ffmpeg/ffprobe 已有 Gyan 8.0.1 来源/checksum 溯源，当前 packaged Electron 也已携带并由最终 verifier 绑定两个 EXE、media manifest 和 notices；这只关闭“最终包是否带入预期字节”的盘点问题。GPL corresponding source/逐库 notice、冻结候选 SBOM、多引擎扫描、签名风险处置仍未完成，在这些证据补齐前正式媒体发行继续 `NO-GO`。
- 正式安装版的登录自启尚未实现/验收；不得从源码树恢复旧计划任务。签名安装器必须在受保护路径创建、验证并在卸载时清理自启项。
- 同宿主最新只读复核有 33 个外部 story2video 任务：31 个 Disabled、1 个 Ready、1 个 Running；动作归属 `D:\AI视频制作`，不是纳川项。`LLMAggregator` 缺席只证明纳川源码持久化已关闭；纳川不得停用/注销外部任务，而须补洁净 CI/测试机或双方 owner 认可的共存隔离证据。
- 当前生产 `data/weixin_access.json` 不存在；旧 bridge 的 `access_locked` 普通文本静默返回且旧 Supervisor 误报 ready，直接解释“你好无回复”。当前源码已把锁定态写为 degraded/not-ready，并在不调用模型时显式回复 `/whoami` 配置指引；尚待新代码 live 重启、owner 精确白名单和真实收发，禁止用 production `ALLOW_ALL` 绕过。
- 飞书旧 SDK INFO 日志曾把 WebSocket `access_key`/`ticket` 写入宽 ACL 的 `data/logs/feishu.out.log`。当前代码已补 SDK ERROR+脱敏、严格 access file、durable inbox/outbox、同 chat 顺序、claim fencing、重启续跑、终态有界维护/dead 墓碑和 Supervisor 业务 health；开放 P0/P1 转为历史日志受控清理、旧会话失效、live ACL/reparse、最终全量/构建、live 重启和真实账号 E2E，缺一仍默认关闭。
- Telegram 正式包未包含、Supervisor 不管理，默认/production runner 在读取凭据或联网前 exit 78。它缺独立 scoped key 与 durable delivery/health；未来生产启用前必须重新做供应链、权限、网络和可靠性审计。
- 除 PK-006 Windows 第三方插件代理外，其他同一 Windows SID 外部进程隔离仍是开放 P0：同 SID 恶意进程可使用 owner 权限读取用户文件和 DPAPI/safeStorage；用户 + SYSTEM ACL、HMAC/scoped key、净化环境和普通 Job Object 不能替代独立低权限身份/AppContainer/VM。
- `scripts/_archive` 仍保留会读取历史明文连接文件的旧探针。它们不是生产入口且不进 engine/Electron 包，但必须继续从正式源码/制品分发排除；若不再承担取证用途，应在保留必要证据后删除，不能把 archive 脚本当运维工具运行。

## 复核命令

以下命令只读或使用现有环境/lockfile，不会调用临时远程 runner：

```powershell
rg -n -S "curl.*\|.*sh|Invoke-RestMethod.*\|.*iex|resolve/master|snapshot_download|npx --yes|uvx " .
.\.venv\Scripts\python.exe -m pytest tests/test_local_model.py tests/test_model_supply_chain.py tests/test_mcp.py tests/test_cli_hub_security.py
npm --prefix desktop audit --omit=dev --registry=https://registry.npmjs.org
git diff --check
```

不要用 `npx <scanner>`、`uvx <scanner>` 临时生成 SBOM；扫描器自身也必须固定版本和 SHA-256，或使用组织已固定的 CI Action。
