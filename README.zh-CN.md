# 纳川

纳川定位为本地优先、BYOK 的多模型 AI 工作系统，而不是模型下拉框或单一聊天机器人。目标是让桌面端、微信、
飞书和 HTTP 入口共享记忆、路由、多模型 Advisory、受控执行、结果验收与可靠投递；当前哪些能力已由代码回归
覆盖、哪些仍需真实凭据和长稳验收，以本页下方和生产审计报告为准。Telegram 目前仅保留源码级开发实验，正式包
不包含、Supervisor 不管理，不能列为生产渠道。

## 分发形态（ADR-0013 + ADR-0015）

纳川现在有三个同步但独立放量的交付：技术用户开源版、普通用户桌面版、企业商用版。三者共用一个核心版本和
同一修复源，不维护三份分叉；更新通道、签名要求、企业策略和生产验收彼此隔离。CLI + 本地 Web 仍是开源版主入口，
Electron 桌面和企业受管发行不再废弃，但在 Authenticode、签名更新、干净机和企业权限门禁满足前保持 `NO-GO`。
详见 [`docs/adr/0015-shared-core-multi-edition-distribution.md`](docs/adr/0015-shared-core-multi-edition-distribution.md)。

Windows 开源版可从项目根目录运行 `install.ps1`，安装后统一使用
`nachuan start|update|doctor|uninstall`；中文双击入口集中在 `安装与维护`。该入口安装经源码闭包校验的 source alpha，
不是未签名 EXE 的替代包装。

源码树内 CLI 用法：`python -m cli start|status|models|chat "消息"|ui`。`npm --prefix desktop run build:web`
同时更新 `desktop/out-web` 与 wheel 使用的 `gateway/web_ui`；引擎默认托管包内 UI，
`NACHUAN_WEB_UI_DIR` 仅用于显式外置覆盖，覆盖无效时 fail-closed 不挂载。

pip 包构建与安装（`pyproject.toml` 已是可构建包，合同测试 `tests/test_pip_packaging.py`）：

    npm --prefix desktop run build:web               # 先冻结并同步 Web UI 字节
    python -m build --wheel --no-isolation           # 产出 dist/llm_aggregator-<ver>-py3-none-any.whl
    pip install dist/llm_aggregator-0.2.0-py3-none-any.whl
    nachuan start                                    # 一条命令启动本地引擎、打开 Web；Ctrl+C 停止
    nachuan status                                   # 其他命令：status|models|chat|ui|codex
    nachuan-engine                                   # 高级裸入口；未显式配置 Key 时按设计故障关闭

`nachuan start` 只监听专属回环地址 `127.77.77.77`，首次原子生成 runtime/approval 两枚独立 Key，并用当前
Windows 用户 DPAPI 保护在 `%LOCALAPPDATA%\Nachuan\local-owner-credentials.json`。启动器只把 120 秒、单次使用的
bootstrap capability 放进浏览器 fragment；页面立即移除 fragment，并换成 host-only、HttpOnly、SameSite=Strict
的持久 Cookie。长期 Key 不再显示在终端，也不进入 argv、URL、页面 JavaScript 或应用日志；以后刷新、重开浏览器或
新标签页均无需重复输入。浏览器不保存 paid-media provider key，该 key 只配置在网关进程侧。

用户已经购买 ChatGPT Plus/Pro 并通过官方 Codex CLI 登录时，可接入自己的订阅文本回合：

    codex login                                      # 官方 Codex CLI 自己完成登录
    nachuan codex bind                               # 绑定官方签名原生 codex.exe，不读取 auth 文件
    nachuan codex status --json                      # 只查官方登录状态，不消耗模型回合
    nachuan start                                    # Web 连接中心验证后出现 codex-subscription

该连接目前是受控的文本/代码问答入口，不暴露 Codex 宿主工具，也不等于 ChatGPT 网页生图、生视频等权益已接入。
Kimi Code 用户订阅的通用文本入口也已通过真实连接、单次回合和引擎重启持久化验证；官方 Windows `kimi login` 的干净退出/安全状态合同及 actual-served K3 身份仍未闭环。

当前代码定位是 **Windows 单机、单 owner 的生产加固工作树**，不是多租户 SaaS。native CLI/宿主启动路径已用
故障关闭 stopgap 收口，但最终残余审计仍有智能体宿主文件工具遍历 owner 秘密的 P0；关闭前不是生产候选。完整
审计、P0/P1 闭环、未验证项和上线阻塞见
[`docs/PRODUCTION_AUDIT_20260713.md`](docs/PRODUCTION_AUDIT_20260713.md)。MSERT 已命中主机上的 Defender
篡改注册表状态，策略虽已恢复但 Defender 平台仍不可用；最终安装包也尚未完成双引擎扫描和正式签名，因此不能宣称
“无病毒/无木马”或已经可上架。逐 provider-call attempt 的本地不可变账本与恢复查询已经落地，旧聚合表仍不得用于
商业结算；供应商发票对账、预算预留/扣减、多币种和退款/结案流程尚未闭环，因此商业计费仍是 `NOT CERTIFIED`。

本机安装、卸载、更新、启停、诊断和备份/恢复的统一中文入口见
[`安装与维护/README.md`](安装与维护/README.md)；不要在 D 盘根目录另建纳川维护副本。

## 当前支持范围

- 正式目标平台：仍在微软支持生命周期内的 Windows 10/11 x64；当前主机 Windows 11 Enterprise 22H2
  `22621.1555` 已过支持期，只能用于修复取证，不能作为干净发布构建机或正式验收机。
- 身份边界：同一 Windows 账户的单 owner；runtime API key 不是多租户身份，禁止把网关暴露给不互信用户。同一
  Windows SID 下的进程可读取 owner 数据/DPAPI，当前用户 + SYSTEM ACL 不是恶意同 SID 进程的隔离边界；运行时
  只能加载明确受信代码，第三方不可信代码必须迁入独立低权限身份/AppContainer/VM，否则保持禁用。
- macOS/Linux 暂不发布：运行态密钥当前使用 Windows DPAPI；原生 Keychain / Secret Service adapter 真机通过前，发布工作流会阻断这些平台。
- 当前仓库处于生产加固分支。历史安装包含未签名或旧密钥种子风险，不得上架；必须由新的 Release Trust Gate 重新构建。
- `0.2.0 early-access` 与 stable 的更新协议已严格分轨：体验通道设计要求独立 Ed25519 信封、metadata/hash/size、
  反回滚、下载后/安装前双重复算和用户确认；stable/public 另强制 Authenticode+可信时间戳。**当前两个通道都不可发布**：
  公共 EA 入口会在读取候选或联网前硬失败，内部存储事务只允许两个数值回环测试端点。法律/许可证、候选绑定的新鲜
  审计、独立签名身份与真实公开存储全部闭环前，不会向用户推送示例、测试或正式更新。

### 桌面与商店安装包 SKU 边界

> ADR-0015 已恢复桌面发行目标；本节重新作为发布边界生效，但不代表当前安装包已经获准交付。

当前 Windows 商店候选包只是 **Electron 桌面端 + bundled Turn Engine（含 HTTP API）**。它不包含
`scripts/start_all.ps1`、Supervisor、`run_weixin_ilink_bridge.py` 或 `run_feishu_bridge.py`；单独安装该包不会开通、
后台运行或保证微信/飞书收发。微信与飞书目前属于从受审源码树启动的受管运维部署，需要
独立配置、Supervisor 和真实账号 E2E。在有签名的渠道服务安装/升级/卸载链交付前，不得把它们宣传为
“安装商店版即可用”的功能。Telegram 继续不进正式包、不受 Supervisor 管理、生产禁用。

## 运行结构

    Channel adapters
        ↓
    Turn Engine
        ├─ 快速单模型聊天
        ├─ 多模型 Advisory：规划 → 作答 → 跨供应商审查
        ├─ Controlled Execution：一次性 Capability + 工作目录约束
        └─ Outcome Gate：completed / completed_unverified / partial / failed
        ↓
    Managed Channel Delivery（微信/飞书）：durable inbox/outbox、去重、重试、死信、健康状态

核心词汇见 CONTEXT.md，关键决策见 docs/adr。

多模型互审按实际 provider/model/family/连接域计票；发起模型的票权固定为零，只接收其它模型的独立审查并汇总，不能
自己审自己。凑不出至少两个异 family、异连接域且完成实际身份验真的审查席位时，结果必须是 `review_unavailable`，
不能用请求别名、自报型号或同源重复席位伪造协同。

## 安全启动

在仓库根目录运行：

    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start_all.ps1

监督器会生成随机本地网关 Key、启动并健康检查引擎与已配置渠道、轮转日志，并每六小时备份全部 SQLite。
本地模型校验/冷启在后台完成，不阻塞网关与渠道；校验成功后才热重载进模型目录。正式安装包只运行随签名产物
放入 `resources/engine` 的 bundled engine，不会旁加载安装目录边上的源码、`.venv` 或系统 `uv`。

admission 对全部已认证 POST 默认计费，只豁免审批 resolve 与 feedback/inject/undo 控制操作；远端 video poll/
fetch 与 Studio 大文件 GET 也计费。默认 per-key 并发 8、
进程全局 32、滚动 60 秒 120 次、SQLite 本地日桶 2000 次。异步 Studio/video/job 另有进程内 global 8、per-key 4、
TTL 6 小时 lease。P1 代码闸已通过最新 admission 与 video/provider 合并回归；global/lease 按进程计算，多
worker 会成倍放大。它也不是
provider-specific、美元/Token 或供应商套餐预算。

图像/视频创建属于可能付费的操作。Gateway 除普通 runtime Bearer 外，还要求独立的
`X-Nachuan-Paid-Media-Key`；该能力由 `NACHUAN_PAID_MEDIA_API_KEY` 注入，必须与 runtime、审批和渠道能力彼此独立，
未配置、格式错误或重叠时故障关闭。内部供应商调用仍要求 16–128 字节 ASCII `Idempotency-Key`，但 renderer/浏览器
既不持有 paid-media key，也不生成或保存该幂等身份。可选 Electron 壳通过 main 专用代理进入付费链；本地 Web UI
只调用 `/v1/paid-media/web/*` 的闭集 POST API，由 Gateway 在服务端完成确认摘要校验、幂等 dispatch 和凭据注入。
Gateway 持久主体由独立 paid capability 做域分离哈希，而不是由可轮换的 runtime Bearer 派生；runtime Bearer 轮换不改变恢复域，
paid capability 轮换会改变恢复域并使旧未决操作的自动重试故障关闭。媒体 provider 的 `create_image/create_video` 还在
统一调用边界要求一次性 authority；只有付费路由完成持久 claim 并进入 provider phase 后才签发，因此 agent、tool-agent、
Studio 或其它内部直调不能绕过付费门禁、财务账本而触达 provider。

Gateway 付费请求库已升级到 schema v2，以随机 database identity 和单调 mutation sequence 绑定非秘密
`.rollback-anchor`；每次 mutation 先原子写 anchor 并 fsync，再以 SQLite `synchronous=FULL` 提交。独立专项 `8/8` 与
store 回归 `48/48` 已通过，能够锁死单独恢复旧数据库快照、替换数据库、sequence 回退和 anchor 丢失。但同时删除或
成对恢复数据库与 anchor、同 SID 篡改、合法备份后的人工重锚及真实断电仍没有闭环，不能把它称为完整 anti-rollback。

Desktop 与 Gateway 对付费 raw body 使用一致的 24 MiB 上限。`model`、`prompt` 必填且有界，image/video/
`extra_body` 使用版本化闭集；未知字段和复杂 provider 参数会在原生确认框与 claim **之前**拒绝。确认框展示固定 path、
model、prompt 有界预览、全部允许的计费标量、输入数量、请求字节数和完整 SHA-256，用户看到的购买摘要不再只是笼统警告。

纯 Web 结果只向浏览器暴露 `nachuan-paid-media://sha256/<digest>` 引用；浏览器用固定的
`POST /v1/paid-media/web/read-asset` 请求内容，原始 capability token 始终留在 Gateway。首次物化会先把完整资产集逐项复验并提交到
principal 绑定的本地 Web archive，再按 durable ACK → 对象清理 → reservation 释放的顺序收口；归档提交后中断可按同一
receipt 幂等续跑；含资产结果的 ledger proof、archive commit 与 durable ACK 复验同一个由 principal、installation
identity/epoch 和完整资产描述符确定的 receipt，漂移即故障关闭。历史读取优先使用已验证归档。archive schema v3 对
全 archive 中“按 principal 隔离去重”的唯一对象正文总计设 8 GiB 硬上限，另限
100,000 个文档、400,000 个成员和 512 MiB 主 SQLite 文件；journal/WAL、临时文件及其他旁车不计入这些口径。服务端每进程
另设 2 个物化槽和 2 个响应读取槽；读取仍会把单个最多 24 MiB 的资产完整载入内存，不能把并发闸理解为流式传输。
当前不静默淘汰，也尚无用户可用的保留期、删除/导出以及 ledger+archive 协调备份恢复流程；达到任一上限会故障关闭，
因此不能据此宣称数据生命周期或长期商用已闭环。

Electron main 在任何供应商 dispatch 前，先检查没有未决操作，再以互斥的 Electron 原生警告框取得每次**新 claim**的
用户确认；安全重试只复用既有操作，不冒充一次新购买。操作写入 safeStorage 加密的 v3 严格账本，并由独立加密 anchor
绑定随机 ledger identity 与单调 sequence floor；账本缺失、anchor 缺失/错配或序列倒退均锁住恢复。账本只允许一个
未结案操作，状态闭集为 `claimed`、`dispatching`、`recoverable`、`result_ready`、`delivered`、`reconciled`。所有
非 2xx 和传输结果未知都进入未决恢复，不按 HTTP 状态猜测“肯定没扣费”。有效 2xx 的规范化响应以 24 MiB 上限暂存于
v3 加密账本；`result_ready` 重试可直接从本地重放而不再次访问 Gateway/provider，结案后清除大响应但保留 30 天
tombstone。

renderer 从操作开始即冻结目标 conversation/message，避免切换会话后把结果写错位置；结果先进入 `awaiting_ack`，再从
实际序列化的会话快照逐字段读回验证，不能用“localStorage.setItem 没报错”冒充持久化。只有 main 确认 `delivered` 后才
清除消息锚点；若在两阶段之间崩溃，启动收敛逻辑会复验结果、补 ack 或保留未决操作。旧 renderer journal 只经严格
迁移进入 main，并在 renderer 旧槽位写入旧版本无法接受的 sentinel 阻断降级。原消息丢失时，人工核销只展示 main 的
可信操作字段，把用户说明明确标为未验证证据，并连续通过两次原生确认后写 `reconciled` tombstone。

两处控制面仍未封口。P1：底层 ack IPC 目前只提交 `operationId`，main 没有自己持有的结果落库证明也会把操作推进
`delivered` 并清除 24 MiB 结果正文；正常 renderer 会先做序列化读回，但该顺序还不是 main 可验证的安全边界，仍需
main-owned result vault/persistence proof。P2：legacy import renderer channel 虽有 schema/sender 校验，却没有 main-owned
durable one-shot seal 证明迁移入口已永久消费。两项都不能被正常 UI 路径测试或 package 结构门禁冒充为已解决。

这里仍有明确容量边界：当前 conversation `localStorage` partialize 对 `data:` 图片的总预算约 2.5 MB。超预算结果现在会
在正常 renderer 流程中因序列化读回不一致而拒绝 ack，不再由该路径误报“已交付”；main v3 仍保留结果并可本地重放，
但会继续阻断新的付费任务。P1 裸 ack 风险仍如上开放；结果进入未来的 IndexedDB/受控文件结果库，或基于真实供应商
证据人工核销前，“大 base64 图片恢复”仍是 `NO-GO` 项。

最终包门禁会解出 ASAR 中实际执行的 main、preload 和全部 renderer JavaScript：用 AST 验证 main 的真实
IPC handler → service 调用、BrowserWindow preload 绑定，以及 preload 的 method → channel → contextBridge 映射；renderer
HTML 只允许一个模块入口，全部 JS chunk 都进入闭集、数量和容量检查，并禁止 paid header/env 或自行直连/生成
Idempotency-Key。该门禁已与 packaged-integrity 合跑 29/29，通过且拒绝 2026-07-14 的旧 ASAR；旧包不能复用、升级或交付。
本轮窄回归只证明当前源码合同，不等于可上架：仍无真实供应商小额调用与账单对账、安装/卸载/自动更新、签名安装版
kill/power-loss 恢复、最终字节双引擎与第三方全量恶意扫描；同 SID 与动态插件也不是强隔离。详见
`docs/adr/0006-paid-media-idempotency-and-recovery.md`。

状态：

    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start_all.ps1 -Action Status -Json

停止：

    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start_all.ps1 -Action Stop

开发时只从 `安装与维护\开发模式启动桌面端.cmd` 进入。不要用公开默认口令；生产运行不允许匿名网关。

普通 runtime key 不能自行批准高风险动作。连接/同步变更与人工裁决还要求独立审批 key；桌面 renderer 不持有
该密钥，只能通过 Electron main 的固定 IPC 和原生确认框执行。可写动作另需短 TTL、精确绑定输入和目录、只能
领取一次的 capability。

注意：Codex `read-only` / Claude `plan` 不是 Windows OS 沙箱；同一用户的 CLI 仍可能读审批密钥和登录配置。
在独立低权限 OS 沙箱落地前，agent exec/job/resume、coding、arch-editor、带工具 vision、daily-video 宿主启动器
和通用 `run_command` 等所有可让模型驱动宿主工具的路径都必须 fail-closed，不能把 “plan”“read-only”或工具
allowlist 当作 OS 隔离。当前代码的预期行为正是返回 503/阻断；这些能力尚未实现安全重启用。

同样，`read_file`/`list_dir`/`write_file` 不能因为“不启动子进程”就默认安全：若工作根是用户 HOME 或包含运行态
`data/`，模型可读到审批 Key、CLI 登录态或其他 owner 凭据。当前 P0 在专用无秘密工作区/隔离 worker 与回归证据
完成前也要求这些宿主文件工具故障关闭。

固定 `--safe-mode --tools ""`、空临时目录和净化环境的 Claude 纯文本 chat 不属于上述宿主工具执行路径；它只在
`CLAUDE_CLI_PATH` 与 `CLAUDE_CLI_SHA256` 精确匹配、逐次复验并禁用 plugins/hooks/MCP/commands 时注册，不从 PATH
发现。哈希准入仍不等于 OS 沙箱或恶意软件证明。

引擎不扫描其他 `AppData/Roaming/*/config.json` 来发现 key；只接受 Supervisor/Electron 启动时精确注入的
runtime key，避免其他本地应用通过伪造配置获得网关权限。

## 渠道授权

所有受管渠道默认拒绝，`/whoami` 仅用于取得自己的标识：

- 微信：生产写入严格 schema 的 `data/weixin_access.json`；配置可原子替换并热撤销。
- 飞书：生产写入严格 schema 的 `data/feishu_access.json`。
- Telegram：生产禁用。仅源码开发实验同时设置 `NACHUAN_ENV=development` 和精确风险确认词才可启动；它没有
  durable delivery、Supervisor health 或生产 scoped key。

旧 `WEIXIN_ALLOWED/WEIXIN_OWNER`、`FEISHU_ALLOWED_USERS/FEISHU_OWNER_OPEN_ID` 只在精确开发环境兼容合并。
仅本地开发允许双重显式全开放，例如 `NACHUAN_ENV=development` 与 `WEIXIN_ALLOW_ALL=1`；生产环境中的
`ALLOW_ALL` 会被忽略。

## 验证

    .\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
    npm --prefix desktop run typecheck
    npm --prefix desktop test
    npm --prefix desktop run build

付费媒体的 main 账本/service/IPC、renderer 路由/恢复/两阶段 ack、Gateway provider authority 与最终 ASAR 合同均有
本轮窄回归；这些源码级证据不替代最终工作树全量重跑、安装版 smoke、故障注入或真实供应商验收。

正式发布还必须通过依赖审计、密钥扫描、固定第三方二进制 SHA-256、包结构验证和签名验证。stable/public 缺少
Authenticode 证书时按设计失败；明确标注的 early-access 可暂时未签名，但仍必须通过独立 Ed25519 更新信封、许可证、
SBOM、最终扫描和干净构建门禁，不能冒充商店/stable。

自动化测试通过也不等于真实渠道已打通。微信和飞书必须分别用真实 owner 凭据完成一发一收、重复消息、断网恢复
和 dead 告警验收；操作步骤见 `RUNBOOK.md`。Telegram 只有在未来补齐生产合同后才进入这套验收。

## 数据与恢复

运行态连接和微信 token 使用当前 Windows 用户作用域 DPAPI 加密，数据目录 ACL 只允许当前用户和 SYSTEM；这可
阻止其它普通账户读取，但不能隔离同 SID 恶意进程。全量数据库备份：

    .\.venv\Scripts\python.exe scripts\sqlite_backup.py backup --data-dir .\data --backup-root .\data\backup\sqlite --keep 14

恢复默认只验证；实际应用前必须停止所有写进程。完整步骤见 RUNBOOK.md。

## 运维入口

- 健康：GET http://127.0.0.1:8080/health
- 日志：data/logs
- 微信投递状态：data/weixin_bridge_health.json
- 飞书投递状态：data/feishu_bridge_health.json
- SQLite 备份：data/backup/sqlite
- 发布与回滚：RUNBOOK.md
- 上架门禁与 P0/P1：docs/PRODUCTION_AUDIT_20260713.md
- 第三方与恶意软件证据边界：docs/THIRD_PARTY_SECURITY.md
- 长期战略目标（本轮不实施）：docs/STRATEGIC_GOALS.md
