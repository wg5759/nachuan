# 纳川插件内核策略：吸收 DeepSeek Harness“一切皆插件”的精华

> 状态：PK-001～PK-006 最小纵切已实施；PK-007～PK-008 待推进
> 日期：2026-08-26
> 目标：在不破坏纳川现有安全账本、真实渠道和安装发行边界的前提下，把模型、工具、协作、知识、渠道和 UI 变成可组合能力

## 1. 最终判断

纳川应该认真学习 DeepSeek Harness，但不应直接把 DeepSeek Harness/Cordis 作为当前生产内核依赖，也不应照搬“无特权核心、动态代码与其他插件平权”的信任模型。

建议把纳川的架构口号定为：

> **能力皆插件，权限归内核，事实进事件，副作用可撤销。**

它保留“一切皆插件”的可组合性，同时明确企业产品必须存在不可绕过的最小可信内核。

## 2. DeepSeek Harness 真正值得学习的部分

截至 2026-08-24，DeepSeek Harness 官方仓库版本仍是 `0.1.x-rc` 开发者预览，README 明示未来会有破坏性变更。官方架构不是简单的“扫目录加载插件”，而是以下完整体系。

### 2.1 运行时是一棵可组合插件树

- Profile 定义一套运行形态，例如 Web、Headless。
- Bundle 提供成组的配置行和插件代码。
- 用户 patch 在 bundle 之上替换或插入配置行。
- 启动时可以 dump 出机器实际加载的完整插件树。

这比纳川目前在 `gateway/app.py`、`router.py` 和 `orchestrator/workflows/*` 中硬编码导入更可审计、更易替换。

### 2.2 Service Definition / Provider / Consumer 三角色

一个能力缝隙不是一个 Python 类或一条 if 分支，而是：

1. Service Definition：稳定接口；
2. Service Provider：具体实现；
3. Consumer：只依赖接口的使用方。

例如模型、存储、文件系统、子进程、沙箱、审批、技能、工具、会话、UI 都使用统一能力缝隙。更换 provider 时，消费者无需复制分支。

### 2.3 类型化事件分域

- Durable Session Event：必须重放、审计、恢复的事实；
- Live Agent Event：请求、步骤、工具运行中的拦截点；
- Capability Event：文件、工具、遥测等能力的策略附着点。

“模型可见即必须进日志”是很强的原则：任何进入模型请求的内容都必须能由事件日志重建。这非常适合纳川现有的结果真相、渠道防重放和长期任务方向。

### 2.4 可逆副作用和依赖注入

- 插件通过 `apply(ctx)` 注册能力；卸载时所有 event、tool、timer 自动解除。
- 外部连接等资源通过 effect disposer 显式回收。
- 插件声明 `inject` 依赖，依赖未就绪就不激活；启动结束仍缺依赖会明确失败。
- provider 更新导致依赖者重新挂载，避免残留半旧状态。

这能解决纳川长期运行时最危险的“旧回调、旧定时器、旧连接、旧模型代际继续活着”问题。

### 2.5 Host/Client 双面插件

DeepSeek Harness 把服务端执行和浏览器 UI 分成两个插件面：Host 处理能力，Client 注册界面和交互；两边有精确版本和运行身份。纳川 Electron Main/Engine/Renderer 目前也天然需要这种三面边界，而不是让 Renderer 直接获得 Engine 权限。

## 3. 不能照搬的地方

### 3.1 项目仍处开发者预览

- 官方 README 明示快速迭代和破坏性变更。
- 当前发行是 RC 预发布，而不是稳定 ABI。
- Cordis 论文自身也是 2026-08-13 的持续修订预印本。

因此当前可学习设计、做兼容适配器和试验，但不应把纳川稳定商业版绑定到其内部 API。

### 3.2 动态插件不是安全沙箱

官方 `cordis-host-runner` 明确说明：Host 动态插件使用的 `node:vm` 只隔离全局对象，不是安全边界；插件能触达其声明的真实服务，必须按 Bash 权限对待。同步超时也只限制同步执行，异步逻辑可越过该时限。

纳川面向个人、企业和真实渠道，第三方或模型生成代码不得与账本、凭证、渠道发送和付费调用同进程平权。

### 3.3 “批准未来版本”不适合默认企业策略

DeepSeek Harness 的动态插件可以选择一次授权覆盖同一插件未来版本。纳川默认只能批准精确 `plugin_id + version + digest + capability_set`；未来版本必须重新验证。只有签名官方插件、能力集合未扩大且策略明确允许时，才可走受控自动升级。

### 3.4 Windows 沙箱与远程 Web 仍有边界

- 官方文档把 Windows ACL restricted-token 后端标为 `partial`，并列出 Everyone/hard-link 等残余边界。
- 沙箱模式只描述文件副作用，不自动约束网络和进程可见性。
- 官方 Web 信任说明仍把真正远程部署认证列为后续工作；Host/Origin 防护不是身份认证。

纳川不能用“有沙箱插件”替代独立低权限身份、AppContainer/VM、出站网络策略和企业鉴权。

### 3.5 生产配置不能接受任意脚本表达式

DeepSeek Harness patch 支持 `!!js` 表达式，适合开发者 Harness。纳川正式发行配置应使用签名、闭集、版本化 JSON/YAML Schema，禁止生产配置在高权限宿主内执行任意表达式。

## 4. 纳川应采用的四层结构

```text
┌────────────────────────────────────────────┐
│ 产品组合层：Personal / Enterprise / Server │
│ Store / Dev profiles + signed bundles      │
├────────────────────────────────────────────┤
│ 能力插件层：模型、工具、工作流、RAG、渠道、UI │
├────────────────────────────────────────────┤
│ 隔离执行层：restricted worker / AppContainer │
│ VM / remote runner / scoped IPC            │
├────────────────────────────────────────────┤
│ 最小可信内核：身份、权限、账本、审计、更新、凭证 │
│ plugin verifier + event log + capability broker │
└────────────────────────────────────────────┘
```

### 4.1 最小可信内核永远不插件化

以下边界可以有策略 provider，但最终执行门不能被第三方插件替换或绕过：

- 已认证主体、租户和真实接收者绑定；
- 付费调用、幂等、防重放、provider phase 和财务账本；
- 凭证库、密钥读取和出站授权；
- 企业 RAG 的租户硬隔离、授权终检和撤权 epoch；
- 安装根、代码签名、自动更新信任和反回滚；
- 事件日志提交点、审计收据和恢复裁决；
- 插件来源、签名、权限声明、隔离等级和撤销名单；
- 高权限 IPC 和本地服务身份。

安全策略本身可由插件提供建议或规则包，但内核拥有唯一 `allow/deny` 执行点和默认拒绝语义。

### 4.2 能力插件

适合插件化：

- 模型/provider 适配器；
- 模型路由、评测和成本策略；
- 工具、Skill、MCP 适配器；
- 多模型协作流程、互审、DAG、Agent Team；
- 知识连接器、解析器、向量检索、重排和输出分类器；
- 微信、飞书、钉钉、Telegram 等渠道适配器；
- 长任务调度器、checkpoint 和通知器；
- UI 工作区、设置卡、状态面板和诊断面板；
- 存储、备份和云同步适配器。

“插件化”只表示通过稳定接口被组合，不表示获得同等信任。

### 4.3 隔离执行层

按信任等级分三类：

1. **内置受审插件**：第一方、固定源码、随签名安装包发布；可在 Engine/Main 受限进程内运行。
2. **第三方插件**：必须在独立低权限 worker、AppContainer、VM 或远端 runner 中运行，只经版本化 IPC 使用获准能力。
3. **模型临时插件**：会话级、内存级、默认无网络/无凭证/无长期写入；精确版本单次授权，退出后销毁，不自动恢复。

禁止因为插件声明了 `filesystem`、`network` 或 `channel.send` 就直接把对象引用交给它。内核只签发窄能力票据。

## 5. Nachuan Plugin Manifest v1

每个插件应有不可变 manifest：

```json
{
  "schema": "nachuan.plugin.v1",
  "id": "com.example.provider.demo",
  "version": "1.2.3",
  "api_version": "1",
  "kind": "provider",
  "entrypoints": {"engine": "...", "main": "...", "renderer": "..."},
  "capabilities": ["model.chat"],
  "data_scopes": ["session:model-input"],
  "network_scopes": ["https://api.example.com:443"],
  "ui_slots": ["settings.models"],
  "config_schema_sha256": "...",
  "artifact_sha256": "...",
  "sbom_sha256": "...",
  "license": "Apache-2.0",
  "publisher": "...",
  "signature": "..."
}
```

规则：

- 未声明的能力不可调用；
- 权限集合扩大必须重新确认；
- 版本和 digest 必须同时匹配；
- Renderer 入口不得因此获得 Engine/Main 对象；
- 配置字段闭集验证，禁止任意代码表达式；
- 安装、启用、授权、升级、停用、卸载是不同状态和不同收据。

## 6. 服务、事件与副作用合同

### 6.1 服务三角色

建议统一定义：

```text
ServiceDefinition  稳定接口、版本、错误语义
ServiceProvider    实现、健康、能力声明、dispose
ServiceConsumer    只依赖接口，不导入具体 provider
```

同一服务只能有一个 authoritative provider，或由内核明确规定聚合规则；不能由加载顺序偶然决定。

### 6.2 事件分三类

- `fact/*`： durable，进入事件日志；
- `runtime/*`：进程内状态通知；
- `policy/*`：可观察或建议，但最终 gate 由内核调用。

模型可见内容、工具调用、渠道投递、审批、授权、插件版本变化和知识来源都必须产生 durable fact。

### 6.3 可逆副作用

插件启动必须形成一个 effect scope，原子注册：

- event listeners；
- tools and routes；
- timers and background jobs；
- process/session handles；
- temporary directories；
- UI slots；
- connection pools。

任一注册失败，全部回滚。卸载完成后必须证明上述集合归零；释放失败则插件进入 `quarantined`，不能假装 disabled。

## 7. Profile 与 Bundle

纳川可定义：

- `personal`：单所有者、本地优先；
- `enterprise`：多租户身份、RAG 权限、审计和组织治理；
- `server`：中央团队服务；
- `store`：应用商店闭集能力；
- `developer`：允许本地未签名插件，但醒目标识且与正式数据隔离。

Bundle 是签名的插件组合，不复制源码：

- `nachuan-base`：会话、模型、工具、知识、审批；
- `nachuan-desktop`：Main/Renderer；
- `nachuan-channels-cn`：微信/飞书/钉钉；
- `nachuan-enterprise-rag`：企业知识服务；
- `nachuan-agent-team`：商业协作。

生产 profile 只加载安装包随附或受信仓库解析出的精确 bundle。

## 8. 当前实现与剩余差距

截至 2026-08-26，PK-001～PK-006 最小纵切已经落地：`orchestrator/plugin_kernel.py`
提供严格 manifest、service/event registry、能力票据、借用租约、LIFO effect 回收、
失败回滚、卸载和 quarantine；`EchoProvider` 已通过 `provider.factory.echo` 内置插件
接入 legacy Router。`ToolRegistry` 新增闭集 schema、精确 `tool.execute:<name>` 能力、
逐次验票、调用借用和卸载撤销；现有六份受审 Skill 已冻结为不带执行入口的
`nachuan.skill-bundle.v1` 数据服务，`list_skills/load_skill` 由同一 bundle 工具插件提供。
legacy Tool Agent 只从当前 Router 内核读取这两个工具的实时 schema 和执行入口；插件卸载后
模型 schema 与执行能力同时消失。低风险 `pipeline` 已成为 `workflow.pipeline` 服务插件，
由严格能力票据发出 turn/step/model/result 四类 durable event；SQLite 真相层使用精确 schema、
绝对 WAL deadline、原子建库、容量上限和全局 SHA-256 链。事件只留执行标识、路由、状态、
长度与内容摘要，不复制 prompt/instruction/output；没有持久 sink 时在首次模型调用前故障关闭。
Router reload 会复用同一内核，关闭时先清 provider 与工作流借用，再关闭事件库，旧接口保持兼容。
PK-005 新增闭集 `UiSlotRegistry`，首个内置 `workspace.orchestration` slot 只允许映射到
已编译的 `orchestrate` 组件；Host 不可下发 JS、HTML、URL 或文案。Electron Main 只能通过
挑战后同一 socket 的 `plugin.ui.snapshot` HMAC 会话能力读取，preload 只暴露无参数只读 IPC，
Renderer 再次验证闭集 DTO；Web 使用普通受保护只读端点保持同形 API。
PK-006 增加签名第三方 bundle、闭集 SBOM、撤销集、持久 quarantine、单次有界 IPC 和
Windows 真 AppContainer worker。第三方 Python 不被导入 Engine；内核只挂载内置代理，再按
`id + version + artifact_sha256` 精确选择已验 bundle。

仍待统一迁移的部分包括：

- 目前只有无外网、无密钥的 `EchoProvider` 完成插件纵切；其他 provider 仍由 Router 旧构造路径管理。
- MCP registry 有注册表外形，但生产能力被整体禁用，尚无签名、隔离和权限合同。
- 除 `list_skills/load_skill` 外，其他 `TOOLS` 仍是 legacy 静态列表，工具实现和分发仍集中在 `tool_agent.py`。
- 除 `pipeline` 外的工作流仍在 `gateway/app.py` 中逐个直接 import，新增流程仍需改 Gateway。
- 目前只有“多模型协作”工作区入口迁为 UI slot；其余工作区和设置面板仍是硬编码。
- `pipeline` 事件目前只重建执行拓扑与摘要，不能重建客户原文；其他会话、工具、插件和渠道也尚未汇入统一事件模型。

因此继续采用旁路内核和 legacy adapter 渐进迁移，不做大爆炸重写。

## 9. 渐进迁移路线

### PK-001：内核合同，不改业务（已完成最小纵切）

新增：

- `PluginManifestV1`；
- `ServiceRegistry`；
- `EventRegistry`；
- `EffectScope`；
- `CapabilityBroker`；
- `PluginLifecycleReceipt`。

先用 fake 插件验证加载、依赖、失败回滚、卸载和权限拒绝，不接真实 provider。

### PK-002：第一个模型 provider 纵切（EchoProvider 已完成）

把 `EchoProvider` 作为首个内置插件：

- legacy router 通过 adapter 读取 registry；
- 旧路由接口和测试保持不变；
- 插件卸载后模型目录立即撤销；
- 不涉及密钥和外网，风险最低。

### PK-003：工具与 Skill（已完成最小纵切）

- `list_skills/load_skill` 已迁入内核 `ToolRegistry`，通过 `PluginContext.register_tool` 挂载；
- 工具注册必须拥有精确 `tool.execute:<name>` 能力，每次调用重新验票，借用期间禁止卸载；
- Skill 已变成冻结数据 bundle，不含 Python/JS entrypoint，不执行 `SKILL.md` 中的代码或命令；
- 现有 `trusted-manifest.json` 及每份 Skill SHA-256 继续作为发行来源门，篡改后 bundle 与工具均不挂载；
- 聚焦核心25项、相邻工具/Router/Store50项、管理/目录63项、依赖边界13项与工具/Skill/打包组合118项分区通过；去重后15个文件共224个用例均有绿色终态，wheel 合同确认携带 `plugin_kernel.py/tool_plugins.py/provider_plugins.py`。
- 本机另发现未改动公开400f8fb也可复现的 `ConversationStore` 冷启动 WAL 锁等待；它发生在插件执行前，已单列为 SQLite 稳定性债务，不能拿来否定或冒充 PK-003 证据。

### PK-004：工作流与事件日志（已完成最小纵切）

- 低风险 `pipeline` 已迁为 `workflow.pipeline` 内置服务插件；legacy HTTP 路由只借用服务租约，不再直接调用实现；
- 本流程不使用工具，因此如实只产生 turn/step/model/result，不伪造 tool 事件；以后真实工具调用必须使用闭集 tool 事件；
- durable event 必须先落 `data/workflow-events.db` 再通知监听器，缺 sink 时首个模型调用前拒绝；落盘中断向 HTTP 投射 `retry_safe=false`；
- 事件库是 append-only 精确 schema、全局哈希链、20 万事件/256 MiB 逻辑载荷/384 MiB 文件上限，并纳入 readiness、在线 SQLite 备份与数据生命周期清单；
- 原始 prompt、instruction、output、content 在任意嵌套层级均拒绝入库，只保存 SHA-256、长度、路由和终态；这能审计拓扑和篡改，不能冒充完整内容恢复；
- 直接调用 `run_pipeline` 的 legacy adapter 继续兼容；已有 Provider Call Ledger、会话库和任务账本均未重写真相源；
- 聚焦事件/API/生命周期/备份/隐私/打包回归 126 项及 wheel 自包含合同通过；候选53为880个声明文件，公开最终提交 `a237fc8` 的 Actions `32929332224` 为后端4139/40、Desktop1424/14、发行证据37、发行安全18全绿；本机社区版已升级至同提交，health/readiness均ok、数据库8/8、在线备份17库并包含事件库，四插件实挂且关闭归零。真实付费模型、渠道和长期归档轮换不属于本纵切证据。

### PK-005：Host/Main/Renderer 三面插件（已完成最小纵切）

- 内核新增 `UiSlotDefinition/UiSlotRegistry`，slot 注册必须持精确 `ui.slot:<slot_id>` capability；重复 slot 或同 surface/component 阴影注册原子失败，卸载自动移除；
- 当前闭集只有 `surface=workspace.menu`、`component=orchestrate`、`slot_id=workspace.orchestration`；catalog 绑定精确 SHA-256，拒绝 reparse、未知字段和远程代码字段；允许 uv/pip 产生的受哈希约束 hardlink，因为解析的正是同一次已验哈希字节；
- Engine 提供内容无关 `nachuan.plugin-ui.snapshot.v1`，只含 slot、顺序、插件 id/version 和 artifact digest；内部路由不进入 OpenAPI；
- Electron Main 固定选择 `plugin.ui.snapshot + GET + /internal/v1/desktop/session/plugin-ui-snapshot`，沿用挑战、同一 loopback socket、boot generation、nonce、HMAC 请求与签名响应；Renderer 不能选择 capability、target、method、header 或 body；
- preload 只暴露无参数 `getPluginUiSnapshot()`；Main 和 Renderer 都用同一闭集解析器复验，通用 Renderer Engine 代理明确拒绝 `/v1/plugin-ui/snapshot`，renderer 无长期 key；
- Web shim 通过带 runtime authority 的 `/v1/plugin-ui/snapshot` 获取同一 DTO，不携带 approval key；Team Web 继续标 planned；
- 现有 `OrchestratePane` 代码仍由正式构建编译，插件只能决定入口是否出现，不能携带或执行组件代码；slot 缺失或响应畸形时入口安全隐藏；
- 聚焦公开候选 Python 153项/6跳过、Desktop 81项、typecheck、Web/Electron build 与 wheel 自包含合同通过；候选57为887个声明文件。最终公开提交 `8017158` 的 Actions `32939620298` 为后端4153/40、Desktop1433/14、发行证据37、发行安全18全绿。本机社区版已升级至同提交，doctor、health/readiness、数据库8/8、在线备份17库均正常；`-I` 隔离 wheel 实际加载五插件和 UI slot，卸载后slot归零、关闭后插件归零，HTTP快照/Web shim/正式Web资产字节全部复验。当前只证明内置只读菜单 slot，不证明动态第三方 UI、安全 worker、热更新订阅或其他面板已插件化。

### PK-006：隔离第三方插件（已完成最小纵切）

- bundle 只允许 `manifest.json/plugin.py/sbom.json` 三个普通 non-reparse 文件；manifest、SBOM、请求和响应都必须是无重复字段的 canonical JSON；
- Ed25519 签名绑定精确入口/SBOM SHA-256、publisher key id、版本、capability 和 CPU/内存/请求/响应/墙钟限额；未知 publisher、改字节、多文件或撤销身份均在 worker 前拒绝；
- broker 只把验过的 `plugin.py` 字节复制到每次临时执行根；worker 以 `-I -S -B`、封闭环境和四字节长度帧只处理一个 JSON 请求，不在 argv 携带凭据或客户目标；
- Windows 启动器用 `SECURITY_CAPABILITIES` 创建无 capability AppContainer，恢复线程前反查 `TokenIsAppContainer=1`；未授网络 capability，仅给专用 CPython 运行时缓存和本次执行根最小 ACL；
- 子进程以 `CREATE_SUSPENDED` 起动，先纳入 kill-on-close Job Object 再恢复；Job 强制活动进程数 1、CPU 时间和内存上限，墙钟超时终止整个 Job。Windows `CHILD_PROCESS_POLICY` 会使 CPython 3.12 在入口前以 `0xC0000142` 退出，因此不做假兼容，改由已实验的单进程 Job 限额封锁；
- 协议错误、worker 异常或超时会把精确签名身份写入独立 SQLite quarantine，重启 broker 也不会自动复活；新版本/新哈希不会被旧身份误伤；
- 内核中只挂载 builtin `isolated.plugin.execute` 代理，第三方 manifest 仍不能 in-process mount；服务借用期间禁止卸载，释放后注册和引用全部清理；
- 当前本机证据为核心/worker/AppContainer/proxy 27 项与插件/发行相邻 89 项全绿，恶意样例确认插件能正常 import `socket/subprocess`，但不能读宿主哨兵文件、写外部文件、连本机 TCP 或拉起子进程。它不等于插件市场、Linux/macOS 隔离、出站白名单或动态第三方 UI 已完成。

### PK-007：企业 RAG 插件组合

- 解析、embedding、检索、重排、DLP 可换；
- 身份、租户硬隔离、正文前授权和撤权 epoch 仍由内核掌握。

### PK-008：生态与兼容

- 提供 Nachuan SDK；
- 可选 DeepSeek Harness bridge、OpenClaw bundle/skill bridge；
- 外部生态插件始终运行在隔离 worker，不直接导入主进程。

## 10. 验收门

每一阶段都必须证明：

- 未声明能力 100% 拒绝；
- 插件失败不会留下 tool/event/timer/process/UI 残留；
- 精确版本升级失败能恢复旧 provider；
- 插件卸载后旧引用、旧回调和旧连接不可继续工作；
- 两个插件依赖缺失或成环时 fail loud；
- Renderer 插件不能绕过 Main/Engine IPC；
- 恶意插件不能读取凭证、跨租户、调用渠道或付费 provider；
- 现有微信、飞书、媒体、账本、安装和更新回归不退步；
- 干净安装态和强杀/重启后生命周期收敛；
- profile dump 与实际加载插件、哈希、权限完全一致。

## 11. 对三个终极目标的帮助

- **月/年级长城任务**：任务调度、checkpoint、监控、恢复和通知作为插件组合，durable event/goal 由内核保存。
- **真实商业智能体协作**：Agent Team、审批、人机接管、业务连接器成为可替换工作流插件，企业身份与账本不被替换。
- **强模型训练弱模型**：数据生成、蒸馏、评测、候选模型和路由均可插件化；基线、盲测、防泄题、晋升和回滚门由内核控制。

插件内核不是第四个终极目标，而是让三个目标能独立迭代、验收和回滚的共同地基。

## 12. 与 OpenClaw 开源路线合并

最终建议不是二选一：

- 学 OpenClaw：本地优先、公共核心、SDK、插件市场和社区治理；
- 学 DeepSeek Harness：服务缝隙、插件树、类型化事件、依赖注入和可逆副作用；
- 保留纳川：企业身份、真实渠道、财务/幂等账本、安装更新信任和故障关闭。

公共仓库可以开放插件接口、内置插件、协议、评测和安全门；托管控制面、客户数据、签名材料、生产拓扑和风控仍保持独立。

## 13. 官方依据

- DeepSeek Harness 官方仓库与开发者预览说明：
  https://github.com/deepseek-ai/deepseek-harness
- DeepSeek Harness 官方架构：
  https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/architecture.md
- 动态 Host 插件信任说明：`node:vm` 不是安全边界：
  https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/extensions/cordis-host-runner/README.md
- Client 插件 guard、生命周期与已知限制：
  https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/extensions/cordis-client-runner/README.md
- Process Sandbox 的 full/partial 边界：
  https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/sandbox.md
- Microsoft AppContainer 实现与 `SECURITY_CAPABILITIES` 启动示例：
  https://learn.microsoft.com/windows/win32/secauthz/implementing-an-appcontainer
- Microsoft `UpdateProcThreadAttribute` 的 AppContainer、句柄列表和进程创建属性合同：
  https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
- Cordis 可逆 effect 与 reactive coeffect 论文预印本：
  https://github.com/cordiverse/paper
