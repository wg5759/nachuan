# ADR-0014：用户自有订阅连接、Web 功能真源与团队中央服务

- 状态：接受（按垂直切片实施）
- 日期：2026-07-23
- 决策人：机主
- 取代：ADR-0013 中“Electron 永久冻结”和“公网/团队服务不在范围”的部分；ADR-0013 的本地 Web、loopback 鉴权与危险能力 fail-closed 原则继续有效

## 背景

纳川不能只接 API Key。个人用户或团队成员已经购买 Kimi Code、ChatGPT Plus/Pro、Codex 等套餐时，应能通过厂商提供的官方 CLI 登录能力使用自己的账号权益，而不是再次寻找 API Key。这里的目标是用户自用，不是转卖、共享或汇集他人的订阅额度。

当前仓库已有不完整的登录型目录卡片和 Kimi ACP/Codex 隔离研究资产，但生产路由仍故障关闭；Web 与 Electron 之间也存在启动、审批和特权 API 差异。若继续分别开发两个前端，功能必然漂移。

## 决策

### 1. 用户自有订阅是一等连接类型

纳川连接中心必须同时支持：

1. API Key 连接；
2. 本地模型连接；
3. 用户自有官方 CLI 登录连接。

首批登录连接为：

- Codex：用户通过官方 `codex login` / device auth 完成 ChatGPT 账号授权；首版通过稳定的 `codex exec` stdin/JSONL 受控调用。Codex app-server 可用于后续深度会话集成，但在当前 CLI 中仍标为 experimental，不作为首版稳定承诺。
- Kimi Code：用户通过官方 `kimi login` 完成设备码授权；纳川通过 ACP 或官方本地 server 的受控协议调用。

连接器的公共状态机固定为：

`not_installed -> untrusted_binary/version_unsupported -> installed_unprobed -> logged_out/login_pending/authenticated_unprobed -> ready -> degraded/reauth_required/revoked`

其中 `installed_unprobed` 只表示受信 CLI 已安装、尚未取得任何认证证据；不得把它误报为 `logged_out`。`authenticated_unprobed` 表示已有认证迹象但尚无真实协议握手/回合证据，也不得冒充 `ready`。

公共操作固定为：

- `discover`：发现受信 CLI 及版本；
- `begin-login`：在用户明确点击后启动官方授权；
- `status`：只返回登录方法、能力和匿名化状态，不返回令牌；
- `invoke`：通过受控 worker 发起会话；
- `logout`：只在用户明确确认后调用官方退出并清理纳川连接。

浏览器 Cookie、网页 localStorage、原始 OAuth token、CLI auth 文件内容不得进入 renderer、Gateway 请求、日志或纳川数据库。纳川只保存连接元数据、受信二进制证明、匿名化账号域和调用回执。

厂商缺少公开能力时必须显式返回 `unsupported`：当前 Kimi Code CLI 没有独立的公开 `status/logout` 命令，不能通过删除隐藏配置文件冒充官方注销；真实 ACP 握手或回合成功前最多标为 `authenticated_unprobed`。

### 2. 登录型调用必须经过隔离 worker

Gateway 不得直接在持有供应商 Key、渠道 token 和账本密钥的进程内启动模型 CLI。每个 CLI 登录域进入独立 worker：

- 子进程环境采用显式白名单，不继承 Gateway 机密；
- prompt 只走 stdin/JSON-RPC/ACP，不进入 argv；
- 工作目录、文件能力、网络能力和审批策略按会话显式声明；
- chat 会话默认使用空的私有工作目录、无宿主写权限；
- code/agent 会话必须由用户选择工作区并进入独立审批域；
- worker 有超时、输出上限、协议字段闭集和整棵进程树收口；
- CLI 路径与字节必须绑定受信安装清单，脚本 shim 不冒充已固定的原生可执行文件。

本决策不解禁正式 xreview。Kimi/Codex 作为普通用户连接可独立推进；互审仍受现有四家、独立连接域和 actual-served 回执门禁约束。

### 3. Web 是唯一功能真源

聊天、会话、文件、工具、审批、连接中心、同步、媒体、用量和设置首先在 Web 形态完成。Electron 不再拥有独立产品逻辑，只提供：

- 同一 renderer 构建的桌面壳；
- 必需的操作系统集成；
- 与 Web 客户端端口等价的受控本机服务。

所有功能必须通过一个版本化 `NachuanClientPort` 合同访问。Web shim、Electron preload 和团队 Web transport 分别实现该合同，并共享同一组合同测试。不得新增只有 Electron renderer 能调用而 Web 没有可解释状态的产品功能。

功能对等门禁至少包含：

1. 同一份 capability manifest；
2. Web 浏览器 E2E；
3. Electron 同 renderer smoke；
4. Gateway 公共 API 合同；
5. 明确列出的 OS-only 能力及 Web 替代/不可用状态。

新版 Windows 安装包只有在 Web 功能闭环和对等门禁通过后才构建。

### 4. 团队版是中央服务器 Web，但订阅按用户隔离

团队版新增用户、组织和租户边界。每位成员拥有自己的连接、模型权限、额度、审批和审计记录；禁止把一个成员的 CLI 登录或套餐额度共享给其他成员。

团队服务的最小安全闭集为：

- 用户身份与服务端会话；
- organization / membership / role；
- 每条业务记录的 tenant/owner 归属；
- 每用户连接与凭据/CLI profile 隔离；
- RBAC 与高风险操作二次确认；
- 每用户预算、配额和 provider 调用账本；
- append-only 审计；
- TLS、CSRF、会话吊销、备份与数据导出/删除。

CLI 登录 worker 可以是服务器端每用户隔离 profile，也可以是用户设备上的受信 companion；两者必须实现同一个 worker 协议。未完成隔离和厂商允许范围核验前，不把本地单 owner Gateway 直接绑定到公网。

## 首批验收纵切

按依赖顺序逐条 RED -> GREEN：

1. pip 安装后一个命令启动本地 Web；刷新后模型仍可用，账本/审批状态不被误报成引擎离线。
2. Codex 登录连接：未安装、未登录、登录成功、退出四个用户可见状态；fake app-server 合同先绿，再做一次用户确认的真实 CLI 会话。
3. Kimi Code 登录连接：同上，协议使用 stdin/ACP，prompt 不进入 argv。
4. Agnes 一次连接后同时注册 chat/image/video；真实媒体调用仍需 consent、幂等和账本。
5. capability manifest 在 Web 与 Electron 构建中逐项相同。
6. 团队 API 第一纵切：两个组织的同名会话、连接和审计互不可见，越权请求在读取业务正文前拒绝。

## 明确非目标

- 不抓取或复用网页 Cookie；
- 不把 ChatGPT/Kimi 网页会话伪装成通用 OpenAI API；
- 不共享、转卖或池化用户订阅；
- 不在本 ADR 中宣称厂商套餐允许第三方托管或商业转售；
- 不在 Web 功能闭环前重打 Windows 安装包。
