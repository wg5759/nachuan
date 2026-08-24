# ADR-0011：Page Agent 只作为隔离 Agent 浏览器候选

- 状态：接受（仅限隔离 PoC；生产接入仍为 NO-GO）
- 日期：2026-07-17（2026-07-20 复核）
- 评估版本：`alibaba/page-agent` v1.12.2，commit `5485e8cffb44a1e3bdf7f58b3e5879b892c2e8dd`

## 背景

纳川当前右栏是供用户手动使用的 Electron `webview`。右栏对话只把任务、模型和聊天历史提交到通用 Agent；没有向模型提供当前 URL、DOM、截图或可执行页面句柄。后端也因该浏览器共享机主登录态而故障关闭全部 `browser_*` 工具。因此它不是可由模型控制的浏览器。

Page Agent 能把网页 DOM 压缩为文本结构，并用索引化的点击、输入、选择和滚动动作完成单页工作流。它对标准表单、自有后台、CRM/ERP 录入和网页信息提取有明确价值，且通常不需要截图或视觉模型。

但其官方边界同样明确：核心面向由网站开发者主动集成的当前页面；没有视觉能力；不支持跨域 iframe、Canvas、拖拽等交互。官方维护者也确认间接提示注入仍不是已解决问题，高风险动作审批应由集成方自己实现，不能把框架自带提示当安全边界。

## 决策

1. 不把 Page Agent IIFE、Chrome 扩展或 Beta MCP 直接装进现有右栏。
2. 不向当前默认会话注入 Page Agent，不复用现有手动浏览器 Cookie、登录态或缓存。
3. 若实施 PoC，新建显式标注的“Agent 浏览器（实验）”，使用临时非持久 partition；关闭后销毁会话。长期版本按租户/工作区隔离。
4. 只从固定版本、固定完整性和可追溯 npm provenance 的本地包构建；禁止 CDN 动态加载。纳入许可证、SBOM、锁文件、恶意代码静态审计和升级回归。
5. 模型与供应商凭据只留在 Gateway/Vault。guest、网页主世界和 renderer 都不得获得 provider key、runtime key 或 approval key。
6. 页面执行器由 Electron Main 掌控。当前纯策略骨架只允许 `inspect`、`scroll`；未来写动作若单独验收，只能扩展为闭集 typed action，仍不开放任意 selector、任意 HTTP、`eval` 或 `execute_javascript`。
7. 页面 DOM 一律视为不可信证据。默认剔除 password、OTP、token、支付和已知 PII；限制 DOM 字节数、节点数和历史长度；不启用远端 `llms.txt` 指令。
8. 每一步能力绑定 `session_id + webContents 身份 + 精确 origin + navigation epoch + DOM digest + element handle + action + value hash + expiry`。导航、重绘、金额/收件人/按钮变化后旧能力立即失效。
9. 初始 PoC 只允许读取和滚动。点击、输入、提交、发送、删除、购买、上传、登录、密码和 OTP 分级；有外部副作用的动作必须走原生默认取消的一次性审批。
10. 所有结果以执行后页面证据和持久回执为准，禁止以模型的 `done` 自述冒充完成。

## 当前源码证据（仍非真实 PoC）

`desktop/src/main/page-agent-readonly-session.ts` 已实现纯 Main 策略骨架：临时且终身不复用的 session/partition、会话与句柄硬上限、单调时钟、非重入变更、只允许 `inspect/scroll`、完整 `valueSha256`、Main 签发的 opaque element handle、当前 DOM snapshot 权威，以及导航后旧 handle/capability 撤销。独立互审发现并修复了伪 UUID 对象可借隐式 `ToString` 绕过 partition 唯一性的缺口，以及伪 `Uint8Array.byteLength` 把零字节随机源冒充 32 字节的缺口。

`desktop/src/main/page-agent-readonly-browser-runtime.ts` 进一步定义了 fake Electron runtime 合同：唯一临时 partition、`cache=false`、锁定 WebPreferences、权限/下载/登录/网络 deny gate、全 frame 导航撤权、越域关闭、open/navigate 共享硬加载预算、await 后 lifecycle/view 复验，以及 Cookie/storage/cache/connection 的分阶段有界清理。deny gate 即使清理成功也终身保留；网络只在 opening/open、policy 已绑定、请求携带当前正整数 WebContents ID 且 URL 精确同源时放行，`close()` 同步切为 closing 后连迟到同源请求也立即拒绝。缺 ID/外来 ID 均 fail-closed；同源 subframe 导航同样会推进 epoch 并撤销 snapshot、排队 capability 与 active lease。

`desktop/src/main/page-agent-electron-adapter.ts` 已把该合同映射到注入的 Electron 39 API 表面：唯一 raw Session 只能有一个本适配器 WebRequest owner，view 必须绑定精确 raw Session；请求还必须匹配 raw WebContents、非空 frame 和正整数 ID。只有 GET/HEAD、非 Proxy 的真实空 `uploadData` 数组及 Electron 39 已知的读取资源类型才可能继续交给 runtime；ping、CSP report、WebSocket、缺字段、普通伪对象、Proxy 数组和未来未知类型直接取消。Proxy 检查先于长度/元素读取，恶意 getter 不会执行。权限、下载、HTTP login、preconnect、Service Worker 注册与 client-certificate 也进入 deny/关闭路径。

2026-07-20 定向 Vitest 为 3 files / 79 tests passed，Desktop typecheck 和 scoped diff-check 通过；适配器/测试 SHA-256 为 `160C583B...`/`AFCFAFBD...`。独立增量复核确认 Proxy-array 反例已关闭。该证据使用注入 fake Electron，没有启动真实 Electron 或联网；`select-client-certificate` 的真实取消语义、preconnect、Service Worker、Cookie、连接池、raw frame/身份稳定性、真实 DOM/节点映射与 BrowserPane 生命周期仍未验证，也没有安装或执行 Page Agent。JS Promise 硬超时不能抢占阻塞 event loop 的同步第三方调用。因此只记策略、fake runtime 与 adapter 合同源码级 GREEN，受限 PoC 与生产接入继续 NO-GO。

## 明确不采用

- Chrome 扩展：当前清单需要 `tabs`、`tabGroups`、`storage` 和 `<all_urls>`，权限范围超过右栏需求。
- Page Agent MCP：仍为 Beta，且会扩张外部控制面。
- 在任意公网网页主世界中放置 API Key 或通用 IPC。
- 直接恢复旧 `browser_eval` 或让 Gateway/模型执行任意 JavaScript。
- 先在真实登录、支付、发布、邮箱或企业后台上试跑。

## PoC 放行条件

- 手动浏览器与 Agent 浏览器的 Cookie、缓存、存储完全隔离。
- 恶意页面无法观察任何纳川密钥、调用主窗 IPC或访问 Engine。
- 提示注入夹具不能触发出站、提交、删除、购买、上传或凭据输入。
- origin、导航 epoch、DOM digest、元素句柄或审批任一变化都必须故障关闭。
- 验证取消、窗口关闭、模型超时、页面崩溃和应用退出后的清理与可恢复状态。
- Page Agent 升级或失效不影响现有手动浏览器。

## 已核对的官方证据

- 仓库与许可证：https://github.com/alibaba/page-agent
- v1.12.2：https://github.com/alibaba/page-agent/releases/tag/v1.12.2
- 官方限制：https://alibaba.github.io/page-agent/docs/introduction/limitations
- 数据脱敏（可选钩子，不是默认保证）：https://alibaba.github.io/page-agent/docs/features/data-masking
- 提示注入维护者说明：https://github.com/alibaba/page-agent/issues/212#issuecomment-4044668047
- 高风险审批不进核心的维护者决定：https://github.com/alibaba/page-agent/issues/259#issuecomment-4065960286
