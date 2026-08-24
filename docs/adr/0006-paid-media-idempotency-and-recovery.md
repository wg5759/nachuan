# ADR-0006：付费媒体采用持久幂等领取、provider 权限闸与两阶段交付

- 状态：接受（源码控制面已落地）；生产外部证据仍待闭环
- 日期：2026-07-16

## 背景

图像和视频创建会产生供应商费用或远端任务。仅靠响应缓存、请求正文去重、renderer `localStorage` 或进程内锁，
无法区分“用户主动再生成一次”与“网络断开后的同一次重试”，也无法在供应商已接收而本地响应丢失时阻止重复扣费。
HTTP 状态也不能证明供应商的财务阶段：402/403/404/409/422 等响应可能由网关、代理或供应商在不同阶段产生，不能
据此自动释放购买门禁。

此外，路由 decorator 只保护已知 HTTP 入口；如果 provider 对象仍可由 agent、tool-agent、Studio 或内部编排直接调用，
付费 header 与幂等路由仍可能被绕过。因此权限必须收口到 provider 创建调用本身，而不能只靠 API 路由约定。

## 决策

### Gateway 身份、持久领取与 provider choke point

- `/v1/images/generations` 与 `/v1/videos/generations` 同时要求普通 runtime Bearer、独立
  `X-Nachuan-Paid-Media-Key` 和 16–128 字节 ASCII `Idempotency-Key`。付费能力从
  `NACHUAN_PAID_MEDIA_API_KEY` 注入；未配置、格式非法或与 runtime/审批/渠道能力重叠即故障关闭。
- Gateway 只把独立 paid capability 的域分离 SHA-256 principal 放入 request state；原始 paid key、runtime Bearer 和
  幂等 key 不进入 handler、SQLite 或响应。轮换 runtime Bearer 不改变付费恢复域；轮换 paid capability 会创建新域，
  Desktop 对旧未决操作的自动重试必须拒绝。
- Gateway 在 provider 调用前持久 claim，写稳定 operation/turn identity 与 fencing token；进入 provider phase 前再次
  持久栅栏。相同 key 换请求返回冲突；活跃领取返回有界等待；成功结果在模型路由解析前可直接重放。
- 只有完成 claim 与 provider-phase fence 的付费路由，才为精确 image/video operation 绑定一次性 authority。
  `create_image/create_video` 的统一 provider 调用边界必须先验证并消费 authority，随后才允许写 financial attempt 和
  访问 provider。没有 authority 的 agent/chat、agent/run、tool-agent、Studio 或内部直调在 provider 前故障关闭；
  authority 不能借 ContextVar 的子任务传播重复使用。
- 只有成功结果已经写入 Gateway 可重放回执后才能向调用方返回 2xx；phase-0 路由失败或视频队列未接收可用 fencing
  token 安全释放领取，已经进入 provider phase 的操作不能用该规则释放。
- `paid_media_requests.db` schema v2 以随机 database identity 和单调 mutation sequence 绑定非秘密
  `.rollback-anchor`。mutation 先原子写 anchor 并 fsync，再以 SQLite `synchronous=FULL` 提交；独立专项 `8/8` 与
  store 回归 `48/48` 已通过。单独恢复旧数据库快照、替换数据库、sequence 回退和 anchor 丢失都会锁死；数据库与
  anchor 同时删除/成对恢复、同 SID 篡改、合法备份人工重锚和真实断电仍未解决。

### Desktop main 真相源与每次新购买审批

- renderer 不持有 runtime/paid key、幂等 key 或请求摘要，也不能直接 fetch 付费路由；它只能经闭集 preload API 向
  Electron main 提交固定 path 与有界正文。IPC 必须同时匹配预期 webContents 与 `senderFrame === mainFrame`，应用还
  必须持有 single-instance 锁。
- Gateway 与 Desktop 的 paid raw body 上限统一为 24 MiB；`model`、`prompt` 必填且有界，image/video/`extra_body`
  采用版本化闭集。未知字段和复杂 provider 参数必须在 native dialog 与 claim 前拒绝。确认框展示 path、model、prompt
  有界预览、全部允许的计费标量、输入数量、raw bytes 和完整 SHA-256，使用户确认绑定到实际规范化购买请求。
- 每次**新 claim**在 main 先查询未决操作，再取得唯一互斥审批槽，并显示 Electron OS-native 付费警告；已有未决操作、
  另一审批框尚未结束、owner/main-frame 不可信或用户取消时，均在 claim/dispatch 前停止。安全恢复只复用既有
  operation，不冒充新购买，也不再次创建幂等身份。
- Desktop main 真相源为 safeStorage 加密的 v3 严格账本及独立加密 `.anchor`。anchor 保存随机 ledger identity 与单调
  sequence floor；初始化后 ledger 缺失、anchor 缺失、identity 错配或 sequence 回退都锁住恢复。目录和文件还必须是
  ACL 加固、non-reparse，并以临时文件 fsync + 原子替换写入。
- 账本只允许一个未结案操作，状态闭集为 `claimed`、`dispatching`、`recoverable`、`result_ready`、`delivered`、
  `reconciled`。所有非 2xx、未知传输结果、超限/不可解码响应与语义无效 2xx 都保留未决操作；不再按状态码猜测
  “供应商必然未接收”。
- 有效 2xx 的严格 JSON 响应以 24 MiB 上限、status 与 SHA-256 暂存在 v3 加密账本。`result_ready` 重试从本地解码并
  重放，不再次访问 Gateway/provider；损坏、缺失或超限响应故障关闭并要求人工核对。进入 `delivered` 或
  `reconciled` 后清除大响应，保留 30 天 tombstone，自动恢复在第 27 天截止。

### Renderer 冻结目标与两阶段 ack

- 发起付费操作时冻结 conversation id、message identity、operation id 和开始时间；异步结果、错误、polling 与人工核销
  都只能更新该目标，不能读取用户后来切换到的“当前会话”或旧数组下标。
- 结果先写入目标消息并置 `phase=awaiting_ack`，随后读取 `agg-conversations` 的**实际序列化快照**，逐字段验证同一
  operation 的精确 images/videoTask 已持久化。仅调用 flush、看到 `setItem` 未抛错或内存状态已更新都不算持久证据。
- 当前 conversation `localStorage` partialize 对 `data:` 图片总预算约 2.5 MB；超预算图片会从序列化快照被省略。此时
  验证必须返回 false，main v3 保留 24 MiB 范围内的原结果并继续阻止新购买。该设计把“误报交付”改成可恢复阻塞，
  但在受控 IndexedDB/文件结果库落地前，不把大 base64 图片交付视为已解决。
- 实际快照验证通过后才请求 main 完成 durable-result ack；main 成功写入 `delivered` 后，renderer 才清除消息锚点。
  若应用在两步之间崩溃，启动收敛会重新列出 main 未决项、复验 `awaiting_ack` 结果、补 ack 后清锚点；验证失败或
  main 仍未结案时继续保留。
- 开放 P1：上述验证由 renderer 自律执行，底层 ack IPC 只携带 `operationId`。main 没有 main-owned result vault 或
  persistence proof，裸 ack 仍可把 `result_ready` 推进 `delivered` 并清除结果正文。必须让 main 持有结果落库真相源，
  并把 ack 绑定 operation/result digest 与 main 可复验凭证；完成前不把两阶段 UI 顺序当成安全边界。
- 旧 `nachuan.paid-media.pending.v1` 只按精确 schema、最多一条未结案记录迁入 main；导入成功后在 renderer 旧槽位写
  旧版本不能接受的 sentinel，读取/导入/sentinel 任一步不确定都停止付费操作。
- 开放 P2：legacy import renderer channel 尚无 main-owned durable one-shot seal；严格 schema 和 renderer sentinel 不能
  证明迁移 IPC 已在 main 侧永久消费，重启/renderer 重放边界仍需一次性持久凭证。
- 原消息丢失时，全局恢复卡只把 main 返回的 operation id/path/state/dispatch count/创建时间列为可信字段；用户填写
  的供应商任务/账单说明明确标为“未验证的核对说明”。main 连续显示两次原生确认后写 `reconciled` tombstone，
  不删除账本，也不声称用户说明不可删除或已经由系统验证。

### 最终包验证

- `_verify_pack.mjs` 必须从最终 Electron ASAR 检查实际运行的 main、preload、renderer，而不是只 grep 源码或搜证据字符串。
  AST 必须证明 main handler → service、BrowserWindow → preload 及 preload method → channel → contextBridge 的真实结构；
  renderer HTML/全部 JS chunk 必须满足入口、路径、数量和容量闭集，且不得含 paid header/env/key、直调付费 route 或自行
  幂等实现。该结构门已与 packaged-integrity 合跑 29/29；它仍不证明运行时可达性或下述业务交付语义。
- 2026-07-14 现存 `desktop/release/win-unpacked/resources/app.asar` 缺少上述 late control plane，必须被 gate 拒绝；
  该包不是候选，不能继续安装、升级、签名或交付。

## 后果

- runtime Bearer 正常轮换不再切断同一 paid capability 域内的安全恢复；paid capability 轮换仍是显式安全边界。
- 路由之外的内部 provider 调用不能无权创建付费媒体，减少“新入口忘加 decorator”造成的旁路。
- 正常 renderer 流程固定为“provider 成功 → main 持久 `result_ready` 响应 → renderer 精确序列化结果 → main
  `delivered` → renderer 清锚点”，能收敛普通崩溃窗口；但在 P1 main-owned proof 落地前，裸 ack 仍能绕过该顺序，
  因此不能宣称 renderer compromise 下也成立。
- 保守地把所有非 2xx/未知传输留作恢复，可能增加人工核对，但优先避免重复扣费。
- 超过 renderer 约 2.5 MB `data:` 预算的结果在正常 UI 流程中不再被误报为已交付，但会让 main 的 `result_ready`
  操作继续占用唯一未决槽；P1 裸 ack 仍可绕过该保证。这需要后续受控结果库或基于真实证据的人工核销，而不是无限
  自动重试。
- renderer compromise 不再能直接读取付费能力或幂等身份，清空 renderer 存储也不能删除 main 财务账本；这缩小了
  信任边界，但不构成同 SID 恶意进程隔离。

## 尚未关闭的边界

- Desktop anchor 能阻断单独回滚/替换 ledger，但 ledger 与 anchor 的协调删除、首次旧版引导前的历史回滚、目录 fsync
  持久性和同 SID 篡改不能由当前源码合同证明。Gateway schema v2 rollback anchor 的单文件旧快照/替换/sequence 回退/
  anchor 丢失已通过专项验证；数据库与 anchor 协调删除/恢复仍需要更高层受保护 epoch，合法备份缺人工 re-anchor 流程，
  真实断电也未验证。
- P1 main ack 缺 main-owned result vault/persistence proof，可能在只凭 operationId 的裸 ack 后清除唯一结果正文；P2
  legacy import renderer channel 缺 main-owned durable one-shot seal。两者均为开放项，字符串/结构 package gate 不能
  替代运行时证明。
- 仍缺真实供应商小额调用、任务查询、发票/账单对账、预算预留/扣减、多币种、退款/补发和人工结案演练。
- renderer 仍使用受 partialize 约 2.5 MB `data:` 总预算约束的 conversation `localStorage`；尚无 IndexedDB/受控文件
  结果库，因此大 base64 结果可能安全阻塞后续新付费任务。
- 仍缺签名安装版 kill/power-loss、磁盘满、安装/卸载/自动更新/回滚 smoke；当前自动更新发布入口保持关闭。
- 仍缺最终字节 Defender + 第二独立引擎扫描、正式签名和第三方依赖/动态插件全量恶意审查；不能宣称无病毒、无木马
  或无后门。
- safeStorage、当前用户 + SYSTEM ACL、single-instance 与 main-frame IPC 都不是同 SID 恶意进程的强隔离；不可信
  动态插件/第三方执行面必须迁入独立低权限身份、AppContainer 或 VM，否则保持禁用。
- 本轮 main ledger/service/IPC、renderer recovery/routing/ack、Gateway route/provider boundary 和 package gate 的窄
  回归只证明当前源码合同。最终工作树全量、干净构建、安装版验收与外部证据完成前，发布保持 `NO-GO`。
