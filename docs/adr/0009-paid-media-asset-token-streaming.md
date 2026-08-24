# ADR-0009：付费媒体资产令牌与有界流式归档

- 状态：拟议（代码、迁移和打包闭环完成前保持 `NO-GO`）
- 日期：2026-07-16
- 范围：Gateway 图像生成结果、Desktop Main 归档、幂等重放、容量与恢复

## 问题

现有链路允许约 128 MiB 的成功 JSON。Gateway 会先把供应商响应解析成完整对象；Desktop HTTP
传输会累计分块、`Buffer.concat`、转 UTF-8、`JSON.parse`，归档时还会再次 base64 解码。一个大响应
因此会同时保留多份副本，实际峰值可远高于线上的字节上限；Node 的非严格 UTF-8 转换还可能把损坏
字节替换为 U+FFFD。单纯把 128 MiB 改成另一个数字不能关闭这个问题。

## 决策

成功响应改为不超过 1 MiB 的严格 UTF-8 元数据；媒体字节通过 Gateway 私有资产存储和一次性、
owner-bound 的不透明令牌单独传输。任何供应商 URL 或 base64 都先在 Gateway 落入私有 staging，
核对长度与 SHA-256，并通过受信媒体探针完整解码。只有验证成功的字节才能生成令牌。

公开结果使用版本化闭集，例如：

```json
{
  "schema": "nachuan.paid-media-result.v2",
  "kind": "image",
  "created": 1784200000,
  "turnId": "<64 位小写十六进制稳定回合摘要>",
  "assets": [
    {
      "token": "nma1_...",
      "mediaType": "image/png",
      "byteLength": 123456,
      "sha256": "...",
      "validationReceiptSha256": "..."
    }
  ]
}
```

字段必须闭集、顺序无语义、最多四项；每项上限 24 MiB，总元数据上限 1 MiB。令牌不得包含主机
路径、供应商 URL、凭据或原始 task id。令牌同时绑定 Installation Epoch Root 提供的稳定安装 principal/
epoch、operation/turn、资产序号、媒体类型、长度和摘要；不能直接绑定可轮换的 raw paid key。普通
runtime key、另一安装/epoch 或另一 operation 均不能读取。

paid key 轮换时，旧 epoch 只保留 recovery-only 映射；存在未 ACK 结果时不得销毁对应权威，也不得让
同一个 Desktop operation 因新 key 进入新的 provider 域。安装 principal、epoch 或恢复映射不可验证时，
付费媒体失败关闭；这使本 ADR 的正式启用依赖 ADR-0008，而不是用另一个用户可回放 sidecar 冒充稳定
身份。

Gateway 提供双认证的私有接口：

- `GET /v1/paid-media/assets/{token}`：返回精确 `Content-Length`、`Content-Type`、
  `X-Content-SHA256`，从已钉扎的普通文件句柄流式发送；不接受 Range，不暴露重定向或路径。
- `POST /v1/paid-media/assets/ack`：只接受当前 operation 的完整令牌集合和 Desktop 归档回执摘要。
  先把 request 真源原子推进到 `acked`，再清理字节；重复 ACK 返回同一结果。

资产文件/索引不是付费执行权威。`durable_media_requests` 中不可变的小型成功文档才是令牌、owner
和摘要真源。下载前必须按 turn 的唯一索引回读该文档并精确匹配，避免一个被回放或替换的资产
sidecar 自行授权。ACK 使用独立 CAS 记录，不能重写原始成功 response；它绑定 canonical token-set
digest、operation/turn 和 Main archive receipt digest。只有字段完全相同的重复 ACK 才幂等成功；子集、
不同 receipt、重复/非规范 token、跨 operation 和并发冲突必须拒绝。文件缺失、摘要漂移、令牌已 ACK、
真源不可读时一律失败关闭，绝不重新调用供应商。

## 顺序与崩溃收敛

新图像操作固定顺序：

1. Gateway durable claim；验证 v2 协商、稳定安装 principal/epoch、路由和 adapter 能力；
2. 在 provider fence 前为 asset store、staging 和 probe 最大闭包做跨实例共享的持久预约；容量不足则
   释放未使用 claim 并停止，不能进入 provider；
3. provider fence 后供应商调用一次；
4. 每个资产私有落盘、完整解码、摘要复核；
5. 把不可变的小型令牌文档提交为 durable success；
6. Desktop 严格解析元数据，逐个流式下载到私有临时文件，同时计算长度/摘要；
7. Desktop 从钉扎文件句柄再次探测；已存在的同摘要文件必须重新核长度/hash/probe 后复用，多个资产
   使用 pending manifest 收敛，不能只依赖 create-only/rename；
8. Desktop vault archive receipt 落盘并复核，再把 Main ledger 推进到 `result_ready`；
9. Desktop 发送 ACK；Gateway 独立 CAS 持久标记 ACK、拒绝新的 GET，等待已经取得 lease 的在途 GET
   关闭后再幂等清理字节和预约；
10. renderer 两阶段 readback/ack 继续使用本地 `nachuan-paid-media://sha256/...` 引用。

崩溃规则：

- 第 3 步后、第 4 步首个资产落盘前：provider outcome 已经 unknown/可能收费，立即保持
  `recovery_required` 并禁止自动重调。可恢复的 adapter 必须先持久化有界 provider receipt、URL 或 task
  引用，只能靠供应商原生查询/幂等能力恢复。
- 第 4 步后、第 5 步前：provider outcome 已存在但不可证明为 durable success，保持
  `recovery_required`；资产按保守保留期清理，禁止自动重试供应商。
- 第 5 步后、第 8 步前：同一幂等键只重放令牌文档；Desktop 继续下载/归档，不再付费。
- 第 7 步文件已写但 receipt 未写：启动时按 pending manifest 钉扎并复核全部资产，再提交或保守隔离；
  不重新下载已证明相同的字节。
- 第 8 步 vault receipt 已写但 ledger 未到 `result_ready`：复核 receipt 后幂等补提交，再重发 ACK。
- ACK 提交后、文件清理前：下载已被真源拒绝，后台只做幂等垃圾清理。
- ACK 后本地 archive 丢失：报告不可恢复，不重新付费，也不把已删除远端字节伪装成可重放。

未 ACK durable success 不使用现有 30 天 TTL 静默 prune。它持续占用硬容量，直到完全相同的 ACK 成功，
或管理员携带不可变人工证据执行显式 `terminal-expired` 流程；容量满必须在 provider 前背压。不可变
成功 response 的字节和 token 集合在 ACK 前后始终不变，ACK 状态只能从独立记录查询。

## 内存、磁盘与超时约束

- Desktop 成功元数据响应上限 1 MiB；非 2xx 错误体上限 64 KiB，使用 fatal UTF-8。
- 资产全程 file-backed；不得使用 `Buffer.concat`、`readFile` 或完整 base64 Buffer 作为正常路径。
- 下载使用总时限、空闲时限、精确长度、最大字节数和取消信号；提前响应必须销毁上传/下载句柄。
- 每个重阶段都重验当前卷剩余空间。逻辑容量账本不是物理 extent，也不防同卷外部进程抢占；
  `ENOSPC` 必须保持 reservation 并失败关闭，不能释放后自动重试供应商。
- Gateway 预约至少覆盖四个 24 MiB 资产以及下载、探针和原子提交所需的同时存在副本；预约必须在
  provider fence 前持久落盘，success 未 ACK 时不释放。仅进程内计数或按 profile 分叉的 journal 不满足
  跨实例约束。
- Gateway asset store 与 Desktop staging/vault 都必须是非 reparse 私有目录；递归清理前再次验证，
  对同 SID 并发 swap 不宣称强隔离。

## 供应商适配器迁移

第一阶段可先把已解析的供应商结果规范化为令牌，以消除 Gateway→Desktop 的大 JSON 和 Desktop
多副本；但这仍不能宣称 Gateway 低内存完成。正式门禁还要求供应商适配器使用流式响应：优先请求
URL 结果并把 JSON 严格限制在小体积；必须支持 base64 的适配器要用经模糊测试的增量 JSON/base64
解析器直接写 staging。禁止在生产路径回退到 `response.json()` 读取大 base64。

v2 协商是付费前置条件：Desktop 必须发送固定协议版本/header，Gateway 在 claim/provider fence 前确认
adapter 支持令牌流式结果。旧客户端、只支持 v1 大 JSON 的 adapter、未协商的 `b64_json` 路径一律在
供应商调用前拒绝，不能静默降级。

供应商 URL 只能经公共网络下载模块进入 staging：仅 canonical HTTPS、禁止凭据和代理环境；DNS 解析后
钉扎公网 IP，每个重定向重新解析并复核，拒绝 loopback、私网、link-local、metadata 和非预期端口；
同时限制跳数、Content-Length、实际字节、总时限与空闲时限。任何 provider 返回的 URL 都是不可信
输入，不能由通用 HTTP 客户端直接访问。

## 验收

- 128 MiB base64 旧成功响应在 provider 调用前/协议协商处被拒绝，不进入 Desktop。
- 24 MiB 单资产和四资产边界均以小于 1 MiB 元数据完成，Desktop 峰值不随资产总大小线性复制。
- 非规范 base64、损坏 UTF-8、少/多字节、摘要冲突、重复 token、跨 principal/operation、ACK 后下载、
  sidecar/文件回放、reparse、并发 ACK、每个写入点崩溃均有负测。
- paid key 轮换、旧 recovery epoch、两个 Gateway 实例、未 ACK 超过 30 天、容量差一字节、provider
  返回后首字节前崩溃、在途 GET 与 ACK 竞争、不同 archive receipt 的重复 ACK 均有负测。
- 旧 `nachuan.paid-media-vault.archive.v1` 只做本地历史读取；新操作不得再产生含供应商 URL/base64 的
  128 MiB archive。迁移不删除旧证据。
- Fresh package 中只包含实现该协议所需闭集；真实图片经 Gateway 探针、Desktop vault、协议 readback
  和 renderer ACK 全链通过，且服务最终停止。

## 剩余边界

本协议避免大 JSON、多次付费和路径泄露，但不替代 Installation Epoch Root、同 SID 隔离、物理磁盘
预分配、供应商原生账单对账、恶意解码器沙箱、AV/许可证和正式签名门禁。上述任一未关闭时，商业
发布仍为 `NO-GO`。
