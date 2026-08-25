# 纳川企业级 RAG 全链路权限架构

> 状态：RAG-ACL-001 身份边界、RAG-ACL-002 本地 metadata/outbox、RAG-ACL-003 安全写入规划/隔离暂存、RAG-ACL-004 本地授权门面与 RAG-ACL-005 权限感知检索代理纵切已实现；真实 ReBAC/ABAC/向量/加密正文后端、生成 DLP、撤权同步、PostgreSQL RLS 与真实验收仍未实现，不得宣称企业级权限已经上线
> 日期：2026-08-24
> 适用范围：纳川团队版、企业版、多租户云同步和外部知识源同步

## 1. 结论

用户提出的“分片级最小权限打标 + 独立权限引擎鉴权 + 生成侧合规脱敏”方向正确，但生产实现必须再补四个硬约束：

1. **未授权正文不得越过检索信任边界。** 向量库可以在受控后端内部产生候选 ID，但未经授权的正文不能进入外部重排器、外部模型、日志或遥测。
2. **所有派生物继承权限。** 向量、摘要、关键词索引、问答缓存、会话上下文、引用、导出文件和训练样本都必须继承其来源集合中最严格的权限与数据驻留要求。
3. **撤权使用单调策略版本。** 每次权限变更提升 `policy_epoch`；查询、缓存和引用都绑定该版本。旧版本请求和缓存不得在撤权后继续返回。
4. **生成脱敏只是纵深防御，不是授权。** 敏感原文一旦进入模型，输出分类器无法证明它不会泄露。授权必须在模型看到上下文之前完成。

因此，纳川应建设 `knowledge_v2`，保留现有个人知识库兼容模式，不能直接把现有 `user_id` 字段包装成企业权限。

## 2. 当前实现审计

当前实现适合单机、单所有者或简单用户隔离，不满足企业多租户威胁模型：

- `orchestrator/knowledge.py` 的 `kb_docs` 只有 `user_id/title/source/status/text_hash`；`kb_chunks` 只有 `user_id/doc_id/text/vec`。
- 检索条件只有 `c.user_id=? AND d.status='active'`，没有租户、组织、项目、职级、临时授权、显式拒绝、关系继承或策略版本。
- `gateway/app.py` 的 `/v1/kb/docs` 和 `/v1/kb/query` 从请求参数或请求体读取 `user_id`，共享 API key 仅证明调用方知道网关密钥，没有把已认证主体强绑定到该 `user_id`。
- 检索结果直接拼入系统消息后调用模型，没有独立的策略决策点、上下文清单、模型路由分级、输出 DLP 或引用复核。
- `orchestrator/cloud_sync.py` 可把 Supabase 登录用户映射到本地用户，但知识文档和权限关系并非同一事务或同一因果版本，不能保证撤权即时生效。

2026-08-25 已完成第一条独立边界：`gateway/enterprise_context.py` 只接受应用侧可信 resolver 生成的
冻结 `EnterpriseRequestContext`；企业请求正文不能提交或覆盖租户、主体、组、角色和 epoch。
`POST /v1/enterprise/kb/query` 在后续能力未完成时固定返回 `enterprise_rag_not_ready`，不会回退到个人知识库。
这只关闭 RAG-ACL-001，不改变下列未完成判断。

现状允许继续服务个人版，但企业版必须默认拒绝沿用这条路径。

## 3. 威胁模型与安全不变量

### 3.1 必须覆盖的失效场景

- 分片夹带：重叠窗口跨过权限边界，把高低密内容放进同一块。
- 身份冒用：调用方自行填写别人的 `user_id`、`tenant_id` 或角色。
- 复杂关系：部门、项目、职级、文档继承、黑名单、临时授权和跨组织协作发生组合。
- 间接推断：多个低密片段组合出未授权的敏感结论，或通过是否有结果推断文档存在。
- 撤权延迟：目录权限已取消，旧向量、摘要或缓存仍然命中。
- 跨租户：共享索引、批量任务、缓存键、日志、备份或模型会话串租户。
- 中间服务泄漏：未授权正文虽然在最后被过滤，却已进入重排器、追踪系统或模型提供商。
- 派生物降级：摘要、引用、导出物或微调样本丢失源权限。
- 权限引擎故障：超时、空响应、旧策略或部分批量结果被错误解释为允许。
- 连接器漂移：SharePoint、飞书、企业微信、网盘等源端权限变化未可靠同步。

### 3.2 不变量

任何实现都必须满足：

- 请求中的租户和主体来自已验证身份，不接受业务正文覆盖。
- `deny` 优先于 `allow`；无决策、超时、策略缺失、版本不匹配均为拒绝。
- 一个分片只能属于一个租户、一个权限同质区和一个来源版本；无法证明时隔离，不入检索。
- 未授权正文不进入重排、生成、缓存、引用和遥测阶段。
- 每一条输出都可追溯到授权上下文清单和策略版本。
- 任何缓存键都至少含 `tenant_id + subject_scope_fingerprint + policy_epoch + corpus_epoch + model_route_class`。
- 撤权后，旧策略版本不能继续读取；恢复授权也必须显式产生新版本。
- 高安全租户可选择独立数据库、独立向量索引、独立对象存储和独立密钥，逻辑隔离不能冒充物理隔离。

## 4. 目标架构

```text
身份提供方 / SSO
       │ 验证 token、设备、会话
       ▼
认证网关 ──> RequestContext（不可由正文改写）
       │
       ├──> 授权门面 AuthzFacade
       │      ├── 关系图：组织/项目/文件夹/文档/分片继承
       │      ├── 属性策略：职级/用途/设备/区域/时间/数据分级
       │      └── 单调 policy_epoch + 决策审计
       │
       ▼
租户硬隔离检索 ──> 候选 ID ──> 分片级 BatchCheck
                                      │ 仅允许的正文
                                      ▼
                                  受控重排
                                      │
                         授权上下文清单 + 模型路由策略
                                      ▼
                                     LLM
                                      │
                         输出 DLP / 推断风险 / 引用复核
                                      ▼
                         响应 + 可审计引用 + 决策收据
```

### 4.1 不可信输入与可信上下文分离

服务端创建不可变 `RequestContext`：

```json
{
  "tenant_id": "t_...",
  "subject_id": "u_...",
  "session_id": "s_...",
  "groups": ["g_..."],
  "roles": ["employee"],
  "attributes": {"department": "sales", "clearance": 2},
  "purpose": "customer_support",
  "device_trust": "managed",
  "region": "cn-east",
  "policy_epoch": 1842,
  "session_epoch": 77
}
```

客户端只提交查询和可选用途；主体、租户、组、角色、策略版本均由认证网关和权限信息点生成。后台任务、智能体和连接器也必须是独立服务主体，不能借用“owner”。

### 4.2 授权门面

纳川不应把某个向量数据库当作唯一权限系统。建议引入统一 `AuthzFacade`：

- 关系权限承载组织、项目、文件夹、文档、组成员、继承和直接共享，可采用 Zanzibar 风格实现（例如 OpenFGA）。
- 属性策略承载职级、设备、区域、用途、时间窗、保密级别和模型路由，可采用 OPA 类策略决策点。
- 最终决策采用交集：关系许可、属性许可、租户许可、数据驻留许可全部通过才允许；任一显式拒绝或异常即拒绝。
- 调用方是策略执行点（PEP），授权门面是统一决策点（PDP）。禁止每个业务模块自行复制规则。
- 决策必须返回 `allow/deny`、原因码、`policy_epoch`、模型版本、关系版本、适用义务（脱敏、仅本地模型、禁止导出等）。

不能同时维护两套互相独立的“最终真相”；关系图和属性策略只是同一最终决策的输入。

### 4.3 存储硬边界

建议分级部署：

- 标准企业租户：共享 PostgreSQL，但所有业务表强制 RLS；应用服务账号不能拥有 `BYPASSRLS`，表所有者也应 `FORCE ROW LEVEL SECURITY`。向量索引按租户/安全域分区。
- 高安全租户：独立数据库、向量索引、对象桶、备份集和 KMS 数据密钥。
- `global_public` 公开知识必须使用独立索引和独立写入流程；不能把企业主库中“当前看似最低密级”的内容当故障降级来源。

RLS 是租户硬下限，不替代应用层对象授权。应用层漏检时 RLS 仍应阻止跨租户；RLS 漏配时安全测试必须阻止发布。

## 5. 数据模型建议

不要在旧表上无边界追加几十列。新建版本化数据域：

```text
kb_v2_documents
  tenant_id, document_id, source_id, source_version, corpus_epoch
  classification, policy_id, policy_epoch, status, content_hash

kb_v2_chunks
  tenant_id, chunk_id, document_id, ordinal, text_ciphertext/ref
  policy_id, policy_epoch, classification, provenance_digest
  embedding_ref, created_at, revoked_at

kb_v2_acl_bindings
  tenant_id, resource_type, resource_id, relation, subject_type, subject_id
  condition_id, valid_from, valid_until, source_version

kb_v2_policy_outbox
  tenant_id, event_id, source_version, policy_epoch, resource_scope
  operation, state, created_at, applied_at

kb_v2_audit_decisions
  decision_id, tenant_id, pseudonymous_subject_id, action, resource_ids
  policy_epoch, result, reason_codes, query_digest, created_at
```

关键原则：

- 关系元组只存不含个人信息的稳定 ID。
- 文档和分片都带策略指针；分片可以比文档更严格，不能更宽松。
- 原文可进入加密对象存储，检索索引只持必要字段；向量本身也按敏感资产保护。
- 派生物保存 `provenance_digest`，权限取来源集合的最严格合并结果。

## 6. 安全分片与写入

### 6.1 顺序

1. 连接器读取源内容和源 ACL 的同一可验证版本。
2. 识别租户、文档层级、权限边界、数据分类和驻留要求。
3. 先切权限同质区，再做语义分片；重叠窗口不得跨权限边界。
4. 无法确定边界的块按最严格策略处理；若租户或策略来源不明确，进入隔离区，不生成可检索向量。
5. 原文、分片、向量、关键词索引和 ACL 通过事务性 outbox 发布。
6. 只有内容版本与权限版本均激活后才把文档状态切为 `searchable`。

### 6.2 分片规则

- 同一分片的 `tenant_id`、`policy_id`、分类级别和源版本必须一致。
- 表格、页眉页脚、批注、附件、OCR 层和隐藏文本都要分类，不能只看正文段落。
- 混合敏感段落优先在安全边界处分割；无法安全分割时整块取最高密级。
- 摘要分片和父子分片继承所有来源权限，不允许“摘要后降密”。
- 写入前检测提示注入、恶意附件、数据投毒和重复版本，但内容安全扫描不能改变授权结果。

## 7. 权限感知检索

采用“硬隔离预过滤 + 权限感知候选 + 分片级终检”的组合，不绑定单一向量库：

1. 验证 `RequestContext`，读取当前租户 `policy_epoch`。
2. 存储层强制租户/安全域过滤，任何查询都不能跨该边界。
3. 当用户可访问对象集合较小时，先用 `ListObjects` 一类接口生成可访问文档 ID，再推入向量过滤。
4. 当集合很大时，向量搜索在租户域内超量召回候选 ID；在读取正文前，对分片执行 `BatchCheck`。
5. 未授权、无决策、版本不一致或批次缺项的候选全部删除，并记录原因。
6. 只有授权正文进入重排器；外部重排器还需通过数据分类和区域路由策略。
7. 若授权结果少于目标 `k`，在限定预算内继续拉取下一页候选，而不是用未授权内容补足。
8. 引用返回前对 `chunk_id + policy_epoch` 再核验一次，避免长生成期间发生撤权。

向量库的元数据过滤仍有价值，但它只是性能优化和租户硬边界的一部分，不承担全部企业权限逻辑。

## 8. 生成、脱敏和推断泄漏

生成前创建 `AuthorizedContextManifest`：

```json
{
  "decision_id": "d_...",
  "tenant_id": "t_...",
  "subject_scope_fingerprint": "sha256:...",
  "policy_epoch": 1842,
  "corpus_epoch": 551,
  "chunks": [
    {"chunk_id": "c_1", "content_hash": "...", "classification": 2}
  ],
  "obligations": ["no_training", "region_cn", "mask_pii"]
}
```

控制措施：

- 根据最高分类、租户合同和数据驻留要求选择模型；不合规的外部模型路由直接拒绝。
- 系统提示词只能约束行为，不能承担权限边界。
- 输出前做 PII、密钥、合同条款、商业秘密分类和租户自定义 DLP；命中时拒绝、模板化回答或脱敏。
- 对财务汇总、人员统计等易推断场景设置最小样本量、维度白名单和确定性查询模板；必要时人工审批。
- 会话历史再次使用前按当前 `policy_epoch` 复核，不能把上一轮已撤权内容留在上下文里。
- 输出引用必须只包含仍被授权的来源，且隐藏未授权文档是否存在。

“多个低密片段推导高密结论”无法靠一个输出分类器彻底证明安全。高风险场景应限制允许的问题类型、聚合维度、模型路由和输出模板，并以对抗评测持续验证。

## 9. 撤权、同步和缓存

### 9.1 因果版本

- 每个租户维护单调 `policy_epoch` 和 `corpus_epoch`。
- 权限撤销先提交权威关系和新 `policy_epoch`，再通过 outbox 更新检索索引；旧 epoch 请求立即拒绝或重试。
- 内容与 ACL 从外部源同步时保存同一源版本/游标；不能先发布内容、稍后再补权限。
- 若无法做到全域原子更新，按资源范围设置 `authz_fence`，只暂停受影响文档族，不必停整个租户。

### 9.2 缓存

- 结果缓存、检索缓存、授权缓存、会话压缩和引用缓存均包含策略版本和主体权限指纹。
- 撤权提升 epoch 后，旧缓存即使未物理删除也不再可读。
- 禁止只按问题文本或 `user_id` 缓存企业 RAG 答案。
- 缓存对象继承来源最高分类并使用租户密钥加密。

## 10. 故障降级

生产默认 `fail closed`：

- 身份、权限、策略版本、RLS、模型路由或 DLP 任一关键组件异常，企业检索返回明确不可用，不返回主库内容。
- 如产品必须提供降级答案，只能查询物理独立、不可被企业连接器写入的 `global_public` 库。
- OPA/OpenFGA 类服务必须通过带策略激活状态的健康检查后才能接收流量；“进程活着”不等于策略就绪。
- 恢复后重放 outbox、复核策略版本、扫描旧缓存，并对故障窗口做审计，不自动扩大权限。

## 11. 审计与告警

每次查询至少记录：

- `decision_id`、租户、匿名化主体、动作、策略版本和请求用途；
- 候选数量、授权/拒绝数量和原因码，不默认记录敏感正文；
- 进入模型的分片 ID 与哈希、模型路由类别、输出 DLP 结果和引用复核结果；
- 权限同步游标、撤权传播延迟、缓存版本和异常降级路径。

指标包括：跨租户拦截、无决策拒绝、策略超时、撤权传播 P95/P99、未授权候选率、引用复核失败、DLP 命中、连接器漂移和审计落盘失败。审计链路故障对高安全租户同样应阻止检索。

## 12. 评估体系与发布门

### 12.1 必测矩阵

- 同租户允许、跨租户拒绝、伪造 `user_id/tenant_id` 拒绝。
- 部门/项目/文件夹继承、显式拒绝优先、循环关系处理。
- 临时授权到期、授权撤销、撤销与正在生成并发。
- 混合敏感分片、重叠跨界、OCR/表格/附件夹带。
- 预过滤与后过滤结果一致；过滤后不足 `k` 时不越权补齐。
- 未授权正文不出现在重排器、模型请求、日志、追踪和缓存。
- 缓存串租户、旧 epoch、会话压缩和引用撤权。
- 权限引擎超时、空响应、部分批量响应、策略未激活时全部拒绝。
- 多个低密片段的组合推断、提示注入诱导、文档存在性探测。
- 备份、恢复、导出、删除和云同步继续保持租户及策略边界。

### 12.2 上线门

- 安全属性测试和跨租户对抗集 100% 通过，任何泄漏为零容忍。
- 干净环境端到端验收覆盖真实身份提供方、真实权限变更和真实连接器。
- 撤权传播达到明确 SLO；超出 SLO 时自动设 fence 并告警。
- 权限服务故障演练证明默认拒绝，公开库降级与企业库物理分离。
- 第三方模型请求证据证明数据分类、地区和不训练义务被执行。
- 独立安全评审通过后才能标记“企业级 RAG 权限可用”。

## 13. 纳川实施切片

1. **RAG-ACL-001：身份边界（已完成源码纵切）。** 新增不可变 `RequestContext`，禁止企业 KB API 接受可覆盖主体；缺可信 resolver、返回伪字典或客户端夹带身份字段均故障关闭，个人模式仍显式标为单所有者。
2. **RAG-ACL-002：`knowledge_v2` 存储（本地 metadata/outbox 纵切已完成）。** 独立 SQLite schema 已建立租户 epoch、文档/分片元数据和策略 outbox；不存正文，分片不得比文档低密，策略 epoch 单调且陈旧读取拒绝。PostgreSQL RLS、加密正文/向量、激活事务和真实云隔离仍未完成；旧库只做迁移源。
3. **RAG-ACL-003：安全写入（本地规划/隔离暂存纵切已完成）。** `EnterpriseSecureIngestPlanner` 固定可信 tenant/source/version/epoch，跨边界快照只返回无正文/无元数据的 quarantined 计划；先按 `policy_id + classification + acl_digest` 切连续权限域，再在域内无重叠分片，一个源快照的多域用同一 corpus epoch/outbox 事务原子暂存。暂存前重算 plan/payload 哈希闭包，正文只在瞬时 payload 中、不进 SQLite；派生物继承来源最高密级，不同 policy/epoch 在授权编译器可证明交集前一律隔离。连接器 ACL 同版本证明、加密对象写入、恶意内容扫描、向量派生及 searchable 激活仍未完成。
4. **RAG-ACL-004：授权门面（本地组合/收据纵切已完成）。** `EnterpriseAuthorizationFacade` 只接收冻结 `EnterpriseRequestContext` 和租户/策略版本绑定资源；跨租户或 epoch 不一致不调用策略引擎即拒绝。关系与属性批量结果必须精确闭合集合并绑定同一 `policy_id + policy_epoch`，两者交集才允许，显式 deny 优先；异常/超时返回 `authz_dependency_unavailable`，缺项/多项/旧策略返回 `authz_component_invalid`。允许义务去重合并，拒绝时不透传允许义务；主体/会话/权限范围用受保护 audit key 做 HMAC 指纹，决策收据不含明文主体。真实 OpenFGA/OPA、密钥托管、持久审计与生产延迟验收仍未实现。
5. **RAG-ACL-005：权限感知检索（本地代理纵切已完成）。** `EnterprisePermissionAwareRetriever` 只把可信 context 的 tenant 传入候选源，候选回传跨 tenant、分页重复或游标循环即熔断；按受限预算超量召回，逐页调用 ACL-004，对 allow 候选才向内容读取器请求正文，结果不足继续翻页。内容返回必须与授权 ID 闭包、tenant、索引 hash 和正文实算 hash 精确一致；仅授权正文可进入重排器，重排结果必须是完整排列，不能增删 ID。授权正文对象自身冻结并复核 hash，引用返回前重新按当前 epoch 授权；故障只返回空/通用不足，不读取未授权正文。真实向量库租户硬分区、加密对象读取、searchable 激活、外部重排路由与 API E2E 仍未实现。
6. **RAG-ACL-006：生成防护。** 上下文清单、模型分级路由、输出 DLP、引用复核和策略感知缓存。
7. **RAG-ACL-007：撤权与同步。** 单调 epoch、outbox、范围 fence、连接器漂移检测和恢复审计。
8. **RAG-ACL-008：真实验收。** 多租户对抗、撤权并发、故障演练、长稳和独立安全评审。

第一阶段不要改现有个人知识库的行为；企业功能走独立 API 与数据域，完成迁移验收后再决定是否统一。

## 14. 权威依据

- NIST SP 800-162：ABAC 根据主体、对象、操作和环境属性评估授权。
  https://csrc.nist.gov/pubs/sp/800/162/upd2/final
- NIST SP 800-207：零信任不因网络位置或资产归属授予隐式信任，应在资源访问前分别完成认证和授权。
  https://csrc.nist.gov/pubs/sp/800/207/final
- Google Zanzibar：关系型授权、因果顺序和内容/ACL 变更的一致性是大规模授权系统的核心。
  https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/
- OWASP LLM08:2025：RAG 的向量与嵌入存在未授权访问、跨租户泄漏、反演和投毒风险。
  https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/
- OWASP LLM02:2025：提示词限制可能被绕过，不能单独防止敏感信息泄漏。
  https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/
- PostgreSQL Row Security：启用 RLS 且无策略时默认拒绝；需注意表所有者和 `BYPASSRLS` 例外。
  https://www.postgresql.org/docs/current/ddl-rowsecurity.html
- OpenFGA RAG Authorization：官方给出预过滤、后过滤、批量权限检查和在 LLM 前过滤的工程模式。
  https://openfga.dev/docs/modeling/agents/rag-authorization
- OPA 部署与运行：OPA 作为 PDP、应用作为 PEP；策略未就绪或不可用时由集成方实施 fail-closed。
  https://www.openpolicyagent.org/docs/deploy
  https://www.openpolicyagent.org/docs/operations
