# ADR-0008：用独立 Installation Epoch Root 阻断协调回滚

- 状态：部分实施（Root v5 四组件安装/运行时源码已绿；协调备份/恢复仍为商业发布 `NO-GO`）
- 日期：2026-07-16
- 范围：Desktop 付费账本、Gateway 付费请求库、自动更新状态、备份/恢复与卸载生命周期

## 背景

Desktop ledger/anchor 和 Gateway SQLite/rollback-anchor 都能检测各自的单边旧快照、身份替换、序列倒退与 anchor
丢失；但两组文件位于同一个应用数据域。若它们被成对删除或成对恢复，当前实现会把现场识别为首次初始化，旧未决操作
可能失去幂等证据。再增加一个同目录 sidecar 不能改变这个结论。

当前打包版数据位于 `%APPDATA%\aggregator-desktop\data`，源码/Supervisor 形态位于项目 `data/`。普通 SQLite 备份只
收集数据库，不携带两类 anchor；自动更新 floor 也在可被同一用户配置快照回放的 safeStorage 文件中。

## 决策合同

商业安装必须由安装器显式建立独立权威根，建议路径：

```text
C:\ProgramData\Nachuan\StateRoot\installation-root.db
```

运行时不得依据“所有文件都不存在”自动创建该根。root 不存在、损坏、为 reparse、ACL 被放宽或与本地身份/序列不一致
时，仅付费媒体和自动更新激活故障关闭；普通离线聊天不得被无关阻断。

root 至少保存：

- 256-bit `installation_id`、owner SID 摘要、单调 `epoch`、`root_revision`；
- `provisioning | active | maintenance_locked | retired` 状态；
- Desktop ledger identity、sequence floor、状态摘要；
- Gateway database identity、mutation sequence floor、状态摘要；
- Gateway Assets database identity、mutation sequence floor、状态摘要；
- Channel Media database identity、mutation sequence floor、状态摘要；
- updater release/keyring floor 和最后接受制品摘要。

每次会触达供应商的状态变化顺序固定为：本地 anchor → 本地 ledger/DB → root CAS。root CAS 未确认时立即熔断；只允许
本地序列与 floor 相等，或在可证明的崩溃收敛窗口内暂为 `floor + 1`，后者只能幂等补提交，不能再次出站。

Gateway 作为 root 单写者；Desktop main 用 boot-token 保护的内部回环接口 CAS。renderer、模型、普通 HTTP API 不暴露
root、维护票据或重锚能力。商业版要抵抗普通同 SID 进程时，单写者必须迁到 `LocalService` 状态代理和受 ACL 保护的
named pipe；普通用户可写的 ProgramData 文件只能防误删/常规恢复，不能宣称强隔离。

## 生命周期

| 场景 | 必须行为 |
|---|---|
| 首次安装 | 提权安装器创建 Root v5 `provisioning`，预分配四组件 identity；Gateway/Assets/Channel 落盘绑定，Desktop 首启绑定后转 `active` |
| v4 原地迁移 | 精确复验旧 Root/Gateway/Assets 后进入 `component_addition`，仅新增 Channel；旧 identity/floor/state proof 原样保留并追加迁移回执 |
| 自动更新 | 保留 installation id/epoch/root/数据，只单调推进 updater floor；禁止重建 root |
| 普通卸载 | 默认只移除程序与自启，保留 root 和用户数据，避免重装遗忘旧未决操作 |
| 原地重装 | root 与数据一致时接续；root 存在但任一数据集缺失时锁定 |
| 彻底清除 | 独立中文维护入口、UAC 与原生双确认；先写 `retired` tombstone，再按用户明确选择清除 |
| 备份 | manifest 记录 installation id/epoch/四组件 identity、sequence、hash；权威 root 只作证据，不作为普通可直接覆盖恢复的文件 |
| 恢复 | 先进入 `maintenance_locked` 并停止相关进程；验证通过后使用 10 分钟一次性人工票据重锚 |
| 合法重锚 | 创建新 epoch/identity，不在旧 epoch 内降低 floor；旧未决操作全部转 manual-only |

人工恢复/重锚只能由 `安装与维护` 中文入口触发，要求输入快照 SHA-256 尾段并留下不可变回执。中途崩溃时保持
`maintenance_locked`，只允许继续或回滚，绝不自动“修绿”。

## 实施状态（2026-07-18）

Root schema v5 已把 Desktop、Gateway、Gateway Assets、Channel Media 纳入固定闭集；保留 maintenance、begin reanchor、
显式 complete 与连续 receipt 链。v4→v5 迁移只允许精确、无歧义的安全子集，写入 append-only schema migration receipt，
旧三组件 proof 保持不变；component-addition 只允许 Channel 完成绑定。普通运行时只严格 `open`，不能创建或迁移；active
更新器 verifier 只读验证既有权威，不把非零 floor 当首次安装。迁移 receipt 的 operation digest 会由普通
`InstallationRoot.open()` 根据 installation id 和源快照摘要重算，不能只靠字段自述。

源码回归包括 Root 64 项、Root API/协议 84 项、三个安装控制器 73 项，以及 bootstrap/Gateway 集成矩阵；独立审查仍把
最终结论限定为 `CONDITIONAL GO`。历史 v4 兼容目前主要由当前代码动态生成降级 fixture，尚缺真实旧版冻结 SQLite 样本；
最终安装包、多用户和强杀/断电测试也未完成。

`nachuan.installation-backup.v2` 已能严格复验一个外部预冻结、预 staging 的 Root v5 四组件快照，并固定
`captureReady=false`、`restoreReady=false`。它不负责跨组件停写、受限 staging、Desktop safeStorage inventory、可信签发、
restore 或 reanchor；`final_proof_digest` 也仍只是未来受限协调器提交的持久承诺。Desktop/Gateway/Assets/Channel 均没有完整
生产 reanchor adapter。健康接口必须继续报告 `backup_supported=false`、`reanchor_supported=false`。

## 验收矩阵

- 分别或同时删除 Desktop/Gateway 的数据与 anchor，root 保留时均锁定且不生成新 identity；
- 两组成对恢复旧快照、混用另一安装/epoch/identity 时均由 floor/identity 阻断；
- root 缺失、损坏、reparse、父链可替换或 ACL 放宽时，付费能力 503，普通聊天仍可用；
- 本地提交后 root 回应丢失只能 `floor + 1` 幂等收敛；并发 CAS 只能一项成功；
- 自动更新、失败回滚、普通卸载、原地重装不改变 installation id/epoch；
- 未授权 restore/reanchor 零文件变化；授权票据单次使用且 epoch 增加；
- 对重锚的每个写入点做崩溃注入，重启后始终保持 locked 或可继续事务；
- 安装版 smoke 验证 ProgramData root、AppData 数据与更新缓存的保留/清理边界。

## 无法由纯本地文件彻底解决的边界

同一 Windows SID 的恶意进程、管理员/SYSTEM、以及同时恢复 ProgramData、AppData、数据库与 DPAPI 用户配置的整盘镜像，
都能越过普通本地文件合同。TPM sealing 本身也不是单调反回滚；更强保证需要 TPM NV 单调计数器或远端 append-only
witness。Installation root 也不能替代供应商原生幂等、任务查询、账单/发票和退款对账。

在 canonical manifest、受限协调器、组件适配器、安装器迁移、签名安装包强杀/断电与真实恢复证据全部落地前，本 ADR 不解除 `NO-GO`。
