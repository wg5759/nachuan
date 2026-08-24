# ADR-0012：TaskLedger 以精确 SQLite 代际和独立物理终态页作为权威

- 状态：接受（源码与测试合同；Windows 断电实机仍待验）
- 日期：2026-07-19

## 背景

`jobs`/`steps` 是长期任务的执行、租约、幂等键和审批后 `execution_spec` 真源。旧实现先切 WAL、设置页数，再用 `CREATE IF NOT EXISTS` 与 `ALTER TABLE` 静默补齐对象；未知库、残缺库和被删触发器的库因此会在分类前被修改。

schema-v2 曾把 `zeroblob` 放在将来接收终态文本的同一行，误把“blob 已占字节”当成“UPDATE 必能原地完成”。SQLite 可能先为新 cell/overflow chain 分配页、再回收旧 blob；当 `max_page_count` 已等于当前 `page_count` 时，未领取失败和已领取终态都可抛出 `SQLITE_FULL`，并把 job/step 留在 `running`。

## 决策

当前代际使用 `application_id=NCTL`、`user_version=3`。权威比较覆盖完整 `sqlite_master(type,name,tbl_name,sql)`，包括 `sql=NULL` 的真实自动索引；额外 table/view/index/trigger、保留前缀伪对象、缺对象、字面量大小写变化和 token 边界变化全部拒绝。

`missing` 只表示 main、`-wal`、`-shm`、`-journal` 四个 family 成员全部不存在；main 缺失但任一 sidecar 存在时必须保留现场并在任何 RW open 前拒绝。已有 main 先用 `mode=ro&immutable=1` 做无副作用的基础页初筛。因为 immutable 会忽略 hot WAL，sidecar 准入使用以下闭集：

- 无 sidecar：直接采用 immutable 视图的精确代际；
- `-wal` 与 `-shm` 成对、且没有 `-journal`：再用 `mode=ro`、`query_only=ON` 和显式只读事务读取包含 WAL 的一致逻辑视图，只有精确 current 或显式支持的完整历史代才能进入 RW；未知/残缺逻辑 schema 在 checkpoint 或恢复前拒绝；
- WAL 无 SHM、SHM 无 WAL、任意 rollback journal：保留现场并预先拒绝，不能让探针创建缺失 SHM 或尝试 rollback recovery。

WAL-aware 只读分类允许 SQLite 对既有 SHM 做锁协调，但不得改写 main/WAL。它既能在读写恢复前识别“外来 schema 只存在于废弃 WAL”，也能接住“主库仍是 v2、v2→v3 事务已经 commit 到 WAL 后进程强杀”的合法状态；后者的逻辑视图是完整 v3，不能因 immutable 主文件仍是 v2 而永久拒绝。

family 成员存在性在 immutable 分类前后、WAL-aware 分类后必须相同，writer open 前再对照一次；成员在 missing preflight 后到达会触发重新分类而不是 provision。只有已经证明 family 全空才允许建库；无 sidecar 的完整历史代或 WAL-aware 逻辑视图中的完整历史代才允许迁移；完整 current 代才允许进入正常运行与切换 WAL。支持的历史代只有：

- `aa0025a` 原始完整 DDL；
- 实际安装开发库中由历史 `ALTER TABLE` 形成的完整追加列代；
- `1cbc955`、`72ea2a3`、`2821cc4` 共同提交的完整租约 DDL。
- 完整且计数一致的 NCTL/schema-v2；迁移会清空旧同一行 blob，并在同一事务内建立 v3 独立页权威。

任意缺索引、混入对象或部分列组合都不自愈。迁移在单事务内重建当前表、触发器、索引和容量计数，保留执行规范、租约 epoch/owner/token、幂等键、步骤状态和结果；失败时整笔回滚。

运行期所有写在同一 `RLock` 和 `BEGIN IMMEDIATE` 下串行。外部连接提交会改变 writer 的 `data_version/schema_version`，下一次读写先做完整精确复验与容量对账。普通轮询不重复 `quick_check` 和全表 `SUM`：它通过短写屏障把 query-only reader 固定到已提交快照，只做身份与小规模 schema 对照，随后立即释放 writer 锁；独立活跃读者计数只用于让 `close()` 等待在途快照。`close()` 可重复调用。

异步 root/step 心跳通过工作线程调用同步 SQLite 续租，避免 FULL 提交阻塞事件循环。续租返回 false 或抛错后，先取消并排空 executor；该 worker 不再用已经无法证明的 epoch 尝试释放租约。

固定边界为 4,096 jobs、65,536 steps、192 MiB 逻辑载荷、256 MiB 主库；主库、WAL、SHM、rollback journal 还各有启动/操作前水位闸。输出、错误、结果和执行规范同时有 UTF-8 字节上限。

v3 新增 `ledger_terminal_headroom`。job 创建时即为“worker 启动前失败”提交独立页预留；从失败/暂停恢复时必须先重新取得它。step 只有在 claim 事务内取得独立预留后才能返回给 executor。预留按数据库真实 `page_size` 和终态整行最大编码量计算（不只计算新增 result/output），记录 owner、所需页数与物化 blob；它同时进入逻辑容量计数，不能被另一个在途任务借名占用。

终态事务先记录 `page_count/freelist_count`，删除自己名下的预留，并要求 freelist 增量（或 auto-vacuum 的等价页收缩）达到该终态的保守页数；之后才更新 job/step。提交前还要求主库没有超过事务前页数，且事务前已有空闲页没有被净消耗。任一条件失败则整笔回滚，预留和运行态都保留。step 失败会在同一事务内消费 step 与 root job 两份预留；retry/释放会归还 step 预留，下一次 claim 必须重新取得。重启会逐行复核“活动 job、running step 与预留 owner”双向闭集。

## 边界与后果

- 独立预留证明的是 SQLite 主库页分配，不是 NTFS extent、磁盘配额或卷剩余空间预分配。
- `max_page_count` 只约束主库，不是 live WAL 的硬上限；`journal_size_limit` 也不能被表述成实时磁盘硬保证。即使主库页充足，WAL 写入仍可能因卷突然耗尽而失败。
- 预留解决受控主库容量下“执行完才发现终态需要新页”，不能消除操作系统突然磁盘耗尽、I/O 故障、WAL/SHM 故障或断电。
- 当前测试证明并发正确性和故障关闭；Windows Defender/磁盘抖动下的墙钟延迟不是性能验收结果，仍需独立压测。
- 已拒绝 symlink/junction/reparse 路径和打开前后的文件身份变化；但同 SID 恶意进程仍可能在最后一次复验与系统调用之间竞争。生产仍需要低权限服务账户、ACL/句柄钉扎和实机故障注入。
- family presence 的两次复验封住可观测到的到达/消失竞态，但 Python/SQLite 没有把最后一次 `lstat` 与后续 RW `open` 合成单一内核原子操作；同 SID 对手仍可在该窄窗口换入 sidecar。exact current main 的合法 hot WAL 也必须进入锁内复核，不能用 immutable 结果直接宣称 WAL 内容可信。
- SQLite 3.22+ 在 WAL 与 SHM 已存在时支持只读打开 WAL 数据库；本实现依赖该能力做逻辑视图分类。SHM 是锁与索引协调文件，分类期间其字节不承诺恒定；main 与 WAL 的无改写才是拒绝路径的取证边界。参考 SQLite 官方 [Write-Ahead Logging](https://sqlite.org/wal.html)。
- 本 ADR 只加固长期任务权威，不实现月/年调度、商业流程编排或模型训练。
