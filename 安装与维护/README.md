# 纳川安装与维护总入口

以后与纳川有关的安装、卸载、更新、启停、诊断、备份和恢复，都从本目录进入；不再到 D 盘根目录寻找“纳川维护”“纳川临时”等兄弟文件夹。

## 当前可直接使用的入口

- **开源版用户入口**：双击 `安装开源版.cmd`，或在 PowerShell 运行项目根目录 `install.ps1`。安装后统一使用
  `nachuan start|update|doctor|uninstall`；四个中文双击入口分别是安装、更新、诊断和卸载。它是用户级源码安装，
  会解析不可变 GitHub commit、验证公开源码闭包，并使用固定 SHA-256 的 uv 与受管 Python，不需要管理员权限。
  当前状态仍是 source alpha，不是已签名普通客户桌面版。
- `检查三版本同步状态.cmd`：核对 Python 网关、桌面端以及开源/桌面/企业发布合同是否仍为同一个核心版本。
- `查看免费签名与交付状态.cmd`：打开免费开源签名路线、当前批准状态和客户交付边界；不把“已开源”误报成
  “已获 Windows 证书”。
- **pip 包 + CLI（ADR-0013 主分发形态）**：构建 `python -m build --wheel --no-isolation`（产物在 `dist\*.whl`），安装 `pip install dist\llm_aggregator-0.2.0-py3-none-any.whl`。装完：
  - `nachuan start`：一命令启动本地引擎 + Web 界面（仅绑 127.0.0.1，首次原子生成 runtime/approval 两枚随机 Key 并以当前用户 DPAPI+ACL 保护，自动打开浏览器；Key 只显示在 owner 当前终端，不进 argv/URL/日志）。`--no-open` 只起服务，`--port` 换端口。
  - `nachuan status|models|chat "消息"|ui`：健康、模型目录、单条聊天、打印 Web 地址。
  - `nachuan codex bind|status|logout|unbind`、`nachuan kimi bind|login|status|logout|unbind`：用户自有订阅连接的绑定/登录/状态/退出/解绑（只驱动官方 CLI，不抓 Cookie）。
  - 它与 Supervisor 多服务（微信/飞书桥）是两种形态：CLI 是单人本地 Web；渠道长驻仍走下方 Supervisor。
- `查看运行状态.cmd`：只读查看 Supervisor、引擎、微信和飞书状态，不会启动服务。
- `停止纳川.cmd`：停止 Supervisor、引擎与桥接，并留下持久停机闩锁，防计划任务自动复活。
- `恢复并启动纳川.cmd`：显式清除停机状态并启动受控 Supervisor。微信仍需 owner 白名单，不会自动授权第一个联系人。
- `构建本地安装包-精简版.cmd`：从锁文件进行本地 lean 构建。正式许可证、签名、AV、真实渠道和 soak 门禁未满足时会故障关闭，不能把输出当正式上架包。
- `开发模式启动桌面端.cmd`：仅供开发调试；必须显式设置开发确认变量，不能冒充生产或商店启动入口。
- `手动检查上游更新.cmd`：人工前台执行只读上游/依赖巡检并把报告留在项目 `data\`；不会安装、升级或注册计划任务。未配置受证明的 npm/gh 工具时对应栏目会明确跳过，不会回退 PATH。
- `准备FFmpeg构建输入.cmd`：人工下载 Gyan 官方固定 ZIP，先核对 ZIP 的大小和 SHA-256，再只解出受审的
  `ffmpeg.exe`、`ffprobe.exe`、`LICENSE`、`README.txt`；明确不解出 `ffplay.exe`。正式 `prepare-pack`
  本身不会联网，也不会从 PATH 或 `Program Files` 拿媒体二进制。

## FFmpeg 构建输入与许可证边界

- 人工入口的本机材料统一位于 `构建输入\`：原始 ZIP 在 `下载\`，严格四文件源在
  `ffmpeg-8.0.1-essentials_build\`，逐次验证回执在 `records\`。这些都是可重建的本机输入并已从 Git
  排除；脚本、锁文件和说明仍在项目主目录内受版本管理。
- 构建使用 `NACHUAN_MEDIA_RUNTIME_SRC` 显式指定受审源；未指定时只认上述项目内固定中文路径。源目录、
  `bin`、临时目录或备份只要出现 junction/symlink/reparse、额外 sidecar、大小或 SHA-256 漂移，就故障关闭。
- `desktop/media-runtime-lock.json` 当前锁定的是 Gyan 8.0.1 Windows x64 静态候选。它可用于工程接线与
  真解码测试，但其 GPLv3 静态构建含 x264/x265 等多项外部库；在对应源码、构建脚本、完整 NOTICE/SBOM
  和分发法律复核形成闭包前，正式生产发布必须保持 `NO-GO`。一个 `LICENSE` 文件或 FFmpeg 主仓 commit
  链接不能冒充完整 corresponding-source 证据。
- 正式替换路线已经冻结为后续专项：基于固定源码和固定工具链自建最小、禁网络、未启用 GPL/nonfree
  外部库的 LGPL codec 闭包，只保留本 probe 六种容器/图片格式及白名单视频/音频解码器；同时产出可复现
  构建配方、完整源码包、许可证/NOTICE、Native SBOM、二进制哈希、FATE/本项目反例回归和双引擎扫描。
  本轮不临时现编现换，避免用未经验证的新二进制替代已测候选。

## 安全修复

- `安全修复\恢复WindowsDefender策略.ps1`：管理员专用的主机安全恢复脚本；默认可用 `-CheckOnly` 只读检查。
  它只清理明确禁用 Defender/Windows Update 的本地策略并生成本机回执，不启动纳川，也不绕过系统保护。
- `安全修复\records\` 保存本机策略恢复证据，`安全修复\下载\` 保存经官方域、SHA-256 和 Microsoft
  Authenticode 验真的临时修复包；两者均为本机材料、已从 Git/发布包排除，禁止当成纳川依赖分发。
- 重启后双击 `安全修复\重启后检查安全状态.cmd`；它只读检查 TPM、Secure Boot、Defender、Windows Update、
  禁用策略和 pending rename，并把回执留在 `records\`。当前重启前实测按预期返回 2/未恢复，不会制造假绿。
- 需要安排维护窗或系统就地升级时，只看 `安全修复\系统恢复与升级检查清单.md`；不要另存桌面副本或从搜索结果
  临时拼命令。
- 本机下载过的三个微软包、最终域、大小、SHA-256、签名与执行结果统一见
  `安全修复\官方修复包验真记录.md`；不要凭文件名判断可信，也不要重复执行已返回 1605 的包。
- 当前 Defender 平台产品注册仍不完整，官方平台/定义包返回 `0x80070645`。必须先重启刷新已修复的服务与策略，
  再复核平台、更新签名并重新扫描。不要重复双击下载目录中的 EXE，也不要手工删除受保护注册表镜像。

## 安装与卸载

开源源码版现已有用户级安装、更新、诊断和卸载入口；它不向 `Program Files` 写文件，卸载默认保留
`%LOCALAPPDATA%\Nachuan\data`。当前仍没有可交付的正式签名桌面/企业生产安装包。历史 `0.1.0` 未签名安装器
已经作废，禁止重新安装或交付。

未来正式安装器产生后：

1. 安装入口和版本/SHA-256/签名说明必须放在本目录；
2. Windows 的实际卸载由“设置 → 应用 → 已安装的应用 → 纳川”执行；
3. 本目录必须同时提供安装后检查、升级、回滚和残留清理说明；
4. 任何必须位于 `C:\Program Files` 或 `C:\ProgramData` 的受保护实体只保留一份，不能复制回项目目录冒充第二真源。

## 自动更新

桌面端已经有受签名元数据、哈希、大小、反回滚和用户确认保护的自动更新代码，但当前没有可发布通道：Early Access 公共入口会在读取候选或联网前硬失败，内部事务仅允许数值回环测试端点；Stable/Public 仍要求有效 Authenticode。法律/许可证、候选绑定审计、独立签名身份和真实存储闭环前，不允许手工上传或绕过门禁。

## 备份与恢复

当前**没有**可供用户执行的 Installation Root 商业权威备份或恢复入口。项目中的
`nachuan.installation-backup.v2` 只是对“已由外部停写并复制到 staging 的 Root v5
四组件快照”做严格复验的试行格式，固定报告 `captureReady=false`、
`restoreReady=false`；它不会停止进程、不会创建备份、不会恢复或 re-anchor。

协议和缺口见 `..\docs\INSTALLATION_BACKUP_MANIFEST_V2.md`。受限协调器、Desktop
safeStorage/Vault inventory、跨组件 writer fence、可信签发和全组件 restore/re-anchor
适配器完成前，禁止通过手工复制 ProgramData/AppData 数据库、运行
`scripts\sqlite_backup.py` 或删除 rollback anchor 来冒充可恢复备份。未来入口通过真实
故障注入验收后，只会放在本目录，不会另建 D 盘根目录“纳川备份/维护”兄弟文件夹。

## 纳川的受控实体

- 纳川项目数据：`D:\大模型聚合器\data\`
- 纳川源码维护脚本真源：`D:\大模型聚合器\scripts\`
- 2026-06-26 遗留在 D 盘根目录的乱码同项目空壳（仅空的 `dist\models`，0 个文件）已原样归档到
  `安装与维护\安全修复\历史乱码空壳-20260626\`，用于留痕，不是第二套源码或安装入口。

全机共享知识库及其月检工具属于 `D:\AI知识库\`，不是纳川的第二套项目目录。纳川未来位于
`C:\Program Files` 或 `C:\ProgramData` 的正式受保护实体产生后，再在本目录增加唯一状态指针；不要另建 D 盘根目录兄弟文件夹。

## 当前发布状态

正式上架仍为 `NO-GO`：逐 provider-call 本地 attempt 账本已经落地，但还缺供应商账单/发票对账、服务端预算
预留与扣减、多币种和容量归档；同时仍缺最终双引擎 AV、两项 npm 许可证法律闭环、冻结的唯一候选 commit、
受支持干净 Windows 构建、真实微信/飞书闭环、安装/升级/自动更新/卸载 smoke 和长期 soak。代码签名证书按用户决定
暂缓购买；这不阻塞明确标注且不冒充正式版的内部/Early Access 验证，但 Stable/Public 仍必须通过有效签名和时间戳门禁。
门禁未满足前，正式发布构建失败是正确行为。

免费路径已冻结在 `..\docs\CODE_SIGNING_POLICY.md`：优先 SignPath Foundation，备选 Microsoft Store MSIX 重签。
开源许可证不会自动发证；外部批准前不得配置 SignPath secret，也不得用 GitHub artifact attestation 冒充 Authenticode。

项目根目录的 `build\`、`dist\`、`node_modules\`、`desktop\node_modules\` 和 `.venv\` 都是可重建的开发/构建缓存，
不是安装入口。尤其 `dist\engine.exe` 与 `dist\llama-cpu\` 中的 EXE/DLL 未形成最终签名、双引擎扫描和安装闭包证据，
禁止双击、分发或把它们当成“已安装纳川”；正式安装包产生后只从本目录公布的唯一入口安装。
