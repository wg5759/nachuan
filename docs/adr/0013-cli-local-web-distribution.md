# ADR-0013：分发形态转向 CLI + 本地 Web，冻结 Electron/商店/签名链

- 状态：接受（源码层实施开始；发布证据按新门禁重新累计）
- 日期：2026-07-20

## 背景

此前唯一发布路径是「Microsoft Store SKU + NSIS 签名安装包」，它被一组外部前置条件卡死：Authenticode 证书采购、签名级洁净主机（PR-005 当前主机不合格）、商店 13 条上架门禁、ASAR 最终字节门禁、安装/卸载/断电恢复验收。这些条件与产品价值（本地优先的多模型工作系统）没有因果关系，却消耗了大部分发布预算。

同时期 AI 工具的行业分发形态已经收敛：Kimi Code、Claude Code、Codex CLI、Aider、Open WebUI 等全部走「包管理器（npm/pip）+ CLI + 本地或托管网页」，没有任何一家要求终端用户安装 Authenticode 签名安装包。包管理器 + 账号 + HTTPS 就是这代工具的信任根；自动更新由 `pip install --upgrade` / `npm update` 原生承担，不再需要自建 Ed25519 更新信封。

机主 2026-07-20 拍板：放弃签名证书路线，按 CLI 与网页端两个方向走。

## 决策

1. **主分发形态**改为：pip 包（引擎 + `nachuan` CLI）+ 网关静态托管的本地 Web UI。Web UI 只监听专属 `127/8` 回环地址（当前 `127.77.77.77`），复用现有网关随机 runtime key 鉴权；长期 Key 由 DPAPI 保存，短期单次 fragment 只负责换取 host-only HttpOnly/SameSite Cookie，不把 Key交给页面 JavaScript。
2. **Electron 桌面端冻结**为可选壳：代码与测试资产保留、不再主动投入；商店 SKU、Authenticode/Ed25519 双轨更新、NSIS 安装器、ASAR 最终字节门禁、electronFuses 整章废弃。相关文档（README 商店边界节、`PACKAGING.md` 安装器与双轨更新合同）标注废弃并指向本 ADR。`docs/自动更新机制.md` 描述的是上游依赖巡检器，与发布通道无关，继续有效。
3. **威胁模型对齐 CLI 行业默认**：引擎/CLI 以用户身份运行是预期行为，同 SID 不再是「必须 AppContainer/LocalService」的 P0。危险能力（agent exec、宿主文件工具、MCP/插件、浏览器写动作、正式 xreview、Telegram）维持现状 fail-closed，不因分发形态变化而解禁。
4. **付费媒体确认链迁入网关**：确认交互与账本归属网关（预算闸、幂等、provider choke point、append-only 账本原本就在网关侧），Web UI 只做展示与确认弹窗；Electron main 的 paid-media 代理/确认框层随壳冻结，不再作为安全边界维护。`X-Nachuan-Paid-Media-Key`、Idempotency-Key、人工确认前置等机制不变，只换呈现层。
5. **发布门禁收敛为五条**：① 源码测试闭集全绿（Python + 保留的 Desktop 测试）；② 依赖审计 + 密钥扫描 + 第三方二进制固定来源/SHA-256；③ 微信/飞书真实账号 E2E；④ 真实供应商小额调用与账单对账；⑤ 商用预算闸保持默认关闭且回归绿。满足前可标记 internal-only，不满足不得以任何形式对外发布。
6. **pip 打包**：`pyproject.toml` 从应用项目转为可构建包（console script `nachuan`），Web UI 静态资源随包携带；引擎以源码形式运行，PyInstaller 单文件引擎不再是唯一受信运行方式。

## 边界与后果

- 公网托管 SaaS 不在本决策范围；任何把网关暴露到非本机地址的行为仍受 `app.py:main` 的「非 loopback + 弱 key 拒启」护栏约束。
- macOS/Linux 仍按原约束：运行态密钥的平台密钥库适配（Keychain/Secret Service）真机通过前，发布目标保持 Windows-only。
- 局域网洁净机的用途从「签名构建机」降级为「长稳 soak + 跨平台验证机」，门槛降低但不取消。
- Electron 侧未完成项（PR-001 裸 ack 的 main-owned proof、legacy seal、付费媒体恢复链的 Electron 段）不再作为发布阻塞跟踪；其网关侧对应物（账本、恢复、幂等）继续按五条门禁验收。
- 旧审计报告 `docs/PRODUCTION_AUDIT_20260713.md` 是历史快照，不回写；其 P0/P1 中仅与商店/签名/安装器相关的条目由本 ADR 标注废弃，其余（渠道 E2E、对账、隐私执行、供应链闭包）继续有效。
- 本 ADR 不解禁任何当前 fail-closed 能力，不改变多模型互审门禁（正式 xreview 仍退出 78），不授权对外公开发布。
