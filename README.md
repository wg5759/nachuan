# 纳川（Nachuan）

纳川是本地优先、BYOK 的多模型 AI 工作系统。它把模型连接、工具、Skill、知识、
多模型协作和可恢复任务放在一个可审计运行时中，而不是只提供模型下拉框。

> 当前公开状态：**source alpha**。源码可研究、构建和贡献；官方签名二进制、
> 企业多租户、真实渠道长稳和插件市场仍分别受发布门约束。

## 设计原则

> 能力皆插件，权限归内核，事实进事件，副作用可撤销。

模型、工具、工作流、RAG 组件、渠道和 UI 将逐步迁入稳定的能力缝隙；身份、租户、
凭证、财务/幂等账本、企业 RAG 最终授权、审计真相和安装更新信任不能被插件绕过。

当前 PK-001/PK-002 已提供严格插件 Manifest、Service/Event/Effect/Capability
内核，以及由插件 service 构造的本地 EchoProvider 纵切。第三方和模型临时插件
仍保持禁用，直到隔离 Worker、签名/SBOM、窄能力票据和卸载回滚验收完成。

## 当前能力

- OpenAI-compatible、Codex 订阅、Kimi Code 订阅等模型连接适配；
- 快速聊天、多模型协作、工具与 Skill；
- 本地知识库、长期记忆、案例复用；
- Web UI 与 Electron 桌面候选；
- 微信/飞书等渠道的持久幂等与恢复源码路径；
- 安装、许可证、SBOM、更新与最终包安全门。

能力存在于源码不等于对应真实账号、供应商、安装态或生产环境已经验收。请查看
相关设计文档和测试，而不要依据一个进程、页面或历史截图判断就绪状态。

## 快速开始（Windows 开源版）

推荐入口会下载官方安装脚本到临时目录，再执行本地文件；不会把网络响应直接管道给 PowerShell：

```powershell
$installer = Join-Path $env:TEMP 'nachuan-install.ps1'; Invoke-WebRequest https://raw.githubusercontent.com/wg5759/nachuan/main/install.ps1 -OutFile $installer; & $installer -Action Install
```

安装器不要求管理员权限；它把官方仓库引用先解析为不可变 commit，再逐项核对
`OPEN_SOURCE_SNAPSHOT.json`，并下载固定版本、固定大小和固定 SHA-256 的 `uv` 与 Python 3.12.9。

```powershell
nachuan start       # 启动本地 Web
nachuan update      # 安装新 commit，旧版本保留为回退证据
nachuan doctor      # 离线检查源码闭包、运行时哈希与三版本同步契约
nachuan uninstall   # 默认保留用户数据
```

默认仅监听 `127.0.0.1`。首次启动生成的本地运行凭证不得提交到仓库、日志或问题单。
当前仍是 source alpha，适合技术用户自托管试用，不等同于已签名普通客户桌面版。

从源码参与开发仍要求 Node.js 24.14.0 和 npm 11.12.1；见 `CONTRIBUTING.md`。

## 三版本同步

开源版、普通用户桌面版和企业商用版共享 `0.2.0` 核心，但使用三个独立发布通道。安全和功能修复不再维护三份
分叉源码；桌面版与企业版仍分别要求签名、更新、部署和真实业务验收。合同见
`config/distribution-channels.v1.json` 与 `docs/adr/0015-shared-core-multi-edition-distribution.md`。

Windows 免费开源签名不是自动权益。纳川将优先申请 SignPath Foundation，并评估 Microsoft Store MSIX 重签；
批准前不发布未签名官方安装器。详见 `docs/CODE_SIGNING_POLICY.md`。

## 测试

```powershell
.\.venv\Scripts\python.exe -X utf8 -m pytest -q
npm --prefix desktop run typecheck
uv run python scripts/verify_distribution_contract.py
```

发布、渠道、插件、付费媒体、企业 RAG 和自动更新还有额外的真实环境门禁。

## 企业 RAG

现有 `KnowledgeBase` 是个人/单所有者模式，不是企业多租户权限边界。企业目标架构
要求不可伪造的 RequestContext、租户硬隔离、权限同质分片、ReBAC/ABAC、模型前
终检、撤权 epoch、策略感知缓存、输出 DLP 和引用复核。详见
`docs/ENTERPRISE_RAG_AUTHORIZATION_ARCHITECTURE.md`。

## 安全与贡献

- 安全报告：`SECURITY.md`
- 贡献指南与 DCO：`CONTRIBUTING.md`
- 治理：`GOVERNANCE.md`
- 商标：`TRADEMARKS.md`
- 第三方来源：构建期 license/SBOM evidence 与源码旁 notices

## 许可证

Apache License 2.0。参见 `LICENSE` 和 `NOTICE`。
