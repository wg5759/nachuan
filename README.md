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

## 快速开始（源码）

要求 Python 3.11+、Node.js 24.14.0 和 npm 11.12.1。

```powershell
git clone https://github.com/wg5759/nachuan.git
cd nachuan
uv sync --locked
npm --prefix desktop ci --ignore-scripts
npm --prefix desktop run build:web
.\.venv\Scripts\python.exe -m cli start
```

默认仅监听 `127.0.0.1`。首次启动生成的本地运行凭证不得提交到仓库、日志或问题单。

## 测试

```powershell
.\.venv\Scripts\python.exe -X utf8 -m pytest -q
npm --prefix desktop run typecheck
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
