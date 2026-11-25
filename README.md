# Nachuan (纳川)

> **Zero-Telemetry, Verifiable Multi-Agent Control Plane**
> **可自证零遥测的多 Agent 编码与本地 AI 控制面** — Built for developers who want multi-worktree parallel coding, visual diff review, cross-platform native secret storage, and **tool-verifiable privacy** instead of opaque promises.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Zero Telemetry](https://img.shields.io/badge/telemetry-8%2F8%20checks%20verified-brightgreen.svg)](scripts/verify_zero_telemetry.py)
[![Coding Control Plane](https://img.shields.io/badge/control--plane-Worktree%20%2B%20Diff%20%2B%20Plan%2FBuild-6f42c1.svg)](gateway/workspace_control.py)
[![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-informational.svg)](.github/workflows/ci.yml)

English | [简体中文完整运维与边界说明 (README.zh-CN.md)](README.zh-CN.md)

> **Release status**: `0.2.0` **source alpha** (Apache-2.0). Source, CLI + Local Web control plane, zero-telemetry verifier, and multi-worktree Coding Studio are open for inspection, testing, and contribution; signed consumer desktop installers and hosted enterprise multi-tenant deployments remain gated by independent release doors (see [`PACKAGING.md`](PACKAGING.md) and [`docs/CODE_SIGNING_POLICY.md`](docs/CODE_SIGNING_POLICY.md)).

![Nachuan 31s Real-Machine Walkthrough](https://github.com/wg5759/nachuan/releases/download/v0.2.0-alpha/nachuan_demo_en_preview.gif)

### Core Highlights · 核心卖点速览

- **60-Second Quickstart · 60 秒极速启动**：一条命令 `nachuan start` 启动 `127.77.77.77` 专属回环引擎与本地 Web 控制面。
- **One-Command Zero-Telemetry Proof · 一键自证零遥测**：随时运行 `python scripts/verify_zero_telemetry.py --json`，8 项硬断言端到端实证 0 遥测 SDK、0 第三方 CLI 凭据读取、0 隐式非回环外联。
- **Hook-Safe Multi-Worktree Coding Control Plane · 多 Git Worktree 并行编码控制面**：隔离任务分支 + 自动 `.git/info/exclude` 零污染 + 可视化逐行 Diff + 单文件 Revert / 本地 Commit + Plan（只读探索）/ Build（审批绑定单次消费）双模执行闸。
- **Live Outbound Firewall & Air-Gapped Mode · 实时网络出站审计与空气间隙纯离线模式**：可视化查看每次出站请求，一键硬拦截所有非回环连接，本地 Ollama / `llama.cpp` 全速离线运行。
- **3-DB Lean SQLite Core & Cross-Platform Keyring · 3 核心 SQLite 库与跨平台密钥环**：精简为 `core.db` / `memory.db` / `ops.db` 三库架构，原生适配 Windows DPAPI / macOS Keychain / Linux Secret Service / `0600` AES-256-GCM 密文密钥文件。

---

## Why Nachuan? (Don't Trust Promises — Verify Every Packet)

Most coding shells ask you to *trust* their privacy claims, or give local agents unrestricted shell access with zero approval trail. Nachuan takes a strict engineering stance:

1. **Tool-Verifiable Zero Telemetry** — Run one command anytime to verify static zero-SDK compliance, zero third-party CLI credential harvesting (never reads `~/.claude.json` or `~/.codex/auth.json`), and live air-gapped blocking:
   ```bash
   python scripts/verify_zero_telemetry.py --json
   ```
2. **Real-Time Outbound Audit Firewall & One-Click Air-Gapped Mode** — Every outbound HTTP request inside the gateway and Electron shell passes through a unified `OutboundGuard` ring buffer visible live in the UI (`GET /v1/privacy/outbound-audit`). Flip **Air-Gapped Mode** on to hard-block every non-loopback connection before socket connect while keeping local Ollama / `llama.cpp` models running at full speed.
3. **Hook-Safe Multi-Worktree Coding Studio + Plan/Build Sandbox** — Spawn isolated `git worktree` sessions in parallel for Codex, Claude Code, OpenCode, Kimi Code, Local Ollama, or any BYOK cloud model. Every git call forces `-c core.hooksPath=/dev/null -c core.fsmonitor=false -c protocol.file.allow=never` to prevent malicious repo hook RCE. Review structured per-file Unified Diffs, revert single files, commit selectively, and route sensitive Build commands to Desktop / Mobile Web PWA / Discord / Slack / Telegram / Feishu / WeChat approvals.
4. **Cross-Platform Native Secret Store** — Zero plaintext secret fallback: Windows DPAPI, macOS Keychain (`/usr/bin/security`), Linux Secret Service (`secret-tool`), and `0600` AES-256-GCM encrypted keyfiles on headless servers.
5. **Lean 3-Database Core + Hybrid Local/Cloud Routing** — Slimmed down to 3 SQLite core files (`core.db`, `memory.db`, `ops.db`) with feature flags keeping heavy optional modules off by default; mix free local models with flagship cloud APIs to slash token spend.

---

## How Nachuan Compares

| Capability | **Nachuan** | T3 Code | OpenCode | OpenClaw |
|---|:---:|:---:|:---:|:---:|
| **Tool-Verifiable Zero Telemetry (`verify_zero_telemetry.py`)** | **Yes (CI-gated)** | No | Partial | Partial |
| **Live Outbound Audit UI + One-Click Air-Gapped Mode** | **Yes** | No | No | No |
| **Hook-Safe Parallel Git Worktrees + Per-File Diff / Revert** | **Yes** | Partial (raw git) | No | No |
| **Plan (Read-Only) / Build Approval Execution Sandbox** | **Yes** | Partial | Yes (no remote ledger) | No |
| **Remote Mobile Approvals (Web PWA / Discord / Slack / Telegram / Feishu / WeChat)** | **Yes** | Web only | No | IM only |
| **Cross-Platform Secret Keyring (Win / macOS / Linux)** | **Yes** | Partial | Env/file | Env/file |
| **Local Offline Models + BYOK Cloud Hybrid Routing** | **Yes** | Subscription-focused | Yes | Yes |

---

## 60-Second Quickstart

### Option A — CLI + Local Web Control Plane (macOS / Linux / Windows)

```bash
# 1. Build web renderer bundle
npm --prefix desktop run build:web

# 2. Install as a local Python package / CLI
pip install -e .

# 3. Launch local engine (binds strictly to 127.77.77.77) & open Web UI
nachuan start
```

### Option B — Windows Verified Source Installer (No Admin Required, SHA-256 Verified)

Downloads the official installer locally first (never pipes network text into `iex`), resolves the repo ref to an immutable 40-char commit, and verifies every file against `OPEN_SOURCE_SNAPSHOT.json`:

```powershell
$installer = Join-Path $env:TEMP 'nachuan-install.ps1'
Invoke-WebRequest https://raw.githubusercontent.com/wg5759/nachuan/main/install.ps1 -OutFile $installer
& $installer -Action Install
```

Other handy CLI commands:
```bash
nachuan status                           # Inspect engine & connected models
nachuan models                           # List active local & BYOK routes
nachuan chat "Summarize git diff"        # Fast terminal turn
nachuan doctor                           # Verify source closure & runtime hashes
python scripts/verify_zero_telemetry.py  # Independently verify 0 telemetry calls
```

### Option C — Air-Gapped Offline Mode from Boot

```bash
NACHUAN_OFFLINE_MODE=1 nachuan start
```

All non-loopback traffic (including web search, cloud providers, webhooks, and cloud sync) is hard-blocked before connecting while local Ollama / `llama-server` models remain fully operational.

---

## Core Architecture

```text
Desktop (Electron) / Local Web PWA / Mobile IM (Discord, Slack, Telegram, Feishu, WeChat)
                                    │
                                    ▼
             Nachuan Turn Engine & Gateway (FastAPI, 127.x loopback)
   ┌──────────────────┬────────────────────────┬───────────────────────────┐
   │ Privacy Firewall │ Multi-Worktree Studio  │ Multi-Model Orchestrator  │
   │ • OutboundGuard  │ • Hook-safe worktrees  │ • Local + BYOK Routing    │
   │ • Air-Gapped Gate│ • Per-file Diff/Revert │ • Cross-Vendor Review     │
   │ • SecretStore    │ • Plan/Build Sandbox   │ • Same-Origin Memory/RAG  │
   │   (DPAPI/Keychain│ • Remote Approvals     │ • Feature-Flagged Extras  │
   │    /libsecret)   │                        │                           │
   └──────────────────┴────────────────────────┴───────────────────────────┘
                                    │
                     3-DB Lean SQLite Core (core / memory / ops)
```

---

## Key API Surfaces

- **Privacy & Outbound Firewall (P2)**:
  - `GET /v1/privacy/outbound-audit` (`limit`, `since_id`, `blocked_only`) & `DELETE /v1/privacy/outbound-audit`
  - `GET /v1/privacy/offline-mode` & `POST /v1/privacy/offline-mode`
- **Workspace Coding Control Plane (P3 — Worktrees, Diff, Revert, Commit & Plan/Build Approval Gate)**:
  - `GET / POST /v1/workspace/worktrees` & `POST /v1/workspace/worktrees/remove` (`DELETE /v1/workspace/worktrees`)
  - `GET /v1/workspace/diff` (`worktree_path`, `staged`)
  - `POST /v1/workspace/revert-file` & `POST /v1/workspace/commit` (local commit only, never `git push`)
  - `POST /v1/workspace/exec-plan` (`plan` read-only allowlist | `build` one-time approval-bound execution)
- **Multi-Worktree Coding Studio & Approvals (P3)**:
  - `GET / POST /v1/coding/sessions`, `DELETE /v1/coding/sessions/{id}`
  - `GET /v1/coding/sessions/{id}/diff`, `POST /v1/coding/sessions/{id}/mode` (`plan` | `build`)
  - `POST /v1/coding/sessions/{id}/revert`, `POST /v1/coding/sessions/{id}/commit`, `POST /v1/coding/sessions/{id}/exec`
  - `GET /v1/coding/approvals` & `POST /v1/coding/approvals/{id}/resolve`
- **Global IM Remote Approval Bridge (P4)**:
  - `bridge/global_approval_webhook.py` — SSRF-allowlisted Discord & Slack HTTPS approval cards + Slack HMAC-SHA256 replay-protected verification.

---

## Verification & Tests

```bash
# Zero-telemetry & air-gapped proof
python scripts/verify_zero_telemetry.py --json

# Core P0-P4 backend verification suites
pytest -q tests/test_p0_privacy_isolation.py tests/test_p1_architecture_slim.py \
  tests/test_p2_privacy_crossplatform.py tests/test_p3_coding_studio.py \
  tests/test_p4_global_approval.py

# Shared-core distribution contract
python scripts/verify_distribution_contract.py

# Desktop TypeScript check, web build, and Vitest suite
npm --prefix desktop run typecheck
npm --prefix desktop run build:web
npm --prefix desktop test
```

---

## Security Boundaries, Governance & Documentation

- **Full Chinese Operations & Architecture Notes**: [`README.zh-CN.md`](README.zh-CN.md)
- **Architecture Decision Records**: [`docs/adr/`](docs/adr/)
- **Open-Source Strategy & Boundaries**: [`docs/OPEN_SOURCE_STRATEGY_OPENCLAW_COMPARISON.md`](docs/OPEN_SOURCE_STRATEGY_OPENCLAW_COMPARISON.md)
- **Packaging & Release Gates**: [`PACKAGING.md`](PACKAGING.md) · [`docs/CODE_SIGNING_POLICY.md`](docs/CODE_SIGNING_POLICY.md)
- **Security Policy, Governance & Trademarks**: [`SECURITY.md`](SECURITY.md) · [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`GOVERNANCE.md`](GOVERNANCE.md) · [`TRADEMARKS.md`](TRADEMARKS.md)

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
