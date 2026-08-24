"""自动更新机制（批9）单测：全部 mock 网络/子进程，不真发任何请求。

覆盖：
  ① 新模型探测——假 connections + 假 /models 响应，断言 diff 正确、报告含新模型、key 不入报告文本。
  ② watch_state 快照 roundtrip——首跑全报、二跑无变化不报。
  ③ 某探测器抛异常——其它节照常、报告仍生成。
  ④ --dry / 无网——所有子进程/网络 mock 掉，不真发请求。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

import scripts.watch_updates as wu


def test_documented_script_entrypoint_bootstraps_project_imports(tmp_path):
    script = wu.PROJECT_ROOT / "scripts" / "watch_updates.py"
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() not in {"PYTHONPATH", "PYTHONHOME"}
    }

    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=tmp_path,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "--dry" in result.stdout

SECRET_KEY = "sk-super-secret-DO-NOT-LEAK-abcdef123456"


def _write_attested(path: Path, payload: bytes) -> str:
    path.write_bytes(payload)
    path.chmod(0o755)
    return wu.file_sha256(path)


def _set_attested_executable(monkeypatch, name: str, path: Path, payload: bytes) -> None:
    digest = _write_attested(path, payload)
    monkeypatch.setenv(f"NACHUAN_WATCH_{name}_BIN", str(path.resolve()))
    monkeypatch.setenv(f"NACHUAN_WATCH_{name}_SHA256", digest)


def _set_attested_npm(monkeypatch, tmp_path: Path) -> tuple[Path, Path, Path]:
    node = tmp_path / ("node.exe" if os.name == "nt" else "node")
    npm_root = tmp_path / "npm"
    npm_cli = npm_root / "bin" / "npm-cli.js"
    transitive_cli = npm_root / "lib" / "cli.js"
    npm_cli.parent.mkdir(parents=True)
    transitive_cli.parent.mkdir(parents=True)
    _set_attested_executable(monkeypatch, "NODE", node, b"reviewed node bytes")
    npm_digest = _write_attested(npm_cli, b"require('../lib/cli.js')")
    _write_attested(transitive_cli, b"module.exports = () => {}")
    monkeypatch.setenv("NACHUAN_WATCH_NPM_CLI", str(npm_cli.resolve()))
    monkeypatch.setenv("NACHUAN_WATCH_NPM_CLI_SHA256", npm_digest)
    monkeypatch.setenv(
        "NACHUAN_WATCH_NPM_TREE_SHA256", wu._attested_tree_sha256(npm_root.resolve())
    )
    return node, npm_cli, transitive_cli


class _FakeResp:
    """够用的假 httpx.Response：只需 .json() 和 .raise_for_status()。"""

    def __init__(self, payload: Any, status: int = 200):
        self._payload = payload
        self.status_code = status

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("boom", request=None, response=None)  # type: ignore[arg-type]


# ───────────────────── ① 新模型探测 ─────────────────────
def test_probe_new_models_diff_and_no_key_leak(monkeypatch, tmp_path):
    """上游 /models 返回 已接入+全新 混合，只列全新的；且 api_key 绝不出现在报告文本里。"""
    conns = {
        "agnes": {
            "type": "openai_compat",
            "api_key": SECRET_KEY,
            "base_url": "https://apihub.agnes-ai.com/v1",
            "enabled_models": [
                {"id": "agnes-flash", "upstream_model": "agnes-2.0-flash"},
            ],
        },
        # 非 openai_compat 连接（volcano）应被跳过，不拉 /models
        "volcano": {
            "type": "volcano",
            "api_key": SECRET_KEY,
            "base_url": "https://ark.cn-beijing.volces.com/api/coding/v3",
            "enabled_models": [{"id": "glm", "upstream_model": "glm-latest"}],
        },
    }
    conn_file = tmp_path / "connections.json"
    conn_file.write_text(json.dumps(conns), "utf-8")
    monkeypatch.setattr(wu, "CONNECTIONS_PATH", conn_file)

    captured_headers: dict[str, Any] = {}

    def fake_get(url: str, headers: dict | None = None, timeout: float | None = None):
        captured_headers["h"] = headers or {}
        # 只有 agnes 会被拉；返回一个已接入 + 两个全新
        assert "agnes-ai.com" in url, f"不应对非 agnes 连接发请求: {url}"
        return _FakeResp(
            {
                "data": [
                    {"id": "agnes-2.0-flash"},  # 已接入（enabled_models 里的 upstream_model）
                    {"id": "agnes-3.0-ultra"},  # 全新
                    {"id": "agnes-omni-preview"},  # 全新
                ]
            }
        )

    monkeypatch.setattr(wu.httpx, "get", fake_get)
    # 预设集合置空，避免真读 catalog 影响 diff 判定
    monkeypatch.setattr(wu, "_preset_known_upstream", lambda: set())

    res = wu.probe_new_models(dry=False)

    assert res["ok"] is True
    agnes_entry = next(c for c in res["connections"] if c["provider"] == "agnes")
    assert agnes_entry["new_models"] == ["agnes-3.0-ultra", "agnes-omni-preview"]
    assert "agnes-2.0-flash" not in agnes_entry["new_models"]  # 已接入的不算新
    # volcano 被跳过：结果里不应出现 volcano 条目
    assert all(c["provider"] != "volcano" for c in res["connections"])
    # key 只进了请求头 Authorization
    assert captured_headers["h"].get("Authorization") == f"Bearer {SECRET_KEY}"

    # 渲染报告：含新模型名，且绝不含 api_key
    report = wu.render_report(
        res, {"ok": True, "outdated": []}, {"ok": True, "outdated": []},
        {"ok": True, "changed": []}, date_str="2026-07-07",
    )
    assert "agnes-3.0-ultra" in report and "agnes-omni-preview" in report
    assert SECRET_KEY not in report
    assert "sk-super-secret" not in report


def test_probe_new_models_connection_error_isolated(monkeypatch, tmp_path):
    """单个连接 /models 抛错 → 记为该连接 error、其它逻辑不炸，且报告不含 key。"""
    conns = {
        "agnes": {
            "type": "openai_compat",
            "api_key": SECRET_KEY,
            "base_url": "https://apihub.agnes-ai.com/v1",
            "enabled_models": [],
        }
    }
    conn_file = tmp_path / "connections.json"
    conn_file.write_text(json.dumps(conns), "utf-8")
    monkeypatch.setattr(wu, "CONNECTIONS_PATH", conn_file)
    monkeypatch.setattr(wu, "_preset_known_upstream", lambda: set())

    def boom(url: str, headers: dict | None = None, timeout: float | None = None):
        raise httpx.ConnectError(f"cannot reach {url} with key {SECRET_KEY}")  # 故意把 key 塞进异常

    monkeypatch.setattr(wu.httpx, "get", boom)

    res = wu.probe_new_models(dry=False)
    entry = next(c for c in res["connections"] if c["provider"] == "agnes")
    assert entry["error"]  # 记了错
    # 关键：即便异常消息里带了 key，我们只记异常「类型」，报告绝不泄露 key
    assert SECRET_KEY not in json.dumps(res)
    report = wu.render_report(
        res, {"ok": True, "outdated": []}, {"ok": True, "outdated": []},
        {"ok": True, "changed": []}, date_str="2026-07-07",
    )
    assert SECRET_KEY not in report
    assert "拉取失败" in report


# ───────────────────── ② watch_state 快照 roundtrip ─────────────────────
def _fake_gh_factory(release_tag: str, sha: str):
    """造一个假 _gh_api：releases/latest 给 tag，commits 给 sha。"""

    def _fake(path: str):
        if path.endswith("/releases/latest"):
            return {"tag_name": release_tag, "html_url": f"https://x/{release_tag}"}
        if "/commits" in path:
            return [{"sha": sha + "0" * 40, "commit": {"message": "some change\n\nbody"}}]
        return None

    return _fake


def test_upstream_snapshot_roundtrip(monkeypatch):
    """首跑（无快照）→ 全报；二跑（快照相同）→ 不报；三跑（有新 tag）→ 只报变化的那个。"""
    monkeypatch.setattr(wu, "_resolve_gh_command", lambda: object())  # 假装认证已通过

    # 首跑：state 空
    monkeypatch.setattr(wu, "_gh_api", _fake_gh_factory("v1.0", "aaaaaaa"))
    first = wu.probe_upstream(dry=False, state={})
    assert first["ok"] and first["first_run"] is True
    # 首跑全报：4 个仓库都在 changed 里
    assert len(first["changed"]) == len(wu.WATCHED_REPOS)
    snap = first["new_state"]
    assert snap["SakanaAI/fugu"]["release"] == "v1.0"

    # 二跑：把首跑快照喂回，且上游没变 → changed 为空
    second = wu.probe_upstream(dry=False, state=snap)
    assert second["ok"] and second["first_run"] is False
    assert second["changed"] == [], "上游无变化时不应报任何仓库"

    # 三跑：只有 fugu 出了新 release v2.0，其它不变
    def _mixed(path: str):
        if path.startswith("repos/SakanaAI/fugu/"):
            return _fake_gh_factory("v2.0", "aaaaaaa")(path)
        return _fake_gh_factory("v1.0", "aaaaaaa")(path)

    monkeypatch.setattr(wu, "_gh_api", _mixed)
    third = wu.probe_upstream(dry=False, state=snap)
    changed_repos = [c["repo"] for c in third["changed"]]
    assert changed_repos == ["SakanaAI/fugu"], f"只应报有变化的 fugu，实得 {changed_repos}"
    assert third["new_state"]["SakanaAI/fugu"]["release"] == "v2.0"


def test_upstream_no_gh_degrades(monkeypatch):
    """gh 未认证 → 探测标记失败但不抛，且绝不回落 PATH。"""
    monkeypatch.setattr(
        wu,
        "_resolve_gh_command",
        lambda: (_ for _ in ()).throw(wu._ToolUnavailable("untrusted")),
    )
    res = wu.probe_upstream(dry=False, state={})
    assert res["ok"] is False and "gh" in res["note"] and "不回落 PATH" in res["note"]


def test_run_cmd_decodes_utf8_output():
    """回归：Windows 上子进程必须按 UTF-8 解码——gh/npm 返回含中文/emoji 的 JSON 时不能 GBK 崩。

    用 python 打印一段非 ASCII 到 stdout；若 _run_cmd 用了 locale(GBK) 解码，在中文 Windows 上会
    UnicodeDecodeError。断言能原样取回中文（曾导致 OpenFugu 的中文 commit message 静默丢失）。
    """
    import sys as _sys

    # 让子进程直接把 UTF-8 字节写进 stdout（绕开子 python 自身的 print 编码），
    # 纯测 _run_cmd 是否用 UTF-8 把这些字节解码回来。
    prog = "import sys; sys.stdout.buffer.write('提交信息：修复🚀 émoji'.encode('utf-8'))"
    code, out, err = wu._run_cmd([_sys.executable, "-c", prog], timeout=30)
    assert code == 0
    assert "提交信息" in out and "🚀" in out


def test_run_cmd_rejects_path_command_before_subprocess(monkeypatch):
    """纵使 PATH 头部放了伪 gh/npm/uv，裸命令名也不得越过统一子进程边界。"""

    monkeypatch.setattr(
        wu.subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not spawn")),
    )
    code, out, err = wu._run_cmd(["gh", "api", "repos/x/y"])
    assert code == -1 and not out and "PATH" in err


def test_run_cmd_strips_path_and_code_injection_environment(monkeypatch):
    """绝对程序也只能收到最小环境，不能继承 PATH/NODE_OPTIONS/项目密钥。"""

    monkeypatch.setenv("PATH", "C:\\attacker-first")
    monkeypatch.setenv("NODE_OPTIONS", "--require=C:\\evil.js")
    monkeypatch.setenv("NACHUAN_API_KEY", "do-not-forward")
    monkeypatch.setenv("SYSTEMROOT", os.environ.get("SYSTEMROOT", "C:\\Windows"))
    captured: dict[str, Any] = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(wu.subprocess, "run", fake_run)
    code, out, err = wu._run_cmd([str(Path(sys.executable).resolve()), "-c", "pass"])
    assert (code, out, err) == (0, "ok", "")
    child = captured["kwargs"]["env"]
    assert "PATH" not in child
    assert "NODE_OPTIONS" not in child
    assert "NACHUAN_API_KEY" not in child
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["stdin"] is subprocess.DEVNULL
    assert captured["kwargs"]["close_fds"] is True


def test_python_probe_fails_closed_without_current_pip_or_attested_uv(monkeypatch):
    """当前解释器不可用且 uv 未认证时，绝不能再试 PATH 中的 uv/pip。"""

    unavailable = lambda: (_ for _ in ()).throw(wu._ToolUnavailable("untrusted"))
    monkeypatch.setattr(wu, "_current_python_pip_command", unavailable)
    monkeypatch.setattr(wu, "_resolve_uv_command", unavailable)
    monkeypatch.setattr(
        wu.subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not spawn")),
    )
    result = wu.probe_python_deps()
    assert result["ok"] is False
    assert "不回落 PATH" in result["note"]


def test_attested_uv_is_absolute_and_rechecked_before_each_launch(monkeypatch, tmp_path):
    """显式 uv 路径+哈希可用；文件替换后第二次调用必须在 spawn 前拒绝。"""

    uv_bin = tmp_path / ("uv.exe" if os.name == "nt" else "uv")
    _set_attested_executable(monkeypatch, "UV", uv_bin, b"reviewed uv bytes")
    command = wu._resolve_uv_command()
    calls: list[list[str]] = []

    def fake_run_cmd(args, **kwargs):
        calls.append(args)
        return 0, "[]", ""

    monkeypatch.setattr(wu, "_run_cmd", fake_run_cmd)
    assert wu._run_tool(command, ["list"])[0] == 0
    assert Path(calls[0][0]).is_absolute()

    uv_bin.write_bytes(b"replaced after review")
    assert wu._run_tool(command, ["list"])[0] == -1
    assert len(calls) == 1, "identity drift must fail before subprocess"


def test_npm_probe_uses_attested_node_and_npm_cli_without_path(monkeypatch, tmp_path):
    """npm.cmd 不进入信任链；只运行哈希绑定的 node.exe + npm-cli.js。"""

    node, npm_cli, _ = _set_attested_npm(monkeypatch, tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path / "attacker"))
    monkeypatch.setenv("NODE_OPTIONS", "--require=evil.js")
    captured: dict[str, Any] = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["env"] = kwargs["env"]
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(wu.subprocess, "run", fake_run)
    result = wu.probe_npm_deps()
    assert result["ok"] is True
    assert captured["args"][:2] == [str(node.resolve()), str(npm_cli.resolve())]
    assert "outdated" in captured["args"]
    assert "PATH" not in captured["env"] and "NODE_OPTIONS" not in captured["env"]
    assert captured["env"]["npm_config_registry"] == "https://registry.npmjs.org"
    assert captured["env"]["npm_config_ignore_scripts"] == "true"


def test_npm_wrong_hash_fails_before_subprocess(monkeypatch, tmp_path):
    _, npm_cli, _ = _set_attested_npm(monkeypatch, tmp_path)
    monkeypatch.setenv("NACHUAN_WATCH_NPM_CLI_SHA256", "0" * 64)
    monkeypatch.setattr(
        wu.subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not spawn")),
    )
    result = wu.probe_npm_deps()
    assert result["ok"] is False and "不回落 PATH" in result["note"]


def test_npm_transitive_tree_replacement_fails_before_subprocess(monkeypatch, tmp_path):
    """只钉 npm-cli.js 不够；其 require() 的任一传递文件变化也必须阻断。"""

    _, _, transitive_cli = _set_attested_npm(monkeypatch, tmp_path)
    command = wu._resolve_npm_command()
    monkeypatch.setattr(
        wu,
        "_run_cmd",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not spawn")),
    )
    transitive_cli.write_bytes(b"require('attacker-payload')")
    code, out, err = wu._run_tool(command, ["outdated"])
    assert code == -1 and not out and "身份复核失败" in err


def test_gh_api_uses_attested_absolute_binary(monkeypatch, tmp_path):
    gh = tmp_path / ("gh.exe" if os.name == "nt" else "gh")
    _set_attested_executable(monkeypatch, "GH", gh, b"reviewed gh bytes")
    monkeypatch.setenv("PATH", str(tmp_path / "attacker"))
    captured: dict[str, Any] = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["env"] = kwargs["env"]
        return SimpleNamespace(returncode=0, stdout='{"tag_name":"v1"}', stderr="")

    monkeypatch.setattr(wu.subprocess, "run", fake_run)
    assert wu._gh_api("repos/a/b/releases/latest") == {"tag_name": "v1"}
    assert captured["args"][0] == str(gh.resolve())
    assert "PATH" not in captured["env"]


# ───────────────────── ③ 某探测器抛异常 → 其它照常 ─────────────────────
def test_one_probe_crashes_others_survive(monkeypatch, tmp_path):
    """让 Python 依赖探测器直接抛异常，其余三节仍渲染，报告仍完整生成。"""
    monkeypatch.setattr(wu, "DATA_DIR", tmp_path)
    monkeypatch.setattr(wu, "STATE_PATH", tmp_path / "watch_state.json")
    monkeypatch.setattr(wu, "CONNECTIONS_PATH", tmp_path / "nope.json")  # 不存在 → 新模型节空

    def kaboom(**kwargs):
        raise RuntimeError("pip 世界末日")

    monkeypatch.setattr(wu, "probe_python_deps", kaboom)
    # 其它探测器 dry 化，避免真联网
    monkeypatch.setattr(wu, "probe_new_models", lambda **k: {"ok": True, "connections": []})
    monkeypatch.setattr(wu, "probe_npm_deps", lambda **k: {"ok": True, "outdated": []})
    monkeypatch.setattr(wu, "probe_upstream", lambda **k: {"ok": True, "changed": [], "new_state": {}})

    rc = wu.run(["--dry"])  # 走完整主流程
    assert rc == 0
    # 报告文件应生成，且 Python 节标记探测失败（_safe 收敛了异常）
    report_files = list(tmp_path.glob("update_report_*.md"))
    assert report_files, "即便一个探测器炸了，报告仍应落盘"
    text = report_files[0].read_text("utf-8")
    assert "## ① 新模型" in text and "## ③ npm" in text and "## ④ 上游" in text
    assert "探测器异常" in text or "探测失败" in text  # Python 节体现出降级


def test_safe_wrapper_converts_exception():
    """_safe 兜底壳：任何异常 → {ok:False,...}，不外抛。"""

    def bad(**k):
        raise ValueError("x")

    out = wu._safe(bad)
    assert out["ok"] is False and "ValueError" in out["note"]


# ───────────────────── ④ --dry / 无网：不真发请求 ─────────────────────
def test_dry_run_makes_no_network_or_subprocess(monkeypatch, tmp_path):
    """--dry：httpx / subprocess 全被换成"一调用就失败"的哨兵，确认无人触发它们。"""
    monkeypatch.setattr(wu, "DATA_DIR", tmp_path)
    monkeypatch.setattr(wu, "STATE_PATH", tmp_path / "watch_state.json")

    def _forbid_http(*a, **k):
        raise AssertionError("dry 模式不应发 HTTP 请求")

    def _forbid_proc(*a, **k):
        raise AssertionError("dry 模式不应起子进程")

    monkeypatch.setattr(wu.httpx, "get", _forbid_http)
    monkeypatch.setattr(wu.httpx, "Client", _forbid_http)
    monkeypatch.setattr(wu.subprocess, "run", _forbid_proc)

    rc = wu.run(["--dry"])
    assert rc == 0
    reports = list(tmp_path.glob("update_report_*.md"))
    assert reports and "(无更新)" in reports[0].read_text("utf-8")


def test_dry_json_output_shape(monkeypatch, tmp_path, capsys):
    """--dry --json：输出可解析 JSON，含四路结果键 + report_path。"""
    monkeypatch.setattr(wu, "DATA_DIR", tmp_path)
    monkeypatch.setattr(wu, "STATE_PATH", tmp_path / "watch_state.json")
    monkeypatch.setattr(wu.httpx, "get", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no net")))
    monkeypatch.setattr(wu.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no proc")))

    rc = wu.run(["--dry", "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    # 取最后一段 JSON（前面可能有进度打印）
    start = out.index("{")
    payload = json.loads(out[start:])
    assert set(["models", "python_deps", "npm_deps", "upstream", "report_path"]).issubset(payload)


# ───────────────────── 飞书推送：缺配置即跳过 ─────────────────────
def test_feishu_skips_when_unconfigured(monkeypatch, capsys):
    """无 app_id/secret/owner → 明确打印「未配置飞书」并返回 False，不发请求。"""
    from gateway.config import Settings

    fake = Settings(feishu_app_id="", feishu_app_secret="", feishu_owner_open_id="")
    monkeypatch.setattr(wu, "httpx", wu.httpx)  # 占位
    import gateway.config as gc

    monkeypatch.setattr(gc, "get_settings", lambda: fake)

    ok = wu.push_feishu("摘要")
    assert ok is False
    assert "未配置飞书" in capsys.readouterr().out


def test_feishu_pushes_open_id_and_masks_summary(monkeypatch, capsys):
    """配齐凭证 → 走 tenant_access_token → im/v1/messages(receive_id_type=open_id)，摘要正确送达。"""
    from gateway.config import Settings

    fake = Settings(
        feishu_app_id="cli_x", feishu_app_secret="sec_x", feishu_owner_open_id="ou_owner"
    )
    import gateway.config as gc

    monkeypatch.setattr(gc, "get_settings", lambda: fake)

    calls: list[dict[str, Any]] = []

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url: str, **kw):
            calls.append({"url": url, **kw})
            if "tenant_access_token" in url:
                return _FakeResp({"tenant_access_token": "t-abc", "code": 0})
            return _FakeResp({"code": 0})

    monkeypatch.setattr(wu.httpx, "Client", _FakeClient)

    ok = wu.push_feishu("📡 更新发现摘要")
    assert ok is True
    send = next(c for c in calls if "im/v1/messages" in c["url"])
    assert send["params"]["receive_id_type"] == "open_id"
    assert send["json"]["receive_id"] == "ou_owner"
    assert json.loads(send["json"]["content"])["text"] == "📡 更新发现摘要"
    assert "已推送" in capsys.readouterr().out


def test_stale_versions_not_reported_as_new(monkeypatch, tmp_path):
    """版本感知（机主被误导后补）：上游多出的同族旧版（1.5 < 已接 2.0）归 stale 不算新模型。"""
    import scripts.watch_updates as wu

    conns = {"agnes": {
        "type": "openai_compat", "base_url": "https://x/v1", "api_key": "sk-test",
        "enabled_models": [
            {"id": "agnes-flash", "upstream_model": "agnes-2.0-flash"},
            {"id": "agnes-image", "upstream_model": "agnes-image-2.1-flash"},
        ],
    }}
    monkeypatch.setattr(wu, "_load_connections", lambda: conns)
    monkeypatch.setattr(wu, "_preset_known_upstream", lambda: set())
    monkeypatch.setattr(wu, "_fetch_models", lambda b, k: [
        "agnes-1.5-flash", "agnes-2.0-flash", "agnes-image-2.0-flash",
        "agnes-image-2.1-flash", "agnes-3.0-flash",
    ])
    out = wu.probe_new_models()
    entry = out["connections"][0]
    assert entry["new_models"] == ["agnes-3.0-flash"]  # 真升级版才算新
    assert set(entry["stale_models"]) == {"agnes-1.5-flash", "agnes-image-2.0-flash"}


def test_family_version_parsing():
    import scripts.watch_updates as wu

    assert wu._family_version("agnes-1.5-flash") == ("agnes-#-flash", (1, 5))
    assert wu._family_version("agnes-video-v2.0") == ("agnes-video-v#", (2, 0))
    f1, v1 = wu._family_version("agnes-image-2.0-flash")
    f2, v2 = wu._family_version("agnes-image-2.1-flash")
    assert f1 == f2 and v1 < v2
