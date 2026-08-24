"""coding_team 实机 demo：临时仓库 + 真实 agent 并行实现一个小任务 + 评审。"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")  # Windows 控制台 UTF-8
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # 项目根入 sys.path

from gateway.connections import ConnectionStore  # noqa: E402
from gateway.router import Router  # noqa: E402
from orchestrator.workflows.coding_team import run_coding_team  # noqa: E402


def _git(repo: Path, *a: str) -> None:
    subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)


async def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="codeteam-"))
    _git(tmp, "init", "-b", "main")
    _git(tmp, "config", "user.email", "t@t.com")
    _git(tmp, "config", "user.name", "t")
    (tmp / "README.md").write_text("# demo\n", encoding="utf-8")
    _git(tmp, "add", "-A")
    _git(tmp, "commit", "-m", "init")
    print("repo:", tmp, flush=True)

    store = ConnectionStore(Path("data/connections.json"))
    router = Router(store=store)
    try:
        res = await run_coding_team(
            router,
            repo=str(tmp),
            task="Create calc.py with a function add(a, b) returning a+b, plus a one-line self-test under __main__.",
            planner="glm",
            implementers=[
                {"name": "codex-impl", "agent": "codex"},
            ],
            reviewer="glm",
        )
    finally:
        await router.aclose()

    print("\n=== PLAN (glm) ===\n", (res["plan"] or "")[:400])
    for im in res["implementations"]:
        r = im.get("result", {})
        print(f"\n=== {im['name']} ({im['agent']}) ===")
        print("ok:", r.get("ok"), "| error:", (r.get("error") or "")[:150])
        print("diff:\n", (im.get("diff") or "(no diff)")[:700])
    print("\n=== REVIEW (glm) ===\n", (res["review"] or "")[:600])


if __name__ == "__main__":
    asyncio.run(main())
