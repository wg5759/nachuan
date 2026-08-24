#!/usr/bin/env python
"""PostToolUse 钩子（#4 自动验证）：改完代码当场秒级静态检查。

- 改 .py    → py_compile 语法检查（瞬时，抓语法/缩进错）
- 改 .ts/.tsx → 前端 `npm run typecheck`（tsc --noEmit，抓类型错）

只做"快"的静态检查，不在每次编辑时跑完整 pytest（太慢、会打断节奏）；
完整测试由提交前手动跑。失败时 exit 2 + stderr → 反馈给在编辑的 agent，当场看到红。
读取 PostToolUse 传来的 JSON（stdin），取被改文件路径。
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

# Windows 控制台默认 GBK，✓/❌ 会噎死 → 统一 utf-8 输出
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _fail(msg: str) -> None:
    print(msg[:1500], file=sys.stderr)
    sys.exit(2)  # 非 0 + stderr → agent 会看到


def main() -> None:
    try:
        data = json.load(sys.stdin)
    except Exception:  # noqa: BLE001  没有/坏 JSON → 安静放过
        return
    fp = ((data.get("tool_input") or {}).get("file_path") or "").strip()
    if not fp:
        return
    p = pathlib.Path(fp)
    ext = p.suffix.lower()

    if ext == ".py":
        import py_compile

        try:
            py_compile.compile(str(p), doraise=True)
        except py_compile.PyCompileError as e:
            _fail(f"❌ 语法错误 {p.name}:\n{e}")
        except FileNotFoundError:
            return
        print(f"✓ {p.name} 语法 OK")
    elif ext in (".ts", ".tsx"):
        desk = ROOT / "desktop"
        if not (desk / "package.json").exists():
            return
        try:
            r = subprocess.run(
                ["npm.cmd" if sys.platform == "win32" else "npm", "run", "typecheck"],
                cwd=str(desk),
                shell=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=180,
            )
        except subprocess.TimeoutExpired:
            return  # 超时不阻断（环境慢时别卡死编辑）
        if r.returncode != 0:
            tail = (r.stdout + r.stderr).strip().splitlines()
            _fail("❌ 前端类型检查未过:\n" + "\n".join(tail[-15:]))
        print("✓ 前端类型检查通过")


if __name__ == "__main__":
    main()
