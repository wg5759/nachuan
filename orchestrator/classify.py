"""零成本难度/类型分类（纯启发式，不调用任何 LLM）。

供「智能」「级联」「拆解」模式判断该把活派给便宜还是贵的模型。
后续可升级为 embedding 路由（仍接近零成本）或小模型裁判。
"""

from __future__ import annotations

import re
from typing import Any

_CODE = re.compile(r"```|def |class |function |import |#include|SELECT |</?\w+>|=>", re.I)
_HARD = re.compile(
    r"证明|推导|分析|为什么|设计|算法|架构|优化|重构|复杂|严谨|论证|权衡|debug|"
    r"prove|analyze|reason|architect|optimize|refactor|complex|step.by.step|trade.?off",
    re.I,
)


def classify(prompt: str) -> dict[str, Any]:
    """返回 {difficulty: easy|hard, kind: chat|code|reason|long, length}。"""
    n = len(prompt or "")
    has_code = bool(_CODE.search(prompt or ""))
    is_long = n > 1500
    is_hard_kw = bool(_HARD.search(prompt or ""))
    difficulty = "hard" if (has_code or is_long or is_hard_kw) else "easy"
    if has_code:
        kind = "code"
    elif is_long:
        kind = "long"
    elif is_hard_kw:
        kind = "reason"
    else:
        kind = "chat"
    return {"difficulty": difficulty, "kind": kind, "length": n}
