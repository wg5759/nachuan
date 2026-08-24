"""nachuan CLI：本地引擎的用户入口（ADR-0013）。

用法（源码树内）::

    python -m cli start             # 一条命令启动本地引擎与 Web
    python -m cli status            # 引擎健康
    python -m cli models            # 列出虚拟模型（需要 runtime key）
    python -m cli chat "你好"       # 走 /v1/chat/completions
    python -m cli ui                # 打印本地 Web UI 地址

runtime key 解析顺序：环境变量 NACHUAN_GATEWAY_KEY → DATA_DIR/gateway_api_key.txt。
退出码：0 成功；64 用法错误；69 引擎不可达或上游错误；77 鉴权失败/缺 key。
"""

from .nachuan import (
    EXIT_OK,
    EXIT_REFUSED,
    EXIT_UNAVAILABLE,
    EXIT_USAGE,
    main,
    run,
)

__all__ = [
    "EXIT_OK",
    "EXIT_REFUSED",
    "EXIT_UNAVAILABLE",
    "EXIT_USAGE",
    "main",
    "run",
]
