"""PyInstaller 打包入口：启动引擎（等价 `python -m gateway.app`）。

打成单个可执行文件后，目标机无需安装 Python / uv 即可运行引擎。
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from gateway.runtime_profile import enforce_frozen_store_profile

INSTALLATION_PROVISION_ARGUMENT = "--nachuan-provision-installation-root"
WEIXIN_BRIDGE_ARGUMENT = "--nachuan-weixin-bridge"
ISOLATED_PLUGIN_WORKER_ARGUMENT = "--nachuan-isolated-plugin-worker"
_EXIT_USAGE = 64
_EXIT_UNAVAILABLE = 69
_EXIT_REFUSED = 77


def enforce_frozen_financial_ledger() -> None:
    """Make a packaged engine fail closed even when Electron is bypassed."""

    if not bool(getattr(sys, "frozen", False)):
        return
    raw_data_dir = str(os.environ.get("DATA_DIR") or "").strip()
    data_dir = Path(raw_data_dir)
    if not raw_data_dir or not data_dir.is_absolute():
        raise RuntimeError(
            "packaged engine requires an absolute DATA_DIR from the trusted launcher"
        )
    # Never honor inherited overrides in a production executable.
    os.environ["NACHUAN_PROVIDER_CALL_LEDGER_MODE"] = "required"
    os.environ["NACHUAN_PROVIDER_CALL_LEDGER_PATH"] = str(
        data_dir / "provider-calls.db"
    )


def run_engine_entrypoint(arguments: list[str] | None = None) -> int:
    """Dispatch the closed installer/channel verbs before the network service."""

    args = list(sys.argv[1:] if arguments is None else arguments)
    if args:
        if args[0] == ISOLATED_PLUGIN_WORKER_ARGUMENT:
            if len(args) != 6:
                return _EXIT_USAGE
            if not bool(getattr(sys, "frozen", False)) or os.name != "nt":
                return _EXIT_REFUSED
            from orchestrator.windows_appcontainer import (
                current_process_is_nachuan_appcontainer,
                fence_current_process_singleton,
            )

            if not current_process_is_nachuan_appcontainer():
                return _EXIT_REFUSED
            try:
                request_limit = int(args[2])
                response_limit = int(args[3])
                cpu_time_ms = int(args[4])
                memory_bytes = int(args[5])
            except ValueError:
                return _EXIT_USAGE
            if not fence_current_process_singleton(
                cpu_time_ms=cpu_time_ms,
                memory_bytes=memory_bytes,
            ):
                return _EXIT_REFUSED
            from cli.isolated_plugin_worker_entrypoint import run

            return run(
                args[1],
                max_request=request_limit,
                max_response=response_limit,
            )
        if args == [WEIXIN_BRIDGE_ARGUMENT]:
            # The signed engine payload is also the only reviewed Python
            # runtime available in an installed Desktop build. Reuse that
            # exact payload instead of a system Python or unpacked source.
            enforce_frozen_store_profile()
            from scripts.run_weixin_ilink_bridge import main as bridge_main

            bridge_main()
            return 0
        if args != [INSTALLATION_PROVISION_ARGUMENT]:
            # A closed argument set prevents a misspelled installer command
            # from accidentally falling through to a long-running Gateway.
            return _EXIT_USAGE
        if not bool(getattr(sys, "frozen", False)) or os.name != "nt":
            return _EXIT_REFUSED
        try:
            from gateway.installation_bootstrap import provision_fixed_authority

            provision_fixed_authority()
            return 0
        except Exception:  # noqa: BLE001 -- installer output is deliberately fixed
            # Never leak paths, SIDs, identities, or chained SQLite/ACL errors
            # into an NSIS log that may be collected by third parties.
            sys.stderr.write("NACHUAN_INSTALLATION_AUTHORITY_FAILED\n")
            return _EXIT_UNAVAILABLE

    enforce_frozen_store_profile()
    enforce_frozen_financial_ledger()
    from gateway.app import main

    main()
    return 0


if __name__ == "__main__":
    raise SystemExit(run_engine_entrypoint())
