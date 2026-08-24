"""nachuan CLI 实现（ADR-0013）。只依赖 httpx；不持有任何持久秘密。"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import webbrowser
from pathlib import Path
from typing import Any, TextIO

import httpx

from gateway.codex_subscription_worker import (
    CodexSubscriptionError,
    CodexSubscriptionWorker,
)
from cli.local_web_start import (
    LocalOwnerCredentialError,
    LocalPaidMediaCapabilityError,
    LocalWebStartError,
    load_local_owner_credentials,
    load_or_create_local_owner_credentials,
    load_or_create_local_paid_media_capability,
    serve_local_web,
)
from gateway.subscription_cli_config import (
    SubscriptionCliConfigError,
    bind_kimi_subscription_cli,
    discover_and_bind_codex_subscription_cli,
    load_subscription_cli_environment,
    unbind_codex_subscription_cli,
    unbind_kimi_subscription_cli,
)
from gateway.kimi_release_manifest import fetch_kimi_official_manifest
from gateway.kimi_subscription_login import (
    KimiSubscriptionLoginController,
    KimiSubscriptionLoginError,
)
from cli import paid_media_operator

DEFAULT_BASE_URL = "http://127.0.0.1:8080"
EXIT_OK = 0
EXIT_USAGE = 64
EXIT_UNAVAILABLE = 69
EXIT_REFUSED = 77

_KEY_ENV = "NACHUAN_GATEWAY_KEY"
_KEY_FILE = "gateway_api_key.txt"
_TIMEOUT_FAST = 5.0
_TIMEOUT_CHAT = 120.0
_BODY_PREVIEW = 500


def _base_url() -> str:
    raw = os.environ.get("NACHUAN_GATEWAY_URL", "").strip()
    return (raw or DEFAULT_BASE_URL).rstrip("/")


def _data_dir() -> Path:
    configured = os.environ.get("DATA_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()
    local_app_data = os.environ.get("LOCALAPPDATA", "").strip()
    if local_app_data:
        return Path(local_app_data) / "Nachuan"
    return Path.home() / ".nachuan"


def _runtime_key() -> str | None:
    """运行时 key 只从环境或 Supervisor 生成的 key 文件读取，不扫描其他应用配置。"""

    key = os.environ.get(_KEY_ENV, "").strip()
    if key:
        return key
    data_dir = _data_dir()
    try:
        return load_local_owner_credentials(data_dir).runtime_key
    except FileNotFoundError:
        pass
    except LocalOwnerCredentialError:
        return None
    try:
        value = (data_dir / _KEY_FILE).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


def _client(base_url: str, transport: httpx.BaseTransport | None) -> httpx.Client:
    return httpx.Client(base_url=base_url, transport=transport)


def _request(
    client: httpx.Client,
    method: str,
    path: str,
    *,
    key: str | None = None,
    timeout: float = _TIMEOUT_FAST,
    json_body: dict[str, Any] | None = None,
) -> tuple[httpx.Response | None, str | None]:
    """统一错误面：返回 (response, None) 或 (None, 用户可读错误)。"""

    headers = {"Authorization": f"Bearer {key}"} if key else None
    try:
        response = client.request(
            method, path, headers=headers, timeout=timeout, json=json_body
        )
    except (httpx.ConnectError, httpx.ConnectTimeout):
        return None, "引擎未运行或不可达（先启动引擎，或检查 NACHUAN_GATEWAY_URL）。"
    except httpx.TimeoutException:
        return None, "请求超时：引擎响应过慢。"
    return response, None


def _status_error(response: httpx.Response) -> tuple[int, str]:
    if response.status_code in (401, 403):
        return EXIT_REFUSED, "鉴权失败：runtime key 不对，检查 NACHUAN_GATEWAY_KEY 或 data/gateway_api_key.txt。"
    preview = response.text[:_BODY_PREVIEW]
    return EXIT_UNAVAILABLE, f"引擎返回 HTTP {response.status_code}：{preview}"


def _print_json(payload: Any, out: TextIO) -> None:
    out.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def _cmd_status(args: argparse.Namespace, client: httpx.Client, out: TextIO, err: TextIO) -> int:
    response, error = _request(client, "GET", "/health")
    if error:
        err.write(error + "\n")
        return EXIT_UNAVAILABLE
    assert response is not None
    if response.status_code != 200:
        code, message = _status_error(response)
        err.write(message + "\n")
        return code
    try:
        payload = response.json()
    except ValueError:
        payload = {"raw": response.text[:_BODY_PREVIEW]}
    if args.json:
        _print_json(payload, out)
    else:
        status = payload.get("status", "unknown") if isinstance(payload, dict) else "unknown"
        out.write(f"引擎状态：{status}\n")
    return EXIT_OK


def _require_key(err: TextIO) -> str | None:
    key = _runtime_key()
    if not key:
        err.write(
            "缺少 runtime key：设置 NACHUAN_GATEWAY_KEY，"
            "或先由 Supervisor 生成 data/gateway_api_key.txt。\n"
        )
    return key


def _cmd_models(args: argparse.Namespace, client: httpx.Client, out: TextIO, err: TextIO) -> int:
    key = _require_key(err)
    if not key:
        return EXIT_REFUSED
    response, error = _request(client, "GET", "/v1/models", key=key)
    if error:
        err.write(error + "\n")
        return EXIT_UNAVAILABLE
    assert response is not None
    if response.status_code != 200:
        code, message = _status_error(response)
        err.write(message + "\n")
        return code
    payload = response.json()
    if args.json:
        _print_json(payload, out)
    else:
        for item in payload.get("data", []):
            out.write(str(item.get("id", "?")) + "\n")
    return EXIT_OK


def _cmd_chat(args: argparse.Namespace, client: httpx.Client, out: TextIO, err: TextIO) -> int:
    key = _require_key(err)
    if not key:
        return EXIT_REFUSED
    body = {
        "model": args.model,
        "messages": [{"role": "user", "content": args.message}],
        "stream": False,
    }
    response, error = _request(
        client, "POST", "/v1/chat/completions", key=key,
        timeout=_TIMEOUT_CHAT, json_body=body,
    )
    if error:
        err.write(error + "\n")
        return EXIT_UNAVAILABLE
    assert response is not None
    if response.status_code != 200:
        code, message = _status_error(response)
        err.write(message + "\n")
        return code
    payload = response.json()
    if args.json:
        _print_json(payload, out)
        return EXIT_OK
    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        _print_json(payload, out)
        return EXIT_OK
    out.write(str(content) + "\n")
    return EXIT_OK


def _cmd_ui(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    url = _base_url() + "/"
    out.write(f"本地 Web UI：{url}\n")
    out.write("（默认使用 wheel 内置 Web UI；NACHUAN_WEB_UI_DIR 仅用于显式外置覆盖。）\n")
    if args.open:
        webbrowser.open(url)
    return EXIT_OK


def _cmd_start(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    data_dir = _data_dir()
    try:
        credentials = load_or_create_local_owner_credentials(data_dir)
        paid_capability = load_or_create_local_paid_media_capability(data_dir)
        return serve_local_web(
            credentials,
            paid_capability,
            data_dir=data_dir,
            port=args.port,
            open_browser=not args.no_open,
            out=out,
            environment=os.environ,
        )
    except (
        LocalOwnerCredentialError,
        LocalPaidMediaCapabilityError,
        LocalWebStartError,
    ) as exc:
        err.write(f"纳川本地 Web 启动失败：{exc}\n")
        return EXIT_REFUSED


def _cmd_paid_media(
    args: argparse.Namespace,
    out: TextIO,
    err: TextIO,
) -> int:
    data_dir = _data_dir()
    try:
        if args.paid_media_recovery_command == "inspect":
            payload = paid_media_operator.inspect_prepared_video(
                data_dir=data_dir,
                operation_id=args.operation_id,
            )
        elif args.paid_media_recovery_command == "execute":
            payload = asyncio.run(
                paid_media_operator.execute_prepared_video(
                    data_dir=data_dir,
                    operation_id=args.operation_id,
                    decision_id=args.decision_id,
                    confirmation=args.confirm,
                    media_config_path=args.media_config,
                )
            )
        else:
            err.write("未知的 prepared 恢复命令。\n")
            return EXIT_USAGE
    except paid_media_operator.PaidMediaOperatorCliError as exc:
        err.write(f"本机管理员 prepared 恢复失败：{exc}\n")
        return EXIT_REFUSED
    if args.json:
        _print_json(payload, out)
    elif args.paid_media_recovery_command == "inspect":
        out.write(
            "既有 prepared 视频已通过只读核验；未调用 Agnes。\n"
            f"operationId: {payload['operationId']}\n"
            f"decisionId: {payload['decisionId']}\n"
            f"candidateSha256: {payload['candidateSha256']}\n"
            f"确认短语: {payload['challenge']}\n"
        )
    else:
        out.write(
            "既有 prepared 视频恢复完成；Agnes create=0，poll=0。\n"
            f"operationId: {payload['operationId']}\n"
            f"resultSha256: {payload['resultSha256']}\n"
            f"archiveReceiptSha256: {payload['archiveReceiptSha256']}\n"
        )
    return EXIT_OK


def _cmd_codex(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    data_dir = _data_dir()
    if args.codex_command == "bind":
        try:
            binding = discover_and_bind_codex_subscription_cli(
                data_dir,
                args.path,
                environment=os.environ,
            )
        except SubscriptionCliConfigError as exc:
            err.write(f"Codex binding failed: {exc}\n")
            return EXIT_REFUSED
        if args.json:
            _print_json(
                {
                    "state": "bound",
                    "path": binding.path,
                    "sha256": binding.sha256,
                    "publisher": binding.publisher,
                },
                out,
            )
        else:
            out.write(
                "Codex bound to official signed CLI.\n"
                f"Publisher: {binding.publisher}\n"
                f"Path: {binding.path}\n"
                "Next: run `codex login` if needed, then "
                "`nachuan codex status`.\n"
            )
        return EXIT_OK

    if args.codex_command == "status":
        try:
            overlay = load_subscription_cli_environment(data_dir)
        except SubscriptionCliConfigError as exc:
            err.write(f"Codex binding unavailable: {exc}\n")
            return EXIT_UNAVAILABLE
        environment = dict(os.environ)
        environment.update(overlay)
        state = CodexSubscriptionWorker(environment=environment).probe_status()
        if args.json:
            _print_json({"state": state, "bound": bool(overlay)}, out)
        else:
            out.write(f"Codex subscription state: {state}\n")
        return (
            EXIT_OK
            if state in {"authenticated_unprobed", "ready"}
            else EXIT_UNAVAILABLE
        )

    if args.codex_command == "unbind":
        try:
            removed = unbind_codex_subscription_cli(data_dir)
        except SubscriptionCliConfigError as exc:
            err.write(f"Codex binding unavailable: {exc}\n")
            return EXIT_UNAVAILABLE
        if args.json:
            _print_json({"state": "unbound", "removed": removed}, out)
        else:
            out.write("Codex binding removed.\n" if removed else "Codex was not bound.\n")
        return EXIT_OK

    if args.codex_command == "logout":
        try:
            overlay = load_subscription_cli_environment(data_dir)
        except SubscriptionCliConfigError as exc:
            err.write(f"Codex binding unavailable: {exc}\n")
            return EXIT_UNAVAILABLE
        environment = dict(os.environ)
        environment.update(overlay)
        try:
            state = CodexSubscriptionWorker(environment=environment).logout()
        except CodexSubscriptionError as exc:
            if args.json:
                _print_json({"state": exc.code}, out)
            else:
                err.write(f"Codex logout failed: {exc.code}\n")
            return EXIT_UNAVAILABLE
        if args.json:
            _print_json({"state": state}, out)
        else:
            out.write(
                "Codex subscription state: logged_out\n"
                "Official `codex logout` ran and the post-logout official "
                "`codex login status` proof reads logged out.\n"
            )
        return EXIT_OK

    err.write(f"Unknown Codex command: {args.codex_command}\n")
    return EXIT_USAGE


def _cmd_kimi(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    data_dir = _data_dir()
    if args.kimi_command == "bind":
        executable_path = args.path
        if executable_path is None:
            executable_path = str(Path.home() / ".kimi-code" / "bin" / "kimi.exe")
        try:
            binding = bind_kimi_subscription_cli(
                data_dir,
                executable_path,
                version=args.version,
                manifest_fetcher=fetch_kimi_official_manifest,
            )
        except SubscriptionCliConfigError as exc:
            err.write(f"Kimi Code binding failed: {exc}\n")
            return EXIT_REFUSED
        if args.json:
            _print_json(
                {
                    "state": "bound",
                    "path": binding.path,
                    "version": binding.version,
                    "platform": binding.platform,
                    "provenance": binding.provenance,
                },
                out,
            )
        else:
            out.write(
                "Kimi Code bound to an official HTTPS release manifest.\n"
                f"Provenance: {binding.provenance}\n"
                f"Version: {binding.version} ({binding.platform})\n"
                f"Path: {binding.path}\n"
                "State: installed_unprobed. Login and ACP model access are "
                "not verified yet.\n"
            )
        return EXIT_OK

    if args.kimi_command == "login":
        try:
            overlay = load_subscription_cli_environment(data_dir)
            state = KimiSubscriptionLoginController(
                protected_overlay=overlay,
            ).login()
        except SubscriptionCliConfigError as exc:
            err.write(f"Kimi Code binding unavailable: {exc}\n")
            return EXIT_UNAVAILABLE
        except KimiSubscriptionLoginError as exc:
            err.write(f"Kimi Code login unavailable: {exc.code}\n")
            return (
                EXIT_REFUSED
                if exc.code == "login_cancelled"
                else EXIT_UNAVAILABLE
            )
        if args.json:
            _print_json({"state": state}, out)
        else:
            out.write(
                "Kimi Code's official ACP authenticate method confirmed a "
                "local token record in Nachuan's isolated profile. Remote "
                "token acceptance and model access remain unprobed.\n"
            )
        return EXIT_OK

    if args.kimi_command == "status":
        try:
            overlay = load_subscription_cli_environment(data_dir)
        except SubscriptionCliConfigError as exc:
            err.write(f"Kimi Code binding unavailable: {exc}\n")
            return EXIT_UNAVAILABLE
        required = {
            "KIMI_CLI_PATH",
            "KIMI_CLI_SHA256",
            "KIMI_CLI_VERSION",
            "KIMI_CODE_HOME",
            "KIMI_CLI_TEMP_ROOT",
        }
        bound = required.issubset(overlay)
        if bound:
            try:
                state = KimiSubscriptionLoginController(
                    protected_overlay=overlay,
                ).probe_status()
            except KimiSubscriptionLoginError:
                state = "unavailable"
        else:
            state = "not_installed"
        if args.json:
            _print_json({"state": state, "bound": bound}, out)
        else:
            out.write(f"Kimi Code subscription state: {state}\n")
        return (
            EXIT_OK
            if state in {"authenticated_unprobed", "ready"}
            else EXIT_UNAVAILABLE
        )

    if args.kimi_command == "unbind":
        try:
            removed = unbind_kimi_subscription_cli(data_dir)
        except SubscriptionCliConfigError as exc:
            err.write(f"Kimi Code binding unavailable: {exc}\n")
            return EXIT_UNAVAILABLE
        if args.json:
            _print_json({"state": "unbound", "removed": removed}, out)
        else:
            out.write(
                "Kimi Code binding removed.\n"
                if removed
                else "Kimi Code was not bound.\n"
            )
        return EXIT_OK

    if args.kimi_command == "logout":
        # The official Kimi Code CLI exposes no headless logout, and Nachuan
        # never edits the vendor token store; report that boundary as-is.
        if args.json:
            _print_json({"state": "logout_unsupported"}, out)
        else:
            out.write(
                "Kimi Code logout is unsupported: the official CLI exposes no "
                "headless logout and Nachuan never edits the vendor token "
                "store. Use `nachuan kimi unbind` to drop the local binding.\n"
            )
        return EXIT_REFUSED

    err.write(f"Unknown Kimi Code command: {args.kimi_command}\n")
    return EXIT_USAGE


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nachuan",
        description="纳川本地引擎 CLI（ADR-0013：CLI + 本地 Web 分发形态）",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_status = sub.add_parser("status", help="引擎健康状态")
    p_status.add_argument("--json", action="store_true", help="输出原始 JSON")

    p_models = sub.add_parser("models", help="列出虚拟模型")
    p_models.add_argument("--json", action="store_true", help="输出原始 JSON")

    p_chat = sub.add_parser("chat", help="发送一条聊天消息")
    p_chat.add_argument("message", help="用户消息")
    p_chat.add_argument("--model", default="auto", help="虚拟模型名（默认 auto）")
    p_chat.add_argument("--json", action="store_true", help="输出原始 JSON")

    p_ui = sub.add_parser("ui", help="打印本地 Web UI 地址")
    p_ui.add_argument("--open", action="store_true", help="同时用默认浏览器打开")
    p_start = sub.add_parser(
        "start",
        help="一个命令启动本地引擎与 Web UI（前台运行）",
    )
    p_start.add_argument(
        "--port",
        type=int,
        default=8080,
        choices=range(1, 65536),
        metavar="PORT",
        help="本地监听端口（默认 8080）",
    )
    p_start.add_argument(
        "--no-open",
        action="store_true",
        help="启动后不自动打开默认浏览器",
    )
    p_paid_media = sub.add_parser(
        "paid-media",
        help="本机管理员付费媒体维护（不接受 provider key 或私有 task id）",
    )
    paid_media_sub = p_paid_media.add_subparsers(
        dest="paid_media_command",
        required=True,
    )
    p_recover_prepared = paid_media_sub.add_parser(
        "recover-prepared",
        help="只消费一笔既有 prepared 视频，禁止 provider create/poll",
    )
    prepared_sub = p_recover_prepared.add_subparsers(
        dest="paid_media_recovery_command",
        required=True,
    )
    p_prepared_inspect = prepared_sub.add_parser(
        "inspect",
        help="只读核验并生成一次性本机管理员裁决",
    )
    p_prepared_inspect.add_argument("operation_id")
    p_prepared_inspect.add_argument("--json", action="store_true")
    p_prepared_execute = prepared_sub.add_parser(
        "execute",
        help="按已核验裁决恢复本地字节、归档并 ACK",
    )
    p_prepared_execute.add_argument("operation_id")
    p_prepared_execute.add_argument("--decision-id", required=True)
    p_prepared_execute.add_argument("--confirm", required=True)
    p_prepared_execute.add_argument(
        "--media-config",
        type=Path,
        default=None,
        help="可选受信 ffmpeg/ffprobe 证明文件",
    )
    p_prepared_execute.add_argument("--json", action="store_true")
    p_codex = sub.add_parser(
        "codex",
        help="Bind and inspect a user-owned ChatGPT/Codex subscription",
    )
    codex_sub = p_codex.add_subparsers(dest="codex_command", required=True)
    p_codex_bind = codex_sub.add_parser(
        "bind",
        help="Bind the official signed Codex CLI without reading its login store",
    )
    p_codex_bind.add_argument(
        "--path",
        default=None,
        help="Absolute native codex.exe path (auto-detect official npm install if omitted)",
    )
    p_codex_bind.add_argument("--json", action="store_true")
    p_codex_status = codex_sub.add_parser(
        "status",
        help="Verify the protected binding and official CLI login status",
    )
    p_codex_status.add_argument("--json", action="store_true")
    p_codex_unbind = codex_sub.add_parser(
        "unbind",
        help="Remove the protected Codex CLI binding",
    )
    p_codex_unbind.add_argument("--json", action="store_true")
    p_codex_logout = codex_sub.add_parser(
        "logout",
        help=(
            "Run the official `codex logout` and report only a post-logout "
            "official status proof"
        ),
    )
    p_codex_logout.add_argument("--json", action="store_true")
    p_kimi = sub.add_parser(
        "kimi",
        help="Bind and inspect a user-owned Kimi Code subscription CLI",
    )
    kimi_sub = p_kimi.add_subparsers(dest="kimi_command", required=True)
    p_kimi_bind = kimi_sub.add_parser(
        "bind",
        help="Bind an official Kimi Code CLI by its exact release manifest",
    )
    p_kimi_bind.add_argument(
        "--path",
        default=None,
        help=(
            "Absolute native kimi.exe path "
            "(defaults to ~/.kimi-code/bin/kimi.exe)"
        ),
    )
    p_kimi_bind.add_argument(
        "--version",
        required=True,
        help="Exact installed release version, for example 0.27.0",
    )
    p_kimi_bind.add_argument("--json", action="store_true")
    p_kimi_login = kimi_sub.add_parser(
        "login",
        help="Run the official device login in Nachuan's isolated Kimi profile",
    )
    p_kimi_login.add_argument("--json", action="store_true")
    p_kimi_status = kimi_sub.add_parser(
        "status",
        help="Probe the protected profile through official ACP authenticate",
    )
    p_kimi_status.add_argument("--json", action="store_true")
    p_kimi_unbind = kimi_sub.add_parser(
        "unbind",
        help="Remove only the protected Nachuan Kimi Code binding",
    )
    p_kimi_unbind.add_argument("--json", action="store_true")
    p_kimi_logout = kimi_sub.add_parser(
        "logout",
        help=(
            "Truthfully refuse: the official Kimi Code CLI has no headless "
            "logout and Nachuan never edits the vendor token store"
        ),
    )
    p_kimi_logout.add_argument("--json", action="store_true")
    return parser


def run(
    argv: list[str],
    *,
    transport: httpx.BaseTransport | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    args = _build_parser().parse_args(argv)
    base_url = _base_url()

    if args.command == "ui":
        return _cmd_ui(args, out, err)
    if args.command == "start":
        return _cmd_start(args, out, err)
    if args.command == "paid-media":
        return _cmd_paid_media(args, out, err)
    if args.command == "codex":
        return _cmd_codex(args, out, err)
    if args.command == "kimi":
        return _cmd_kimi(args, out, err)

    with _client(base_url, transport) as client:
        if args.command == "status":
            return _cmd_status(args, client, out, err)
        if args.command == "models":
            return _cmd_models(args, client, out, err)
        if args.command == "chat":
            return _cmd_chat(args, client, out, err)
    err.write(f"未知命令：{args.command}\n")
    return EXIT_USAGE


def main() -> None:
    raise SystemExit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()
