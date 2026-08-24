from __future__ import annotations

import asyncio
import io
import os
import socket

import pytest


def test_launcher_fails_closed_without_explicit_test_data_dir(monkeypatch) -> None:
    from cli import nachuan
    from scripts import start_zero_network_web_e2e as launcher

    monkeypatch.delenv("DATA_DIR", raising=False)

    def must_not_start(*_args, **_kwargs) -> int:
        raise AssertionError("launcher touched the default/product data directory")

    monkeypatch.setattr(nachuan, "run", must_not_start)
    error = io.StringIO()

    assert launcher.main([], out=io.StringIO(), err=error) == 64
    assert "--data-dir" in error.getvalue()
    assert "DATA_DIR" not in os.environ


def test_launcher_refuses_a_nonempty_unmarked_data_dir(monkeypatch, tmp_path) -> None:
    from cli import nachuan
    from scripts import start_zero_network_web_e2e as launcher

    data_dir = tmp_path / "looks-like-real-data"
    data_dir.mkdir()
    existing = data_dir / "connections.json"
    existing.write_text("leave-me-alone", encoding="utf-8")

    def must_not_start(*_args, **_kwargs) -> int:
        raise AssertionError("launcher entered an unmarked existing data directory")

    monkeypatch.setattr(nachuan, "run", must_not_start)
    error = io.StringIO()

    assert (
        launcher.main(
            ["--data-dir", str(data_dir)],
            out=io.StringIO(),
            err=error,
        )
        == 64
    )
    assert "不是本启动器创建" in error.getvalue()
    assert existing.read_text(encoding="utf-8") == "leave-me-alone"
    assert not (data_dir / ".nachuan-zero-network-e2e").exists()


def test_launcher_installs_zero_network_guards_before_cli_start(
    monkeypatch, tmp_path
) -> None:
    from cli import nachuan
    from gateway import websearch
    from scripts import start_zero_network_web_e2e as launcher

    monkeypatch.setenv("LOCAL_MODEL_AUTODOWNLOAD", "1")
    monkeypatch.setenv("NACHUAN_EMBED_DISABLED", "0")

    async def forbidden_search(*_args, **_kwargs) -> int:
        raise AssertionError("the E2E launcher left real web search enabled")

    monkeypatch.setattr(websearch, "maybe_augment_request", forbidden_search)
    observed: dict[str, object] = {}

    def fake_run(argv, *, out, err) -> int:  # noqa: ANN001
        del out, err
        observed["argv"] = list(argv)
        observed["autodownload"] = os.environ.get("LOCAL_MODEL_AUTODOWNLOAD")
        observed["embedding"] = os.environ.get("NACHUAN_EMBED_DISABLED")
        observed["data_dir"] = os.environ.get("DATA_DIR")
        observed["search_result"] = asyncio.run(
            websearch.maybe_augment_request(object())
        )
        return 37

    monkeypatch.setattr(nachuan, "run", fake_run)

    data_dir = tmp_path / "isolated-data"
    assert (
        launcher.main(
            ["--data-dir", str(data_dir)],
            out=io.StringIO(),
            err=io.StringIO(),
        )
        == 37
    )
    assert observed == {
        "argv": ["start"],
        "autodownload": "0",
        "embedding": "1",
        "data_dir": str(data_dir.resolve()),
        "search_result": 0,
    }
    assert os.environ["LOCAL_MODEL_AUTODOWNLOAD"] == "1"
    assert os.environ["NACHUAN_EMBED_DISABLED"] == "0"
    assert websearch.maybe_augment_request is forbidden_search
    assert (data_dir / ".nachuan-zero-network-e2e").is_file()


def test_launcher_forwards_port_and_no_open_with_test_only_banner(
    monkeypatch, tmp_path
) -> None:
    from cli import nachuan
    from scripts import start_zero_network_web_e2e as launcher

    observed: dict[str, object] = {}

    def fake_run(argv, *, out, err) -> int:  # noqa: ANN001
        del err
        observed["argv"] = list(argv)
        observed["banner_before_start"] = out.getvalue()
        return 0

    monkeypatch.setattr(nachuan, "run", fake_run)
    output = io.StringIO()

    assert (
        launcher.main(
            [
                "--data-dir",
                str(tmp_path / "isolated-data"),
                "--port",
                "18080",
                "--no-open",
            ],
            out=output,
            err=io.StringIO(),
        )
        == 0
    )
    assert observed["argv"] == ["start", "--port", "18080", "--no-open"]
    assert "TEST-ONLY ZERO-NETWORK" in str(observed["banner_before_start"])


def test_launcher_blocks_external_sockets_before_dns_but_allows_loopback(
    monkeypatch,
    tmp_path,
) -> None:
    from cli import nachuan
    from scripts import start_zero_network_web_e2e as launcher

    calls: list[tuple[str, object]] = []

    def fake_getaddrinfo(host, *args, **kwargs):  # noqa: ANN001
        del args, kwargs
        calls.append(("dns", host))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (str(host), 18181))]

    def fake_connect(_sock, address) -> None:  # noqa: ANN001
        calls.append(("connect", address))

    def fake_connect_ex(_sock, address) -> int:  # noqa: ANN001
        calls.append(("connect_ex", address))
        return 123

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(socket.socket, "connect", fake_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", fake_connect_ex)

    def fake_run(argv, *, out, err) -> int:  # noqa: ANN001
        del argv, out, err
        with pytest.raises(
            launcher.ZeroNetworkViolation,
            match="TEST-ONLY ZERO-NETWORK",
        ):
            socket.getaddrinfo("example.com", 443)
        assert ("dns", "example.com") not in calls

        socket.getaddrinfo("127.23.45.67", 18181)
        socket.getaddrinfo("::1", 18181)
        socket.getaddrinfo("localhost", 18181)
        with socket.socket() as client:
            client.connect(("127.0.0.1", 18181))
            assert client.connect_ex(("127.0.0.1", 18181)) == 123
            with pytest.raises(launcher.ZeroNetworkViolation):
                client.connect(("93.184.216.34", 443))
            with pytest.raises(launcher.ZeroNetworkViolation):
                client.connect_ex(("example.com", 443))
        return 0

    monkeypatch.setattr(nachuan, "run", fake_run)

    assert (
        launcher.main(
            ["--data-dir", str(tmp_path / "isolated-data")],
            out=io.StringIO(),
            err=io.StringIO(),
        )
        == 0
    )
    assert calls == [
        ("dns", "127.23.45.67"),
        ("dns", "::1"),
        ("dns", "localhost"),
        ("connect", ("127.0.0.1", 18181)),
        ("connect_ex", ("127.0.0.1", 18181)),
    ]
    assert socket.getaddrinfo is fake_getaddrinfo
    assert socket.socket.connect is fake_connect
    assert socket.socket.connect_ex is fake_connect_ex
