from __future__ import annotations

import io
from pathlib import Path

import pytest

from cli.local_web_start import (
    LocalOwnerCredentialError,
    LocalOwnerCredentials,
    LocalPaidMediaCapability,
    LocalPaidMediaCapabilityError,
    load_or_create_local_owner_credentials,
    load_or_create_local_paid_media_capability,
    serve_local_web,
    _open_when_ready,
)


_SCHEMA = "nachuan.local-owner-credentials/v1"
_PAID_SCHEMA = "nachuan.local-paid-media-capability/v1"


def _document(runtime_key: str, approval_key: str) -> dict[str, str]:
    return {
        "schema": _SCHEMA,
        "runtime_key": runtime_key,
        "approval_key": approval_key,
    }


def _paid_document(key: str) -> dict[str, str]:
    return {"schema": _PAID_SCHEMA, "key": key}


def test_first_start_atomically_creates_two_independent_protected_credentials(
    tmp_path: Path,
) -> None:
    stored: dict[str, str] | None = None
    writes: list[tuple[Path, dict[str, str], str]] = []
    tokens = iter(("A" * 43, "B" * 43))

    def read_document(path: Path, *, purpose: str) -> dict[str, str]:
        assert path == tmp_path / "local-owner-credentials.json"
        assert purpose == _SCHEMA
        if stored is None:
            raise FileNotFoundError(path)
        return dict(stored)

    def create_document(
        path: Path,
        payload: dict[str, str],
        *,
        purpose: str,
    ) -> bool:
        nonlocal stored
        writes.append((path, dict(payload), purpose))
        stored = dict(payload)
        return True

    credentials = load_or_create_local_owner_credentials(
        tmp_path,
        read_document=read_document,
        create_document=create_document,
        token_factory=lambda: next(tokens),
    )

    assert credentials == LocalOwnerCredentials(
        runtime_key=f"nc-runtime-v1-{'A' * 43}",
        approval_key=f"nc-approval-v1-{'B' * 43}",
        created=True,
    )
    assert writes == [
        (
            tmp_path / "local-owner-credentials.json",
            _document(credentials.runtime_key, credentials.approval_key),
            _SCHEMA,
        )
    ]
    assert credentials.runtime_key != credentials.approval_key


def test_existing_protected_credentials_are_reused_without_rotation(
    tmp_path: Path,
) -> None:
    expected = _document(
        f"nc-runtime-v1-{'R' * 43}",
        f"nc-approval-v1-{'P' * 43}",
    )

    credentials = load_or_create_local_owner_credentials(
        tmp_path,
        read_document=lambda _path, *, purpose: dict(expected),
        create_document=lambda *_args, **_kwargs: pytest.fail(
            "an existing credential document must not be replaced"
        ),
        token_factory=lambda: pytest.fail("existing credentials must not rotate"),
    )

    assert credentials.runtime_key == expected["runtime_key"]
    assert credentials.approval_key == expected["approval_key"]
    assert credentials.created is False


def test_create_race_rereads_the_authoritative_winner(tmp_path: Path) -> None:
    winner = _document(
        f"nc-runtime-v1-{'W' * 43}",
        f"nc-approval-v1-{'Q' * 43}",
    )
    reads = 0

    def read_document(_path: Path, *, purpose: str) -> dict[str, str]:
        nonlocal reads
        reads += 1
        if reads == 1:
            raise FileNotFoundError
        return dict(winner)

    credentials = load_or_create_local_owner_credentials(
        tmp_path,
        read_document=read_document,
        create_document=lambda *_args, **_kwargs: False,
        token_factory=iter(("A" * 43, "B" * 43)).__next__,
    )

    assert credentials == LocalOwnerCredentials(
        runtime_key=winner["runtime_key"],
        approval_key=winner["approval_key"],
        created=False,
    )
    assert reads == 2


@pytest.mark.parametrize(
    "document",
    [
        {},
        {
            **_document(
                f"nc-runtime-v1-{'R' * 43}",
                f"nc-approval-v1-{'P' * 43}",
            ),
            "unexpected": "field",
        },
        _document("short", f"nc-approval-v1-{'P' * 43}"),
        _document(
            f"nc-runtime-v1-{'R' * 43}",
            f"nc-runtime-v1-{'R' * 43}",
        ),
    ],
)
def test_malformed_or_ambiguous_credentials_fail_closed(
    tmp_path: Path,
    document: dict[str, str],
) -> None:
    with pytest.raises(LocalOwnerCredentialError):
        load_or_create_local_owner_credentials(
            tmp_path,
            read_document=lambda _path, *, purpose: dict(document),
            create_document=lambda *_args, **_kwargs: pytest.fail(
                "invalid existing state must not be overwritten"
            ),
        )


def test_paid_media_capability_is_created_once_and_reused_across_restarts(
    tmp_path: Path,
) -> None:
    stored: dict[str, str] | None = None
    writes: list[tuple[Path, dict[str, str], str]] = []
    generation_calls = 0

    def read_document(path: Path, *, purpose: str) -> dict[str, str]:
        assert path == tmp_path / "local-paid-media-capability.json"
        assert purpose == _PAID_SCHEMA
        if stored is None:
            raise FileNotFoundError(path)
        return dict(stored)

    def create_document(
        path: Path,
        payload: dict[str, str],
        *,
        purpose: str,
    ) -> bool:
        nonlocal stored
        writes.append((path, dict(payload), purpose))
        stored = dict(payload)
        return True

    def token_factory() -> str:
        nonlocal generation_calls
        generation_calls += 1
        return "a" * 64

    first = load_or_create_local_paid_media_capability(
        tmp_path,
        read_document=read_document,
        create_document=create_document,
        token_factory=token_factory,
    )
    second = load_or_create_local_paid_media_capability(
        tmp_path,
        read_document=read_document,
        create_document=lambda *_args, **_kwargs: pytest.fail(
            "an existing paid capability must not be replaced"
        ),
        token_factory=lambda: pytest.fail(
            "an existing paid capability must not rotate"
        ),
    )

    assert first == LocalPaidMediaCapability(
        key=f"sk-paid-media-{'a' * 64}",
        created=True,
    )
    assert second == LocalPaidMediaCapability(key=first.key, created=False)
    assert writes == [
        (
            tmp_path / "local-paid-media-capability.json",
            _paid_document(first.key),
            _PAID_SCHEMA,
        )
    ]
    assert generation_calls == 1


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"schema": _PAID_SCHEMA, "key": "short"},
        {
            **_paid_document(f"sk-paid-media-{'b' * 64}"),
            "unexpected": "field",
        },
        _paid_document(f"sk-paid-media-{'B' * 64}"),
    ],
)
def test_malformed_paid_media_capability_fails_closed_without_overwrite(
    tmp_path: Path,
    document: dict[str, str],
) -> None:
    with pytest.raises(LocalPaidMediaCapabilityError):
        load_or_create_local_paid_media_capability(
            tmp_path,
            read_document=lambda _path, *, purpose: dict(document),
            create_document=lambda *_args, **_kwargs: pytest.fail(
                "invalid existing paid capability must not be overwritten"
            ),
        )


def test_serve_sets_engine_environment_without_putting_keys_in_a_url(
    tmp_path: Path,
) -> None:
    credentials = LocalOwnerCredentials(
        runtime_key=f"nc-runtime-v1-{'R' * 43}",
        approval_key=f"nc-approval-v1-{'P' * 43}",
        created=False,
    )
    paid_capability = LocalPaidMediaCapability(
        key=f"sk-paid-media-{'c' * 64}",
        created=False,
    )
    environment = {
        "GATEWAY_API_KEYS": "old-runtime",
        "APPROVAL_ADMIN_KEY": "old-approval",
        "NACHUAN_PAID_MEDIA_API_KEY": f"sk-paid-media-{'d' * 64}",
        "GATEWAY_HOST": "localhost",
    }
    observed: dict[str, str] = {}
    output = io.StringIO()

    def engine_main() -> None:
        observed.update(environment)

    code = serve_local_web(
        credentials,
        paid_capability,
        data_dir=tmp_path,
        port=18080,
        open_browser=False,
        out=output,
        environment=environment,
        engine_main=engine_main,
    )

    assert code == 0
    assert observed["GATEWAY_API_KEYS"] == credentials.runtime_key
    assert observed["APPROVAL_ADMIN_KEY"] == credentials.approval_key
    assert observed["NACHUAN_PAID_MEDIA_API_KEY"] == paid_capability.key
    assert observed["GATEWAY_HOST"] == "127.77.77.77"
    assert observed["GATEWAY_PORT"] == "18080"
    assert observed["NACHUAN_LOCAL_WEB_BOOTSTRAP_TOKEN"].startswith(
        "nc-web-bootstrap-v1-"
    )
    assert environment == {
        "GATEWAY_API_KEYS": "old-runtime",
        "APPROVAL_ADMIN_KEY": "old-approval",
        "NACHUAN_PAID_MEDIA_API_KEY": f"sk-paid-media-{'d' * 64}",
        "GATEWAY_HOST": "localhost",
    }
    rendered = output.getvalue()
    assert credentials.runtime_key not in rendered
    assert credentials.approval_key not in rendered
    assert paid_capability.key not in rendered
    assert "NACHUAN_PAID_MEDIA_API_KEY" not in rendered
    assert "http://127.77.77.77:18080/" in rendered
    assert "?" not in rendered
    assert "#" not in rendered
    assert "浏览器会自动安全登录" in rendered


def test_ready_opener_keeps_long_lived_keys_out_of_the_url_and_uses_one_time_fragment() -> None:
    requested: list[str] = []
    opened: list[str] = []

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def get(self, url: str):
            requested.append(url)
            return type("Response", (), {"status_code": 200})()

    token = f"nc-web-bootstrap-v1-{'B' * 43}"
    _open_when_ready(
        "http://127.77.77.77:18080",
        "http://127.77.77.77:18080",
        token,
        client_factory=lambda **_kwargs: Client(),
        browser_open=lambda url: opened.append(url),
        sleep=lambda _seconds: None,
    )

    assert requested == ["http://127.77.77.77:18080/health"]
    assert opened == [
        f"http://127.77.77.77:18080/#nachuan-bootstrap={token}"
    ]
    assert "nc-runtime-v1-" not in opened[0]
    assert "nc-approval-v1-" not in opened[0]
