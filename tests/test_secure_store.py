from __future__ import annotations

import json
import os
import subprocess
import time

import pytest

from gateway.connections import ConnectionStore
from gateway import secure_store as secure_store_module
from gateway.secure_store import (
    SecureStorageError,
    _current_user_sid,
    _read_windows_security_state,
    _trusted_system_executable,
    assert_restricted_windows_acl,
    harden_restricted_windows_acl,
    read_protected_json,
    trusted_windows_system_executable,
    write_protected_json,
)


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI contract")


def _open_security_writable_descriptor(path):
    import ctypes
    from ctypes import wintypes
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    access = 0x80000000 | 0x40000000 | 0x00020000 | 0x00040000 | 0x00080000
    handle = kernel32.CreateFileW(
        str(path), access, 0, None, 3, 0x80 | 0x00200000, None
    )
    invalid = ctypes.c_void_p(-1).value
    if handle in (None, invalid):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return msvcrt.open_osfhandle(
            int(handle), os.O_RDWR | int(getattr(os, "O_BINARY", 0))
        )
    except BaseException:
        kernel32.CloseHandle(handle)
        raise


def test_handle_acl_api_sets_and_verifies_without_reopening_the_path(
    tmp_path, monkeypatch
):
    path = tmp_path / "exclusive-owner.bin"
    path.write_bytes(b"owner")
    descriptor = _open_security_writable_descriptor(path)
    try:
        def reject_path_api(*_args, **_kwargs):
            raise AssertionError("exclusive-handle ACL must not reopen the path")

        monkeypatch.setattr(
            secure_store_module, "_read_windows_security_state", reject_path_api
        )
        monkeypatch.setattr(secure_store_module, "_set_exact_acl", reject_path_api)
        secure_store_module.harden_restricted_windows_handle_acl(
            descriptor, directory=False
        )
        secure_store_module.assert_restricted_windows_handle_acl(
            descriptor, directory=False
        )
    finally:
        os.close(descriptor)

    monkeypatch.undo()
    assert_restricted_windows_acl(path)


def test_protected_json_is_dpapi_encrypted_and_acl_restricted(tmp_path):
    path = tmp_path / "runtime-secret.json"
    payload = {"credential": "synthetic-test-value"}

    write_protected_json(path, payload, purpose="test/runtime")

    raw = path.read_text("utf-8")
    envelope = json.loads(raw)
    assert envelope["protection"] == "windows-dpapi-current-user"
    assert "synthetic-test-value" not in raw
    assert read_protected_json(path, purpose="test/runtime") == payload
    assert_restricted_windows_acl(path)


def test_protected_json_create_if_absent_never_replaces_existing_document(tmp_path):
    path = tmp_path / "first-writer-wins.json"
    write_protected_json(path, {"owner": "first"}, purpose="test/create-once")

    created = secure_store_module.write_protected_json_if_absent(
        path,
        {"owner": "second"},
        purpose="test/create-once",
    )

    assert created is False
    assert read_protected_json(path, purpose="test/create-once") == {"owner": "first"}


def test_transient_runtime_directory_can_be_restricted_before_plaintext_write(
    tmp_path,
):
    directory = tmp_path / "transient-runtime"
    directory.mkdir()

    harden_restricted_windows_acl(directory, directory=True)

    assert_restricted_windows_acl(directory)
    prompt = directory / "prompt.txt"
    prompt.write_text("synthetic transient value", encoding="utf-8")
    broadened = subprocess.run(
        [
            str(_trusted_system_executable("icacls.exe")),
            str(prompt),
            "/grant",
            "*S-1-5-32-545:(R)",
        ],
        capture_output=True,
        check=False,
    )
    assert broadened.returncode == 0
    # The public helper also repairs a child file if a future caller needs an
    # independently protected DACL rather than inherited directory protection.
    harden_restricted_windows_acl(prompt, directory=False)
    assert_restricted_windows_acl(prompt)


def test_plaintext_is_migrated_in_place_without_leaving_value_on_disk(tmp_path):
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps({"token": "legacy-synthetic-value"}), encoding="utf-8")

    loaded = read_protected_json(path, purpose="test/migration", migrate_plaintext=True)

    assert loaded == {"token": "legacy-synthetic-value"}
    assert "legacy-synthetic-value" not in path.read_text("utf-8")
    assert read_protected_json(path, purpose="test/migration") == loaded


def test_plaintext_migrator_can_revoke_previously_exposed_credentials(tmp_path):
    path = tmp_path / "legacy-revoked.json"
    path.write_text(json.dumps({"token": "legacy-exposed-value"}), encoding="utf-8")

    loaded = read_protected_json(
        path,
        purpose="test/revoke-migration",
        migrate_plaintext=True,
        plaintext_migrator=lambda _legacy: {},
    )

    assert loaded == {}
    assert "legacy-exposed-value" not in path.read_text("utf-8")
    assert read_protected_json(path, purpose="test/revoke-migration") == {}


def test_ciphertext_is_bound_to_its_purpose(tmp_path):
    path = tmp_path / "bound.json"
    write_protected_json(path, {"token": "synthetic"}, purpose="test/one")

    with pytest.raises(SecureStorageError):
        read_protected_json(path, purpose="test/two")


def test_connection_store_transparently_migrates_legacy_plaintext(tmp_path):
    path = tmp_path / "connections.json"
    path.write_text(
        json.dumps({"demo": {"api_key": "synthetic-provider-value"}}),
        encoding="utf-8",
    )

    store = ConnectionStore(path)

    assert store.get("demo") == {"api_key": "synthetic-provider-value"}
    assert "synthetic-provider-value" not in path.read_text("utf-8")
    store.set("other", {"api_key": "synthetic-second-value"})
    raw = path.read_text("utf-8")
    assert "synthetic-provider-value" not in raw
    assert "synthetic-second-value" not in raw


def test_acl_assertion_rejects_an_extra_explicit_trustee(tmp_path):
    path = tmp_path / "acl.json"
    write_protected_json(path, {"value": "synthetic"}, purpose="test/acl")
    added = subprocess.run(
        [
            str(_trusted_system_executable("icacls.exe")),
            str(path),
            "/grant",
            "*S-1-5-32-545:(R)",
        ],
        capture_output=True,
        check=False,
    )
    assert added.returncode == 0

    with pytest.raises(SecureStorageError, match="额外主体"):
        assert_restricted_windows_acl(path)


def test_preowned_permissive_nachuan_boundary_is_reowned_and_closed(tmp_path):
    boundary = tmp_path / "Nachuan"
    state_root = boundary / "StateRoot"
    state_root.mkdir(parents=True)
    harden_restricted_windows_acl(boundary, directory=True)

    # Model a ProgramData pre-creation/squatting attempt without ever touching
    # ProgramData itself: the DACL is broadened and ownership is transferred to
    # the well-known local Users group.
    broadened = subprocess.run(
        [
            str(_trusted_system_executable("icacls.exe")),
            str(boundary),
            "/grant",
            "*S-1-5-32-545:(F)",
        ],
        capture_output=True,
        check=False,
    )
    assert broadened.returncode == 0, broadened.stderr
    reowned = subprocess.run(
        [
            str(_trusted_system_executable("icacls.exe")),
            str(boundary),
            "/setowner",
            "*S-1-5-32-545",
            "/q",
        ],
        capture_output=True,
        check=False,
    )
    assert reowned.returncode == 0, reowned.stderr
    assert _read_windows_security_state(boundary)[0] == "S-1-5-32-545"

    with pytest.raises(SecureStorageError, match="owner"):
        assert_restricted_windows_acl(boundary)

    harden_restricted_windows_acl(boundary, directory=True)
    assert _read_windows_security_state(boundary)[0] == _current_user_sid()
    assert_restricted_windows_acl(boundary)
    # The explicit child boundary is independently protected; hardening never
    # walks upward into the shared temp root (or C:\\ / ProgramData in product).
    harden_restricted_windows_acl(state_root, directory=True)
    assert_restricted_windows_acl(state_root)


def test_acl_assertion_is_native_and_has_a_wide_non_regression_budget(
    tmp_path, monkeypatch
):
    directory = tmp_path / "Nachuan" / "StateRoot"
    directory.mkdir(parents=True)
    harden_restricted_windows_acl(directory, directory=True)

    def reject_subprocess(*_args, **_kwargs):
        raise AssertionError("ACL verification must not spawn whoami/icacls")

    monkeypatch.setattr(subprocess, "run", reject_subprocess)
    started = time.perf_counter()
    for _index in range(25):
        assert_restricted_windows_acl(directory)
    elapsed = time.perf_counter() - started
    # The old shell implementation needed about 1 second for only 20 checks on
    # the reference host.  This deliberately loose budget catches that design
    # without turning normal CI scheduling noise into a flaky test.
    assert elapsed < 1.5


@pytest.mark.parametrize(
    ("directory", "permission", "message"),
    [
        (False, "(R)", "完全控制"),
        (True, "(F)", "继承标志"),
    ],
)
def test_acl_assertion_rejects_non_exact_mask_or_inheritance_flags(
    tmp_path, directory, permission, message
):
    target = tmp_path / ("acl-directory" if directory else "acl-file.bin")
    if directory:
        target.mkdir()
    else:
        target.write_bytes(b"synthetic")
    harden_restricted_windows_acl(target, directory=directory)
    icacls = str(_trusted_system_executable("icacls.exe"))
    principal = f"*{_current_user_sid()}"
    if directory:
        removed = subprocess.run(
            [icacls, str(target), "/remove:g", principal, "/q"],
            capture_output=True,
            check=False,
        )
        assert removed.returncode == 0, removed.stderr
        changed = subprocess.run(
            [icacls, str(target), "/grant", f"{principal}:{permission}", "/q"],
            capture_output=True,
            check=False,
        )
    else:
        changed = subprocess.run(
            [icacls, str(target), "/grant:r", f"{principal}:{permission}", "/q"],
            capture_output=True,
            check=False,
        )
    assert changed.returncode == 0, changed.stderr

    with pytest.raises(SecureStorageError, match=message):
        assert_restricted_windows_acl(target)

    if not directory:
        restored = subprocess.run(
            [icacls, str(target), "/grant:r", f"{principal}:(F)", "/q"],
            capture_output=True,
            check=False,
        )
        assert restored.returncode == 0, restored.stderr
    harden_restricted_windows_acl(target, directory=directory)
    assert_restricted_windows_acl(target)


def test_each_secret_read_repairs_acl_even_inside_recheck_cache_window(tmp_path):
    path = tmp_path / "acl-read.json"
    payload = {"value": "synthetic"}
    write_protected_json(path, payload, purpose="test/acl-read")
    added = subprocess.run(
        [
            str(_trusted_system_executable("icacls.exe")),
            str(path),
            "/grant",
            "*S-1-5-32-545:(R)",
        ],
        capture_output=True,
        check=False,
    )
    assert added.returncode == 0

    assert read_protected_json(path, purpose="test/acl-read") == payload
    assert_restricted_windows_acl(path)


def test_windows_helpers_are_resolved_outside_path_lookup():
    system_directory = _trusted_system_executable("whoami.exe").parent
    for name in ("whoami.exe", "icacls.exe", "taskkill.exe"):
        executable = trusted_windows_system_executable(name)
        assert executable.is_absolute()
        assert executable.parent == system_directory
        assert executable.is_file()


def test_windows_helper_rejects_paths_and_non_executables():
    for name in ("..\\whoami.exe", "whoami", ""):
        with pytest.raises(SecureStorageError):
            _trusted_system_executable(name)


def test_oversized_secret_document_is_rejected_before_parsing(tmp_path):
    path = tmp_path / "oversized.json"
    path.write_bytes(b"x" * (4 * 1024 * 1024 + 1))

    with pytest.raises(SecureStorageError, match="大小上限"):
        read_protected_json(path, purpose="test/oversized", migrate_plaintext=True)
