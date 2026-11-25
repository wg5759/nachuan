from __future__ import annotations

import os
import subprocess

import pytest

from gateway.installed_nachuan_core_identity import (
    NACHUAN_CORE_SERVICE_NAME,
    NACHUAN_CORE_LOGON_ACCOUNT,
    NachuanCoreServiceIdentity,
    nachuan_core_service_sid,
    validate_nachuan_core_runtime_token,
    validate_nachuan_core_service_sid,
)
from gateway.secure_store import trusted_windows_system_executable


@pytest.mark.skipif(os.name != "nt", reason="Windows service SID")
def test_nachuan_core_identity_matches_windows_and_rejects_generic_users() -> None:
    sid = nachuan_core_service_sid()
    identity = NachuanCoreServiceIdentity.default()
    sc = trusted_windows_system_executable("sc.exe")
    result = subprocess.run(
        [str(sc), "showsid", NACHUAN_CORE_SERVICE_NAME],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )

    assert result.returncode == 0
    assert sid in result.stdout
    assert identity.service_name == NACHUAN_CORE_SERVICE_NAME
    assert identity.logon_account == NACHUAN_CORE_LOGON_ACCOUNT
    assert identity.service_sid == sid
    assert validate_nachuan_core_service_sid(sid) == sid
    for forbidden in (
        "S-1-1-0",
        "S-1-5-11",
        "S-1-5-19",
        "S-1-5-32-545",
        "S-1-5-80-0",
    ):
        with pytest.raises(ValueError):
            validate_nachuan_core_service_sid(forbidden)


def test_nachuan_core_runtime_requires_localservice_plus_exact_service_group() -> None:
    service_sid = nachuan_core_service_sid()
    assert validate_nachuan_core_runtime_token(
        token_user_sid="S-1-5-19",
        service_sid_member=True,
        administrator_member=False,
        session_id=0,
    ) == service_sid

    rejected = (
        {
            "token_user_sid": service_sid,
            "service_sid_member": True,
            "administrator_member": False,
            "session_id": 0,
        },
        {
            "token_user_sid": "S-1-5-19",
            "service_sid_member": False,
            "administrator_member": False,
            "session_id": 0,
        },
        {
            "token_user_sid": "S-1-5-19",
            "service_sid_member": True,
            "administrator_member": True,
            "session_id": 0,
        },
        {
            "token_user_sid": "S-1-5-19",
            "service_sid_member": True,
            "administrator_member": False,
            "session_id": 1,
        },
    )
    for claims in rejected:
        with pytest.raises(ValueError, match="runtime token"):
            validate_nachuan_core_runtime_token(**claims)
