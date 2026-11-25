"""Frozen identity contract for the dedicated NachuanCore Windows service."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass


NACHUAN_CORE_SERVICE_NAME = "NachuanCore"
NACHUAN_CORE_LOGON_ACCOUNT = r"NT AUTHORITY\LocalService"
_LOCAL_SERVICE_SID = "S-1-5-19"


def _service_sid(name: str) -> str:
    if name != NACHUAN_CORE_SERVICE_NAME:
        raise ValueError("Nachuan service name is invalid")
    digest = hashlib.sha1(name.upper().encode("utf-16-le")).digest()
    parts = struct.unpack("<IIIII", digest)
    return "S-1-5-80-" + "-".join(str(value) for value in parts)


def nachuan_core_service_sid() -> str:
    return _service_sid(NACHUAN_CORE_SERVICE_NAME)


def validate_nachuan_core_service_sid(value: object) -> str:
    sid = str(value or "").upper()
    expected = nachuan_core_service_sid().upper()
    if sid != expected:
        raise ValueError("NachuanCore service SID is invalid")
    return sid


def validate_nachuan_core_runtime_token(
    *,
    token_user_sid: object,
    service_sid_member: object,
    administrator_member: object,
    session_id: object,
) -> str:
    """Validate the LocalService token shape used by the dedicated service.

    A Windows service SID is an enabled token group when the service logs on as
    LocalService; it is not the token user.  Keeping this distinction explicit
    prevents both generic LocalService processes and interactive principals from
    being accepted as NachuanCore.
    """

    if (
        str(token_user_sid or "").upper() != _LOCAL_SERVICE_SID
        or type(service_sid_member) is not bool
        or service_sid_member is not True
        or type(administrator_member) is not bool
        or administrator_member is not False
        or isinstance(session_id, bool)
        or not isinstance(session_id, int)
        or session_id != 0
    ):
        raise ValueError("NachuanCore runtime token is invalid")
    return nachuan_core_service_sid()


@dataclass(frozen=True, slots=True)
class NachuanCoreServiceIdentity:
    service_name: str
    logon_account: str
    service_sid: str

    def __post_init__(self) -> None:
        if (
            self.service_name != NACHUAN_CORE_SERVICE_NAME
            or self.logon_account != NACHUAN_CORE_LOGON_ACCOUNT
            or validate_nachuan_core_service_sid(self.service_sid)
            != self.service_sid.upper()
        ):
            raise ValueError("NachuanCore service identity is invalid")

    @classmethod
    def default(cls) -> "NachuanCoreServiceIdentity":
        return cls(
            service_name=NACHUAN_CORE_SERVICE_NAME,
            logon_account=NACHUAN_CORE_LOGON_ACCOUNT,
            service_sid=nachuan_core_service_sid(),
        )


__all__ = [
    "NACHUAN_CORE_SERVICE_NAME",
    "NACHUAN_CORE_LOGON_ACCOUNT",
    "NachuanCoreServiceIdentity",
    "nachuan_core_service_sid",
    "validate_nachuan_core_runtime_token",
    "validate_nachuan_core_service_sid",
]
