"""Authoritative Installation Epoch Root for paid and updater state.

The root is intentionally independent from normal user data.  Runtime code may
only open an already provisioned database with SQLite ``mode=rw``; creation is
reserved for the explicit :meth:`InstallationRoot.provision` installer path.

This module is deliberately transport agnostic.  It does not expose HTTP, start
services, or know about the Desktop/Gateway ledgers.  Callers must present the
identity, monotonic floor and state digest of those ledgers at every boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
from typing import Callable, Literal


_APPLICATION_ID = 0x4E434952  # "NCIR"
_SCHEMA_VERSION = 5
_MAX_COUNTER = (1 << 63) - 1
_MAX_AUTHORITY_FILE_BYTES = 16 * 1024 * 1024
_MAX_REANCHOR_RECEIPTS = 65_536
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_COMPONENTS = ("desktop", "gateway", "gateway_assets", "channel_media")
_ZERO_DIGEST = "0" * 64

ComponentName = Literal["desktop", "gateway", "gateway_assets", "channel_media"]
RootStatus = Literal["provisioning", "active", "maintenance_locked", "retired"]


_ROOT_DDL = """
CREATE TABLE installation_root (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 5),
    installation_id TEXT NOT NULL CHECK (length(installation_id) = 64),
    owner_sid_digest TEXT NOT NULL CHECK (length(owner_sid_digest) = 64),
    epoch INTEGER NOT NULL CHECK (epoch >= 1),
    root_revision INTEGER NOT NULL CHECK (root_revision >= 1),
    status TEXT NOT NULL CHECK (
        status IN ('provisioning','active','maintenance_locked','retired')
    ),
    lock_kind TEXT NOT NULL CHECK (
        lock_kind IN (
            'none','operator','integrity','component_addition','reanchor','retired'
        )
    ),
    lock_reason_digest TEXT CHECK (
        lock_reason_digest IS NULL OR length(lock_reason_digest) = 64
    ),
    reanchor_pending INTEGER NOT NULL CHECK (reanchor_pending IN (0,1)),
    reanchor_operation_digest TEXT CHECK (
        reanchor_operation_digest IS NULL OR length(reanchor_operation_digest) = 64
    ),
    reanchor_snapshot_digest TEXT CHECK (
        reanchor_snapshot_digest IS NULL OR length(reanchor_snapshot_digest) = 64
    ),
    reanchor_source_epoch INTEGER CHECK (
        reanchor_source_epoch IS NULL OR reanchor_source_epoch >= 1
    ),
    CHECK (
        (status = 'provisioning' AND lock_kind = 'none'
            AND lock_reason_digest IS NULL AND reanchor_pending = 0
            AND reanchor_operation_digest IS NULL
            AND reanchor_snapshot_digest IS NULL
            AND reanchor_source_epoch IS NULL)
        OR (status = 'active' AND lock_kind = 'none'
            AND lock_reason_digest IS NULL AND reanchor_pending = 0
            AND (
                (reanchor_operation_digest IS NULL
                    AND reanchor_snapshot_digest IS NULL
                    AND reanchor_source_epoch IS NULL)
                OR (reanchor_operation_digest IS NOT NULL
                    AND reanchor_snapshot_digest IS NOT NULL
                    AND reanchor_source_epoch IS NOT NULL
                    AND epoch = reanchor_source_epoch + 1)
            ))
        OR (status = 'maintenance_locked'
            AND lock_kind IN ('operator','integrity','component_addition')
            AND reanchor_pending = 0
            AND reanchor_operation_digest IS NULL
            AND reanchor_snapshot_digest IS NULL
            AND reanchor_source_epoch IS NULL)
        OR (status = 'maintenance_locked' AND lock_kind = 'reanchor'
            AND lock_reason_digest IS NOT NULL AND reanchor_pending = 1
            AND reanchor_operation_digest IS NOT NULL
            AND reanchor_snapshot_digest IS NOT NULL
            AND reanchor_source_epoch IS NOT NULL
            AND epoch = reanchor_source_epoch + 1)
        OR (status = 'retired' AND lock_kind = 'retired'
            AND lock_reason_digest IS NOT NULL AND reanchor_pending = 0
            AND reanchor_operation_digest IS NULL
            AND reanchor_snapshot_digest IS NULL
            AND reanchor_source_epoch IS NULL)
    )
)
"""

_COMPONENT_DDL = """
CREATE TABLE installation_components (
    component TEXT PRIMARY KEY CHECK (
        component IN ('desktop','gateway','gateway_assets','channel_media')
    ),
    identity TEXT NOT NULL CHECK (length(identity) = 64),
    epoch INTEGER NOT NULL CHECK (epoch >= 1),
    bound INTEGER NOT NULL CHECK (bound IN (0,1)),
    sequence_floor INTEGER NOT NULL CHECK (sequence_floor >= 0),
    state_digest TEXT CHECK (state_digest IS NULL OR length(state_digest) = 64),
    recovery_floor INTEGER CHECK (recovery_floor IS NULL OR recovery_floor >= 0),
    recovery_state_digest TEXT CHECK (
        recovery_state_digest IS NULL OR length(recovery_state_digest) = 64
    ),
    CHECK (
        (bound = 0 AND sequence_floor = 0 AND state_digest IS NULL
            AND recovery_floor IS NULL AND recovery_state_digest IS NULL)
        OR (bound = 1 AND state_digest IS NOT NULL AND (
            (recovery_floor IS NULL AND recovery_state_digest IS NULL)
            OR (recovery_floor = sequence_floor
                AND recovery_state_digest = state_digest)
        ))
    )
)
"""

# Closed historical schema accepted only by the explicit installer migration.
# Runtime ``open`` never consults these definitions and therefore cannot mutate
# or silently upgrade a legacy authority root.
_V4_ROOT_DDL = """
CREATE TABLE installation_root (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 4),
    installation_id TEXT NOT NULL CHECK (length(installation_id) = 64),
    owner_sid_digest TEXT NOT NULL CHECK (length(owner_sid_digest) = 64),
    epoch INTEGER NOT NULL CHECK (epoch >= 1),
    root_revision INTEGER NOT NULL CHECK (root_revision >= 1),
    status TEXT NOT NULL CHECK (
        status IN ('provisioning','active','maintenance_locked','retired')
    ),
    lock_kind TEXT NOT NULL CHECK (
        lock_kind IN ('none','operator','integrity','reanchor','retired')
    ),
    lock_reason_digest TEXT CHECK (
        lock_reason_digest IS NULL OR length(lock_reason_digest) = 64
    ),
    reanchor_pending INTEGER NOT NULL CHECK (reanchor_pending IN (0,1)),
    reanchor_operation_digest TEXT CHECK (
        reanchor_operation_digest IS NULL OR length(reanchor_operation_digest) = 64
    ),
    reanchor_snapshot_digest TEXT CHECK (
        reanchor_snapshot_digest IS NULL OR length(reanchor_snapshot_digest) = 64
    ),
    reanchor_source_epoch INTEGER CHECK (
        reanchor_source_epoch IS NULL OR reanchor_source_epoch >= 1
    ),
    CHECK (
        (status = 'provisioning' AND lock_kind = 'none'
            AND lock_reason_digest IS NULL AND reanchor_pending = 0
            AND reanchor_operation_digest IS NULL
            AND reanchor_snapshot_digest IS NULL
            AND reanchor_source_epoch IS NULL)
        OR (status = 'active' AND lock_kind = 'none'
            AND lock_reason_digest IS NULL AND reanchor_pending = 0
            AND (
                (reanchor_operation_digest IS NULL
                    AND reanchor_snapshot_digest IS NULL
                    AND reanchor_source_epoch IS NULL)
                OR (reanchor_operation_digest IS NOT NULL
                    AND reanchor_snapshot_digest IS NOT NULL
                    AND reanchor_source_epoch IS NOT NULL
                    AND epoch = reanchor_source_epoch + 1)
            ))
        OR (status = 'maintenance_locked' AND lock_kind IN ('operator','integrity')
            AND reanchor_pending = 0
            AND reanchor_operation_digest IS NULL
            AND reanchor_snapshot_digest IS NULL
            AND reanchor_source_epoch IS NULL)
        OR (status = 'maintenance_locked' AND lock_kind = 'reanchor'
            AND lock_reason_digest IS NOT NULL AND reanchor_pending = 1
            AND reanchor_operation_digest IS NOT NULL
            AND reanchor_snapshot_digest IS NOT NULL
            AND reanchor_source_epoch IS NOT NULL
            AND epoch = reanchor_source_epoch + 1)
        OR (status = 'retired' AND lock_kind = 'retired'
            AND lock_reason_digest IS NOT NULL AND reanchor_pending = 0
            AND reanchor_operation_digest IS NULL
            AND reanchor_snapshot_digest IS NULL
            AND reanchor_source_epoch IS NULL)
    )
)
"""

_V4_COMPONENT_DDL = """
CREATE TABLE installation_components (
    component TEXT PRIMARY KEY CHECK (
        component IN ('desktop','gateway','gateway_assets')
    ),
    identity TEXT NOT NULL CHECK (length(identity) = 64),
    epoch INTEGER NOT NULL CHECK (epoch >= 1),
    bound INTEGER NOT NULL CHECK (bound IN (0,1)),
    sequence_floor INTEGER NOT NULL CHECK (sequence_floor >= 0),
    state_digest TEXT CHECK (state_digest IS NULL OR length(state_digest) = 64),
    recovery_floor INTEGER CHECK (recovery_floor IS NULL OR recovery_floor >= 0),
    recovery_state_digest TEXT CHECK (
        recovery_state_digest IS NULL OR length(recovery_state_digest) = 64
    ),
    CHECK (
        (bound = 0 AND sequence_floor = 0 AND state_digest IS NULL
            AND recovery_floor IS NULL AND recovery_state_digest IS NULL)
        OR (bound = 1 AND state_digest IS NOT NULL AND (
            (recovery_floor IS NULL AND recovery_state_digest IS NULL)
            OR (recovery_floor = sequence_floor
                AND recovery_state_digest = state_digest)
        ))
    )
)
"""

_UPDATER_DDL = """
CREATE TABLE installation_updater (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    release_sequence INTEGER NOT NULL CHECK (release_sequence >= 0),
    keyring_sequence INTEGER NOT NULL CHECK (keyring_sequence >= 0),
    artifact_digest TEXT NOT NULL CHECK (length(artifact_digest) = 64),
    state_digest TEXT NOT NULL CHECK (length(state_digest) = 64)
)
"""

_REANCHOR_RECEIPT_DDL = """
CREATE TABLE installation_reanchor_receipts (
    target_epoch INTEGER PRIMARY KEY CHECK (target_epoch >= 2),
    source_epoch INTEGER NOT NULL UNIQUE CHECK (source_epoch >= 1),
    operation_digest TEXT NOT NULL UNIQUE CHECK (length(operation_digest) = 64),
    snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
    final_proof_digest TEXT NOT NULL CHECK (length(final_proof_digest) = 64),
    completed_root_revision INTEGER NOT NULL UNIQUE CHECK (
        completed_root_revision >= 1
    ),
    CHECK (target_epoch = source_epoch + 1)
) WITHOUT ROWID
"""

_REANCHOR_RECEIPT_NO_UPDATE_DDL = """
CREATE TRIGGER installation_reanchor_receipts_no_update
BEFORE UPDATE ON installation_reanchor_receipts
BEGIN
    SELECT RAISE(ABORT, 'installation reanchor receipts are append-only');
END
"""

_REANCHOR_RECEIPT_NO_DELETE_DDL = """
CREATE TRIGGER installation_reanchor_receipts_no_delete
BEFORE DELETE ON installation_reanchor_receipts
BEGIN
    SELECT RAISE(ABORT, 'installation reanchor receipts are append-only');
END
"""

_REANCHOR_RECEIPT_NO_REPLACE_DDL = """
CREATE TRIGGER installation_reanchor_receipts_no_replace
BEFORE INSERT ON installation_reanchor_receipts
WHEN EXISTS (
    SELECT 1 FROM installation_reanchor_receipts
    WHERE target_epoch = NEW.target_epoch
        OR source_epoch = NEW.source_epoch
        OR operation_digest = NEW.operation_digest
        OR completed_root_revision = NEW.completed_root_revision
)
BEGIN
    SELECT RAISE(ABORT, 'installation reanchor receipts are append-only');
END
"""

_SCHEMA_MIGRATION_DDL = """
CREATE TABLE installation_schema_migrations (
    target_version INTEGER PRIMARY KEY CHECK (target_version = 5),
    source_version INTEGER NOT NULL UNIQUE CHECK (source_version = 4),
    installation_id TEXT NOT NULL CHECK (length(installation_id) = 64),
    operation_digest TEXT NOT NULL UNIQUE CHECK (length(operation_digest) = 64),
    snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
    completed_root_revision INTEGER NOT NULL UNIQUE CHECK (
        completed_root_revision >= 2
    ),
    CHECK (target_version = source_version + 1)
) WITHOUT ROWID
"""

_SCHEMA_MIGRATION_NO_UPDATE_DDL = """
CREATE TRIGGER installation_schema_migrations_no_update
BEFORE UPDATE ON installation_schema_migrations
BEGIN
    SELECT RAISE(ABORT, 'installation schema migrations are append-only');
END
"""

_SCHEMA_MIGRATION_NO_DELETE_DDL = """
CREATE TRIGGER installation_schema_migrations_no_delete
BEFORE DELETE ON installation_schema_migrations
BEGIN
    SELECT RAISE(ABORT, 'installation schema migrations are append-only');
END
"""

_SCHEMA_MIGRATION_NO_REPLACE_DDL = """
CREATE TRIGGER installation_schema_migrations_no_replace
BEFORE INSERT ON installation_schema_migrations
WHEN EXISTS (
    SELECT 1 FROM installation_schema_migrations
    WHERE target_version = NEW.target_version
        OR source_version = NEW.source_version
        OR operation_digest = NEW.operation_digest
        OR completed_root_revision = NEW.completed_root_revision
)
BEGIN
    SELECT RAISE(ABORT, 'installation schema migrations are append-only');
END
"""

_EXPECTED_OBJECTS = {
    ("table", "installation_root"): _ROOT_DDL,
    ("table", "installation_components"): _COMPONENT_DDL,
    ("table", "installation_updater"): _UPDATER_DDL,
    ("table", "installation_reanchor_receipts"): _REANCHOR_RECEIPT_DDL,
    (
        "trigger",
        "installation_reanchor_receipts_no_update",
    ): _REANCHOR_RECEIPT_NO_UPDATE_DDL,
    (
        "trigger",
        "installation_reanchor_receipts_no_delete",
    ): _REANCHOR_RECEIPT_NO_DELETE_DDL,
    (
        "trigger",
        "installation_reanchor_receipts_no_replace",
    ): _REANCHOR_RECEIPT_NO_REPLACE_DDL,
    ("table", "installation_schema_migrations"): _SCHEMA_MIGRATION_DDL,
    (
        "trigger",
        "installation_schema_migrations_no_update",
    ): _SCHEMA_MIGRATION_NO_UPDATE_DDL,
    (
        "trigger",
        "installation_schema_migrations_no_delete",
    ): _SCHEMA_MIGRATION_NO_DELETE_DDL,
    (
        "trigger",
        "installation_schema_migrations_no_replace",
    ): _SCHEMA_MIGRATION_NO_REPLACE_DDL,
}

_V4_EXPECTED_OBJECTS = {
    ("table", "installation_root"): _V4_ROOT_DDL,
    ("table", "installation_components"): _V4_COMPONENT_DDL,
    ("table", "installation_updater"): _UPDATER_DDL,
    ("table", "installation_reanchor_receipts"): _REANCHOR_RECEIPT_DDL,
    (
        "trigger",
        "installation_reanchor_receipts_no_update",
    ): _REANCHOR_RECEIPT_NO_UPDATE_DDL,
    (
        "trigger",
        "installation_reanchor_receipts_no_delete",
    ): _REANCHOR_RECEIPT_NO_DELETE_DDL,
    (
        "trigger",
        "installation_reanchor_receipts_no_replace",
    ): _REANCHOR_RECEIPT_NO_REPLACE_DDL,
}


class InstallationRootError(RuntimeError):
    """Base class for the narrow public failure surface."""


class InstallationRootUnavailable(InstallationRootError):
    """The root cannot be safely read, validated, or CAS-mutated."""


class InstallationRootLocked(InstallationRootError):
    """The root is retired, maintenance locked, or detected a rollback/conflict."""


class _CommitIntegrityLock(InstallationRootLocked):
    """Internal signal: persist the prepared integrity lock, then report Locked."""


@dataclass(frozen=True)
class InstallationRootDependencies:
    """OS authority dependencies, injectable for installer and fault tests.

    Runtime ACL checks are assertions only.  ``harden_acl`` is called solely by
    explicit provisioning and never by :meth:`InstallationRoot.open` or a normal
    state mutation.
    """

    owner_sid: Callable[[], str]
    random_bytes: Callable[[int], bytes]
    assert_acl: Callable[[Path, bool], None]
    harden_acl: Callable[[Path, bool], None]
    trusted_boundary: Callable[[Path], Path]
    fault_injector: Callable[[str], None] = lambda _stage: None


@dataclass(frozen=True)
class ComponentState:
    component: ComponentName
    identity: str
    epoch: int
    bound: bool
    sequence_floor: int
    state_digest: str | None
    recovery_floor: int | None
    recovery_state_digest: str | None


@dataclass(frozen=True)
class UpdaterState:
    release_sequence: int
    keyring_sequence: int
    artifact_digest: str
    state_digest: str


@dataclass(frozen=True)
class InstallationRootSnapshot:
    installation_id: str
    owner_sid_digest: str
    epoch: int
    root_revision: int
    status: RootStatus
    lock_kind: str
    lock_reason_digest: str | None
    reanchor_pending: bool
    reanchor_operation_digest: str | None
    reanchor_snapshot_digest: str | None
    reanchor_source_epoch: int | None
    principal_digest: str
    components: tuple[ComponentState, ...]
    updater: UpdaterState

    def component(self, name: ComponentName) -> ComponentState:
        for value in self.components:
            if value.component == name:
                return value
        raise KeyError(name)


@dataclass(frozen=True)
class RootMutationResult:
    snapshot: InstallationRootSnapshot
    applied: bool
    recovered: bool = False


def _default_owner_sid() -> str:
    if os.name == "nt":
        # The public ACL assertion uses the same native SID source.  The private
        # helper is intentionally not copied here so there is one SID parser.
        from gateway.secure_store import _current_user_sid  # type: ignore[attr-defined]

        return str(_current_user_sid())
    if not hasattr(os, "geteuid"):
        raise OSError("cannot determine the installation-root owner")
    return f"uid:{os.geteuid()}"


def _default_assert_acl(path: Path, directory: bool) -> None:
    info = os.lstat(path)
    if directory != stat.S_ISDIR(info.st_mode):
        raise PermissionError("installation-root ACL target type is invalid")
    if os.name == "nt":
        from gateway.secure_store import assert_restricted_windows_acl

        assert_restricted_windows_acl(path)
        return
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise PermissionError("installation-root owner is invalid")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise PermissionError("installation-root permissions are too broad")


def _default_harden_acl(path: Path, directory: bool) -> None:
    if os.name == "nt":
        from gateway.secure_store import harden_restricted_windows_acl

        harden_restricted_windows_acl(path, directory=directory)
        return
    os.chmod(path, 0o700 if directory else 0o600)


@lru_cache(maxsize=1)
def _windows_program_data() -> Path:
    """Resolve ProgramData through the trusted Windows Known Folder API."""

    if os.name != "nt":
        raise OSError("Windows ProgramData is unavailable on this platform")
    import ctypes
    from ctypes import wintypes
    from uuid import UUID

    class GUID(ctypes.Structure):
        _fields_ = (
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        )

    value = UUID("62ab5d82-fdc1-4dc3-a9dd-070d1d495d97")
    folder_id = GUID(
        value.time_low,
        value.time_mid,
        value.time_hi_version,
        (ctypes.c_ubyte * 8)(*value.bytes[8:]),
    )
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    shell32.SHGetKnownFolderPath.argtypes = (
        ctypes.POINTER(GUID),
        wintypes.DWORD,
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_wchar_p),
    )
    shell32.SHGetKnownFolderPath.restype = ctypes.c_long
    ole32.CoTaskMemFree.argtypes = (ctypes.c_void_p,)
    ole32.CoTaskMemFree.restype = None
    raw = ctypes.c_wchar_p()
    result = int(
        shell32.SHGetKnownFolderPath(
            ctypes.byref(folder_id),
            0,
            None,
            ctypes.byref(raw),
        )
    )
    try:
        if result != 0:
            raise OSError(
                "SHGetKnownFolderPath(FOLDERID_ProgramData) failed: "
                f"0x{result & 0xFFFFFFFF:08x}"
            )
        if not raw.value:
            raise OSError("Windows ProgramData known folder is empty")
        resolved = Path(raw.value)
        if not resolved.is_absolute() or ".." in resolved.parts:
            raise OSError("Windows ProgramData known folder is invalid")
        return resolved
    finally:
        if raw:
            ole32.CoTaskMemFree(ctypes.cast(raw, ctypes.c_void_p))


def _default_trusted_boundary(_database_path: Path) -> Path:
    """Return the installer-owned boundary whose descendants may hold the root.

    The boundary itself must already exist and be ACL-hardened by the installer.
    We intentionally do not attempt to rewrite ``C:\\``, ``ProgramData`` or a
    shared temporary directory from normal root code.
    """

    if os.name == "nt":
        return _windows_program_data() / "Nachuan"
    return Path("/var/lib/nachuan")


def default_installation_root_path() -> Path:
    """Return the one production authority path without consulting the environment.

    Installers and the packaged gateway must agree on this exact location.  The
    trusted boundary resolver deliberately uses the Windows Known Folder API,
    so an inherited ``PROGRAMDATA`` value can never redirect the authority.
    This helper only resolves the path; it never creates or hardens anything.
    """

    boundary = _default_trusted_boundary(Path("installation-root.db"))
    return boundary / "StateRoot" / "installation-root.db"


DEFAULT_DEPENDENCIES = InstallationRootDependencies(
    owner_sid=_default_owner_sid,
    random_bytes=secrets.token_bytes,
    assert_acl=_default_assert_acl,
    harden_acl=_default_harden_acl,
    trusted_boundary=_default_trusted_boundary,
)


def owner_sid_digest(owner_sid: str) -> str:
    """Return the domain-separated digest stored in the authority root."""

    if (
        not isinstance(owner_sid, str)
        or not owner_sid
        or owner_sid != owner_sid.strip()
        or len(owner_sid.encode("utf-8")) > 512
    ):
        raise InstallationRootUnavailable("installation-root owner SID is invalid")
    encoded = owner_sid.encode("utf-8")
    framed = len(encoded).to_bytes(4, "big") + encoded
    return sha256(b"nachuan.installation-root.owner-sid.v1\0" + framed).hexdigest()


def installation_principal(installation_id: str, epoch: int) -> str:
    """Derive a stable, non-secret principal for one installation epoch."""

    _require_digest(installation_id, "installation id")
    _require_counter(epoch, "installation epoch", minimum=1)
    return sha256(
        b"nachuan.installation-principal.v1\0"
        + bytes.fromhex(installation_id)
        + int(epoch).to_bytes(8, "big", signed=False)
    ).hexdigest()


def _reason_digest(reason: str) -> str:
    encoded = reason.encode("utf-8", errors="strict")
    return sha256(b"nachuan.installation-root.lock-reason.v1\0" + encoded).hexdigest()


def _require_digest(value: object, label: str, *, allow_zero: bool = True) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise InstallationRootUnavailable(f"{label} is invalid")
    if not allow_zero and value == _ZERO_DIGEST:
        raise InstallationRootUnavailable(f"{label} must not be zero")
    return value


def _require_counter(value: object, label: str, *, minimum: int = 0) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > _MAX_COUNTER
    ):
        raise InstallationRootUnavailable(f"{label} is invalid")
    return int(value)


def _require_component(value: object) -> ComponentName:
    if value not in _COMPONENTS:
        raise InstallationRootUnavailable("installation-root component is invalid")
    return value  # type: ignore[return-value]


def _canonical_sql(value: object) -> str:
    """Frozen v4 migration-fingerprint canonicalization; never schema authority."""

    return re.sub(r"\s+", "", str(value or "")).lower().rstrip(";")


def _exact_sql(value: object) -> str:
    return value if isinstance(value, str) and value else ""


@lru_cache(maxsize=2)
def _expected_schema_sql(version: int) -> dict[tuple[str, str], tuple[str, str]]:
    declarations = _V4_EXPECTED_OBJECTS if version == 4 else _EXPECTED_OBJECTS
    if version not in {4, _SCHEMA_VERSION}:
        raise sqlite3.DatabaseError("installation-root schema version is unsupported")
    connection = sqlite3.connect(":memory:")
    try:
        for ddl in declarations.values():
            connection.execute(ddl)
        rows = connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
        ).fetchall()
    finally:
        connection.close()
    generated = {
        (str(row[0]), str(row[1])): (str(row[2]), _exact_sql(row[3]))
        for row in rows
    }
    if not set(declarations).issubset(generated) or any(
        not generated[identity][1] for identity in declarations
    ):
        raise sqlite3.DatabaseError(
            "installation-root expected schema generation failed"
        )
    return generated


def _schema_migration_operation_digest(
    installation_id: str,
    snapshot_digest: str,
) -> str:
    """Derive the replay identity from the exact legacy source snapshot."""

    installation_id = _require_digest(
        installation_id, "schema migration installation id", allow_zero=False
    )
    snapshot_digest = _require_digest(
        snapshot_digest, "schema migration snapshot digest", allow_zero=False
    )
    digest = sha256(b"nachuan.installation-root.schema-migration/v1\x00")
    for value in ("4", "5", installation_id, snapshot_digest):
        encoded = value.encode("ascii")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _is_reparse_or_symlink(info: os.stat_result) -> bool:
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(info.st_mode) or bool(
        int(getattr(info, "st_file_attributes", 0)) & reparse
    )


def _identity(info: os.stat_result) -> tuple[int, int, int]:
    return int(info.st_dev), int(info.st_ino), stat.S_IFMT(info.st_mode)


def _path_key(path: Path) -> str:
    """Return a lexical, case-normalized key without following reparse points."""

    return os.path.normcase(os.path.abspath(os.fspath(path)))


class InstallationRoot:
    """SQLite-backed monotonic authority for one installed Nachuan instance."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        dependencies: InstallationRootDependencies = DEFAULT_DEPENDENCIES,
    ) -> None:
        candidate = Path(path)
        if not candidate.is_absolute() or ".." in candidate.parts:
            raise InstallationRootUnavailable("installation-root path must be absolute")
        self.path = candidate
        self.dependencies = dependencies

    @classmethod
    def open(
        cls,
        path: str | os.PathLike[str],
        *,
        dependencies: InstallationRootDependencies = DEFAULT_DEPENDENCIES,
    ) -> "InstallationRoot":
        """Open and validate an existing authority root without creating files."""

        root = cls(path, dependencies=dependencies)
        root.snapshot()
        return root

    @classmethod
    def provision(
        cls,
        path: str | os.PathLike[str],
        *,
        dependencies: InstallationRootDependencies = DEFAULT_DEPENDENCIES,
    ) -> "InstallationRoot":
        """Explicitly create a new ``provisioning`` root for an installer.

        The immediate parent must already exist.  Exclusive file creation means
        an interrupted or retired installation can never be silently replaced.
        """

        root = cls(path, dependencies=dependencies)
        created = False
        try:
            # Provision is the sole path allowed to repair a deliberately
            # prepared parent ACL.  Check object type/reparse first, harden,
            # then assert; runtime paths always take the assertion-only branch.
            root._assert_parent_path(assert_acl=False)
            dependencies.harden_acl(root.path.parent, True)
            root._assert_parent_path()
            descriptor = os.open(root.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.close(descriptor)
            created = True
            dependencies.harden_acl(root.path, False)
            journal_descriptor = os.open(
                root._journal_path,
                os.O_CREAT | os.O_EXCL | os.O_RDWR,
                0o600,
            )
            os.close(journal_descriptor)
            dependencies.harden_acl(root._journal_path, False)
            root._assert_database_path()

            installation_id = root._new_identity()
            desktop_identity = root._new_identity(excluding={installation_id})
            gateway_identity = root._new_identity(
                excluding={installation_id, desktop_identity}
            )
            gateway_assets_identity = root._new_identity(
                excluding={installation_id, desktop_identity, gateway_identity}
            )
            channel_media_identity = root._new_identity(
                excluding={
                    installation_id,
                    desktop_identity,
                    gateway_identity,
                    gateway_assets_identity,
                }
            )
            owner_digest = owner_sid_digest(dependencies.owner_sid())

            connection = root._connect(validate_schema=False)
            try:
                transaction_identity = root._assert_database_path()
                connection.execute("BEGIN IMMEDIATE")
                dependencies.fault_injector("provision.after_begin")
                connection.execute(_ROOT_DDL)
                connection.execute(_COMPONENT_DDL)
                connection.execute(_UPDATER_DDL)
                connection.execute(_REANCHOR_RECEIPT_DDL)
                connection.execute(_REANCHOR_RECEIPT_NO_UPDATE_DDL)
                connection.execute(_REANCHOR_RECEIPT_NO_DELETE_DDL)
                connection.execute(_REANCHOR_RECEIPT_NO_REPLACE_DDL)
                connection.execute(_SCHEMA_MIGRATION_DDL)
                connection.execute(_SCHEMA_MIGRATION_NO_UPDATE_DDL)
                connection.execute(_SCHEMA_MIGRATION_NO_DELETE_DDL)
                connection.execute(_SCHEMA_MIGRATION_NO_REPLACE_DDL)
                connection.execute(
                    "INSERT INTO installation_root "
                    "(singleton,schema_version,installation_id,owner_sid_digest,epoch,"
                    "root_revision,status,lock_kind,lock_reason_digest,reanchor_pending,"
                    "reanchor_operation_digest,reanchor_snapshot_digest,"
                    "reanchor_source_epoch) "
                    "VALUES(1,?,?,?,?,?,'provisioning','none',NULL,0,NULL,NULL,NULL)",
                    (
                        _SCHEMA_VERSION,
                        installation_id,
                        owner_digest,
                        1,
                        1,
                    ),
                )
                connection.executemany(
                    "INSERT INTO installation_components "
                    "(component,identity,epoch,bound,sequence_floor,state_digest,"
                    "recovery_floor,recovery_state_digest) "
                    "VALUES(?,?,1,0,0,NULL,NULL,NULL)",
                    (
                        ("desktop", desktop_identity),
                        ("gateway", gateway_identity),
                        ("gateway_assets", gateway_assets_identity),
                        ("channel_media", channel_media_identity),
                    ),
                )
                connection.execute(
                    "INSERT INTO installation_updater "
                    "(singleton,release_sequence,keyring_sequence,artifact_digest,"
                    "state_digest) VALUES(1,0,0,?,?)",
                    (_ZERO_DIGEST, _ZERO_DIGEST),
                )
                connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
                root._validate_schema(connection)
                if root._assert_database_path() != transaction_identity:
                    raise OSError("installation-root path changed during provisioning")
                dependencies.fault_injector("provision.before_commit")
                connection.commit()
                dependencies.fault_injector("provision.after_commit")
            except BaseException:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()
            dependencies.harden_acl(root.path, False)
            root._assert_database_path()
            return cls.open(root.path, dependencies=dependencies)
        except (InstallationRootUnavailable, InstallationRootLocked):
            raise
        except Exception as exc:
            # A created but incomplete file is intentionally retained as a
            # fail-closed installation tombstone.  Provisioning never retries by
            # overwriting it, and runtime mode=rw cannot turn it into a new root.
            detail = " after exclusive creation" if created else ""
            raise InstallationRootUnavailable(
                f"cannot provision installation root{detail}"
            ) from exc

    @classmethod
    def migrate_v4_to_v5(
        cls,
        path: str | os.PathLike[str],
        *,
        operation_digest: str | None = None,
        snapshot_digest: str | None = None,
        dependencies: InstallationRootDependencies = DEFAULT_DEPENDENCIES,
    ) -> "InstallationRoot":
        """Installer-only atomic migration into a resumable component-addition lock.

        The schema receipt proves the v4→v5 SQLite commit.  It intentionally
        remains append-only after ``channel_media`` is later bound; the final
        component bind clears only the component-addition lock and activates the
        four-component root.
        """

        requested_operation = (
            None
            if operation_digest is None
            else _require_digest(
                operation_digest,
                "schema migration operation digest",
                allow_zero=False,
            )
        )
        requested_snapshot = (
            None
            if snapshot_digest is None
            else _require_digest(
                snapshot_digest,
                "schema migration snapshot digest",
                allow_zero=False,
            )
        )
        root = cls(path, dependencies=dependencies)
        expected_owner = owner_sid_digest(dependencies.owner_sid())
        connection: sqlite3.Connection | None = None
        committed = False
        try:
            before = root._assert_database_path()
            connection = sqlite3.connect(
                f"{root.path.as_uri()}?mode=rw",
                uri=True,
                timeout=5.0,
                isolation_level=None,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA recursive_triggers=ON")
            if root._assert_database_path() != before:
                raise OSError(
                    "installation-root path identity changed while opening migration"
                )
            user_version = connection.execute("PRAGMA user_version").fetchone()
            if user_version is None:
                raise sqlite3.DatabaseError(
                    "installation-root migration source version is unavailable"
                )
            version = int(user_version[0])
            if version == _SCHEMA_VERSION:
                root._validate_schema(
                    connection, expected_owner_digest=expected_owner
                )
                receipt = connection.execute(
                    "SELECT installation_id,operation_digest,snapshot_digest "
                    "FROM installation_schema_migrations WHERE target_version=5"
                ).fetchone()
                if receipt is None:
                    raise InstallationRootLocked(
                        "installation-root v5 migration receipt does not match"
                    )
                receipt_snapshot = str(receipt["snapshot_digest"])
                expected_operation = _schema_migration_operation_digest(
                    str(receipt["installation_id"]), receipt_snapshot
                )
                if (
                    receipt["operation_digest"] != expected_operation
                    or (
                        requested_operation is not None
                        and requested_operation != expected_operation
                    )
                    or (
                        requested_snapshot is not None
                        and requested_snapshot != receipt_snapshot
                    )
                ):
                    raise InstallationRootLocked(
                        "installation-root v5 migration receipt does not match"
                    )
                committed = True
            elif version != 4:
                raise InstallationRootUnavailable(
                    "installation-root migration source version is unsupported"
                )
            else:
                # Exact read preflight precedes the only persistent PRAGMA.
                root._validate_v4_migration_source(
                    connection,
                    expected_owner_digest=expected_owner,
                )
                journal = connection.execute("PRAGMA journal_mode=PERSIST").fetchone()
                if journal is None or str(journal[0]).lower() != "persist":
                    raise sqlite3.DatabaseError(
                        "installation-root migration cannot pin PERSIST journal"
                    )
                connection.execute("BEGIN IMMEDIATE")
                locked_version = int(
                    connection.execute("PRAGMA user_version").fetchone()[0]
                )
                if locked_version == _SCHEMA_VERSION:
                    # Another elevated installer won the migration race after
                    # our read preflight.  Release the write lock and converge
                    # through the exact v5 receipt path in this same API call.
                    connection.rollback()
                    connection.close()
                    connection = None
                    return cls.migrate_v4_to_v5(
                        root.path,
                        operation_digest=requested_operation,
                        snapshot_digest=requested_snapshot,
                        dependencies=dependencies,
                    )
                if locked_version != 4:
                    raise InstallationRootUnavailable(
                        "installation-root migration source changed version"
                    )
                dependencies.fault_injector("schema_migration.after_begin")
                (
                    legacy_root,
                    legacy_components,
                    computed_snapshot,
                ) = root._validate_v4_migration_source(
                    connection,
                    expected_owner_digest=expected_owner,
                )
                computed_operation = _schema_migration_operation_digest(
                    str(legacy_root["installation_id"]), computed_snapshot
                )
                if (
                    requested_snapshot is not None
                    and requested_snapshot != computed_snapshot
                ):
                    raise InstallationRootLocked(
                        "installation-root v4 snapshot digest does not match"
                    )
                if (
                    requested_operation is not None
                    and requested_operation != computed_operation
                ):
                    raise InstallationRootLocked(
                        "installation-root v4 migration operation does not match"
                    )
                snapshot_digest = computed_snapshot
                operation_digest = computed_operation
                if root._assert_database_path() != before:
                    raise OSError(
                        "installation-root path changed during schema migration"
                    )
                existing_identities = {
                    str(legacy_root["installation_id"]),
                    *(str(row["identity"]) for row in legacy_components),
                }
                channel_identity = root._new_identity(excluding=existing_identities)
                next_revision = int(legacy_root["root_revision"]) + 1

                connection.execute(
                    "ALTER TABLE installation_root RENAME TO installation_root_v4"
                )
                connection.execute(
                    "ALTER TABLE installation_components "
                    "RENAME TO installation_components_v4"
                )
                connection.execute(_ROOT_DDL)
                connection.execute(_COMPONENT_DDL)
                connection.execute(_SCHEMA_MIGRATION_DDL)
                connection.execute(_SCHEMA_MIGRATION_NO_UPDATE_DDL)
                connection.execute(_SCHEMA_MIGRATION_NO_DELETE_DDL)
                connection.execute(_SCHEMA_MIGRATION_NO_REPLACE_DDL)
                connection.execute(
                    "INSERT INTO installation_root "
                    "(singleton,schema_version,installation_id,owner_sid_digest,epoch,"
                    "root_revision,status,lock_kind,lock_reason_digest,reanchor_pending,"
                    "reanchor_operation_digest,reanchor_snapshot_digest,"
                    "reanchor_source_epoch) "
                    "SELECT singleton,5,installation_id,owner_sid_digest,epoch,?,"
                    "'maintenance_locked','component_addition',?,0,NULL,NULL,NULL "
                    "FROM installation_root_v4",
                    (next_revision, snapshot_digest),
                )
                connection.execute(
                    "INSERT INTO installation_components "
                    "(component,identity,epoch,bound,sequence_floor,state_digest,"
                    "recovery_floor,recovery_state_digest) "
                    "SELECT component,identity,epoch,bound,sequence_floor,state_digest,"
                    "recovery_floor,recovery_state_digest "
                    "FROM installation_components_v4"
                )
                connection.execute(
                    "INSERT INTO installation_components "
                    "(component,identity,epoch,bound,sequence_floor,state_digest,"
                    "recovery_floor,recovery_state_digest) "
                    "VALUES('channel_media',?,?,0,0,NULL,NULL,NULL)",
                    (channel_identity, int(legacy_root["epoch"])),
                )
                connection.execute(
                    "INSERT INTO installation_schema_migrations "
                    "(target_version,source_version,installation_id,operation_digest,"
                    "snapshot_digest,completed_root_revision) VALUES(5,4,?,?,?,?)",
                    (
                        str(legacy_root["installation_id"]),
                        operation_digest,
                        snapshot_digest,
                        next_revision,
                    ),
                )
                dependencies.fault_injector(
                    "schema_migration.after_component_addition"
                )
                connection.execute("DROP TABLE installation_components_v4")
                connection.execute("DROP TABLE installation_root_v4")
                connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
                root._validate_schema(
                    connection, expected_owner_digest=expected_owner
                )
                if root._assert_database_path() != before:
                    raise OSError(
                        "installation-root path changed before migration commit"
                    )
                dependencies.fault_injector("schema_migration.before_commit")
                connection.commit()
                committed = True
                dependencies.fault_injector("schema_migration.after_commit")
        except (InstallationRootUnavailable, InstallationRootLocked):
            if connection is not None and connection.in_transaction:
                connection.rollback()
            raise
        except Exception as exc:
            if connection is not None and connection.in_transaction:
                connection.rollback()
            raise InstallationRootUnavailable(
                "installation-root v4 to v5 migration failed closed"
            ) from exc
        finally:
            if connection is not None:
                connection.close()
        if not committed:
            raise InstallationRootUnavailable(
                "installation-root v4 to v5 migration did not commit"
            )
        return cls.open(root.path, dependencies=dependencies)

    @classmethod
    def open_or_migrate_for_installer(
        cls,
        path: str | os.PathLike[str],
        *,
        dependencies: InstallationRootDependencies = DEFAULT_DEPENDENCIES,
    ) -> "InstallationRoot":
        """Open v5 or migrate one exact v4 source; never used by runtime."""

        try:
            return cls.open(path, dependencies=dependencies)
        except InstallationRootUnavailable as open_error:
            try:
                return cls.migrate_v4_to_v5(path, dependencies=dependencies)
            except (InstallationRootUnavailable, InstallationRootLocked) as exc:
                raise exc from open_error

    def _new_identity(self, *, excluding: set[str] | None = None) -> str:
        value = self.dependencies.random_bytes(32)
        if not isinstance(value, bytes) or len(value) != 32:
            raise InstallationRootUnavailable("installation-root random source is invalid")
        encoded = value.hex()
        if encoded == _ZERO_DIGEST or encoded in (excluding or set()):
            raise InstallationRootUnavailable("installation-root random identity is invalid")
        return encoded

    @property
    def _journal_path(self) -> Path:
        return Path(f"{self.path}-journal")

    def _trusted_parent_chain(self) -> tuple[Path, ...]:
        try:
            boundary = Path(self.dependencies.trusted_boundary(self.path))
        except Exception as exc:
            raise OSError("installation-root trusted boundary is unavailable") from exc
        if not boundary.is_absolute() or ".." in boundary.parts:
            raise OSError("installation-root trusted boundary is invalid")
        boundary_key = _path_key(boundary)
        parent_key = _path_key(self.path.parent)
        try:
            common = os.path.normcase(os.path.commonpath((boundary_key, parent_key)))
        except ValueError as exc:
            raise OSError("installation-root path is outside its trusted boundary") from exc
        if common != boundary_key:
            raise OSError("installation-root path is outside its trusted boundary")

        chain: list[Path] = []
        current = self.path.parent
        while True:
            chain.append(current)
            if _path_key(current) == boundary_key:
                return tuple(reversed(chain))
            parent = current.parent
            if _path_key(parent) == _path_key(current):
                raise OSError("installation-root trusted boundary is not an ancestor")
            current = parent

    def _assert_parent_path(
        self, *, assert_acl: bool = True
    ) -> tuple[tuple[int, int, int], ...]:
        identities: list[tuple[int, int, int]] = []
        for component in self._trusted_parent_chain():
            try:
                info = os.lstat(component)
            except OSError as exc:
                raise OSError("installation-root parent path is unavailable") from exc
            if not stat.S_ISDIR(info.st_mode) or _is_reparse_or_symlink(info):
                raise OSError("installation-root parent path is not an ordinary directory")
            identities.append(_identity(info))
            if assert_acl:
                self.dependencies.assert_acl(component, True)
        return tuple(identities)

    def _assert_database_path(
        self,
    ) -> tuple[
        tuple[tuple[int, int, int], ...],
        tuple[int, int, int],
        tuple[int, int, int],
    ]:
        parents = self._assert_parent_path()
        try:
            info = os.lstat(self.path)
        except FileNotFoundError as exc:
            raise OSError("installation-root database is missing") from exc
        if not stat.S_ISREG(info.st_mode) or _is_reparse_or_symlink(info):
            raise OSError("installation-root database is not an ordinary file")
        if int(info.st_size) > _MAX_AUTHORITY_FILE_BYTES:
            raise OSError("installation-root database exceeds the byte limit")
        self.dependencies.assert_acl(self.path, False)
        try:
            journal_info = os.lstat(self._journal_path)
        except FileNotFoundError as exc:
            raise OSError("installation-root persistent journal is missing") from exc
        if not stat.S_ISREG(journal_info.st_mode) or _is_reparse_or_symlink(journal_info):
            raise OSError("installation-root SQLite journal is not an ordinary file")
        if int(journal_info.st_size) > _MAX_AUTHORITY_FILE_BYTES:
            raise OSError("installation-root SQLite journal exceeds the byte limit")
        self.dependencies.assert_acl(self._journal_path, False)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{self.path}{suffix}")
            try:
                os.lstat(sidecar)
            except FileNotFoundError:
                continue
            raise OSError("installation-root has an unexpected SQLite sidecar")
        return parents, _identity(info), _identity(journal_info)

    def _connect(self, *, validate_schema: bool = True) -> sqlite3.Connection:
        before = self._assert_database_path()
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                f"{self.path.as_uri()}?mode=rw",
                uri=True,
                timeout=5.0,
                isolation_level=None,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA recursive_triggers=ON")
            initial_journal = connection.execute("PRAGMA journal_mode").fetchone()
            if initial_journal is None or str(initial_journal[0]).lower() not in {
                "delete",
                "persist",
            }:
                raise sqlite3.DatabaseError(
                    "installation-root database uses an unexpected journal mode"
                )
            journal = connection.execute("PRAGMA journal_mode=PERSIST").fetchone()
            if journal is None or str(journal[0]).lower() != "persist":
                raise sqlite3.DatabaseError("installation-root journal mode is not PERSIST")
            trusted = connection.execute("PRAGMA trusted_schema").fetchone()
            synchronous = connection.execute("PRAGMA synchronous").fetchone()
            recursive_triggers = connection.execute(
                "PRAGMA recursive_triggers"
            ).fetchone()
            if trusted != (0,) and tuple(trusted or ()) != (0,):
                raise sqlite3.DatabaseError("installation-root trusted_schema is not disabled")
            if synchronous is None or int(synchronous[0]) != 2:
                raise sqlite3.DatabaseError("installation-root synchronous mode is not FULL")
            if recursive_triggers is None or int(recursive_triggers[0]) != 1:
                raise sqlite3.DatabaseError(
                    "installation-root recursive triggers are not enabled"
                )
            after = self._assert_database_path()
            if before != after:
                raise OSError("installation-root path identity changed while opening")
            if validate_schema:
                self._validate_schema(connection)
            return connection
        except BaseException:
            if connection is not None:
                connection.close()
            raise

    def _validate_v4_migration_source(
        self,
        connection: sqlite3.Connection,
        *,
        expected_owner_digest: str,
    ) -> tuple[sqlite3.Row, tuple[sqlite3.Row, ...], str]:
        """Validate one clean active v4 root before installer-only migration."""

        page_count = connection.execute("PRAGMA page_count").fetchone()
        page_size = connection.execute("PRAGMA page_size").fetchone()
        application_id = connection.execute("PRAGMA application_id").fetchone()
        user_version = connection.execute("PRAGMA user_version").fetchone()
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
        if (
            page_count is None
            or page_size is None
            or int(page_count[0]) < 1
            or int(page_size[0]) < 512
            or int(page_count[0]) * int(page_size[0]) > _MAX_AUTHORITY_FILE_BYTES
            or application_id is None
            or int(application_id[0]) != _APPLICATION_ID
            or user_version is None
            or int(user_version[0]) != 4
            or journal_mode is None
            or str(journal_mode[0]).lower() not in {"delete", "persist"}
        ):
            raise sqlite3.DatabaseError(
                "legacy installation-root schema identity is invalid"
            )
        rows = connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
        ).fetchall()
        actual = {
            (str(row[0]), str(row[1])): (str(row[2]), row[3]) for row in rows
        }
        expected_objects = _expected_schema_sql(4)
        if set(actual) != set(expected_objects):
            raise sqlite3.DatabaseError(
                "legacy installation-root schema object set is invalid"
            )
        for identity, (expected_table, expected_sql) in expected_objects.items():
            actual_table, actual_sql = actual[identity]
            if actual_table != expected_table or _exact_sql(actual_sql) != expected_sql:
                raise sqlite3.DatabaseError(
                    "legacy installation-root schema definition is invalid"
                )
        check = connection.execute("PRAGMA quick_check").fetchone()
        if check is None or check[0] != "ok":
            raise sqlite3.DatabaseError("legacy installation-root database is corrupt")
        integrity = connection.execute("PRAGMA integrity_check(1)").fetchone()
        if integrity is None or integrity[0] != "ok":
            raise sqlite3.DatabaseError(
                "legacy installation-root integrity check failed"
            )

        roots = connection.execute("SELECT * FROM installation_root").fetchall()
        components = tuple(
            connection.execute(
                "SELECT * FROM installation_components ORDER BY component"
            ).fetchall()
        )
        updaters = connection.execute("SELECT * FROM installation_updater").fetchall()
        receipts = tuple(
            connection.execute(
                "SELECT * FROM installation_reanchor_receipts ORDER BY target_epoch"
            ).fetchall()
        )
        if (
            len(roots) != 1
            or len(components) != 3
            or len(updaters) != 1
            or len(receipts) > _MAX_REANCHOR_RECEIPTS
        ):
            raise sqlite3.DatabaseError(
                "legacy installation-root singleton rows are invalid"
            )
        root = roots[0]
        installation_id = _require_digest(
            root["installation_id"], "legacy installation id", allow_zero=False
        )
        owner_digest = _require_digest(
            root["owner_sid_digest"], "legacy owner SID digest", allow_zero=False
        )
        epoch = _require_counter(root["epoch"], "legacy installation epoch", minimum=1)
        root_revision = _require_counter(
            root["root_revision"], "legacy root revision", minimum=1
        )
        if root_revision > _MAX_COUNTER - 2:
            raise InstallationRootLocked("installation-root revision is exhausted")
        if (
            root["singleton"] != 1
            or int(root["schema_version"]) != 4
            or root["status"] != "active"
            or root["lock_kind"] != "none"
            or root["lock_reason_digest"] is not None
            or root["reanchor_pending"] != 0
            or owner_digest != expected_owner_digest
        ):
            raise InstallationRootLocked(
                "legacy installation root is not a clean active migration source"
            )

        current_receipt: sqlite3.Row | None = None
        expected_target = 2
        previous_revision = 0
        for receipt in receipts:
            target = _require_counter(
                receipt["target_epoch"], "legacy receipt target epoch", minimum=2
            )
            source = _require_counter(
                receipt["source_epoch"], "legacy receipt source epoch", minimum=1
            )
            completed_revision = _require_counter(
                receipt["completed_root_revision"],
                "legacy receipt root revision",
                minimum=1,
            )
            for field in (
                "operation_digest",
                "snapshot_digest",
                "final_proof_digest",
            ):
                _require_digest(
                    receipt[field], f"legacy receipt {field}", allow_zero=False
                )
            if (
                target != source + 1
                or target != expected_target
                or target > epoch
                or completed_revision <= previous_revision
                or completed_revision > root_revision
            ):
                raise sqlite3.DatabaseError(
                    "legacy installation-root reanchor chain is inconsistent"
                )
            if target == epoch:
                current_receipt = receipt
            expected_target += 1
            previous_revision = completed_revision
        if expected_target != epoch + 1:
            raise sqlite3.DatabaseError(
                "legacy installation-root reanchor chain is incomplete"
            )
        reanchor_operation = root["reanchor_operation_digest"]
        reanchor_snapshot = root["reanchor_snapshot_digest"]
        reanchor_source = root["reanchor_source_epoch"]
        receipt_empty = (
            reanchor_operation is None
            and reanchor_snapshot is None
            and reanchor_source is None
            and (epoch == 1 or current_receipt is not None)
        )
        receipt_complete = (
            reanchor_operation is not None
            and reanchor_snapshot is not None
            and reanchor_source is not None
            and int(reanchor_source) + 1 == epoch
            and current_receipt is not None
            and current_receipt["source_epoch"] == reanchor_source
            and current_receipt["operation_digest"] == reanchor_operation
            and current_receipt["snapshot_digest"] == reanchor_snapshot
        )
        if not (receipt_empty or receipt_complete):
            raise sqlite3.DatabaseError(
                "legacy installation-root active receipt is invalid"
            )

        seen: set[str] = set()
        identities: set[str] = set()
        for component in components:
            name = str(component["component"])
            identity = _require_digest(
                component["identity"], "legacy component identity", allow_zero=False
            )
            if (
                name not in {"desktop", "gateway", "gateway_assets"}
                or name in seen
                or identity == installation_id
                or identity in identities
                or _require_counter(
                    component["epoch"], "legacy component epoch", minimum=1
                )
                != epoch
                or component["bound"] != 1
                or component["recovery_floor"] is not None
                or component["recovery_state_digest"] is not None
            ):
                raise InstallationRootLocked(
                    "legacy installation-root component set is not migration-safe"
                )
            _require_counter(
                component["sequence_floor"], "legacy component sequence"
            )
            _require_digest(
                component["state_digest"],
                "legacy component state digest",
                allow_zero=False,
            )
            seen.add(name)
            identities.add(identity)
        if seen != {"desktop", "gateway", "gateway_assets"}:
            raise sqlite3.DatabaseError(
                "legacy installation-root component set is incomplete"
            )

        updater = updaters[0]
        release = _require_counter(
            updater["release_sequence"], "legacy updater release sequence"
        )
        keyring = _require_counter(
            updater["keyring_sequence"], "legacy updater keyring sequence"
        )
        artifact = _require_digest(
            updater["artifact_digest"], "legacy updater artifact digest"
        )
        state = _require_digest(updater["state_digest"], "legacy updater state digest")
        if (
            updater["singleton"] != 1
            or (release == 0) != (artifact == _ZERO_DIGEST)
            or (release == 0 and keyring == 0) != (state == _ZERO_DIGEST)
        ):
            raise sqlite3.DatabaseError(
                "legacy installation-root updater state is inconsistent"
            )
        snapshot_document = {
            "schema": "nachuan.installation-root-v4-logical-snapshot/v1",
            "application_id": _APPLICATION_ID,
            "user_version": 4,
            "objects": [
                {
                    "type": identity[0],
                    "name": identity[1],
                    "sql": _canonical_sql(actual[identity]),
                }
                for identity in sorted(actual)
            ],
            "root": dict(root),
            "components": [dict(row) for row in components],
            "updater": dict(updater),
            "reanchor_receipts": [dict(row) for row in receipts],
        }
        snapshot_bytes = json.dumps(
            snapshot_document,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
        return root, components, sha256(snapshot_bytes).hexdigest()

    def _validate_schema(
        self,
        connection: sqlite3.Connection,
        *,
        expected_owner_digest: str | None = None,
    ) -> None:
        page_count = connection.execute("PRAGMA page_count").fetchone()
        page_size = connection.execute("PRAGMA page_size").fetchone()
        if (
            page_count is None
            or page_size is None
            or int(page_count[0]) < 1
            or int(page_size[0]) < 512
            or int(page_count[0]) * int(page_size[0]) > _MAX_AUTHORITY_FILE_BYTES
        ):
            raise sqlite3.DatabaseError(
                "installation-root page allocation exceeds the byte limit"
            )
        application_id = connection.execute("PRAGMA application_id").fetchone()
        user_version = connection.execute("PRAGMA user_version").fetchone()
        if (
            application_id is None
            or user_version is None
            or int(application_id[0]) != _APPLICATION_ID
            or int(user_version[0]) != _SCHEMA_VERSION
        ):
            raise sqlite3.DatabaseError("installation-root schema identity is invalid")

        rows = connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
        ).fetchall()
        actual = {
            (str(row[0]), str(row[1])): (str(row[2]), row[3]) for row in rows
        }
        expected_objects = _expected_schema_sql(_SCHEMA_VERSION)
        if set(actual) != set(expected_objects):
            raise sqlite3.DatabaseError("installation-root schema object set is invalid")
        for identity, (expected_table, expected_sql) in expected_objects.items():
            actual_table, actual_sql = actual[identity]
            if actual_table != expected_table or _exact_sql(actual_sql) != expected_sql:
                raise sqlite3.DatabaseError("installation-root schema definition is invalid")

        check = connection.execute("PRAGMA quick_check").fetchone()
        if check is None or check[0] != "ok":
            raise sqlite3.DatabaseError("installation-root database is corrupt")

        root_rows = connection.execute("SELECT * FROM installation_root").fetchall()
        component_rows = connection.execute(
            "SELECT * FROM installation_components ORDER BY component"
        ).fetchall()
        updater_rows = connection.execute("SELECT * FROM installation_updater").fetchall()
        schema_migrations = connection.execute(
            "SELECT * FROM installation_schema_migrations ORDER BY target_version"
        ).fetchall()
        reanchor_receipts = connection.execute(
            "SELECT * FROM installation_reanchor_receipts ORDER BY target_epoch"
        )
        receipt_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM installation_reanchor_receipts"
            ).fetchone()[0]
        )
        if receipt_count > _MAX_REANCHOR_RECEIPTS:
            raise sqlite3.DatabaseError(
                "installation-root reanchor receipt history exceeds the limit"
            )
        if (
            len(root_rows) != 1
            or len(component_rows) != len(_COMPONENTS)
            or len(updater_rows) != 1
            or len(schema_migrations) > 1
        ):
            raise sqlite3.DatabaseError("installation-root singleton rows are invalid")

        root = root_rows[0]
        installation_id = _require_digest(
            root["installation_id"], "installation id", allow_zero=False
        )
        _require_digest(root["owner_sid_digest"], "owner SID digest", allow_zero=False)
        epoch = _require_counter(root["epoch"], "installation epoch", minimum=1)
        _require_counter(root["root_revision"], "root revision", minimum=1)
        if root["singleton"] != 1 or root["schema_version"] != _SCHEMA_VERSION:
            raise sqlite3.DatabaseError("installation-root singleton metadata is invalid")
        if root["status"] not in {
            "provisioning",
            "active",
            "maintenance_locked",
            "retired",
        }:
            raise sqlite3.DatabaseError("installation-root status is invalid")
        status = str(root["status"])
        lock_kind = str(root["lock_kind"])
        lock_reason = root["lock_reason_digest"]
        pending = root["reanchor_pending"]
        reanchor_operation = root["reanchor_operation_digest"]
        reanchor_snapshot = root["reanchor_snapshot_digest"]
        reanchor_source_epoch = root["reanchor_source_epoch"]
        if lock_kind not in {
            "none",
            "operator",
            "integrity",
            "component_addition",
            "reanchor",
            "retired",
        }:
            raise sqlite3.DatabaseError("installation-root lock kind is invalid")
        if pending not in (0, 1):
            raise sqlite3.DatabaseError("installation-root reanchor marker is invalid")
        if root["lock_reason_digest"] is not None:
            _require_digest(
                root["lock_reason_digest"], "lock reason digest", allow_zero=False
            )
        if reanchor_operation is not None:
            _require_digest(reanchor_operation, "reanchor operation digest", allow_zero=False)
        if reanchor_snapshot is not None:
            _require_digest(reanchor_snapshot, "reanchor snapshot digest", allow_zero=False)
        if reanchor_source_epoch is not None:
            _require_counter(
                reanchor_source_epoch, "reanchor source epoch", minimum=1
            )
        current_reanchor_receipt: sqlite3.Row | None = None
        expected_target_epoch = 2
        previous_completed_revision = 0
        for receipt in reanchor_receipts:
            target_epoch = _require_counter(
                receipt["target_epoch"], "reanchor receipt target epoch", minimum=2
            )
            source_epoch = _require_counter(
                receipt["source_epoch"], "reanchor receipt source epoch", minimum=1
            )
            operation_digest = _require_digest(
                receipt["operation_digest"],
                "reanchor receipt operation digest",
                allow_zero=False,
            )
            receipt_snapshot_digest = _require_digest(
                receipt["snapshot_digest"],
                "reanchor receipt snapshot digest",
                allow_zero=False,
            )
            final_proof_digest = _require_digest(
                receipt["final_proof_digest"],
                "reanchor receipt final proof digest",
                allow_zero=False,
            )
            completed_revision = _require_counter(
                receipt["completed_root_revision"],
                "reanchor receipt root revision",
                minimum=1,
            )
            if (
                target_epoch != source_epoch + 1
                or target_epoch != expected_target_epoch
                or target_epoch > epoch
                or completed_revision > int(root["root_revision"])
                or completed_revision <= previous_completed_revision
            ):
                raise sqlite3.DatabaseError(
                    "installation-root reanchor receipt is inconsistent"
                )
            expected_target_epoch += 1
            previous_completed_revision = completed_revision
            if target_epoch == epoch:
                current_reanchor_receipt = receipt
        expected_last_receipt_epoch = (
            epoch - 1
            if status == "maintenance_locked"
            and lock_kind == "reanchor"
            and pending == 1
            else epoch
        )
        if expected_target_epoch != expected_last_receipt_epoch + 1:
            raise sqlite3.DatabaseError(
                "installation-root reanchor receipt chain is incomplete"
            )
        if status == "provisioning":
            if (
                lock_kind != "none"
                or lock_reason is not None
                or pending != 0
                or reanchor_operation is not None
                or reanchor_snapshot is not None
                or reanchor_source_epoch is not None
            ):
                raise sqlite3.DatabaseError("unlocked installation-root metadata is invalid")
        elif status == "active":
            receipt_empty = (
                reanchor_operation is None
                and reanchor_snapshot is None
                and reanchor_source_epoch is None
                and (epoch == 1 or current_reanchor_receipt is not None)
            )
            receipt_complete = (
                reanchor_operation is not None
                and reanchor_snapshot is not None
                and reanchor_source_epoch is not None
                and int(reanchor_source_epoch) + 1 == epoch
                and current_reanchor_receipt is not None
                and current_reanchor_receipt["source_epoch"] == reanchor_source_epoch
                and current_reanchor_receipt["operation_digest"] == reanchor_operation
                and current_reanchor_receipt["snapshot_digest"] == reanchor_snapshot
            )
            if (
                lock_kind != "none"
                or lock_reason is not None
                or pending != 0
                or not (receipt_empty or receipt_complete)
            ):
                raise sqlite3.DatabaseError("active installation-root metadata is invalid")
        elif status == "maintenance_locked":
            if (
                lock_kind
                not in {"operator", "integrity", "component_addition", "reanchor"}
                or lock_reason is None
            ):
                raise sqlite3.DatabaseError("maintenance lock metadata is invalid")
            if lock_kind == "reanchor":
                if (
                    pending != 1
                    or reanchor_operation is None
                    or reanchor_snapshot is None
                    or reanchor_source_epoch is None
                    or int(reanchor_source_epoch) + 1 != epoch
                    or lock_reason != reanchor_snapshot
                    or current_reanchor_receipt is not None
                ):
                    raise sqlite3.DatabaseError("reanchor transaction marker is invalid")
            elif (
                pending != 0
                or reanchor_operation is not None
                or reanchor_snapshot is not None
                or reanchor_source_epoch is not None
            ):
                raise sqlite3.DatabaseError("non-reanchor lock carries reanchor state")
        elif (
            lock_kind != "retired"
            or lock_reason is None
            or pending != 0
            or reanchor_operation is not None
            or reanchor_snapshot is not None
            or reanchor_source_epoch is not None
        ):
            raise sqlite3.DatabaseError("retirement tombstone metadata is invalid")

        seen: set[str] = set()
        component_identities: set[str] = set()
        bound = 0
        for row in component_rows:
            component = str(row["component"])
            if component not in _COMPONENTS or component in seen:
                raise sqlite3.DatabaseError("installation-root component set is invalid")
            seen.add(component)
            component_identity = _require_digest(
                row["identity"], "component identity", allow_zero=False
            )
            if (
                component_identity == installation_id
                or component_identity in component_identities
            ):
                raise sqlite3.DatabaseError(
                    "installation-root component identity set is invalid"
                )
            component_identities.add(component_identity)
            if _require_counter(row["epoch"], "component epoch", minimum=1) != epoch:
                raise sqlite3.DatabaseError("installation-root component epoch is invalid")
            sequence = _require_counter(row["sequence_floor"], "component sequence")
            if row["bound"] not in (0, 1):
                raise sqlite3.DatabaseError("installation-root component binding is invalid")
            if row["bound"]:
                _require_digest(
                    row["state_digest"], "component state digest", allow_zero=False
                )
                recovery_floor = row["recovery_floor"]
                recovery_digest = row["recovery_state_digest"]
                if (recovery_floor is None) != (recovery_digest is None):
                    raise sqlite3.DatabaseError(
                        "component recovery fence is incomplete"
                    )
                if recovery_floor is not None:
                    if (
                        _require_counter(
                            recovery_floor, "component recovery floor"
                        )
                        != sequence
                        or _require_digest(
                            recovery_digest,
                            "component recovery state digest",
                            allow_zero=False,
                        )
                        != row["state_digest"]
                    ):
                        raise sqlite3.DatabaseError(
                            "component recovery fence does not bind current state"
                        )
                bound += 1
            elif (
                sequence != 0
                or row["state_digest"] is not None
                or row["recovery_floor"] is not None
                or row["recovery_state_digest"] is not None
            ):
                raise sqlite3.DatabaseError("unbound installation-root component is invalid")
        if seen != set(_COMPONENTS):
            raise sqlite3.DatabaseError("installation-root component set is incomplete")
        if root["status"] == "active" and bound != len(_COMPONENTS):
            raise sqlite3.DatabaseError("active installation-root components are incomplete")
        if root["status"] == "provisioning" and bound == len(_COMPONENTS):
            raise sqlite3.DatabaseError("provisioning installation-root was not activated")
        if lock_kind == "component_addition":
            channel = next(
                row
                for row in component_rows
                if str(row["component"]) == "channel_media"
            )
            if (
                status != "maintenance_locked"
                or bound != len(_COMPONENTS) - 1
                or bool(channel["bound"])
                or len(schema_migrations) != 1
            ):
                raise sqlite3.DatabaseError(
                    "installation-root component addition marker is invalid"
                )

        if schema_migrations:
            migration = schema_migrations[0]
            completed_migration_revision = _require_counter(
                migration["completed_root_revision"],
                "schema migration root revision",
                minimum=2,
            )
            migration_operation_digest = _require_digest(
                migration["operation_digest"],
                "schema migration operation digest",
                allow_zero=False,
            )
            migration_snapshot_digest = _require_digest(
                migration["snapshot_digest"],
                "schema migration snapshot digest",
                allow_zero=False,
            )
            expected_migration_operation = _schema_migration_operation_digest(
                str(root["installation_id"]),
                migration_snapshot_digest,
            )
            if (
                int(migration["source_version"]) != 4
                or int(migration["target_version"]) != _SCHEMA_VERSION
                or migration["installation_id"] != root["installation_id"]
                or migration_operation_digest != expected_migration_operation
                or completed_migration_revision > int(root["root_revision"])
                or (
                    lock_kind == "component_addition"
                    and (
                        completed_migration_revision != int(root["root_revision"])
                        or root["lock_reason_digest"]
                        != migration_snapshot_digest
                    )
                )
                or (
                    status == "active"
                    and int(root["root_revision"])
                    <= completed_migration_revision
                )
            ):
                raise sqlite3.DatabaseError(
                    "installation-root schema migration receipt is invalid"
                )
        elif lock_kind == "component_addition":
            raise sqlite3.DatabaseError(
                "installation-root component addition receipt is missing"
            )

        updater = updater_rows[0]
        if updater["singleton"] != 1:
            raise sqlite3.DatabaseError("installation-root updater singleton is invalid")
        updater_release = _require_counter(
            updater["release_sequence"], "updater release sequence"
        )
        updater_keyring = _require_counter(
            updater["keyring_sequence"], "updater keyring sequence"
        )
        updater_artifact = _require_digest(
            updater["artifact_digest"], "updater artifact digest"
        )
        updater_state = _require_digest(
            updater["state_digest"], "updater state digest"
        )
        if (updater_release == 0) != (updater_artifact == _ZERO_DIGEST):
            raise sqlite3.DatabaseError("updater artifact floor is inconsistent")
        if (updater_release == 0 and updater_keyring == 0) != (
            updater_state == _ZERO_DIGEST
        ):
            raise sqlite3.DatabaseError("updater state floor is inconsistent")

        expected_owner = (
            owner_sid_digest(self.dependencies.owner_sid())
            if expected_owner_digest is None
            else _require_digest(
                expected_owner_digest,
                "expected owner SID digest",
                allow_zero=False,
            )
        )
        if root["owner_sid_digest"] != expected_owner:
            raise InstallationRootLocked("installation-root owner SID does not match")

    def _snapshot_from_connection(
        self, connection: sqlite3.Connection
    ) -> InstallationRootSnapshot:
        root = connection.execute("SELECT * FROM installation_root WHERE singleton=1").fetchone()
        components = connection.execute(
            "SELECT * FROM installation_components ORDER BY component"
        ).fetchall()
        updater = connection.execute(
            "SELECT * FROM installation_updater WHERE singleton=1"
        ).fetchone()
        if root is None or updater is None or len(components) != len(_COMPONENTS):
            raise sqlite3.DatabaseError("installation-root state is incomplete")
        component_values = tuple(
            ComponentState(
                component=_require_component(row["component"]),
                identity=str(row["identity"]),
                epoch=int(row["epoch"]),
                bound=bool(row["bound"]),
                sequence_floor=int(row["sequence_floor"]),
                state_digest=(None if row["state_digest"] is None else str(row["state_digest"])),
                recovery_floor=(
                    None if row["recovery_floor"] is None else int(row["recovery_floor"])
                ),
                recovery_state_digest=(
                    None
                    if row["recovery_state_digest"] is None
                    else str(row["recovery_state_digest"])
                ),
            )
            for row in components
        )
        return InstallationRootSnapshot(
            installation_id=str(root["installation_id"]),
            owner_sid_digest=str(root["owner_sid_digest"]),
            epoch=int(root["epoch"]),
            root_revision=int(root["root_revision"]),
            status=str(root["status"]),  # type: ignore[arg-type]
            lock_kind=str(root["lock_kind"]),
            lock_reason_digest=(
                None
                if root["lock_reason_digest"] is None
                else str(root["lock_reason_digest"])
            ),
            reanchor_pending=bool(root["reanchor_pending"]),
            reanchor_operation_digest=(
                None
                if root["reanchor_operation_digest"] is None
                else str(root["reanchor_operation_digest"])
            ),
            reanchor_snapshot_digest=(
                None
                if root["reanchor_snapshot_digest"] is None
                else str(root["reanchor_snapshot_digest"])
            ),
            reanchor_source_epoch=(
                None
                if root["reanchor_source_epoch"] is None
                else int(root["reanchor_source_epoch"])
            ),
            principal_digest=installation_principal(
                str(root["installation_id"]), int(root["epoch"])
            ),
            components=component_values,  # type: ignore[arg-type]
            updater=UpdaterState(
                release_sequence=int(updater["release_sequence"]),
                keyring_sequence=int(updater["keyring_sequence"]),
                artifact_digest=str(updater["artifact_digest"]),
                state_digest=str(updater["state_digest"]),
            ),
        )

    def _read_snapshot(self) -> InstallationRootSnapshot:
        connection: sqlite3.Connection | None = None
        try:
            # Validation must happen inside the same read snapshot used to
            # materialize the result.  A pre-transaction validation can observe
            # an old root row and a concurrently committed receipt.
            connection = self._connect(validate_schema=False)
            transaction_identity = self._assert_database_path()
            connection.execute("BEGIN")
            self._assert_database_path()
            self._validate_schema(connection)
            snapshot = self._snapshot_from_connection(connection)
            if self._assert_database_path() != transaction_identity:
                raise OSError("installation-root path changed during inspection")
            connection.commit()
            return snapshot
        except (InstallationRootUnavailable, InstallationRootLocked):
            if connection is not None and connection.in_transaction:
                connection.rollback()
            raise
        except Exception as exc:
            if connection is not None and connection.in_transaction:
                connection.rollback()
            raise InstallationRootUnavailable("installation root is unavailable") from exc
        finally:
            if connection is not None:
                connection.close()

    def snapshot(self) -> InstallationRootSnapshot:
        """Inspect validated state, including provisioning/locked/retired state."""

        return self._read_snapshot()

    def require_active(self) -> InstallationRootSnapshot:
        snapshot = self.snapshot()
        if snapshot.status != "active":
            raise InstallationRootLocked(
                f"installation root is not active ({snapshot.status})"
            )
        return snapshot

    def principal(self) -> str:
        """Return the current active installation/epoch principal."""

        return self.require_active().principal_digest

    def _write(
        self,
        name: str,
        action: Callable[[sqlite3.Connection], RootMutationResult],
    ) -> RootMutationResult:
        connection: sqlite3.Connection | None = None
        transaction_identity = None
        try:
            # Acquire the writer lock before the only schema/state validation.
            # Otherwise concurrent completion can expose a mixed old-root/new-
            # receipt view during the preflight validation.
            connection = self._connect(validate_schema=False)
            transaction_identity = self._assert_database_path()
            connection.execute("BEGIN IMMEDIATE")
            self._assert_database_path()
            self._validate_schema(connection)
            result = action(connection)
            if self._assert_database_path() != transaction_identity:
                raise OSError("installation-root path changed during mutation")
            self.dependencies.fault_injector(f"{name}.before_commit")
            connection.commit()
            self.dependencies.fault_injector(f"{name}.after_commit")
            return result
        except _CommitIntegrityLock as exc:
            try:
                if connection is None or transaction_identity is None:
                    raise OSError("integrity lock transaction was not established")
                if self._assert_database_path() != transaction_identity:
                    raise OSError(
                        "installation-root path changed during integrity lock"
                    )
                self.dependencies.fault_injector(f"{name}.before_commit")
                connection.commit()
                self.dependencies.fault_injector(f"{name}.after_commit")
            except Exception as commit_exc:
                if connection is not None and connection.in_transaction:
                    connection.rollback()
                raise InstallationRootUnavailable(
                    f"installation-root {name} is unavailable"
                ) from commit_exc
            raise InstallationRootLocked(str(exc)) from None
        except (InstallationRootUnavailable, InstallationRootLocked):
            if connection is not None and connection.in_transaction:
                connection.rollback()
            raise
        except Exception as exc:
            if connection is not None and connection.in_transaction:
                connection.rollback()
            raise InstallationRootUnavailable(
                f"installation-root {name} is unavailable"
            ) from exc
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _root_row(connection: sqlite3.Connection) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM installation_root WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise sqlite3.DatabaseError("installation-root singleton is missing")
        return row

    @staticmethod
    def _component_row(
        connection: sqlite3.Connection, component: ComponentName
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM installation_components WHERE component=?", (component,)
        ).fetchone()
        if row is None:
            raise sqlite3.DatabaseError("installation-root component is missing")
        return row

    @staticmethod
    def _next_revision(row: sqlite3.Row) -> int:
        revision = _require_counter(row["root_revision"], "root revision", minimum=1)
        if revision >= _MAX_COUNTER:
            raise InstallationRootLocked("installation-root revision is exhausted")
        return revision + 1

    def _integrity_lock(
        self,
        connection: sqlite3.Connection,
        reason: str,
    ) -> None:
        row = self._root_row(connection)
        if row["status"] == "retired":
            raise InstallationRootLocked("installation root is retired")
        if (
            row["status"] == "maintenance_locked"
            and row["lock_kind"] == "reanchor"
            and row["reanchor_pending"] == 1
        ):
            # A stale or conflicting request must never destroy a resumable
            # reanchor receipt.  The caller may only continue component binds.
            raise InstallationRootLocked(
                "installation-root reanchor is already in progress"
            )
        if row["status"] == "maintenance_locked" and row["lock_kind"] == "integrity":
            raise InstallationRootLocked(
                f"installation-root integrity lock: {reason}"
            )
        connection.execute(
            "UPDATE installation_root SET root_revision=?,status='maintenance_locked',"
            "lock_kind='integrity',lock_reason_digest=?,reanchor_pending=0,"
            "reanchor_operation_digest=NULL,reanchor_snapshot_digest=NULL,"
            "reanchor_source_epoch=NULL WHERE singleton=1",
            (self._next_revision(row), _reason_digest(reason)),
        )
        raise _CommitIntegrityLock(f"installation-root integrity lock: {reason}")

    def _require_binding(
        self,
        connection: sqlite3.Connection,
        *,
        installation_id: str,
        epoch: int,
    ) -> sqlite3.Row:
        _require_digest(installation_id, "installation id", allow_zero=False)
        _require_counter(epoch, "installation epoch", minimum=1)
        row = self._root_row(connection)
        if row["installation_id"] != installation_id:
            raise InstallationRootLocked(
                "installation-root installation identity does not match"
            )
        if int(row["epoch"]) != epoch:
            raise InstallationRootLocked(
                "installation-root epoch does not match"
            )
        return row

    @staticmethod
    def _require_revision(row: sqlite3.Row, expected_root_revision: int) -> None:
        expected = _require_counter(
            expected_root_revision, "expected root revision", minimum=1
        )
        if int(row["root_revision"]) != expected:
            raise InstallationRootUnavailable("installation-root CAS revision changed")

    @staticmethod
    def _require_active_row(row: sqlite3.Row) -> None:
        if row["status"] != "active":
            raise InstallationRootLocked(
                f"installation root is not active ({row['status']})"
            )

    def bind_component(
        self,
        component: ComponentName,
        *,
        installation_id: str,
        epoch: int,
        identity: str,
        state_digest: str,
        expected_root_revision: int,
        sequence_floor: int = 0,
    ) -> RootMutationResult:
        """Bind one preallocated component identity and activate the closed set."""

        component = _require_component(component)
        _require_digest(identity, "component identity", allow_zero=False)
        _require_digest(state_digest, "component state digest", allow_zero=False)
        sequence_floor = _require_counter(sequence_floor, "component sequence")

        def action(connection: sqlite3.Connection) -> RootMutationResult:
            root = self._root_row(connection)
            if root["status"] == "active":
                if (
                    root["installation_id"] == installation_id
                    and int(root["epoch"]) == epoch
                ):
                    active_component = self._component_row(connection, component)
                    if (
                        active_component["identity"] == identity
                        and int(active_component["epoch"]) == epoch
                        and active_component["bound"]
                        and int(active_component["sequence_floor"]) == sequence_floor
                        and active_component["state_digest"] == state_digest
                    ):
                        return RootMutationResult(
                            snapshot=self._snapshot_from_connection(connection),
                            applied=False,
                        )
                raise InstallationRootLocked(
                    "active installation root is not accepting a binding"
                )
            root = self._require_binding(
                connection, installation_id=installation_id, epoch=epoch
            )
            if root["status"] == "retired":
                raise InstallationRootLocked("installation root is retired")
            current = self._component_row(connection, component)
            if current["identity"] != identity or int(current["epoch"]) != epoch:
                self._integrity_lock(connection, "component identity conflict")
            if current["bound"]:
                if (
                    int(current["sequence_floor"]) == sequence_floor
                    and current["state_digest"] == state_digest
                ):
                    return RootMutationResult(
                        snapshot=self._snapshot_from_connection(connection), applied=False
                    )
                self._require_revision(root, expected_root_revision)
                self._integrity_lock(connection, "component binding digest conflict")
            if not (
                root["status"] == "provisioning"
                or (
                    root["status"] == "maintenance_locked"
                    and root["lock_kind"] == "reanchor"
                    and root["reanchor_pending"] == 1
                )
                or (
                    root["status"] == "maintenance_locked"
                    and root["lock_kind"] == "component_addition"
                    and component == "channel_media"
                )
            ):
                raise InstallationRootLocked("installation root is not accepting bindings")
            self._require_revision(root, expected_root_revision)
            connection.execute(
                "UPDATE installation_components SET bound=1,sequence_floor=?,state_digest=?,"
                "recovery_floor=NULL,recovery_state_digest=NULL "
                "WHERE component=? AND identity=? AND epoch=? AND bound=0",
                (sequence_floor, state_digest, component, identity, epoch),
            )
            bound_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM installation_components WHERE bound=1"
                ).fetchone()[0]
            )
            next_revision = self._next_revision(root)
            if bound_count == len(_COMPONENTS) and (
                root["status"] == "provisioning"
                or root["lock_kind"] == "component_addition"
            ):
                connection.execute(
                    "UPDATE installation_root SET root_revision=?,status='active',"
                    "lock_kind='none',lock_reason_digest=NULL,reanchor_pending=0 "
                    "WHERE singleton=1",
                    (next_revision,),
                )
            else:
                connection.execute(
                    "UPDATE installation_root SET root_revision=? WHERE singleton=1",
                    (next_revision,),
                )
            return RootMutationResult(
                snapshot=self._snapshot_from_connection(connection), applied=True
            )

        return self._write("component_bind", action)

    def verify_component(
        self,
        component: ComponentName,
        *,
        installation_id: str,
        epoch: int,
        identity: str,
        sequence_floor: int,
        state_digest: str,
        previous_state_digest: str | None = None,
    ) -> RootMutationResult:
        """Verify exact state or idempotently close one proven ``floor + 1`` gap.

        A recovery caller must present the previous digest that is still stored
        in root.  This operation only advances root; it is not an outbound fence.
        """

        component = _require_component(component)
        _require_digest(identity, "component identity", allow_zero=False)
        sequence_floor = _require_counter(sequence_floor, "component sequence")
        _require_digest(state_digest, "component state digest", allow_zero=False)
        if previous_state_digest is not None:
            _require_digest(
                previous_state_digest,
                "previous component state digest",
                allow_zero=False,
            )

        def action(connection: sqlite3.Connection) -> RootMutationResult:
            root = self._require_binding(
                connection, installation_id=installation_id, epoch=epoch
            )
            self._require_active_row(root)
            current = self._component_row(connection, component)
            if (
                current["identity"] != identity
                or int(current["epoch"]) != epoch
                or not current["bound"]
            ):
                self._integrity_lock(connection, "component identity or binding drift")
            current_floor = int(current["sequence_floor"])
            current_digest = str(current["state_digest"])
            if current_floor == sequence_floor and current_digest == state_digest:
                recovery_pending = (
                    current["recovery_floor"] == current_floor
                    and current["recovery_state_digest"] == current_digest
                )
                return RootMutationResult(
                    snapshot=self._snapshot_from_connection(connection),
                    applied=False,
                    recovered=recovery_pending,
                )
            if current["recovery_floor"] is not None:
                raise InstallationRootLocked(
                    "component recovery fence must be acknowledged before advancing"
                )
            if (
                sequence_floor == current_floor + 1
                and previous_state_digest == current_digest
            ):
                connection.execute(
                    "UPDATE installation_components SET sequence_floor=?,state_digest=?,"
                    "recovery_floor=?,recovery_state_digest=? "
                    "WHERE component=? AND sequence_floor=? AND state_digest=?",
                    (
                        sequence_floor,
                        state_digest,
                        sequence_floor,
                        state_digest,
                        component,
                        current_floor,
                        current_digest,
                    ),
                )
                connection.execute(
                    "UPDATE installation_root SET root_revision=? WHERE singleton=1",
                    (self._next_revision(root),),
                )
                self.dependencies.fault_injector("component_verify.after_floor_update")
                return RootMutationResult(
                    snapshot=self._snapshot_from_connection(connection),
                    applied=True,
                    recovered=True,
                )
            self._integrity_lock(
                connection, "component floor rollback, jump, or digest conflict"
            )
            raise AssertionError("unreachable")

        return self._write("component_verify", action)

    def acknowledge_component_recovery(
        self,
        component: ComponentName,
        *,
        installation_id: str,
        epoch: int,
        identity: str,
        recovery_floor: int,
        recovery_state_digest: str,
        next_floor: int,
        next_state_digest: str,
        expected_root_revision: int,
    ) -> RootMutationResult:
        """Advance past a recovery fence into durable local no-outbound state.

        The caller must first commit ``next_floor`` locally with every affected
        operation marked manual-only/no-outbound.  Advancing the root and clearing
        the fence are one transaction; normal component advancement remains
        blocked until it commits.
        """

        component = _require_component(component)
        _require_digest(identity, "component identity", allow_zero=False)
        recovery_floor = _require_counter(recovery_floor, "component recovery floor")
        next_floor = _require_counter(next_floor, "next component floor")
        _require_digest(
            recovery_state_digest,
            "component recovery state digest",
            allow_zero=False,
        )
        _require_digest(
            next_state_digest, "next component state digest", allow_zero=False
        )
        if next_state_digest == recovery_state_digest:
            raise InstallationRootUnavailable(
                "component recovery acknowledgement must change state digest"
            )
        if next_floor != recovery_floor + 1:
            raise InstallationRootUnavailable(
                "component recovery acknowledgement must advance exactly once"
            )

        def action(connection: sqlite3.Connection) -> RootMutationResult:
            root = self._require_binding(
                connection, installation_id=installation_id, epoch=epoch
            )
            self._require_active_row(root)
            current = self._component_row(connection, component)
            if (
                current["identity"] != identity
                or int(current["epoch"]) != epoch
                or not current["bound"]
            ):
                self._integrity_lock(connection, "component identity or binding drift")
            if (
                int(current["sequence_floor"]) == next_floor
                and current["state_digest"] == next_state_digest
                and current["recovery_floor"] is None
                and current["recovery_state_digest"] is None
            ):
                return RootMutationResult(
                    snapshot=self._snapshot_from_connection(connection), applied=False
                )
            self._require_revision(root, expected_root_revision)
            if (
                int(current["sequence_floor"]) != recovery_floor
                or current["state_digest"] != recovery_state_digest
                or current["recovery_floor"] != recovery_floor
                or current["recovery_state_digest"] != recovery_state_digest
            ):
                self._integrity_lock(
                    connection, "component recovery acknowledgement state conflict"
                )
            cursor = connection.execute(
                "UPDATE installation_components SET sequence_floor=?,state_digest=?,"
                "recovery_floor=NULL,recovery_state_digest=NULL "
                "WHERE component=? AND identity=? "
                "AND epoch=? AND recovery_floor=? AND recovery_state_digest=?",
                (
                    next_floor,
                    next_state_digest,
                    component,
                    identity,
                    epoch,
                    recovery_floor,
                    recovery_state_digest,
                ),
            )
            if cursor.rowcount != 1:
                raise sqlite3.DatabaseError(
                    "component recovery acknowledgement did not update exactly one row"
                )
            connection.execute(
                "UPDATE installation_root SET root_revision=? WHERE singleton=1",
                (self._next_revision(root),),
            )
            return RootMutationResult(
                snapshot=self._snapshot_from_connection(connection), applied=True
            )

        return self._write("component_recovery_ack", action)

    def advance_component(
        self,
        component: ComponentName,
        *,
        installation_id: str,
        epoch: int,
        identity: str,
        expected_floor: int,
        expected_state_digest: str,
        next_floor: int,
        next_state_digest: str,
        expected_root_revision: int,
    ) -> RootMutationResult:
        """CAS one component floor after its local durable state already committed."""

        component = _require_component(component)
        _require_digest(identity, "component identity", allow_zero=False)
        expected_floor = _require_counter(expected_floor, "expected component floor")
        next_floor = _require_counter(next_floor, "next component floor")
        _require_digest(
            expected_state_digest, "expected component state digest", allow_zero=False
        )
        _require_digest(
            next_state_digest, "next component state digest", allow_zero=False
        )
        if next_state_digest == expected_state_digest:
            raise InstallationRootUnavailable(
                "component advancement must change state digest"
            )
        if next_floor != expected_floor + 1:
            raise InstallationRootUnavailable("component floor must advance exactly once")

        def action(connection: sqlite3.Connection) -> RootMutationResult:
            root = self._require_binding(
                connection, installation_id=installation_id, epoch=epoch
            )
            self._require_active_row(root)
            current = self._component_row(connection, component)
            if (
                current["identity"] != identity
                or int(current["epoch"]) != epoch
                or not current["bound"]
            ):
                self._integrity_lock(connection, "component identity or binding drift")
            current_floor = int(current["sequence_floor"])
            current_digest = str(current["state_digest"])
            if current_floor == next_floor:
                if current_digest == next_state_digest:
                    recovery_pending = (
                        current["recovery_floor"] == current_floor
                        and current["recovery_state_digest"] == current_digest
                    )
                    return RootMutationResult(
                        snapshot=self._snapshot_from_connection(connection),
                        applied=False,
                        recovered=recovery_pending,
                    )
            self._require_revision(root, expected_root_revision)
            if current_floor == next_floor:
                self._integrity_lock(connection, "concurrent component digest conflict")
            if current_floor != expected_floor or current_digest != expected_state_digest:
                self._integrity_lock(
                    connection, "component CAS floor or digest conflict"
                )
            if current["recovery_floor"] is not None:
                raise InstallationRootLocked(
                    "component recovery fence must be acknowledged before advancing"
                )
            cursor = connection.execute(
                "UPDATE installation_components SET sequence_floor=?,state_digest=?,"
                "recovery_floor=NULL,recovery_state_digest=NULL "
                "WHERE component=? AND identity=? AND epoch=? "
                "AND sequence_floor=? AND state_digest=?",
                (
                    next_floor,
                    next_state_digest,
                    component,
                    identity,
                    epoch,
                    expected_floor,
                    expected_state_digest,
                ),
            )
            if cursor.rowcount != 1:
                raise sqlite3.DatabaseError("component CAS did not update exactly one row")
            connection.execute(
                "UPDATE installation_root SET root_revision=? WHERE singleton=1",
                (self._next_revision(root),),
            )
            self.dependencies.fault_injector("component_advance.after_floor_update")
            return RootMutationResult(
                snapshot=self._snapshot_from_connection(connection), applied=True
            )

        return self._write("component_advance", action)

    @staticmethod
    def _valid_updater_transition(
        current_release: int,
        current_keyring: int,
        current_artifact: str,
        current_state: str,
        next_release: int,
        next_keyring: int,
        next_artifact: str,
        next_state: str,
    ) -> bool:
        if next_release < current_release or next_keyring < current_keyring:
            return False
        if next_release == current_release and next_keyring == current_keyring:
            return False
        if next_state == _ZERO_DIGEST or next_state == current_state:
            return False
        if next_release == current_release:
            return next_artifact == current_artifact
        return next_artifact != _ZERO_DIGEST and next_artifact != current_artifact

    def verify_updater(
        self,
        *,
        installation_id: str,
        epoch: int,
        release_sequence: int,
        keyring_sequence: int,
        artifact_digest: str,
        updater_state_digest: str,
        previous_release_sequence: int | None = None,
        previous_keyring_sequence: int | None = None,
        previous_artifact_digest: str | None = None,
        previous_updater_state_digest: str | None = None,
    ) -> RootMutationResult:
        """Verify updater floors or close one locally proven post-commit gap."""

        release_sequence = _require_counter(release_sequence, "updater release sequence")
        keyring_sequence = _require_counter(keyring_sequence, "updater keyring sequence")
        _require_digest(artifact_digest, "updater artifact digest")
        _require_digest(updater_state_digest, "updater state digest")
        previous: tuple[int, int, str, str] | None = None
        if any(
            value is not None
            for value in (
                previous_release_sequence,
                previous_keyring_sequence,
                previous_artifact_digest,
                previous_updater_state_digest,
            )
        ):
            if (
                previous_release_sequence is None
                or previous_keyring_sequence is None
                or previous_artifact_digest is None
                or previous_updater_state_digest is None
            ):
                raise InstallationRootUnavailable(
                    "previous updater proof must be complete"
                )
            previous = (
                _require_counter(
                    previous_release_sequence, "previous updater release sequence"
                ),
                _require_counter(
                    previous_keyring_sequence, "previous updater keyring sequence"
                ),
                _require_digest(
                    previous_artifact_digest, "previous updater artifact digest"
                ),
                _require_digest(
                    previous_updater_state_digest, "previous updater state digest"
                ),
            )

        def action(connection: sqlite3.Connection) -> RootMutationResult:
            root = self._require_binding(
                connection, installation_id=installation_id, epoch=epoch
            )
            self._require_active_row(root)
            row = connection.execute(
                "SELECT * FROM installation_updater WHERE singleton=1"
            ).fetchone()
            if row is None:
                raise sqlite3.DatabaseError("updater floor is missing")
            current = (
                int(row["release_sequence"]),
                int(row["keyring_sequence"]),
                str(row["artifact_digest"]),
                str(row["state_digest"]),
            )
            candidate = (
                release_sequence,
                keyring_sequence,
                artifact_digest,
                updater_state_digest,
            )
            if candidate == current:
                return RootMutationResult(
                    snapshot=self._snapshot_from_connection(connection), applied=False
                )
            if previous == current and self._valid_updater_transition(*current, *candidate):
                connection.execute(
                    "UPDATE installation_updater SET release_sequence=?,"
                    "keyring_sequence=?,artifact_digest=?,state_digest=? "
                    "WHERE singleton=1",
                    candidate,
                )
                connection.execute(
                    "UPDATE installation_root SET root_revision=? WHERE singleton=1",
                    (self._next_revision(root),),
                )
                return RootMutationResult(
                    snapshot=self._snapshot_from_connection(connection),
                    applied=True,
                    recovered=True,
                )
            self._integrity_lock(
                connection, "updater floor rollback, reuse, or state conflict"
            )
            raise AssertionError("unreachable")

        return self._write("updater_verify", action)

    def advance_updater(
        self,
        *,
        installation_id: str,
        epoch: int,
        expected_release_sequence: int,
        expected_keyring_sequence: int,
        expected_artifact_digest: str,
        expected_updater_state_digest: str,
        next_release_sequence: int,
        next_keyring_sequence: int,
        next_artifact_digest: str,
        next_updater_state_digest: str,
        expected_root_revision: int,
    ) -> RootMutationResult:
        """CAS independent release/keyring floors, allowing strictly newer jumps."""

        expected = (
            _require_counter(
                expected_release_sequence, "expected updater release sequence"
            ),
            _require_counter(
                expected_keyring_sequence, "expected updater keyring sequence"
            ),
            _require_digest(expected_artifact_digest, "expected updater artifact digest"),
            _require_digest(
                expected_updater_state_digest, "expected updater state digest"
            ),
        )
        candidate = (
            _require_counter(next_release_sequence, "next updater release sequence"),
            _require_counter(next_keyring_sequence, "next updater keyring sequence"),
            _require_digest(next_artifact_digest, "next updater artifact digest"),
            _require_digest(next_updater_state_digest, "next updater state digest"),
        )
        if not self._valid_updater_transition(*expected, *candidate):
            raise InstallationRootUnavailable("updater transition is not monotonic")

        def action(connection: sqlite3.Connection) -> RootMutationResult:
            root = self._require_binding(
                connection, installation_id=installation_id, epoch=epoch
            )
            self._require_active_row(root)
            row = connection.execute(
                "SELECT * FROM installation_updater WHERE singleton=1"
            ).fetchone()
            if row is None:
                raise sqlite3.DatabaseError("updater floor is missing")
            current = (
                int(row["release_sequence"]),
                int(row["keyring_sequence"]),
                str(row["artifact_digest"]),
                str(row["state_digest"]),
            )
            if current == candidate:
                return RootMutationResult(
                    snapshot=self._snapshot_from_connection(connection), applied=False
                )
            self._require_revision(root, expected_root_revision)
            if current != expected:
                self._integrity_lock(connection, "updater CAS conflict")
            connection.execute(
                "UPDATE installation_updater SET release_sequence=?,keyring_sequence=?,"
                "artifact_digest=?,state_digest=? WHERE singleton=1",
                candidate,
            )
            connection.execute(
                "UPDATE installation_root SET root_revision=? WHERE singleton=1",
                (self._next_revision(root),),
            )
            return RootMutationResult(
                snapshot=self._snapshot_from_connection(connection), applied=True
            )

        return self._write("updater_advance", action)

    def enter_maintenance(
        self,
        *,
        installation_id: str,
        epoch: int,
        expected_root_revision: int,
        reason_digest: str,
    ) -> RootMutationResult:
        _require_digest(reason_digest, "maintenance reason digest", allow_zero=False)

        def action(connection: sqlite3.Connection) -> RootMutationResult:
            root = self._require_binding(
                connection, installation_id=installation_id, epoch=epoch
            )
            if (
                root["status"] == "maintenance_locked"
                and root["lock_kind"] == "operator"
                and root["lock_reason_digest"] == reason_digest
            ):
                return RootMutationResult(
                    snapshot=self._snapshot_from_connection(connection), applied=False
                )
            self._require_active_row(root)
            self._require_revision(root, expected_root_revision)
            connection.execute(
                "UPDATE installation_root SET root_revision=?,status='maintenance_locked',"
                "lock_kind='operator',lock_reason_digest=?,reanchor_pending=0,"
                "reanchor_operation_digest=NULL,reanchor_snapshot_digest=NULL,"
                "reanchor_source_epoch=NULL "
                "WHERE singleton=1",
                (self._next_revision(root), reason_digest),
            )
            return RootMutationResult(
                snapshot=self._snapshot_from_connection(connection), applied=True
            )

        return self._write("maintenance_enter", action)

    def resume_active(
        self,
        *,
        installation_id: str,
        epoch: int,
        expected_root_revision: int,
    ) -> RootMutationResult:
        """Exit only an operator lock; integrity/reanchor locks need reanchor."""

        def action(connection: sqlite3.Connection) -> RootMutationResult:
            root = self._require_binding(
                connection, installation_id=installation_id, epoch=epoch
            )
            if root["status"] == "active":
                return RootMutationResult(
                    snapshot=self._snapshot_from_connection(connection), applied=False
                )
            if not (
                root["status"] == "maintenance_locked"
                and root["lock_kind"] == "operator"
                and root["reanchor_pending"] == 0
            ):
                raise InstallationRootLocked(
                    "installation root cannot resume without reanchor"
                )
            bound = int(
                connection.execute(
                    "SELECT COUNT(*) FROM installation_components WHERE bound=1"
                ).fetchone()[0]
            )
            if bound != len(_COMPONENTS):
                self._integrity_lock(connection, "maintenance resume has incomplete bindings")
            self._require_revision(root, expected_root_revision)
            connection.execute(
                "UPDATE installation_root SET root_revision=?,status='active',"
                "lock_kind='none',lock_reason_digest=NULL,reanchor_pending=0,"
                "reanchor_operation_digest=NULL,reanchor_snapshot_digest=NULL,"
                "reanchor_source_epoch=NULL WHERE singleton=1",
                (self._next_revision(root),),
            )
            return RootMutationResult(
                snapshot=self._snapshot_from_connection(connection), applied=True
            )

        return self._write("maintenance_resume", action)

    def begin_reanchor(
        self,
        *,
        installation_id: str,
        epoch: int,
        expected_root_revision: int,
        operation_digest: str,
        snapshot_digest: str,
    ) -> RootMutationResult:
        """Start an authorized new epoch while remaining maintenance locked."""

        _require_digest(installation_id, "installation id", allow_zero=False)
        epoch = _require_counter(epoch, "installation epoch", minimum=1)
        _require_digest(
            operation_digest, "reanchor operation digest", allow_zero=False
        )
        _require_digest(snapshot_digest, "reanchor snapshot digest", allow_zero=False)

        def action(connection: sqlite3.Connection) -> RootMutationResult:
            root = self._root_row(connection)
            completed_receipt = connection.execute(
                "SELECT * FROM installation_reanchor_receipts "
                "WHERE operation_digest=? LIMIT 1",
                (operation_digest,),
            ).fetchone()
            if completed_receipt is not None:
                exact_current_receipt = (
                    root["installation_id"] == installation_id
                    and int(root["epoch"]) == int(completed_receipt["target_epoch"])
                    and int(completed_receipt["source_epoch"]) == epoch
                    and completed_receipt["snapshot_digest"] == snapshot_digest
                )
                if exact_current_receipt and root["status"] == "active":
                    return RootMutationResult(
                        snapshot=self._snapshot_from_connection(connection),
                        applied=False,
                    )
                if exact_current_receipt:
                    raise InstallationRootLocked(
                        "reanchor was historically completed but the root is not active"
                    )
                raise InstallationRootLocked(
                    "reanchor operation digest was already completed"
                )
            if (
                root["status"] == "maintenance_locked"
                and root["lock_kind"] == "reanchor"
                and root["reanchor_pending"] == 1
            ):
                if (
                    root["installation_id"] == installation_id
                    and int(root["reanchor_source_epoch"]) == epoch
                    and root["reanchor_operation_digest"] == operation_digest
                    and root["reanchor_snapshot_digest"] == snapshot_digest
                ):
                    return RootMutationResult(
                        snapshot=self._snapshot_from_connection(connection),
                        applied=False,
                    )
                raise InstallationRootLocked(
                    "a different reanchor operation is already in progress"
                )
            if root["status"] == "active":
                if (
                    root["installation_id"] == installation_id
                    and root["reanchor_source_epoch"] is not None
                    and int(root["reanchor_source_epoch"]) == epoch
                    and root["reanchor_operation_digest"] == operation_digest
                    and root["reanchor_snapshot_digest"] == snapshot_digest
                ):
                    return RootMutationResult(
                        snapshot=self._snapshot_from_connection(connection),
                        applied=False,
                    )
                raise InstallationRootLocked(
                    "reanchor is not pending on the active installation root"
                )
            if root["status"] == "retired":
                raise InstallationRootLocked("installation root is retired")
            if root["installation_id"] != installation_id:
                raise InstallationRootLocked(
                    "reanchor installation identity does not match"
                )
            if int(root["epoch"]) != epoch:
                raise InstallationRootLocked(
                    "reanchor source epoch does not match"
                )
            if root["status"] != "maintenance_locked":
                raise InstallationRootLocked("reanchor requires maintenance lock")
            if root["lock_kind"] not in {"operator", "integrity"}:
                raise InstallationRootLocked("installation root cannot begin reanchor")
            self._require_revision(root, expected_root_revision)
            if connection.execute(
                "SELECT 1 FROM installation_reanchor_receipts "
                "WHERE operation_digest=? LIMIT 1",
                (operation_digest,),
            ).fetchone() is not None:
                raise InstallationRootLocked(
                    "reanchor operation digest was already completed"
                )
            if epoch >= _MAX_COUNTER:
                raise InstallationRootLocked("installation epoch is exhausted")
            installation_identity = str(root["installation_id"])
            desktop_identity = self._new_identity(excluding={installation_identity})
            gateway_identity = self._new_identity(
                excluding={installation_identity, desktop_identity}
            )
            gateway_assets_identity = self._new_identity(
                excluding={installation_identity, desktop_identity, gateway_identity}
            )
            channel_media_identity = self._new_identity(
                excluding={
                    installation_identity,
                    desktop_identity,
                    gateway_identity,
                    gateway_assets_identity,
                }
            )
            next_epoch = epoch + 1
            connection.execute(
                "UPDATE installation_root SET epoch=?,root_revision=?,"
                "lock_kind='reanchor',lock_reason_digest=?,reanchor_pending=1,"
                "reanchor_operation_digest=?,reanchor_snapshot_digest=?,"
                "reanchor_source_epoch=? "
                "WHERE singleton=1",
                (
                    next_epoch,
                    self._next_revision(root),
                    snapshot_digest,
                    operation_digest,
                    snapshot_digest,
                    epoch,
                ),
            )
            self.dependencies.fault_injector("reanchor.after_root_update")
            connection.execute(
                "UPDATE installation_components SET identity=?,epoch=?,bound=0,"
                "sequence_floor=0,state_digest=NULL,recovery_floor=NULL,"
                "recovery_state_digest=NULL WHERE component='desktop'",
                (desktop_identity, next_epoch),
            )
            self.dependencies.fault_injector("reanchor.after_desktop_reset")
            connection.execute(
                "UPDATE installation_components SET identity=?,epoch=?,bound=0,"
                "sequence_floor=0,state_digest=NULL,recovery_floor=NULL,"
                "recovery_state_digest=NULL WHERE component='gateway'",
                (gateway_identity, next_epoch),
            )
            connection.execute(
                "UPDATE installation_components SET identity=?,epoch=?,bound=0,"
                "sequence_floor=0,state_digest=NULL,recovery_floor=NULL,"
                "recovery_state_digest=NULL WHERE component='gateway_assets'",
                (gateway_assets_identity, next_epoch),
            )
            connection.execute(
                "UPDATE installation_components SET identity=?,epoch=?,bound=0,"
                "sequence_floor=0,state_digest=NULL,recovery_floor=NULL,"
                "recovery_state_digest=NULL WHERE component='channel_media'",
                (channel_media_identity, next_epoch),
            )
            self.dependencies.fault_injector(
                "reanchor.after_gateway_assets_reset"
            )
            return RootMutationResult(
                snapshot=self._snapshot_from_connection(connection), applied=True
            )

        return self._write("reanchor", action)

    def complete_reanchor(
        self,
        *,
        installation_id: str,
        epoch: int,
        expected_root_revision: int,
        operation_digest: str,
        snapshot_digest: str,
        final_proof_digest: str,
    ) -> RootMutationResult:
        """Activate a fully rebound epoch using one durable final proof."""

        _require_digest(installation_id, "installation id", allow_zero=False)
        epoch = _require_counter(epoch, "installation epoch", minimum=2)
        _require_digest(
            operation_digest, "reanchor operation digest", allow_zero=False
        )
        _require_digest(snapshot_digest, "reanchor snapshot digest", allow_zero=False)
        _require_digest(
            final_proof_digest, "reanchor final proof digest", allow_zero=False
        )
        _require_counter(
            expected_root_revision,
            "expected root revision",
            minimum=1,
        )

        def action(connection: sqlite3.Connection) -> RootMutationResult:
            root = self._root_row(connection)
            receipt = connection.execute(
                "SELECT * FROM installation_reanchor_receipts "
                "WHERE target_epoch=?",
                (epoch,),
            ).fetchone()
            if receipt is not None:
                exact_current_receipt = (
                    root["installation_id"] == installation_id
                    and int(root["epoch"]) == epoch
                    and receipt["operation_digest"] == operation_digest
                    and receipt["snapshot_digest"] == snapshot_digest
                    and receipt["final_proof_digest"] == final_proof_digest
                )
                if exact_current_receipt and root["status"] == "active":
                    return RootMutationResult(
                        snapshot=self._snapshot_from_connection(connection),
                        applied=False,
                    )
                if exact_current_receipt:
                    raise InstallationRootLocked(
                        "reanchor was historically completed but the root is not active"
                    )
                raise InstallationRootLocked(
                    "reanchor completion proof conflicts with the durable receipt"
                )
            root = self._require_binding(
                connection,
                installation_id=installation_id,
                epoch=epoch,
            )
            if not (
                root["status"] == "maintenance_locked"
                and root["lock_kind"] == "reanchor"
                and root["reanchor_pending"] == 1
                and root["reanchor_operation_digest"] == operation_digest
                and root["reanchor_snapshot_digest"] == snapshot_digest
                and int(root["reanchor_source_epoch"]) + 1 == epoch
            ):
                raise InstallationRootLocked(
                    "reanchor completion proof does not match the pending operation"
                )
            self._require_revision(root, expected_root_revision)
            bound_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM installation_components WHERE bound=1"
                ).fetchone()[0]
            )
            if bound_count != len(_COMPONENTS):
                raise InstallationRootLocked(
                    "reanchor completion requires every component binding"
                )
            next_revision = self._next_revision(root)
            connection.execute(
                "INSERT INTO installation_reanchor_receipts("
                "target_epoch,source_epoch,operation_digest,snapshot_digest,"
                "final_proof_digest,completed_root_revision) VALUES(?,?,?,?,?,?)",
                (
                    epoch,
                    int(root["reanchor_source_epoch"]),
                    operation_digest,
                    snapshot_digest,
                    final_proof_digest,
                    next_revision,
                ),
            )
            self.dependencies.fault_injector("reanchor_complete.after_receipt")
            connection.execute(
                "UPDATE installation_root SET root_revision=?,status='active',"
                "lock_kind='none',lock_reason_digest=NULL,reanchor_pending=0 "
                "WHERE singleton=1",
                (next_revision,),
            )
            self.dependencies.fault_injector("reanchor_complete.after_root_update")
            return RootMutationResult(
                snapshot=self._snapshot_from_connection(connection),
                applied=True,
            )

        return self._write("reanchor_complete", action)

    def retire(
        self,
        *,
        installation_id: str,
        epoch: int,
        expected_root_revision: int,
        reason_digest: str,
    ) -> RootMutationResult:
        """Commit a non-revivable retirement tombstone before destructive clear."""

        _require_digest(reason_digest, "retirement reason digest", allow_zero=False)

        def action(connection: sqlite3.Connection) -> RootMutationResult:
            root = self._require_binding(
                connection, installation_id=installation_id, epoch=epoch
            )
            if (
                root["status"] == "maintenance_locked"
                and root["lock_kind"] == "reanchor"
                and root["reanchor_pending"] == 1
            ):
                raise InstallationRootLocked(
                    "installation root cannot retire while reanchor is pending"
                )
            if root["status"] == "retired":
                if root["lock_reason_digest"] == reason_digest:
                    return RootMutationResult(
                        snapshot=self._snapshot_from_connection(connection), applied=False
                    )
                raise InstallationRootLocked("installation root is already retired")
            self._require_revision(root, expected_root_revision)
            connection.execute(
                "UPDATE installation_root SET root_revision=?,status='retired',"
                "lock_kind='retired',lock_reason_digest=?,reanchor_pending=0,"
                "reanchor_operation_digest=NULL,reanchor_snapshot_digest=NULL,"
                "reanchor_source_epoch=NULL "
                "WHERE singleton=1",
                (self._next_revision(root), reason_digest),
            )
            return RootMutationResult(
                snapshot=self._snapshot_from_connection(connection), applied=True
            )

        return self._write("retire", action)


__all__ = [
    "ComponentState",
    "DEFAULT_DEPENDENCIES",
    "InstallationRoot",
    "InstallationRootDependencies",
    "InstallationRootError",
    "InstallationRootLocked",
    "InstallationRootSnapshot",
    "InstallationRootUnavailable",
    "RootMutationResult",
    "UpdaterState",
    "installation_principal",
    "owner_sid_digest",
    "default_installation_root_path",
]
