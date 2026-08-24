"""Gateway coordination with the Installation Epoch Root.

Only paid-media mutations and remote paid-media dispatch depend on this
controller.  It deliberately has no application globals, starts no service,
and never discovers ProgramData from environment variables.  The caller must
open an :class:`~gateway.installation_root.InstallationRoot` from an explicit,
trusted path before constructing this object.

Normal runtime must use :meth:`GatewayInstallationControl.open_bound`.
:meth:`GatewayInstallationControl.provision` is reserved for an already
pre-validated, explicit installer/first-run flow; it is the only path here that
may create the gateway ledger.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import re
import stat
from threading import RLock
from typing import Literal

from gateway.durable_media_requests import (
    DurableMediaAuthorityCorruption,
    DurableMediaRequestStore,
    DurableMediaRequestUnavailable,
    DurableMediaRootState,
    DurableMediaRootTransition,
)
from gateway.installation_root import (
    ComponentState,
    InstallationRoot,
    InstallationRootError,
    InstallationRootSnapshot,
)
from gateway.secure_store import (
    SecureStorageError,
    assert_restricted_windows_handle_acl,
    harden_restricted_windows_handle_acl,
)


_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_ZERO_DIGEST = "0" * 64
_PAID_PRINCIPAL_DOMAIN = b"nachuan.gateway.paid-principal.v1\x00"
_MAX_ROOT_CAS_CALLS = 4
_MAX_RECONCILE_INSPECTIONS = 5
_MAX_OUTBOUND_INSPECTIONS = 4
_OWNERSHIP_MAGIC = b"NACHUAN_GATEWAY_LEDGER_OWNER_V1\n"

ControlMode = Literal[
    "detached",
    "provisioned_not_active",
    "ready",
    "manual_only",
    "fused",
]


class GatewayInstallationControlUnavailable(RuntimeError):
    """Paid-media authority cannot currently be proven safe."""


class _AuthorityMismatch(RuntimeError):
    """Internal closed failure used without matching exception text."""


def _is_reparse_or_symlink(info: os.stat_result) -> bool:
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(info.st_mode) or bool(
        int(getattr(info, "st_file_attributes", 0)) & reparse
    )


class _GatewayLedgerOwnership:
    """Crash-released, cross-process exclusive ownership of one gateway ledger."""

    def __init__(self, path: Path, descriptor: int) -> None:
        self.path = path
        self._descriptor = descriptor
        self._close_lock = RLock()

    @staticmethod
    def _assert_plain_path(path: Path, *, must_exist: bool) -> None:
        parent = os.lstat(path.parent)
        if not stat.S_ISDIR(parent.st_mode) or _is_reparse_or_symlink(parent):
            raise OSError("gateway ownership parent is not a plain directory")
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            if must_exist:
                raise
            return
        if not stat.S_ISREG(info.st_mode) or _is_reparse_or_symlink(info):
            raise OSError("gateway ownership path is not a plain file")

    @classmethod
    def acquire(
        cls,
        path: Path,
        *,
        create_if_missing: bool,
        repair_incomplete_receipt: bool = False,
    ) -> "_GatewayLedgerOwnership":
        path = Path(os.path.abspath(os.fspath(path)))
        exists = path.exists()
        if not exists and not create_if_missing:
            raise OSError("gateway ownership file is missing")
        cls._assert_plain_path(path, must_exist=exists)
        descriptor = (
            cls._acquire_windows(
                path,
                create=not exists,
                writable=not exists or repair_incomplete_receipt,
            )
            if os.name == "nt"
            else cls._acquire_posix(path, create=not exists)
        )
        try:
            descriptor_info = os.fstat(descriptor)
            path_info = os.lstat(path)
            if (
                not stat.S_ISREG(descriptor_info.st_mode)
                or not stat.S_ISREG(path_info.st_mode)
                or _is_reparse_or_symlink(path_info)
                or (int(descriptor_info.st_dev), int(descriptor_info.st_ino))
                != (int(path_info.st_dev), int(path_info.st_ino))
            ):
                raise OSError("gateway ownership identity changed")
            os.lseek(descriptor, 0, os.SEEK_SET)
            initialize_receipt = not exists
            if exists:
                raw = os.read(descriptor, len(_OWNERSHIP_MAGIC) + 1)
                if raw != _OWNERSHIP_MAGIC:
                    if not (
                        repair_incomplete_receipt
                        and len(raw) < len(_OWNERSHIP_MAGIC)
                        and _OWNERSHIP_MAGIC.startswith(raw)
                    ):
                        raise OSError("gateway ownership receipt is invalid")
                    initialize_receipt = True
            if os.name == "nt":
                try:
                    if initialize_receipt:
                        harden_restricted_windows_handle_acl(
                            descriptor, directory=False
                        )
                    else:
                        assert_restricted_windows_handle_acl(
                            descriptor, directory=False
                        )
                except SecureStorageError as exc:
                    raise OSError("gateway ownership ACL is invalid") from exc
            if initialize_receipt:
                # Harden first so every full receipt necessarily has already
                # passed exact-handle ACL verification.  A crash before or
                # during this write therefore leaves only the explicitly
                # repairable empty/strict-prefix state.
                os.lseek(descriptor, 0, os.SEEK_SET)
                cls._write_receipt(descriptor)
                if os.name == "nt":
                    try:
                        assert_restricted_windows_handle_acl(
                            descriptor, directory=False
                        )
                    except SecureStorageError as exc:
                        raise OSError("gateway ownership ACL is invalid") from exc
            return cls(path, descriptor)
        except BaseException:
            os.close(descriptor)
            raise

    @staticmethod
    def _write_receipt(descriptor: int) -> None:
        view = memoryview(_OWNERSHIP_MAGIC)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("gateway ownership receipt write was incomplete")
            view = view[written:]
        os.ftruncate(descriptor, len(_OWNERSHIP_MAGIC))
        os.fsync(descriptor)

    @staticmethod
    def _acquire_windows(path: Path, *, create: bool, writable: bool) -> int:
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
        generic_read = 0x80000000
        generic_write = 0x40000000
        read_control = 0x00020000
        write_dac = 0x00040000
        write_owner = 0x00080000
        create_new = 1
        open_existing = 3
        file_attribute_normal = 0x80
        file_flag_open_reparse_point = 0x00200000
        invalid_handle = ctypes.c_void_p(-1).value
        handle = kernel32.CreateFileW(
            str(path),
            generic_read
            | read_control
            | (
                generic_write | write_dac | write_owner
                if writable
                else 0
            ),
            0,  # FILE_SHARE_NONE: mandatory across processes and path aliases.
            None,
            create_new if create else open_existing,
            file_attribute_normal | file_flag_open_reparse_point,
            None,
        )
        if handle in (None, invalid_handle):
            raise OSError(
                ctypes.get_last_error(), "cannot acquire gateway ledger ownership"
            )
        try:
            flags = os.O_RDWR if writable else os.O_RDONLY
            flags |= int(getattr(os, "O_BINARY", 0))
            return msvcrt.open_osfhandle(int(handle), flags)
        except BaseException:
            kernel32.CloseHandle(handle)
            raise

    @staticmethod
    def _acquire_posix(path: Path, *, create: bool) -> int:
        import fcntl

        flags = os.O_RDWR
        if create:
            flags |= os.O_CREAT | os.O_EXCL
        descriptor = os.open(path, flags, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def close(self) -> None:
        with self._close_lock:
            descriptor = self._descriptor
            if descriptor >= 0:
                os.close(descriptor)
                self._descriptor = -1


def _ownership_path(
    root: InstallationRoot,
    installation_id: str,
    gateway_identity: str,
) -> Path:
    authority = root
    root_path = getattr(authority, "path", None)
    if root_path is None:
        authority = getattr(root, "root", None)
        root_path = getattr(authority, "path", None)
    if root_path is None:
        raise OSError("installation root path is unavailable for ownership")
    candidate = Path(root_path)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise OSError("installation root path is invalid for ownership")
    if not _is_digest(installation_id) or not _is_digest(gateway_identity):
        raise OSError("gateway ownership identity is invalid")
    root_info = os.lstat(candidate)
    if not stat.S_ISREG(root_info.st_mode) or _is_reparse_or_symlink(root_info):
        raise OSError("installation root identity is invalid for ownership")
    device = int(root_info.st_dev)
    inode = int(root_info.st_ino)
    if device < 0 or inode < 0:
        raise OSError("installation root file identity is invalid")
    identity_bytes = f"{device:x}:{inode:x}".encode("ascii")
    ownership_digest = sha256(
        b"nachuan.gateway-ledger-ownership-path.v1\x00"
        + len(identity_bytes).to_bytes(4, "big")
        + identity_bytes
        + bytes.fromhex(installation_id)
        + bytes.fromhex(gateway_identity)
    ).hexdigest()
    dependencies = getattr(authority, "dependencies", None)
    trusted_boundary = getattr(dependencies, "trusted_boundary", None)
    if not callable(trusted_boundary):
        raise OSError("installation root trusted boundary is unavailable")
    boundary = Path(trusted_boundary(candidate))
    if not boundary.is_absolute() or ".." in boundary.parts:
        raise OSError("installation root trusted boundary is invalid")
    # Keep the leaf short enough for ordinary Windows MAX_PATH callers while
    # retaining the full commitment in the digest.
    return boundary / f".gateway-{ownership_digest}.writer-owner"


def _close_factory_resources(
    store: DurableMediaRequestStore | None,
    ownership: _GatewayLedgerOwnership | None,
) -> None:
    try:
        if store is not None:
            store.close()
    finally:
        if ownership is not None:
            ownership.close()


@dataclass(frozen=True, slots=True)
class GatewayInstallationControlState:
    """Non-secret, inspectable status of the gateway authority boundary."""

    mode: ControlMode
    reason_code: str
    installation_id: str | None = None
    epoch: int | None = None
    database_identity: str | None = None
    mutation_sequence: int | None = None
    state_digest: str | None = None
    paid_principal: str | None = None

    @property
    def outbound_ready(self) -> bool:
        return self.mode == "ready"


def stable_paid_principal(root_principal_digest: object) -> str:
    """Derive the paid-media principal from the root, never from a paid key."""

    if (
        not isinstance(root_principal_digest, str)
        or _DIGEST_RE.fullmatch(root_principal_digest) is None
        or root_principal_digest == _ZERO_DIGEST
    ):
        raise ValueError("root principal digest must be a nonzero SHA-256 digest")
    return sha256(
        _PAID_PRINCIPAL_DOMAIN + bytes.fromhex(root_principal_digest)
    ).hexdigest()


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and _DIGEST_RE.fullmatch(value) is not None
        and value != _ZERO_DIGEST
    )


def _normal_local_state(local: DurableMediaRootState) -> bool:
    return (
        local.authority_mode == "normal"
        and local.installation_id is None
        and local.epoch is None
        and local.recovery_floor is None
        and local.recovery_state_digest is None
    )


def _manual_local_state(local: DurableMediaRootState) -> bool:
    return (
        local.authority_mode == "manual_only"
        and _is_digest(local.installation_id)
        and isinstance(local.epoch, int)
        and not isinstance(local.epoch, bool)
        and local.epoch >= 1
        and isinstance(local.recovery_floor, int)
        and not isinstance(local.recovery_floor, bool)
        and local.recovery_floor >= 0
        and _is_digest(local.recovery_state_digest)
        and local.mutation_sequence == local.recovery_floor + 1
    )


def _component_matches(
    component: ComponentState,
    state: DurableMediaRootState,
) -> bool:
    return (
        component.sequence_floor == state.mutation_sequence
        and component.state_digest == state.state_digest
    )


class GatewayInstallationControl:
    """Fail-closed paid-media authority controller for one gateway ledger.

    Instances are built by :meth:`open_bound` or :meth:`provision` so the store
    is guaranteed to receive this controller's synchronous root commit hook.
    Ordinary chat and health code must remain outside this object.
    """

    def __init__(
        self,
        root: InstallationRoot,
        *,
        expected_installation_id: str,
        expected_epoch: int,
        expected_gateway_identity: str,
    ) -> None:
        if not isinstance(root, InstallationRoot) and not all(
            callable(getattr(root, name, None))
            for name in (
                "snapshot",
                "bind_component",
                "verify_component",
                "acknowledge_component_recovery",
                "advance_component",
            )
        ):
            raise TypeError("root must implement the InstallationRoot interface")
        if not _is_digest(expected_installation_id):
            raise ValueError("expected installation id is invalid")
        if (
            not isinstance(expected_epoch, int)
            or isinstance(expected_epoch, bool)
            or expected_epoch < 1
        ):
            raise ValueError("expected epoch is invalid")
        if not _is_digest(expected_gateway_identity):
            raise ValueError("expected gateway identity is invalid")
        self._root = root
        self._expected_installation_id = expected_installation_id
        self._expected_epoch = expected_epoch
        self._expected_gateway_identity = expected_gateway_identity
        self._store: DurableMediaRequestStore | None = None
        self._ownership: _GatewayLedgerOwnership | None = None
        self._lock = RLock()
        self._close_lock = RLock()
        self._closing = False
        self._generation = 0
        self._root_transition_in_flight = False
        self._state = GatewayInstallationControlState(
            mode="detached",
            reason_code="store-not-attached",
            installation_id=expected_installation_id,
            epoch=expected_epoch,
            database_identity=expected_gateway_identity,
        )

    @classmethod
    def _from_snapshot(
        cls,
        root: InstallationRoot,
        snapshot: InstallationRootSnapshot,
    ) -> "GatewayInstallationControl":
        component = snapshot.component("gateway")
        return cls(
            root,
            expected_installation_id=snapshot.installation_id,
            expected_epoch=snapshot.epoch,
            expected_gateway_identity=component.identity,
        )

    @classmethod
    def open_bound(
        cls,
        root: InstallationRoot,
        store_path: str | os.PathLike[str],
    ) -> "GatewayInstallationControl":
        """Strictly open an existing v3 ledger and reconcile it with ``root``.

        This normal-runtime path never creates or migrates the ledger.  Failure
        is isolated to the caller that opted into paid-media authority.
        """

        ownership: _GatewayLedgerOwnership | None = None
        store: DurableMediaRequestStore | None = None
        try:
            snapshot = root.snapshot()
            control = cls._from_snapshot(root, snapshot)
            ownership = _GatewayLedgerOwnership.acquire(
                _ownership_path(
                    root,
                    control._expected_installation_id,
                    control._expected_gateway_identity,
                ),
                create_if_missing=False,
            )
            store = DurableMediaRequestStore(
                store_path,
                construction_policy="open_bound",
                expected_database_identity=control._expected_gateway_identity,
                pre_mutation_hook=control.assert_local_mutation_ready,
                root_commit_hook=control.root_commit_hook,
            )
        except (
            InstallationRootError,
            DurableMediaRequestUnavailable,
            OSError,
            ValueError,
        ):
            _close_factory_resources(store, ownership)
            raise GatewayInstallationControlUnavailable(
                "cannot open bound gateway authority"
            ) from None
        except BaseException:
            _close_factory_resources(store, ownership)
            raise
        try:
            control._attach_factory_store(store, ownership)
        except BaseException:
            _close_factory_resources(store, ownership)
            raise
        try:
            control.reconcile_startup()
        except BaseException:
            control.close()
            raise
        return control

    @classmethod
    def verify_bound_for_component_addition(
        cls,
        root: InstallationRoot,
        store_path: str | os.PathLike[str],
    ) -> "GatewayInstallationControl":
        """Installer-only exact proof of a legacy gateway during v5 addition.

        This path is deliberately separate from runtime reconciliation.  It
        opens only the existing ledger, rollback anchor, and ownership receipt;
        it never creates, repairs, binds, verifies, advances, or resumes local
        authority.  The returned controller remains non-writable and must be
        closed by the installer after the new component transaction finishes.
        """

        ownership: _GatewayLedgerOwnership | None = None
        store: DurableMediaRequestStore | None = None
        try:
            snapshot = root.snapshot()
            if (
                snapshot.status != "maintenance_locked"
                or snapshot.lock_kind != "component_addition"
                or snapshot.reanchor_pending
            ):
                raise _AuthorityMismatch(
                    "root is not in the component-addition proof state"
                )
            component = snapshot.component("gateway")
            if not component.bound:
                raise _AuthorityMismatch("legacy gateway component is not bound")
            control = cls._from_snapshot(root, snapshot)
            ownership = _GatewayLedgerOwnership.acquire(
                _ownership_path(
                    root,
                    control._expected_installation_id,
                    control._expected_gateway_identity,
                ),
                create_if_missing=False,
            )
            store = DurableMediaRequestStore(
                store_path,
                construction_policy="open_bound",
                expected_database_identity=control._expected_gateway_identity,
                pre_mutation_hook=control.assert_local_mutation_ready,
                root_commit_hook=control.root_commit_hook,
            )
            local = store.inspect_root_state()
            fresh = root.snapshot()
            if fresh != snapshot:
                raise _AuthorityMismatch(
                    "component-addition Root changed during gateway proof"
                )
            proven = control._validated_component(
                fresh,
                local,
                require_active=False,
            )
            if (
                not _normal_local_state(local)
                or proven.recovery_floor is not None
                or proven.recovery_state_digest is not None
                or not _component_matches(proven, local)
            ):
                raise _AuthorityMismatch(
                    "legacy gateway proof does not match the Root"
                )
            control._attach_factory_store(store, ownership)
            control._publish_state(
                "provisioned_not_active",
                "component-addition-proof-verified",
                fresh,
                local,
            )
            return control
        except (
            InstallationRootError,
            DurableMediaRequestUnavailable,
            _AuthorityMismatch,
            KeyError,
            OSError,
            ValueError,
        ):
            _close_factory_resources(store, ownership)
            raise GatewayInstallationControlUnavailable(
                "cannot verify legacy gateway authority for component addition"
            ) from None
        except BaseException:
            _close_factory_resources(store, ownership)
            raise

    @classmethod
    def verify_bound_for_active_installer(
        cls,
        root: InstallationRoot,
        store_path: str | os.PathLike[str],
    ) -> "GatewayInstallationControl":
        """Installer-only exact proof of an already-active gateway authority."""

        ownership: _GatewayLedgerOwnership | None = None
        store: DurableMediaRequestStore | None = None
        try:
            snapshot = root.snapshot()
            if (
                snapshot.status != "active"
                or snapshot.lock_kind != "none"
                or snapshot.reanchor_pending
            ):
                raise _AuthorityMismatch("root is not in the active proof state")
            component = snapshot.component("gateway")
            if not component.bound:
                raise _AuthorityMismatch("active gateway component is not bound")
            control = cls._from_snapshot(root, snapshot)
            ownership = _GatewayLedgerOwnership.acquire(
                _ownership_path(
                    root,
                    control._expected_installation_id,
                    control._expected_gateway_identity,
                ),
                create_if_missing=False,
            )
            store = DurableMediaRequestStore(
                store_path,
                construction_policy="open_bound",
                expected_database_identity=control._expected_gateway_identity,
                pre_mutation_hook=control.assert_local_mutation_ready,
                root_commit_hook=control.root_commit_hook,
            )
            local = store.inspect_root_state()
            fresh = root.snapshot()
            if fresh != snapshot:
                raise _AuthorityMismatch("active Root changed during gateway proof")
            proven = control._validated_component(
                fresh,
                local,
                require_active=True,
            )
            if (
                not _normal_local_state(local)
                or proven.recovery_floor is not None
                or proven.recovery_state_digest is not None
                or not _component_matches(proven, local)
            ):
                raise _AuthorityMismatch(
                    "active gateway proof does not match the Root"
                )
            control._attach_factory_store(store, ownership)
            control._publish_state(
                "provisioned_not_active",
                "active-installer-proof-verified",
                fresh,
                local,
            )
            return control
        except (
            InstallationRootError,
            DurableMediaRequestUnavailable,
            _AuthorityMismatch,
            KeyError,
            OSError,
            ValueError,
        ):
            _close_factory_resources(store, ownership)
            raise GatewayInstallationControlUnavailable(
                "cannot verify active gateway authority for installer"
            ) from None
        except BaseException:
            _close_factory_resources(store, ownership)
            raise

    @classmethod
    def provision(
        cls,
        root: InstallationRoot,
        store_path: str | os.PathLike[str],
    ) -> "GatewayInstallationControl":
        """Explicitly create/bind the gateway ledger during installation.

        The caller must already have validated that this is the intended
        elevated installer/first-run operation and that ``root`` came from the
        trusted Installation Root path.  Normal startup must never call this
        method.  Existing exact DB+anchor pairs are opened only to make an
        interrupted explicit provisioning attempt idempotent; partial pairs are
        rejected and no legacy migration is attempted.
        """

        store: DurableMediaRequestStore | None = None
        ownership: _GatewayLedgerOwnership | None = None
        try:
            snapshot = root.snapshot()
            if snapshot.status not in {"provisioning", "active"}:
                raise _AuthorityMismatch("root is not accepting provisioning")
            control = cls._from_snapshot(root, snapshot)
            component = snapshot.component("gateway")
            path = Path(os.path.abspath(os.fspath(store_path)))
            anchor_path = Path(f"{path}.rollback-anchor")
            database_exists = path.exists()
            anchor_exists = anchor_path.exists()
            if database_exists != anchor_exists:
                raise _AuthorityMismatch("partial gateway authority pair")
            if snapshot.status == "active" or component.bound:
                # Once a component binding exists, absence is authority loss,
                # never permission to mint a replacement ledger.  This also
                # covers a response-loss retry while the root still awaits the
                # remaining installation component bindings.
                if not database_exists:
                    raise _AuthorityMismatch("bound gateway authority is missing")
                policy = "open_bound"
            else:
                # Only an explicit provisioning root with an unbound,
                # preallocated gateway identity may create a fresh pair.
                policy = "open_bound" if database_exists else "create_bound"
            ownership = _GatewayLedgerOwnership.acquire(
                _ownership_path(
                    root, snapshot.installation_id, component.identity
                ),
                create_if_missing=(
                    snapshot.status == "provisioning" and not component.bound
                ),
                repair_incomplete_receipt=(
                    snapshot.status == "provisioning"
                    and not component.bound
                    and not database_exists
                    and not anchor_exists
                ),
            )
            store = DurableMediaRequestStore(
                path,
                construction_policy=policy,
                expected_database_identity=component.identity,
                pre_mutation_hook=control.assert_local_mutation_ready,
                root_commit_hook=control.root_commit_hook,
            )
            control._attach_factory_store(store, ownership)
            local = store.inspect_root_state()
            if not _normal_local_state(local) or local.mutation_sequence != 0:
                raise _AuthorityMismatch("provisioning ledger is not initial")
            result = root.bind_component(
                "gateway",
                installation_id=snapshot.installation_id,
                epoch=snapshot.epoch,
                identity=component.identity,
                sequence_floor=local.mutation_sequence,
                state_digest=local.state_digest,
                expected_root_revision=snapshot.root_revision,
            )
            if result.snapshot.status == "active":
                control.reconcile_startup()
            elif result.snapshot.status == "provisioning":
                control._publish_state(
                    "provisioned_not_active",
                    "awaiting-installation-activation",
                    result.snapshot,
                    local,
                )
            else:
                raise _AuthorityMismatch("root left provisioning unexpectedly")
            return control
        except (
            InstallationRootError,
            DurableMediaRequestUnavailable,
            _AuthorityMismatch,
            OSError,
            ValueError,
        ):
            _close_factory_resources(store, ownership)
            raise GatewayInstallationControlUnavailable(
                "cannot provision gateway authority"
            ) from None
        except BaseException:
            _close_factory_resources(store, ownership)
            raise

    def _attach_factory_store(
        self,
        store: DurableMediaRequestStore,
        ownership: _GatewayLedgerOwnership,
    ) -> None:
        with self._lock:
            if self._store is not None or self._ownership is not None:
                raise RuntimeError("gateway authority store is already attached")
            self._store = store
            self._ownership = ownership
            self._generation += 1

    @property
    def store(self) -> DurableMediaRequestStore:
        with self._lock:
            store = self._store
            mode = self._state.mode
            closing = self._closing
        if closing:
            raise GatewayInstallationControlUnavailable(
                "gateway authority is closing"
            )
        if store is None:
            raise GatewayInstallationControlUnavailable(
                "gateway authority store is not attached"
            )
        if mode == "provisioned_not_active":
            raise GatewayInstallationControlUnavailable(
                "gateway authority is awaiting activation"
            )
        return store

    def inspect_local_authority(self) -> DurableMediaRootState:
        """Read the local proof without granting a mutation capability."""

        with self._lock:
            store = self._store
            closing = self._closing
        if store is None or closing:
            raise GatewayInstallationControlUnavailable(
                "gateway authority store is not attached"
            )
        try:
            return store.inspect_root_state()
        except DurableMediaAuthorityCorruption:
            self._fuse("local-authority-corruption")
            raise GatewayInstallationControlUnavailable(
                "gateway local authority is structurally invalid"
            ) from None
        except DurableMediaRequestUnavailable:
            raise GatewayInstallationControlUnavailable(
                "gateway local authority is unavailable"
            ) from None

    @property
    def state(self) -> GatewayInstallationControlState:
        with self._lock:
            return self._state

    def assert_local_mutation_ready(self) -> None:
        """Reject a logical ledger write before SQLite changes when not ready."""

        with self._lock:
            if (
                self._state.mode != "ready"
                or self._store is None
                or self._ownership is None
                or self._closing
                or self._root_transition_in_flight
            ):
                raise DurableMediaRequestUnavailable(
                    "gateway paid-media mutation authority is unavailable"
                )

    def close(self) -> None:
        # The close lock serializes retries after an asynchronous BaseException.
        # ``_closing`` rejects new capabilities, while the attached references
        # and ownership handle remain intact until the store lock has drained
        # every write that already passed its pre-mutation gate and root hook.
        with self._close_lock:
            with self._lock:
                store = self._store
                ownership = self._ownership
                if store is None and ownership is None:
                    self._closing = False
                    return
                self._closing = True
                self._generation += 1
            try:
                if store is not None:
                    store.close()
                if ownership is not None:
                    ownership.close()
            except BaseException:
                # Do not detach on KeyboardInterrupt/SystemExit-like paths.
                # A retry can finish closing; in the meantime no new local or
                # outbound capability is granted and ownership remains held if
                # the interruption happened before its close completed.
                with self._lock:
                    self._generation += 1
                raise
            with self._lock:
                if self._store is store:
                    self._store = None
                if self._ownership is ownership:
                    self._ownership = None
                self._closing = False
                self._generation += 1
                if self._state.mode != "fused":
                    self._state = GatewayInstallationControlState(
                        mode="detached",
                        reason_code="store-closed",
                        installation_id=self._expected_installation_id,
                        epoch=self._expected_epoch,
                        database_identity=self._expected_gateway_identity,
                    )

    def _validated_component(
        self,
        snapshot: InstallationRootSnapshot,
        local: DurableMediaRootState,
        *,
        require_active: bool = True,
    ) -> ComponentState:
        if require_active and snapshot.status != "active":
            raise _AuthorityMismatch("root is not active")
        if (
            snapshot.installation_id != self._expected_installation_id
            or snapshot.epoch != self._expected_epoch
            or local.database_identity != self._expected_gateway_identity
        ):
            raise _AuthorityMismatch("installation authority identity drift")
        component = snapshot.component("gateway")
        if (
            not component.bound
            or component.identity != self._expected_gateway_identity
            or component.epoch != self._expected_epoch
            or not _is_digest(component.state_digest)
            or not _is_digest(local.state_digest)
        ):
            raise _AuthorityMismatch("gateway component binding drift")
        if _normal_local_state(local):
            return component
        if _manual_local_state(local):
            if (
                local.installation_id != self._expected_installation_id
                or local.epoch != self._expected_epoch
            ):
                raise _AuthorityMismatch("manual recovery receipt drift")
            return component
        raise _AuthorityMismatch("local authority mode is invalid")

    def _publish_state(
        self,
        mode: ControlMode,
        reason_code: str,
        snapshot: InstallationRootSnapshot,
        local: DurableMediaRootState,
    ) -> GatewayInstallationControlState:
        paid_principal = None
        if mode in {"ready", "manual_only"}:
            paid_principal = stable_paid_principal(snapshot.principal_digest)
        state = GatewayInstallationControlState(
            mode=mode,
            reason_code=reason_code,
            installation_id=snapshot.installation_id,
            epoch=snapshot.epoch,
            database_identity=local.database_identity,
            mutation_sequence=local.mutation_sequence,
            state_digest=local.state_digest,
            paid_principal=paid_principal,
        )
        with self._lock:
            if self._state.mode == "fused":
                return self._state
            self._state = state
            self._generation += 1
            return state

    def _publish_root_commit_state(
        self,
        snapshot: InstallationRootSnapshot,
        local: DurableMediaRootState,
    ) -> GatewayInstallationControlState:
        """Publish hook success only while the originating store is attached."""

        state = GatewayInstallationControlState(
            mode="ready",
            reason_code="authority-exact",
            installation_id=snapshot.installation_id,
            epoch=snapshot.epoch,
            database_identity=local.database_identity,
            mutation_sequence=local.mutation_sequence,
            state_digest=local.state_digest,
            paid_principal=stable_paid_principal(snapshot.principal_digest),
        )
        with self._lock:
            if (
                self._store is None
                or self._state.mode != "ready"
                or not self._root_transition_in_flight
            ):
                raise _AuthorityMismatch(
                    "controller lifecycle changed during root commit"
                )
            self._state = state
            self._generation += 1
            return state

    def _fuse(
        self,
        reason_code: str,
        *,
        local: DurableMediaRootState | None = None,
    ) -> GatewayInstallationControlState:
        with self._lock:
            if self._state.mode == "fused":
                return self._state
            self._state = GatewayInstallationControlState(
                mode="fused",
                reason_code=reason_code,
                installation_id=self._expected_installation_id,
                epoch=self._expected_epoch,
                database_identity=self._expected_gateway_identity,
                mutation_sequence=(None if local is None else local.mutation_sequence),
                state_digest=(None if local is None else local.state_digest),
            )
            self._generation += 1
            return self._state

    def reconcile_startup(self) -> GatewayInstallationControlState:
        """Align an opened strict ledger with the active Installation Root.

        A proven local ``root + 1`` state is first installed as a root recovery
        fence.  The ledger then durably advances once into ``manual_only`` and
        the fence is acknowledged.  ``manual_only`` is intentionally permanent
        in this controller; an operator workflow to clear it is out of scope.
        """

        with self._lock:
            if self._state.mode == "fused":
                return self._state
            store = self._store
            closing = self._closing
        if store is None or closing:
            raise GatewayInstallationControlUnavailable(
                "gateway authority is not attached for reconciliation"
            )
        local: DurableMediaRootState | None = None
        try:
            for _inspection in range(_MAX_RECONCILE_INSPECTIONS):
                local = store.inspect_root_state()
                snapshot = self._root.snapshot()
                if snapshot.status == "provisioning":
                    component = self._validated_component(
                        snapshot, local, require_active=False
                    )
                    if (
                        _normal_local_state(local)
                        and component.recovery_floor is None
                        and _component_matches(component, local)
                    ):
                        return self._publish_state(
                            "provisioned_not_active",
                            "awaiting-installation-activation",
                            snapshot,
                            local,
                        )
                    raise _AuthorityMismatch(
                        "provisioning gateway authority is not exact"
                    )
                component = self._validated_component(snapshot, local)

                if _normal_local_state(local):
                    if _component_matches(component, local):
                        if component.recovery_floor is None:
                            store.resume_after_root_reconcile(local)
                            return self._publish_state(
                                "ready", "authority-exact", snapshot, local
                            )
                        if (
                            component.recovery_floor != local.mutation_sequence
                            or component.recovery_state_digest != local.state_digest
                        ):
                            raise _AuthorityMismatch("root recovery fence drift")
                        manual = store.enter_authority_manual_only(
                            installation_id=snapshot.installation_id,
                            epoch=snapshot.epoch,
                            recovery_floor=local.mutation_sequence,
                            recovery_state_digest=local.state_digest,
                        )
                        try:
                            self._acknowledge_manual_recovery(snapshot, manual)
                        except InstallationRootError:
                            # The acknowledgement may have committed before its
                            # response was lost.  Only a fresh snapshot may
                            # decide whether to retry or accept it.
                            continue
                        continue

                    if (
                        component.recovery_floor is None
                        and local.mutation_sequence == component.sequence_floor + 1
                    ):
                        try:
                            self._root.verify_component(
                                "gateway",
                                installation_id=snapshot.installation_id,
                                epoch=snapshot.epoch,
                                identity=component.identity,
                                sequence_floor=local.mutation_sequence,
                                state_digest=local.state_digest,
                                previous_state_digest=component.state_digest,
                            )
                        except InstallationRootError:
                            # As above, a post-commit transport failure is
                            # resolved solely by the next validated snapshot.
                            continue
                        continue
                    raise _AuthorityMismatch("gateway floor gap is not recoverable")

                if _manual_local_state(local):
                    if (
                        _component_matches(component, local)
                        and component.recovery_floor is None
                    ):
                        store.resume_after_root_reconcile(local)
                        return self._publish_state(
                            "manual_only",
                            "manual-recovery-required",
                            snapshot,
                            local,
                        )
                    if (
                        component.sequence_floor == local.recovery_floor
                        and component.state_digest == local.recovery_state_digest
                        and component.recovery_floor == local.recovery_floor
                        and component.recovery_state_digest
                        == local.recovery_state_digest
                    ):
                        transition = DurableMediaRootTransition(
                            before=DurableMediaRootState(
                                database_identity=local.database_identity,
                                mutation_sequence=local.recovery_floor,
                                state_digest=str(local.recovery_state_digest),
                                authority_mode="normal",
                            ),
                            after=local,
                        )
                        try:
                            self._acknowledge_manual_recovery(snapshot, transition)
                        except InstallationRootError:
                            continue
                        continue
                    raise _AuthorityMismatch("manual recovery root state conflicts")
            raise _AuthorityMismatch("startup reconciliation did not converge")
        except InstallationRootError:
            raise GatewayInstallationControlUnavailable(
                "installation root is temporarily unavailable"
            ) from None
        except DurableMediaAuthorityCorruption:
            return self._fuse("local-authority-corruption", local=local)
        except DurableMediaRequestUnavailable:
            raise GatewayInstallationControlUnavailable(
                "gateway local authority is temporarily unavailable"
            ) from None
        except _AuthorityMismatch:
            return self._fuse("authority-mismatch", local=local)
        except Exception:
            raise GatewayInstallationControlUnavailable(
                "gateway authority reconciliation failed transiently"
            ) from None

    def _acknowledge_manual_recovery(
        self,
        snapshot: InstallationRootSnapshot,
        transition: DurableMediaRootTransition,
    ) -> None:
        self._root.acknowledge_component_recovery(
            "gateway",
            installation_id=snapshot.installation_id,
            epoch=snapshot.epoch,
            identity=transition.after.database_identity,
            recovery_floor=transition.before.mutation_sequence,
            recovery_state_digest=transition.before.state_digest,
            next_floor=transition.after.mutation_sequence,
            next_state_digest=transition.after.state_digest,
            expected_root_revision=snapshot.root_revision,
        )

    def _validate_transition(self, transition: DurableMediaRootTransition) -> None:
        if not isinstance(transition, DurableMediaRootTransition):
            raise _AuthorityMismatch("root transition type is invalid")
        before = transition.before
        after = transition.after
        if (
            not _normal_local_state(before)
            or not _normal_local_state(after)
            or before.database_identity != self._expected_gateway_identity
            or after.database_identity != self._expected_gateway_identity
            or after.mutation_sequence != before.mutation_sequence + 1
            or not _is_digest(before.state_digest)
            or not _is_digest(after.state_digest)
            or before.state_digest == after.state_digest
        ):
            raise _AuthorityMismatch("root transition is invalid")

    def root_commit_hook(self, transition: DurableMediaRootTransition) -> None:
        """Synchronously CAS one locally committed transition into the root.

        The store calls this while holding its write lock.  This method never
        calls back into the store.  At most four ``advance_component`` calls are
        made; every retry starts from a fresh root snapshot and branches only on
        typed state, never on exception strings.
        """

        failed_local = (
            transition.after
            if isinstance(transition, DurableMediaRootTransition)
            else None
        )
        confirmed = False
        try:
            self._validate_transition(transition)
            with self._lock:
                if self._state.mode != "ready" or self._root_transition_in_flight:
                    raise _AuthorityMismatch("controller is not ready for root commit")
                if (
                    self._state.mutation_sequence != transition.before.mutation_sequence
                    or self._state.state_digest != transition.before.state_digest
                ):
                    raise _AuthorityMismatch("controller transition proof is stale")
                self._root_transition_in_flight = True
                self._generation += 1

            cas_calls = 0
            for _inspection in range(_MAX_ROOT_CAS_CALLS + 1):
                try:
                    snapshot = self._root.snapshot()
                except InstallationRootError:
                    continue
                component = self._validated_component(snapshot, transition.after)
                if component.recovery_floor is not None:
                    raise _AuthorityMismatch("root has a recovery fence")
                if _component_matches(component, transition.after):
                    self._publish_root_commit_state(snapshot, transition.after)
                    confirmed = True
                    return
                if not _component_matches(component, transition.before):
                    raise _AuthorityMismatch("root is neither before nor after")
                if cas_calls >= _MAX_ROOT_CAS_CALLS:
                    break
                cas_calls += 1
                try:
                    result = self._root.advance_component(
                        "gateway",
                        installation_id=snapshot.installation_id,
                        epoch=snapshot.epoch,
                        identity=component.identity,
                        expected_floor=transition.before.mutation_sequence,
                        expected_state_digest=transition.before.state_digest,
                        next_floor=transition.after.mutation_sequence,
                        next_state_digest=transition.after.state_digest,
                        expected_root_revision=snapshot.root_revision,
                    )
                except InstallationRootError:
                    continue
                advanced = self._validated_component(
                    result.snapshot, transition.after
                )
                if (
                    advanced.recovery_floor is None
                    and _component_matches(advanced, transition.after)
                ):
                    self._publish_root_commit_state(
                        result.snapshot, transition.after
                    )
                    confirmed = True
                    return
            raise _AuthorityMismatch("root CAS did not converge")
        except Exception:
            self._fuse("root-commit-unconfirmed", local=failed_local)
            raise GatewayInstallationControlUnavailable(
                "gateway root commit could not be confirmed"
            ) from None
        finally:
            # DurableMediaRequestStore deliberately translates BaseException
            # from this hook into a pending-root result.  Guarantee that even
            # KeyboardInterrupt/SystemExit-like paths cannot leave a false
            # ready state after the local commit has become durable.
            if not confirmed:
                self._fuse("root-commit-unconfirmed", local=failed_local)
            with self._lock:
                self._root_transition_in_flight = False
                self._generation += 1

    def _outbound_sample_changed(
        self,
        generation: int,
        store: DurableMediaRequestStore,
    ) -> bool:
        with self._lock:
            return (
                self._state.mode == "ready"
                and self._store is store
                and (
                    self._generation != generation
                    or self._root_transition_in_flight
                )
            )

    def assert_outbound_ready(self) -> GatewayInstallationControlState:
        """Freshly prove exact authority immediately before remote dispatch."""

        for _inspection in range(_MAX_OUTBOUND_INSPECTIONS):
            with self._lock:
                state = self._state
                generation = self._generation
                store = self._store
                closing = self._closing
            if closing or state.mode != "ready":
                raise GatewayInstallationControlUnavailable(
                    "gateway outbound authority is unavailable"
                )
            if store is None:
                self._fuse("outbound-authority-unavailable")
                raise GatewayInstallationControlUnavailable(
                    "gateway outbound authority is unavailable"
                )
            try:
                local = store.inspect_root_state()
                snapshot = self._root.snapshot()
                component = self._validated_component(snapshot, local)
                if (
                    not _normal_local_state(local)
                    or component.recovery_floor is not None
                    or not _component_matches(component, local)
                ):
                    raise _AuthorityMismatch("outbound proof is not exact")
                store.resume_after_root_reconcile(local)
            except InstallationRootError:
                raise GatewayInstallationControlUnavailable(
                    "gateway outbound authority is unavailable"
                ) from None
            except DurableMediaAuthorityCorruption:
                if self._outbound_sample_changed(generation, store):
                    continue
                self._fuse(
                    "local-authority-corruption", local=locals().get("local")
                )
                raise GatewayInstallationControlUnavailable(
                    "gateway outbound authority is unavailable"
                ) from None
            except DurableMediaRequestUnavailable:
                if self._outbound_sample_changed(generation, store):
                    continue
                raise GatewayInstallationControlUnavailable(
                    "gateway outbound authority is unavailable"
                ) from None
            except _AuthorityMismatch:
                if self._outbound_sample_changed(generation, store):
                    continue
                self._fuse("outbound-authority-mismatch", local=locals().get("local"))
                raise GatewayInstallationControlUnavailable(
                    "gateway outbound authority is unavailable"
                ) from None
            except Exception:
                raise GatewayInstallationControlUnavailable(
                    "gateway outbound authority is unavailable"
                ) from None

            with self._lock:
                if (
                    self._state.mode == "ready"
                    and not self._closing
                    and not self._root_transition_in_flight
                    and (
                        self._generation == generation
                        or (
                            self._state.mutation_sequence
                            == local.mutation_sequence
                            and self._state.state_digest == local.state_digest
                        )
                    )
                ):
                    return self._publish_state(
                        "ready", "outbound-proof-fresh", snapshot, local
                    )
            # A completed concurrent local/root transition invalidated this
            # inspection.  Re-inspect a coherent store snapshot before deciding.
        raise GatewayInstallationControlUnavailable(
            "gateway outbound authority is unavailable"
        )


__all__ = [
    "GatewayInstallationControl",
    "GatewayInstallationControlState",
    "GatewayInstallationControlUnavailable",
    "stable_paid_principal",
]
