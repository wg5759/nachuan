"""Installation Root coordination for the channel-media request authority.

The controller owns only the ``channel_media`` component.  Normal runtime must
use :meth:`open_bound`; :meth:`provision` is reserved for an explicit installer
flow and is the only entry point allowed to create the database/anchor pair.
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

from gateway.channel_media_requests import DurableChannelMediaRequestStore
from gateway.durable_media_requests import (
    DurableMediaAuthorityCorruption,
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


_COMPONENT = "channel_media"
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_ZERO_DIGEST = "0" * 64
_MAX_ROOT_CAS_CALLS = 4
_MAX_RECONCILE_INSPECTIONS = 5
_MAX_PROVIDER_INSPECTIONS = 4
_OWNERSHIP_MAGIC = b"NACHUAN_CHANNEL_MEDIA_LEDGER_OWNER_V1\n"

ControlMode = Literal[
    "detached",
    "provisioned_not_active",
    "ready",
    "manual_only",
    "fused",
]


class ChannelMediaInstallationControlUnavailable(RuntimeError):
    """Channel-media provider authority cannot currently be proven safe."""


class _AuthorityMismatch(RuntimeError):
    pass


def _is_reparse_or_symlink(info: os.stat_result) -> bool:
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(info.st_mode) or bool(
        int(getattr(info, "st_file_attributes", 0)) & reparse
    )


class _ChannelMediaWriterOwnership:
    """Crash-released cross-process ownership of one channel ledger."""

    def __init__(self, path: Path, descriptor: int) -> None:
        self.path = path
        self._descriptor = descriptor
        self._close_lock = RLock()

    @staticmethod
    def _assert_plain_path(path: Path, *, must_exist: bool) -> None:
        parent = os.lstat(path.parent)
        if not stat.S_ISDIR(parent.st_mode) or _is_reparse_or_symlink(parent):
            raise OSError("channel ownership parent is not a plain directory")
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            if must_exist:
                raise
            return
        if not stat.S_ISREG(info.st_mode) or _is_reparse_or_symlink(info):
            raise OSError("channel ownership path is not a plain file")

    @classmethod
    def acquire(
        cls,
        path: Path,
        *,
        create_if_missing: bool,
        repair_incomplete_receipt: bool = False,
    ) -> "_ChannelMediaWriterOwnership":
        path = Path(os.path.abspath(os.fspath(path)))
        exists = path.exists()
        if not exists and not create_if_missing:
            raise OSError("channel ownership file is missing")
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
                raise OSError("channel ownership identity changed")
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
                        raise OSError("channel ownership receipt is invalid")
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
                    raise OSError("channel ownership ACL is invalid") from exc
            if initialize_receipt:
                os.lseek(descriptor, 0, os.SEEK_SET)
                cls._write_receipt(descriptor)
                if os.name == "nt":
                    try:
                        assert_restricted_windows_handle_acl(
                            descriptor, directory=False
                        )
                    except SecureStorageError as exc:
                        raise OSError("channel ownership ACL is invalid") from exc
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
                raise OSError("channel ownership receipt write was incomplete")
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
            | (generic_write | write_dac | write_owner if writable else 0),
            0,
            None,
            create_new if create else open_existing,
            file_attribute_normal | file_flag_open_reparse_point,
            None,
        )
        if handle in (None, invalid_handle):
            raise OSError(
                ctypes.get_last_error(),
                "cannot acquire channel-media ledger ownership",
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


def _ownership_path(
    root: InstallationRoot,
    installation_id: str,
    database_identity: str,
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
    if not _is_digest(installation_id) or not _is_digest(database_identity):
        raise OSError("channel ownership identity is invalid")
    root_info = os.lstat(candidate)
    if not stat.S_ISREG(root_info.st_mode) or _is_reparse_or_symlink(root_info):
        raise OSError("installation root identity is invalid for ownership")
    device = int(root_info.st_dev)
    inode = int(root_info.st_ino)
    if device < 0 or inode < 0:
        raise OSError("installation root file identity is invalid")
    identity_bytes = f"{device:x}:{inode:x}".encode("ascii")
    ownership_digest = sha256(
        b"nachuan.channel-media-ledger-ownership-path.v1\x00"
        + len(identity_bytes).to_bytes(4, "big")
        + identity_bytes
        + bytes.fromhex(installation_id)
        + bytes.fromhex(database_identity)
    ).hexdigest()
    dependencies = getattr(authority, "dependencies", None)
    trusted_boundary = getattr(dependencies, "trusted_boundary", None)
    if not callable(trusted_boundary):
        raise OSError("installation root trusted boundary is unavailable")
    boundary = Path(trusted_boundary(candidate))
    if not boundary.is_absolute() or ".." in boundary.parts:
        raise OSError("installation root trusted boundary is invalid")
    return boundary / f".channel-media-{ownership_digest}.writer-owner"


def _close_factory_resources(
    store: DurableChannelMediaRequestStore | None,
    ownership: _ChannelMediaWriterOwnership | None,
) -> None:
    try:
        if store is not None:
            store.close()
    finally:
        if ownership is not None:
            ownership.close()


@dataclass(frozen=True, slots=True)
class ChannelMediaInstallationControlState:
    mode: ControlMode
    reason_code: str
    installation_id: str | None = None
    epoch: int | None = None
    database_identity: str | None = None
    mutation_sequence: int | None = None
    state_digest: str | None = None

    @property
    def provider_dispatch_ready(self) -> bool:
        return self.mode == "ready"


class ChannelMediaInstallationControl:
    """Fail-closed Root controller for one channel-media request database."""

    def __init__(
        self,
        root: InstallationRoot,
        *,
        expected_installation_id: str,
        expected_epoch: int,
        expected_database_identity: str,
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
        if not _is_digest(expected_database_identity):
            raise ValueError("expected channel-media identity is invalid")
        self._root = root
        self._expected_installation_id = expected_installation_id
        self._expected_epoch = expected_epoch
        self._expected_database_identity = expected_database_identity
        self._store: DurableChannelMediaRequestStore | None = None
        self._ownership: _ChannelMediaWriterOwnership | None = None
        self._lock = RLock()
        self._close_lock = RLock()
        self._closing = False
        self._generation = 0
        self._root_transition_in_flight = False
        self._state = ChannelMediaInstallationControlState(
            mode="detached",
            reason_code="store-not-attached",
            installation_id=expected_installation_id,
            epoch=expected_epoch,
            database_identity=expected_database_identity,
        )

    @classmethod
    def _from_snapshot(
        cls,
        root: InstallationRoot,
        snapshot: InstallationRootSnapshot,
    ) -> "ChannelMediaInstallationControl":
        component = snapshot.component(_COMPONENT)
        return cls(
            root,
            expected_installation_id=snapshot.installation_id,
            expected_epoch=snapshot.epoch,
            expected_database_identity=component.identity,
        )

    @classmethod
    def open_bound(
        cls,
        root: InstallationRoot,
        store_path: str | os.PathLike[str],
    ) -> "ChannelMediaInstallationControl":
        store: DurableChannelMediaRequestStore | None = None
        ownership: _ChannelMediaWriterOwnership | None = None
        try:
            snapshot = root.snapshot()
            control = cls._from_snapshot(root, snapshot)
            ownership = _ChannelMediaWriterOwnership.acquire(
                _ownership_path(
                    root,
                    control._expected_installation_id,
                    control._expected_database_identity,
                ),
                create_if_missing=False,
            )
            store = DurableChannelMediaRequestStore(
                store_path,
                construction_policy="open_bound",
                expected_database_identity=control._expected_database_identity,
                pre_mutation_hook=control.assert_local_mutation_ready,
                root_commit_hook=control.root_commit_hook,
            )
            control._store = store
            control._ownership = ownership
            control._generation += 1
        except (InstallationRootError, DurableMediaRequestUnavailable, OSError, ValueError):
            _close_factory_resources(store, ownership)
            raise ChannelMediaInstallationControlUnavailable(
                "cannot open bound channel-media authority"
            ) from None
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
    def verify_bound_for_active_installer(
        cls,
        root: InstallationRoot,
        store_path: str | os.PathLike[str],
    ) -> "ChannelMediaInstallationControl":
        """Open-only exact proof for an installer/update over active Root.

        Unlike normal runtime ``open_bound``, this path never reconciles a
        local +1 state, installs a recovery fence, or resumes the store.  The
        returned controller deliberately remains non-writable until closed.
        """

        store: DurableChannelMediaRequestStore | None = None
        ownership: _ChannelMediaWriterOwnership | None = None
        try:
            snapshot = root.snapshot()
            if (
                snapshot.status != "active"
                or snapshot.lock_kind != "none"
                or snapshot.reanchor_pending
            ):
                raise _AuthorityMismatch("root is not in the active proof state")
            component = snapshot.component(_COMPONENT)
            if not component.bound:
                raise _AuthorityMismatch("active channel-media component is not bound")
            control = cls._from_snapshot(root, snapshot)
            ownership = _ChannelMediaWriterOwnership.acquire(
                _ownership_path(
                    root,
                    control._expected_installation_id,
                    control._expected_database_identity,
                ),
                create_if_missing=False,
            )
            store = DurableChannelMediaRequestStore(
                store_path,
                construction_policy="open_bound",
                expected_database_identity=control._expected_database_identity,
                pre_mutation_hook=control.assert_local_mutation_ready,
                root_commit_hook=control.root_commit_hook,
            )
            local = store.inspect_root_state()
            fresh = root.snapshot()
            if fresh != snapshot:
                raise _AuthorityMismatch(
                    "active Root changed during channel-media proof"
                )
            proven = control._validated_component(fresh, local)
            if (
                not _normal_local_state(local)
                or proven.recovery_floor is not None
                or proven.recovery_state_digest is not None
                or not _component_matches(proven, local)
            ):
                raise _AuthorityMismatch(
                    "active channel-media proof does not match the Root"
                )
            control._store = store
            control._ownership = ownership
            control._generation += 1
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
            raise ChannelMediaInstallationControlUnavailable(
                "cannot verify active channel-media authority for installer"
            ) from None
        except BaseException:
            _close_factory_resources(store, ownership)
            raise

    @classmethod
    def provision(
        cls,
        root: InstallationRoot,
        store_path: str | os.PathLike[str],
    ) -> "ChannelMediaInstallationControl":
        store: DurableChannelMediaRequestStore | None = None
        ownership: _ChannelMediaWriterOwnership | None = None
        try:
            snapshot = root.snapshot()
            component_addition = (
                snapshot.status == "maintenance_locked"
                and snapshot.lock_kind == "component_addition"
                and not snapshot.component(_COMPONENT).bound
            )
            if (
                snapshot.status not in {"provisioning", "active"}
                and not component_addition
            ):
                raise _AuthorityMismatch("root is not accepting provisioning")
            control = cls._from_snapshot(root, snapshot)
            component = snapshot.component(_COMPONENT)
            path = Path(os.path.abspath(os.fspath(store_path)))
            anchor_path = Path(f"{path}.rollback-anchor")
            database_exists = path.exists()
            anchor_exists = anchor_path.exists()
            if database_exists != anchor_exists:
                raise _AuthorityMismatch("partial channel-media authority pair")
            if snapshot.status == "active" or component.bound:
                if not database_exists:
                    raise _AuthorityMismatch("bound channel-media authority is missing")
                policy = "open_bound"
            else:
                policy = "open_bound" if database_exists else "create_bound"
            ownership = _ChannelMediaWriterOwnership.acquire(
                _ownership_path(
                    root,
                    snapshot.installation_id,
                    component.identity,
                ),
                create_if_missing=(
                    snapshot.status in {"provisioning", "maintenance_locked"}
                    and not component.bound
                ),
                repair_incomplete_receipt=(
                    snapshot.status in {"provisioning", "maintenance_locked"}
                    and not component.bound
                    and not database_exists
                    and not anchor_exists
                ),
            )
            store = DurableChannelMediaRequestStore(
                path,
                construction_policy=policy,
                expected_database_identity=component.identity,
                pre_mutation_hook=control.assert_local_mutation_ready,
                root_commit_hook=control.root_commit_hook,
            )
            control._store = store
            control._ownership = ownership
            control._generation += 1
            local = store.inspect_root_state()
            if not _normal_local_state(local) or local.mutation_sequence != 0:
                raise _AuthorityMismatch("provisioning channel-media ledger is not initial")
            result = root.bind_component(
                _COMPONENT,
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
            raise ChannelMediaInstallationControlUnavailable(
                "cannot provision channel-media authority"
            ) from None
        except BaseException:
            _close_factory_resources(store, ownership)
            raise

    @property
    def state(self) -> ChannelMediaInstallationControlState:
        with self._lock:
            return self._state

    @property
    def store(self) -> DurableChannelMediaRequestStore:
        with self._lock:
            store = self._store
            ownership = self._ownership
            mode = self._state.mode
            closing = self._closing
        if (
            store is None
            or ownership is None
            or closing
            or mode not in {"ready", "manual_only"}
        ):
            raise ChannelMediaInstallationControlUnavailable(
                "channel-media authority store is unavailable"
            )
        return store

    def inspect_local_authority(self) -> DurableMediaRootState:
        with self._lock:
            store = self._store
            closing = self._closing
        if store is None or closing:
            raise ChannelMediaInstallationControlUnavailable(
                "channel-media authority store is not attached"
            )
        try:
            return store.inspect_root_state()
        except DurableMediaAuthorityCorruption:
            self._fuse("local-authority-corruption")
            raise ChannelMediaInstallationControlUnavailable(
                "channel-media local authority is structurally invalid"
            ) from None
        except DurableMediaRequestUnavailable:
            raise ChannelMediaInstallationControlUnavailable(
                "channel-media local authority is unavailable"
            ) from None

    def _publish_state(
        self,
        mode: ControlMode,
        reason_code: str,
        snapshot: InstallationRootSnapshot,
        local: DurableMediaRootState,
    ) -> ChannelMediaInstallationControlState:
        state = ChannelMediaInstallationControlState(
            mode=mode,
            reason_code=reason_code,
            installation_id=snapshot.installation_id,
            epoch=snapshot.epoch,
            database_identity=local.database_identity,
            mutation_sequence=local.mutation_sequence,
            state_digest=local.state_digest,
        )
        with self._lock:
            if self._state.mode == "fused":
                return self._state
            self._state = state
            self._generation += 1
            return state

    def _fuse(self, reason_code: str) -> ChannelMediaInstallationControlState:
        with self._lock:
            if self._state.mode != "fused":
                self._state = ChannelMediaInstallationControlState(
                    mode="fused",
                    reason_code=reason_code,
                    installation_id=self._expected_installation_id,
                    epoch=self._expected_epoch,
                    database_identity=self._expected_database_identity,
                )
                self._generation += 1
            return self._state

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
            or local.database_identity != self._expected_database_identity
        ):
            raise _AuthorityMismatch("installation authority identity drift")
        component = snapshot.component(_COMPONENT)
        if (
            not component.bound
            or component.identity != self._expected_database_identity
            or component.epoch != self._expected_epoch
            or not _is_digest(component.state_digest)
            or not _is_digest(local.state_digest)
        ):
            raise _AuthorityMismatch("channel-media component binding drift")
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

    def _acknowledge_manual_recovery(
        self,
        snapshot: InstallationRootSnapshot,
        transition: DurableMediaRootTransition,
    ) -> None:
        self._root.acknowledge_component_recovery(
            _COMPONENT,
            installation_id=snapshot.installation_id,
            epoch=snapshot.epoch,
            identity=transition.after.database_identity,
            recovery_floor=transition.before.mutation_sequence,
            recovery_state_digest=transition.before.state_digest,
            next_floor=transition.after.mutation_sequence,
            next_state_digest=transition.after.state_digest,
            expected_root_revision=snapshot.root_revision,
        )

    def reconcile_startup(self) -> ChannelMediaInstallationControlState:
        """Converge a strict local proof with Root or fuse on identity drift."""

        with self._lock:
            if self._state.mode == "fused":
                return self._state
            store = self._store
            closing = self._closing
        if store is None or closing:
            raise ChannelMediaInstallationControlUnavailable(
                "channel-media authority is not attached for reconciliation"
            )
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
                        "provisioning channel-media authority is not exact"
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
                        store.enter_authority_manual_only(
                            installation_id=snapshot.installation_id,
                            epoch=snapshot.epoch,
                            recovery_floor=local.mutation_sequence,
                            recovery_state_digest=local.state_digest,
                        )
                        continue

                    if (
                        component.recovery_floor is None
                        and local.mutation_sequence == component.sequence_floor + 1
                    ):
                        try:
                            self._root.verify_component(
                                _COMPONENT,
                                installation_id=snapshot.installation_id,
                                epoch=snapshot.epoch,
                                identity=component.identity,
                                sequence_floor=local.mutation_sequence,
                                state_digest=local.state_digest,
                                previous_state_digest=component.state_digest,
                            )
                        except InstallationRootError:
                            continue
                        continue
                    raise _AuthorityMismatch(
                        "channel-media floor gap is not recoverable"
                    )

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
                                mutation_sequence=int(local.recovery_floor),
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
                    raise _AuthorityMismatch(
                        "manual channel-media recovery conflicts with Root"
                    )
                raise _AuthorityMismatch("local authority mode is invalid")
            raise _AuthorityMismatch("startup reconciliation did not converge")
        except InstallationRootError:
            raise ChannelMediaInstallationControlUnavailable(
                "installation root is temporarily unavailable"
            ) from None
        except DurableMediaAuthorityCorruption:
            return self._fuse("local-authority-corruption")
        except DurableMediaRequestUnavailable:
            raise ChannelMediaInstallationControlUnavailable(
                "channel-media local authority is temporarily unavailable"
            ) from None
        except _AuthorityMismatch:
            return self._fuse("authority-mismatch")
        except Exception:
            raise ChannelMediaInstallationControlUnavailable(
                "channel-media authority reconciliation failed transiently"
            ) from None

    def assert_local_mutation_ready(self) -> None:
        with self._lock:
            if (
                self._state.mode != "ready"
                or self._store is None
                or self._ownership is None
                or self._closing
                or self._root_transition_in_flight
            ):
                raise DurableMediaRequestUnavailable(
                    "channel-media mutation authority is unavailable"
                )

    def _validate_transition(self, transition: DurableMediaRootTransition) -> None:
        if not isinstance(transition, DurableMediaRootTransition):
            raise _AuthorityMismatch("root transition type is invalid")
        before = transition.before
        after = transition.after
        if (
            not _normal_local_state(before)
            or not _normal_local_state(after)
            or before.database_identity != self._expected_database_identity
            or after.database_identity != self._expected_database_identity
            or after.mutation_sequence != before.mutation_sequence + 1
            or not _is_digest(before.state_digest)
            or not _is_digest(after.state_digest)
            or before.state_digest == after.state_digest
        ):
            raise _AuthorityMismatch("root transition is invalid")

    def root_commit_hook(self, transition: DurableMediaRootTransition) -> None:
        """Synchronously confirm one committed local transition in Root."""

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
                    self._publish_state(
                        "ready", "authority-exact", snapshot, transition.after
                    )
                    confirmed = True
                    return
                if not _component_matches(component, transition.before):
                    raise _AuthorityMismatch("root is neither before nor after")
                if cas_calls >= _MAX_ROOT_CAS_CALLS:
                    break
                cas_calls += 1
                try:
                    result = self._root.advance_component(
                        _COMPONENT,
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
                    self._publish_state(
                        "ready", "authority-exact", result.snapshot, transition.after
                    )
                    confirmed = True
                    return
            raise _AuthorityMismatch("root CAS did not converge")
        except Exception:
            self._fuse("root-commit-unconfirmed")
            raise ChannelMediaInstallationControlUnavailable(
                "channel-media root commit could not be confirmed"
            ) from None
        finally:
            if not confirmed:
                self._fuse("root-commit-unconfirmed")
            with self._lock:
                self._root_transition_in_flight = False
                self._generation += 1

    def _provider_sample_changed(
        self,
        generation: int,
        store: DurableChannelMediaRequestStore,
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

    def assert_provider_dispatch_ready(
        self,
    ) -> ChannelMediaInstallationControlState:
        """Freshly prove exact Root/local authority before provider dispatch."""

        for _inspection in range(_MAX_PROVIDER_INSPECTIONS):
            with self._lock:
                state = self._state
                generation = self._generation
                store = self._store
                closing = self._closing
            if closing or state.mode != "ready" or store is None:
                raise ChannelMediaInstallationControlUnavailable(
                    "channel-media provider authority is unavailable"
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
                    raise _AuthorityMismatch("provider proof is not exact")
                store.resume_after_root_reconcile(local)
            except InstallationRootError:
                raise ChannelMediaInstallationControlUnavailable(
                    "channel-media provider authority is unavailable"
                ) from None
            except DurableMediaAuthorityCorruption:
                if self._provider_sample_changed(generation, store):
                    continue
                self._fuse("local-authority-corruption")
                raise ChannelMediaInstallationControlUnavailable(
                    "channel-media provider authority is unavailable"
                ) from None
            except DurableMediaRequestUnavailable:
                if self._provider_sample_changed(generation, store):
                    continue
                raise ChannelMediaInstallationControlUnavailable(
                    "channel-media provider authority is unavailable"
                ) from None
            except _AuthorityMismatch:
                if self._provider_sample_changed(generation, store):
                    continue
                self._fuse("provider-authority-mismatch")
                raise ChannelMediaInstallationControlUnavailable(
                    "channel-media provider authority is unavailable"
                ) from None
            except Exception:
                raise ChannelMediaInstallationControlUnavailable(
                    "channel-media provider authority is unavailable"
                ) from None

            with self._lock:
                if (
                    self._state.mode == "ready"
                    and not self._closing
                    and not self._root_transition_in_flight
                    and (
                        self._generation == generation
                        or (
                            self._state.mutation_sequence == local.mutation_sequence
                            and self._state.state_digest == local.state_digest
                        )
                    )
                ):
                    return self._publish_state(
                        "ready", "provider-proof-fresh", snapshot, local
                    )
        raise ChannelMediaInstallationControlUnavailable(
            "channel-media provider authority is unavailable"
        )

    def close(self) -> None:
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
                # Keep the attached reference and the closed gate so a later
                # lifecycle retry can finish draining the same store.
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
                    self._state = ChannelMediaInstallationControlState(
                        mode="detached",
                        reason_code="store-closed",
                        installation_id=self._expected_installation_id,
                        epoch=self._expected_epoch,
                        database_identity=self._expected_database_identity,
                    )


__all__ = [
    "ChannelMediaInstallationControl",
    "ChannelMediaInstallationControlState",
    "ChannelMediaInstallationControlUnavailable",
]
