"""Fail-closed Root-v4 controller boundary for the private Asset Store.

This module deliberately owns only the ``gateway_assets`` component.  It is
kept separate from :mod:`gateway.gateway_installation_control` because the two
stores have different recovery and read-capability semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import stat
from threading import RLock
from typing import Literal

from gateway.installation_root import (
    InstallationRoot,
    InstallationRootError,
    InstallationRootSnapshot,
)
from gateway.paid_media_asset_store import (
    DEFAULT_ASSET_STORE_DEPENDENCIES,
    PaidMediaAssetRootState,
    PaidMediaAssetRootTransition,
    PaidMediaAssetStore,
    PaidMediaAssetStoreDependencies,
    PaidMediaAssetStoreError,
)
from gateway.secure_store import (
    SecureStorageError,
    assert_restricted_windows_handle_acl,
    harden_restricted_windows_handle_acl,
)


_MAX_ROOT_CAS_CALLS = 4
_OWNERSHIP_MAGIC = b"NACHUAN_ASSET_STORE_OWNER_V1\n"

AssetControlMode = Literal[
    "detached",
    "provisioned_not_active",
    "ready",
    "manual_only",
    "fused",
]


class AssetInstallationControlUnavailable(RuntimeError):
    """The private Asset Store authority cannot currently be proven safe."""


def _is_reparse_or_symlink(info: os.stat_result) -> bool:
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(info.st_mode) or bool(
        int(getattr(info, "st_file_attributes", 0)) & reparse
    )


class _AssetWriterOwnership:
    """Crash-released, cross-process ownership for one private Asset Store."""

    def __init__(self, path: Path, descriptor: int) -> None:
        self.path = path
        self._descriptor = descriptor
        self._close_lock = RLock()

    @staticmethod
    def _assert_plain_path(path: Path, *, must_exist: bool) -> None:
        parent = os.lstat(path.parent)
        if not stat.S_ISDIR(parent.st_mode) or _is_reparse_or_symlink(parent):
            raise OSError("asset ownership parent is invalid")
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            if must_exist:
                raise
            return
        if not stat.S_ISREG(info.st_mode) or _is_reparse_or_symlink(info):
            raise OSError("asset ownership path is invalid")

    @classmethod
    def acquire(
        cls,
        path: Path,
        *,
        create_if_missing: bool,
        repair_incomplete_receipt: bool = False,
    ) -> "_AssetWriterOwnership":
        path = Path(os.path.abspath(os.fspath(path)))
        exists = path.exists()
        if not exists and not create_if_missing:
            raise OSError("asset ownership receipt is missing")
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
                raise OSError("asset ownership identity changed")
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
                        raise OSError("asset ownership receipt is invalid")
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
                    raise OSError("asset ownership ACL is invalid") from exc
            if initialize_receipt:
                os.lseek(descriptor, 0, os.SEEK_SET)
                cls._write_receipt(descriptor)
                if os.name == "nt":
                    try:
                        assert_restricted_windows_handle_acl(
                            descriptor, directory=False
                        )
                    except SecureStorageError as exc:
                        raise OSError("asset ownership ACL is invalid") from exc
            return cls(path, descriptor)
        except BaseException:
            os.close(descriptor)
            raise

    @staticmethod
    def _write_receipt(descriptor: int) -> None:
        remaining = memoryview(_OWNERSHIP_MAGIC)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("asset ownership receipt write was incomplete")
            remaining = remaining[written:]
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
                ctypes.get_last_error(), "cannot acquire asset writer ownership"
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
    asset_identity: str,
) -> Path:
    authority = root
    root_path = getattr(authority, "path", None)
    if root_path is None:
        authority = getattr(root, "root", None)
        root_path = getattr(authority, "path", None)
    if root_path is None:
        raise OSError("installation Root path is unavailable for asset ownership")
    candidate = Path(root_path)
    root_info = os.lstat(candidate)
    if (
        not candidate.is_absolute()
        or ".." in candidate.parts
        or not stat.S_ISREG(root_info.st_mode)
        or _is_reparse_or_symlink(root_info)
    ):
        raise OSError("installation Root path is invalid for asset ownership")
    try:
        installation_bytes = bytes.fromhex(installation_id)
        identity_bytes = bytes.fromhex(asset_identity)
    except ValueError as exc:
        raise OSError("asset ownership identity is invalid") from exc
    if len(installation_bytes) != 32 or len(identity_bytes) != 32:
        raise OSError("asset ownership identity is invalid")
    file_identity = f"{int(root_info.st_dev):x}:{int(root_info.st_ino):x}".encode(
        "ascii"
    )
    ownership_digest = sha256(
        b"nachuan.asset-store-ownership-path.v1\x00"
        + len(file_identity).to_bytes(4, "big")
        + file_identity
        + installation_bytes
        + identity_bytes
    ).hexdigest()
    dependencies = getattr(authority, "dependencies", None)
    trusted_boundary = getattr(dependencies, "trusted_boundary", None)
    if not callable(trusted_boundary):
        raise OSError("installation Root trusted boundary is unavailable")
    boundary = Path(trusted_boundary(candidate))
    if not boundary.is_absolute() or ".." in boundary.parts:
        raise OSError("installation Root trusted boundary is invalid")
    return boundary / f".assets-{ownership_digest}.writer-owner"


def _close_factory_resources(
    store: PaidMediaAssetStore | None,
    ownership: _AssetWriterOwnership | None,
) -> None:
    try:
        if store is not None:
            store.close()
    finally:
        if ownership is not None:
            ownership.close()


@dataclass(frozen=True, slots=True)
class AssetInstallationControlState:
    mode: AssetControlMode
    reason_code: str
    installation_id: str | None = None
    epoch: int | None = None
    database_identity: str | None = None
    mutation_sequence: int | None = None
    state_digest: str | None = None

    @property
    def mutation_ready(self) -> bool:
        return self.mode == "ready"


class AssetInstallationControl:
    """Construction boundary for one Root-bound paid-media Asset Store."""

    def __init__(
        self,
        root: InstallationRoot,
        snapshot: InstallationRootSnapshot,
    ) -> None:
        component = snapshot.component("gateway_assets")
        self._root = root
        self._expected_installation_id = snapshot.installation_id
        self._expected_epoch = snapshot.epoch
        self._expected_database_identity = component.identity
        self._store: PaidMediaAssetStore | None = None
        self._ownership: _AssetWriterOwnership | None = None
        self._lock = RLock()
        self._close_lock = RLock()
        self._closing = False
        self._root_transition_in_flight = False
        self._state = AssetInstallationControlState(
            mode="detached",
            reason_code="store-not-attached",
            installation_id=snapshot.installation_id,
            epoch=snapshot.epoch,
            database_identity=component.identity,
        )

    @classmethod
    def _store_arguments(
        cls,
        control: "AssetInstallationControl",
        dependencies: PaidMediaAssetStoreDependencies,
    ) -> dict[str, object]:
        return {
            "installation_id": control._expected_installation_id,
            "epoch": control._expected_epoch,
            "expected_database_identity": control._expected_database_identity,
            "dependencies": dependencies,
            "pre_mutation_hook": control.assert_local_mutation_ready,
            "root_commit_hook": control.root_commit_hook,
        }

    @classmethod
    def open_bound(
        cls,
        root: InstallationRoot,
        store_path: str | os.PathLike[str],
        *,
        store_dependencies: PaidMediaAssetStoreDependencies = DEFAULT_ASSET_STORE_DEPENDENCIES,
    ) -> "AssetInstallationControl":
        """Open-only runtime entry; never create a missing store or Root bind."""

        path = Path(os.path.abspath(os.fspath(store_path)))
        store: PaidMediaAssetStore | None = None
        ownership: _AssetWriterOwnership | None = None
        try:
            snapshot = root.snapshot()
            control = cls(root, snapshot)
            if not path.is_dir():
                raise OSError("bound asset-store directory is missing")
            ownership = _AssetWriterOwnership.acquire(
                _ownership_path(
                    root,
                    snapshot.installation_id,
                    snapshot.component("gateway_assets").identity,
                ),
                create_if_missing=False,
            )
            control._attach_ownership(ownership)
            store = PaidMediaAssetStore.open_bound(
                path,
                **cls._store_arguments(control, store_dependencies),
            )
            control._attach_store(store)
            control.reconcile_startup()
            return control
        except (
            InstallationRootError,
            PaidMediaAssetStoreError,
            AssetInstallationControlUnavailable,
            OSError,
            TypeError,
            ValueError,
        ):
            _close_factory_resources(store, ownership)
            raise AssetInstallationControlUnavailable(
                "cannot open bound asset authority"
            ) from None
        except BaseException:
            _close_factory_resources(store, ownership)
            raise

    @classmethod
    def verify_bound_for_component_addition(
        cls,
        root: InstallationRoot,
        store_path: str | os.PathLike[str],
        *,
        store_dependencies: PaidMediaAssetStoreDependencies = DEFAULT_ASSET_STORE_DEPENDENCIES,
    ) -> "AssetInstallationControl":
        """Installer-only exact proof of legacy assets during v5 addition.

        Existing directory, database, rollback anchor, and ownership receipt are
        opened strictly.  No create, repair, Root mutation, recovery transition,
        or local resume is permitted, and the returned controller intentionally
        remains non-writable until it is closed.
        """

        path = Path(os.path.abspath(os.fspath(store_path)))
        store: PaidMediaAssetStore | None = None
        ownership: _AssetWriterOwnership | None = None
        try:
            snapshot = root.snapshot()
            if (
                snapshot.status != "maintenance_locked"
                or snapshot.lock_kind != "component_addition"
                or snapshot.reanchor_pending
            ):
                raise AssetInstallationControlUnavailable(
                    "Root is not in the component-addition proof state"
                )
            component = snapshot.component("gateway_assets")
            if not component.bound:
                raise AssetInstallationControlUnavailable(
                    "legacy asset component is not bound"
                )
            control = cls(root, snapshot)
            if not path.is_dir():
                raise OSError("bound asset-store directory is missing")
            ownership = _AssetWriterOwnership.acquire(
                _ownership_path(
                    root,
                    snapshot.installation_id,
                    component.identity,
                ),
                create_if_missing=False,
            )
            store = PaidMediaAssetStore.open_bound(
                path,
                **cls._store_arguments(control, store_dependencies),
            )
            local = store.inspect_root_state()
            fresh = root.snapshot()
            if fresh != snapshot:
                raise AssetInstallationControlUnavailable(
                    "component-addition Root changed during asset proof"
                )
            proven = control._validated_component(fresh)
            if (
                local.installation_id != fresh.installation_id
                or local.epoch != fresh.epoch
                or local.database_identity != proven.identity
                or local.authority_mode != "normal"
                or local.recovery_floor is not None
                or local.recovery_state_digest is not None
                or proven.recovery_floor is not None
                or proven.recovery_state_digest is not None
                or not control._proof_matches(proven, local)
            ):
                raise AssetInstallationControlUnavailable(
                    "legacy asset proof does not match the Root"
                )
            control._attach_ownership(ownership)
            control._attach_store(store)
            control._publish(
                "provisioned_not_active",
                "component-addition-proof-verified",
                local,
            )
            return control
        except (
            InstallationRootError,
            PaidMediaAssetStoreError,
            AssetInstallationControlUnavailable,
            KeyError,
            OSError,
            TypeError,
            ValueError,
        ):
            _close_factory_resources(store, ownership)
            raise AssetInstallationControlUnavailable(
                "cannot verify legacy asset authority for component addition"
            ) from None
        except BaseException:
            _close_factory_resources(store, ownership)
            raise

    @classmethod
    def verify_bound_for_active_installer(
        cls,
        root: InstallationRoot,
        store_path: str | os.PathLike[str],
        *,
        store_dependencies: PaidMediaAssetStoreDependencies = DEFAULT_ASSET_STORE_DEPENDENCIES,
    ) -> "AssetInstallationControl":
        """Installer-only exact proof of an already-active Asset Store."""

        path = Path(os.path.abspath(os.fspath(store_path)))
        store: PaidMediaAssetStore | None = None
        ownership: _AssetWriterOwnership | None = None
        try:
            snapshot = root.snapshot()
            if (
                snapshot.status != "active"
                or snapshot.lock_kind != "none"
                or snapshot.reanchor_pending
            ):
                raise AssetInstallationControlUnavailable(
                    "Root is not in the active proof state"
                )
            component = snapshot.component("gateway_assets")
            if not component.bound:
                raise AssetInstallationControlUnavailable(
                    "active asset component is not bound"
                )
            control = cls(root, snapshot)
            if not path.is_dir():
                raise OSError("bound asset-store directory is missing")
            ownership = _AssetWriterOwnership.acquire(
                _ownership_path(
                    root,
                    snapshot.installation_id,
                    component.identity,
                ),
                create_if_missing=False,
            )
            store = PaidMediaAssetStore.open_bound(
                path,
                **cls._store_arguments(control, store_dependencies),
            )
            local = store.inspect_root_state()
            fresh = root.snapshot()
            if fresh != snapshot:
                raise AssetInstallationControlUnavailable(
                    "active Root changed during asset proof"
                )
            proven = control._validated_component(fresh)
            if (
                local.installation_id != fresh.installation_id
                or local.epoch != fresh.epoch
                or local.database_identity != proven.identity
                or local.authority_mode != "normal"
                or local.recovery_floor is not None
                or local.recovery_state_digest is not None
                or proven.recovery_floor is not None
                or proven.recovery_state_digest is not None
                or not control._proof_matches(proven, local)
            ):
                raise AssetInstallationControlUnavailable(
                    "active asset proof does not match the Root"
                )
            control._attach_ownership(ownership)
            control._attach_store(store)
            control._publish(
                "provisioned_not_active",
                "active-installer-proof-verified",
                local,
            )
            return control
        except (
            InstallationRootError,
            PaidMediaAssetStoreError,
            AssetInstallationControlUnavailable,
            KeyError,
            OSError,
            TypeError,
            ValueError,
        ):
            _close_factory_resources(store, ownership)
            raise AssetInstallationControlUnavailable(
                "cannot verify active asset authority for installer"
            ) from None
        except BaseException:
            _close_factory_resources(store, ownership)
            raise

    @classmethod
    def provision(
        cls,
        root: InstallationRoot,
        store_path: str | os.PathLike[str],
        *,
        store_dependencies: PaidMediaAssetStoreDependencies = DEFAULT_ASSET_STORE_DEPENDENCIES,
    ) -> "AssetInstallationControl":
        """Installer-only create/open and exact ``gateway_assets`` bind."""

        path = Path(os.path.abspath(os.fspath(store_path)))
        store: PaidMediaAssetStore | None = None
        ownership: _AssetWriterOwnership | None = None
        try:
            snapshot = root.snapshot()
            if snapshot.status not in {"provisioning", "active"}:
                raise AssetInstallationControlUnavailable(
                    "asset authority cannot be provisioned in this Root state"
                )
            component = snapshot.component("gateway_assets")
            control = cls(root, snapshot)
            store_exists = path.exists()
            ownership = _AssetWriterOwnership.acquire(
                _ownership_path(root, snapshot.installation_id, component.identity),
                create_if_missing=(
                    snapshot.status == "provisioning" and not component.bound
                ),
                repair_incomplete_receipt=(
                    snapshot.status == "provisioning"
                    and not component.bound
                    and not store_exists
                ),
            )
            control._attach_ownership(ownership)
            if component.bound or snapshot.status == "active":
                if not path.is_dir():
                    raise OSError("bound asset-store directory is missing")
                store = PaidMediaAssetStore.open_bound(
                    path,
                    **cls._store_arguments(control, store_dependencies),
                )
            elif path.exists():
                if not path.is_dir():
                    raise OSError("asset-store authority path is invalid")
                store = PaidMediaAssetStore.open_bound(
                    path,
                    **cls._store_arguments(control, store_dependencies),
                )
            else:
                store = PaidMediaAssetStore.provision(
                    path,
                    **cls._store_arguments(control, store_dependencies),
                )
            control._attach_store(store)
            local = control.inspect_local_authority()
            bound_snapshot = control._bind_asset_component(local)
            if bound_snapshot.status == "active":
                control.reconcile_startup()
            elif bound_snapshot.status == "provisioning":
                control._publish(
                    "provisioned_not_active",
                    "awaiting-installation-activation",
                    local,
                )
            else:
                raise AssetInstallationControlUnavailable(
                    "asset authority bind left provisioning unexpectedly"
                )
            return control
        except (
            InstallationRootError,
            PaidMediaAssetStoreError,
            AssetInstallationControlUnavailable,
            OSError,
            TypeError,
            ValueError,
        ):
            _close_factory_resources(store, ownership)
            raise AssetInstallationControlUnavailable(
                "cannot provision asset authority"
            ) from None
        except BaseException:
            _close_factory_resources(store, ownership)
            raise

    def _attach_ownership(self, ownership: _AssetWriterOwnership) -> None:
        with self._lock:
            if self._ownership is not None or self._closing:
                raise AssetInstallationControlUnavailable(
                    "asset writer ownership cannot be attached"
                )
            self._ownership = ownership

    def _attach_store(self, store: PaidMediaAssetStore) -> None:
        with self._lock:
            if self._store is not None or self._closing:
                raise AssetInstallationControlUnavailable(
                    "asset authority store cannot be attached"
                )
            self._store = store

    def _bind_asset_component(
        self,
        local: PaidMediaAssetRootState,
    ) -> InstallationRootSnapshot:
        """Bind once, or prove that a lost bind response already committed."""

        for _attempt in range(_MAX_ROOT_CAS_CALLS):
            snapshot = self._root.snapshot()
            if (
                snapshot.installation_id != self._expected_installation_id
                or snapshot.epoch != self._expected_epoch
            ):
                raise AssetInstallationControlUnavailable(
                    "asset installation identity changed during bind"
                )
            component = snapshot.component("gateway_assets")
            if (
                component.identity != self._expected_database_identity
                or component.epoch != self._expected_epoch
            ):
                raise AssetInstallationControlUnavailable(
                    "asset Root component identity changed during bind"
                )
            if component.bound:
                if self._proof_matches(component, local):
                    return snapshot
                raise AssetInstallationControlUnavailable(
                    "asset Root component was bound to a conflicting proof"
                )
            if snapshot.status != "provisioning":
                raise AssetInstallationControlUnavailable(
                    "asset Root cannot bind outside provisioning"
                )
            try:
                result = self._root.bind_component(
                    "gateway_assets",
                    installation_id=snapshot.installation_id,
                    epoch=snapshot.epoch,
                    identity=component.identity,
                    sequence_floor=local.mutation_sequence,
                    state_digest=local.state_digest,
                    expected_root_revision=snapshot.root_revision,
                )
            except InstallationRootError:
                # A failed call may be a stale CAS or a committed response whose
                # transport result was lost. Only an exact Root reread decides.
                continue
            bound = self._validated_component(result.snapshot)
            if not self._proof_matches(bound, local):
                raise AssetInstallationControlUnavailable(
                    "asset Root bind returned a conflicting proof"
                )
            return result.snapshot
        raise AssetInstallationControlUnavailable(
            "asset Root bind could not be confirmed"
        )

    @property
    def state(self) -> AssetInstallationControlState:
        with self._lock:
            return self._state

    @property
    def store(self) -> PaidMediaAssetStore:
        with self._lock:
            store = self._store
            mode = self._state.mode
            closing = self._closing
        if store is None or closing or mode not in {"ready", "manual_only"}:
            raise AssetInstallationControlUnavailable(
                "asset authority read-capable store is unavailable"
            )
        return store

    def inspect_local_authority(self) -> PaidMediaAssetRootState:
        with self._lock:
            store = self._store
            closing = self._closing
        if store is None or closing:
            raise AssetInstallationControlUnavailable(
                "asset authority store is not attached"
            )
        try:
            return store.inspect_root_state()
        except PaidMediaAssetStoreError:
            self._fuse("local-authority-corruption")
            raise AssetInstallationControlUnavailable(
                "asset local authority is unavailable"
            ) from None

    def _validated_component(
        self,
        snapshot: InstallationRootSnapshot,
    ):
        if (
            snapshot.installation_id != self._expected_installation_id
            or snapshot.epoch != self._expected_epoch
        ):
            raise AssetInstallationControlUnavailable(
                "asset installation identity changed"
            )
        component = snapshot.component("gateway_assets")
        if (
            component.identity != self._expected_database_identity
            or component.epoch != self._expected_epoch
            or not component.bound
        ):
            raise AssetInstallationControlUnavailable(
                "asset Root component binding changed"
            )
        return component

    @staticmethod
    def _proof_matches(component, local: PaidMediaAssetRootState) -> bool:
        return (
            component.sequence_floor == local.mutation_sequence
            and component.state_digest == local.state_digest
        )

    def _publish(
        self,
        mode: AssetControlMode,
        reason_code: str,
        local: PaidMediaAssetRootState,
    ) -> AssetInstallationControlState:
        state = AssetInstallationControlState(
            mode=mode,
            reason_code=reason_code,
            installation_id=local.installation_id,
            epoch=local.epoch,
            database_identity=local.database_identity,
            mutation_sequence=local.mutation_sequence,
            state_digest=local.state_digest,
        )
        with self._lock:
            if self._state.mode == "fused":
                return self._state
            self._state = state
            return state

    def _fuse(self, reason_code: str) -> AssetInstallationControlState:
        with self._lock:
            if self._state.mode == "fused":
                return self._state
            self._state = AssetInstallationControlState(
                mode="fused",
                reason_code=reason_code,
                installation_id=self._expected_installation_id,
                epoch=self._expected_epoch,
                database_identity=self._expected_database_identity,
            )
            return self._state

    def reconcile_startup(self) -> AssetInstallationControlState:
        local = self.inspect_local_authority()
        try:
            snapshot = self._root.snapshot()
            component = self._validated_component(snapshot)
            if snapshot.status == "provisioning":
                if (
                    local.authority_mode != "normal"
                    or component.recovery_floor is not None
                    or not self._proof_matches(component, local)
                ):
                    raise AssetInstallationControlUnavailable(
                        "provisioning asset authority is not exact"
                    )
                return self._publish(
                    "provisioned_not_active",
                    "awaiting-installation-activation",
                    local,
                )
            if snapshot.status != "active":
                raise AssetInstallationControlUnavailable(
                    "asset Root is not active"
                )

            if local.authority_mode == "normal":
                recovery_required = self._ensure_root_recovery_fence(local)
                if not recovery_required:
                    with self._lock:
                        store = self._store
                    if store is None:
                        raise AssetInstallationControlUnavailable(
                            "asset authority store is not attached"
                        )
                    store.resume_after_root_reconcile(local)
                    return self._publish("ready", "authority-exact", local)
                with self._lock:
                    store = self._store
                if store is None:
                    raise AssetInstallationControlUnavailable(
                        "asset authority store is not attached"
                    )
                local = store.enter_authority_manual_only(
                    installation_id=self._expected_installation_id,
                    epoch=self._expected_epoch,
                    recovery_floor=local.mutation_sequence,
                    recovery_state_digest=local.state_digest,
                ).after
            elif local.authority_mode != "manual_only":
                raise AssetInstallationControlUnavailable(
                    "asset local authority mode is invalid"
                )

            self._acknowledge_manual_only(local)
            with self._lock:
                store = self._store
            if store is None:
                raise AssetInstallationControlUnavailable(
                    "asset authority store is not attached"
                )
            store.resume_after_root_reconcile(local)
            return self._publish(
                "manual_only", "manual-recovery-required", local
            )
        except (
            InstallationRootError,
            PaidMediaAssetStoreError,
            AssetInstallationControlUnavailable,
        ):
            self._fuse("authority-reconciliation-failed")
            raise AssetInstallationControlUnavailable(
                "asset authority reconciliation failed"
            ) from None

    def _ensure_root_recovery_fence(
        self,
        local: PaidMediaAssetRootState,
    ) -> bool:
        """Return whether exact local normal state requires manual recovery."""

        writes = 0
        while True:
            snapshot = self._root.snapshot()
            if snapshot.status != "active":
                raise AssetInstallationControlUnavailable(
                    "asset Root left active state during recovery"
                )
            component = self._validated_component(snapshot)
            if self._proof_matches(component, local):
                if component.recovery_floor is None:
                    return False
                if (
                    component.recovery_floor == local.mutation_sequence
                    and component.recovery_state_digest == local.state_digest
                ):
                    return True
                raise AssetInstallationControlUnavailable(
                    "asset Root recovery fence conflicts with local proof"
                )
            if (
                component.recovery_floor is not None
                or local.mutation_sequence != component.sequence_floor + 1
            ):
                raise AssetInstallationControlUnavailable(
                    "asset Root and local proofs are not recoverably adjacent"
                )
            if writes >= _MAX_ROOT_CAS_CALLS:
                raise AssetInstallationControlUnavailable(
                    "asset Root recovery fence could not be confirmed"
                )
            writes += 1
            try:
                self._root.verify_component(
                    "gateway_assets",
                    installation_id=snapshot.installation_id,
                    epoch=snapshot.epoch,
                    identity=component.identity,
                    sequence_floor=local.mutation_sequence,
                    state_digest=local.state_digest,
                    previous_state_digest=component.state_digest,
                )
            except InstallationRootError:
                # A response may be lost after the Root transaction commits.
                # The next exact reread is the only acknowledgement.
                continue

    def _acknowledge_manual_only(
        self,
        local: PaidMediaAssetRootState,
    ) -> None:
        """Idempotently clear the Root fence after local no-outbound receipt."""

        if (
            local.authority_mode != "manual_only"
            or local.recovery_floor is None
            or local.recovery_state_digest is None
            or local.mutation_sequence != local.recovery_floor + 1
        ):
            raise AssetInstallationControlUnavailable(
                "asset manual-only receipt is invalid"
            )
        writes = 0
        while True:
            snapshot = self._root.snapshot()
            if snapshot.status != "active":
                raise AssetInstallationControlUnavailable(
                    "asset Root left active state during recovery acknowledgement"
                )
            component = self._validated_component(snapshot)
            if self._proof_matches(component, local):
                if (
                    component.recovery_floor is None
                    and component.recovery_state_digest is None
                ):
                    return
                raise AssetInstallationControlUnavailable(
                    "asset Root retained an invalid recovery fence"
                )
            if (
                component.sequence_floor != local.recovery_floor
                or component.state_digest != local.recovery_state_digest
                or component.recovery_floor != local.recovery_floor
                or component.recovery_state_digest != local.recovery_state_digest
            ):
                raise AssetInstallationControlUnavailable(
                    "asset Root recovery acknowledgement proof conflicts"
                )
            if writes >= _MAX_ROOT_CAS_CALLS:
                raise AssetInstallationControlUnavailable(
                    "asset Root recovery acknowledgement could not be confirmed"
                )
            writes += 1
            try:
                self._root.acknowledge_component_recovery(
                    "gateway_assets",
                    installation_id=snapshot.installation_id,
                    epoch=snapshot.epoch,
                    identity=component.identity,
                    recovery_floor=local.recovery_floor,
                    recovery_state_digest=local.recovery_state_digest,
                    next_floor=local.mutation_sequence,
                    next_state_digest=local.state_digest,
                    expected_root_revision=snapshot.root_revision,
                )
            except InstallationRootError:
                continue

    def assert_local_mutation_ready(self) -> None:
        with self._lock:
            state = self._state
            closing = self._closing
            in_flight = self._root_transition_in_flight
        if closing or in_flight or state.mode != "ready":
            raise PaidMediaAssetStoreError(
                "asset mutation authority is unavailable"
            )
        try:
            snapshot = self._root.snapshot()
            component = self._validated_component(snapshot)
            if (
                snapshot.status != "active"
                or component.recovery_floor is not None
                or component.sequence_floor != state.mutation_sequence
                or component.state_digest != state.state_digest
            ):
                raise AssetInstallationControlUnavailable(
                    "asset Root proof is not fresh"
                )
        except (InstallationRootError, AssetInstallationControlUnavailable):
            raise PaidMediaAssetStoreError(
                "asset mutation authority is unavailable"
            ) from None

    def root_commit_hook(self, transition: PaidMediaAssetRootTransition) -> None:
        with self._lock:
            if (
                self._state.mode != "ready"
                or self._root_transition_in_flight
                or self._closing
            ):
                raise AssetInstallationControlUnavailable(
                    "asset Root confirmation is unavailable"
                )
            self._root_transition_in_flight = True
        try:
            for _attempt in range(_MAX_ROOT_CAS_CALLS):
                snapshot = self._root.snapshot()
                component = self._validated_component(snapshot)
                if self._proof_matches(component, transition.after):
                    self._publish("ready", "authority-exact", transition.after)
                    return
                if not self._proof_matches(component, transition.before):
                    raise AssetInstallationControlUnavailable(
                        "asset Root transition conflicts with local authority"
                    )
                try:
                    result = self._root.advance_component(
                        "gateway_assets",
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
                advanced = result.snapshot.component("gateway_assets")
                if self._proof_matches(advanced, transition.after):
                    self._publish("ready", "authority-exact", transition.after)
                    return
            raise AssetInstallationControlUnavailable(
                "asset Root confirmation could not be proven"
            )
        except BaseException:
            self._fuse("root-commit-unconfirmed")
            raise
        finally:
            with self._lock:
                self._root_transition_in_flight = False

    def close(self) -> None:
        with self._close_lock:
            with self._lock:
                store = self._store
                ownership = self._ownership
                if store is None and ownership is None:
                    self._closing = False
                    return
                self._closing = True
            try:
                if store is not None:
                    store.close()
                if ownership is not None:
                    ownership.close()
            except BaseException:
                raise
            else:
                with self._lock:
                    self._store = None
                    self._ownership = None
                    self._closing = False


__all__ = [
    "AssetInstallationControl",
    "AssetInstallationControlState",
    "AssetInstallationControlUnavailable",
]
