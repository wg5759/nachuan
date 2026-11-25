"""One cross-process restricted file lock for installed-channel authorities."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TypeVar

from gateway.secure_store import (
    SecureStorageError,
    harden_restricted_windows_acl,
)


_Error = TypeVar("_Error", bound=Exception)


class InstalledChannelFileLock:
    def __init__(
        self,
        path: Path,
        *,
        error_type: type[_Error],
        busy_message: str,
    ) -> None:
        self.path = path
        self._error_type = error_type
        self._busy_message = busy_message
        self._handle = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        harden_restricted_windows_acl(self.path.parent, directory=True)
        handle = self.path.open("a+b")
        try:
            if handle.seek(0, os.SEEK_END) == 0:
                handle.write(b"\0")
                handle.flush()
                os.fsync(handle.fileno())
            harden_restricted_windows_acl(self.path, directory=False)
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, ImportError, SecureStorageError) as exc:
            handle.close()
            raise self._error_type(self._busy_message) from exc
        self._handle = handle
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        handle, self._handle = self._handle, None
        if handle is None:
            return
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except (OSError, ImportError):
            pass
        finally:
            handle.close()


__all__ = ["InstalledChannelFileLock"]
