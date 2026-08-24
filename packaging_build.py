"""Setuptools commands that keep wheel inputs free of stale build output."""

from __future__ import annotations

import shutil
from pathlib import Path

from setuptools.command.build_py import build_py as _build_py


class CleanBuildPy(_build_py):
    """Recreate ``build_lib`` before copying the current package closure.

    Setuptools' incremental ``build_py`` leaves files that disappeared from the
    source tree in ``build/lib``.  A later wheel can otherwise resurrect stale
    Python modules or hashed Web chunks.  The target is accepted only when its
    resolved path is a strict child of this invocation's build base.
    """

    def run(self) -> None:
        build_command = self.get_finalized_command("build")
        build_base = Path(build_command.build_base).absolute().resolve()
        build_lib = Path(self.build_lib).absolute()
        resolved_build_lib = build_lib.resolve()
        if build_base not in resolved_build_lib.parents:
            raise RuntimeError("refusing to clean build_lib outside build_base")
        if build_lib.is_symlink():
            raise RuntimeError("refusing to clean a symlinked build_lib")
        if build_lib.exists():
            shutil.rmtree(build_lib)
        super().run()
