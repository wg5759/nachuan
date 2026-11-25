"""Build a diagnostic-only, interpreter-bound cache from the locked SDK wheel.

SDK source is compiled, never executed here. This cache is not an installed
release authority; production packaging must independently seal final bytes.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import marshal
import os
from pathlib import Path
import struct
import sys
import tempfile
import zipfile


WHEEL_SHA256 = "9b443a5d47a7d204dd42dc40896c8b75087cc35788e45c48c140806d7df7e5e8"


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    directory = root / "data" / "test-evidence" / "sdk-lifecycle-20260905"
    wheel = directory / "lark_oapi-1.6.8-py3-none-any.whl"
    if hashlib.sha256(wheel.read_bytes()).hexdigest() != WHEEL_SHA256:
        raise SystemExit("SDK_WHEEL_HASH_MISMATCH")
    descriptor, temporary = tempfile.mkstemp(prefix="sdk-bytecode-", suffix=".zip", dir=directory)
    os.close(descriptor)
    temporary_path = Path(temporary)
    modules = 0
    try:
        with zipfile.ZipFile(wheel) as source, zipfile.ZipFile(
            temporary_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
        ) as output:
            for entry in sorted(source.infolist(), key=lambda item: item.filename):
                name = entry.filename
                if entry.is_dir():
                    continue
                if name.startswith("/") or "\\" in name or ".." in name.split("/"):
                    raise ValueError("SDK archive path is invalid")
                if entry.file_size > 2_000_000:
                    raise ValueError("SDK entry exceeds diagnostic budget")
                data = source.read(entry)
                if name.endswith(".py"):
                    code = compile(data, "nachuan-sdk://1.6.8/" + name, "exec", dont_inherit=True, optimize=0)
                    data = (
                        importlib.util.MAGIC_NUMBER + struct.pack("<I", 1)
                        + importlib.util.source_hash(data) + marshal.dumps(code)
                    )
                    name = name[:-3] + ".pyc"
                    modules += 1
                if name.endswith("/RECORD"):
                    continue
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o644 << 16
                output.writestr(info, data)
        cache_sha = hashlib.sha256(temporary_path.read_bytes()).hexdigest()
        filename = f"lark_sdk_{sys.implementation.cache_tag}_{cache_sha[:16]}.zip"
        destination = directory / filename
        if destination.exists():
            if hashlib.sha256(destination.read_bytes()).hexdigest() != cache_sha:
                raise ValueError("SDK diagnostic cache conflicts with existing bytes")
            temporary_path.unlink()
        else:
            os.replace(temporary_path, destination)
        manifest = {
            "schema": "nachuan.feishu-sdk-bytecode-diagnostic.v1",
            "source_wheel_sha256": WHEEL_SHA256,
            "cache_file": filename,
            "cache_sha256": cache_sha,
            "python": list(sys.version_info[:3]),
            "python_tag": sys.implementation.cache_tag,
            "magic_hex": importlib.util.MAGIC_NUMBER.hex(),
            "optimization": 0,
            "compiled_modules": modules,
            "sdk_source_modified": False,
            "production_approved": False,
        }
        manifest_path = directory / "bytecode-manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(manifest), flush=True)
        return 0
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
