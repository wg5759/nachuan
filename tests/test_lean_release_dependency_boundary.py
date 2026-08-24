from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _normalized_requirement_name(requirement: str) -> str:
    head = requirement.split(";", 1)[0].split("[", 1)[0]
    head = head.split("@", 1)[0]
    for marker in ("===", "==", "~=", ">=", "<=", "!=", ">", "<"):
        head = head.split(marker, 1)[0]
    return head.strip().lower().replace("_", "-").replace(".", "-")


def test_lean_release_selector_keeps_voice_runtime_out_of_base_and_dev() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    base = {_normalized_requirement_name(item) for item in project["project"]["dependencies"]}
    extras = project["project"]["optional-dependencies"]
    dev = {_normalized_requirement_name(item) for item in extras["dev"]}
    voice_lab = {_normalized_requirement_name(item) for item in extras["voice-lab"]}

    assert "faster-whisper" not in base
    assert "faster-whisper" not in dev
    assert "faster-whisper" in voice_lab


def test_engine_spec_excludes_voice_and_local_compression_from_lean_payload() -> None:
    tree = ast.parse((ROOT / "engine.spec").read_text(encoding="utf-8"))
    collected: set[str] = set()
    imported: set[str] = set()
    excluded: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif (
            isinstance(node, ast.For)
            and isinstance(node.target, ast.Name)
            and isinstance(node.iter, (ast.Tuple, ast.List))
            and all(isinstance(item, ast.Constant) and isinstance(item.value, str) for item in node.iter.elts)
        ):
            if any(
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id == "collect_all"
                and call.args
                and isinstance(call.args[0], ast.Name)
                and call.args[0].id == node.target.id
                for call in ast.walk(node)
            ):
                collected.update(item.value for item in node.iter.elts)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Analysis":
            keyword = next(item for item in node.keywords if item.arg == "excludes")
            excluded.update(ast.literal_eval(keyword.value))

    forbidden_packages = {
        "ctranslate2",
        "faster_whisper",
        "funasr",
        "kaldiio",
        "numpy",
        "onnxruntime",
        "sentencepiece",
        "tokenizers",
        "torch",
        "torch_complex",
    }
    forbidden_modules = {
        "gateway.asr_nemotron",
        "gateway.asr_sensevoice",
        "orchestrator.compress",
        "orchestrator.neural_coordinator",
    }

    assert forbidden_packages.isdisjoint(collected)
    assert forbidden_packages.isdisjoint(imported)
    assert forbidden_packages | forbidden_modules <= excluded
    assert "gateway.audio" not in excluded


def test_windows_dev_export_has_no_voice_or_local_compression_runtime() -> None:
    completed = subprocess.run(
        [
            "uv",
            "export",
            "--frozen",
            "--format",
            "requirements.txt",
            "--no-default-groups",
            "--group",
            "dev",
            "--extra",
            "dev",
            "--python",
            "3.12.9",
            "--no-emit-project",
            "--no-header",
            "--no-annotate",
            "--no-hashes",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    selected = {
        _normalized_requirement_name(line)
        for line in completed.stdout.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    forbidden = {
        "ctranslate2",
        "faster-whisper",
        "funasr",
        "kaldiio",
        "onnxruntime",
        "tokenizers",
        "torch-complex",
    }

    assert selected.isdisjoint(forbidden), selected & forbidden


def test_windows_lean_sbom_is_text_first_and_keeps_core_gateway_runtime() -> None:
    completed = subprocess.run(
        [
            "uv",
            "export",
            "--frozen",
            "--format",
            "cyclonedx1.5",
            "--no-default-groups",
            "--group",
            "dev",
            "--extra",
            "dev",
            "--python",
            "3.12.9",
            "--no-emit-project",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    sbom = json.loads(completed.stdout)
    selected = {
        str(component["name"]).lower().replace("_", "-").replace(".", "-")
        for component in sbom["components"]
    }
    forbidden = {
        "ctranslate2",
        "faster-whisper",
        "funasr",
        "kaldiio",
        "onnxruntime",
        "tokenizers",
        "torch-complex",
    }

    assert {"fastapi", "lark-oapi", "uvicorn"} <= selected
    assert selected.isdisjoint(forbidden), selected & forbidden


def test_text_gateway_imports_without_local_model_extras() -> None:
    completed = subprocess.run(
        [sys.executable, "-c", "import gateway.app; print('GATEWAY_IMPORT_OK')"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"},
        text=True,
        encoding="utf-8",
        # This is a deadlock watchdog, not a gateway startup SLA.  A full-suite
        # Windows host can delay a cold import while still completing normally.
        timeout=180,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "GATEWAY_IMPORT_OK"


def test_neural_coordinator_degrades_to_no_cast_without_numpy() -> None:
    from orchestrator import neural_coordinator

    neural_coordinator.reset()
    assert neural_coordinator.pick_neural(object(), "user: 分析这个任务\n") is None
