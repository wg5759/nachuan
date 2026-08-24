"""Static guardrails for financial attribution on internal model calls."""

from __future__ import annotations

import ast
from pathlib import Path


_ROOT = Path(__file__).parents[1]
_SOURCE_ROOTS = ("gateway", "orchestrator", "train")
_EXCLUDED = {
    "gateway/app.py",
    "gateway/failover.py",
    "orchestrator/media.py",
    "orchestrator/modes.py",
}
_FAILOVER_CALLS = {
    "chat_once_with_deadline",
    "chat_with_fallback",
    "stream_with_fallback",
}


def _production_python_files() -> list[Path]:
    files: list[Path] = []
    for source_root in _SOURCE_ROOTS:
        files.extend((_ROOT / source_root).rglob("*.py"))
    return [
        path
        for path in files
        if path.relative_to(_ROOT).as_posix() not in _EXCLUDED
    ]


def _is_role_scope(node: ast.AST) -> bool:
    if not isinstance(node, (ast.With, ast.AsyncWith)):
        return False
    for item in node.items:
        context = item.context_expr
        if not (
            isinstance(context, ast.Call)
            and isinstance(context.func, ast.Name)
            and context.func.id == "bind_provider_call_scope"
        ):
            continue
        if len([keyword for keyword in context.keywords if keyword.arg == "role"]) == 1:
            return True
    return False


def test_every_internal_failover_call_has_a_lexical_role_scope():
    checked: list[str] = []
    missing: list[str] = []

    for path in _production_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported_names = {
            alias.asname or alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module == "gateway.failover"
            for alias in node.names
            if alias.name in _FAILOVER_CALLS
        }
        if not imported_names:
            continue
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in imported_names
            ):
                continue
            relative = path.relative_to(_ROOT).as_posix()
            label = f"{relative}:{node.lineno}"
            checked.append(label)
            ancestor = node
            while ancestor in parents and not _is_role_scope(ancestor):
                ancestor = parents[ancestor]
            if not _is_role_scope(ancestor):
                missing.append(label)

    assert checked, "no internal failover calls were discovered"
    assert not missing, f"internal failover calls without role scope: {missing}"


def test_loop_and_parallel_roles_include_their_stable_coordinates():
    expected_coordinates = {
        "orchestrator/conductor.py": (
            "attempt_{_attempt + 1}",
            "execute.round_{round_no}.node_{idx + 1}",
            "synthesis.round_{round_no}",
            "review.round_{rounds}",
        ),
        "orchestrator/orchestrated_agent.py": (
            "trinity.coordinator.turn_{k + 1}",
            "trinity.thinker.turn_{turn}",
            "trinity.review.turn_{turn}",
            "trinity.worker.turn_{turn}",
            "execute.round_{rounds}",
            "review.round_{rounds}",
        ),
        "orchestrator/tool_agent.py": (
            "reasoning.step_{step + 1}",
            "delegate.step_{step + 1}.call_{tool_index + 1}",
            "finalize.{reason}",
        ),
        "train/build_routing_dataset.py": (
            "item_{item_index}.candidate_{candidate_index}",
            "{role_prefix}.answer",
            "{role_prefix}.judge",
        ),
    }
    for relative, coordinates in expected_coordinates.items():
        source = (_ROOT / relative).read_text(encoding="utf-8")
        for coordinate in coordinates:
            assert coordinate in source, f"{relative} lost role coordinate {coordinate}"
