from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from scripts.verify_distribution_contract import (
    DistributionContractError,
    verify_contract,
)


ROOT = Path(__file__).resolve().parents[1]


def _minimal_copy(tmp_path: Path) -> Path:
    target = tmp_path / "project"
    (target / "config").mkdir(parents=True)
    (target / "desktop").mkdir()
    (target / "gateway").mkdir()
    shutil.copy2(ROOT / "config" / "distribution-channels.v1.json", target / "config")
    shutil.copy2(ROOT / "pyproject.toml", target)
    shutil.copy2(ROOT / "desktop" / "package.json", target / "desktop")
    shutil.copy2(ROOT / "gateway" / "__init__.py", target / "gateway")
    return target


def test_real_distribution_contract_keeps_all_editions_on_one_core() -> None:
    receipt = verify_contract(ROOT)

    assert receipt["core_version"] == "0.2.0"
    assert receipt["client_ready"] == {
        "community": False,
        "desktop": False,
        "enterprise": False,
    }
    assert len(receipt["channels"]) == 3


def test_version_drift_fails_closed(tmp_path: Path) -> None:
    root = _minimal_copy(tmp_path)
    package = json.loads((root / "desktop" / "package.json").read_text("utf-8"))
    package["version"] = "0.2.1"
    (root / "desktop" / "package.json").write_text(
        json.dumps(package), encoding="utf-8"
    )

    with pytest.raises(DistributionContractError, match="must be identical"):
        verify_contract(root)


def test_enterprise_cannot_silently_drop_signing(tmp_path: Path) -> None:
    root = _minimal_copy(tmp_path)
    contract_path = root / "config" / "distribution-channels.v1.json"
    contract = json.loads(contract_path.read_text("utf-8"))
    contract["editions"]["enterprise"]["requires_authenticode"] = False
    contract_path.write_text(json.dumps(contract), encoding="utf-8")

    with pytest.raises(DistributionContractError, match="must fail closed"):
        verify_contract(root)
