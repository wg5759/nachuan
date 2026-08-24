from __future__ import annotations

import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ADR_ROOT = PROJECT_ROOT / "docs" / "adr"
ADR_FILE = re.compile(r"^(?P<id>[0-9]{4})-[a-z0-9][a-z0-9-]*\.md$")
ADR_HEADING = re.compile(r"^# ADR-(?P<id>[0-9]{4})(?:：|:)\S")


def test_adr_file_ids_are_unique_and_match_their_headings() -> None:
    seen: dict[str, Path] = {}
    files = sorted(ADR_ROOT.glob("*.md"))
    assert files, "ADR directory is empty"

    for path in files:
        match = ADR_FILE.fullmatch(path.name)
        assert match is not None, f"non-canonical ADR filename: {path.name}"
        adr_id = match.group("id")
        assert adr_id not in seen, (
            f"duplicate ADR-{adr_id}: {seen[adr_id].name} and {path.name}"
        )
        seen[adr_id] = path

        first_line = path.read_text(encoding="utf-8").splitlines()[0]
        heading = ADR_HEADING.match(first_line)
        assert heading is not None, f"non-canonical ADR heading: {path.name}"
        assert heading.group("id") == adr_id, (
            f"ADR filename/heading mismatch: {path.name}: {first_line}"
        )
