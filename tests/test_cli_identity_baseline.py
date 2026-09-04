from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.baseline_cli_identity_collections import (
    BASELINE_CONTRACT,
    BaselineError,
    collection_fingerprint,
    compare_baseline,
    write_baseline,
)


def _payload(*items: dict[str, object]) -> dict[str, object]:
    return {"results": list(items)}


def test_collection_fingerprint_is_order_stable_and_excludes_target() -> None:
    first = _payload(
        {"name": "target", "permission": "changes-are-ignored"},
        {"name": "existing-b", "permission": "read"},
        {"name": "existing-a", "permission": "none"},
    )
    second = _payload(
        {"name": "existing-a", "permission": "none"},
        {"name": "target", "permission": "different-target-value"},
        {"name": "existing-b", "permission": "read"},
    )
    assert collection_fingerprint(first, excluded_name="target") == (
        collection_fingerprint(second, excluded_name="target")
    )


def test_collection_fingerprint_detects_non_target_change() -> None:
    before = collection_fingerprint(
        _payload({"name": "existing", "permission": "none"}),
        excluded_name="target",
    )
    after = collection_fingerprint(
        _payload({"name": "existing", "permission": "read"}),
        excluded_name="target",
    )
    assert before != after


def test_owner_only_baseline_round_trip_returns_only_booleans(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    baseline = {
        "contract": BASELINE_CONTRACT,
        "admin_count": 2,
        "admin_digest": "a" * 64,
        "profile_count": 3,
        "profile_digest": "b" * 64,
    }
    write_baseline(path, baseline)
    assert path.stat().st_mode & 0o077 == 0
    result = compare_baseline(path, baseline)
    assert result["baseline_accepted"] is True
    assert result["digests_returned"] is False
    assert "a" * 64 not in json.dumps(result)
    with pytest.raises(BaselineError, match="already exists"):
        write_baseline(path, baseline)


def test_baseline_rejects_group_readable_or_changed_evidence(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    baseline = {
        "contract": BASELINE_CONTRACT,
        "admin_count": 1,
        "admin_digest": "a" * 64,
        "profile_count": 1,
        "profile_digest": "b" * 64,
    }
    write_baseline(path, baseline)
    changed = dict(baseline, admin_digest="c" * 64)
    assert compare_baseline(path, changed)["baseline_accepted"] is False
    path.chmod(0o640)
    with pytest.raises(BaselineError, match="owner-only"):
        compare_baseline(path, baseline)
