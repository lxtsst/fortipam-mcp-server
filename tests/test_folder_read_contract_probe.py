from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "probe_folder_read_contract.py"
SPEC = importlib.util.spec_from_file_location("probe_folder_read_contract", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_project_shape_returns_structure_without_values() -> None:
    payload = {
        "http_method": "GET",
        "results": [
            {
                "id": 7,
                "name": "must-not-escape",
                "inherit-policy": "enable",
                "user-permission": [],
            }
        ],
        "status": "success",
    }

    result = MODULE.project_shape(payload, 200)

    assert result["http_status"] == 200
    assert result["result_count"] == 1
    assert result["result_item_keys"] == [
        "id",
        "inherit-policy",
        "name",
        "user-permission",
    ]
    assert result["result_item_shapes"] == {
        "id": ["integer"],
        "inherit-policy": ["string"],
        "name": ["string"],
        "user-permission": ["array"],
    }
    assert "must-not-escape" not in repr(result)
    assert result["raw_values_returned"] is False
    assert result["device_write_executed"] is False


def test_project_shape_rejects_non_object_payload() -> None:
    try:
        MODULE.project_shape([], 200)
    except RuntimeError as exc:
        assert str(exc) == "top_level_not_object"
    else:  # pragma: no cover - assertion guard.
        raise AssertionError("non-object payload must fail closed")
