from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Callable

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from fortipam_mcp.action_packages import (
    ActionPackageValidationError,
    get_action_package,
    load_action_packages,
    validate_action_packages,
)


PROJECT_ROOT = Path(__file__).parents[1]
SCHEMA_PATH = PROJECT_ROOT / "schemas" / "v3_action_package.schema.json"


def _schema_validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def test_packaged_folder_create_candidate_is_valid_and_inert() -> None:
    registry = load_action_packages()
    _schema_validator().validate(registry)

    package = get_action_package()
    assert package["id"] == "folder-create"
    assert package["version"] == "3.2.0"
    assert package["evidence_status"] == "evidence_pending"
    assert package["status"] == "disabled_by_policy"
    assert package["method"] == "unknown"
    assert package["path"] == "unknown"
    assert package["body"] == "unknown"
    assert package["adapter"] == "none"
    assert package["executable"] is False
    assert package["dispatchable"] is False
    assert package["mcp_exposed"] is False
    assert package["registered_tool"] is False
    assert package["device_access"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        lambda registry: registry.update({"unexpected": True}),
        lambda registry: registry["packages"][0].update({"unexpected": True}),
        lambda registry: registry["packages"][0].update({"method": "POST"}),
        lambda registry: registry["packages"][0].update({"path": "/api/v2/unknown"}),
        lambda registry: registry["packages"][0].update({"body": {"name": "x"}}),
        lambda registry: registry["packages"][0].update({"adapter": "fortipam-rest"}),
        lambda registry: registry["packages"][0].update({"executable": True}),
        lambda registry: registry["packages"][0].update({"dispatchable": True}),
        lambda registry: registry["packages"][0].update({"mcp_exposed": True}),
        lambda registry: registry["packages"][0].update({"registered_tool": True}),
        lambda registry: registry["packages"][0].update({"device_access": True}),
    ],
)
def test_schema_and_validator_reject_unsafe_or_unknown_changes(
    mutation: Callable[[dict[str, Any]], object],
) -> None:
    broken = copy.deepcopy(load_action_packages())
    mutation(broken)
    with pytest.raises(ValidationError):
        _schema_validator().validate(broken)
    with pytest.raises(ActionPackageValidationError):
        validate_action_packages(broken)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda registry: registry["packages"][0].update({"evidence_status": "contract_tested"}),
        lambda registry: registry["packages"][0].update({"status": "enabled_by_policy"}),
        lambda registry: registry["packages"][0].update({"maturity": "implemented"}),
        lambda registry: registry["packages"][0].update({"evidence_refs": ["unreviewed-note"]}),
        lambda registry: registry["packages"][0].update({"evidence_gaps": []}),
        lambda registry: registry["packages"][0].pop("required_gates"),
    ],
)
def test_evidence_pending_candidate_cannot_be_promoted_or_strip_its_gates(
    mutation: Callable[[dict[str, Any]], object],
) -> None:
    broken = copy.deepcopy(load_action_packages())
    mutation(broken)
    with pytest.raises(ActionPackageValidationError):
        validate_action_packages(broken)


def test_action_package_lookup_is_exact_and_returns_a_copy() -> None:
    package = get_action_package()
    package["status"] = "enabled_by_policy"
    assert get_action_package()["status"] == "disabled_by_policy"
    with pytest.raises(ActionPackageValidationError, match="not catalogued"):
        get_action_package("folder-create", "9.9.9")


def test_no_tool_or_adapter_surface_is_present_in_package_contract() -> None:
    package = get_action_package()
    assert package["registered_tool"] is False
    assert package["mcp_exposed"] is False
    assert package["adapter"] == "none"
    assert package["device_access"] is False
