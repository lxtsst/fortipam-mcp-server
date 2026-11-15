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
    REGISTRY_PATH,
    get_action_package,
    load_action_packages,
    validate_action_packages,
)


PROJECT_ROOT = Path(__file__).parents[1]
SCHEMA_PATH = PROJECT_ROOT / "schemas" / "v3_action_package.schema.json"
SOURCE_REGISTRY_PATH = PROJECT_ROOT / "registry" / "v3_action_packages.json"


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
    assert package["contract_status"] == "documented"
    assert package["method"] == "POST"
    assert package["path"] == "/api/v2/cmdb/secret/folder"
    assert package["scope"] == "child_only"
    assert package["body"] == "folder-create-request-v2"
    assert package["request_schema"]["fields"] == [
        "id",
        "name",
        "inherit-policy",
        "inherit-permission",
        "inherit-folder-ztna",
        "parent-folder",
        "user-permission",
        "group-permission",
    ]
    assert package["request_schema"]["bounded_inputs"] == {
        "name": {
            "type": "string",
            "min_length": 1,
            "max_length": 64,
            "path_separators_allowed": False,
            "control_characters_allowed": False,
        },
        "parent-folder": {
            "type": "integer",
            "minimum": 1,
            "maximum": 2_147_483_647,
        },
    }
    assert package["permission_contract"] == {
        "status": "source_documented_lab_identity_pending",
        "collection_read": "SecretFolder Read",
        "detail_read": "SecretFolder Read",
        "child_create": "SecretFolder Read/Write",
        "root_folder_required": False,
        "current_lab_evidence": "v3_api_identity_folder_collection_read_http_403",
        "execution_identity_status": "dedicated_v4_least_privilege_identity_pending",
        "provider_access_group": "secretgrp",
    }
    assert any("Root creation is explicitly out of scope" in gap for gap in package["evidence_gaps"])
    assert package["adapter"] == "none"
    assert package["executable"] is False
    assert package["dispatchable"] is False
    assert package["mcp_exposed"] is False
    assert package["registered_tool"] is False
    assert package["device_access"] is False


def test_packaged_registry_matches_the_authoritative_source_registry() -> None:
    packaged = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    source = json.loads(SOURCE_REGISTRY_PATH.read_text(encoding="utf-8"))
    assert packaged == source


@pytest.mark.parametrize(
    "mutation",
    [
        lambda registry: registry.update({"unexpected": True}),
        lambda registry: registry["packages"][0].update({"unexpected": True}),
        lambda registry: registry["packages"][0].update({"path": "/api/v2/unknown"}),
        lambda registry: registry["packages"][0].update({"body": {"name": "x"}}),
        lambda registry: registry["packages"][0].update({"source_refs": ["unreviewed-note"]}),
        lambda registry: registry["packages"][0]["request_schema"].update({"unknown": True}),
        lambda registry: registry["packages"][0].update({"scope": "root_and_child"}),
        lambda registry: registry["packages"][0]["request_schema"].update(
            {"bounded_inputs": {"parent-folder": {"minimum": 0}}}
        ),
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
        lambda registry: registry["packages"][0].update({"contract_status": "verified"}),
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
