from copy import deepcopy

import pytest

from fortipam_mcp.secret_description_update_contract import (
    SecretDescriptionUpdateContractError, compile_secret_description_update_body,
    project_secret_description_metadata,
)


def test_description_delta_preserves_identity_and_rejects_material_or_drift() -> None:
    baseline = {
        "version": "v7.0.0", "build": 29, "status": "success",
        "http_method": "GET", "http_status": 200, "path": "secret", "name": "database",
        "results": {"id": 17, "name": "synthetic", "folder": 9,
                    "template": "Unix Account (SSH Password)", "description": "Before"},
    }
    expected = dict(expected_secret_id=17, expected_name="synthetic",
                    expected_folder_id=9, expected_template="Unix Account (SSH Password)")

    def compile(value: object, description: str = "After") -> dict[str, str | int]:
        return compile_secret_description_update_body(value, **expected, description=description)

    original = deepcopy(baseline)
    assert compile(baseline) == {"id": 17, "name": "synthetic", "folder": 9,
                                "template": "Unix Account (SSH Password)", "description": "After"}
    assert baseline == original
    for field, value in (("field", []), ("password", "synthetic-material"),
                         ("folder", 10), ("id", True), ("q_origin_key", "unexpected")):
        changed = deepcopy(baseline)
        changed["results"][field] = value
        with pytest.raises(SecretDescriptionUpdateContractError, match="unavailable"):
            compile(changed)
    for field, value in (("build", 30), ("http_method", "PUT"), ("version", "v1.9.1")):
        changed = deepcopy(baseline)
        changed[field] = value
        with pytest.raises(SecretDescriptionUpdateContractError):
            compile(changed)
    for description in ("Before", "x\n", "界" * 342):
        with pytest.raises(SecretDescriptionUpdateContractError):
            compile(baseline, description)
    assert compile(baseline, "界" * 341)["description"] == "界" * 341
    owner_response = deepcopy(baseline)
    owner_response["status"] = "OK"
    owner_response["results"].update(field=None, uuid="synthetic", recording="enable")
    with pytest.raises(SecretDescriptionUpdateContractError):
        compile(owner_response)
    projected = project_secret_description_metadata(owner_response)
    assert compile(projected)["description"] == "After"
    assert "uuid" not in projected["results"]
    assert "field" not in projected["results"]
    owner_response["results"]["field"] = [{"value": "synthetic-material"}]
    with pytest.raises(SecretDescriptionUpdateContractError):
        project_secret_description_metadata(owner_response)
