from __future__ import annotations

import pytest

from fortipam_mcp.catalog import CatalogError, RuntimeCatalog


def test_packaged_catalog_has_verified_fndn_coverage() -> None:
    catalog = RuntimeCatalog.load()
    status = catalog.status()

    assert catalog.product == "FortiPAM"
    assert catalog.version == "1.9.0"
    assert len(catalog.operations) == 1295
    assert status["coverage"] == {
        "captured_operations": 1295,
        "captured_resource_pages": 88,
        "expected_resource_pages": 91,
        "unavailable_resource_pages": 3,
    }
    assert status["live_api_exposure_from_catalog"] is False


@pytest.mark.parametrize(
    ("method", "path", "expected_risk"),
    (
        ("GET", "/api/v2/monitor/system/status", "read"),
        ("GET", "/api/v2/cmdb/system/global", "read"),
        ("GET", "/api/v2/cmdb/secret/approval-profile", "high"),
    ),
)
def test_finds_three_lab_validated_operations(
    method: str, path: str, expected_risk: str
) -> None:
    operation = RuntimeCatalog.load().find(method, path)

    assert operation is not None
    assert operation.risk_tier == expected_risk


def test_search_is_bounded_and_catalog_only() -> None:
    catalog = RuntimeCatalog.load()
    results = catalog.search("password changer", method="GET", limit=5)

    assert 1 <= len(results) <= 5
    assert all(result.method == "GET" for result in results)
    assert any(result.risk_tier == "high" for result in results)
    assert all(result.details()["live_call_permitted"] is False for result in results)

    with pytest.raises(CatalogError):
        catalog.search("status", limit=26)


def test_exact_classifier_does_not_interpret_instance_paths() -> None:
    catalog = RuntimeCatalog.load()

    assert catalog.find("GET", "/api/v2/cmdb/secret/approval-profile/private-name") is None
    assert catalog.find("GET", "/api/v2/cmdb/secret/approval-profile/{name}") is not None


def test_discovery_entry_catalog_candidate_has_no_body_or_response_schema_claim() -> None:
    catalog = RuntimeCatalog.load()
    create = catalog.find("POST", "/api/v2/cmdb/secret/discovery")
    detail = catalog.find("GET", "/api/v2/cmdb/secret/discovery/{name}")

    assert create is not None
    assert create.risk_tier == "high"
    assert create.mcp_eligibility == "documented_not_exposed"
    body_parameters = [
        parameter for parameter in create.parameters if parameter.location == "body"
    ]
    assert len(body_parameters) == 1
    assert body_parameters[0].required is True
    assert body_parameters[0].schema_reference is None

    assert detail is not None
    assert detail.risk_tier == "high"
    assert detail.mcp_eligibility == "documented_not_exposed"
    assert any(
        parameter.name == "name"
        and parameter.location == "path"
        and parameter.required is True
        for parameter in detail.parameters
    )
    assert create.details()["live_call_permitted"] is False
    assert detail.details()["live_call_permitted"] is False
