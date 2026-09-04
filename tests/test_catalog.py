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
