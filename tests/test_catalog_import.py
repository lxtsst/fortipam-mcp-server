from __future__ import annotations

from fortipam_mcp.catalog_import import build_runtime_catalog, sha256_bytes


def test_importer_keeps_only_bounded_runtime_metadata() -> None:
    source = {
        "catalog_kind": "sanitized_fndn_ui_swagger_catalog",
        "product": "FortiPAM",
        "version": "1.9.0",
        "generated_at": "2026-08-20T12:44:21Z",
        "coverage": {
            "expected_resource_pages": 1,
            "captured_resource_pages": 1,
            "unavailable_resource_pages": 0,
            "captured_operations": 1,
        },
        "api_family_summary": [
            {"api_family": "Monitor API", "resource_pages": 1, "operations": 1}
        ],
        "unavailable_resources": [],
        "resource_pages": [
            {
                "api_family": "Monitor API",
                "source_group": "system",
                "base_path": "/api/v2/monitor",
                "parameter_profiles": [[]],
                "response_profiles": [[{"status": "200", "schema": {"type": "object"}}]],
                "operations": [
                    {
                        "method": "GET",
                        "path": "/system/status",
                        "operation_id": None,
                        "parameter_profile": 0,
                        "response_profile": 0,
                        "risk_tier": "read",
                        "mcp_eligibility": "candidate_read_only",
                        "description": "must not be copied",
                    }
                ],
            }
        ],
    }

    output = build_runtime_catalog(source, source_sha256="a" * 64)

    assert output["review_after"] == "2026-11-18"
    operation = output["operations"][0]
    assert operation["operation_key"] == "GET /api/v2/monitor/system/status"
    assert "description" not in operation
    assert "schema" not in operation
    assert sha256_bytes(b"fortipam") == (
        "f0d0d3778a8a36c179e4e616a0e34611208a6e47429e4a01644947f464fba4b9"
    )
