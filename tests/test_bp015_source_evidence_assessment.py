from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, cast

import pytest

from v4_planning import (
    BP015_EVIDENCE_STATE,
    BP015_SOURCE_EVIDENCE_CONTRACT,
    BP015SourceEvidenceError,
    UNAVAILABLE_BP015_PROJECTIONS,
    assess_bp015_source_evidence,
)


_CATALOG_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "fortipam_mcp"
    / "data"
    / "fortipam_1_9_runtime_catalog.json"
)
_USER_GROUP_ROUTE = "/api/v2/cmdb/user/group"
_EVIDENCE_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "fortipam_mcp"
    / "data"
    / "bp015_local_source_evidence.json"
)


def _catalog() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_CATALOG_PATH.read_text(encoding="utf-8")))


def _evidence() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_EVIDENCE_PATH.read_text(encoding="utf-8")))


def _operation(catalog: dict[str, Any], path: str = _USER_GROUP_ROUTE) -> dict[str, Any]:
    return next(
        item
        for item in catalog["operations"]
        if item["method"] == "GET" and item["path"] == path
    )


def test_bp015_source_evidence_accepts_only_exact_local_metadata() -> None:
    assessment = assess_bp015_source_evidence(_catalog(), _evidence())

    assert assessment.contract == BP015_SOURCE_EVIDENCE_CONTRACT
    assert assessment.assessment_status == "partial"
    assert assessment.evidence_state == BP015_EVIDENCE_STATE
    assert assessment.source_contract_ready is False
    assert assessment.device_access is False
    assert assessment.dispatchable is False
    assert assessment.unavailable_projections == UNAVAILABLE_BP015_PROJECTIONS
    assert assessment.official_semantics_sha256 == (
        "58ccb242e0786f84ad89e99185757f48e31932f9494618198d12b66a47142f9f"
    )
    assert assessment.frontend_shape_sha256 == (
        "0c2bf35bb5cde1a5154012d6bf2f529d8d59e782a35aebe0bd29976ca9da434f"
    )
    assert assessment.validated_operation_keys == (
        "GET /api/v2/cmdb/user/group",
        "GET /api/v2/cmdb/user/group/{name}",
        "GET /api/v2/cmdb/firewall.schedule/recurring",
        "GET /api/v2/cmdb/firewall.schedule/recurring/{name}",
    )


@pytest.mark.parametrize(
    ("mutation", "match"),
    (
        (lambda catalog: catalog.__setitem__("version", "1.9.1"), "identity"),
        (
            lambda catalog: catalog["coverage"].__setitem__("captured_operations", 1),
            "coverage",
        ),
        (
            lambda catalog: catalog["source"].__setitem__("catalog_kind", "other"),
            "source kind",
        ),
        (
            lambda catalog: _operation(catalog).__setitem__("path", "/mutated"),
            "route",
        ),
        (
            lambda catalog: catalog.__setitem__(
                "operations",
                [item for item in catalog["operations"] if item is not _operation(catalog)],
            ),
            "operation coverage",
        ),
        (
            lambda catalog: _operation(catalog).__setitem__("risk_tier", "high"),
            "operation changed",
        ),
        (
            lambda catalog: _operation(catalog).__setitem__(
                "mcp_eligibility", "documented_not_exposed"
            ),
            "operation changed",
        ),
        (
            lambda catalog: _operation(catalog).__setitem__("response_codes", ["201"]),
            "response profile",
        ),
        (
            lambda catalog: _operation(catalog).__setitem__("response_schema", None),
            "unsupported metadata",
        ),
    ),
)
def test_bp015_source_evidence_rejects_catalog_drift(
    mutation: Any, match: str
) -> None:
    catalog = deepcopy(_catalog())
    mutation(catalog)

    with pytest.raises(BP015SourceEvidenceError, match=match):
        assess_bp015_source_evidence(catalog, _evidence())


@pytest.mark.parametrize(
    ("mutation", "match"),
    (
        (
            lambda evidence: evidence["official_product_semantics"].__setitem__(
                "product_version", "1.9.0"
            ),
            "official semantics",
        ),
        (
            lambda evidence: evidence["authenticated_frontend_shape"].__setitem__(
                "api_contract", True
            ),
            "frontend shape",
        ),
        (
            lambda evidence: evidence["authenticated_frontend_shape"].__setitem__(
                "size_bytes", 1
            ),
            "frontend shape",
        ),
        (
            lambda evidence: evidence["sanitized_catalog_routes"].__setitem__(
                "response_schema_available", True
            ),
            "catalog evidence",
        ),
        (
            lambda evidence: evidence["non_promotion"].__setitem__("dispatchable", True),
            "non-promotion",
        ),
        (lambda evidence: evidence.__setitem__("unexpected", None), "unsupported metadata"),
    ),
)
def test_bp015_source_evidence_rejects_local_evidence_drift(
    mutation: Any, match: str
) -> None:
    evidence = deepcopy(_evidence())
    mutation(evidence)

    with pytest.raises(BP015SourceEvidenceError, match=match):
        assess_bp015_source_evidence(_catalog(), evidence)
