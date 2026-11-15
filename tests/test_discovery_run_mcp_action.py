"""Exact-bound Unix Discovery Scan C/P/E and default-off behavior."""

from __future__ import annotations

from pathlib import Path

import pytest

from fortipam_mcp.discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from fortipam_mcp.discovery_entry_create_http_transport import FortiPamDiscoveryEntryCreateHttpTransport
from fortipam_mcp.discovery_run_http_transport import (
    DiscoveryRunResult, FortiPamDiscoveryRunHttpTransport,
)
from fortipam_mcp.discovery_run_mcp_action import (
    UnixDiscoveryRunLiveWorkflow, build_unix_discovery_run_candidate,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig


def test_run_claims_once_and_rejects_reference_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    config = SecretMetadataHttpTransportConfig(
        "https://example.test", "test-token", 5, None,
    )
    transport = FortiPamDiscoveryRunHttpTransport(config)
    reference = FortiPamDiscoveryEntryCreateHttpTransport(config)
    request = DisabledUnixDiscoveryCreateInput(
        "bp014-discovery-unix-disabled-20260930-r8", 17,
    )
    state = {"reference": "a" * 64, "writes": 0}
    monkeypatch.setattr(
        FortiPamDiscoveryRunHttpTransport, "inspect_unscanned",
        lambda _self, _request: True,
    )
    monkeypatch.setattr(
        FortiPamDiscoveryEntryCreateHttpTransport, "inspect_credential_reference",
        lambda _self, _request: state["reference"],
    )

    def run_once(_self, _request):
        state["writes"] += 1
        return DiscoveryRunResult("accepted", 200, True, True)

    monkeypatch.setattr(FortiPamDiscoveryRunHttpTransport, "run_once", run_once)
    workflow = UnixDiscoveryRunLiveWorkflow(
        transport, reference, request, tmp_path / "claim.json", clock=lambda: 100,
    )
    requester = "b" * 64
    stale = workflow.preview(requester_digest=requester)
    state["reference"] = "c" * 64
    with pytest.raises(RuntimeError):
        workflow.confirm(stale["preview_ref"], requester_digest=requester)
    assert state["writes"] == 0

    fresh = workflow.preview(requester_digest=requester)
    authorized = workflow.confirm(fresh["preview_ref"], requester_digest=requester)
    result = workflow.execute(authorized["authorization_ref"], requester_digest=requester)

    assert result["outcome"] == "succeeded"
    assert result["verification"] == "exact_scan_timestamp"
    assert result["import_dispatched"] is False
    assert (tmp_path / "claim.json").is_file()
    assert state["writes"] == 1
    with pytest.raises(RuntimeError):
        workflow.execute(authorized["authorization_ref"], requester_digest=requester)
    assert state["writes"] == 1


def test_run_candidate_is_default_off() -> None:
    assert build_unix_discovery_run_candidate({}) is None
    with pytest.raises(ValueError):
        build_unix_discovery_run_candidate({
            "FORTIPAM_MCP_V4_DISCOVERY_RUN_700_EXECUTION_ENABLED": "true",
        })
