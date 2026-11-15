"""One-shot Unix Discovery candidate behavior without device access."""

from __future__ import annotations

from pathlib import Path

import pytest

from fortipam_mcp.discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from fortipam_mcp.discovery_entry_create_http_transport import (
    DiscoveryEntryCreateResult,
    FortiPamDiscoveryEntryCreateHttpTransport,
)
from fortipam_mcp.discovery_entry_live_workflow import UnixDiscoveryCreateLiveWorkflow
from fortipam_mcp.discovery_entry_mcp_action import build_unix_discovery_candidate
from fortipam_mcp.discovery_entry_projection import DiscoveryEntryReadback
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig


def _readback() -> DiscoveryEntryReadback:
    return DiscoveryEntryReadback(True, False, True, True, True, True, True, True, True)


def test_unix_discovery_candidate_claims_once_and_rejects_reference_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    config = SecretMetadataHttpTransportConfig(
        base_url="https://example.test", bearer_token="test-token",
        timeout_seconds=5, ca_file=None,
    )
    transport = FortiPamDiscoveryEntryCreateHttpTransport(config)
    request = DisabledUnixDiscoveryCreateInput(
        "bp014-discovery-unix-disabled-20260930-r6", 17,
    )
    state = {"exists": False, "reference": "a" * 64, "writes": 0}
    monkeypatch.setattr(
        FortiPamDiscoveryEntryCreateHttpTransport, "inspect_current",
        lambda _self, _request: _readback() if state["exists"] else None,
    )
    monkeypatch.setattr(
        FortiPamDiscoveryEntryCreateHttpTransport, "inspect_credential_reference",
        lambda _self, _request: state["reference"],
    )

    def create_once(_self, _request, *, before_dispatch=None):
        if before_dispatch is not None:
            before_dispatch()
        state["writes"] += 1
        state["exists"] = True
        return DiscoveryEntryCreateResult(True, "http_200", 200, _readback())

    monkeypatch.setattr(FortiPamDiscoveryEntryCreateHttpTransport,
                        "create_and_readback", create_once)
    workflow = UnixDiscoveryCreateLiveWorkflow(
        transport, request, tmp_path / "claim.json", clock=lambda: 100,
    )
    requester = "b" * 64
    stale = workflow.preview(requester_digest=requester)
    state["reference"] = "c" * 64
    with pytest.raises(RuntimeError):
        workflow.confirm(stale["preview_ref"], requester_digest=requester)
    assert not (tmp_path / "claim.json").exists()

    fresh = workflow.preview(requester_digest=requester)
    authorized = workflow.confirm(fresh["preview_ref"], requester_digest=requester)
    result = workflow.execute(authorized["authorization_ref"], requester_digest=requester)

    assert result["outcome"] == "succeeded"
    assert result["verification"] == "exact_disabled_unscanned_source"
    assert (tmp_path / "claim.json").is_file()
    assert state["writes"] == 1
    with pytest.raises(RuntimeError):
        workflow.execute(authorized["authorization_ref"], requester_digest=requester)
    assert state["writes"] == 1


def test_unix_discovery_candidate_is_default_off() -> None:
    assert build_unix_discovery_candidate({}) is None
    with pytest.raises(ValueError):
        build_unix_discovery_candidate({
            "FORTIPAM_MCP_V4_DISCOVERY_UNIX_700_EXECUTION_ENABLED": "true",
        })
