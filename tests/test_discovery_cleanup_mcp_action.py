"""Requester, prior-create, drift, Gate and durable recovery boundaries."""
from __future__ import annotations
import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fortipam_mcp.server import MCP_SERVER_CLASS

from fortipam_mcp.discovery_cleanup_mcp_action import (
    BINDING_CONTRACT, CONTRACT, PREFIX, UnixDiscoveryCleanupLiveWorkflow,
    UnixDiscoveryCleanupMcpAction, build_unix_discovery_cleanup_candidate,
    register_unix_discovery_cleanup_tools,
)
from fortipam_mcp.discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from fortipam_mcp.discovery_entry_create_http_transport import (
    DiscoveryEntryCleanupResult, FortiPamDiscoveryEntryCreateHttpTransport,
)
from fortipam_mcp.discovery_entry_live_workflow import CONTRACT as CREATE_CONTRACT, source_binding_digest
from fortipam_mcp.discovery_entry_projection import DiscoveryEntryReadback
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig


def _fixture(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    request = DisabledUnixDiscoveryCreateInput("bp014-discovery-unix-disabled-20261002-r16", 17)
    config = SecretMetadataHttpTransportConfig("https://example.test", "test-token", 5, None)
    creation = tmp_path / "create.json"
    creation.write_text(json.dumps({"contract": CREATE_CONTRACT, "reference_digest": "a" * 64,
                                   "source_binding_digest": source_binding_digest(request),
                                   "state": "post_attempt_reserved", "reserved_at": 100}))
    creation.chmod(0o600)
    state = {"reference": "a" * 64, "present": True, "drift": False, "writes": 0, "reads": 0, "now": 100}
    binding = {"contract": BINDING_CONTRACT, "source_name": request.source_name,
               "discovery_secret_id": request.discovery_secret_id, "accepted_digest": "c" * 64,
               "creation_claim_sha256": hashlib.sha256(creation.read_bytes()).hexdigest()}
    binding_path = tmp_path / "binding.json"
    binding_path.write_text(json.dumps(binding)); binding_path.chmod(0o600)

    def inspect(self):
        state["reads"] += 1
        self._require_unconsumed_cleanup()
        if state["drift"] or not state["present"]:
            raise RuntimeError("fixture drift")
        return DiscoveryEntryReadback(True, False, True, True, True, True, True, True, True)

    def cleanup(self, *, before_dispatch=None):
        inspect(self)
        if before_dispatch is not None:
            before_dispatch()
        self._reserve_cleanup_claim(request)
        state["writes"] += 1
        state["present"] = False
        return DiscoveryEntryCleanupResult(True, "http_200", True)

    monkeypatch.setattr(FortiPamDiscoveryEntryCreateHttpTransport, "inspect_bound_cleanup", inspect)
    monkeypatch.setattr(FortiPamDiscoveryEntryCreateHttpTransport, "inspect_credential_reference", lambda *_: state["reference"])
    monkeypatch.setattr(FortiPamDiscoveryEntryCreateHttpTransport, "cleanup_bound_disposable", cleanup)
    monkeypatch.setattr(FortiPamDiscoveryEntryCreateHttpTransport, "inspect_current", lambda *_: None if not state["present"] else object())
    monkeypatch.setattr("fortipam_mcp.discovery_cleanup_mcp_action.load_secret_metadata_http_transport_config", lambda _: config)
    environment = {PREFIX + "ENABLED": "true", PREFIX + "BINDING_FILE": str(binding_path),
                   PREFIX + "CREATION_CLAIM_FILE": str(creation), PREFIX + "INTENT_CLAIM_FILE": str(tmp_path / "intent.json"),
                   PREFIX + "CLAIM_FILE": str(tmp_path / "delete.json")}
    workflow = UnixDiscoveryCleanupLiveWorkflow(
        config, request, accepted_digest=binding["accepted_digest"], creation_claim_sha256=binding["creation_claim_sha256"],
        creation_claim=creation, intent_claim=Path(environment[PREFIX + "INTENT_CLAIM_FILE"]),
        cleanup_claim=Path(environment[PREFIX + "CLAIM_FILE"]), clock=lambda: state["now"],
    )
    return workflow, state, environment


def test_exact_requester_drift_and_fresh_process_replay(tmp_path, monkeypatch):
    workflow, state, environment = _fixture(tmp_path, monkeypatch)
    preview = workflow.preview(requester_digest="b" * 64)
    with pytest.raises(RuntimeError):
        workflow.confirm(preview["preview_ref"], requester_digest="d" * 64)
    state["drift"] = True
    with pytest.raises(RuntimeError):
        workflow.confirm(preview["preview_ref"], requester_digest="b" * 64)
    state["drift"] = False
    authorized = workflow.confirm(preview["preview_ref"], requester_digest="b" * 64)
    assert authorized["contract"] == CONTRACT
    result = workflow.execute(authorized["authorization_ref"], requester_digest="b" * 64)
    assert result["outcome"] == "succeeded"
    assert result["authorization_claim_consumed"] and result["transport_claim_consumed"]
    assert state["writes"] == 1
    assert json.loads((tmp_path / "intent.json").read_text())["requester_digest"] == "b" * 64
    with pytest.raises(RuntimeError):
        workflow.execute(authorized["authorization_ref"], requester_digest="b" * 64)
    fresh = build_unix_discovery_cleanup_candidate(environment)
    assert fresh is not None
    before = state["reads"]
    with pytest.raises(RuntimeError):
        fresh._workflow.preview(requester_digest="b" * 64)
    assert state["reads"] == before
    assert state["writes"] == 1


def test_creation_claim_tamper_and_reference_drift_reject_before_claims(tmp_path, monkeypatch):
    workflow, state, _ = _fixture(tmp_path, monkeypatch)
    state["reference"] = "e" * 64
    with pytest.raises(RuntimeError):
        workflow.preview(requester_digest="b" * 64)
    assert not (tmp_path / "intent.json").exists()
    state["reference"] = "a" * 64
    before = state["reads"]
    with (tmp_path / "create.json").open("a") as stream:
        stream.write(" ")
    with pytest.raises(RuntimeError):
        workflow.preview(requester_digest="b" * 64)
    assert state["reads"] == before
    assert state["writes"] == 0


def test_expired_intent_and_default_closed_gate_do_not_dispatch(tmp_path, monkeypatch):
    workflow, state, environment = _fixture(tmp_path, monkeypatch)
    preview = workflow.preview(requester_digest="b" * 64)
    state["now"] = 700
    with pytest.raises(RuntimeError):
        workflow.confirm(preview["preview_ref"], requester_digest="b" * 64)
    action = build_unix_discovery_cleanup_candidate(environment)
    assert action is not None
    before = state["reads"]
    with pytest.raises(RuntimeError):
        action.execute("opaque-authorization", None)
    assert state["reads"] == before and state["writes"] == 0
    assert build_unix_discovery_cleanup_candidate({}) is None
    with pytest.raises(ValueError):
        build_unix_discovery_cleanup_candidate({PREFIX + "EXECUTION_ENABLED": "true"})


def test_registration_accepts_only_opaque_intent_references(tmp_path, monkeypatch):
    workflow, _, _ = _fixture(tmp_path, monkeypatch)
    server = SimpleNamespace(mcp=MCP_SERVER_CLASS("discovery-cleanup"))
    register_unix_discovery_cleanup_tools(server, UnixDiscoveryCleanupMcpAction(workflow, execution_enabled=False))
    tools = asyncio.run(server.mcp.list_tools())
    schemas = {t.name: t.input_schema for t in tools}
    assert schemas["preview_v4_unix_discovery_cleanup_700"].get("properties", {}) == {}
    assert set(schemas["confirm_v4_unix_discovery_cleanup_700"]["properties"]) == {"preview_ref"}
    assert set(schemas["execute_confirmed_v4_unix_discovery_cleanup_700"]["properties"]) == {"authorization_ref"}
