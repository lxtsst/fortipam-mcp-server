"""Intent lifetime remains binding across slow fixed metadata reads."""

from dataclasses import replace
import hashlib
import json

import pytest

from fortipam_mcp.discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from fortipam_mcp.discovery_entry_create_http_transport import (
    DiscoveryEntryCreateResult, FortiPamDiscoveryEntryCreateHttpTransport,
)
from fortipam_mcp.discovery_cleanup_mcp_action import UnixDiscoveryCleanupLiveWorkflow
from fortipam_mcp.discovery_entry_live_workflow import (
    CONTRACT as CREATE_CONTRACT, UnixDiscoveryCreateLiveWorkflow, source_binding_digest,
)
from fortipam_mcp.discovery_entry_m4_runtime import DiscoveryEntryExecutionBinding
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_discovery_cleanup_mcp_action import _fixture as _cleanup_fixture
from test_discovery_entry_live_workflow import _readback
from test_discovery_entry_create_http_transport import _fixture_transport
from test_discovery_entry_m4_runtime import _DomainReader, _ad_binding, _runtime
from test_v4_execution_kernel import NOW, _authorization
from v4_planning import M4Outcome, M4Verification, canonical_digest


REQUESTER = "b" * 64


def _create_fixture(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    config = SecretMetadataHttpTransportConfig("https://example.test", "synthetic-token", 5, None)
    transport = FortiPamDiscoveryEntryCreateHttpTransport(config)
    request = DisabledUnixDiscoveryCreateInput("bp014-discovery-unix-disabled-20261007-r1", 17)
    state = {"now": 100, "expire_during_read": False, "writes": 0, "exists": False}
    monkeypatch.setattr(FortiPamDiscoveryEntryCreateHttpTransport, "inspect_current",
                        lambda *_: _readback() if state["exists"] else None)

    def reference(*_):
        if state["expire_during_read"]:
            state["now"] = 700
        return "a" * 64

    def create(_self, _request, *, before_dispatch=None, **kwargs):
        if before_dispatch is not None:
            before_dispatch()
        state["writes"] += 1
        state["exists"] = True
        return DiscoveryEntryCreateResult(True, "http_200", 200, _readback())

    monkeypatch.setattr(FortiPamDiscoveryEntryCreateHttpTransport, "inspect_credential_reference", reference)
    monkeypatch.setattr(FortiPamDiscoveryEntryCreateHttpTransport, "create_and_readback", create)
    workflow = UnixDiscoveryCreateLiveWorkflow(
        transport, request, tmp_path / "source.json", clock=lambda: state["now"],
    )
    return workflow, state


@pytest.mark.parametrize("operation", ["confirm", "execute"])
def test_create_intent_expires_during_workflow_read_without_authorization_or_claim(tmp_path, monkeypatch, operation):
    workflow, state = _create_fixture(tmp_path, monkeypatch)
    preview = workflow.preview(requester_digest=REQUESTER)
    assert preview["expires_at"] == 700
    reference = preview["preview_ref"]
    if operation == "execute":
        reference = workflow.confirm(reference, requester_digest=REQUESTER)["authorization_ref"]
    state["expire_during_read"] = True
    with pytest.raises(RuntimeError):
        getattr(workflow, operation)(reference, requester_digest=REQUESTER)
    assert state["now"] == 700 and state["writes"] == 0
    assert not (tmp_path / "source.json").exists()
    if operation == "confirm":
        assert workflow._authorized == {}


def test_create_expiry_in_final_native_transport_read_retains_parent_claim_without_post(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    transport, request, native = _fixture_transport(monkeypatch)
    clock = {"now": 100, "reads": 0, "posts": 0}
    original_reference = FortiPamDiscoveryEntryCreateHttpTransport.inspect_credential_reference
    original_post = FortiPamDiscoveryEntryCreateHttpTransport._post_once

    def reference(self, request):
        result = original_reference(self, request)
        clock["reads"] += 1
        if clock["reads"] == 4:
            clock["now"] = 700
        return result

    def post(self, request):
        clock["posts"] += 1
        return original_post(self, request)

    monkeypatch.setattr(FortiPamDiscoveryEntryCreateHttpTransport, "inspect_credential_reference", reference)
    monkeypatch.setattr(FortiPamDiscoveryEntryCreateHttpTransport, "_post_once", post)
    workflow = UnixDiscoveryCreateLiveWorkflow(
        transport, request, tmp_path / "source.json", clock=lambda: clock["now"],
    )
    preview = workflow.preview(requester_digest=REQUESTER)
    authorized = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    result = workflow.execute(authorized["authorization_ref"], requester_digest=REQUESTER)
    assert result["outcome"] == "reconciliation_required"
    assert clock["reads"] == 4 and clock["now"] == 700 and clock["posts"] == 0
    assert native["row"] is None and transport._create_attempted is False
    assert (tmp_path / "source.json").is_file()
    retained = (tmp_path / "source.json").read_bytes()
    clock["now"] = 100
    with pytest.raises(RuntimeError):
        workflow.execute(authorized["authorization_ref"], requester_digest=REQUESTER)
    assert clock["posts"] == 0 and (tmp_path / "source.json").read_bytes() == retained


def test_cleanup_expiry_in_final_native_record_read_retains_intent_without_delete_claim(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    original_transport, request, native = _fixture_transport(monkeypatch)
    assert original_transport.create_and_readback(request).verified
    reference = original_transport.inspect_credential_reference(request)
    creation = tmp_path / "create.json"
    creation.write_text(json.dumps({
        "contract": CREATE_CONTRACT, "reference_digest": reference,
        "source_binding_digest": source_binding_digest(request),
        "state": "post_attempt_reserved", "reserved_at": 100,
    }))
    creation.chmod(0o600)
    creation_bytes = creation.read_bytes()
    clock = {"now": 100, "reads": 0}
    original_read = FortiPamDiscoveryEntryCreateHttpTransport._read_cleanup_digest

    def read(self, request):
        result = original_read(self, request)
        clock["reads"] += 1
        if clock["reads"] == 4:
            clock["now"] = 700
        return result

    monkeypatch.setattr(FortiPamDiscoveryEntryCreateHttpTransport, "_read_cleanup_digest", read)
    workflow = UnixDiscoveryCleanupLiveWorkflow(
        original_transport._config, request, accepted_digest=original_transport._bound_digest,
        creation_claim_sha256=hashlib.sha256(creation_bytes).hexdigest(),
        creation_claim=creation, intent_claim=tmp_path / "intent.json",
        cleanup_claim=tmp_path / "delete.json", clock=lambda: clock["now"],
    )
    preview = workflow.preview(requester_digest=REQUESTER)
    authorized = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    result = workflow.execute(authorized["authorization_ref"], requester_digest=REQUESTER)
    assert result["outcome"] == "reconciliation_required"
    assert result["authorization_claim_consumed"] is True
    assert result["transport_claim_consumed"] is False
    assert clock["reads"] == 4 and clock["now"] == 700
    assert native["deletes"] == 0 and native["row"] is not None
    assert creation.read_bytes() == creation_bytes
    assert (tmp_path / "intent.json").is_file() and not (tmp_path / "delete.json").exists()
    retained = (tmp_path / "intent.json").read_bytes()
    clock["now"] = 100
    with pytest.raises(RuntimeError):
        workflow.execute(authorized["authorization_ref"], requester_digest=REQUESTER)
    assert native["deletes"] == 0 and (tmp_path / "intent.json").read_bytes() == retained


@pytest.mark.parametrize("late_clock", ["authorization_expiry", "plan_expiry", "before_issue", "native_bool", "native_float"])
def test_ad_final_domain_read_rechecks_private_authorization_lifetime_without_post(tmp_path, monkeypatch, late_clock):
    source = _ad_binding(monkeypatch)
    clock = {"now": NOW, "late": None}

    class Reader(_DomainReader):
        def inspect_domain_account_projection(self, binding, *, expected_secret_id=None):
            result = super().inspect_domain_account_projection(binding, expected_secret_id=expected_secret_id)
            if self.inspections == 4:
                clock["now"] = clock["late"]
            return result

    reader = Reader(monkeypatch)
    runtime, resolver, store, transport, native = _runtime(
        tmp_path, monkeypatch, source, domain_reader=reader,
    )
    runtime._clock = lambda: clock["now"]
    if late_clock == "plan_expiry":
        base = resolver.binding.plan
        content = {**base.canonical_content(), "expires_at": NOW + 60}
        plan = replace(base, expires_at=NOW + 60, plan_digest=canonical_digest(content))
        resolver.binding = DiscoveryEntryExecutionBinding(plan, _authorization(plan), source)
    binding = resolver.binding
    clock["late"] = {
        "authorization_expiry": binding.authorization.expires_at,
        "plan_expiry": binding.plan.expires_at,
        "before_issue": binding.authorization.issued_at - 1,
        "native_bool": True, "native_float": float(NOW),
    }[late_clock]
    result = runtime.execute_bound(
        binding.authorization.authorization_ref, expected_binding_digest=source.parameters_digest,
    )
    assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert result.verification is M4Verification.UNKNOWN
    assert reader.inspections == 4 and store.claim_count == 1
    assert native["posts"] == 0 and transport._create_attempted is False
    assert all(method == "GET" for method, _ in native["calls"])
    clock["now"] = NOW
    replay = runtime.execute_bound(
        binding.authorization.authorization_ref, expected_binding_digest=source.parameters_digest,
    )
    assert replay.idempotent_replay and replay.outcome is result.outcome
    assert store.claim_count == 1 and native["posts"] == 0


@pytest.mark.parametrize("operation", ["confirm", "execute"])
def test_cleanup_intent_expires_during_workflow_read_preserving_creation_claim(tmp_path, monkeypatch, operation):
    workflow, state, _ = _cleanup_fixture(tmp_path, monkeypatch)
    creation = (tmp_path / "create.json").read_bytes()
    preview = workflow.preview(requester_digest=REQUESTER)
    assert preview["expires_at"] == 700
    reference = preview["preview_ref"]
    if operation == "execute":
        reference = workflow.confirm(reference, requester_digest=REQUESTER)["authorization_ref"]

    def reference_read(*_):
        state["now"] = 700
        return state["reference"]

    monkeypatch.setattr(FortiPamDiscoveryEntryCreateHttpTransport, "inspect_credential_reference", reference_read)
    with pytest.raises(RuntimeError):
        getattr(workflow, operation)(reference, requester_digest=REQUESTER)
    assert state["now"] == 700 and state["writes"] == 0
    assert (tmp_path / "create.json").read_bytes() == creation
    assert not (tmp_path / "intent.json").exists()
    assert not (tmp_path / "delete.json").exists()
    if operation == "confirm":
        assert workflow._authorized == {}
