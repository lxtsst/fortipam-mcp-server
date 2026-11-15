"""Run the real create intent workflow, persistent store and fixed REST adapter."""

from __future__ import annotations

import json
from pathlib import Path
import stat
from typing import Any

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.local_user_create_live_workflow import (
    BP002_ENABLED_GUEST_WORKFLOW_CONTRACT,
    LocalUserCreateLiveWorkflow, LocalUserCreateLiveWorkflowError, _claim_inputs,
)
from fortipam_mcp.local_user_reset_fixture_transport import (
    FortiPamLocalUserResetFixtureTransport, LocalUserResetFixtureTransportError, _CREATE,
)
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.local_user_create_mcp_action import (
    ProtectedLocalUserCreateMcpAction, V4LocalUserCreateActionRuntimeError,
    local_user_create_action_principal_from_access_token,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings
from v4_planning import M4ClaimState, M4Outcome

from test_local_user_reset_fixture_preflight import Harness as PreflightHarness
from test_local_user_reset_name_reader import NAME, PRINCIPAL
from test_local_user_reset_projection import _body

REQUESTER = "a" * 64


class Harness:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.directory = root / "fixture"; self.directory.mkdir(mode=0o700)
        self.key = root / "ledger.key"; self.key.write_bytes(b"k" * 32); self.key.chmod(0o600)
        self.state = PersistentM4ExecutionStateStore(root / "ledger.sqlite3", self.key)
        self.preflight = PreflightHarness()
        self.detail = _body({}, mkey=NAME)
        self.creates = self.detail_reads = 0
        self.post_failure = ""
        self.modify_readback = False
        self.late_gate_close = False
        self.late_expiry = False
        self.before_post: Any = None
        self.now = 100
        self.transport = self.new_transport()
        self.workflow = LocalUserCreateLiveWorkflow(self.transport, clock=lambda: self.now, execution_store=self.state,
            workflow_contract=BP002_ENABLED_GUEST_WORKFLOW_CONTRACT)

    def new_transport(self) -> FortiPamLocalUserResetFixtureTransport:
        return FortiPamLocalUserResetFixtureTransport(
            self.preflight.network.reader._config, username=NAME, api_principal=PRINCIPAL,
            material_directory=self.directory, enabled=True, connection_factory=self.connect,
        )

    def connect(self, *args: Any, **kwargs: Any) -> Any:
        connection = self.preflight.connect(*args, **kwargs)
        original = connection.request
        if self.late_gate_close and self.transport._attempted:
            self.transport._enabled = False
        if self.late_expiry and self.transport._attempted:
            self.now = 701

        def request(method: str, path: str, *, body: Any = None, headers: dict[str, str]) -> None:
            if path == _CREATE:
                assert method == "POST" and isinstance(body, memoryview)
                assert "X-HTTP-Method-Override" not in headers
                record = next(iter(self.workflow._records.values()))
                # Reopen the real ledger before the HTTP request. Its reservation
                # must already survive loss of all volatile workflow state.
                reopened = PersistentM4ExecutionStateStore(self.root / "ledger.sqlite3", self.key)
                assert reopened.claim(**_claim_inputs(record)).state is M4ClaimState.IN_PROGRESS
                if self.before_post is not None:
                    self.before_post()
                self.creates += 1
                selected = json.loads(body.tobytes())
                password = selected.pop("password")
                assert password.encode() == (self.directory / "initial-password").read_bytes()
                selected.update(id=17, q_ref=0)
                selected["vdom"] = [{"name": "synthetic-scope", "q_origin_key": "synthetic-scope"}]
                if self.modify_readback:
                    selected["comments"] = "synthetic-drift"
                self.detail = _body(selected, mkey=NAME)
                connection.response.body = _body({}, http_method="POST", mkey=NAME, revision_changed=True,
                    old_revision="synthetic-before", revision="synthetic-after").replace(b',"results":{}', b'')
                if self.post_failure == "timeout":
                    raise TimeoutError
                if self.post_failure == "wrong_identity":
                    connection.response.body = _body({}, http_method="POST", mkey="different-fixture")
            elif path == self.transport._detail:
                assert method == "GET" and body is None
                self.detail_reads += 1
                connection.response.body = self.detail
            else:
                original(method, path, body=body, headers=headers)

        connection.request = request
        return connection

    def confirm(self) -> str:
        preview = self.workflow.preview(username=NAME, requester_digest=REQUESTER)
        return str(self.workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)["authorization_ref"])

    def execute(self, reference: str) -> dict[str, object]:
        return self.workflow.execute(reference, requester_digest=REQUESTER)


def test_existing_intent_flow_creates_once_and_retains_private_material_and_readback(tmp_path: Path) -> None:
    h = Harness(tmp_path); reference = h.confirm()
    assert h.creates == 0 and not list(h.directory.iterdir())
    result = h.execute(reference)
    assert result["outcome"] == "succeeded" and result["credentials_returned"] is False
    assert h.creates == h.detail_reads == 1
    assert h.transport._created is not None
    for name in ("initial-password", "created-readback.json"):
        assert stat.S_IMODE((h.directory / name).stat().st_mode) == 0o600
    evidence = json.loads((h.directory / "created-readback.json").read_bytes())
    assert evidence["user_id"] == 17 and evidence["username"] == NAME
    assert h.state.audit_events[-1].outcome is M4Outcome.SUCCEEDED
    assert NAME not in json.dumps(result) and "password" not in evidence
    assert h.execute(reference)["idempotent_replay"] is True
    assert h.creates == 1
    h.preflight.disposed()


def test_enabled_guest_requires_its_explicit_contract_and_matching_state(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    with pytest.raises(LocalUserCreateLiveWorkflowError):
        LocalUserCreateLiveWorkflow(h.transport, execution_store=h.state)
    preview = h.workflow.preview(username=NAME, requester_digest=REQUESTER)
    assert preview["Proposed Changes"]["status"] == "enable"
    assert preview["Proposed Changes"]["access_profile"] == "Guest"
    assert preview["Expected State"]["status_enabled"] is True
    assert "status_disabled" not in preview["Expected State"]
    reference = h.workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)["authorization_ref"]
    assert h.execute(str(reference))["outcome"] == "succeeded"
    assert json.loads(h.transport._expected.draft._wire)["status"] == "enable"
    assert h.state.claim_count == 1 and h.creates == 1
    h.preflight.disposed()


def test_rest_fixture_cannot_use_legacy_unguarded_or_nonpersistent_entry(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    with pytest.raises(LocalUserCreateLiveWorkflowError): LocalUserCreateLiveWorkflow(h.transport)
    with pytest.raises(LocalUserResetFixtureTransportError): h.transport.create_and_readback(NAME)
    assert h.creates == 0 and not list(h.directory.iterdir())


def test_changed_complete_preflight_invalidates_the_existing_confirmation(tmp_path: Path) -> None:
    h = Harness(tmp_path); reference = h.confirm()
    path = next(path for path in h.preflight.bodies if "action=default" in path)
    defaults = json.loads(h.preflight.bodies[path])
    defaults["results"]["comments"] = "synthetic-valid-default-drift"
    h.preflight.bodies[path] = bytearray(json.dumps(defaults).encode())
    with pytest.raises(LocalUserCreateLiveWorkflowError): h.execute(reference)
    assert h.creates == 0 and not list(h.directory.iterdir())


@pytest.mark.parametrize("failure", ["timeout", "wrong_identity", "changed_readback"])
def test_uncertain_create_is_read_reconciled_but_never_reattributed_or_replayed(tmp_path: Path, failure: str) -> None:
    h = Harness(tmp_path); h.post_failure = failure; h.modify_readback = failure == "changed_readback"
    reference = h.confirm(); result = h.execute(reference)
    assert result["outcome"] == "reconciliation_required"
    assert h.creates == h.detail_reads == 1 and h.transport._created is None
    assert (h.directory / "initial-password").is_file()
    assert not (h.directory / "created-readback.json").exists()
    assert h.state.audit_events[-1].outcome is M4Outcome.RECONCILIATION_REQUIRED
    with pytest.raises(LocalUserCreateLiveWorkflowError): h.execute(reference)
    assert h.creates == 1
    h.preflight.disposed()


def test_pending_material_blocks_a_new_process_and_new_intent(tmp_path: Path) -> None:
    h = Harness(tmp_path); h.post_failure = "timeout"; h.execute(h.confirm())
    retained = (h.directory / "initial-password").read_bytes()
    h.transport = h.new_transport()
    h.workflow = LocalUserCreateLiveWorkflow(h.transport, clock=lambda: h.now, execution_store=h.state,
        workflow_contract=BP002_ENABLED_GUEST_WORKFLOW_CONTRACT)
    assert h.execute(h.confirm())["outcome"] == "reconciliation_required"
    assert h.creates == 1 and (h.directory / "initial-password").read_bytes() == retained


def test_final_transport_gate_is_checked_after_material_persistence(tmp_path: Path) -> None:
    h = Harness(tmp_path); reference = h.confirm(); h.late_gate_close = True
    assert h.execute(reference)["outcome"] == "reconciliation_required"
    assert h.creates == 0 and (h.directory / "initial-password").exists()


def test_actual_intent_expiry_is_rechecked_at_the_http_dispatch_boundary(tmp_path: Path) -> None:
    h = Harness(tmp_path); reference = h.confirm(); h.late_expiry = True
    assert h.execute(reference)["outcome"] == "reconciliation_required"
    assert h.creates == 0


def test_durable_finalize_failure_does_not_report_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness(tmp_path); reference = h.confirm()
    def failed(**kwargs: Any) -> None: raise OSError
    monkeypatch.setattr(h.state, "finalize", failed)
    assert h.execute(reference)["outcome"] == "reconciliation_required"
    assert h.creates == 1
    assert not h.state.audit_events
    with pytest.raises(LocalUserCreateLiveWorkflowError): h.execute(reference)


def test_material_symlink_is_not_followed_or_overwritten(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    protected = tmp_path / "unrelated"; protected.write_bytes(b"synthetic-preserve")
    (h.directory / "initial-password").symlink_to(protected)
    assert h.execute(h.confirm())["outcome"] == "reconciliation_required"
    assert h.creates == 0 and protected.read_bytes() == b"synthetic-preserve"


def test_existing_sdk_principal_and_protected_action_drive_durable_rest_fixture(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    resource = "https://mcp.example.test/fpamcp-v4"
    settings = V4PlanningAuthorizationSettings(resource, b"p" * 32)
    def principal(client: str, scopes: list[str]) -> Any:
        return local_user_create_action_principal_from_access_token(AccessToken(
            token="synthetic-sdk-validated-token", client_id=client, scopes=scopes,
            expires_at=2_000_000_000, resource=resource,
            subject=client, claims={"iss": "https://mcp.example.test/oauth"},
        ), settings)
    # This test composes the existing SDK principal boundary; it is not an
    # assertion that a real OAuth login or MCP HTTP acceptance happened.
    scopes = ["fortipam:read", "fortipam:plan"]
    with pytest.raises(V4LocalUserCreateActionRuntimeError): principal("synthetic-client", scopes)
    owner = principal("synthetic-client", [*scopes, "fortipam:operate"])
    stranger = principal("synthetic-other", [*scopes, "fortipam:operate"])
    action = ProtectedLocalUserCreateMcpAction(h.workflow, execution_enabled=True)
    preview = action.preview(NAME, owner)
    confirmation = action.confirm(str(preview["preview_ref"]), owner)
    with pytest.raises(V4LocalUserCreateActionRuntimeError): action.execute(str(confirmation["authorization_ref"]), stranger)
    assert h.creates == 0
    assert action.execute(str(confirmation["authorization_ref"]), owner)["outcome"] == "succeeded"
    assert h.creates == 1
