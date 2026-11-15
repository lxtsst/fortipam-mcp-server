"""Actual LDAP/M4/C3 joins against the synthetic HTTP peer, without network."""
from __future__ import annotations

import copy
from dataclasses import asdict
import json
from pathlib import Path
import pickle
from typing import Any, cast

import pytest

from fortipam_mcp.ldap_server_live_workflow import LdapServerLiveWorkflow, LdapServerLiveWorkflowError
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from v4_planning import M4AuthorizationDenied
from v4_planning.material_provider import MaterialAccessDenied
from v4_planning.material_runtime import MaterialRuntimeOutcome, material_lease_request_digest

from test_ldap_server_http_transport import Loader, setup
from test_ldap_server_m4_runtime import _stores
from test_ldap_server_projection import SERIAL

REQUESTER = "1" * 64
TRANSPORT = "2" * 64
IDENTITY = {"requester_digest": REQUESTER, "transport_digest": TRANSPORT}
AUTHORITY_KEY = b"synthetic-authority-key-ldap-000001"


def _make(tmp_path: Path, peer: Any, state: Path, now: list[int],
          loader: Loader | None = None, **overrides: Any) -> tuple[LdapServerLiveWorkflow, Loader]:
    loader = loader if loader is not None else Loader(peer.binding)
    execution, material = _stores(tmp_path)
    kwargs: dict[str, Any] = {
        "expected_serial": SERIAL, "state_directory": state, "loader": loader,
        "execution_store": execution, "material_store": material, "authority_key": AUTHORITY_KEY,
        "environment_ref": "synthetic-lab-environment", "scope_ref": "synthetic-lab-scope",
        "audience_ref": "synthetic-lab-audience", "allowed_requester_digest": REQUESTER,
        "allowed_transport_digest": TRANSPORT, "execution_enabled": True,
        "clock": lambda: now[0], "connection_factory": peer.connection,
    }
    kwargs.update(overrides)
    if kwargs["execution_enabled"] is None:
        del kwargs["execution_enabled"]
    return LdapServerLiveWorkflow(peer.binding,
        SecretMetadataHttpTransportConfig("https://pam.example", "synthetic-token", 5, None), **kwargs), loader


def _setup(tmp_path: Path, **overrides: Any) -> Any:
    _, peer, state, now = setup(tmp_path)
    workflow, loader = _make(tmp_path, peer, state, now, **overrides)
    return workflow, loader, peer, state, now


def _authorize(workflow: LdapServerLiveWorkflow) -> str:
    preview = workflow.preview(**IDENTITY)
    authorized = workflow.authorize(cast(str, preview["preview_ref"]), **IDENTITY)
    return cast(str, authorized["authorization_ref"])


def test_real_authority_to_http_join_and_minimized_replay(tmp_path: Path) -> None:
    workflow, loader, peer, _, now = _setup(tmp_path)
    assert peer.connections == [] and loader.loads == 0
    preview = workflow.preview(**IDENTITY)
    assert preview["expires_at"] == 160 and preview["policy_mode"] == "lab_auto"
    now[0] = 103
    authorized = workflow.authorize(preview["preview_ref"], **IDENTITY)
    assert authorized["expires_at"] == preview["expires_at"]
    assert loader.loads == peer.binds == peer.posts == 0
    result = workflow.execute(authorized["authorization_ref"], **IDENTITY)
    assert result["outcome"] == "succeeded" and result["verification"] == "verified"
    assert result["idempotent_replay"] is False
    assert loader.loads == peer.posts == peer.binds == 1 and peer.deletes == 0
    assert loader.buffers is not None and not any(any(value) for value in loader.buffers)
    count = len(peer.connections)
    replay = workflow.execute(authorized["authorization_ref"], **IDENTITY)
    assert replay == {**result, "idempotent_replay": True}
    assert len(peer.connections) == count and loader.loads == peer.posts == 1
    rendered = json.dumps([preview, authorized, result, replay])
    for private in (peer.binding.name, peer.binding.server, peer.binding.dn, peer.binding.ca_name,
                    peer.binding.username, peer.binding.private_nonce, "synthetic-token",
                    "synthetic-lab-environment", "synthetic-lab-scope", "synthetic-lab-audience"):
        assert private not in rendered
    assert set(result) == {"contract", "outcome", "verification", "compensation", "idempotent_replay"}


@pytest.mark.parametrize("stage", ["preview", "authorize", "execute"])
@pytest.mark.parametrize("field", ["requester_digest", "transport_digest"])
@pytest.mark.parametrize("value", [None, "", "9" * 64])
def test_identity_is_required_and_pinned_before_all_effects(tmp_path: Path, stage: str, field: str, value: Any) -> None:
    workflow, loader, peer, _, _ = _setup(tmp_path)
    preview = workflow.preview(**IDENTITY)
    authorized = workflow.authorize(preview["preview_ref"], **IDENTITY)
    count = len(peer.connections)
    identity = {**IDENTITY, field: value}
    args = () if stage == "preview" else (preview["preview_ref"] if stage == "authorize" else authorized["authorization_ref"],)
    with pytest.raises(LdapServerLiveWorkflowError):
        getattr(workflow, stage)(*args, **identity)
    assert len(peer.connections) == count and loader.loads == peer.binds == peer.posts == 0


@pytest.mark.parametrize("field", ["requester_digest", "transport_digest"])
def test_omitted_identity_argument_is_not_accepted(tmp_path: Path, field: str) -> None:
    workflow, loader, peer, _, _ = _setup(tmp_path)
    kwargs = dict(IDENTITY)
    del kwargs[field]
    with pytest.raises(TypeError):
        workflow.preview(**kwargs)
    assert peer.connections == [] and loader.loads == 0


@pytest.mark.parametrize("override", [
    {"environment_ref": "another-lab-environment"}, {"scope_ref": "another-lab-scope"},
    {"audience_ref": "another-lab-audience"}, {"authority_key": b"different-authority-key-000000001"},
    {"allowed_requester_digest": "8" * 64}, {"allowed_transport_digest": "8" * 64},
])
def test_signed_preview_cannot_be_transplanted_to_another_namespace(tmp_path: Path, override: dict[str, Any]) -> None:
    original, loader, peer, state, now = _setup(tmp_path)
    preview = original.preview(**IDENTITY)
    other, _ = _make(tmp_path, peer, state, now, loader, **override)
    # Even bypassing the volatile ref registry cannot bypass its HMAC context.
    other._preview = original._preview
    identity = {"requester_digest": override.get("allowed_requester_digest", REQUESTER),
                "transport_digest": override.get("allowed_transport_digest", TRANSPORT)}
    count = len(peer.connections)
    with pytest.raises(LdapServerLiveWorkflowError):
        other.authorize(cast(str, preview["preview_ref"]), **identity)
    assert loader.loads == peer.posts == 0 and len(peer.connections) == count


def test_hmac_verifier_rejects_tampered_issued_plan(tmp_path: Path) -> None:
    workflow, loader, peer, _, _ = _setup(tmp_path)
    ref = _authorize(workflow)
    issued = workflow._authority._issued
    assert issued is not None
    object.__setattr__(issued.plan, "summary_digest", "f" * 64)
    with pytest.raises(M4AuthorizationDenied):
        workflow._authority.verify(issued.plan, issued.authorization, now_epoch=100)
    with pytest.raises(LdapServerLiveWorkflowError):
        workflow.execute(ref, **IDENTITY)
    assert workflow._execution_store.claim_count == loader.loads == peer.posts == 0


@pytest.mark.parametrize("stage", ["authorize", "execute"])
def test_unchanged_deadline_refuses_expiry(tmp_path: Path, stage: str) -> None:
    workflow, loader, peer, _, now = _setup(tmp_path)
    preview = workflow.preview(**IDENTITY)
    ref = preview["preview_ref"]
    if stage == "execute":
        ref = workflow.authorize(ref, **IDENTITY)["authorization_ref"]
    now[0] = 160
    count = len(peer.connections)
    with pytest.raises(LdapServerLiveWorkflowError):
        getattr(workflow, stage)(ref, **IDENTITY)
    assert loader.loads == peer.binds == peer.posts == 0 and len(peer.connections) == count


def test_clock_rollback_is_sticky(tmp_path: Path) -> None:
    workflow, loader, peer, _, now = _setup(tmp_path)
    preview = workflow.preview(**IDENTITY)
    now[0] = 99
    with pytest.raises(LdapServerLiveWorkflowError):
        workflow.authorize(preview["preview_ref"], **IDENTITY)
    now[0] = 101
    with pytest.raises(LdapServerLiveWorkflowError):
        workflow.preview(**IDENTITY)
    assert loader.loads == peer.binds == peer.posts == 0


@pytest.mark.parametrize("stage", ["authorize", "execute"])
def test_fresh_source_drift_precedes_material_loading(tmp_path: Path, stage: str) -> None:
    workflow, loader, peer, _, _ = _setup(tmp_path)
    preview = workflow.preview(**IDENTITY)
    ref = preview["preview_ref"]
    if stage == "execute":
        ref = workflow.authorize(ref, **IDENTITY)["authorization_ref"]
    peer.defaults["group-filter"] = "synthetic-source-drift"
    if stage == "authorize":
        with pytest.raises(LdapServerLiveWorkflowError):
            workflow.authorize(ref, **IDENTITY)
    else:
        result = workflow.execute(ref, **IDENTITY)
        assert result["outcome"] == "precondition_failed"
    assert loader.loads == peer.binds == peer.posts == 0


@pytest.mark.parametrize("enabled", [None, False])
def test_default_gate_allows_only_preview(tmp_path: Path, enabled: bool | None) -> None:
    workflow, loader, peer, _, _ = _setup(tmp_path, execution_enabled=enabled)
    preview = workflow.preview(**IDENTITY)
    count = len(peer.connections)
    with pytest.raises(LdapServerLiveWorkflowError):
        workflow.authorize(preview["preview_ref"], **IDENTITY)
    with pytest.raises(LdapServerLiveWorkflowError):
        workflow.execute("ldap-auth-unknown", **IDENTITY)
    assert loader.loads == peer.binds == peer.posts == 0 and len(peer.connections) == count


@pytest.mark.parametrize("unknown", [False, True])
def test_durable_claim_blocks_new_preview_and_restart_reissue(tmp_path: Path, unknown: bool) -> None:
    workflow, loader, peer, state, now = _setup(tmp_path)
    ref = _authorize(workflow)
    peer.lost_post_ack = unknown
    result = workflow.execute(ref, **IDENTITY)
    assert result["outcome"] == ("reconciliation_required" if unknown else "succeeded")
    assert workflow.execute(ref, **IDENTITY)["idempotent_replay"] is True
    count = len(peer.connections)
    with pytest.raises(LdapServerLiveWorkflowError):
        workflow.preview(**IDENTITY)
    restarted, fresh_loader = _make(tmp_path, peer, state, now)
    with pytest.raises(LdapServerLiveWorkflowError):
        restarted.execute(ref, **IDENTITY)
    with pytest.raises(LdapServerLiveWorkflowError):
        restarted.preview(**IDENTITY)
    # A fresh HTTP directory cannot reset the dedicated persistent M4 claim.
    fresh_state = tmp_path / "fresh-http"
    fresh_state.mkdir(mode=0o700)
    redirected, redirected_loader = _make(tmp_path, peer, fresh_state, now)
    with pytest.raises(LdapServerLiveWorkflowError):
        redirected.preview(**IDENTITY)
    assert peer.posts == loader.loads == 1 and fresh_loader.loads == redirected_loader.loads == 0
    assert len(peer.connections) == count and peer.deletes == 0


def test_restart_does_not_recognize_unconsumed_volatile_authorization(tmp_path: Path) -> None:
    workflow, loader, peer, state, now = _setup(tmp_path)
    ref = _authorize(workflow)
    restarted, _ = _make(tmp_path, peer, state, now)
    count = len(peer.connections)
    with pytest.raises(LdapServerLiveWorkflowError):
        restarted.execute(ref, **IDENTITY)
    assert len(peer.connections) == count and loader.loads == peer.posts == 0


def test_prior_http_claim_blocks_preview_without_material_or_network(tmp_path: Path) -> None:
    workflow, loader, peer, state, _ = _setup(tmp_path)
    claim = state / "create.claim.json"
    claim.write_text("{}", encoding="ascii")
    claim.chmod(0o600)
    with pytest.raises(LdapServerLiveWorkflowError):
        workflow.preview(**IDENTITY)
    assert peer.connections == [] and loader.loads == peer.posts == 0


def test_unfinished_material_claim_survives_join_without_reloading(tmp_path: Path) -> None:
    workflow, loader, peer, _, _ = _setup(tmp_path)
    ref = _authorize(workflow)
    issued = workflow._authority._issued
    assert issued is not None
    workflow._material_store.claim(request_digest=material_lease_request_digest(issued.lease_request),
                                  authorization_digest=issued.authorization.authorization_digest)
    with pytest.raises(LdapServerLiveWorkflowError):
        workflow.execute(ref, **IDENTITY)
    assert loader.loads == peer.binds == peer.posts == 0


@pytest.mark.parametrize("terminal", [False, True])
def test_unrelated_material_claim_blocks_new_preview_before_reads(tmp_path: Path, terminal: bool) -> None:
    workflow, loader, peer, state, now = _setup(tmp_path)
    store = workflow._material_store
    store.claim(request_digest="a" * 64, authorization_digest="b" * 64)
    if terminal:
        store.finalize(request_digest="a" * 64, authorization_digest="b" * 64,
                       outcome=MaterialRuntimeOutcome.RECONCILIATION_REQUIRED)
    assert workflow._execution_store.claim_count == 0 and store.claim_count == 1
    with pytest.raises(LdapServerLiveWorkflowError):
        workflow.preview(**IDENTITY)
    restarted, fresh_loader = _make(tmp_path, peer, state, now)
    with pytest.raises(LdapServerLiveWorkflowError):
        restarted.preview(**IDENTITY)
    assert peer.connections == [] and loader.loads == fresh_loader.loads == peer.posts == 0


def test_workflow_is_opaque_and_copy_serialization_are_denied(tmp_path: Path) -> None:
    workflow, _, peer, _, _ = _setup(tmp_path)
    assert peer.binding.username not in repr(workflow)
    assert AUTHORITY_KEY.decode() not in str(workflow)
    assert not hasattr(workflow, "__dict__")
    with pytest.raises(TypeError):
        asdict(workflow)
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(MaterialAccessDenied):
            operation(workflow)


@pytest.mark.parametrize("change", [
    {"environment_ref": ""}, {"scope_ref": ""}, {"audience_ref": ""},
    {"allowed_requester_digest": ""}, {"allowed_transport_digest": ""},
    {"authority_key": b"too-short"}, {"execution_enabled": 1},
])
def test_constructor_rejects_incomplete_authority(tmp_path: Path, change: dict[str, Any]) -> None:
    _, peer, state, now = setup(tmp_path)
    with pytest.raises(LdapServerLiveWorkflowError):
        _make(tmp_path, peer, state, now, **change)
    assert peer.connections == [] and peer.posts == 0
