"""Synthetic signed creation + single Owner API/CLI + durable transition claims."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from fortipam_mcp import isolated_folder_policy_transition_http_transport as module
from fortipam_mcp.isolated_folder_creation_ownership import IsolatedFolderCreationSnapshot
from fortipam_mcp.isolated_folder_live_workflow import IsolatedFolderLiveWorkflow
from fortipam_mcp.isolated_folder_m4_adapter import IsolatedFolderBinding
from fortipam_mcp.isolated_folder_policy_transition_contract import IsolatedFolderPolicyTransitionBinding
from fortipam_mcp.isolated_folder_policy_transition_live_workflow import IsolatedFolderPolicyTransitionLiveWorkflow
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from v4_planning import canonical_digest
from test_isolated_folder_creation_ownership import folder
from test_isolated_folder_m4_adapter import Transport
from test_single_secret_folder_membership_candidate import Peer, OWNER, envelope, global_columns
from test_single_secret_folder_membership_source import FOLDER_NAME, SERIAL, binding

CREATOR = "b" * 64
POLICY = "Synthetic Fixed Policy"
PARENT_PATH = "Public/Synthetic-Parent"


class CreationTransport(Transport):
    def __init__(self, row: dict[str, Any], parent: dict[str, Any]):
        super().__init__(None)
        self.row = deepcopy(row)
        self.parent = deepcopy(parent)

    def read_parent_digest(self, identifier):
        assert identifier == self.parent["id"]
        return canonical_digest(self.parent)

    def read_creation_device_serial(self): return SERIAL

    def find_child_ids(self, name, parent): return (42,) if self.posts else ()

    def create_isolated_child(self, **kwargs):
        super().create_isolated_child(**kwargs)
        return {"http_status": 200, "mkey": 42}

    def read_created_folder_snapshot(self, identifier, **kwargs):
        assert identifier == 42
        return IsolatedFolderCreationSnapshot(SERIAL, self.row)


class PolicyPeer(Peer):
    def __init__(self):
        super().__init__()
        self.row = folder()
        self.row.update(id=42, name=FOLDER_NAME, **{"parent-folder": 7})
        self.parent = dict(folder(), id=7, name="Synthetic-Parent",
                           **{"parent-folder": 0, "secret-policy": "Synthetic Parent Policy"})
        self.inherited_policy = ""
        self.definition = {"name": POLICY, "recording": "enable", "block-clipboard": "disable",
                           "rdp-event-filter": "not-set"}
        self.puts: list[dict[str, Any]] = []
        self.fault: str | None = None
        self.reads = 0
        self.parent_reads = 0
        self.parent_drift_at = None
        self.complete_policy_reads = 0
        self.complete_policy_changes: dict[str, Any] = {}
        self.postwrite_policy_changes: dict[str, Any] = {}

    def read_columns(self):
        assert self.active
        self.calls.append("SSH columns")
        return global_columns()

    def respond(self, request):
        path = request.url.path
        assert "authorization" not in request.headers
        if path == "/XX/YY/ZZ/AUTH":
            response = super().respond(request)
            if self.fault != "csrf": response.headers["set-cookie"] = "ccsrftoken=synthetic-csrf; Secure; Path=/"
            return response
        if path.startswith("/api/v2/utility/id/"):
            assert self.active and request.method == "GET" and request.url.params["type"] == "folder"
            self.calls.append(path)
            identifier = 7 if path.endswith("/Synthetic-Parent") else 42
            return httpx.Response(200, json=envelope("id", {"id": identifier}, "utility"))
        if path == "/api/v2/cmdb/secret/folder/7":
            assert self.active and request.method == "GET"
            assert request.url.params["format"] == module._FOLDER_FIELDS
            self.calls.append(path)
            self.parent_reads += 1
            value = envelope("folder", deepcopy(self.parent))
            if self.fault == "parent_serial": value["serial"] = "OTHER"
            if self.fault == "parent_id": value["results"]["id"] = True
            if self.fault == "parent_mkey": value["mkey"] = True
            if self.fault == "parent_missing": del value["results"]["user-permission"]
            if self.parent_reads == self.parent_drift_at:
                value["results"]["secret-policy"] = "Synthetic Changed Parent Policy"
            return httpx.Response(200, json=value)
        if path == "/api/v2/cmdb/secret/folder/42":
            assert self.active
            self.calls.append(path)
            if request.method == "PUT":
                assert not request.url.query and request.headers["x-csrftoken"] == "synthetic-csrf"
                body = json.loads(request.content)
                self.puts.append(body)
                self.row["inherit-policy"] = body["inherit-policy"]
                self.row["secret-policy"] = (self.inherited_policy if body["inherit-policy"] == "enable"
                                             else body["secret-policy"])
                self.complete_policy_changes.update(self.postwrite_policy_changes)
                ack = envelope("folder", {})
                del ack["results"]
                ack.update(http_method="PUT", mkey=42)
                if self.fault == "ack": ack["serial"] = "WRONG"
                if self.fault == "duplicate_ack":
                    return httpx.Response(200, content=json.dumps(ack)[:-1] + ',"build":29}',
                                          headers={"content-type": "application/json"})
                if self.fault == "readback": self.row["ztna-tags-match-logic"] = "or"
                if self.fault == "logout": self.logout_fault = True
                return httpx.Response(200, json=ack)
            assert request.url.params["format"] == module._FOLDER_FIELDS
            self.reads += 1
            value = envelope("folder", deepcopy(self.row))
            if self.fault == "folder_mkey": value["mkey"] = True
            if self.fault == "serial": value["serial"] = "WRONG"
            if self.fault == "final_drift" and self.reads == 3:
                value["results"]["ztna-tags-match-logic"] = "or"
            return httpx.Response(200, json=value)
        if path == "/api/v2/cmdb/secret/policy/" + POLICY:
            if "format" not in request.url.params:
                assert self.active and request.method == "GET"
                assert dict(request.url.params) == {"with_meta": "true", "vdom": "root"}
                self.complete_policy_reads += 1
                payload = json.loads((Path(__file__).parent / "fixtures/policy_assignment_definition.synthetic.json").read_bytes())
                payload.update(serial=SERIAL, mkey=POLICY)
                payload["results"][0].update(self.definition, q_origin_key=POLICY,
                    q_ref=int(len(self.puts) == 1))
                payload["results"][0].update(self.complete_policy_changes)
                return httpx.Response(200, json=payload)
            assert self.active and request.method == "GET" and request.url.params["format"] == module._POLICY_FIELDS
            self.calls.append(path)
            value = envelope("policy", deepcopy(self.definition))
            if self.fault == "policy_mkey": value["mkey"] = "other"
            return httpx.Response(200, json=value)
        return super().respond(request)


@pytest.fixture
def setup(tmp_path, monkeypatch, request):
    tmp_path.chmod(0o700)
    peer = PolicyPeer()
    peer.inherited_policy = getattr(request, "param", "")
    peer.row["secret-policy"] = peer.inherited_policy
    producer = CreationTransport(peer.row, peer.parent)
    creation_binding = IsolatedFolderBinding(FOLDER_NAME, 7, OWNER, producer.read_parent_digest(7))
    key = tmp_path / "key"
    key.write_bytes(b"a" * 32); key.chmod(0o600)
    creation = IsolatedFolderLiveWorkflow(tmp_path / "workflow.sqlite3", key, producer,
        binding=creation_binding, ownership_expected_serial=SERIAL, clock=lambda: 1000)
    preview = creation.preview(folder_name=FOLDER_NAME, parent_folder_id=7, requester_digest=CREATOR)
    authorization = creation.confirm(preview["preview_ref"], requester_digest=CREATOR)
    assert creation.execute(authorization["authorization_ref"], requester_digest=CREATOR)["outcome"] == "succeeded"
    hosts = tmp_path / "known_hosts"
    hosts.write_text("synthetic pinned peer\n"); hosts.chmod(0o600)
    claims = tmp_path / "claims"; claims.mkdir(mode=0o700)
    monkeypatch.setattr(module, "SingleSecretFolderMembershipSshReader", peer.reader)
    config = SecretMetadataHttpTransportConfig("https://fortipam.example.test", "synthetic-token", 5, None)
    args = dict(binding=IsolatedFolderPolicyTransitionBinding(creation_binding, binding(), POLICY),
        creation_workflow=creation, creation_preview_ref=preview["preview_ref"], creator_digest=CREATOR,
        parent_path=PARENT_PATH, credentials=peer.credentials, ssh_host="synthetic.invalid", ssh_port=22,
        ssh_known_hosts_file=hosts, claim_dir=claims, client_factory=peer.client)
    build = lambda enabled=True, **profile: module.IsolatedFolderPolicyHttpTransport(
        config, **args, execution_enabled=enabled, **profile)
    return peer, build, args, producer


def dispatch(transport, current, restore=False, clock=lambda: 1000):
    method = transport.restore_and_readback if restore else transport.transition_and_readback
    return method(current.state_digest, expires_at=1600, clock=clock)


@pytest.mark.parametrize("setup", ("", "Synthetic Inherited Policy"), indirect=True)
def test_real_signed_getter_api_cli_composition_full_native_save_and_exact_owned_restore(setup):
    peer, build, args, producer = setup
    transport = build()
    assert peer.calls == []
    before = transport.inspect_transition()
    assert peer.logins == peer.logouts == 1 and not peer.active
    result = dispatch(transport, before)
    assert result.acknowledged and result.logout_verified and result.after.phase == "explicit"
    saved = peer.puts[0]
    assert len(saved) == 11 and "folder-type" not in saved
    relation = saved["user-permission"][0]
    assert relation["allowed-launcher-type"] == "all" and "q_origin_key" not in relation
    assert "q_origin_key" not in relation["user-name"][0]
    after = transport.inspect_owned_restore()
    restored = dispatch(transport, after, True)
    assert restored.after == before and peer.row == producer.row
    assert peer.puts[1]["inherit-policy"] == "enable" and peer.puts[1]["secret-policy"] == ""
    assert json.loads(restored.after.current_folder_json)["secret-policy"] == peer.inherited_policy
    assert len(peer.puts) == 2 and peer.logins == peer.logouts == 4
    assert peer.credential_calls == 4 and len(peer.ssh_configs) == 4
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in args["claim_dir"].iterdir())
    for method in (transport.inspect_transition, transport.inspect_owned_restore, build().inspect_transition):
        with pytest.raises(module.IsolatedFolderPolicyHttpTransportError): method()
    assert len(peer.puts) == 2


@pytest.mark.parametrize("operation", ("assign", "restore"))
@pytest.mark.parametrize("fault", ("parent_policy", "parent_other_field", "parent_serial", "parent_id",
                                   "parent_mkey", "parent_missing", "parent_final_drift"))
def test_parent_complete_digest_or_identity_drift_refuses_before_claim_in_both_phases(setup, operation, fault):
    peer, build, args, _ = setup
    transport = build()
    current = transport.inspect_transition()
    if operation == "restore":
        dispatch(transport, current)
        current = transport.inspect_owned_restore()
    puts = len(peer.puts)
    claims = set(args["claim_dir"].iterdir())
    peer.fault = fault
    if fault == "parent_policy": peer.parent["secret-policy"] = "Synthetic Changed Parent Policy"
    if fault == "parent_other_field": peer.parent["ztna-tags-match-logic"] = "or"
    if fault == "parent_final_drift": peer.parent_drift_at = peer.parent_reads + 2
    with pytest.raises(module.IsolatedFolderPolicyHttpTransportError):
        dispatch(transport, current, operation == "restore")
    assert len(peer.puts) == puts
    assert set(args["claim_dir"].iterdir()) == claims
    assert not peer.active and peer.logins == peer.logouts
    assert not transport._claim_path(operation == "restore").exists()


@pytest.mark.parametrize("fault", ("folder_mkey", "policy_mkey", "serial", "final_drift", "role", "creator", "receipt", "membership"))
def test_invalid_fresh_identity_receipt_membership_or_final_drift_refuses_before_put(setup, fault):
    peer, build, args, _ = setup
    transport = build(); before = transport.inspect_transition()
    peer.fault = fault
    if fault == "role": peer.role["results"]["accprofile"] = "other"
    if fault == "creator": transport._creator = "c" * 64
    if fault == "receipt":
        with args["creation_workflow"]._connect() as connection:
            connection.execute("UPDATE v4_isolated_folder_creation_ownership SET receipt_mac = 'bad'")
    if fault == "membership": peer.detail["results"]["folder"] = 7
    with pytest.raises(module.IsolatedFolderPolicyHttpTransportError): dispatch(transport, before)
    assert peer.puts == [] and not peer.active
    assert not list(args["claim_dir"].iterdir())


@pytest.mark.parametrize("fault", ("ack", "duplicate_ack", "readback", "logout", "csrf"))
def test_uncertain_attempt_claim_is_durable_and_never_imports_restoration_or_replays(setup, fault):
    peer, build, args, _ = setup
    transport = build(); before = transport.inspect_transition()
    peer.fault = fault
    with pytest.raises(module.IsolatedFolderPolicyHttpTransportError): dispatch(transport, before)
    assert len(peer.puts) == (0 if fault == "csrf" else 1)
    count = len(peer.calls)
    for method in (transport.inspect_transition, transport.inspect_owned_restore, build().inspect_transition):
        with pytest.raises(module.IsolatedFolderPolicyHttpTransportError): method()
    assert len(peer.calls) == count and len(list(args["claim_dir"].iterdir())) == 1


def test_default_gate_expiry_and_changed_directory_refuse_without_write(setup):
    peer, build, args, _ = setup
    transport = build(False); before = transport.inspect_transition()
    with pytest.raises(module.IsolatedFolderPolicyHttpTransportError): dispatch(transport, before)
    enabled = build()
    with pytest.raises(module.IsolatedFolderPolicyHttpTransportError): dispatch(enabled, before, clock=lambda: 1600)
    args["claim_dir"].chmod(0o755)
    with pytest.raises(module.IsolatedFolderPolicyHttpTransportError): dispatch(enabled, before)
    assert peer.puts == []


def test_last_read_expiry_refuses_before_claim_and_mutable_dispatch_body_is_cleared(setup, monkeypatch):
    peer, build, args, _ = setup
    transport = build(); before = transport.inspect_transition()
    original = transport._read
    now = [1000]
    reads = [0]
    bodies = []
    zeroize = module._zeroize_mutable
    def read(reader, ssh):
        result = original(reader, ssh)
        reads[0] += 1
        if reads[0] == 2: now[0] = 1600
        return result
    def clear(body):
        if b'"inherit-policy"' in body: bodies.append(body)
        zeroize(body)
    monkeypatch.setattr(transport, "_read", read)
    monkeypatch.setattr(module, "_zeroize_mutable", clear)
    with pytest.raises(module.IsolatedFolderPolicyHttpTransportError): dispatch(transport, before, clock=lambda: now[0])
    assert bodies and all(not any(body) for body in bodies)
    assert peer.puts == [] and not list(args["claim_dir"].iterdir())


def test_full_workflow_uses_independent_cpe_for_conversion_and_restoration_without_private_dto(setup):
    peer, build, _, _ = setup
    workflow = IsolatedFolderPolicyTransitionLiveWorkflow(build(), execution_enabled=True, clock=lambda: 1000)
    outputs = []
    for preview_method in (workflow.preview_transition, workflow.preview_restore):
        preview = preview_method(requester_digest=CREATOR)
        authorization = workflow.confirm(preview["preview_ref"], requester_digest=CREATOR)
        result = workflow.execute(authorization["authorization_ref"], requester_digest=CREATOR)
        assert result["outcome"] == "succeeded"
        outputs.extend((preview, authorization, result))
    assert len(peer.puts) == 2 and peer.logins == peer.logouts and not peer.active
    for private in (FOLDER_NAME, OWNER, SERIAL, POLICY, "native_body_json", "baseline_folder_json"):
        assert private not in json.dumps(outputs)


def test_complete_policy_profile_binds_full_configuration_through_assignment_and_restore(setup):
    peer, build, _, _ = setup
    transport = build(bind_complete_policy_definition=True)
    original = transport.inspect_transition()
    assert original.complete_policy_configuration_digest is not None
    assert original.policy_digest != build().inspect_transition().policy_digest
    workflow = IsolatedFolderPolicyTransitionLiveWorkflow(transport, execution_enabled=True, clock=lambda: 1000)
    for preview_method in (workflow.preview_transition, workflow.preview_restore):
        preview = preview_method(requester_digest=CREATOR)
        authorization = workflow.confirm(preview["preview_ref"], requester_digest=CREATOR)
        result = workflow.execute(authorization["authorization_ref"], requester_digest=CREATOR)
        assert result["outcome"] == "succeeded"
        assert original.complete_policy_configuration_digest not in json.dumps((preview, authorization, result))
    assert len(peer.puts) == 2 and peer.complete_policy_reads > 2
    assert peer.logins == peer.logouts and not peer.active


@pytest.mark.parametrize("change", [
    {"need-approval": "enable"}, {"password-changer": "enable"},
    {"checkout-duration": 999}, {"approval-profile": "Synthetic Changed Approval"},
])
def test_noncontrol_policy_drift_refuses_before_assignment_claim_or_put(setup, change):
    peer, build, args, _ = setup
    transport = build(bind_complete_policy_definition=True)
    before = transport.inspect_transition()
    peer.complete_policy_changes.update(change)
    current = transport.inspect_transition()
    assert current.policy_definition_json == before.policy_definition_json
    assert current.policy_digest != before.policy_digest
    with pytest.raises(module.IsolatedFolderPolicyHttpTransportError):
        dispatch(transport, before)
    assert peer.puts == [] and not list(args["claim_dir"].iterdir())
    assert peer.logins == peer.logouts and not peer.active


def test_noncontrol_policy_drift_in_final_prewrite_read_refuses_without_claim(setup, monkeypatch):
    peer, build, args, _ = setup
    transport = build(bind_complete_policy_definition=True)
    before = transport.inspect_transition()
    original = transport._read_complete_policy
    def read(owner):
        observed = original(owner)
        if peer.complete_policy_reads == 2:
            peer.complete_policy_changes["need-approval"] = "enable"
        return observed
    monkeypatch.setattr(transport, "_read_complete_policy", read)
    with pytest.raises(module.IsolatedFolderPolicyHttpTransportError):
        dispatch(transport, before)
    assert peer.puts == [] and not list(args["claim_dir"].iterdir())


def test_complete_policy_postcondition_failure_preserves_original_restore_basis(setup):
    peer, build, args, _ = setup
    transport = build(bind_complete_policy_definition=True)
    before = transport.inspect_transition()
    peer.postwrite_policy_changes["need-approval"] = "enable"
    with pytest.raises(module.IsolatedFolderPolicyHttpTransportError):
        dispatch(transport, before)
    assert len(peer.puts) == 1 and len(list(args["claim_dir"].iterdir())) == 1
    assert transport._converted is not None and transport._converted[0] == before
    assert peer.logins == peer.logouts and not peer.active
    with pytest.raises(module.IsolatedFolderPolicyHttpTransportError):
        transport.inspect_owned_restore()
    with pytest.raises(module.IsolatedFolderPolicyHttpTransportError):
        dispatch(transport, before)
    assert len(peer.puts) == 1 and not transport._claim_path(True).exists()


def test_noncontrol_policy_drift_refuses_before_restore_claim_or_put(setup):
    peer, build, _, _ = setup
    transport = build(bind_complete_policy_definition=True)
    before = transport.inspect_transition()
    dispatch(transport, before)
    restore = transport.inspect_owned_restore()
    peer.complete_policy_changes["need-approval"] = "enable"
    with pytest.raises(module.IsolatedFolderPolicyHttpTransportError):
        transport.restore_and_readback(restore.state_digest, expires_at=1100, clock=lambda: 1000)
    assert len(peer.puts) == 1 and not transport._claim_path(True).exists()


def test_complete_policy_source_rejects_unclassified_field_without_decoding_or_fallback(setup, monkeypatch):
    peer, build, args, _ = setup
    peer.complete_policy_changes["password"] = "SYNTHETIC_OPAQUE_MATERIAL"
    transport = build(bind_complete_policy_definition=True)
    observed = []
    consume = module.consume_policy_assignment_definition
    def source(raw, **kwargs):
        observed.append(raw)
        return consume(raw, **kwargs)
    monkeypatch.setattr(module, "consume_policy_assignment_definition", source)
    with pytest.raises(module.IsolatedFolderPolicyHttpTransportError):
        transport.inspect_transition()
    assert observed and all(not any(raw) for raw in observed)
    assert peer.complete_policy_reads == 1 and peer.puts == []
    assert not list(args["claim_dir"].iterdir())
    assert peer.logins == peer.logouts and not peer.active
