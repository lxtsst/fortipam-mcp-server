"""Real local creation custody with synthetic material and relation transports."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from fortipam_mcp import isolated_folder_policy_transition_http_transport as transport_module
from fortipam_mcp import policy_assignment_fixture_guard as module
from fortipam_mcp.isolated_folder_creation_ownership import IsolatedFolderCreationSnapshot
from fortipam_mcp.isolated_folder_live_workflow import IsolatedFolderLiveWorkflow
from fortipam_mcp.isolated_folder_m4_adapter import IsolatedFolderBinding
from fortipam_mcp.isolated_folder_policy_transition_contract import IsolatedFolderPolicyTransitionBinding
from fortipam_mcp.isolated_folder_policy_transition_live_workflow import IsolatedFolderPolicyTransitionLiveWorkflow
from fortipam_mcp.isolated_folder_policy_transition_mcp_action import (
    IsolatedFolderPolicyTransitionMcpAction, IsolatedFolderPolicyTransitionMcpActionError,
)
from fortipam_mcp.single_secret_folder_membership_source import (
    SingleSecretFolderMembershipBinding, SingleSecretFolderMembershipObservation,
)
from v4_planning import canonical_digest
from test_instruction_feature_http_reader import Client, Response
from test_isolated_folder_creation_ownership import folder
from test_isolated_folder_m4_adapter import Transport
from test_single_secret_folder_membership_candidate import Peer, OWNER, envelope
from test_web_secret_fixture_lifecycle import fixture as lifecycle_fixture

INHERITED, ASSIGNED = "Synthetic Inherited Policy", "Synthetic Assigned Policy"
SERIAL = "unit-appliance"
FOLDER = "mcp-v4-single-folder-synthetic"


def fixture(tmp_path, monkeypatch):
    original = lifecycle_fixture(tmp_path, monkeypatch)
    construct, bind, _, directory, store, _, _, clients, _, _ = original
    def material_client(policy):
        responses = [Response(bytearray(item.content)) for item in clients[0].responses]
        for index in (0, 3, 6):
            value = json.loads(responses[index].content)
            value["results"][0]["policy"] = policy
            responses[index].content = bytearray(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode())
        return Client(responses)
    clients[0] = material_client(INHERITED)
    lifecycle = construct()
    runner, principal = bind(lifecycle)
    assert runner.execute_bound()["outcome"] == "succeeded"
    clients[1:] = [material_client(name) for name in (INHERITED, INHERITED, INHERITED,
        ASSIGNED, ASSIGNED, ASSIGNED, INHERITED)]
    guard = module.PolicyAssignmentFixtureGuard(lifecycle,
        inherited_policy_name=INHERITED, assigned_policy_name=ASSIGNED)
    creation = runner._capture._record.read_acknowledged_creation()
    secret = json.loads(creation.creation.baseline_json)
    class SourcePeer(Peer):
        def __init__(self):
            super().__init__()
            self.row = {**folder(), "id": secret["folder"], "name": FOLDER,
                        "parent-folder": 7, "secret-policy": INHERITED}
            self.parent = {**folder(), "id": 7, "name": "Synthetic-Parent", "parent-folder": 0,
                           "secret-policy": INHERITED}
            self.puts = []
            self.relation_drift = False
            self.effective_drift = False
        def respond(self, request):
            path = request.url.path
            if path.startswith("/api/v2/utility/id/"):
                result = envelope("id", {"id": 7 if path.endswith("Synthetic-Parent") else secret["folder"]}, "utility")
            elif path == "/api/v2/cmdb/secret/folder/7":
                result = envelope("folder", deepcopy(self.parent))
            elif path == "/api/v2/cmdb/secret/folder/" + str(secret["folder"]):
                if request.method == "PUT":
                    assert request.headers["x-csrftoken"] == "synthetic-csrf"
                    body = json.loads(request.content); self.puts.append(body)
                    self.row.update({"inherit-policy": body["inherit-policy"], "secret-policy":
                        INHERITED if body["inherit-policy"] == "enable" else body["secret-policy"]})
                    result = envelope("folder", {})
                    del result["results"]
                    result.update(http_method="PUT", mkey=secret["folder"])
                else:
                    result = envelope("folder", deepcopy(self.row))
                    if "with_meta" in request.url.params:
                        del result["action"]
                    if self.relation_drift and "with_meta" in request.url.params:
                        result["results"]["user-permission"][0]["allowed-launcher-type"] = "changed"
            elif path == "/api/v2/cmdb/secret/database/" + str(secret["id"]):
                result = json.loads(clients[0].responses[0].content)
                result["results"][0]["policy"] = ASSIGNED if self.effective_drift else self.row["secret-policy"]
            elif path.startswith("/api/v2/cmdb/secret/policy/"):
                name = path.rsplit("/", 1)[1]
                result = json.loads((Path(__file__).parent / "fixtures/policy_assignment_definition.synthetic.json").read_bytes())
                result.update(mkey=name)
                result["results"][0].update(name=name, q_origin_key=name,
                    q_ref=int(self.row["secret-policy"] == ASSIGNED))
                if "format" in request.url.params:
                    result["results"] = {k: result["results"][0][k] for k in ("name", "recording", "block-clipboard", "rdp-event-filter")}
            else:
                response = super().respond(request)
                if path == "/XX/YY/ZZ/AUTH":
                    response.headers["set-cookie"] = "ccsrftoken=synthetic-csrf; Secure; Path=/"
                if "json" not in response.headers.get("content-type", "") or response.status_code != 200:
                    return response
                result = response.json()
            result["serial"] = SERIAL
            return httpx.Response(200, json=result)
    peer = SourcePeer()
    class FolderCreator(Transport):
        def __init__(self): super().__init__(None)
        def read_parent_digest(self, identifier): return canonical_digest(peer.parent)
        def read_creation_device_serial(self): return SERIAL
        def find_child_ids(self, name, parent): return (secret["folder"],) if self.posts else ()
        def create_isolated_child(self, **kwargs):
            super().create_isolated_child(**kwargs)
            return {"http_status": 200, "mkey": secret["folder"]}
        def read_created_folder_snapshot(self, identifier, **kwargs):
            return IsolatedFolderCreationSnapshot(SERIAL, deepcopy(peer.row))
    creator = FolderCreator()
    folder_binding = IsolatedFolderBinding(FOLDER, 7, OWNER, creator.read_parent_digest(7))
    key = tmp_path / "folder-key"; key.write_bytes(b"f" * 32); key.chmod(0o600)
    folders = IsolatedFolderLiveWorkflow(tmp_path / "folders.sqlite", key, creator,
        binding=folder_binding, ownership_expected_serial=SERIAL, clock=lambda: 1000)
    preview = folders.preview(folder_name=FOLDER, parent_folder_id=7, requester_digest=principal.requester.digest)
    grant = folders.confirm(preview["preview_ref"], requester_digest=principal.requester.digest)
    assert folders.execute(grant["authorization_ref"], requester_digest=principal.requester.digest)["outcome"] == "succeeded"
    binding = IsolatedFolderPolicyTransitionBinding(folder_binding, SingleSecretFolderMembershipBinding(
        secret["folder"], FOLDER, secret["id"], secret["name"], SERIAL,
        "Synthetic Folder Witness", "Synthetic Secret Witness"), ASSIGNED)
    ownership = folders.read_creation_ownership(preview["preview_ref"], principal.requester.digest)
    class Membership:
        def __init__(self, *args): pass
        def observe(self): return SingleSecretFolderMembershipObservation(True, True, True, True, "d" * 64)
    monkeypatch.setattr(transport_module, "SingleSecretFolderMembershipSource", Membership)
    monkeypatch.setattr(transport_module, "_SessionProvider", lambda *args: SimpleNamespace(qualify=lambda: None))
    hosts = tmp_path / "known_hosts"; hosts.write_text("synthetic pinned peer\n"); hosts.chmod(0o600)
    claims = tmp_path / "claims"; claims.mkdir(mode=0o700)
    transport = transport_module.IsolatedFolderPolicyHttpTransport(lifecycle._config, binding=binding,
        creation_workflow=folders, creation_preview_ref=preview["preview_ref"], creator_digest=principal.requester.digest,
        parent_path="Public/Synthetic-Parent", credentials=peer.credentials, ssh_host="synthetic.invalid", ssh_port=22,
        ssh_known_hosts_file=hosts, claim_dir=claims, client_factory=peer.client, execution_enabled=True,
        bind_complete_policy_definition=True, fixture_guard=guard)
    return SimpleNamespace(guard=guard, transport=transport, peer=peer, clients=clients, principal=principal,
        lifecycle=lifecycle, runner=runner, directory=directory, store=store, binding=binding, ownership=ownership,
        material_client=material_client)


def test_normal_original_custody_full_retention_relation_and_independent_restore(tmp_path, monkeypatch):
    c = fixture(tmp_path, monkeypatch)
    before = {name: (c.directory / name).read_bytes() for name in ("creation.record", "creation.ack")}
    c.guard.qualify_baseline(c.principal)
    workflow = IsolatedFolderPolicyTransitionLiveWorkflow(c.transport, execution_enabled=True, clock=lambda: 1000)
    for method in (workflow.preview_transition, workflow.preview_restore):
        preview = method(requester_digest=c.principal.requester.digest)
        authorization = workflow.confirm(preview["preview_ref"], requester_digest=c.principal.requester.digest)
        result = workflow.execute(authorization["authorization_ref"], requester_digest=c.principal.requester.digest)
        assert result["outcome"] == "succeeded"
        assert c.guard.preservation_digest not in json.dumps((preview, authorization, result))
    assert len(c.peer.puts) == 2 and c.peer.row["secret-policy"] == INHERITED
    assert all(client.is_closed and len(client.calls) == 7 for client in c.clients)
    assert all((c.directory / name).read_bytes() == value for name, value in before.items())
    assert c.peer.logins == c.peer.logouts and not c.peer.active
    c.clients.extend(c.material_client(INHERITED) for _ in range(2))
    assert c.lifecycle.recover_once(c.principal)["outcome"] == "succeeded"
    assert all((c.directory / name).read_bytes() == value for name, value in before.items())


@pytest.mark.parametrize("fault", ["relation", "effective", "material", "unknown-field"])
def test_drift_refuses_before_native_claim_or_put(tmp_path, monkeypatch, fault):
    c = fixture(tmp_path, monkeypatch)
    c.guard.qualify_baseline(c.principal)
    before = c.transport.inspect_transition()
    if fault == "relation": c.peer.relation_drift = True
    elif fault == "effective": c.peer.effective_drift = True
    else:
        client = c.clients[2]
        for index in ((1, 5) if fault == "material" else (0, 3, 6)):
            value = json.loads(client.responses[index].content)
            if fault == "material": value["results"] = "SYNTHETIC_CHANGED_PASSWORD"
            else: value["results"][0]["future-config"]["nested"].append("changed")
            client.responses[index].content = bytearray(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode())
    with pytest.raises(transport_module.IsolatedFolderPolicyHttpTransportError):
        c.transport.transition_and_readback(before.state_digest, expires_at=1100, clock=lambda: 1000)
    assert not c.peer.puts and not list(c.transport._claim_dir.iterdir())


def test_binding_and_principal_substitution_refuse_before_material_consumption(tmp_path, monkeypatch):
    c = fixture(tmp_path, monkeypatch)
    with pytest.raises(module.PolicyAssignmentFixtureGuardError):
        c.guard.qualify_baseline(object())
    with pytest.raises(module.PolicyAssignmentFixtureGuardError):
        c.guard.check_binding(replace(c.binding, policy_name=INHERITED), c.ownership)
    assert all(not client.calls for client in c.clients[1:])
    c.guard.qualify_baseline(c.principal)
    with pytest.raises(module.PolicyAssignmentFixtureGuardError):
        c.guard.qualify_baseline(c.principal)
    assert len(c.clients[1].calls) == 7 and not c.clients[2].calls


def test_mcp_pins_actual_client_before_sources_and_preview_does_not_read_material(tmp_path, monkeypatch):
    c = fixture(tmp_path, monkeypatch)
    c.guard.qualify_baseline(c.principal)
    workflow = IsolatedFolderPolicyTransitionLiveWorkflow(c.transport, execution_enabled=True, clock=lambda: 1000)
    action = IsolatedFolderPolicyTransitionMcpAction(workflow, execution_enabled=True)
    foreign = replace(c.principal, transport_namespace_digest="f" * 64)
    with pytest.raises(IsolatedFolderPolicyTransitionMcpActionError): action.preview_transition(foreign)
    assert not c.peer.logins and not c.clients[2].calls
    preview = action.preview_transition(c.principal)
    with pytest.raises(IsolatedFolderPolicyTransitionMcpActionError):
        action.confirm_transition(preview["preview_ref"], foreign)
    authorized = action.confirm_transition(preview["preview_ref"], c.principal)
    logins = c.peer.logins
    with pytest.raises(IsolatedFolderPolicyTransitionMcpActionError):
        action.execute_transition(authorized["authorization_ref"], foreign)
    assert c.peer.logins == logins and not c.clients[2].calls
    assert action.execute_transition(authorized["authorization_ref"], c.principal)["outcome"] == "succeeded"
    assert len(c.peer.puts) == 1


def test_post_material_failure_retains_consumed_native_ack_basis_without_replay(tmp_path, monkeypatch):
    c = fixture(tmp_path, monkeypatch)
    c.guard.qualify_baseline(c.principal)
    before = c.transport.inspect_transition()
    for index in (1, 5):
        value = json.loads(c.clients[4].responses[index].content)
        value["results"] = "SYNTHETIC_POSTWRITE_PASSWORD_DRIFT"
        c.clients[4].responses[index].content = bytearray(json.dumps(value, separators=(",", ":")).encode())
    with pytest.raises(transport_module.IsolatedFolderPolicyHttpTransportError):
        c.transport.transition_and_readback(before.state_digest, expires_at=1100, clock=lambda: 1000)
    assert len(c.peer.puts) == 1 and c.transport._converted is not None
    assert c.transport._claim_path(False).exists() and not c.transport._claim_path(True).exists()
    with pytest.raises(transport_module.IsolatedFolderPolicyHttpTransportError):
        c.transport.transition_and_readback(before.state_digest, expires_at=1100, clock=lambda: 1000)
    assert len(c.peer.puts) == 1 and c.peer.logins == c.peer.logouts
