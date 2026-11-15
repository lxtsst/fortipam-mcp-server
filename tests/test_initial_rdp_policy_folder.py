"""The explicit RDP birth profile cannot widen inherited Folder authority."""
from dataclasses import replace
import hashlib
import json

import httpx
import pytest

from fortipam_mcp import isolated_folder_mcp_action as entry
from fortipam_mcp.folder_http_transport import FolderHttpResponse
from fortipam_mcp.folder_live_workflow import ChildFolderWorkflowError
from fortipam_mcp.isolated_folder_creation_ownership import (
    RDP_POLICY_CONTRACT, validate_creation_ownership,
)
from fortipam_mcp.isolated_folder_m4_adapter import (
    InitialRdpPolicyBinding, IsolatedFolderBinding, RDP_POLICY_ADAPTER_REF,
    initial_rdp_policy_child_body,
)
from fortipam_mcp.policy_assignment_definition import consume_policy_assignment_definition
from test_isolated_folder_creation_ownership import setup, REQUESTER, SERIAL
from test_isolated_folder_http_transport import namespace_transport
from test_isolated_folder_mcp_action import namespace_startup
from test_policy_assignment_definition import response


def policy():
    return InitialRdpPolicyBinding("mcp-v4-secret-policy-synthetic", "c" * 64,
        hashlib.sha256(SERIAL.encode()).hexdigest())


@pytest.mark.parametrize("fault", [None, "preview", "confirmation", "final", "readback", "snapshot"])
def test_real_workflow_pins_policy_and_keeps_receipts_and_consumed_dispatches_separate(setup, monkeypatch, fault):
    build, transport, legacy, _ = setup
    selected = replace(legacy, initial_rdp_policy=policy())
    stage = ["preview"]
    monkeypatch.setattr(transport, "initial_rdp_policy_matches", lambda p: p == policy() and stage[0] != fault, raising=False)

    def create(**kwargs):
        assert kwargs.pop("policy") == policy()
        stage[0] = "final"
        kwargs["before_dispatch"]()
        transport.posts += 1
        transport.folder.update({"inherit-policy": "disable", "secret-policy": policy().name})
        stage[0] = "readback"
        return {"http_status": 200, "mkey": 23}

    monkeypatch.setattr(transport, "create_initial_rdp_policy_child", create, raising=False)
    monkeypatch.setattr(transport, "verify_initial_rdp_policy_child", lambda *a, **k: True, raising=False)
    transport.snapshot_error = fault == "snapshot"
    workflow = build(selected)
    if fault == "preview":
        with pytest.raises(Exception): workflow.preview(folder_name=legacy.name, parent_folder_id=17, requester_digest=REQUESTER)
        assert transport.posts == 0
        return
    preview = workflow.preview(folder_name=legacy.name, parent_folder_id=17, requester_digest=REQUESTER)
    assert preview["Current State"]["complete_policy_matches"] is True
    assert preview["Expected State"]["inherit_policy"] == "disable"
    stage[0] = "confirmation"
    if fault == "confirmation":
        with pytest.raises(ChildFolderWorkflowError): workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
        assert transport.posts == 0
        return
    confirmation = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    stage[0] = "execute"
    result = workflow.execute(confirmation["authorization_ref"], requester_digest=REQUESTER)
    assert (result["outcome"] == "succeeded") is (fault is None)
    assert transport.posts == (0 if fault == "final" else 1)
    if fault is None:
        owned = build(selected).read_creation_ownership(preview["preview_ref"], REQUESTER)
        assert owned.contract == RDP_POLICY_CONTRACT
        assert owned.snapshot.folder["secret-policy"] == policy().name
        assert workflow._plan(workflow._get_by_preview(preview["preview_ref"])).adapter_ref == RDP_POLICY_ADAPTER_REF
        with pytest.raises(ValueError): validate_creation_ownership(owned, binding=legacy, expected_serial=SERIAL)
        with pytest.raises(ChildFolderWorkflowError): build(legacy).read_creation_ownership(preview["preview_ref"], REQUESTER)
    else:
        with pytest.raises(ChildFolderWorkflowError): build(selected).read_creation_ownership(preview["preview_ref"], REQUESTER)
    if fault is None:
        workflow.execute(confirmation["authorization_ref"], requester_digest=REQUESTER)
    else:
        with pytest.raises(ChildFolderWorkflowError):
            workflow.execute(confirmation["authorization_ref"], requester_digest=REQUESTER)
    assert transport.posts == (0 if fault == "final" else 1)


def test_binding_requires_new_version_serial_and_exact_mode_without_changing_legacy_digest(setup):
    build, _, old, _ = setup
    new = replace(old, initial_rdp_policy=policy())
    assert (old.action_version, new.action_version) == ("3.3.0", "3.4.0")
    assert old.parameters_digest != new.parameters_digest
    with pytest.raises(ValueError): replace(new, empty_inactive_policy=True)
    with pytest.raises(ChildFolderWorkflowError): build(new, serial=None)
    with pytest.raises(Exception): build(new, serial="OTHER_SERIAL").preview(
        folder_name=old.name, parent_folder_id=17, requester_digest=REQUESTER)
    body = initial_rdp_policy_child_body(old.name, 17, old.owner_name, policy())
    assert body["inherit-policy"] == "disable" and body["secret-policy"] == policy().name
    assert body["user-permission"][0]["allowed-launcher-type"] == "all"
    assert body["group-permission"] == [] and body["inherit-permission"] == "disable"


@pytest.mark.parametrize("fault", [None, "opt-in", "serial", "owner", "namespace", "conflict"])
def test_normal_environment_builder_requires_exact_profile_prerequisites(namespace_startup, monkeypatch, fault):
    env, calls = namespace_startup
    binding = IsolatedFolderBinding("mcp-v4-Collector", 17, "synthetic-owner", "a" * 64, initial_rdp_policy=policy())
    monkeypatch.setattr(entry, "_private_binding", lambda path: (binding, "Public/Parent"))
    env.update({entry.PREFIX + "INITIAL_RDP_POLICY_ENABLED": "true", entry.PREFIX + "OWNERSHIP_EXPECTED_SERIAL": SERIAL})
    edits = {"opt-in": ("INITIAL_RDP_POLICY_ENABLED", "false"), "serial": ("OWNERSHIP_EXPECTED_SERIAL", "OTHER"),
        "owner": ("OWNER_READBACK_ENABLED", "false"), "namespace": ("NAMESPACE_ENABLED", "false"),
        "conflict": ("EMPTY_INACTIVE_POLICY_ENABLED", "true")}
    if fault:
        suffix, value = edits[fault]
        env[entry.PREFIX + suffix] = value
        with pytest.raises(ValueError): entry.build_isolated_folder_candidate(env)
        assert calls == {}
    else:
        action = entry.build_isolated_folder_candidate(env)
        assert action._binding is binding and action._action._execution_enabled is False


def test_private_binding_schema_cannot_silently_add_policy_to_inherited_profile(tmp_path):
    path = tmp_path / "binding.json"
    value = dict(contract=entry.RDP_POLICY_CONTRACT, name="Collector", parent_folder_id=17,
        owner_name="synthetic-owner", parent_digest="a" * 64, parent_path="Public/Parent",
        initial_rdp_policy=dict(name=policy().name, configuration_digest=policy().configuration_digest,
            serial_digest=policy().serial_digest))
    path.write_text(json.dumps(value)); path.chmod(0o600)
    assert entry._private_binding(path)[0].initial_rdp_policy == policy()
    value["contract"] = entry.CONTRACT
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError): entry._private_binding(path)


@pytest.mark.parametrize("fault", [None, "recording", "clipboard", "other-control", "serial", "logout"])
def test_live_policy_source_requires_full_configuration_controls_serial_and_logout(monkeypatch, fault):
    transport = namespace_transport(monkeypatch, None)
    def change(value):
        value["serial"] = SERIAL
        value["mkey"] = policy().name
        value["results"][0].update({"name": policy().name, "q_origin_key": policy().name,
            "recording": "enable", "block-clipboard": "enable"})
    raw = response(change)
    expected = consume_policy_assignment_definition(bytearray(raw), policy_name=policy().name, serial_digest=policy().serial_digest)
    selected = replace(policy(), configuration_digest=expected.configuration_digest)
    value = json.loads(raw)
    if fault in {"recording", "clipboard", "other-control"}:
        key = {"recording": "recording", "clipboard": "block-clipboard", "other-control": "need-approval"}[fault]
        value["results"][0][key] = "disable" if fault != "other-control" else "enable"
    if fault == "serial": value["serial"] = "OTHER"
    def handle(request):
        assert request.method == "GET" and request.url.path == "/api/v2/cmdb/secret/policy/" + policy().name
        assert str(request.url.query, "ascii") == "with_meta=true&vdom=root"
        return httpx.Response(200, json=value)
    session = transport._owner_session
    session._client = httpx.Client(base_url="https://fortipam.example.test", transport=httpx.MockTransport(handle))
    session._clock = lambda: 1
    session._expires_at = 2
    session.logout_verified = fault != "logout"
    monkeypatch.setattr(transport, "_creation_owner_role", lambda: {"serial": SERIAL})
    try:
        if fault in {"serial", "logout"}:
            with pytest.raises(ValueError): transport.initial_rdp_policy_matches(selected)
        else:
            assert transport.initial_rdp_policy_matches(selected) is (fault is None)
    finally:
        session._client.close()


@pytest.mark.parametrize("fault", [None, "namespace", "policy", "final", "ack-build", "ack-serial", "ack-native-status"])
def test_http_create_uses_fixed_explicit_body_and_never_posts_after_failed_final_guard(monkeypatch, fault):
    from fortipam_mcp.folder_namespace_ssh_reader import FolderNamespaceObservation
    transport = namespace_transport(monkeypatch, lambda *args: FolderNamespaceObservation("name_absent", 25, 2, "a" * 64, True))
    monkeypatch.setattr(transport, "initial_rdp_policy_matches", lambda p: fault != "policy")
    if fault == "namespace": monkeypatch.setattr(transport, "_observe_namespace", lambda *a: False)
    posts = []
    def request(method, path, raw):
        posts.append(json.loads(raw))
        assert (method, path) == ("POST", "/api/v2/cmdb/secret/folder")
        value = dict(version="v7.0.0", build=30 if fault == "ack-build" else 29,
            serial="OTHER" if fault == "ack-serial" else SERIAL, status="success", path="secret", name="folder",
            http_method="POST", http_status=500 if fault == "ack-native-status" else 200, vdom="root", mkey=23)
        return FolderHttpResponse(200, "application/json", value)
    monkeypatch.setattr(transport._folders, "_request", request, raising=False)
    def final():
        if fault == "final": raise ValueError("synthetic expired intent")
    args = dict(name="Collector", parent_folder_id=17, owner_name="test-owner", policy=policy(), before_dispatch=final)
    if fault:
        with pytest.raises(ValueError): transport.create_initial_rdp_policy_child(**args)
    else:
        assert transport.create_initial_rdp_policy_child(**args) == {"http_status": 200, "mkey": 23}
    assert len(posts) == (0 if fault in {"namespace", "policy", "final"} else 1)
    if posts: assert posts[0] == initial_rdp_policy_child_body("Collector", 17, "test-owner", policy())


def test_explicit_birth_binding_cannot_enter_the_legacy_single_secret_transition():
    from fortipam_mcp.isolated_folder_policy_transition_contract import (
        IsolatedFolderPolicyTransitionBinding, IsolatedFolderPolicyTransitionContractError,
    )
    from fortipam_mcp.single_secret_folder_membership_source import SingleSecretFolderMembershipBinding
    binding = IsolatedFolderBinding("Collector", 17, "synthetic-owner", "a" * 64, initial_rdp_policy=policy())
    member = SingleSecretFolderMembershipBinding(23, "Collector", 35, "Secret", SERIAL, "Witness", "SecretWitness")
    with pytest.raises(IsolatedFolderPolicyTransitionContractError):
        IsolatedFolderPolicyTransitionBinding(binding, member, policy().name)
