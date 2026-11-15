from dataclasses import replace
from typing import cast

import pytest

from fortipam_mcp.secret_create_191_private_adapter import SecretCreate700WebTargetBinding
from fortipam_mcp.secret_create_m4_runtime import ProtectedSecretCreateM4Runtime
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataProjectionInspection
from fortipam_mcp.target_contract import WebTargetCreateInput
from fortipam_mcp.target_bound_web_projection_reader import (
    ADAPTER_REF, TargetBoundWebProjectionReader, target_bound_web_binding_digest,
)
from test_secret_create_m4_runtime import _secret_plan, _binding, _Resolver, _Verifier
from test_v4_execution_kernel import _authorization, NOW
from test_v4_secret_create_runtime import _Provider, _Adapter, _runtime
from v4_planning import InMemoryM4ExecutionStateStore, M4AdapterFailure, M4Outcome, canonical_digest
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome, SecretCreatePrivateAdapter


ABSENT = SecretMetadataProjectionInspection(False, True, True, False, False, False, False, False)
PRESENT = SecretMetadataProjectionInspection(
    True, True, True, True, True, True, True, True,
    recording_matches=True, http_service_enabled=True, proxy_mode_enabled=True,
)


class Transport:
    def __init__(self, before=ABSENT, after=PRESENT):
        self.before, self.after = before, after
        self.calls = []

    def inspect_target_bound_web_projection(self, folder, secret, *, target):
        self.calls.append((folder, secret, target))
        return self.before if len(self.calls) == 1 else self.after


def prepared(transport):
    binding = SecretCreate700WebTargetBinding(
        "fortipam-700-build29-target-bound-web-create-candidate-v1", "7.0.0",
        "1" * 64, "Lab/example-folder", "example-secret", "Web Account",
        WebTargetCreateInput("mcp-v4-target-web-20261003-r1", "https://app.example.test"), True,
    )
    ref = "target-bound-web-secret-ref01"
    reader = TargetBoundWebProjectionReader(binding, ref, transport)
    base = _secret_plan()
    changes = dict(
        adapter_ref=ADAPTER_REF, target_ref=ref,
        parameters_digest=reader.inspect_onboarding_binding_digest(),
        expected_current_digest=reader.state_digest(exists=False),
        expected_state_digest=reader.state_digest(exists=True),
    )
    plan = replace(base, **changes, plan_digest=canonical_digest({**base.canonical_content(), **changes}))
    binding = replace(binding, plan_digest=plan.plan_digest)
    return plan, TargetBoundWebProjectionReader(binding, ref, transport)


@pytest.mark.parametrize("before, after, succeeds", [
    (ABSENT, PRESENT, True),
    (replace(ABSENT, folder_exists=False), PRESENT, False),
    (PRESENT, PRESENT, False),
    (ABSENT, replace(PRESENT, proxy_mode_enabled=False), False),
    (ABSENT, replace(PRESENT, http_service_enabled=False), False),
    (ABSENT, replace(PRESENT, recording_matches=False), False),
    (ABSENT, replace(PRESENT, target_matches=False), False),
    (ABSENT, ABSENT, False),
])
def test_independent_m4_readback_is_required_after_positive_ack(before, after, succeeds):
    transport = Transport(before, after)
    plan, reader = prepared(transport)
    authorization = _authorization(plan)
    provider = _Provider()
    adapter = _Adapter(SecretCreateAdapterOutcome.VERIFIED_CREATED)
    runtime = ProtectedSecretCreateM4Runtime(
        _Resolver(_binding(plan, authorization)), _Verifier(), InMemoryM4ExecutionStateStore(),
        _runtime(provider, cast(SecretCreatePrivateAdapter, adapter)), reader,
        authenticated_requester_digest=plan.requester_digest, clock=lambda: NOW,
    )
    result = runtime.execute_bound(authorization.authorization_ref)
    assert (result.outcome is M4Outcome.SUCCEEDED) is succeeds
    assert transport.calls == [
        (reader._binding.folder_path, reader._binding.secret_name, reader._binding.target),
    ] * (2 if before is ABSENT else 1)
    if before is not ABSENT:
        assert provider.events == [] and adapter.calls == 0
    else:
        assert provider.events == ["validate", "acquire", "release"]
        assert adapter.calls == 1
    runtime.execute_bound(authorization.authorization_ref)
    assert adapter.calls == (1 if before is ABSENT else 0)


@pytest.mark.parametrize("field, value", [
    ("adapter_ref", "ordinary-secret-create-adapter"),
    ("target_ref", "different-object-ref01"),
    ("parameters_digest", "a" * 64),
    ("expected_current_digest", "b" * 64),
    ("expected_state_digest", "c" * 64),
    ("action_id", "different-action"),
    ("action_version", "2.0.0"),
])
def test_plan_substitution_rejects_before_device_reads(field, value):
    transport = Transport()
    plan, reader = prepared(transport)
    changed = replace(plan, **{field: value}, plan_digest=canonical_digest({
        **plan.canonical_content(), field: value,
    }))
    reader = TargetBoundWebProjectionReader(
        replace(reader._binding, plan_digest=changed.plan_digest), reader._object_ref, transport,
    )
    for method in (reader.read_current, reader.read_postcondition):
        with pytest.raises(M4AdapterFailure, match="unavailable"):
            method(changed)
    assert transport.calls == []


@pytest.mark.parametrize("field", [
    "folder_matches", "template_matches", "target_matches", "inherit_permission_matches",
    "recording_matches", "http_service_enabled", "proxy_mode_enabled", "field_values_attached",
])
def test_absence_rejects_contradictory_relations(field):
    plan, reader = prepared(Transport(replace(ABSENT, **{field: True})))
    with pytest.raises(M4AdapterFailure):
        reader.read_current(plan)


def test_reader_rejects_non_boolean_results_and_sanitizes_transport_failure():
    for invalid in (object(), replace(ABSENT, secret_exists=0)):
        plan, reader = prepared(Transport(invalid))
        with pytest.raises(M4AdapterFailure, match="unavailable"):
            reader.read_current(plan)

    class BrokenTransport:
        def inspect_target_bound_web_projection(self, *args, **kwargs):
            raise RuntimeError("private upstream selector")

    plan, reader = prepared(BrokenTransport())
    with pytest.raises(M4AdapterFailure) as caught:
        reader.read_current(plan)
    assert "private upstream selector" not in str(caught.value)
    assert caught.value.__suppress_context__


def test_binding_digest_covers_target_and_excludes_circular_plan_digest():
    _, reader = prepared(Transport())
    digest = reader.inspect_onboarding_binding_digest()
    assert target_bound_web_binding_digest(
        replace(reader._binding, plan_digest="9" * 64), reader._object_ref,
    ) == digest
    assert target_bound_web_binding_digest(
        replace(reader._binding, target=replace(reader._binding.target, web_url="https://different.example.test")),
        reader._object_ref,
    ) != digest


def planning_source(transport):
    from fortipam_mcp.target_bound_web_projection_reader import (
        TargetBoundWebPlanningBinding, TargetBoundWebPlanningSource,
    )
    from test_v4_planning import _target_bound_web_draft, _requester
    from v4_planning import ObjectClass

    draft = _target_bound_web_draft()
    draft = replace(draft, material_reference_metadata=replace(
        draft.material_reference_metadata, provider_class="central_lab_inventory_reference",
    ))
    _, reader = prepared(transport)
    objects = {item.object_class: item for item in draft.desired_objects}
    binding = TargetBoundWebPlanningBinding(
        create_binding=reader._binding, requester_digest=_requester().digest,
        environment_ref=draft.environment_ref, scope_ref=draft.scope_ref,
        folder_object_ref=objects[ObjectClass.FOLDER_BINDING].object_ref,
        folder_ref=dict(objects[ObjectClass.FOLDER_BINDING].desired_fields)["folder_ref"],
        target_object_ref=objects[ObjectClass.WEB_TARGET_BINDING].object_ref,
        target_profile_ref=dict(objects[ObjectClass.WEB_TARGET_BINDING].desired_fields)["profile_ref"],
        template_object_ref=objects[ObjectClass.TEMPLATE_BINDING].object_ref,
        template_ref=dict(objects[ObjectClass.TEMPLATE_BINDING].desired_fields)["template_ref"],
        secret_object_ref=reader._object_ref,
    )
    return draft, TargetBoundWebPlanningSource(binding, transport)


@pytest.mark.parametrize("inspection", [ABSENT, PRESENT])
def test_planning_source_feeds_exact_independent_m4_state_contract(inspection):
    from fortipam_mcp.secret_onboarding_projection_source import secret_onboarding_projection_contract
    from test_v4_planning import _requester, _promoted_registry, Authorizer, Issuer
    from v4_planning import M2PlanningEngine, ObjectClass, ChangeKind, canonical_json

    transport = Transport(inspection)
    draft, source = planning_source(transport)
    requester = _requester()
    authorizer = Authorizer((draft,), projection_source_ref="fortipam-191-secret-onboarding-projection")
    authorizer._grants.add(("fortipam-700-target-bound-web-projection", "projection_source"))
    engine = M2PlanningEngine(
        _promoted_registry(), Issuer(), authorizer,
        projection_contract_resolver=lambda scheme, cls: secret_onboarding_projection_contract(cls),
    )
    projections = source.project(draft, requester, now_epoch=NOW)
    summary = engine.compile_summary(draft, requester, projections, now_epoch=NOW)
    change = next(item for item in summary.object_changes
                  if item.object_class is ObjectClass.TARGET_BOUND_WEB_SECRET_METADATA)
    assert change.change_kind is (ChangeKind.NO_OP if inspection.secret_exists else ChangeKind.CREATE)
    _, reader = prepared(Transport())
    assert change.current_projection_digest == reader.state_digest(exists=inspection.secret_exists)
    assert change.expected_projection_digest == reader.state_digest(exists=True)
    assert source.inspect_target_bound_web_binding_digest(draft, requester) == reader.inspect_onboarding_binding_digest()
    assert len(transport.calls) == 1
    serialized = canonical_json(summary.canonical_content())
    for value in (source._binding.create_binding.folder_path, source._binding.create_binding.secret_name,
                  source._binding.create_binding.target.target_name, source._binding.create_binding.target.web_url):
        assert value not in serialized


@pytest.mark.parametrize("mode", [
    "requester", "scope", "environment", "wrong_provider", "wrong_purpose",
    "unavailable_material", "missing_material", "target_ref", "target_profile",
    "secret_ref", "wrong_blueprint", "targetless_class", "extra_object",
])
def test_planning_source_rejects_substitution_before_reads(mode):
    from test_v4_planning import _requester, _web_account_draft

    transport = Transport()
    draft, source = planning_source(transport)
    requester = _requester()
    if mode == "requester":
        source._binding = replace(source._binding, requester_digest="0" * 64)
    elif mode in {"scope", "environment"}:
        draft = replace(draft, **{mode + "_ref": "different-reference01"})
    elif mode in {"wrong_provider", "wrong_purpose", "unavailable_material"}:
        field, value = {
            "wrong_provider": ("provider_class", "external_vault_lease"),
            "wrong_purpose": ("purpose", "credential_rotation"),
            "unavailable_material": ("lifecycle", "unavailable"),
        }[mode]
        draft = replace(draft, material_reference_metadata=replace(
            draft.material_reference_metadata, **{field: value},
        ))
    elif mode == "missing_material":
        draft = replace(draft, material_reference_metadata=None)
    elif mode == "wrong_blueprint":
        draft = replace(draft, blueprint_ref="FPA-BP-005")
    elif mode == "extra_object":
        draft = replace(draft, desired_objects=(*draft.desired_objects, _web_account_draft().desired_objects[-1]))
    else:
        objects = list(draft.desired_objects)
        if mode == "target_ref":
            objects[2] = replace(objects[2], object_ref="different-target-ref01")
        elif mode == "target_profile":
            objects[2] = replace(objects[2], desired_fields=(
                ("profile_ref", "different-profile-ref01"), ("target_relation_matches", True),
            ))
        elif mode == "secret_ref":
            objects[-1] = replace(objects[-1], object_ref="different-secret-ref01")
        elif mode == "targetless_class":
            objects[-1] = _web_account_draft().desired_objects[-1]
        draft = replace(draft, desired_objects=tuple(objects))
    with pytest.raises(M4AdapterFailure):
        source.project(draft, requester, now_epoch=NOW)
    assert transport.calls == []


@pytest.mark.parametrize("inspection", [
    replace(ABSENT, folder_exists=False), replace(ABSENT, template_exists=False),
    replace(ABSENT, target_matches=True), replace(PRESENT, recording_matches=False),
    replace(PRESENT, http_service_enabled=False), replace(PRESENT, proxy_mode_enabled=False),
    replace(PRESENT, target_matches=False), replace(PRESENT, inherit_permission_matches=False),
    replace(PRESENT, secret_exists=1),
])
def test_planning_source_never_promotes_incomplete_relations(inspection):
    from test_v4_planning import _requester

    draft, source = planning_source(Transport(inspection))
    with pytest.raises(M4AdapterFailure):
        source.project(draft, _requester(), now_epoch=NOW)


def binding_payload():
    from dataclasses import asdict
    from fortipam_mcp.target_bound_web_projection_reader import PLANNING_BINDING_CONTRACT

    _, source = planning_source(Transport())
    payload = asdict(source._binding)
    create = payload.pop("create_binding")
    return {
        "contract": PLANNING_BINDING_CONTRACT, **payload,
        "folder_path": create["folder_path"], "secret_name": create["secret_name"],
        "target_name": create["target"]["target_name"], "web_url": create["target"]["web_url"],
    }


def test_owned_file_loads_exact_profile_without_exposing_selectors(tmp_path):
    import json
    from fortipam_mcp.target_bound_web_projection_reader import load_target_bound_web_planning_binding

    payload = binding_payload()
    path = tmp_path / "binding.json"
    path.write_text(json.dumps(payload))
    path.chmod(0o600)
    binding = load_target_bound_web_planning_binding(path)
    _, source = planning_source(Transport())
    expected = replace(source._binding, create_binding=replace(
        source._binding.create_binding, plan_digest="0" * 64,
    ))
    assert binding == expected
    for selector in (payload["folder_path"], payload["secret_name"], payload["web_url"], payload["target_name"]):
        assert selector not in repr(binding)
        assert selector not in repr(binding.create_binding)
    assert path.read_text() == json.dumps(payload)


@pytest.mark.parametrize("mode", [
    "world_readable", "executable", "readonly_mode", "symlink", "directory", "fifo",
    "relative", "missing", "empty", "oversized", "duplicate_key", "array",
    "wrong_contract", "missing_field", "extra_material", "caller_plan_digest",
    "wrong_type", "wrong_target", "embedded_credentials", "duplicate_reference",
    "wrong_requester_digest", "wrong_owner",
])
def test_binding_loader_rejects_unsafe_or_ambiguous_files(tmp_path, monkeypatch, mode):
    import json
    import os
    from pathlib import Path
    from fortipam_mcp.target_bound_web_projection_reader import load_target_bound_web_planning_binding

    payload = binding_payload()
    edits = {
        "wrong_contract": ("contract", "different-contract"),
        "extra_material": ("password", "synthetic-material"),
        "caller_plan_digest": ("plan_digest", "1" * 64),
        "wrong_type": ("target_name", 1),
        "wrong_target": ("target_name", "shared-target"),
        "embedded_credentials": ("web_url", "https://user:synthetic@example.test"),
        "duplicate_reference": ("target_object_ref", payload["secret_object_ref"]),
        "wrong_requester_digest": ("requester_digest", "invalid"),
    }
    if mode in edits:
        key, value = edits[mode]
        payload[key] = value
    if mode == "missing_field":
        payload.pop("web_url")
    content = json.dumps(payload)
    if mode == "empty":
        content = ""
    elif mode == "oversized":
        content = " " * 16385
    elif mode == "duplicate_key":
        content = '{"contract":"ignored",' + content[1:]
    elif mode == "array":
        content = "[]"
    path = tmp_path / "binding.json"
    path.write_text(content)
    path.chmod(0o600)
    if mode in {"world_readable", "executable", "readonly_mode"}:
        path.chmod({"world_readable": 0o644, "executable": 0o700, "readonly_mode": 0o400}[mode])
    elif mode == "symlink":
        link = tmp_path / "link.json"
        link.symlink_to(path)
        path = link
    elif mode == "directory":
        path = tmp_path
    elif mode == "fifo":
        path = tmp_path / "fifo"
        os.mkfifo(path, 0o600)
    elif mode == "relative":
        path = Path("binding.json")
    elif mode == "missing":
        path = tmp_path / "missing.json"
    elif mode == "wrong_owner":
        uid = os.getuid()
        monkeypatch.setattr("fortipam_mcp.target_bound_web_projection_reader.os.getuid", lambda: uid + 1)
    with pytest.raises(M4AdapterFailure) as caught:
        load_target_bound_web_planning_binding(path)
    assert str(caught.value) == "The Target-bound Web Secret projection is unavailable."
    assert caught.value.__suppress_context__
