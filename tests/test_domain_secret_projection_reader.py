from dataclasses import asdict, replace
import json

import pytest

from fortipam_mcp.secret_create_191_private_adapter import SecretCreate700DomainBinding
from fortipam_mcp.secret_metadata_http_transport import DomainSecretMetadataInspection
from fortipam_mcp.domain_secret_projection_reader import (
    ADAPTER_REF, DomainSecretProjectionReader, domain_secret_binding_digest,
)
from test_secret_create_m4_runtime import _secret_plan
from v4_planning import M4AdapterFailure, canonical_digest

ABSENT = DomainSecretMetadataInspection(False, False, False)
PRESENT = DomainSecretMetadataInspection(True, True, True)
REFS = ("domain-folder-object-ref01", "domain-target-object-ref01", "domain-template-object-ref01", "domain-secret-object-ref01")


class Transport:
    def __init__(self, result=ABSENT):
        self.result = result
        self.calls = []

    def inspect_domain_account_projection(self, binding):
        self.calls.append(binding)
        return self.result


def prepared(transport):
    binding = SecretCreate700DomainBinding(
        'fortipam-700-build29-domain-account-create-candidate-v1', '7.0.0',
        '1' * 64, 'Lab/example-folder', 'example-secret', 'Windows Domain Account',
        'example-domain-target', '192.0.2.40', 'example.test', 'example-owner',
    )
    ref = 'domain-secret-object-ref01'
    reader = DomainSecretProjectionReader(binding, ref, transport, dependency_refs=REFS)
    base = _secret_plan()
    changes = dict(adapter_ref=ADAPTER_REF, target_ref=ref,
                   parameters_digest=reader.inspect_onboarding_binding_digest(),
                   expected_current_digest=reader.state_digest(exists=False),
                   expected_state_digest=reader.state_digest(exists=True))
    plan = replace(base, **changes, plan_digest=canonical_digest({**base.canonical_content(), **changes}))
    return plan, DomainSecretProjectionReader(replace(binding, plan_digest=plan.plan_digest), ref, transport, dependency_refs=REFS)


@pytest.mark.parametrize('result, method, valid', [
    (ABSENT, 'read_current', True), (PRESENT, 'read_postcondition', True),
    (PRESENT, 'read_current', False), (ABSENT, 'read_postcondition', False),
    (replace(ABSENT, metadata_verified=True), 'read_current', False),
    (replace(ABSENT, field_was_redacted=True), 'read_current', False),
    (replace(PRESENT, metadata_verified=False), 'read_postcondition', False),
    (replace(PRESENT, field_was_redacted=False), 'read_postcondition', True),
    (replace(ABSENT, secret_exists=0), 'read_current', False),
    (object(), 'read_current', False),
])
def test_exact_categorical_readback(result, method, valid):
    transport = Transport(result)
    plan, reader = prepared(transport)
    if valid:
        assert getattr(reader, method)(plan) == reader.state_digest(exists=method == 'read_postcondition')
    else:
        with pytest.raises(M4AdapterFailure):
            getattr(reader, method)(plan)
    assert transport.calls == [reader._binding]


@pytest.mark.parametrize('field, value', [
    ('adapter_ref', 'fortipam-700-winrm-collector-create-adapter'),
    ('target_ref', 'different-object-ref01'), ('parameters_digest', 'a' * 64),
    ('expected_current_digest', 'b' * 64), ('expected_state_digest', 'c' * 64),
    ('action_id', 'different-action'), ('action_version', '2.0.0'),
])
def test_substitution_denied_before_transport(field, value):
    transport = Transport()
    plan, reader = prepared(transport)
    changed = replace(plan, **{field: value}, plan_digest=canonical_digest({**plan.canonical_content(), field: value}))
    reader = DomainSecretProjectionReader(replace(reader._binding, plan_digest=changed.plan_digest), reader._object_ref, transport, dependency_refs=REFS)
    for method in (reader.read_current, reader.read_postcondition):
        with pytest.raises(M4AdapterFailure):
            method(changed)
    assert not transport.calls


@pytest.mark.parametrize('field, value', [
    ('folder_path', 'Lab/other-folder'), ('secret_name', 'other-secret'),
    ('target_name', 'other-domain-target'), ('target_ipv4_address', '192.0.2.41'),
    ('domain_dns_root', 'other.test'), ('target_owner_name', 'other-owner'),
    ('target_classification_tag', 'Production'),
])
def test_private_dependency_digest_is_exact(field, value):
    _, reader = prepared(Transport())
    digest = reader.inspect_onboarding_binding_digest()
    assert domain_secret_binding_digest(replace(reader._binding, **{field: value}), reader._object_ref, dependency_refs=REFS) != digest
    assert domain_secret_binding_digest(replace(reader._binding, plan_digest='9' * 64), reader._object_ref, dependency_refs=REFS) == digest


def test_failure_is_value_free():
    class Broken:
        def inspect_domain_account_projection(self, binding):
            raise ValueError('private upstream selector')
    plan, reader = prepared(Broken())
    with pytest.raises(M4AdapterFailure) as caught:
        reader.read_current(plan)
    assert 'private upstream selector' not in str(caught.value)
    assert caught.value.__suppress_context__


def planning_source(transport):
    from fortipam_mcp.domain_secret_projection_reader import DomainSecretPlanningBinding, DomainSecretPlanningSource
    from test_v4_planning import _target_bound_web_draft, _requester
    from v4_planning.models import DesiredObject
    _, reader = prepared(transport)
    draft = _target_bound_web_draft()
    binding = DomainSecretPlanningBinding(
        reader._binding, _requester().digest, draft.environment_ref, draft.scope_ref,
        'domain-folder-object-ref01', 'domain-folder-ref01',
        'domain-target-object-ref01', 'domain-profile-ref01',
        'domain-template-object-ref01', 'domain-template-ref01', reader._object_ref,
    )
    draft = replace(draft, blueprint_ref='FPA-BP-014', outcome_code='onboard_domain_account',
                    material_reference_metadata=replace(draft.material_reference_metadata,
                                                        provider_class='central_lab_inventory_reference'),
                    desired_objects=tuple(DesiredObject(ref, cls, True, tuple(sorted(fields.items())))
                                          for ref, (cls, fields) in binding.expected_objects().items()))
    return draft, DomainSecretPlanningSource(binding, transport)


@pytest.mark.parametrize('inspection', [ABSENT, PRESENT])
def test_planning_projections_match_m4_state_and_hide_private_selectors(inspection):
    from test_v4_planning import _requester
    from v4_planning import ObjectClass
    transport = Transport(inspection)
    draft, source = planning_source(transport)
    result = source.project(draft, _requester(), now_epoch=100)
    secret = next(item for item in result if item.object_ref == source._binding.secret_object_ref)
    _, reader = prepared(Transport())
    assert secret.state_digest == reader.state_digest(exists=inspection.secret_exists)
    b = source._binding
    assert source.inspect_domain_secret_binding_digest(draft, _requester()) == domain_secret_binding_digest(
        b.create_binding, b.secret_object_ref, dependency_refs=(b.folder_object_ref, b.target_object_ref, b.template_object_ref, b.secret_object_ref))
    assert len(result) == 4 and len(transport.calls) == 1
    content = json.dumps([asdict(item) for item in result])
    for name in ('folder_path', 'secret_name', 'target_name', 'target_ipv4_address', 'domain_dns_root', 'target_owner_name'):
        assert getattr(source._binding.create_binding, name) not in content


@pytest.mark.parametrize('change', ['requester', 'environment', 'scope', 'outcome', 'object_ref', 'class', 'fields', 'lifecycle'])
def test_planning_substitution_rejects_before_read(change):
    from test_v4_planning import _requester
    from v4_planning import ObjectClass
    transport = Transport()
    draft, source = planning_source(transport)
    requester = _requester()
    if change == 'requester':
        source._binding = replace(source._binding, requester_digest='f' * 64)
    elif change in ('environment', 'scope'):
        draft = replace(draft, **{change + '_ref': 'other-reference01'})
    elif change == 'outcome':
        draft = replace(draft, outcome_code='onboard_web_account')
    elif change == 'lifecycle':
        draft = replace(draft, material_reference_metadata=replace(draft.material_reference_metadata, lifecycle='pending'))
    else:
        item = draft.desired_objects[-1]
        update = {'object_ref': 'other-object-ref01'} if change == 'object_ref' else (
            {'object_class': ObjectClass.WINRM_COLLECTOR_METADATA} if change == 'class'
            else {'desired_fields': (('services_disabled', False),)})
        draft = replace(draft, desired_objects=(*draft.desired_objects[:-1], replace(item, **update)))
    with pytest.raises(M4AdapterFailure):
        source.project(draft, requester, now_epoch=100)
    assert not transport.calls


@pytest.mark.parametrize('refs', [(), REFS[:3], (REFS[0], REFS[0], REFS[2], REFS[3]), (*REFS[:3], 'other-secret-object01')])
def test_dependency_reference_shape_is_closed(refs):
    _, reader = prepared(Transport())
    with pytest.raises(M4AdapterFailure):
        domain_secret_binding_digest(reader._binding, reader._object_ref, dependency_refs=refs)


def test_dependency_reference_digest_covers_each_relation():
    _, reader = prepared(Transport())
    baseline = reader.inspect_onboarding_binding_digest()
    for index in range(3):
        changed = list(REFS)
        changed[index] = 'different-object-ref01'
        assert domain_secret_binding_digest(reader._binding, reader._object_ref, dependency_refs=tuple(changed)) != baseline


def test_owned_planning_file_fixed_contract_and_settings(tmp_path):
    import json
    from fortipam_mcp.domain_secret_projection_reader import load_domain_secret_planning_binding, PLANNING_BINDING_CONTRACT
    _, source = planning_source(Transport())
    b = source._binding
    payload = {name: getattr(b, name) for name in (
        'requester_digest', 'environment_ref', 'scope_ref', 'folder_object_ref', 'folder_ref',
        'target_object_ref', 'target_profile_ref', 'template_object_ref', 'template_ref', 'secret_object_ref')}
    payload.update({name: getattr(b.create_binding, name) for name in (
        'folder_path', 'secret_name', 'target_name', 'target_ipv4_address', 'domain_dns_root',
        'target_owner_name', 'target_classification_tag')})
    payload['contract'] = PLANNING_BINDING_CONTRACT
    path = tmp_path / 'binding.json'
    path.write_text(json.dumps(payload))
    path.chmod(0o600)
    loaded = load_domain_secret_planning_binding(path)
    assert loaded.create_binding.template_name == 'Windows Domain Account'
    assert loaded.create_binding.target_product_version == '7.0.0'
    assert loaded.create_binding.target_product_build == 29
    for extra in ('password', 'template_name', 'services_enabled'):
        path.write_text(json.dumps({**payload, extra: 'untrusted-value'}))
        with pytest.raises(M4AdapterFailure):
            load_domain_secret_planning_binding(path)
    path.write_text(json.dumps(payload))
    path.chmod(0o644)
    with pytest.raises(M4AdapterFailure):
        load_domain_secret_planning_binding(path)
