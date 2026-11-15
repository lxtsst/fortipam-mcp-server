"""SCIM native payload parity and partial-state limits, with synthetic material only."""
from array import array
import copy
from dataclasses import replace
import json
import pickle

import pytest

from fortipam_mcp import scim_client_contract as contract
from fortipam_mcp.scim_client_contract import (
    NATIVE_NAME, NONMATERIAL_FIELDS, ScimClientContractError, ScimNonmaterialState,
    build_scim_request_with_material, prepare_scim_create, prepare_scim_disable, prepare_scim_rotate,
)
from v4_planning.material_provider import MaterialAccessDenied

CONTEXT = dict(serial_digest='a'*64, schema_digest='b'*64, global_digest='c'*64,
    interfaces_digest='d'*64, saml_digest='e'*64, trust_digest='f'*64)
OLD, NEW = '1'*64, '2'*64  # Synthetic provider binding digests, not password hashes.


def values():
    return {'id': 7, 'name': NATIVE_NAME, 'status': 'enable', 'base-url': 'https://synthetic.invalid/scim/v2',
        'auth-method': 'base', 'client-identity-check': 'disable', 'certificate': '',
        'token-certificate': 'synthetic-unforwarded-token-certificate'}


def prepared(operation):
    current = ScimNonmaterialState.from_values(values())
    if operation == 'create':
        defaults = ScimNonmaterialState.from_values({**values(), 'id': 0, 'name': '', 'status': 'disable',
            'base-url': '', 'client-identity-check': 'enable'})
        transition = prepare_scim_create(defaults, base_url=values()['base-url'], material_binding_digest=NEW, context=CONTEXT)
        return transition, None, NEW
    if operation == 'rotate':
        return prepare_scim_rotate(current, current_material_binding_digest=OLD,
            replacement_material_binding_digest=NEW, context=CONTEXT), current, NEW
    return prepare_scim_disable(current, current_material_binding_digest=OLD, context=CONTEXT), current, OLD


def encoded(transition, current, binding, *, restore=False, context=CONTEXT, material=b'synthetic-secret'):
    private = bytearray(material)
    try:
        with memoryview(private) as view:
            return build_scim_request_with_material(transition, view, current=current, context=context,
                material_binding_digest=binding, restore=restore)
    finally: private[:] = b'\0'*len(private)


@pytest.mark.parametrize('operation', ['create', 'rotate', 'disable'])
def test_exact_native_eight_field_body_and_explicit_credential_verification_limit(operation):
    transition, current, binding = prepared(operation)
    body = encoded(transition, current, binding)
    try:
        wire = json.loads(body)
        assert set(wire) == NONMATERIAL_FIELDS - {'token-certificate'} | {'secret'}
        assert wire == {**{key: value for key, value in transition._proposed._values().items()
            if key != 'token-certificate'}, 'secret': 'synthetic-secret'}
        assert wire['name'] == NATIVE_NAME and wire['auth-method'] == 'base'
        assert wire['client-identity-check'] == 'disable' and wire['certificate'] == ''
    finally: body[:] = b'\0'*len(body)
    transition.verify_nonmaterial_applied(transition._proposed, CONTEXT)
    assert len(transition.parameters_digest) == 64
    preview = transition.preview()
    assert preview['Expected State']['independent_credential_verification_required'] is True
    assert preview['configuration_write_authorized'] is preview['native_backend_qualified'] is False
    assert preview['independent_recovery_qualified'] is False
    public = json.dumps(preview)
    assert all(value not in public for value in ('synthetic-secret', 'synthetic.invalid', NATIVE_NAME, OLD, NEW))


def test_creation_makes_the_native_security_override_visible_without_enabling_shared_writes():
    transition, _, _ = prepared('create')
    preview = transition.preview()
    assert preview['Current State']['client_identity_check_enabled'] is True
    assert preview['Expected State']['client_identity_check_enabled'] is False
    assert 'client-identity-check' in preview['Proposed Changes']['nonmaterial_field_names']
    assert preview['shared_global_interface_saml_writes_included'] is False
    assert preview['creation_id_assignment_qualified'] is False
    # A server-assigned id cannot be accepted by guessing an allocation contract.
    assigned = ScimNonmaterialState.from_values({**transition._proposed._values(), 'id': 42})
    with pytest.raises(ScimClientContractError): transition.verify_nonmaterial_applied(assigned, CONTEXT)
    with pytest.raises(ScimClientContractError): encoded(transition, transition._proposed, OLD, restore=True)


def test_native_unsigned_id_above_the_generic_canonical_integer_limit_is_preserved():
    current = ScimNonmaterialState.from_values({**values(), 'id': 4294967295})
    transition = prepare_scim_rotate(current, current_material_binding_digest=OLD,
        replacement_material_binding_digest=NEW, context=CONTEXT)
    assert len(transition.parameters_digest) == 64
    body = encoded(transition, current, NEW)
    try: assert json.loads(body)['id'] == 4294967295
    finally: body[:] = b'\0'*len(body)


def test_native_scim_suffix_rule_preserves_a_prefixed_service_path():
    current = ScimNonmaterialState.from_values({**values(),'base-url':'https://synthetic.invalid/api/v1/scim/v2'})
    transition = prepare_scim_rotate(current,current_material_binding_digest=OLD,replacement_material_binding_digest=NEW,context=CONTEXT)
    body = encoded(transition,current,NEW)
    try: assert json.loads(body)['base-url'] == 'https://synthetic.invalid/api/v1/scim/v2'
    finally: body[:] = b'\0'*len(body)


@pytest.mark.parametrize('operation', ['rotate', 'disable'])
def test_restore_uses_the_original_configuration_and_original_material_binding(operation):
    transition, current, _ = prepared(operation)
    body = encoded(transition, transition._proposed, OLD, restore=True, material=b'synthetic-retiring-secret')
    try:
        restored = json.loads(body)
        assert restored['secret'] == 'synthetic-retiring-secret'
        assert {key: value for key, value in restored.items() if key != 'secret'} == {
            key: value for key, value in current._values().items() if key != 'token-certificate'}
    finally: body[:] = b'\0'*len(body)
    transition.verify_nonmaterial_restored(current, CONTEXT)
    with pytest.raises(ScimClientContractError): encoded(transition, transition._proposed, NEW, restore=True)


def test_disable_only_changes_status_and_native_secret_relay_does_not_prove_preservation():
    transition, current, binding = prepared('disable')
    assert transition.preview()['Proposed Changes']['nonmaterial_field_names'] == ['status']
    first = encoded(transition, current, binding, material=b'synthetic-first-secret')
    second = encoded(transition, current, binding, material=b'synthetic-wrong-secret')
    try:
        assert first != second
        a, b = json.loads(first), json.loads(second)
        del a['secret']; del b['secret']
        assert a == b
        # The same configuration comparison succeeds for either credential.
        # Only independent authentication/provider evidence can distinguish them.
        transition.verify_nonmaterial_applied(transition._proposed, CONTEXT)
    finally:
        first[:] = b'\0'*len(first); second[:] = b'\0'*len(second)


@pytest.mark.parametrize('field', sorted(NONMATERIAL_FIELDS))
def test_every_nonmaterial_field_including_omitted_token_certificate_is_compared(field):
    transition, _, _ = prepared('rotate')
    changed = values()
    changed[field] = {'id': 8, 'name': 'synthetic-other', 'status': 'disable',
        'base-url': 'https://changed.invalid/scim/v2', 'auth-method': 'unsupported',
        'client-identity-check': 'enable', 'certificate': 'synthetic-cert',
        'token-certificate': 'synthetic-changed-token-cert'}[field]
    with pytest.raises(ScimClientContractError):
        transition.verify_nonmaterial_applied(ScimNonmaterialState.from_values(changed), CONTEXT)


@pytest.mark.parametrize('field', sorted(CONTEXT))
def test_device_schema_and_all_shared_dependencies_must_remain_pinned(field):
    transition, current, binding = prepared('disable')
    changed = {**CONTEXT, field: '0'*64}
    with pytest.raises(ScimClientContractError): encoded(transition, current, binding, context=changed)
    with pytest.raises(ScimClientContractError): transition.verify_nonmaterial_applied(transition._proposed, changed)
    with pytest.raises(ScimClientContractError): encoded(transition, transition._proposed, OLD, restore=True, context=changed)


@pytest.mark.parametrize('operation', ['rotate', 'disable'])
@pytest.mark.parametrize('field,value', [('client-identity-check', 'enable'), ('certificate', 'synthetic-existing-cert'),
    ('auth-method', 'unsupported'), ('name', 'synthetic-other'), ('status', 'disable')])
def test_rotation_or_disable_cannot_silently_change_an_incompatible_security_profile(operation, field, value):
    with pytest.raises(ScimClientContractError):
        current = ScimNonmaterialState.from_values({**values(), field: value})
        if operation == 'rotate':
            prepare_scim_rotate(current, current_material_binding_digest=OLD, replacement_material_binding_digest=NEW, context=CONTEXT)
        else: prepare_scim_disable(current, current_material_binding_digest=OLD, context=CONTEXT)


@pytest.mark.parametrize('fault', ['same-material', 'foreign-material', 'current-drift', 'missing-context', 'extra-context', 'forged-transition'])
def test_unbound_rotation_or_changed_current_state_never_produces_a_body(fault):
    transition, current, binding = prepared('rotate')
    with pytest.raises(ScimClientContractError):
        if fault == 'same-material':
            prepare_scim_rotate(current, current_material_binding_digest=OLD, replacement_material_binding_digest=OLD, context=CONTEXT)
        elif fault == 'foreign-material': encoded(transition, current, OLD)
        elif fault == 'current-drift': encoded(transition, ScimNonmaterialState.from_values({**values(), 'id': 8}), binding)
        elif fault == 'missing-context': encoded(transition, current, binding, context={k: v for k, v in CONTEXT.items() if k != 'saml_digest'})
        elif fault == 'extra-context': encoded(transition, current, binding, context={**CONTEXT, 'isolation': '0'*64})
        else: replace(transition, operation='disable')


@pytest.mark.parametrize('value', ['http://synthetic.invalid/scim/v2', 'https://synthetic.invalid:443/scim/v2',
    'https://user:password@synthetic.invalid/scim/v2', 'https://synthetic.invalid/scim/v2?query=x',
    'https://synthetic.invalid/scim/v2#fragment', 'https://synthetic.invalid/other',
    'https://synthetic.invalid/\nscim/v2', 'https://synthetic.invalid/scim/v2/'])
def test_native_port_separation_and_fixed_tls_service_url_are_not_generic_endpoint_inputs(value):
    with pytest.raises(ScimClientContractError): ScimNonmaterialState.from_values({**values(), 'base-url': value})


@pytest.mark.parametrize('field,value', [('id', True), ('id', -1), ('id', 4294967296),
    ('base-url', 'https://'+'a'*110+'.invalid/scim/v2'), ('certificate', 'a'*80), ('token-certificate', 'a'*80),
    ('name', 'a'*36), ('status', True), ('secret', 'SYNTHETIC_C3_SENTINEL'), ('q_ref', 0)])
def test_invalid_types_sizes_and_credential_or_metadata_keys_are_refused_without_values(field, value):
    with pytest.raises(ScimClientContractError) as error: ScimNonmaterialState.from_values({**values(), field: value})
    assert 'SYNTHETIC_C3_SENTINEL' not in str(error.value)


@pytest.mark.parametrize('material', [b'', b'a'*60, b'a\x00b', b'a\nb', b'a\rb', b'\xff', b'\xc0\x80', b'\xed\xa0\x80'])
def test_invalid_or_oversize_material_is_not_decoded_or_compiled(material):
    transition, current, binding = prepared('rotate')
    with pytest.raises(ScimClientContractError): encoded(transition, current, binding, material=material)


def test_material_escaping_stays_in_mutable_bytes_and_does_not_enter_json_decoding(monkeypatch):
    transition, current, binding = prepared('rotate')
    original = json.loads
    def decode_nonmaterial(raw, *args, **kwargs):
        sentinel = b'SYNTHETIC_C3_SENTINEL' if isinstance(raw, (bytes, bytearray)) else 'SYNTHETIC_C3_SENTINEL'
        assert sentinel not in raw
        return original(raw, *args, **kwargs)
    monkeypatch.setattr(json, 'loads', decode_nonmaterial)
    material = 'SYNTHETIC_C3_SENTINEL"\\é'.encode()
    body = encoded(transition, current, binding, material=material)
    try: assert original(body)['secret'].encode() == material
    finally: body[:] = b'\0'*len(body)
    assert b'SYNTHETIC_C3_SENTINEL' not in transition._context
    assert b'SYNTHETIC_C3_SENTINEL' not in transition._proposed._encoded


def test_partial_material_encoding_failure_clears_owned_output_buffer(monkeypatch):
    transition, current, binding = prepared('rotate'); buffers = []
    def fail(body, material):
        body.extend(material); buffers.append(body._storage); raise RuntimeError('SYNTHETIC_C3_SENTINEL')
    monkeypatch.setattr(contract, '_append_material', fail)
    with pytest.raises(ScimClientContractError) as error: encoded(transition, current, binding)
    assert buffers and not any(buffers[0]) and 'SYNTHETIC_C3_SENTINEL' not in str(error.value)


@pytest.mark.parametrize('material', [b'bad-string-input', 'bad-text-input', memoryview(array('H', [65])), memoryview(b'abc')[::2]])
def test_only_a_bounded_unsigned_contiguous_material_view_is_accepted(material):
    transition, current, binding = prepared('rotate')
    with pytest.raises(ScimClientContractError):
        build_scim_request_with_material(transition, material, current=current, context=CONTEXT, material_binding_digest=binding)


def test_private_state_and_transition_remain_opaque_and_reject_serialization():
    transition, current, _ = prepared('rotate')
    for value in (transition, current):
        assert 'redacted' in repr(value) and 'synthetic.invalid' not in str(value)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(MaterialAccessDenied): operation(value)
    assert replace(transition, _new_material_binding_digest='3'*64).parameters_digest != transition.parameters_digest
