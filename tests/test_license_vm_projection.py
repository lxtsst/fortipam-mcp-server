"""Synthetic provided frames; no license API, polling, secret or device reads."""
from copy import deepcopy
from dataclasses import replace
import json
import pickle

import pytest

from fortipam_mcp import license_vm_projection as module
from fortipam_mcp.license_vm_projection import LicenseVmProjection, project_provided_license_vm
from v4_planning.material_provider import MaterialAccessDenied

SERIAL = 'SYNTHETIC_VM_SERIAL'
PRIVATE = 'SYNTHETIC_UNCLASSIFIED_LICENSE_MATERIAL_MUST_NOT_BE_DECODED_OR_HASHED'


def frame():
    return dict(http_method='GET', status='success', http_status=200, version='v7.0.0', build=29,
        serial=SERIAL, path='license', name='status', results={
            'vm': dict(status=PRIVATE, valid=True, expires=2200000000, cpu_used=3, cpu_max=2,
                mem_used=1024, mem_max=0, vmx_instance_used=1, vmx_instance_max=1,
                enabled_users=5, licensed_users=4, serial=PRIVATE, license=PRIVATE),
            'subscription': dict(status=PRIVATE, key=PRIVATE), 'registration': PRIVATE})


def project(payload):
    raw = bytearray(json.dumps(payload, separators=(',', ':')).encode())
    result = project_provided_license_vm(raw, expected_serial=SERIAL)
    assert not any(raw)
    return result


def test_fixed_vm_scalars_stay_private_and_never_prove_installation_or_ha():
    result = project(frame()); summary = result.summary()
    assert result._values == (('valid', True), ('expires', 2200000000), ('cpu_used', 3), ('cpu_max', 2),
        ('mem_used', 1024), ('mem_max', 0), ('vmx_instance_used', 1), ('vmx_instance_max', 1),
        ('enabled_users', 5), ('licensed_users', 4))
    assert len(result.digest) == 64 and summary['classified_field_count'] == 10
    assert summary['status_field_present'] and summary['unselected_vm_field_count'] == 2
    for field in ('status_enum_classified', 'private_values_returned', 'complete_vm_schema_verified',
            'deployment_or_ha_verified', 'entitlement_verified', 'native_response_contract_verified',
            'authoritative_current_state_observed', 'post_boot_license_verified', 'installation_authorized', 'device_contacted'):
        assert summary[field] is False
    assert PRIVATE not in json.dumps(summary) and SERIAL not in json.dumps(summary)
    assert '2200000000' not in json.dumps(summary) and PRIVATE not in repr(result)


@pytest.mark.parametrize('shape', ['absent', 'null', 'empty'])
def test_missing_null_or_empty_vm_cannot_identify_a_physical_model(shape):
    payload = frame()
    if shape == 'absent': payload['results'].pop('vm')
    else: payload['results']['vm'] = None if shape == 'null' else {}
    result = project(payload)
    assert result.summary()['vm_node_shape'] == ('object' if shape == 'empty' else shape)
    assert result._values == () and not result.summary()['deployment_or_ha_verified']


@pytest.mark.parametrize('field', module._FIELDS)
def test_nullable_or_missing_selected_scalar_preserves_presence(field):
    payload = frame(); payload['results']['vm'][field] = None
    null = project(payload)
    payload['results']['vm'].pop(field)
    missing = project(payload)
    assert (field, None) in null._values and field not in dict(missing._values)
    assert null.digest != missing.digest


@pytest.mark.parametrize('value', [0, 1, 'true', [], {}])
def test_valid_flag_is_not_coerced_from_an_unqualified_type(value):
    payload = frame(); payload['results']['vm']['valid'] = value
    raw = bytearray(json.dumps(payload).encode())
    with pytest.raises(ValueError): project_provided_license_vm(raw, expected_serial=SERIAL)
    assert not any(raw)


@pytest.mark.parametrize('value', [-1, True, 1.0, '1024', 2**63, {}, []])
def test_local_numeric_profile_refuses_other_values_and_clears_raw(value):
    payload = frame(); payload['results']['vm']['mem_max'] = value
    raw = bytearray(json.dumps(payload).encode())
    with pytest.raises(ValueError): project_provided_license_vm(raw, expected_serial=SERIAL)
    assert not any(raw)


def test_large_integers_zero_and_overage_are_observations_without_inferred_semantics():
    payload = frame(); payload['results']['vm']['mem_max'] = 2**63-1
    result = project(payload)
    assert dict(result._values)['mem_max'] == 2**63-1 and len(result.digest) == 64
    assert not result.summary()['entitlement_verified']


def test_status_and_unknown_subtrees_are_never_decoded_or_hashed(monkeypatch):
    canonical = module.canonical_digest
    def guarded(value):
        assert PRIVATE not in json.dumps(value)
        return canonical(value)
    monkeypatch.setattr(module, 'canonical_digest', guarded)
    monkeypatch.setattr(module.metadata, '_scalar', lambda *_: pytest.fail('No response value string may be decoded.'))
    first = project(frame())
    payload = frame()
    payload['results']['vm']['status'] = dict(opaque=PRIVATE)
    payload['results']['vm']['license'] = ['other-'+PRIVATE]
    payload['results']['registration'] = dict(secret=PRIVATE)
    second = project(payload)
    assert first.digest == second.digest
    assert PRIVATE not in json.dumps(second.summary())


@pytest.mark.parametrize('field, value', [('http_method', 'POST'), ('version', 'v7.0.1'), ('build', True),
    ('serial', 'SYNTHETIC_OTHER'), ('path', 'system'), ('name', 'vmlicense'), ('status', 'error'),
    ('http_status', 500), ('error', -1), ('action', 'upload')])
def test_foreign_or_error_envelope_refuses_without_leaking_material(field, value):
    payload = frame(); payload[field] = value
    raw = bytearray(json.dumps(payload).encode())
    with pytest.raises(ValueError) as error: project_provided_license_vm(raw, expected_serial=SERIAL)
    assert not any(raw) and PRIVATE not in str(error.value) and SERIAL not in str(error.value)


@pytest.mark.parametrize('mutation', ['duplicate-vm', 'duplicate-valid', 'escaped-duplicate', 'truncated', 'trailing', 'oversize', 'array-vm'])
def test_ambiguous_or_unbounded_given_frame_refuses_and_clears(mutation):
    raw = bytearray(json.dumps(frame(), separators=(',', ':')).encode())
    if mutation == 'duplicate-vm': raw[:] = raw.replace(b'"vm":{', b'"vm":{},"vm":{')
    elif mutation == 'duplicate-valid': raw[:] = raw.replace(b'"valid":true', b'"valid":false,"valid":true')
    elif mutation == 'escaped-duplicate': raw[:] = raw.replace(b'"valid":true', b'"valid":true,"v\\u0061lid":false')
    elif mutation == 'truncated': raw.pop()
    elif mutation == 'trailing': raw.extend(b'{}')
    elif mutation == 'oversize': raw.extend(b' '*(module.MAX_BYTES+1))
    else:
        payload = frame(); payload['results']['vm'] = []
        raw[:] = json.dumps(payload).encode()
    with pytest.raises(ValueError): project_provided_license_vm(raw, expected_serial=SERIAL)
    assert not any(raw)


@pytest.mark.parametrize('failure', [KeyboardInterrupt, SystemExit, MemoryError])
def test_mid_projection_interruptions_clear_input_and_publish_nothing(monkeypatch, failure):
    raw = bytearray(json.dumps(frame()).encode())
    def fail(*_): raise failure('SYNTHETIC_PRIVATE_FAILURE')
    monkeypatch.setattr(module, '_integer', fail)
    with pytest.raises(failure if failure is not MemoryError else ValueError):
        project_provided_license_vm(raw, expected_serial=SERIAL)
    assert not any(raw)


def test_opaque_projection_is_factory_only_and_cannot_be_replaced_or_serialized():
    projection = project(frame())
    with pytest.raises(ValueError): LicenseVmProjection()
    with pytest.raises((ValueError, TypeError)): replace(projection, _shape='object')
    with pytest.raises(MaterialAccessDenied): deepcopy(projection)
    with pytest.raises(MaterialAccessDenied): pickle.dumps(projection)


def test_boundary_identifies_only_direct_get_and_keeps_native_qualification_closed():
    boundary = module.license_vm_projection_boundary()
    assert boundary['method'] == 'GET' and boundary['path'] == '/api/v2/monitor/license/status'
    assert boundary['polling_helper_can_trigger_fortiguard_update']
    assert not boundary['frontend_polling_helper_invoked'] and not boundary['http_transport_registered']
    assert not boundary['native_schema_qualified'] and not boundary['execution_authorized']
