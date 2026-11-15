"""Synthetic consuming actor, Template and schema preflight checks."""
import copy
from dataclasses import replace
import hashlib
import json
import pickle

import pytest

from fortipam_mcp import target_lifecycle_dependencies as d
from fortipam_mcp import target_preservation_contract as c
from v4_planning.material_provider import MaterialAccessDenied

ACTOR = 'synthetic-owner'
SERIAL = 'SYNTHETIC'
DIGEST = hashlib.sha256(SERIAL.encode()).hexdigest()
COORDINATES = (c.TargetCoordinates('Synthetic Template', '192.0.2.1', '', ''),)
SENTINEL = 'SYNTHETIC_UNSELECTED_MATERIAL'


def envelope(path, name, results):
    return dict(version='v7.0.0', build=29, path=path, name=name, http_method='GET',
                status='success', http_status=200, vdom='root', serial=SERIAL, results=results)


def payloads():
    actor = envelope('web-ui', 'state', {'admin': dict(name=ACTOR, login_name=ACTOR,
        sponsored_group_name='', guest_admin=False), 'unrelated': SENTINEL})
    role = envelope('system', 'admin', [dict(name=ACTOR, accprofile='super_admin',
        status='enable', **{'remote-auth': 'disable', 'wildcard': 'disable', 'password': SENTINEL})])
    templates = envelope('secret', 'template', [dict(name='Synthetic Template',
        permissions={'user': 'owner'}, field=[dict(name='Address', type='target-address', mandatory='enable'),
        dict(name='Password', type='password', mandatory='enable', value=SENTINEL)], extra=SENTINEL)])
    templates.update(http_method='POST', status='OK')
    children = {name: {'unknown': SENTINEL} for name in c.TARGET_STATE_FIELDS}
    for name in c._COORDINATES:
        children[name].update(type='var-string' if name == 'url' else 'string', size=79 if name == 'template' else 255)
    schema = envelope('secret', 'target', dict(children=children))
    return [actor, role, templates, schema, copy.deepcopy(actor), copy.deepcopy(role)]


def qualify(values=None, **kwargs):
    inputs = payloads() if values is None else values
    buffers = [bytearray(json.dumps(value).encode()) for value in inputs]
    try:
        return d.qualify_target_lifecycle_dependencies(*buffers, expected_actor=ACTOR,
            expected_serial_digest=DIGEST, coordinates=kwargs.get('coordinates', COORDINATES))
    finally:
        assert all(not any(buffer) for buffer in buffers)


def test_complete_binding_without_material_decoding(monkeypatch):
    original = json.loads

    def selected_only(raw, *args, **kwargs):
        assert SENTINEL not in str(raw)
        return original(raw, *args, **kwargs)

    monkeypatch.setattr(json, 'loads', selected_only)
    result = qualify()
    assert result.serial_digest == DIGEST and len(result.template_digests) == 1
    assert ACTOR not in repr(result) and 'Synthetic Template' not in repr(result)
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(MaterialAccessDenied):
            operation(result)


@pytest.mark.parametrize('index', [0, 1, 2, 3, 4, 5])
@pytest.mark.parametrize('key,value', [('serial', 'OTHER'), ('build', True), ('http_status', 201)])
def test_cross_device_version_and_status_denied(index, key, value):
    values = payloads(); values[index][key] = value
    with pytest.raises(d.TargetLifecycleDependencyError):
        qualify(values)


@pytest.mark.parametrize('index', [0, 4])
@pytest.mark.parametrize('key,value', [('name', 'other'), ('login_name', 'other'),
    ('sponsored_group_name', 'group'), ('guest_admin', True), ('guest_admin', 0)])
def test_current_actor_context_denied(index, key, value):
    values = payloads(); values[index]['results']['admin'][key] = value
    with pytest.raises(d.TargetLifecycleDependencyError):
        qualify(values)


@pytest.mark.parametrize('index', [1, 5])
@pytest.mark.parametrize('key,value', [('name', 'other'), ('accprofile', 'Guest'),
    ('status', 'disable'), ('remote-auth', 'enable'), ('wildcard', 'enable'), ('q_origin_key', 'other')])
def test_role_identity_and_privileges_denied(index, key, value):
    values = payloads(); values[index]['results'][0][key] = value
    with pytest.raises(d.TargetLifecycleDependencyError):
        qualify(values)


@pytest.mark.parametrize('fault', ['permission', 'missing-permission', 'empty', 'duplicate-kind',
    'missing-name', 'duplicate-name', 'unknown-kind', 'missing-coordinate', 'readonly', 'wrong-type', 'wrong-size', 'missing-schema'])
def test_templates_and_coordinate_schema_denials(fault):
    values = payloads(); template = values[2]['results'][0]; children = values[3]['results']['children']
    coordinates = COORDINATES
    if fault == 'permission': template['permissions']['user'] = 'none'
    elif fault == 'missing-permission': del template['permissions']
    elif fault == 'empty': template['field'] = []
    elif fault == 'duplicate-kind': template['field'].append(dict(name='Second', type='password', mandatory='disable'))
    elif fault == 'missing-name': template['name'] = 'Other Template'
    elif fault == 'duplicate-name': values[2]['results'].append(copy.deepcopy(template))
    elif fault == 'unknown-kind': template['field'][0]['type'] = 'service-address'
    elif fault == 'missing-coordinate': coordinates = (replace(COORDINATES[0], address=''),)
    elif fault == 'readonly': children['address']['readonly'] = True
    elif fault == 'wrong-type': children['url']['type'] = 'string'
    elif fault == 'wrong-size': children['template']['size'] = 80
    elif fault == 'missing-schema': del children['uuid']
    with pytest.raises(d.TargetLifecycleDependencyError):
        qualify(values, coordinates=coordinates)


def test_old_and_new_templates_and_opaque_definition_drift_bound():
    values = payloads(); extra = copy.deepcopy(values[2]['results'][0]); extra['name'] = 'Second Template'
    values[2]['results'].append(extra)
    coordinates = COORDINATES + (replace(COORDINATES[0], template='Second Template'),)
    before = qualify(values, coordinates=coordinates)
    assert len(before.template_digests) == 2
    extra['extra'] = 'changed-undecoded-definition'
    after = qualify(values, coordinates=coordinates)
    assert before.dependency_digest != after.dependency_digest
    values[3]['results']['children']['uuid']['unknown'] = 'changed-schema'
    assert after.dependency_digest != qualify(values, coordinates=coordinates).dependency_digest


@pytest.mark.parametrize('fault', ['alias', 'duplicate-actor-key', 'malformed', 'wrong-input', 'oversize'])
def test_all_owned_buffers_wiped_on_failure(fault):
    buffers = [bytearray(json.dumps(value).encode()) for value in payloads()]
    if fault == 'alias': buffers[4] = buffers[0]
    elif fault == 'duplicate-actor-key': buffers[0] = bytearray(buffers[0].replace(b'"guest_admin": false', b'"guest_admin": false, "guest_admin": false'))
    elif fault == 'malformed': buffers[3] = bytearray(b'{')
    elif fault == 'wrong-input': buffers[2] = b'{}'
    elif fault == 'oversize': buffers[3] = bytearray(b' ' * (d.m._MAX_BYTES + 1))
    with pytest.raises(d.TargetLifecycleDependencyError) as error:
        d.qualify_target_lifecycle_dependencies(*buffers, expected_actor=ACTOR,
            expected_serial_digest=DIGEST, coordinates=COORDINATES)
    assert str(error.value) == d._ERROR and error.value.__suppress_context__
    assert all(not any(buffer) for buffer in buffers if type(buffer) is bytearray)


def test_compatible_optional_monitor_shape_and_admin_object():
    values = payloads()
    for index in (0, 4):
        for key in ('http_status', 'serial', 'vdom'): del values[index][key]
    for index in (1, 5):
        values[index]['status'] = 'OK'
        values[index]['results'] = values[index]['results'][0]
    assert qualify(values).actor_digest == qualify().actor_digest


def test_explicit_schema_action_is_bound():
    values = payloads(); values[3]['action'] = 'schema'
    assert qualify(values).schema_digest == qualify().schema_digest
    values[3]['action'] = 'default'
    with pytest.raises(d.TargetLifecycleDependencyError):
        qualify(values)


def api_payloads():
    local = payloads()
    api = envelope('system', 'api-user', dict(name=ACTOR, accprofile='synthetic-profile',
        q_origin_key=ACTOR, unknown=SENTINEL))
    profile = envelope('system', 'accprofile', dict(name='synthetic-profile',
        secretgrp='custom', **{'secretgrp-permission': {'target':'read-write', 'unknown':SENTINEL}}))
    return [local[0], api, profile, local[2], local[3], copy.deepcopy(profile),
            copy.deepcopy(api), local[4]]


def qualify_api(values=None, **kwargs):
    inputs = api_payloads() if values is None else values
    buffers = [bytearray(json.dumps(value).encode()) for value in inputs]
    try:
        return d.qualify_target_api_lifecycle_dependencies(*buffers,
            expected_actor=kwargs.get('expected_actor', ACTOR), expected_serial_digest=DIGEST,
            coordinates=kwargs.get('coordinates', COORDINATES))
    finally:
        assert all(not any(buffer) for buffer in buffers)


def test_api_principal_complete_binding_and_opaque_result(monkeypatch):
    original = json.loads
    def selected_only(raw, *args, **kwargs):
        assert SENTINEL not in str(raw)
        return original(raw, *args, **kwargs)
    monkeypatch.setattr(json, 'loads', selected_only)
    result = qualify_api()
    local = qualify()
    assert result.actor_digest != local.actor_digest
    assert result.dependency_digest != local.dependency_digest
    assert result.template_digests == local.template_digests
    assert result.schema_digest == local.schema_digest
    assert result.coordinates_digest == local.coordinates_digest
    assert ACTOR not in repr(result) and 'synthetic-profile' not in repr(result)
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(MaterialAccessDenied): operation(result)


@pytest.mark.parametrize('index', range(8))
@pytest.mark.parametrize('key,value', [('serial','OTHER'), ('build',True), ('http_status',201)])
def test_api_origin_version_status(index,key,value):
    values=api_payloads(); values[index][key]=value
    with pytest.raises(d.TargetLifecycleDependencyError): qualify_api(values)


@pytest.mark.parametrize('index', [0,7])
@pytest.mark.parametrize('key,value', [('name','other'),('login_name','other'),
    ('sponsored_group_name','group'),('guest_admin',True),('guest_admin',0)])
def test_api_actor_denial(index,key,value):
    values=api_payloads(); values[index]['results']['admin'][key]=value
    with pytest.raises(d.TargetLifecycleDependencyError): qualify_api(values)


@pytest.mark.parametrize('index', [1,6])
@pytest.mark.parametrize('key,value', [('name','other'),('q_origin_key','other'),
    ('accprofile','other-profile'),('accprofile',[]),('accprofile','../profile'),('accprofile','')])
def test_api_reference_denial(index,key,value):
    values=api_payloads(); values[index]['results'][key]=value
    with pytest.raises(d.TargetLifecycleDependencyError): qualify_api(values)


@pytest.mark.parametrize('index', [2,5])
@pytest.mark.parametrize('fault', ['name','origin','group','missing','read','enable','bool','null','shape'])
def test_api_profile_declared_target_access_denial(index,fault):
    values=api_payloads(); row=values[index]['results']
    if fault=='name':row['name']='other'
    elif fault=='origin':row['q_origin_key']='other'
    elif fault=='group':row['secretgrp']='read-write'
    elif fault=='missing':del row['secretgrp-permission']['target']
    elif fault=='read':row['secretgrp-permission']['target']='read'
    elif fault=='enable':row['secretgrp-permission']['target']='enable'
    elif fault=='bool':row['secretgrp-permission']['target']=True
    elif fault=='null':row['secretgrp-permission']['target']=None
    elif fault=='shape':row['secretgrp-permission']=[]
    with pytest.raises(d.TargetLifecycleDependencyError): qualify_api(values)


@pytest.mark.parametrize('index', [1,2,5,6])
def test_api_undecoded_row_drift_denied(index):
    values=api_payloads(); values[index]['results']['unknown']='changed-undecoded'
    with pytest.raises(d.TargetLifecycleDependencyError): qualify_api(values)


def test_api_reference_and_profile_are_bound_even_with_same_access():
    values=api_payloads()
    for index in (1,6):values[index]['results']['accprofile']='replacement-profile'
    for index in (2,5):values[index]['results']['name']='replacement-profile'
    assert qualify_api(values).actor_digest != qualify_api().actor_digest


@pytest.mark.parametrize('fault', ['alias','duplicate','malformed','wrong-input','oversize','cross-kind'])
def test_api_owned_buffers_wiped_on_all_failures(fault):
    buffers=[bytearray(json.dumps(value).encode()) for value in api_payloads()]
    if fault=='alias':buffers[5]=buffers[2]
    elif fault=='duplicate':buffers[2]=bytearray(buffers[2].replace(b'"target": "read-write"', b'"target": "read-write", "target": "read-write"'))
    elif fault=='malformed':buffers[6]=bytearray(b'{')
    elif fault=='wrong-input':buffers[3]=b'{}'
    elif fault=='oversize':buffers[4]=bytearray(b' '*(d.m._MAX_BYTES+1))
    elif fault=='cross-kind':buffers[1]=bytearray(json.dumps(payloads()[1]).encode())
    with pytest.raises(d.TargetLifecycleDependencyError) as error:
        d.qualify_target_api_lifecycle_dependencies(*buffers,expected_actor=ACTOR,
            expected_serial_digest=DIGEST,coordinates=COORDINATES)
    assert str(error.value)==d._ERROR and error.value.__suppress_context__
    assert all(not any(buffer) for buffer in buffers if type(buffer) is bytearray)


def test_api_template_permissions_and_schema_still_required():
    values=api_payloads();values[3]['results'][0]['permissions']['user']='none'
    with pytest.raises(d.TargetLifecycleDependencyError):qualify_api(values)
    values=api_payloads();values[4]['results']['children']['address']['readonly']=True
    with pytest.raises(d.TargetLifecycleDependencyError):qualify_api(values)


@pytest.mark.parametrize('name', ['synthetic@api', 'synthetic-api'])
def test_api_safe_names_and_singleton_rows(name):
    values=api_payloads()
    for index in (0,7):values[index]['results']['admin'].update(name=name,login_name=name)
    for index in (1,6):values[index]['results'].update(name=name,q_origin_key=name)
    for index in (1,2,5,6):values[index]['results']=[values[index]['results']]
    assert qualify_api(values,expected_actor=name).serial_digest==DIGEST
