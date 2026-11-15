"""Combined disabled-route preview, preservation and restoration regressions."""
from copy import deepcopy
import hashlib
import json

import pytest

from fortipam_mcp.disabled_route_contract import (
    DisabledRouteBinding, DisabledRouteContractError, _DEFAULTS, _RANGES, _TYPES,
    prepare_disabled_route, verify_disabled_route,
)

SERIAL = hashlib.sha256(b'synthetic-appliance').hexdigest()


def envelope(results, action=None):
    value = dict(version='v7.0.0', build=29, path='router', name='static',
                 http_method='GET', http_status=200, status='success',
                 serial='synthetic-appliance', results=results)
    if action is not None:
        value['action'] = action
    else:
        value.update(size=len(results), matched_count=len(results), next_idx=max(0, len(results) - 1))
    return value


def metadata(row):
    return {**deepcopy(row), 'q_origin_key': row['seq-num'], 'q_ref': 0, 'q_static': False,
            'q_no_rename': True, 'q_global_entry': False, 'q_type': 1, 'q_path': 'router',
            'q_name': 'static', 'q_mkey_type': 'integer', 'q_no_edit': False}


def fixture():
    fields = {k: dict(type=t, default=deepcopy(_DEFAULTS[k])) for k, t in _TYPES.items()}
    for name, (minimum, maximum) in _RANGES.items():
        fields[name].update({'min-value': minimum, 'max-value': maximum})
    for name in ('status', 'blackhole', 'link-monitor-exempt'):
        fields[name]['options'] = [{'name': 'enable'}, {'name': 'disable'}]
    for name, size in (('device', 35), ('comment', 255), ('dstaddr', 79)):
        fields[name]['size'] = size
    fields['sdwan-zone'] = dict(mkey='name', mkey_type='string', children={'name': {'type': 'string', 'size': 79}})
    schema = envelope(dict(name='static', path='router', mkey='seq-num', mkey_type='integer',
                           category='table', children=fields), 'schema')
    defaults = envelope(deepcopy(_DEFAULTS), 'default')
    existing = metadata({**deepcopy(_DEFAULTS), 'seq-num': 1, 'device': 'lab-port',
                         'gateway': '192.0.2.1'})
    table = envelope([existing])
    return schema, defaults, table, DisabledRouteBinding(100001, 'a' * 32)


def test_complete_disabled_route_preview_readback_and_restoration():
    schema, defaults, table, binding = fixture()
    original = deepcopy((schema, defaults, table))
    prepared = prepare_disabled_route(schema, defaults, table, serial_digest=SERIAL, binding=binding)
    body = json.loads(prepared.body_bytes)
    assert body['status'] == 'disable' and body['blackhole'] == 'enable'
    assert body['device'] == '' and body['gateway'] == '0.0.0.0'
    assert body['dst'] == '198.18.0.1 255.255.255.255'
    assert body['seq-num'] == binding.sequence
    assert prepared.current_digest != prepared.expected_digest
    created = envelope([metadata(body), *table['results']])
    assert table['next_idx'] == 0 and created['next_idx'] == 1
    assert verify_disabled_route(created, prepared, serial_digest=SERIAL)
    assert not verify_disabled_route(table, prepared, serial_digest=SERIAL)
    assert verify_disabled_route(table, prepared, serial_digest=SERIAL, removed=True)
    assert not verify_disabled_route(created, prepared, serial_digest=SERIAL, removed=True)
    assert (schema, defaults, table) == original
    assert 'lab-port' not in repr(prepared) and binding.nonce not in repr(binding)


@pytest.mark.parametrize('fault', ['version', 'schema-field', 'default', 'partial', 'duplicate', 'identity', 'destination'])
def test_incompatible_or_incomplete_current_state_never_produces_a_body(fault):
    schema, defaults, table, binding = fixture()
    if fault == 'version':
        defaults['build'] = 30
    elif fault == 'schema-field':
        schema['results']['children']['extra'] = {'type': 'string'}
    elif fault == 'default':
        defaults['results']['distance'] = 20
    elif fault == 'partial':
        table['next_idx'] = 1
    elif fault == 'duplicate':
        table['results'] *= 2
        table.update(size=2, matched_count=2, next_idx=1)
    elif fault == 'identity':
        table['serial'] = 'another-appliance'
    else:
        table['results'][0]['dst'] = binding.body['dst']
    with pytest.raises(DisabledRouteContractError, match='^The fixed disabled route is unavailable.$'):
        prepare_disabled_route(schema, defaults, table, serial_digest=SERIAL, binding=binding)


@pytest.mark.parametrize('fault', ['enabled', 'references', 'other-route-changed', 'extra-route', 'partial', 'bool-count'])
def test_changed_or_incomplete_readback_is_not_success(fault):
    schema, defaults, table, binding = fixture()
    prepared = prepare_disabled_route(schema, defaults, table, serial_digest=SERIAL, binding=binding)
    created = envelope([*deepcopy(table['results']), metadata(binding.body)])
    if fault == 'enabled':
        created['results'][1]['status'] = 'enable'
    elif fault == 'references':
        created['results'][1]['q_ref'] = 1
    elif fault == 'other-route-changed':
        created['results'][0]['distance'] = 20
    elif fault == 'extra-route':
        extra = metadata({**deepcopy(_DEFAULTS), 'seq-num': 2})
        created['results'].append(extra)
        created.update(size=3, matched_count=3, next_idx=2)
    elif fault == 'partial':
        created['matched_count'] = 3
    else:
        created['size'] = True
    if fault in {'partial', 'bool-count'}:
        with pytest.raises(DisabledRouteContractError):
            verify_disabled_route(created, prepared, serial_digest=SERIAL)
    else:
        assert verify_disabled_route(created, prepared, serial_digest=SERIAL) is False
