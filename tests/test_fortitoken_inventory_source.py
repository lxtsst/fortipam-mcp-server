"""Private inventory aggregates from synthetic monitor responses only."""
from copy import deepcopy
import hashlib
import json

import pytest

from fortipam_mcp.fortitoken_inventory_source import (FortitokenInventorySource, INVENTORY_PATH,
    project_fortitoken_inventory)
from test_fortitoken_user_contract import SERIAL, TOKEN
from test_fortitoken_user_source import Peer


def envelope(rows=None, *, disclosed=True):
    rows = rows if rows is not None else {
        'SYNTHETIC_PRIVATE_KEY_ALPHA':dict(serial_number=TOKEN.decode(),type='mobile',
            status=dict(name='available',private='SYNTHETIC_PRIVATE_STATUS'),
            license=dict(private='SYNTHETIC_PRIVATE_LICENSE'),activation='SYNTHETIC_PRIVATE_ACTIVATION'),
        'SYNTHETIC_PRIVATE_KEY_BETA':dict(serial_number='SYNTHETIC_TOKEN_BETA',type='hard',status=dict(name='pending'))}
    value = dict(build=29,http_method='GET',name='fortitoken',path='user',status='success',version='v7.0.0',
        serial=SERIAL,http_status=200,results=rows,vdom='synthetic-private-vdom')
    if disclosed: value.update(size=len(rows),matched_count=len(rows),limit_reached=False)
    return value


def project(value):
    raw = bytearray(json.dumps(value).encode())
    try: return project_fortitoken_inventory(raw,expected_serial=SERIAL,source_digest='d'*64,observed_at=1000)
    finally: assert not any(raw)


@pytest.mark.parametrize('wrapped', [False,True])
def test_aggregate_never_decodes_or_hashes_inventory_keys_selectors_or_license_contents(monkeypatch,wrapped):
    payload = envelope(); decode = json.loads; digest = hashlib.sha256
    def private_bytes(raw): return raw.encode() if isinstance(raw,str) else bytes(raw)
    def checked_decode(raw,*args,**kwargs):
        assert b'SYNTHETIC_PRIVATE' not in private_bytes(raw) and TOKEN not in private_bytes(raw)
        return decode(raw,*args,**kwargs)
    def checked_digest(raw=b'',*args,**kwargs):
        assert b'SYNTHETIC_PRIVATE' not in private_bytes(raw) and TOKEN not in private_bytes(raw)
        return digest(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',checked_decode); monkeypatch.setattr(hashlib,'sha256',checked_digest)
    result = project([payload] if wrapped else payload); public = result.public()
    assert result.type_counts == (1,1,0) and result.status_counts == (1,1,0) and result.license_field_count == 1
    assert result.source_digest == 'd'*64 and result.view_count == 1 and result.observed_at == 1000 and result.expires_at == 1010
    assert result.counts_reported_for_each_view and result.no_truncation_reported_for_each_view
    assert public['token_count'] == 2 and not public['license_validity_verified']
    assert not public['complete_inventory_qualified'] and not public['token_ownership_verified']
    assert not public['material_continuity_verified'] and not public['configuration_write_authorized']
    text = json.dumps(public)
    assert 'SYNTHETIC_PRIVATE' not in text and TOKEN.decode() not in text and SERIAL not in text


def test_all_views_are_counted_without_inventing_missing_count_or_truncation_disclosures():
    first = envelope({},disclosed=False); second = envelope()
    result = project([first,second]); assert result.view_count == 2
    assert not result.counts_reported_for_each_view and not result.no_truncation_reported_for_each_view
    assert result.type_counts == (1,1,0) and not result.public()['complete_inventory_qualified']
    empty = project(envelope({})); assert empty.public()['token_count'] == 0
    assert not empty.public()['token_ownership_verified']


def test_unknown_type_or_status_is_categorical_and_license_presence_is_not_validity():
    value = envelope(); row = next(iter(value['results'].values()))
    row.update(type='SYNTHETIC_PRIVATE_UNKNOWN_TYPE',status=dict(name='SYNTHETIC_PRIVATE_UNKNOWN_STATUS'),license=None)
    result = project(value); assert result.type_counts == (1,0,1) and result.status_counts == (0,1,1)
    assert result.license_field_count == 1 and not result.public()['license_validity_verified']


@pytest.mark.parametrize('fault', ['version','build','serial','method','path','name','status','http-status','error',
    'truncated','size','matched','next','count-bool','limit-type','array-empty','array-limit','rows-limit',
    'missing-selector','selector-type','selector-space','selector-empty','status-shape','status-name','type-shape',
    'duplicate-selector','duplicate-across-views','unknown-envelope'])
def test_wrong_device_envelope_truncation_or_ambiguous_rows_refuse_without_partial_counts(fault):
    value = envelope(); first = next(iter(value['results'].values()))
    key = {'version':'version','build':'build','serial':'serial','method':'http_method','path':'path',
        'name':'name','status':'status','http-status':'http_status','error':'error'}.get(fault)
    if key: value[key] = 30 if fault in ('build','http-status','error') else 'synthetic-other'
    elif fault == 'truncated': value['limit_reached'] = True
    elif fault == 'size': value['size'] = 3
    elif fault == 'matched': value['matched_count'] = 3
    elif fault == 'next': value['next_idx'] = 1
    elif fault == 'count-bool': value['size'] = True
    elif fault == 'limit-type': value['limit_reached'] = 0
    elif fault == 'array-empty': value = []
    elif fault == 'array-limit': value = [envelope({})]*32
    elif fault == 'rows-limit': value = envelope({str(i):dict(serial_number='SYNTHETIC_TOKEN_'+str(i),type='hard',status=dict(name='available')) for i in range(129)})
    elif fault == 'missing-selector': del first['serial_number']
    elif fault == 'selector-type': first['serial_number'] = 123
    elif fault == 'selector-space': first['serial_number'] = 'SYNTHETIC TOKEN'
    elif fault == 'selector-empty': first['serial_number'] = ''
    elif fault == 'status-shape': first['status'] = 'available'
    elif fault == 'status-name': first['status'] = {}
    elif fault == 'type-shape': first['type'] = {}
    elif fault == 'duplicate-selector': list(value['results'].values())[1]['serial_number'] = first['serial_number']
    elif fault == 'duplicate-across-views': value = [value,deepcopy(value)]
    else: value['unknown'] = 'SYNTHETIC_PRIVATE_UNRECOGNIZED'
    with pytest.raises(ValueError,match='unavailable'): project(value)


@pytest.mark.parametrize('fault', ['duplicate-key','escaped-key','duplicate-field','escaped-selector','trailing','oversize'])
def test_private_json_ambiguity_and_bounds_clear_the_entire_input(fault):
    raw = bytearray(json.dumps(envelope(),separators=(',',':')).encode())
    if fault == 'duplicate-key': raw[:] = raw.replace(b'SYNTHETIC_PRIVATE_KEY_BETA',b'SYNTHETIC_PRIVATE_KEY_ALPHA')
    elif fault == 'escaped-key': raw[:] = raw.replace(b'SYNTHETIC_PRIVATE_KEY_ALPHA',b'\\u0053YNTHETIC_PRIVATE_KEY_ALPHA')
    elif fault == 'duplicate-field': raw[:] = raw.replace(b'"type":"mobile"',b'"type":"mobile","type":"hard"')
    elif fault == 'escaped-selector': raw[:] = raw.replace(TOKEN,b'\\u0053'+TOKEN[1:])
    elif fault == 'trailing': raw.extend(b' {}')
    else: raw.extend(b' '*1048576)
    with pytest.raises(ValueError,match='unavailable'):
        project_fortitoken_inventory(raw,expected_serial=SERIAL,source_digest='d'*64,observed_at=1000)
    assert not any(raw)


def candidate(*,guarded=True,source_guarded=True):
    peer = Peer(); peer.payloads[INVENTORY_PATH] = envelope(); source = peer.reader(guarded=source_guarded)
    inventory = FortitokenInventorySource(source,source_digest='d'*64,source_guard=(lambda:True) if guarded else None)
    return peer,source,inventory


def test_fixed_https_read_uses_original_device_tls_and_cleans_before_publishing():
    peer,source,inventory = candidate(); observed = inventory.read()
    assert peer.calls == [INVENTORY_PATH] and observed.type_counts == (1,1,0)
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)
    inventory.close(); assert source.read().state.binding is source._binding
    with pytest.raises(ValueError,match='unavailable'): inventory.read()


@pytest.mark.parametrize('fault', ['inventory-gate','user-source-gate','tls','closed','guard-replaced'])
def test_source_and_separate_inventory_authority_are_default_closed_before_connection(fault):
    peer,source,inventory = candidate(guarded=fault != 'inventory-gate',source_guarded=fault != 'user-source-gate')
    if fault == 'tls': source._tls.check_hostname = False
    elif fault == 'closed': source.close()
    elif fault == 'guard-replaced': inventory._guard = lambda:True
    with pytest.raises(ValueError,match='unavailable'): inventory.read()
    assert peer.calls == []


@pytest.mark.parametrize('fault', ['html','truncated','close','deadline'])
def test_transport_failure_never_publishes_and_clears_buffers(fault):
    peer,source,inventory = candidate(); peer.fault = fault
    with pytest.raises(ValueError,match='unavailable'): inventory.read()
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('fault', ['late-close','revoke-at-close','epoch-rollback','monotonic-rollback'])
def test_final_cleanup_freshness_and_source_checks_precede_observation_publication(fault):
    peer,source,inventory = candidate(); factory = source._factory
    def changed(*args,**kwargs):
        connection = factory(*args,**kwargs); close = connection.close
        def cleanup():
            close()
            if fault == 'late-close': peer.time += 5
            elif fault == 'revoke-at-close': inventory._closed = True
            elif fault == 'epoch-rollback': peer.clock.value = 999
            else: peer.time = 9
        connection.close = cleanup; return connection
    source._factory = changed
    with pytest.raises(ValueError,match='unavailable'): inventory.read()
    assert all(not any(raw) for raw in peer.buffers)
