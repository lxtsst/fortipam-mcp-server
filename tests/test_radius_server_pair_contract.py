"""Paired private wire, independent material buffers and complete-state denials."""
from __future__ import annotations

import copy
import json
import pickle
from typing import Any

import pytest

from fortipam_mcp import radius_server_pair_contract as pair
from fortipam_mcp.radius_server_contract import RadiusServerCandidateError, RadiusServerCreateBinding, qualify_radius_created_state
from fortipam_mcp.radius_server_owned_connect_contract import RadiusOwnedConnectError, owned_connect_body
from fortipam_mcp.radius_server_projection import RadiusServerProjectionError, project_radius_defaults, project_radius_detail
from v4_planning.material_provider import MaterialAccessDenied
from test_radius_server_projection import SERIAL, default_row, encoded, envelope, schema


def binding() -> pair.RadiusServerPairBinding:
    return pair.RadiusServerPairBinding('mcp-v4-radius-synthetic','192.0.2.10','192.0.2.11','a'*64)


def view(value: bytes) -> memoryview:
    return memoryview(bytearray(value)).toreadonly()


def test_binding_keeps_both_addresses_and_mode_in_immutable_opaque_intent() -> None:
    b=binding()
    for operation in (copy.copy,copy.deepcopy,pickle.dumps):
        with pytest.raises(MaterialAccessDenied):operation(b)
    with pytest.raises(TypeError):json.dumps(b)
    with pytest.raises(pair.RadiusServerPairError):b.secondary_server='192.0.2.12'
    with pytest.raises(pair.RadiusServerPairError):del b.server
    assert b.server not in repr(b) and b.secondary_server not in repr(b)
    assert b.parameters_digest!=RadiusServerCreateBinding(b.name,b.server,b.private_nonce).parameters_digest
    reverse=pair.RadiusServerPairBinding(b.name,b.secondary_server,b.server,b.private_nonce)
    assert reverse.parameters_digest!=b.parameters_digest
    with pytest.raises(RadiusOwnedConnectError):owned_connect_body(b)  # type: ignore[arg-type]


@pytest.mark.parametrize('secondary',['192.0.2.10','127.0.0.1','8.8.8.8','169.254.1.1','0.0.0.0',
    '224.0.0.1','::1','192.0.2.011','example.test',None])
def test_binding_rejects_shared_or_unqualified_secondary(secondary: Any) -> None:
    with pytest.raises(pair.RadiusServerPairError):
        pair.RadiusServerPairBinding('mcp-v4-radius-synthetic','192.0.2.10',secondary,'a'*64)


def test_native_pair_body_and_saved_test_routes_do_not_swap_material_or_ordinals() -> None:
    b=binding();p=view(b'A'*32);s=view(b'B'*32)
    body=pair.pair_create_body(b,p,s)
    assert json.loads(body)=={'name':b.name,'$originalName':'','auth-type':'auto','server':b.server,
        'secret':'A'*32,'secondary-server':b.secondary_server,'secondary-secret':'B'*32}
    for ordinal,address in (('primary',b.server),('secondary',b.secondary_server)):
        assert json.loads(pair.pair_owned_connect_body(b,ordinal))=={
            'mkey':b.name,'server':address,'auth_type':'auto','ordinal':ordinal}
    assert bytes(p)==b'A'*32 and bytes(s)==b'B'*32


@pytest.mark.parametrize('fault',['same_value','shared_buffer','writable','immutable_backing','short',
    'invalid_byte','strided','released','non_view'])
def test_material_inputs_require_two_distinct_zeroizable_readonly_leases(fault: str) -> None:
    p=view(b'A'*32);s: Any=view(b'B'*32)
    if fault=='same_value':s=view(b'A'*32)
    elif fault=='shared_buffer':
        backing=memoryview(bytearray(b'A'*32+b'B'*32)).toreadonly();p,s=backing[:32],backing[32:]
    elif fault=='writable':s=memoryview(bytearray(b'B'*32))
    elif fault=='immutable_backing':s=memoryview(b'B'*32)
    elif fault=='short':s=view(b'B'*31)
    elif fault=='invalid_byte':s=view(b'B'*31+b'!')
    elif fault=='strided':s=view(b'B'*64)[::2]
    elif fault=='released':s.release()
    else:s=b'B'*32
    with pytest.raises(pair.RadiusServerPairError) as error:pair.pair_create_body(binding(),p,s)
    assert str(error.value)=='The private paired RADIUS prerequisite is unavailable.'


def test_partial_wire_is_cleared_if_second_append_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    captured=[];original=pair._append_material
    def fail(target, value: memoryview) -> None:
        original(target,value);captured.append(target._storage)
        if len(captured)==2:raise ValueError('SYNTHETIC_PRIVATE')
    monkeypatch.setattr(pair,'_append_material',fail)
    with pytest.raises(pair.RadiusServerPairError) as error:pair.pair_create_body(binding(),view(b'A'*32),view(b'B'*32))
    assert len(captured)==2 and all(not any(b) for b in captured)
    assert 'SYNTHETIC_PRIVATE' not in str(error.value)


@pytest.mark.parametrize('fault',[None,'secondary_default','primary_default','wrong_secondary','other_scalar',
    'third_server','other_opaque','reference','bool_reference','origin','serial'])
def test_pair_readback_requires_both_stored_tokens_and_all_other_defaults(fault: str | None) -> None:
    b=binding();shape=schema()
    defaults=project_radius_defaults(encoded(envelope(action='default',results=default_row())),shape,expected_serial=SERIAL)
    row=default_row()|b.desired_nonmaterial()|{'secret':'SYNTHETIC_PRIMARY_OPAQUE',
        'secondary-secret':'SYNTHETIC_SECONDARY_OPAQUE','q_ref':0}
    if fault=='secondary_default':row['secondary-secret']=default_row()['secondary-secret']
    elif fault=='primary_default':row['secret']=default_row()['secret']
    elif fault=='wrong_secondary':row['secondary-server']=b.server
    elif fault=='other_scalar':row['timeout']=99
    elif fault=='third_server':row['tertiary-server']='192.0.2.12'
    elif fault=='other_opaque':row['tertiary-secret']='SYNTHETIC_OTHER_OPAQUE'
    elif fault=='reference':row['q_ref']=1
    elif fault=='bool_reference':row['q_ref']=False
    elif fault=='origin':row['q_origin_key']='OTHER'
    if fault in {'bool_reference','origin'}:
        with pytest.raises(RadiusServerProjectionError):
            project_radius_detail(encoded(envelope(results=[row])),shape,expected_serial=SERIAL)
        return
    state=project_radius_detail(encoded(envelope(results=[row])),shape,expected_serial=SERIAL)
    if fault is None:
        pair.qualify_radius_pair_created_state(state,defaults,shape,b,expected_serial=SERIAL)
        with pytest.raises(RadiusServerCandidateError):qualify_radius_created_state(state,defaults,shape,b,expected_serial=SERIAL)  # type: ignore[arg-type]
    else:
        with pytest.raises(pair.RadiusServerPairError):
            pair.qualify_radius_pair_created_state(state,defaults,shape,b,
                expected_serial='OTHER' if fault=='serial' else SERIAL)
