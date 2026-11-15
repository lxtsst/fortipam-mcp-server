"""Visible private joins from synthetic users/inventory, never global custody."""
import hashlib
import json

import pytest

from fortipam_mcp.fortitoken_binding_source import FortitokenBindingSource, USER_BINDINGS_PATH, project_fortitoken_bindings
from fortipam_mcp.fortitoken_inventory_source import FortitokenInventorySource, INVENTORY_PATH
from test_fortitoken_inventory_source import envelope as inventory_envelope
from test_fortitoken_user_contract import NAME, SERIAL, TOKEN
from test_fortitoken_user_source import Peer


def envelope(peer):
    rows = [dict(name=NAME,**{'two-factor':peer.user['two-factor'],'fortitoken':peer.user['fortitoken'],'q_origin_key':NAME}),
        dict(name='SYNTHETIC_PRIVATE_USER_ALPHA',**{'two-factor':'fortitoken','fortitoken':TOKEN.decode()}),
        dict(name='SYNTHETIC_PRIVATE_USER_BETA',**{'two-factor':'email','fortitoken':'SYNTHETIC_TOKEN_BETA'}),
        dict(name='SYNTHETIC_PRIVATE_USER_UNKNOWN',**{'two-factor':'fortitoken','fortitoken':'SYNTHETIC_TOKEN_OUTSIDE'}),
        dict(name='SYNTHETIC_PRIVATE_USER_EMPTY',**{'two-factor':'fortitoken','fortitoken':''})]
    return dict(build=29,http_method='GET',http_status=200,name='admin',path='system',status='success',version='v7.0.0',
        serial=SERIAL,vdom='root',results=rows,size=len(rows),matched_count=len(rows),limit_reached=False)


def candidate(operation='assign', *, guarded=True, inventory_guarded=True, baseline=True):
    peer = Peer(operation); source = peer.reader(); current = source.read() if baseline else None
    peer.payloads[USER_BINDINGS_PATH] = envelope(peer); peer.payloads[INVENTORY_PATH] = inventory_envelope()
    inventory = FortitokenInventorySource(source,source_digest='d'*64,source_guard=(lambda:True) if inventory_guarded else None)
    bindings = FortitokenBindingSource(inventory,source_digest='e'*64,source_guard=(lambda:True) if guarded else None)
    return peer,source,current,inventory,bindings


def project(peer,current):
    users = bytearray(json.dumps(peer.payloads[USER_BINDINGS_PATH],separators=(',',':')).encode())
    tokens = bytearray(json.dumps(peer.payloads[INVENTORY_PATH],separators=(',',':')).encode())
    try:
        return project_fortitoken_bindings(users,tokens,expected_serial=SERIAL,source_digest='e'*64,
            inventory_source_digest='d'*64,current=current,observed_at=1000)
    finally: assert not any(users) and not any(tokens)


@pytest.mark.parametrize('operation', ['assign','revoke'])
def test_private_join_counts_visible_bindings_without_decoding_or_hashing_response_identities(monkeypatch,operation):
    peer,source,current,inventory,bindings = candidate(operation); decode = json.loads; digest = hashlib.sha256
    def private_bytes(raw): return raw.encode() if isinstance(raw,str) else bytes(raw)
    def checked_decode(raw,*args,**kwargs):
        assert b'SYNTHETIC_PRIVATE' not in private_bytes(raw) and TOKEN not in private_bytes(raw)
        return decode(raw,*args,**kwargs)
    def checked_digest(raw=b'',*args,**kwargs):
        assert b'SYNTHETIC_PRIVATE' not in private_bytes(raw) and TOKEN not in private_bytes(raw)
        return digest(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',checked_decode); monkeypatch.setattr(hashlib,'sha256',checked_digest)
    observed = project(peer,current); public = observed.public(); revoke = operation == 'revoke'
    assert observed.visible_user_count == 5 and observed.fortitoken_mfa_user_count == 3+revoke
    assert observed.nonempty_selector_count == 3+revoke and observed.bindings_to_observed_inventory_count == 2+revoke
    assert observed.unmatched_selector_count == 1 and observed.inventory_tokens_with_multiple_visible_bindings_count == int(revoke)
    assert observed.fortitoken_mfa_without_selector_count == 1 and observed.selector_with_other_mfa_count == 1
    assert observed.source_digest == 'e'*64 and observed.inventory.source_digest == 'd'*64
    assert public['selected_user_mfa_projection_matches_detail'] and public['reported_user_counts_match_rows']
    assert not public['product_actor_verified'] and not public['global_unassigned_ownership_verified']
    assert not public['atomic_snapshot_qualified'] and not public['exact_selected_selector_continuity_verified']
    assert not public['configuration_write_authorized'] and not public['mfa_login_verified']
    text = json.dumps((public,observed.inventory.public()))
    for value in (NAME,SERIAL,TOKEN.decode(),'SYNTHETIC_PRIVATE','d'*64,'e'*64): assert value not in text


@pytest.mark.parametrize('fault', ['serial','version','build','method','route','status','http','error','vdom',
    'size-missing','matched-missing','count-mismatch','count-bool','truncated','next','rows-limit',
    'rows-object','empty','unknown-envelope','unexpected-material','missing-selector','selector-number',
    'selector-space','name-number','name-escaped','mfa-shape','duplicate-name','origin','selected-missing',
    'selected-mfa-drift','selected-presence-drift','inventory-device','inventory-truncated'])
def test_ambiguous_or_drifting_views_refuse_and_clear_both_private_responses(fault):
    peer,source,current,inventory,bindings = candidate(); users = peer.payloads[USER_BINDINGS_PATH]; row = users['results'][0]
    if fault == 'serial': users['serial'] = 'OTHER'
    elif fault == 'version': users['version'] = 'v1.9.1'
    elif fault == 'build': users['build'] = True
    elif fault == 'method': users['http_method'] = 'POST'
    elif fault == 'route': users['path'] = 'user'
    elif fault == 'status': users['status'] = 'error'
    elif fault == 'http': users['http_status'] = 201
    elif fault == 'error': users['error'] = -1
    elif fault == 'vdom': users['vdom'] = 'other'
    elif fault == 'size-missing': del users['size']
    elif fault == 'matched-missing': del users['matched_count']
    elif fault == 'count-mismatch': users['size'] += 1
    elif fault == 'count-bool': users['size'] = True
    elif fault == 'truncated': users['limit_reached'] = True
    elif fault == 'next': users['next_idx'] = 1
    elif fault == 'rows-limit': users['results'] *= 52
    elif fault == 'rows-object': users['results'] = {}
    elif fault == 'empty': users.update(results=[],size=0,matched_count=0)
    elif fault == 'unknown-envelope': users['unexpected'] = 'SYNTHETIC_PRIVATE'
    elif fault == 'unexpected-material': row['password'] = 'SYNTHETIC_PRIVATE_PASSWORD'
    elif fault == 'missing-selector': del row['fortitoken']
    elif fault == 'selector-number': row['fortitoken'] = 123
    elif fault == 'selector-space': row['fortitoken'] = 'SYNTHETIC TOKEN'
    elif fault == 'name-number': row['name'] = 123
    elif fault == 'name-escaped': users['results'][1]['name'] += '\\private'
    elif fault == 'mfa-shape': row['two-factor'] = {}
    elif fault == 'duplicate-name': users['results'][1]['name'] = row['name']
    elif fault == 'origin': row['q_origin_key'] = 'OTHER'
    elif fault == 'selected-missing': row.update(name='OTHER',q_origin_key='OTHER')
    elif fault == 'selected-mfa-drift': row['two-factor'] = 'fortitoken'
    elif fault == 'selected-presence-drift': row['fortitoken'] = TOKEN.decode()
    elif fault == 'inventory-device': peer.payloads[INVENTORY_PATH]['serial'] = 'OTHER'
    else: peer.payloads[INVENTORY_PATH]['limit_reached'] = True
    with pytest.raises(ValueError,match='unavailable'): project(peer,current)


def test_missing_truncation_disclosure_is_preserved_without_qualifying_actor_or_global_view():
    peer,source,current,inventory,bindings = candidate(); del peer.payloads[USER_BINDINGS_PATH]['limit_reached']
    observed = project(peer,current); assert not observed.no_truncation_reported
    assert not observed.public()['product_actor_verified'] and not observed.public()['global_unassigned_ownership_verified']


def test_same_mfa_and_presence_do_not_prove_exact_selected_selector_continuity():
    peer,source,current,inventory,bindings = candidate('revoke')
    peer.payloads[USER_BINDINGS_PATH]['results'][0]['fortitoken'] = 'SYNTHETIC_TOKEN_BETA'
    observed = project(peer,current); public = observed.public()
    assert public['selected_user_mfa_projection_matches_detail']
    assert not public['exact_selected_selector_continuity_verified'] and not public['atomic_snapshot_qualified']
    assert not public['global_unassigned_ownership_verified'] and not public['configuration_write_authorized']


def test_actual_two_fixed_reads_join_under_same_source_and_do_not_keep_material():
    peer,source,current,inventory,bindings = candidate(); observed = bindings.read()
    assert peer.calls[-2:] == [USER_BINDINGS_PATH,INVENTORY_PATH] and observed.visible_user_count == 5
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)
    bindings.close(); assert inventory.read().public()['token_count'] == 2
    with pytest.raises(ValueError,match='unavailable'): bindings.read()


@pytest.mark.parametrize('fault', ['guard','inventory-guard','baseline-missing','baseline-expired','closed','replaced-guard'])
def test_separate_gates_and_fresh_physical_detail_precede_any_binding_requests(fault):
    peer,source,current,inventory,bindings = candidate(guarded=fault != 'guard',inventory_guarded=fault != 'inventory-guard',
        baseline=fault != 'baseline-missing'); count = len(peer.calls)
    if fault == 'baseline-expired': peer.clock.value = 1010
    elif fault == 'closed': source.close()
    elif fault == 'replaced-guard': bindings._guard = lambda:True
    with pytest.raises(ValueError,match='unavailable'): bindings.read()
    assert len(peer.calls) == count


@pytest.mark.parametrize('fault', ['html','truncated','close','deadline','between-reads','after-cleanup','epoch','baseline-replaced'])
def test_both_raw_buffers_clear_when_transport_authority_or_total_freshness_fails(fault):
    peer,source,current,inventory,bindings = candidate(); factory = source._factory
    if fault in ('html','truncated','close','deadline'): peer.fault = fault
    else:
        def changed(*args,**kwargs):
            connection = factory(*args,**kwargs); close = connection.close
            def cleanup():
                close()
                if fault == 'between-reads': inventory._closed = True
                elif fault == 'after-cleanup': peer.time += 3
                elif fault == 'epoch': peer.clock.value = 1010
                else: source._latest = None
            connection.close = cleanup; return connection
        source._factory = changed
    with pytest.raises(ValueError,match='unavailable'): bindings.read()
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('fault', ['duplicate-selector-field','escaped-selector','trailing','oversize'])
def test_json_ambiguity_or_bound_failure_discards_both_inputs(fault):
    peer,source,current,inventory,bindings = candidate('revoke')
    users = bytearray(json.dumps(peer.payloads[USER_BINDINGS_PATH],separators=(',',':')).encode())
    tokens = bytearray(json.dumps(peer.payloads[INVENTORY_PATH]).encode())
    if fault == 'duplicate-selector-field': users[:] = users.replace(b'"fortitoken":"'+TOKEN+b'"',b'"fortitoken":"'+TOKEN+b'","fortitoken":""',1)
    elif fault == 'escaped-selector': users[:] = users.replace(TOKEN,b'\\u0053'+TOKEN[1:],1)
    elif fault == 'trailing': users.extend(b' {}')
    else: users.extend(b' '*524288)
    with pytest.raises(ValueError,match='unavailable'):
        project_fortitoken_bindings(users,tokens,expected_serial=SERIAL,source_digest='e'*64,
            inventory_source_digest='d'*64,current=current,observed_at=1000)
    assert not any(users) and not any(tokens)
