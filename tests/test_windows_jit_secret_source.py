"""Seven fixed reads with synthetic metadata, opaque slots and no custody."""
from dataclasses import replace
import hashlib
import json

import pytest

from fortipam_mcp.windows_jit_secret_contract import _schema, _types
from fortipam_mcp.windows_jit_secret_source import WindowsJitSecretSource, SCHEMA_PATH
from test_windows_jit_script_source import Peer, SERIAL, PRIVATE
from test_windows_jit_secret_contract import fixture, binding, envelope, SECRET
from v4_planning import canonical_digest


def candidate(*,present=2,guarded=True):
    peer = Peer(present); scripts = peer.source(); schema,row = fixture()
    peer.payloads[SCHEMA_PATH] = schema
    secret = WindowsJitSecretSource(scripts,binding(),expected_schema_digest=canonical_digest(_types(_schema(schema,SERIAL))),
        source_digest='b'*64,source_guard=(lambda:True) if guarded else None)
    peer.payloads[secret._detail] = envelope(row)
    return peer,scripts,secret,schema,row


def test_actual_seven_read_join_excludes_slot_totp_and_schema_default_material(monkeypatch):
    peer,scripts,source,schema,row = candidate(); schema['results']['children']['description']['default'] = SECRET
    decode = json.loads; digest = hashlib.sha256
    def checked_decode(raw,*args,**kwargs):
        value = raw.encode() if isinstance(raw,str) else raw
        assert SECRET.encode() not in value and PRIVATE not in value
        return decode(raw,*args,**kwargs)
    def checked_digest(raw=b'',*args,**kwargs):
        assert SECRET.encode() not in raw and PRIVATE not in raw
        return digest(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',checked_decode); monkeypatch.setattr(hashlib,'sha256',checked_digest)
    observed = source.read()
    assert len(peer.calls) == 7 and peer.calls[-2:] == [('GET',SCHEMA_PATH),('GET',source._detail)]
    assert observed.scripts.present == (True,True) and observed.secret.binding is source._binding
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)
    source.close(); assert scripts.read().present == (True,True)


@pytest.mark.parametrize('fault', ['secret-gate','script-gate','absent-pair','schema-pin','schema-device','detail-device',
    'missing-field','unsafe-account','already-applied'])
def test_wrong_source_scope_or_configuration_cannot_produce_a_new_draft(fault):
    peer,scripts,source,schema,row = candidate(present=0 if fault == 'absent-pair' else 2,guarded=fault != 'secret-gate')
    if fault == 'script-gate': scripts._closed = True
    elif fault == 'schema-pin': schema['results']['children']['description']['type'] = 'var-string'
    elif fault == 'schema-device': schema['serial'] = 'OTHER'
    elif fault == 'detail-device': peer.payloads[source._detail]['serial'] = 'OTHER'
    elif fault == 'missing-field': del row['unrelated-option']
    elif fault == 'unsafe-account': row['target-info']['priv_acct'] = 99
    elif fault == 'already-applied':
        row['checkout'] = 'enable'; row['permissions'].update(checkout_status='required',passwd_change='forbidden')
    with pytest.raises(ValueError,match='unavailable'): source.prepare_plan()
    if fault in ('secret-gate','script-gate'): assert peer.calls == []
    elif fault == 'absent-pair': assert len(peer.calls) == 5
    elif fault in ('schema-pin','schema-device'): assert len(peer.calls) == 6
    assert source._plan is None and all(not any(raw) for raw in peer.buffers)


def test_physical_plan_rechecks_script_and_full_nonmaterial_state_without_inverse_authority():
    peer,scripts,source,schema,row = candidate(); plan = source.prepare_plan(); observed = source.read()
    patch = source.compile_fragment(plan)
    assert patch['checkout'] == 'enable' and patch['checkout-duration'] == 5 and len(peer.calls) == 21
    assert source._plan is plan and source._plan_origin is not observed
    with pytest.raises(ValueError,match='unavailable'): source.compile_fragment(replace(plan))
    row['unrelated-option'] = 'changed'
    with pytest.raises(ValueError,match='unavailable'): source.compile_fragment(plan)
    assert all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('fault', ['cloned','foreign','expired','script-reference','superseded'])
def test_stale_foreign_or_changed_script_plan_cannot_compile_fragment(fault):
    peer,scripts,source,schema,row = candidate(); plan = source.prepare_plan()
    if fault == 'cloned': plan = replace(plan)
    elif fault == 'foreign': plan = candidate()[2].prepare_plan()
    elif fault == 'expired': peer.clock.value = 1010
    elif fault == 'superseded': source.prepare_plan()
    else:
        peer.rows[1]['q_ref'] = 1; peer.payloads[peer.details[0]]['results']['q_ref'] = 1
    with pytest.raises(ValueError,match='unavailable'): source.compile_fragment(plan)


@pytest.mark.parametrize('fault', ['total-deadline','final-epoch','revoked-at-cleanup'])
def test_one_deadline_and_freshness_cover_nested_script_reads_and_secret_cleanup(fault):
    peer,scripts,source,schema,row = candidate(); factory = scripts._factory
    def changed(*args,**kwargs):
        connection = factory(*args,**kwargs); connect,close = connection.connect,connection.close
        def delayed():
            connect()
            if fault == 'total-deadline': peer.time += 0.8
        def cleanup():
            close()
            if connection.path == source._detail:
                if fault == 'final-epoch': peer.clock.value = 1010
                elif fault == 'revoked-at-cleanup': source._closed = True
        connection.connect,connection.close = delayed,cleanup; return connection
    scripts._factory = changed
    with pytest.raises(ValueError,match='unavailable'): source.read()
    assert source._latest is None and scripts._deadline_cap is None
    if fault == 'total-deadline': assert len(peer.calls) == 6
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)


def test_preview_retains_all_authority_effect_and_material_gaps():
    peer,scripts,source,schema,row = candidate(); public = source.preview(); text = json.dumps(public)
    assert public['script_definitions_read_locally'] and public['nonmaterial_configuration_observed_locally']
    assert public['metadata_patch_only'] and not public['execution_authorized'] and not public['configuration_ready']
    assert not public['material_preservation_qualified'] and not public['original_subject_custody_verified']
    for value in (SECRET,PRIVATE.decode(),SERIAL,binding().nonce,binding().secret_uuid,'$USER'): assert value not in text


def test_private_fragment_publication_also_stays_inside_the_seven_read_budget(monkeypatch):
    from fortipam_mcp.windows_jit_secret_contract import WindowsJitSecretPlan
    peer,scripts,source,schema,row = candidate(); plan = source.prepare_plan()
    compile_patch = WindowsJitSecretPlan.compile_metadata_patch
    def delayed(*args,**kwargs):
        result = compile_patch(*args,**kwargs); peer.time += 5; return result
    monkeypatch.setattr(WindowsJitSecretPlan,'compile_metadata_patch',delayed)
    with pytest.raises(ValueError,match='unavailable'): source.compile_fragment(plan)
    assert scripts._deadline_cap is None and all(not any(raw) for raw in peer.buffers)
