"""Fixed compound GETs with synthetic records; no native configuration or mail."""
from dataclasses import replace
import hashlib
import json

import pytest

from fortipam_mcp.email_alert_compound_contract import (EmailAlertCompoundPlan,_TABLES,
    email_alert_frame_schema_digest)
from fortipam_mcp.email_alert_compound_source import EmailAlertCompoundSource,DETAILS,KINDS,SCHEMA_PATHS
from test_email_alert_compound_contract import fixture,STEPS
from test_email_alert_general_source import candidate as general_candidate,SCHEMA_PATH,CURRENT_PATH
from test_email_alert_general_contract import SERIAL,SENDER,RECIPIENT,PRIVATE,envelope


def load_state(peer,state):
    peer.payloads[CURRENT_PATH] = envelope(json.loads(state.general._encoded))
    for kind,slot,path in DETAILS:
        frame = state.settings if kind == 'settings' else next(frame for frame in
            getattr(state,'stitches' if kind == 'stitch' else kind+'s') if frame.slot == slot)
        native_path,table = _TABLES[kind]
        peer.payloads[path] = dict(build=29,http_method='GET',http_status=200,name=table,path=native_path,status='success',
            version='v7.0.0',serial=SERIAL,vdom='root',results=json.loads(frame._encoded))


def candidate(*,guarded=True):
    peer,general,_,_ = general_candidate(); state = fixture(); pins = {}
    load_state(peer,state)
    for kind in KINDS:
        frame = state.settings if kind == 'settings' else getattr(state,'stitches' if kind == 'stitch' else kind+'s')[0]
        path,table = _TABLES[kind]
        schema = dict(build=29,http_method='GET',http_status=200,name=table,path=path,status='success',
            version='v7.0.0',serial=SERIAL,action='schema',results={'children':json.loads(frame._specs)})
        for spec in schema['results']['children'].values(): spec.update(default=PRIVATE,help=PRIVATE)
        peer.payloads[SCHEMA_PATHS[kind]] = schema
        pins[kind] = email_alert_frame_schema_digest(schema,kind,expected_serial=SERIAL)
    source = EmailAlertCompoundSource(general,expected_schema_digests=pins,source_digest='b'*64,
        source_guard=(lambda:True) if guarded else None)
    return peer,source,state


EXPECTED = [('GET',SCHEMA_PATH),('GET',CURRENT_PATH),*[('GET',SCHEMA_PATHS[kind]) for kind in KINDS],
    *[('GET',path) for _,_,path in DETAILS]]


def test_fixed_sixteen_gets_project_no_schema_defaults_and_clear_before_publication(monkeypatch):
    peer,source,state = candidate(); decode,digest = json.loads,hashlib.sha256
    def checked_decode(raw,*args,**kwargs):
        assert PRIVATE.encode() not in (raw.encode() if isinstance(raw,str) else raw)
        return decode(raw,*args,**kwargs)
    def checked_digest(raw=b'',*args,**kwargs):
        assert PRIVATE.encode() not in raw
        return digest(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',checked_decode); monkeypatch.setattr(hashlib,'sha256',checked_digest)
    observed = source.read()
    assert observed.state.digest == state.digest and observed.general is source._general._latest
    assert peer.calls == EXPECTED and observed.expires_at == 1010
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)


def test_each_forward_draft_uses_original_physical_plan_and_complete_fresh_prefix():
    peer,source,state = candidate(); plan = source.prepare_plan()
    for index,step in enumerate(STEPS):
        load_state(peer,plan.expected(index)); body = source.compile(plan,step)
        try: assert json.loads(body)
        finally: body[:] = b'\0'*len(body)
    assert peer.calls == EXPECTED*9
    with pytest.raises(ValueError,match='unavailable'): source.compile(replace(plan),'certificate')
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('kind',KINDS)
@pytest.mark.parametrize('fault',['pin','identity','material'])
def test_schema_mismatch_rejects_before_any_critical_or_certificate_current(kind,fault):
    peer,source,state = candidate(); schema = peer.payloads[SCHEMA_PATHS[kind]]
    if fault == 'pin': schema['results']['children']['unrelated-new'] = dict(type='integer')
    elif fault == 'identity': schema['serial'] = 'FOREIGN_SERIAL'
    else: schema['results']['children']['hidden-password'] = dict(type='password-2',default=PRIVATE)
    with pytest.raises(ValueError,match='unavailable'): source.read()
    assert peer.calls == EXPECTED[:3+KINDS.index(kind)] and source._latest is None
    assert all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('fault',['html','truncated','close','deadline','missing','wrong-trigger','foreign-detail','nested-scalar'])
def test_read_failure_clears_all_owned_buffers_and_does_not_publish(fault):
    peer,source,state = candidate()
    if fault in ('html','truncated','close','deadline'): peer.fault = fault
    elif fault == 'missing': peer.payloads[DETAILS[0][2]].update(http_status=404,status='error',results=None)
    elif fault == 'wrong-trigger': peer.payloads[DETAILS[5][2]]['results']['trigger'] = 'Glass Breaking Activated'
    elif fault == 'foreign-detail': peer.payloads[DETAILS[0][2]]['mkey'] = 'FOREIGN'
    else: peer.payloads[DETAILS[0][2]]['results']['unrelated'] = dict(password=PRIVATE)
    with pytest.raises(ValueError,match='unavailable'): source.read()
    assert source._latest is None and all(resource.closed for resource in peer.resources)
    assert all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('fault',['guard','closed','source','schema','general','clock','epoch'])
def test_authority_source_physical_binding_and_time_fail_before_network(fault):
    peer,source,state = candidate(guarded=fault != 'guard')
    if fault == 'closed': source.close()
    elif fault == 'source': source._source = 'f'*64
    elif fault == 'schema': source._schema_pins['settings'] = 'f'*64
    elif fault == 'general': source._general = general_candidate()[1]
    elif fault in ('clock','epoch'):
        source.read(); peer.calls.clear()
        if fault == 'clock': peer.time -= 1
        else: peer.clock.value -= 1
    with pytest.raises(ValueError,match='unavailable'): source.read()
    assert peer.calls == []


@pytest.mark.parametrize('fault',['drift','wrong-prefix','expired','foreign','superseded','guard-after-read'])
def test_stale_unowned_or_drifted_plan_never_produces_a_private_body(fault):
    peer,source,state = candidate(); plan = source.prepare_plan()
    if fault == 'drift': peer.payloads[DETAILS[-1][2]]['results']['unrelated-global'] = 'drift'
    elif fault == 'wrong-prefix': load_state(peer,plan.expected(2))
    elif fault == 'expired': peer.clock.value = 1010
    elif fault == 'foreign': plan = candidate()[1].prepare_plan()
    elif fault == 'superseded': source.prepare_plan()
    else:
        fetch = source._fetch
        def revoked(*args,**kwargs):
            raw = fetch(*args,**kwargs); source._closed = True; return raw
        source._fetch = revoked
    with pytest.raises(ValueError,match='unavailable'): source.compile(plan,'general')
    assert all(not any(raw) for raw in peer.buffers)


def test_sixteen_reads_and_plan_derivation_share_a_single_total_deadline():
    peer,source,state = candidate(); factory = source._general._factory
    def delayed(*args,**kwargs):
        connection = factory(*args,**kwargs); connect = connection.connect
        def connected(): connect(); peer.time += .34
        connection.connect = connected; return connection
    source._general._factory = delayed
    with pytest.raises(ValueError,match='unavailable'): source.prepare_plan()
    assert len(peer.calls) < 16 and source._latest is None and source._plan is None
    assert all(not any(raw) for raw in peer.buffers)


def test_revocation_during_tls_connect_prevents_the_supplementary_get():
    peer,source,state = candidate(); factory = source._general._factory
    def revoked(*args,**kwargs):
        connection = factory(*args,**kwargs); connect = connection.connect
        def connected(): connect(); source._closed = True
        connection.connect = connected; return connection
    source._general._factory = revoked
    with pytest.raises(ValueError): source._fetch(SCHEMA_PATHS['settings'],15)
    assert peer.calls == [] and all(resource.closed for resource in peer.resources)


def test_exact_allowed_paths_noop_and_preview_have_no_dispatch_or_recovery_custody():
    peer,source,state = candidate()
    with pytest.raises(ValueError): source._fetch('/api/v2/cmdb/system/global',15)
    assert peer.calls == []
    public = source.preview(); text = json.dumps(public)
    assert public['existing_graph_observed_locally'] and public['schema_pins_matched_locally'] and public['fixed_get_count'] == 16
    assert not public['configuration_written'] and not public['mail_contacted'] and not public['atomic_snapshot_verified']
    assert not public['execution_authorized'] and not public['native_put_qualified'] and not public['independent_recovery_verified']
    assert all(marker not in text for marker in (SERIAL,SENDER,RECIPIENT,PRIVATE,'old.cert','Original glass'))
    plan = EmailAlertCompoundPlan(state,source._general._scope); load_state(peer,plan.expected())
    with pytest.raises(ValueError,match='unavailable'): source.prepare_plan()
