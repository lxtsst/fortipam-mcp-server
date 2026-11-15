"""Original-account Tag reads use its own session and an independent Owner graph."""
import pytest
from v4_planning import M4AuthorizationDenied

from fortipam_mcp.ems_tag_account_tag_read import EmsAccountTagReadProbe
from fortipam_mcp.ems_tag_authority import EmsTagCreateAuthority
from fortipam_mcp.ems_tag_contract import DisabledLinuxProcessTag
from fortipam_mcp.ems_tag_http_transport import NativeEmsTagHttpTransport, EmsTagHttpError
from fortipam_mcp.ems_tag_sources import CATALOG_PATH
from test_ems_tag_account_authentication import setup, channel as account_channel, finish
from test_ems_tag_http_transport import make as base_http, reply
from test_ems_tag_contract import catalog, full_scope
from test_ems_tag_sources import Channel


def make(root, monkeypatch, *, fault=None, enabled=True):
    env, original, owner, enrollment = setup(root, monkeypatch)
    wire=Channel();reference=owner['transport'];owner_connections=[]
    owner['data']['metadata']['consts']['ComplianceVerification']=wire.metadata['data']['consts']['ComplianceVerification']
    owner['data']['metadata']['consts']['System']['MATCH_TYPE']={'Simple':1}
    owner_connect=reference._connect
    def owner_connection():
        connection=owner_connect();owner_connections.append(connection);response=connection.getresponse
        def getresponse():
            if connection.path==CATALOG_PATH or connection.path.startswith('/api/v1/tags/zero_trust/'):
                return reply(wire.get(connection.path))
            return response()
        connection.getresponse=getresponse;return connection
    monkeypatch.setattr(reference,'_connect',owner_connection)
    tags=reference.make_readonly_tag_reference(DisabledLinuxProcessTag('d'*32),source_key=b'u'*32,reference_enabled=True)
    tags._clock=lambda:owner['now'][0]
    transport, connections=account_channel(root/'account-tags',monkeypatch,env,owner)
    old_connect=transport._connect
    def connect():
        connection=old_connect();response=connection.getresponse
        def getresponse():
            path=connection.path
            if path==CATALOG_PATH or path.startswith('/api/v1/tags/zero_trust/'):
                if fault=='denied':return reply({'result':{'retval':0,'message':None}},status=403)
                if fault=='subset' and path==CATALOG_PATH:return reply(catalog())
                if fault=='owner_drift':wire.scope=full_scope(prior_change=True)
                if fault=='expiry':owner['now'][0]+=60
                return reply(wire.get(path))
            return response()
        connection.getresponse=getresponse;return connection
    monkeypatch.setattr(transport,'_connect',connect)
    probe=EmsAccountTagReadProbe(enrollment,original,transport,tags,execution_enabled=enabled)
    return dict(env=env,original=original,owner=owner,enrollment=enrollment,reference=reference,tags=tags,
        transport=transport,connections=connections,owner_connections=owner_connections,probe=probe)


def close(h):
    h['tags'].close();assert h['reference'].close().next_session_check_401
    finish(h['env'],h['original'],h['owner'],h['enrollment'])


def test_complete_original_account_read_matches_owner_and_never_becomes_mutable_admission(tmp_path,monkeypatch):
    h=make(tmp_path,monkeypatch);proof=h['probe'].run_once()
    assert proof.actor_verified and proof.account_scope_parsed and proof.account_scope_matches_owner
    assert proof.owner_scope_unchanged and proof.complete_read_qualified and proof.own_session_closed
    assert proof.backend_http_status==200 and h['env']['h'].loads==2
    assert h['reference'] is h['owner']['transport']
    assert h['reference']._counts['/api/v1/auth/signin']==1
    assert all(c.closed and not c.body for c in h['connections'])
    assert all(c.method in ('GET','POST') and (c.method!='POST' or '/auth/' in c.path) for c in h['connections'])
    with pytest.raises(M4AuthorizationDenied):EmsTagCreateAuthority(proof,authority_key=b'a'*32,
        environment_ref='ems-home-lab',scope_ref='ems-test-scope',audience_ref='ems-test-audience',
        requester_digest='1'*64,transport_digest='2'*64)
    count=len(h['connections'])
    with pytest.raises(ValueError):h['probe'].run_once()
    assert len(h['connections'])==count and h['env']['h'].loads==2
    # A fresh probe instance cannot reset the original-object purpose reservation.
    other, other_connections=account_channel(tmp_path/'second-reader',monkeypatch,h['env'],h['owner'])
    with pytest.raises(ValueError):EmsAccountTagReadProbe(h['enrollment'],h['original'],other,h['tags'],execution_enabled=True).run_once()
    assert not other_connections and h['env']['h'].loads==2;close(h)


@pytest.mark.parametrize('fault,status,parsed',[('denied',403,False),('subset',200,True)])
def test_denial_or_filtered_graph_is_evidence_but_never_complete_read_admission(tmp_path,monkeypatch,fault,status,parsed):
    h=make(tmp_path,monkeypatch,fault=fault);proof=h['probe'].run_once()
    assert proof.actor_verified and proof.backend_http_status==status and proof.account_scope_parsed is parsed
    assert not proof.account_scope_matches_owner and not proof.complete_read_qualified
    assert proof.owner_scope_unchanged and proof.own_session_closed
    assert h['transport']._closure.next_session_check_401;close(h)


@pytest.mark.parametrize('fault',['owner_drift','expiry'])
def test_drift_or_expiry_cannot_qualify_and_always_closes_account_session(tmp_path,monkeypatch,fault):
    h=make(tmp_path,monkeypatch,fault=fault)
    with pytest.raises(ValueError):h['probe'].run_once()
    assert h['transport']._closed and not list(h['transport']._jar)
    assert all(c.closed and not c.body for c in h['connections']);close(h)


def test_closed_read_gate_never_loads_or_opens_account_session(tmp_path,monkeypatch):
    h=make(tmp_path,monkeypatch,enabled=False)
    with pytest.raises(ValueError):h['probe'].run_once()
    assert not h['connections'] and h['env']['h'].loads==1;close(h)


def test_detached_reference_or_existing_super_session_cannot_substitute_for_account(tmp_path,monkeypatch):
    h=make(tmp_path,monkeypatch)
    with pytest.raises(ValueError):EmsAccountTagReadProbe(h['enrollment'],h['original'],h['reference'],h['tags'],execution_enabled=True)
    original=h['tags']._get;h['tags']._get=lambda _:None
    with pytest.raises(ValueError):h['probe'].run_once()
    assert not h['connections'] and h['env']['h'].loads==1
    h['tags']._get=original;close(h)


def test_reference_default_gate_and_distinct_owner_session_do_not_admit_account_reads(tmp_path,monkeypatch):
    h=make(tmp_path,monkeypatch)
    folder=tmp_path/'other-owner';folder.mkdir(mode=0o700)
    other,_,connections,_,_,_=base_http(folder,monkeypatch);other.authenticate()
    tags=other.make_sources(DisabledLinuxProcessTag('e'*32),source_key=b'v'*32)
    with pytest.raises(ValueError):EmsAccountTagReadProbe(h['enrollment'],h['original'],h['transport'],tags,execution_enabled=True)
    with pytest.raises(EmsTagHttpError):h['reference'].make_readonly_tag_reference(DisabledLinuxProcessTag('e'*32),source_key=b'v'*32)
    assert not h['connections'] and h['env']['h'].loads==1
    tags.close();assert other.close().next_session_check_401;assert all(c.closed for c in connections);close(h)


@pytest.mark.parametrize('method,path',[('GET','/api/v1/tags/zero_trust/999/get'),('GET',CATALOG_PATH+'&filter=anything'),
    ('POST','/api/v1/tags/zero_trust/create'),('DELETE','/api/v1/admins/19/delete')])
def test_opt_in_reference_still_denies_unselected_modified_or_configuration_routes(tmp_path,monkeypatch,method,path):
    h=make(tmp_path,monkeypatch);before=len(h['owner_connections'])
    with pytest.raises(EmsTagHttpError):h['reference']._request(method,path)
    assert len(h['owner_connections'])==before and not h['owner']['writes'];close(h)


@pytest.mark.parametrize('fault',['owner_cookie','closed_reference'])
def test_changed_owner_session_or_closed_reference_refuses_before_account_material(tmp_path,monkeypatch,fault):
    h=make(tmp_path,monkeypatch)
    if fault=='owner_cookie':next(c for c in h['reference']._jar if c.name=='sessionid').value='changed-synthetic-session'
    else:h['tags'].close()
    with pytest.raises(ValueError):h['probe'].run_once()
    assert not h['connections'] and h['env']['h'].loads==1;close(h)
