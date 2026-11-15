"""SDK-bound original Account prerequisites and explicit two-channel closure."""
import json
import ssl
import time
from copy import deepcopy

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.ems_tag_authority import EmsTagCreateAuthority
from fortipam_mcp.ems_tag_account_enrollment import EmsAccountCentralEnrollment
from fortipam_mcp.ems_tag_account_tag_source import EmsOriginalAccountTagSession
from fortipam_mcp.ems_tag_mcp_action import EmsTagMcpAction, EmsTagPreparedContext
from fortipam_mcp.ems_tag_original_binding import load_original_binding
from fortipam_mcp.ems_tag_recovery_authority import EmsTagRecoveryAuthority
from fortipam_mcp.ems_tag_recovery_contract import EmsTagOwnedRecoveryScope
from fortipam_mcp.http_server import create_http_app
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_ems_tag_account_tag_source import make as account_fixture, install_writer
from test_ems_tag_account_tag_read import close as close_fixture
from test_ems_tag_account_authentication import channel as account_channel
from test_ems_tag_account_lifecycle import recovery as account_owner, close_recovery
from test_ems_tag_contract import envelope
from test_ems_tag_http_transport import reply
from test_ems_tag_mcp_oauth import headers, call, data, fpa_admission, LAB
from test_ems_tag_principal_binding import binding, settings, capture
from test_ems_tag_role_fixture import CALLER
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF


def setup(root, monkeypatch):
    cfg = settings(root);identity = binding(root/'identity')
    with TestClient(create_http_app(cfg,v4_ems_tag_principal_binding=identity),base_url='https://mcp.example.com') as client:
        operator = headers(client,'fortipam:read fortipam:plan fortipam:operate')
        assert data(capture(client,operator))['device_write_executed'] is False
    requester = identity.load()
    # These independent fixture M4s happen before the Tag app/preview exists.
    monkeypatch.setitem(CALLER,'requester_digest',requester.requester_digest)
    original_ssl = ssl.create_default_context
    fixture_root = root/'prerequisites';fixture_root.mkdir(mode=0o700)
    try:h = account_fixture(fixture_root,monkeypatch)
    finally:monkeypatch.setattr(ssl,'create_default_context',original_ssl)
    assert h['original']._issued.plan.requester_digest==requester.requester_digest
    assert h['env']['h'].parent._issued.plan.requester_digest==requester.requester_digest
    target = root/'tag';target.mkdir(mode=0o700);(target/'custody').mkdir(mode=0o700)
    for name,value in (('execution.key',b'J'*32),('custody.key',b'K'*32)):
        (target/name).write_bytes(value);(target/name).chmod(0o600)
    store = PersistentM4ExecutionStateStore(target/'execution.sqlite',target/'execution.key',
        monotonic_checkpoint=_ExternalM4Checkpoint(),checkpoint_store_ref=CHECKPOINT_STORE_REF)
    writes = [];install_writer(monkeypatch,h['transport'],h['state'],writes,h['tags']._draft)
    trace = dict(h=h,writes=writes,store=store,target=target)
    class Channel:
        @property
        def scope(self):return h['state']['scope']
    def prepare(principal):
        identity.require_requester(principal)
        source = h['session'].open_once()
        # Account/Role synthetic witnesses use a fixed clock; Tag/OAuth uses
        # real epoch time, as the existing OAuth integration fixtures do.
        source._clock = lambda:int(time.time())
        admission,peer = fpa_admission(h['transport'],source,Channel(),monkeypatch)
        authority = EmsTagCreateAuthority(source,authority_key=b'V'*32,execution_enabled=True,
            requester_digest=principal.requester.digest,transport_digest=principal.transport_namespace_digest,
            fpa_admission=admission,**LAB)
        context = EmsTagPreparedContext(authority=authority,store=store,custody_directory=target/'custody',
            witness_key_file=target/'custody.key',original_binding_file=target/'original.binding.json',
            owned_account_session=h['session'])
        trace.update(source=source,authority=authority,context=context,principal=principal,peer=peer)
        return context
    action = EmsTagMcpAction(phase='create',prepare=prepare,execution_enabled=True)
    return cfg,identity,requester,action,trace


@pytest.mark.parametrize('finish',['execute','cancel_with_owner_drift'])
def test_sdk_requester_precedes_fixture_creation_and_context_owns_account_owner_lifecycle(tmp_path,monkeypatch,finish):
    cfg,identity,requester,action,t = setup(tmp_path,monkeypatch);h = t['h']
    prior_config_writes = (len(h['env']['writes']),len(h['env']['h'].parent_env['writes']))
    try:
        with TestClient(create_http_app(cfg,v4_ems_tag_candidate_action=action),base_url='https://mcp.example.com') as client:
            operator = headers(client,'fortipam:read fortipam:plan fortipam:operate')
            preview = data(call(client,operator,'create','preview'))
            assert t['principal'].requester.digest==requester.requester_digest
            assert prior_config_writes==(len(h['env']['writes']),len(h['env']['h'].parent_env['writes']))
            assert not t['writes'] and t['store'].claim_count==0
            # Omitting explicit Account-session ownership must fail before M4.
            with pytest.raises(ValueError):
                EmsTagPreparedContext(authority=t['authority'],store=t['store'],custody_directory=t['target']/'custody',
                    witness_key_file=t['target']/'custody.key',original_binding_file=t['target']/'other.binding.json')
            if finish=='execute':
                authorization = data(call(client,operator,'create','authorize',preview_ref=preview['preview_ref']))
                result = data(call(client,operator,'create','execute',authorization_ref=authorization['authorization_ref']))
                assert result['outcome']=='succeeded' and result['verification']=='verified' and result['session_closed']
                assert result['fortipam_tag_admission']=='verified' and t['writes']==['create']
                replay = data(call(client,operator,'create','execute',authorization_ref=authorization['authorization_ref']))
                assert replay['idempotent_replay'] and t['writes']==['create']
                assert t['context'].close()
            else:
                h['owner']['data']['born']['trusted_hosts']+=',192.0.2.99/32'
                assert t['context'].close() is False
                count = len(h['connections'])+len(h['owner_connections'])
                assert t['context'].close() is False
                assert len(h['connections'])+len(h['owner_connections'])==count
                assert t['store'].claim_count==0 and not t['writes']
            assert h['session']._closed and not h['session']._enabled
            assert h['transport']._closed and h['reference']._closed and h['tags']._closed
            assert h['enrollment']._closed and h['owner']['source']._closed
            assert h['transport']._closure.next_session_check_401 and h['reference']._closure.next_session_check_401
            packet = json.loads((identity._directory/'sdk-requester-binding.json').read_bytes())
            assert packet['body']['requester_digest']==h['original']._issued.plan.requester_digest
    finally:
        action.close();identity.close();close_fixture(h)


def test_separate_oauth_client_recovers_same_original_account_source_and_closes_both_channels(tmp_path,monkeypatch):
    cfg,identity,requester,create,t = setup(tmp_path,monkeypatch);h = t['h'];recovered = {}
    def prepare(principal):
        identity.require_requester(principal)
        original = load_original_binding(t['target']/'original.binding.json',t['target']/'custody.key',
            monotonic_checkpoint=t['store']._monotonic_checkpoint,checkpoint_store_ref=CHECKPOINT_STORE_REF)
        original_ssl = ssl.create_default_context
        try:
            owner = account_owner(tmp_path/'recover-owner',monkeypatch,h['env'],h['original'])
            owner['data']['metadata']['consts'] = deepcopy(h['owner']['data']['metadata']['consts'])
            previous = h['env']['h']
            enrollment = EmsAccountCentralEnrollment(owner['source'],previous.draft,previous.parent,
                requester_digest=principal.requester.digest,env_file=previous.env,directory=previous.directory,
                witness_key_file=previous.key,clock=lambda:owner['now'][0])
            reference = owner['transport'].make_readonly_tag_reference(original._draft,source_key=b'W'*32,reference_enabled=True)
            reference._clock = lambda:owner['now'][0]
            transport,connections = account_channel(tmp_path/'recover-account',monkeypatch,h['env'],owner)
        finally:monkeypatch.setattr(ssl,'create_default_context',original_ssl)
        underlying = transport._connect
        def connect():
            connection = underlying();receive = connection.getresponse
            def response():
                if connection.path=='/api/v1/auth/signin':
                    return reply(envelope(None),extra=b'Set-Cookie: sessionid=separate-account-mcp-recovery; Path=/; Secure; HttpOnly\r\n')
                return receive()
            connection.getresponse = response;return connection
        monkeypatch.setattr(transport,'_connect',connect)
        writes = []
        for channel in (transport,owner['transport']):install_writer(monkeypatch,channel,h['state'],writes,original._draft)
        session = EmsOriginalAccountTagSession(enrollment,h['original'],transport,reference,source_key=b'Q'*32,
            phase='recover',tag_original=original,execution_enabled=True)
        source = session.open_once();source._clock = lambda:int(time.time())
        scope = EmsTagOwnedRecoveryScope(transport=transport,sources=source,original=original,
            requester_digest=principal.requester.digest,caller_transport_digest=principal.transport_namespace_digest)
        class Channel:
            @property
            def scope(self):return h['state']['scope']
        admission,peer = fpa_admission(transport,source,Channel(),monkeypatch,original=original,
            packet=t['target']/'original.binding.json')
        authority = EmsTagRecoveryAuthority(scope,authority_key=b'R'*32,execution_enabled=True,fpa_admission=admission,**LAB)
        root = tmp_path/'recover';root.mkdir(mode=0o700);(root/'custody').mkdir(mode=0o700)
        for name,value in (('execution.key',b'N'*32),('custody.key',b'Z'*32)):
            (root/name).write_bytes(value);(root/name).chmod(0o600)
        store = PersistentM4ExecutionStateStore(root/'execution.sqlite',root/'execution.key',
            monotonic_checkpoint=_ExternalM4Checkpoint(),checkpoint_store_ref=CHECKPOINT_STORE_REF)
        context = EmsTagPreparedContext(authority=authority,store=store,custody_directory=root/'custody',
            witness_key_file=root/'custody.key',owned_account_session=session)
        recovered.update(context=context,store=store,source=source,scope=scope,session=session,owner=owner,
            transport=transport,connections=connections,writes=writes,principal=principal,original=original)
        return context
    recover = EmsTagMcpAction(phase='recover',prepare=prepare,execution_enabled=True)
    try:
        with TestClient(create_http_app(cfg,v4_ems_tag_candidate_action=create),base_url='https://mcp.example.com') as client:
            operator = headers(client,'fortipam:read fortipam:plan fortipam:operate')
            preview = data(call(client,operator,'create','preview'))
            authorization = data(call(client,operator,'create','authorize',preview_ref=preview['preview_ref']))
            assert data(call(client,operator,'create','execute',authorization_ref=authorization['authorization_ref']))['verification']=='verified'
        with TestClient(create_http_app(cfg,v4_ems_tag_candidate_action=recover),base_url='https://mcp.example.com') as client:
            operator = headers(client,'fortipam:read fortipam:plan fortipam:operate')
            preview = data(call(client,operator,'recover','preview'))
            assert recovered['principal'].requester.digest==requester.requester_digest==t['principal'].requester.digest
            assert recovered['principal'].transport_namespace_digest!=t['principal'].transport_namespace_digest
            assert recovered['source'].source_context_digest==recovered['original']._source
            authorization = data(call(client,operator,'recover','authorize',preview_ref=preview['preview_ref']))
            result = data(call(client,operator,'recover','execute',authorization_ref=authorization['authorization_ref']))
            assert result['outcome']=='succeeded' and result['verification']=='verified' and result['session_closed']
            assert recovered['writes']==['delete'] and recovered['store'].claim_count==1
            assert recovered['transport']._closure.next_session_check_401
            assert recovered['owner']['transport']._closure.next_session_check_401
            assert recovered['context'].close()
    finally:
        create.close();recover.close();identity.close()
        if recovered:
            recovered['original'].close();close_recovery(recovered['owner'])
        close_fixture(h)
