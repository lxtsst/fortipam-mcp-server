"""Real local OAuth/MCP transport around an injected synthetic email backend."""
import asyncio
from dataclasses import replace
import json
import time

import pytest
from starlette.testclient import TestClient

from fortipam_mcp import http_server
from fortipam_mcp.local_oauth import LocalOAuthProvider
from fortipam_mcp.runtime_profile import RuntimeProfile
from fortipam_mcp.server import FortiPamMcpServer
from fortipam_mcp.system_email_local_mcp_action import (
    SystemEmailLocalMcpAction,register_system_email_local_candidate_tools,
)
from fortipam_mcp.system_email_local_workflow import SystemEmailLocalWorkflow
from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
from test_ldap_server_mcp_action import _call,_login,_settings
from test_system_email_local_workflow import Authority,make
from test_system_email_m4_adapter import BINDING,Backend,store_at,transition
from test_system_email_delivery_workflow import DeliveryBackend
from fortipam_mcp.system_email_delivery_contract import SystemEmailDeliveryBinding
from fortipam_mcp.system_email_m4_adapter import system_email_execution_digests
from v4_planning import canonical_digest


def assemble(monkeypatch,tmp_path):
    created=[]
    def capture(*args,**kwargs):
        server=FortiPamMcpServer(*args,**kwargs);created.append(server);return server
    monkeypatch.setattr(http_server,'FortiPamMcpServer',capture)
    settings=_settings(tmp_path)
    app=http_server.create_http_app(settings)
    assert len(created)==1
    return settings,app,created[0]


def bind(settings,headers,server,tmp_path,*,enabled=True,with_delivery=False,register=True):
    assert settings.local_oauth is not None and settings.v4_planning_authorization is not None
    token=asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(
        headers['authorization'].split(' ',1)[1]))
    principal=planning_principal_from_access_token(token,settings.v4_planning_authorization)
    backend=Backend();change=transition(backend);store=store_at(tmp_path);authority=Authority()
    delivery={}
    if with_delivery:
        root=tmp_path/'delivery';root.mkdir(mode=0o700)
        send_store=store_at(root,key_material=b'synthetic-mail-delivery-state-key-02',
            store_ref='system-email-local-delivery-ledger')
        context=canonical_digest({'binding':BINDING,'requester':principal.requester.digest,
            'transport':principal.transport_namespace_digest})
        value=SystemEmailDeliveryBinding('a'*48,'b'*64,change.original.source_serial_digest,
            system_email_execution_digests(change,context)[1])
        delivery=dict(delivery_binding=value,delivery_backend=DeliveryBackend(backend,None),
            delivery_store=send_store,delivery_enabled=enabled)
    workflow=SystemEmailLocalWorkflow(change,backend,store,binding_digest=BINDING,
        allowed_requester_digest=principal.requester.digest,
        allowed_transport_digest=principal.transport_namespace_digest,authority=authority,
        update_enabled=enabled,restore_enabled=enabled,clock=lambda:int(time.time()),**delivery)
    if register:register_system_email_local_candidate_tools(server,SystemEmailLocalMcpAction(workflow))
    return workflow,backend,store,authority


def test_normal_oauth_and_mcp_local_composition_updates_and_restores(monkeypatch,tmp_path):
    settings,app,server=assemble(monkeypatch,tmp_path)
    with TestClient(app,base_url='https://mcp.example.com')as client:
        headers=_login(client,'fortipam:read fortipam:plan fortipam:operate')
        workflow,backend,store,_=bind(settings,headers,server,tmp_path)
        for phase in('update','restore'):
            preview=_call(client,headers,f'preview_v4_system_email_local_{phase}_700',{})
            assert not preview['isError'];data=preview['structuredContent']
            authorization=_call(client,headers,f'authorize_v4_system_email_local_{phase}_700',
                {'preview_ref':data['preview_ref']})
            assert not authorization['isError'];reference=authorization['structuredContent']['authorization_ref']
            result=_call(client,headers,f'execute_v4_system_email_local_{phase}_700',
                {'authorization_ref':reference})
            assert not result['isError']and result['structuredContent']['outcome']=='succeeded'
            assert result['structuredContent']['native_backend_qualified']is False
            replay=_call(client,headers,f'execute_v4_system_email_local_{phase}_700',
                {'authorization_ref':reference})
            assert replay['structuredContent']['idempotent_replay']
            assert 'capture.example.test'not in json.dumps((preview,authorization,result))
        assert len(backend.submissions)==2 and store.claim_count==2
        workflow.close()


@pytest.mark.parametrize('operate,enabled',[(False,True),(True,False)])
def test_missing_operation_scope_or_gate_prevents_authority_and_dispatch(monkeypatch,tmp_path,operate,enabled):
    settings,app,server=assemble(monkeypatch,tmp_path)
    with TestClient(app,base_url='https://mcp.example.com')as client:
        headers=_login(client,'fortipam:read fortipam:plan'+(' fortipam:operate'if operate else''))
        workflow,backend,store,authority=bind(settings,headers,server,tmp_path,enabled=enabled)
        preview=_call(client,headers,'preview_v4_system_email_local_update_700',{})
        assert not preview['isError']
        result=_call(client,headers,'authorize_v4_system_email_local_update_700',
            {'preview_ref':preview['structuredContent']['preview_ref']})
        assert result['isError']and authority.requests==[]
        assert backend.submissions==[]and store.claim_count==0
        workflow.close()


def test_extra_wire_or_recipient_arguments_are_denied_before_sources(monkeypatch,tmp_path):
    settings,app,server=assemble(monkeypatch,tmp_path)
    with TestClient(app,base_url='https://mcp.example.com')as client:
        headers=_login(client,'fortipam:read fortipam:plan fortipam:operate')
        workflow,backend,store,authority=bind(settings,headers,server,tmp_path)
        for key in('body','recipient','server','password'):
            result=_call(client,headers,'preview_v4_system_email_local_update_700',
                {key:'synthetic-private-marker'})
            assert result['isError']and 'synthetic-private-marker'not in json.dumps(result)
        assert backend.reads==0 and backend.submissions==[]and store.claim_count==0
        assert authority.requests==[]
        workflow.close()


@pytest.mark.parametrize('profile',[RuntimeProfile.READONLY,RuntimeProfile.V4_PLAN_ONLY])
def test_private_registrar_refuses_noncontrolled_profiles(tmp_path,profile):
    class Host:
        _runtime_profile=profile
    workflow,*_=make(tmp_path)
    with pytest.raises(ValueError):
        register_system_email_local_candidate_tools(Host(),SystemEmailLocalMcpAction(workflow))


def test_normal_server_startup_does_not_register_local_candidate_tools(monkeypatch,tmp_path):
    _,app,_=assemble(monkeypatch,tmp_path)
    with TestClient(app,base_url='https://mcp.example.com')as client:
        headers=_login(client,'fortipam:read fortipam:plan fortipam:operate')
        result=_call(client,headers,'preview_v4_system_email_local_update_700',{})
        assert result['isError']


def test_http_app_factory_composes_configure_delivery_and_restore(monkeypatch,tmp_path):
    settings,app,server=assemble(monkeypatch,tmp_path)
    with TestClient(app,base_url='https://mcp.example.com')as client:
        headers=_login(client,'fortipam:read fortipam:plan fortipam:operate')
        workflow,configuration,store,_=bind(settings,headers,server,tmp_path,with_delivery=True,register=False)
    app=http_server.create_http_app(settings,v4_system_email_local_candidate_action=SystemEmailLocalMcpAction(workflow))
    with TestClient(app,base_url='https://mcp.example.com')as client:
        for suffix in('update','test_delivery','restore'):
            preview=_call(client,headers,f'preview_v4_system_email_local_{suffix}_700',{})
            assert not preview['isError']
            authorization=_call(client,headers,f'authorize_v4_system_email_local_{suffix}_700',
                {'preview_ref':preview['structuredContent']['preview_ref']})
            assert not authorization['isError']
            result=_call(client,headers,f'execute_v4_system_email_local_{suffix}_700',
                {'authorization_ref':authorization['structuredContent']['authorization_ref']})
            assert not result['isError']and result['structuredContent']['outcome']=='succeeded'
        outcome=_call(client,headers,'get_v4_system_email_local_outcome_700',{})
        assert not outcome['isError']
        value=outcome['structuredContent']
        assert value['workflow_outcome']=='verified_locally'and value['delivery_claims']==1
        assert value['native_delivery_qualified']is False
        assert store.claim_count==2 and len(configuration.submissions)==2
        assert workflow._delivery_backend.sends==1
        assert 'capture.invalid'not in json.dumps(outcome)
        workflow.close()


@pytest.mark.parametrize('invalid',['readonly','plan-only','auth','authority','type'])
def test_http_app_factory_denies_uncontrolled_or_foreign_candidate(monkeypatch,tmp_path,invalid):
    settings=_settings(tmp_path);workflow,backend,store,*_=make(tmp_path)
    action=SystemEmailLocalMcpAction(workflow)
    if invalid=='readonly':settings=replace(settings,runtime_profile=RuntimeProfile.READONLY)
    elif invalid=='plan-only':settings=replace(settings,runtime_profile=RuntimeProfile.V4_PLAN_ONLY)
    elif invalid=='auth':settings=replace(settings,auth_mode='bearer',bearer_token='synthetic-token')
    elif invalid=='authority':settings=replace(settings,v4_planning_authorization=None)
    else:action=object()
    def no_host(*args,**kwargs):raise AssertionError('Host construction must follow candidate validation.')
    monkeypatch.setattr(http_server,'FortiPamMcpServer',no_host)
    with pytest.raises(http_server.HttpConfigurationError):
        http_server.create_http_app(settings,v4_system_email_local_candidate_action=action)
    assert backend.reads==0 and store.claim_count==0
    workflow.close()


def test_delivery_operation_scope_and_arbitrary_mailbox_denials_precede_sender(monkeypatch,tmp_path):
    settings,app,server=assemble(monkeypatch,tmp_path)
    with TestClient(app,base_url='https://mcp.example.com')as client:
        headers=_login(client,'fortipam:read fortipam:plan')
        workflow,_,_,authority=bind(settings,headers,server,tmp_path,with_delivery=True)
        # Host-only synthetic setup supplies an existing successful configuration;
        # the RPC token still has no operation scope.
        identity=dict(requester_digest=workflow._requester,transport_digest=workflow._transport)
        preview=workflow.preview('update',**identity)
        authorization=workflow.authorize('update',preview['preview_ref'],**identity)
        workflow.execute('update',authorization['authorization_ref'],**identity)
        for key in('recipient','email','body'):
            denied=_call(client,headers,'preview_v4_system_email_local_test_delivery_700',
                {key:'synthetic-private-marker'})
            assert denied['isError']and 'synthetic-private-marker'not in json.dumps(denied)
        assert workflow._delivery_backend.reads==0
        preview=_call(client,headers,'preview_v4_system_email_local_test_delivery_700',{})
        assert not preview['isError']
        denied=_call(client,headers,'authorize_v4_system_email_local_test_delivery_700',
            {'preview_ref':preview['structuredContent']['preview_ref']})
        assert denied['isError']and len(authority.requests)==1
        assert workflow._delivery_store.claim_count==0 and workflow._delivery_backend.sends==0
        workflow.close()
