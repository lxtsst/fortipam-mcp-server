"""Normal OAuth/MCP and optional actual Unix authority/CAS for local SAML."""
import asyncio
from contextlib import ExitStack, contextmanager
from dataclasses import replace
import json
from pathlib import Path
import tempfile

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.http_server import create_http_app, HttpConfigurationError
from fortipam_mcp.local_oauth import LocalOAuthProvider
from fortipam_mcp.m4_checkpoint_client import UnixM4ExecutionCheckpoint
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.planning_checkpoint_sidecar import (UnixPlanningCheckpointClient, UnixPlanningCheckpointClientSettings,
    create_checkpoint_sidecar_app)
from fortipam_mcp.reference_authority_sidecar import (UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings,
    create_reference_authority_sidecar_app)
from fortipam_mcp.runtime_profile import RuntimeProfile
from fortipam_mcp.saml_server_local_mcp_action import SamlLocalMcpAction
from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
from test_ldap_server_mcp_action import _settings, _login, _call
from test_saml_server_authority import (make, construct, REFERENCE, ENVIRONMENT, SCOPE_REF, PURPOSES)
from test_saml_server_local_m4 import make as m4_candidate, SCOPE
from test_system_email_authority import owner_file, unix_app
from test_system_email_m4_adapter import Clock
from v4_planning import PersistentReferenceAuthority, PersistentReferenceCheckpointAuthority, PersistentPlanningCheckpointAuthority


def bootstrap(root, scopes='fortipam:read fortipam:plan fortipam:operate'):
    settings = _settings(root)
    with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client:
        headers = _login(client,scopes)
    token = asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(headers['authorization'].split(' ',1)[1]))
    principal = planning_principal_from_access_token(token,settings.v4_planning_authorization)
    return settings,headers,replace(SCOPE,requester_digest=principal.requester.digest),principal.transport_namespace_digest


def rpc_phase(client, headers, phase):
    preview = _call(client,headers,'preview_v4_saml_local_'+phase+'_700',{})
    assert not preview['isError'] and preview['structuredContent']['authorization_policy_mode'] == 'lab_auto'
    authorization = _call(client,headers,'authorize_v4_saml_local_'+phase+'_700',
        {'preview_ref':preview['structuredContent']['preview_ref']})
    assert not authorization['isError']
    result = _call(client,headers,'execute_v4_saml_local_'+phase+'_700',
        {'authorization_ref':authorization['structuredContent']['authorization_ref']})
    return result,authorization


@pytest.mark.parametrize('fault', [None,'lost-ack'])
def test_normal_mcp_owned_create_remove_or_unknown_query_never_resends(monkeypatch, tmp_path, fault):
    settings,headers,scope,transport = bootstrap(tmp_path)
    value = make(monkeypatch,tmp_path,scope=scope,transport=transport); value.candidate.backend.fault = fault
    app = create_http_app(settings,v4_saml_local_candidate_action=SamlLocalMcpAction(value.workflow))
    with TestClient(app,base_url='https://mcp.example.com') as client:
        reads = len(value.candidate.peer.calls)
        for name in ('body','endpoint','certificate','selector','name'):
            result = _call(client,headers,'preview_v4_saml_local_create_700',{name:'SYNTHETIC_PRIVATE_INPUT'})
            assert result['isError'] and 'SYNTHETIC_PRIVATE_INPUT' not in json.dumps(result)
        assert len(value.candidate.peer.calls) == reads and value.calls == []
        result,authorization = rpc_phase(client,headers,'create')
        assert not result['isError'] and (result['structuredContent']['outcome'] == 'succeeded') is (fault is None)
        replay = _call(client,headers,'execute_v4_saml_local_create_700',
            {'authorization_ref':authorization['structuredContent']['authorization_ref']})
        assert replay['structuredContent']['idempotent_replay'] and value.candidate.backend.sends == 1
        if fault is None: assert rpc_phase(client,headers,'remove')[0]['structuredContent']['outcome'] == 'succeeded'
        else: assert _call(client,headers,'preview_v4_saml_local_remove_700',{})['isError']
        outcome = _call(client,headers,'get_v4_saml_local_outcome_700',{})['structuredContent']
        assert outcome['workflow_outcome'] == ('verified_locally' if fault is None else 'reconciliation_required')
        assert outcome['native_backend_qualified'] is outcome['saml_login_verified'] is False
        assert value.candidate.store.claim_count == value.candidate.backend.sends == (2 if fault is None else 1)
        public = json.dumps((result,replay,outcome))
        assert 'example' not in public and value.candidate.initial.plan.binding.name not in public


@pytest.mark.parametrize('scopes', ['fortipam:read','fortipam:read fortipam:plan'])
def test_missing_plan_or_operate_is_rejected_before_workflow_or_issuer(monkeypatch, tmp_path, scopes):
    settings,headers,scope,transport = bootstrap(tmp_path,scopes if 'fortipam:plan' in scopes else 'fortipam:read fortipam:plan fortipam:operate')
    if 'fortipam:plan' not in scopes:
        with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client: headers = _login(client,scopes)
    value = make(monkeypatch,tmp_path,scope=scope,transport=transport)
    calls = []; preview = value.workflow.preview
    def observed(*args,**kwargs): calls.append(True); return preview(*args,**kwargs)
    monkeypatch.setattr(value.workflow,'preview',observed)
    reads = len(value.candidate.peer.calls)
    with TestClient(create_http_app(settings,v4_saml_local_candidate_action=SamlLocalMcpAction(value.workflow)),
            base_url='https://mcp.example.com') as client:
        result = _call(client,headers,'preview_v4_saml_local_create_700',{})
        if 'fortipam:plan' not in scopes:
            assert result['isError'] and calls == [] and len(value.candidate.peer.calls) == reads
        else:
            assert not result['isError']
            assert _call(client,headers,'authorize_v4_saml_local_create_700',
                {'preview_ref':result['structuredContent']['preview_ref']})['isError']
        assert value.calls == [] and value.candidate.store.claim_count == value.candidate.backend.sends == 0


@pytest.mark.parametrize('invalid', ['readonly','plan-only','bearer','authority','type'])
def test_app_factory_requires_exact_controlled_oauth_candidate(monkeypatch, tmp_path, invalid):
    settings = _settings(tmp_path); value = make(monkeypatch,tmp_path); action = SamlLocalMcpAction(value.workflow)
    if invalid == 'readonly': settings = replace(settings,runtime_profile=RuntimeProfile.READONLY)
    elif invalid == 'plan-only': settings = replace(settings,runtime_profile=RuntimeProfile.V4_PLAN_ONLY)
    elif invalid == 'bearer': settings = replace(settings,auth_mode='bearer',bearer_token='synthetic-token')
    elif invalid == 'authority': settings = replace(settings,v4_planning_authorization=None)
    else: action = object()
    with pytest.raises(HttpConfigurationError): create_http_app(settings,v4_saml_local_candidate_action=action)
    assert value.calls == []


def test_default_app_registers_no_saml_execution_candidate(tmp_path):
    settings,headers,_,_ = bootstrap(tmp_path)
    with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client:
        assert _call(client,headers,'preview_v4_saml_local_create_700',{})['isError']
        response = client.post('/fpamcp',headers=headers,json=dict(jsonrpc='2.0',id='list',method='tools/list',params={}))
        names = {tool['name'] for tool in response.json()['result']['tools']}
        assert not any('_saml_local_' in name for name in names)


@contextmanager
def saml_unix_services(root):
    clock = Clock()
    reference_checkpoint = PersistentReferenceCheckpointAuthority(root/'reference-tail.db',owner_file(root/'reference-tail.key',b's'*32),
        authority_ref='saml-test-reference-checkpoint')
    reference = PersistentReferenceAuthority(root/'reference.db',owner_file(root/'reference.key',b'r'*32),
        authority_ref=REFERENCE,monotonic_checkpoint=reference_checkpoint,checkpoint_store_ref='saml-test-reference-state',clock=clock)
    checkpoint = PersistentPlanningCheckpointAuthority(root/'execution-tail.db',owner_file(root/'execution-tail.key',b'z'*32),
        authority_ref='saml-test-execution-checkpoint')
    with ExitStack() as stack:
        sockets = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='samlcp-',dir=Path("/tmp").resolve())))
        stack.enter_context(unix_app(create_reference_authority_sidecar_app(reference),sockets/'r.sock'))
        stack.enter_context(unix_app(create_checkpoint_sidecar_app(checkpoint),sockets/'e.sock'))
        client = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(sockets/'r.sock',REFERENCE))
        store = PersistentM4ExecutionStateStore(root/'execution.db',owner_file(root/'execution.key',b'e'*32),
            monotonic_checkpoint=UnixM4ExecutionCheckpoint(UnixPlanningCheckpointClient(UnixPlanningCheckpointClientSettings(
                sockets/'e.sock',checkpoint.authority_ref)),'saml-test-execution-state'),checkpoint_store_ref='saml-test-execution-state')
        yield reference,client,store


@pytest.mark.parametrize('fault', [None,'lost-ack'])
def test_real_unix_grants_and_checkpoint_drive_normal_mcp_owned_lifecycle(tmp_path, fault):
    settings,headers,scope,transport = bootstrap(tmp_path)
    with saml_unix_services(tmp_path) as (reference,reference_client,store):
        candidate = m4_candidate(tmp_path,opened=store)
        candidate.backend.fault = fault
        value = construct(tmp_path,reference_client,candidate=candidate,scope=scope,transport=transport)
        reference.issue_many(tuple((value.policy.reference_for(phase,purpose),'saml_'+purpose)
            for phase in ('create','remove') for purpose in PURPOSES),requester_digest=scope.requester_digest,
            environment_ref=ENVIRONMENT,scope_ref=SCOPE_REF,expires_at=1120,now_epoch=1000)
        with TestClient(create_http_app(settings,v4_saml_local_candidate_action=SamlLocalMcpAction(value.workflow)),
                base_url='https://mcp.example.com') as client:
            result,authorization = rpc_phase(client,headers,'create')
            assert (result['structuredContent']['outcome'] == 'succeeded') is (fault is None)
            replay = _call(client,headers,'execute_v4_saml_local_create_700',
                {'authorization_ref':authorization['structuredContent']['authorization_ref']})
            assert replay['structuredContent']['idempotent_replay'] and candidate.backend.sends == 1
            if fault is None: assert rpc_phase(client,headers,'remove')[0]['structuredContent']['outcome'] == 'succeeded'
            else: assert _call(client,headers,'preview_v4_saml_local_remove_700',{})['isError']
            outcome = _call(client,headers,'get_v4_saml_local_outcome_700',{})['structuredContent']
            assert outcome['workflow_outcome'] == ('verified_locally' if fault is None else 'reconciliation_required')
            assert candidate.backend.sends == store.claim_count == (2 if fault is None else 1)
