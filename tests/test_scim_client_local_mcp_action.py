"""Actual OAuth/MCP app-factory boundary around the protected local SCIM candidate."""
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
from fortipam_mcp.runtime_profile import RuntimeProfile
from fortipam_mcp.scim_client_local_mcp_action import ScimLocalMcpAction
from fortipam_mcp.reference_authority_sidecar import (UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings,
    create_reference_authority_sidecar_app)
from fortipam_mcp.planning_checkpoint_sidecar import (UnixPlanningCheckpointClient, UnixPlanningCheckpointClientSettings,
    create_checkpoint_sidecar_app)
from fortipam_mcp.material_checkpoint_sidecar import (UnixMaterialCheckpointClient, UnixMaterialCheckpointClientSettings,
    create_material_checkpoint_sidecar_app)
from fortipam_mcp.m4_checkpoint_client import UnixM4ExecutionCheckpoint
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
from test_ldap_server_mcp_action import _settings, _login, _call
from test_scim_client_authority import (make, construct, REFERENCE, ENVIRONMENT, SCOPE_REF, PURPOSES,
    identity)
from test_scim_client_m4_adapter import SCOPE
from test_system_email_authority import owner_file, unix_app
from test_system_email_m4_adapter import Clock
from v4_planning import (PersistentReferenceAuthority, PersistentReferenceCheckpointAuthority,
    PersistentPlanningCheckpointAuthority, PersistentMaterialUseCheckpointAuthority)
from v4_planning.material_persistence import PersistentMaterialUseStateStore


def bootstrap(root, scope='fortipam:read fortipam:plan fortipam:operate'):
    settings = _settings(root)
    with TestClient(create_http_app(settings), base_url='https://mcp.example.com') as client:
        headers = _login(client, scope)
    token = asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(headers['authorization'].split(' ',1)[1]))
    principal = planning_principal_from_access_token(token, settings.v4_planning_authorization)
    return settings, headers, replace(SCOPE, requester_digest=principal.requester.digest), principal.transport_namespace_digest


def rpc_phase(client, headers, operation, restore=False):
    suffix = operation+('_restore' if restore else '')
    preview = _call(client, headers, 'preview_v4_scim_local_'+suffix+'_700', {})
    assert not preview['isError']
    assert preview['structuredContent']['authorization_policy_mode'] == 'lab_auto'
    authorization = _call(client, headers, 'authorize_v4_scim_local_'+suffix+'_700',
        {'preview_ref':preview['structuredContent']['preview_ref']})
    assert not authorization['isError']
    result = _call(client, headers, 'execute_v4_scim_local_'+suffix+'_700',
        {'authorization_ref':authorization['structuredContent']['authorization_ref']})
    return result, authorization


@pytest.mark.parametrize('operation', ['rotate','disable'])
def test_http_factory_runs_protected_workflow_with_no_arbitrary_selectors(monkeypatch, tmp_path, operation):
    settings, headers, scope, transport = bootstrap(tmp_path)
    value = make(monkeypatch, tmp_path, operation=operation, scope=scope, transport=transport)
    app = create_http_app(settings, v4_scim_local_candidate_action=ScimLocalMcpAction(value.workflow))
    with TestClient(app, base_url='https://mcp.example.com') as client:
        for key in ('secret','material','body','client','endpoint'):
            result = _call(client, headers, 'preview_v4_scim_local_'+operation+'_700', {key:'SYNTHETIC_PRIVATE_INPUT'})
            assert result['isError'] and 'SYNTHETIC_PRIVATE_INPUT' not in json.dumps(result)
        assert value.evidence.calls == 0 and value.resolver.loads == 0
        result, authorization = rpc_phase(client, headers, operation)
        assert not result['isError'] and result['structuredContent']['outcome'] == 'succeeded'
        assert rpc_phase(client, headers, operation, True)[0]['structuredContent']['outcome'] == 'succeeded'
        outcome = _call(client, headers, 'get_v4_scim_local_outcome_700', {})
        assert outcome['structuredContent']['workflow_outcome'] == 'verified_locally'
        assert outcome['structuredContent']['native_backend_qualified'] is False
        replay = _call(client, headers, 'execute_v4_scim_local_'+operation+'_700',
            {'authorization_ref':authorization['structuredContent']['authorization_ref']})
        assert replay['structuredContent']['idempotent_replay'] and value.backend.sends == 2
        assert 'synthetic-new-secret' not in json.dumps((result,authorization,outcome,replay))
        assert 'synthetic.invalid' not in json.dumps(outcome)


@pytest.mark.parametrize('scopes', ['fortipam:read','fortipam:read fortipam:plan'])
def test_missing_plan_or_operate_scope_precedes_sources_and_issuer(monkeypatch, tmp_path, scopes):
    settings, headers, scope, transport = bootstrap(tmp_path, scopes if 'fortipam:plan' in scopes else 'fortipam:read fortipam:plan fortipam:operate')
    if 'fortipam:plan' not in scopes:
        with TestClient(create_http_app(settings), base_url='https://mcp.example.com') as client:
            headers = _login(client, scopes)
    value = make(monkeypatch, tmp_path, scope=scope, transport=transport)
    preview_calls = []; original_preview = value.workflow.preview
    def record_preview(*args, **kwargs):
        preview_calls.append(True)
        return original_preview(*args, **kwargs)
    monkeypatch.setattr(value.workflow, 'preview', record_preview)
    app = create_http_app(settings, v4_scim_local_candidate_action=ScimLocalMcpAction(value.workflow))
    with TestClient(app, base_url='https://mcp.example.com') as client:
        preview = _call(client, headers, 'preview_v4_scim_local_rotate_700', {})
        if 'fortipam:plan' not in scopes:
            assert preview['isError'] and value.evidence.calls == 0 and preview_calls == []
        else:
            assert not preview['isError']
            result = _call(client, headers, 'authorize_v4_scim_local_rotate_700',
                {'preview_ref':preview['structuredContent']['preview_ref']})
            assert result['isError']
        assert value.calls == [] and value.resolver.loads == value.store.claim_count == 0


@pytest.mark.parametrize('invalid', ['readonly','plan-only','bearer','authority','type'])
def test_app_factory_requires_exact_controlled_oauth_candidate(monkeypatch, tmp_path, invalid):
    settings = _settings(tmp_path); value = make(monkeypatch, tmp_path)
    action = ScimLocalMcpAction(value.workflow)
    if invalid == 'readonly': settings = replace(settings, runtime_profile=RuntimeProfile.READONLY)
    elif invalid == 'plan-only': settings = replace(settings, runtime_profile=RuntimeProfile.V4_PLAN_ONLY)
    elif invalid == 'bearer': settings = replace(settings, auth_mode='bearer', bearer_token='synthetic-token')
    elif invalid == 'authority': settings = replace(settings, v4_planning_authorization=None)
    else: action = object()
    with pytest.raises(HttpConfigurationError): create_http_app(settings, v4_scim_local_candidate_action=action)
    assert value.evidence.calls == value.resolver.loads == 0


def test_default_app_does_not_advertise_or_bind_local_scim_tools(tmp_path):
    settings, headers, _, _ = bootstrap(tmp_path)
    with TestClient(create_http_app(settings), base_url='https://mcp.example.com') as client:
        result = _call(client, headers, 'preview_v4_scim_local_rotate_700', {})
        assert result['isError']
        response = client.post('/fpamcp', headers=headers, json=dict(jsonrpc='2.0', id='list', method='tools/list', params={}))
        names = {tool['name'] for tool in response.json()['result']['tools']}
        assert not any('_scim_local_' in name for name in names)


@contextmanager
def scim_unix_services(tmp_path):
    clock = Clock()
    reference_checkpoint = PersistentReferenceCheckpointAuthority(tmp_path/'reference-tail.db', owner_file(tmp_path/'reference-tail.key', b's'*32),
        authority_ref='scim-test-reference-checkpoint')
    reference = PersistentReferenceAuthority(tmp_path/'reference.db', owner_file(tmp_path/'reference.key', b'r'*32),
        authority_ref=REFERENCE, monotonic_checkpoint=reference_checkpoint,
        checkpoint_store_ref='scim-test-reference-state', clock=clock)
    execution = PersistentPlanningCheckpointAuthority(tmp_path/'execution-tail.db', owner_file(tmp_path/'execution-tail.key', b'z'*32),
        authority_ref='scim-test-execution-checkpoint')
    material = PersistentMaterialUseCheckpointAuthority(tmp_path/'material-tail.db', owner_file(tmp_path/'material-tail.key', b'q'*32),
        authority_ref='scim-test-material-checkpoint')
    with ExitStack() as stack:
        sockets = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='scimcp-', dir=Path("/tmp").resolve())))
        stack.enter_context(unix_app(create_reference_authority_sidecar_app(reference), sockets/'r.sock'))
        stack.enter_context(unix_app(create_checkpoint_sidecar_app(execution), sockets/'e.sock'))
        stack.enter_context(unix_app(create_material_checkpoint_sidecar_app(material), sockets/'m.sock'))
        client = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(sockets/'r.sock', REFERENCE))
        store = PersistentM4ExecutionStateStore(tmp_path/'execution.db', owner_file(tmp_path/'execution.key', b'e'*32),
            monotonic_checkpoint=UnixM4ExecutionCheckpoint(UnixPlanningCheckpointClient(UnixPlanningCheckpointClientSettings(
                sockets/'e.sock', execution.authority_ref)), 'scim-test-execution-state'), checkpoint_store_ref='scim-test-execution-state')
        material_store = PersistentMaterialUseStateStore(tmp_path/'material.db', owner_file(tmp_path/'material.key', b'm'*32),
            monotonic_checkpoint=UnixMaterialCheckpointClient(UnixMaterialCheckpointClientSettings(sockets/'m.sock', material.authority_ref)),
            checkpoint_store_ref='scim-test-material-state')
        yield reference, client, store, material_store


@pytest.mark.parametrize('operation,fault', [('rotate','none'),('disable','none'),('rotate','lost-ack')])
def test_real_unix_reference_and_both_checkpoint_services_drive_normal_oauth_mcp(tmp_path, operation, fault):
    settings, headers, scope, transport = bootstrap(tmp_path)
    with scim_unix_services(tmp_path) as (reference, client, store, material_store):
        value = construct(tmp_path, client, operation=operation, scope=scope, transport=transport,
            opened=(store,material_store), fault=fault)
        reference.issue_many(tuple((value.policy.reference_for(phase,purpose), 'scim_'+purpose)
            for phase in ('apply','restore') for purpose in PURPOSES), requester_digest=scope.requester_digest,
            environment_ref=ENVIRONMENT, scope_ref=SCOPE_REF, expires_at=1120, now_epoch=1000)
        app = create_http_app(settings, v4_scim_local_candidate_action=ScimLocalMcpAction(value.workflow))
        with TestClient(app, base_url='https://mcp.example.com') as mcp:
            result, authorization = rpc_phase(mcp, headers, operation)
            assert not result['isError']
            assert (result['structuredContent']['outcome'] == 'succeeded') is (fault == 'none')
            if fault == 'none': assert rpc_phase(mcp, headers, operation, True)[0]['structuredContent']['outcome'] == 'succeeded'
            else:
                denied = _call(mcp, headers, 'preview_v4_scim_local_rotate_restore_700', {})
                assert denied['isError'] and value.recovery.loads == 0
            replay = _call(mcp, headers, 'execute_v4_scim_local_'+operation+'_700',
                {'authorization_ref':authorization['structuredContent']['authorization_ref']})
            assert replay['structuredContent']['idempotent_replay']
            outcome = _call(mcp, headers, 'get_v4_scim_local_outcome_700', {})['structuredContent']
            assert outcome['workflow_outcome'] == ('verified_locally' if fault == 'none' else 'reconciliation_required')
            assert value.backend.sends == store.claim_count == material_store.claim_count == (2 if fault == 'none' else 1)
