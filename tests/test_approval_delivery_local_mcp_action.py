"""Protected Approval Email phases through actual OAuth/MCP; product data are synthetic."""
import asyncio
from dataclasses import replace
import json
from threading import Event

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.approval_delivery_local_mcp_action import ApprovalDeliveryLocalMcpAction
from fortipam_mcp.http_server import create_http_app, HttpConfigurationError
from fortipam_mcp.local_oauth import LocalOAuthProvider
from fortipam_mcp.runtime_profile import RuntimeProfile
from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
from test_approval_delivery_authority import make, construct, ENVIRONMENT, SCOPE_REF, PURPOSES, identity
from test_approval_delivery_m4 import SCOPE
from test_approval_delivery_source import candidate as source_candidate  # noqa: F401
from test_approval_delivery_http_backend import candidate as http_candidate  # noqa: F401
from test_ldap_server_mcp_action import _settings, _login, _call


def bootstrap(root,scopes='fortipam:read fortipam:plan fortipam:operate'):
    settings = _settings(root)
    with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client: headers = _login(client,scopes)
    token = asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(headers['authorization'].split(' ',1)[1]))
    principal = planning_principal_from_access_token(token,settings.v4_planning_authorization)
    return settings,headers,replace(SCOPE,requester_digest=principal.requester.digest),principal.transport_namespace_digest


def rpc_phase(client,headers,phase):
    preview = _call(client,headers,'preview_v4_approval_delivery_local_'+phase+'_700',{})
    assert not preview['isError'] and preview['structuredContent']['authorization_policy_mode'] == 'lab_auto'
    authorization = _call(client,headers,'authorize_v4_approval_delivery_local_'+phase+'_700',
        {'preview_ref':preview['structuredContent']['preview_ref']})
    assert not authorization['isError']
    result = _call(client,headers,'execute_v4_approval_delivery_local_'+phase+'_700',
        {'authorization_ref':authorization['structuredContent']['authorization_ref']})
    return result,authorization


@pytest.mark.parametrize('protocol,fault', [('imaps',None),('ms-graph',None),('imaps','lost-ack')])
def test_normal_mcp_local_apply_restore_or_unknown_queries_never_reload(monkeypatch,tmp_path,protocol,fault):
    settings,headers,scope,transport = bootstrap(tmp_path)
    value = make(monkeypatch,tmp_path,protocol=protocol,fault=fault,scope=scope,transport=transport)
    with TestClient(create_http_app(settings,v4_approval_delivery_local_candidate_action=ApprovalDeliveryLocalMcpAction(value.workflow)),
            base_url='https://mcp.example.com') as client:
        calls = value.backend.reads
        for key in ('token','user','body','endpoint','material'):
            result = _call(client,headers,'preview_v4_approval_delivery_local_configure_700',{key:'SYNTHETIC_PRIVATE_INPUT'})
            assert result['isError'] and 'SYNTHETIC_PRIVATE_INPUT' not in json.dumps(result)
        assert value.backend.reads == calls and value.calls == [] and value.resolver.loads == 0
        result,authorization = rpc_phase(client,headers,'configure')
        assert not result['isError'] and (result['structuredContent']['outcome'] == 'succeeded') is (fault is None)
        value.workflow._enabled['configure'] = False; reads = value.backend.reads
        replay = _call(client,headers,'execute_v4_approval_delivery_local_configure_700',
            {'authorization_ref':authorization['structuredContent']['authorization_ref']})
        assert replay['structuredContent']['idempotent_replay'] and value.backend.reads == reads
        if fault is None: assert rpc_phase(client,headers,'restore')[0]['structuredContent']['outcome'] == 'succeeded'
        else: assert _call(client,headers,'preview_v4_approval_delivery_local_restore_700',{})['isError']
        outcome = _call(client,headers,'get_v4_approval_delivery_local_outcome_700',{})['structuredContent']
        assert outcome['workflow_outcome'] == ('verified_locally' if fault is None else 'reconciliation_required')
        assert not outcome['native_backend_qualified'] and not outcome['polling_and_approval_effects_verified']
        assert value.backend.sends == value.store.claim_count == value.material.claim_count == (2 if fault is None else 1)
        assert value.resolver.loads == 1 and value.recovery.loads == int(fault is None)
        public = json.dumps((result,replay,outcome))
        assert 'SYNTHETIC_' not in public


@pytest.mark.parametrize('scopes', ['fortipam:read','fortipam:read fortipam:plan'])
def test_missing_plan_or_operate_is_rejected_before_sources_or_authority(monkeypatch,tmp_path,scopes):
    settings,headers,scope,transport = bootstrap(tmp_path,scopes if 'fortipam:plan' in scopes else 'fortipam:read fortipam:plan fortipam:operate')
    if 'fortipam:plan' not in scopes:
        with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client: headers = _login(client,scopes)
    value = make(monkeypatch,tmp_path,scope=scope,transport=transport); calls = value.backend.reads
    with TestClient(create_http_app(settings,v4_approval_delivery_local_candidate_action=ApprovalDeliveryLocalMcpAction(value.workflow)),
            base_url='https://mcp.example.com') as client:
        preview = _call(client,headers,'preview_v4_approval_delivery_local_configure_700',{})
        if 'fortipam:plan' not in scopes: assert preview['isError'] and value.backend.reads == calls
        else:
            assert not preview['isError']
            assert _call(client,headers,'authorize_v4_approval_delivery_local_configure_700',
                {'preview_ref':preview['structuredContent']['preview_ref']})['isError']
        assert value.calls == [] and value.resolver.loads == value.store.claim_count == 0


@pytest.mark.parametrize('invalid', ['readonly','plan-only','bearer','authority','type'])
def test_factory_requires_exact_controlled_oauth_candidate(monkeypatch,tmp_path,invalid):
    settings = _settings(tmp_path); value = make(monkeypatch,tmp_path); action = ApprovalDeliveryLocalMcpAction(value.workflow)
    if invalid == 'readonly': settings = replace(settings,runtime_profile=RuntimeProfile.READONLY)
    elif invalid == 'plan-only': settings = replace(settings,runtime_profile=RuntimeProfile.V4_PLAN_ONLY)
    elif invalid == 'bearer': settings = replace(settings,auth_mode='bearer',bearer_token='synthetic-token')
    elif invalid == 'authority': settings = replace(settings,v4_planning_authorization=None)
    else: action = object()
    with pytest.raises(HttpConfigurationError): create_http_app(settings,v4_approval_delivery_local_candidate_action=action)
    assert value.resolver.loads == 0 and value.backend.reads == 1


def test_default_app_registers_no_local_approval_delivery_execution_candidate(tmp_path):
    settings,headers,_,_ = bootstrap(tmp_path)
    with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client:
        response = client.post('/fpamcp',headers=headers,json=dict(jsonrpc='2.0',id='list',method='tools/list',params={})).json()
        assert not any('_approval_delivery_local_' in tool['name'] for tool in response['result']['tools'])


def principal_for(settings, headers):
    token = asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(headers['authorization'].split(' ',1)[1]))
    return planning_principal_from_access_token(token, settings.v4_planning_authorization)


@pytest.mark.parametrize('repeat', [False, True])
def test_owned_execute_cancellation_drains_material_and_keeps_query_available(monkeypatch, tmp_path, repeat):
    settings, headers, scope, transport = bootstrap(tmp_path)
    principal = principal_for(settings, headers)
    value = make(monkeypatch, tmp_path, scope=scope, transport=transport)
    action = ApprovalDeliveryLocalMcpAction(value.workflow)
    preview = value.workflow.preview('configure', **identity(value))
    authorization = value.workflow.authorize('configure', preview['preview_ref'], **identity(value))
    started, release = Event(), Event()
    load = value.resolver.load_approval_material_once
    def loading():
        result = load(); started.set()
        assert release.wait(3)
        return result
    monkeypatch.setattr(value.resolver, 'load_approval_material_once', loading)
    async def scenario():
        task = asyncio.create_task(action.call('execute', principal, phase='configure', reference=authorization['authorization_ref']))
        try:
            assert await asyncio.to_thread(started.wait, 2)
            task.cancel(); await asyncio.sleep(.02)
            if repeat: task.cancel(); await asyncio.sleep(.02)
            assert not task.done()
            release.set()
            with pytest.raises(asyncio.CancelledError): await task
            assert value.backend.sends == 0 and all(not any(buffer) for buffer in value.resolver.buffers)
            reads, calls = value.backend.reads, len(value.calls)
            outcome = await action.call('outcome', principal)
            assert outcome['workflow_outcome'] == 'reconciliation_required'
            assert value.backend.reads == reads and len(value.calls) == calls
        finally:
            release.set()
            try: await task
            except asyncio.CancelledError: pass
    asyncio.run(scenario())


def test_queued_preview_cancellation_does_not_start_source_or_grant_reads(monkeypatch, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    settings, headers, scope, transport = bootstrap(tmp_path)
    principal = principal_for(settings, headers)
    value = make(monkeypatch, tmp_path, scope=scope, transport=transport)
    action = ApprovalDeliveryLocalMcpAction(value.workflow)
    reads, release = value.backend.reads, Event()
    async def scenario():
        loop = asyncio.get_running_loop(); loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
        entered = asyncio.Event()
        def occupy():
            loop.call_soon_threadsafe(entered.set)
            assert release.wait(3)
        busy = loop.run_in_executor(None, occupy)
        task = None
        try:
            await asyncio.wait_for(entered.wait(), 1)
            task = asyncio.create_task(action.call('preview', principal, phase='configure'))
            await asyncio.sleep(.02); task.cancel(); await asyncio.sleep(.02)
            assert not task.done()
            release.set(); await busy
            with pytest.raises(asyncio.CancelledError): await task
        finally:
            release.set()
            if task is not None:
                try: await task
                except asyncio.CancelledError: pass
    asyncio.run(scenario())
    assert value.backend.reads == reads and value.calls == [] and value.resolver.loads == 0


@pytest.mark.parametrize('foreign', ['requester', 'client'])
def test_foreign_cancellation_does_not_acquire_owned_revocation(monkeypatch, tmp_path, foreign):
    settings, headers, scope, transport = bootstrap(tmp_path)
    principal = principal_for(settings, headers)
    wrong = (replace(principal, requester=replace(principal.requester, subject_ref='synthetic-foreign-requester'))
        if foreign == 'requester' else replace(principal, transport_namespace_digest='f'*64))
    value = make(monkeypatch, tmp_path, scope=scope, transport=transport)
    action = ApprovalDeliveryLocalMcpAction(value.workflow); reads = value.backend.reads
    async def scenario():
        task = asyncio.create_task(action.call('preview', wrong, phase='configure'))
        await asyncio.sleep(.01); task.cancel()
        with pytest.raises(RuntimeError): await task
        assert not action._cancelled and value.workflow._enabled['configure']
        assert value.backend.reads == reads
        assert (await action.call('preview', principal, phase='configure'))['phase'] == 'configure'
    asyncio.run(scenario())


def test_cancel_racing_with_worker_completion_still_drains_disposal(monkeypatch, tmp_path):
    from fortipam_mcp import approval_delivery_local_mcp_action as module
    settings, headers, scope, transport = bootstrap(tmp_path)
    principal = principal_for(settings, headers)
    value = make(monkeypatch, tmp_path, scope=scope, transport=transport)
    action = ApprovalDeliveryLocalMcpAction(value.workflow)
    finish = module._finish_private_work
    raced, started, release, cleaned = [], Event(), Event(), []
    async def racing(callback, owner):
        result = await finish(callback, owner)
        if not raced:
            raced.append(True); owner._revoke(); raise asyncio.CancelledError
        return result
    def dispose():
        started.set(); assert release.wait(3); cleaned.append(True)
    monkeypatch.setattr(module, '_finish_private_work', racing)
    monkeypatch.setattr(action, '_dispose_private', dispose)
    async def scenario():
        task = asyncio.create_task(action.call('preview', principal, phase='configure'))
        try:
            assert await asyncio.to_thread(started.wait, 2)
            task.cancel(); await asyncio.sleep(.02)
            assert not task.done()
            release.set()
            with pytest.raises(asyncio.CancelledError): await task
            assert cleaned
        finally:
            release.set()
            try: await task
            except asyncio.CancelledError: pass
    asyncio.run(scenario())


def test_cancelled_queued_query_drains_without_acquiring_execution_revocation(monkeypatch, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    settings, headers, scope, transport = bootstrap(tmp_path)
    principal = principal_for(settings, headers)
    value = make(monkeypatch, tmp_path, scope=scope, transport=transport)
    action = ApprovalDeliveryLocalMcpAction(value.workflow); release = Event()
    async def scenario():
        loop = asyncio.get_running_loop(); loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
        entered = asyncio.Event()
        def occupy():
            loop.call_soon_threadsafe(entered.set); assert release.wait(3)
        busy = loop.run_in_executor(None, occupy)
        task = None
        try:
            await asyncio.wait_for(entered.wait(), 1)
            task = asyncio.create_task(action.call('outcome', principal))
            await asyncio.sleep(.02); task.cancel(); await asyncio.sleep(.02)
            assert not task.done() and not action._cancelled
            assert all(value.workflow._enabled.values())
            release.set(); await busy
            with pytest.raises(asyncio.CancelledError): await task
            assert (await action.call('preview', principal, phase='configure'))['phase'] == 'configure'
        finally:
            release.set()
            if task is not None:
                try: await task
                except asyncio.CancelledError: pass
    asyncio.run(scenario())


@pytest.mark.parametrize('repeat', [False, True])
def test_cancelled_http_preview_drains_wire_buffers_and_cookie_without_owner_logout(http_candidate, tmp_path, repeat):
    from fortipam_mcp.approval_delivery_local_workflow import ApprovalDeliveryLocalWorkflow
    settings, headers, scope, transport = bootstrap(tmp_path)
    principal = principal_for(settings, headers)
    value = http_candidate(tmp_path)
    # Only the fixed read is exercised here; no authority or PUT is bound to
    # this new caller's workflow. The backend keeps its original write pins.
    workflow = ApprovalDeliveryLocalWorkflow(value.intent, value.backend, value.evidence, value.resolver, value.recovery,
        value.execution, value.material, scope=scope, allowed_transport_digest=transport,
        source_guard=lambda: True, clock=value.peer.epoch)
    action = ApprovalDeliveryLocalMcpAction(workflow)
    started, release = Event(), Event()
    def hook(phase):
        if phase == 'read' and not started.is_set():
            started.set(); assert release.wait(3)
    value.peer.hook = hook
    async def scenario():
        task = asyncio.create_task(action.call('preview', principal, phase='configure'))
        try:
            assert await asyncio.to_thread(started.wait, 2)
            task.cancel(); await asyncio.sleep(.02)
            if repeat: task.cancel(); await asyncio.sleep(.02)
            assert not task.done()
            release.set()
            with pytest.raises(asyncio.CancelledError): await task
            assert not any(value.backend._window._cookie)
            assert all(not any(buffer) for buffer in value.peer.buffers)
            assert value.peer.writes == [] and value.resolver.loads == 0
            assert value.owner._client is not None and value.owner._session_lock.locked() and value.peer.credentials == 0
            assert (await action.call('outcome', principal))['workflow_outcome'] == 'not_started'
        finally:
            release.set()
            try: await task
            except asyncio.CancelledError: pass
    asyncio.run(scenario())


@pytest.mark.parametrize('lost_ack', [None, 'configure', 'restore'])
def test_real_unix_authority_dual_cas_and_normal_oauth_mcp(tmp_path, lost_ack):
    from test_fortitoken_local_mcp_action import unix_services
    settings, headers, scope, transport = bootstrap(tmp_path)
    with unix_services(tmp_path) as (reference, client, store, material):
        value = construct(tmp_path, client, opened=(store, material), scope=scope, transport=transport)
        reference.issue_many(tuple((value.policy.reference_for(phase, purpose), 'approval_delivery_'+purpose)
            for phase in ('configure', 'restore') for purpose in PURPOSES), requester_digest=scope.requester_digest,
            environment_ref=ENVIRONMENT, scope_ref=SCOPE_REF, expires_at=1120, now_epoch=1000)
        if lost_ack == 'configure': value.backend.fault = 'lost-ack'
        with TestClient(create_http_app(settings, v4_approval_delivery_local_candidate_action=ApprovalDeliveryLocalMcpAction(value.workflow)),
                base_url='https://mcp.example.com') as mcp:
            result, _ = rpc_phase(mcp, headers, 'configure')
            assert (result['structuredContent']['outcome'] == 'succeeded') is (lost_ack != 'configure')
            if lost_ack == 'configure':
                assert _call(mcp, headers, 'preview_v4_approval_delivery_local_restore_700', {})['isError']
            else:
                if lost_ack == 'restore': value.backend.fault = 'lost-ack'
                assert (rpc_phase(mcp, headers, 'restore')[0]['structuredContent']['outcome'] == 'succeeded') is (lost_ack is None)
            outcome = _call(mcp, headers, 'get_v4_approval_delivery_local_outcome_700', {})['structuredContent']
            assert outcome['workflow_outcome'] == ('verified_locally' if lost_ack is None else 'reconciliation_required')
            assert not outcome['native_backend_qualified'] and not outcome['polling_and_approval_effects_verified']
            assert value.backend.sends == store.claim_count == material.claim_count == (1 if lost_ack == 'configure' else 2)
        assert value.workflow._closed
        assert all(not any(buffer) for buffer in value.backend.buffers + value.resolver.buffers + value.recovery.buffers)


@pytest.mark.parametrize('lost_ack', [None, 'configure', 'restore'])
def test_real_tls_cookie_put_unix_authority_dual_cas_and_normal_mcp(source_candidate, tmp_path, monkeypatch, lost_ack):
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from fortipam_mcp.approval_delivery_authority import ApprovalDeliveryProtectedLabAuthority
    from fortipam_mcp.approval_delivery_execution_contract import ApprovalDeliveryExecutionIntent, readback_from_approval_source
    from fortipam_mcp.approval_delivery_http_backend import ApprovalDeliveryHttpBackend
    from fortipam_mcp.approval_delivery_local_workflow import ApprovalDeliveryLocalWorkflow
    from fortipam_mcp.approval_delivery_m4 import approval_delivery_execution_digests
    from fortipam_mcp.approval_delivery_source import ApprovalDeliverySource, CURRENT_PATH
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from test_approval_delivery_contract import state
    from test_approval_delivery_http_backend import Peer, Witness, COOKIE, CSRF, OPAQUE
    from test_approval_delivery_material import Resolver
    from test_approval_delivery_material_contract import BINDINGS
    from test_approval_delivery_m4 import NEW_BINDINGS, NEW_MATERIAL, Evidence
    from test_approval_delivery_source import ACTOR
    from test_fortitoken_local_mcp_action import unix_services
    from test_secret_bulk_import_action_process import tls_material
    from test_system_email_authority import owner_file

    settings, headers, scope, transport = bootstrap(tmp_path)
    certificate, key = tls_material(tmp_path)
    peer = Peer(); requests, writes, connections, buffers = [], [], [], []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *_): pass
        def reply(self, document):
            raw = json.dumps(document).encode()
            self.send_response(200); self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw))); self.send_header('Connection', 'close')
            self.end_headers(); self.wfile.write(raw)
        def do_GET(self):
            requests.append(('GET', self.path))
            assert self.path == CURRENT_PATH and self.headers['Cookie'] == COOKIE
            assert self.headers.get('Authorization') is None
            self.reply(peer.payload)
        def do_PUT(self):
            requests.append(('PUT', self.path))
            assert self.path == CURRENT_PATH and self.headers['Cookie'] == COOKIE
            assert self.headers['X-CSRFTOKEN'] == CSRF and self.headers.get('Authorization') is None
            peer.payload['results']['approval-email-setting'] = json.loads(self.rfile.read(int(self.headers['Content-Length'])))['approval-email-setting']
            writes.append(True)
            if lost_ack == ('configure' if len(writes) == 1 else 'restore'):
                self.close_connection = True; self.connection.shutdown(socket.SHUT_RDWR)
                return
            self.reply(dict(http_method='PUT', http_status=200, status='success', serial='SYNTHETIC01',
                version='v7.0.0', build=29, path='secret', name='setting', revision=OPAQUE))
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(certificate, key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True); thread.start()
    original_readinto = http.client.HTTPResponse.readinto
    def tracked(response, view):
        if not any(buffer is view.obj for buffer in buffers): buffers.append(view.obj)
        return original_readinto(response, view)
    monkeypatch.setattr(http.client.HTTPResponse, 'readinto', tracked)
    def factory(host, port, **options):
        assert host == 'pam.example.test' and options['context'].check_hostname
        connection = http.client.HTTPSConnection(host, port, **options)
        connection._create_connection = lambda address, timeout, source_address: socket.create_connection(
            ('127.0.0.1', server.server_port), timeout, source_address)
        connections.append(connection); return connection
    backend = None
    try:
        _, prototype, owner = source_candidate(); prototype.close()
        owner._client, owner._clock, owner._raw_connection_factory = peer.client(), peer.clock, factory
        owner._config = SecretMetadataHttpTransportConfig('https://pam.example.test', 'synthetic-unused-bearer', 5, str(certificate))
        with unix_services(tmp_path) as (reference, client, store, material):
            source = ApprovalDeliverySource(owner, expected_actor=ACTOR, expected_serial='SYNTHETIC01',
                material_binding_digests=BINDINGS, source_guard=lambda: True)
            source.read()
            original = readback_from_approval_source(source, source_digest=scope.configuration_source_digest, clock=peer.epoch)
            intent = ApprovalDeliveryExecutionIntent(original, {**state('ms-graph'), 'port': 994}, enabled=True,
                original_material_bindings=BINDINGS, proposed_material_bindings=NEW_BINDINGS)
            backend = ApprovalDeliveryHttpBackend(owner, intent, approval_delivery_execution_digests(intent, scope, store, material)[2],
                expected_actor=ACTOR, expected_serial='SYNTHETIC01', source_digest=scope.configuration_source_digest,
                clock=peer.epoch, execution_enabled=True, source_guard=lambda: True)
            evidence = Evidence(Witness(peer), intent)
            resolver = Resolver(intent.material_binding().material_binding_digest); resolver.values = NEW_MATERIAL
            recovery = Resolver(intent.material_binding(restore=True).material_binding_digest)
            policy = ApprovalDeliveryProtectedLabAuthority(intent, scope, backend, evidence, recovery, store, material,
                reference_authority=client, authority_key_file=owner_file(tmp_path/'policy.key', b'p'*32), transport_digest=transport,
                environment_ref=ENVIRONMENT, scope_ref=SCOPE_REF, audience_ref='approval_delivery-test-audience',
                execution_enabled=True, source_guard=lambda: True, clock=peer.epoch)
            workflow = ApprovalDeliveryLocalWorkflow(intent, backend, evidence, resolver, recovery, store, material,
                scope=scope, allowed_transport_digest=transport, authority=policy, configure_enabled=True, restore_enabled=True,
                source_guard=lambda: True, clock=peer.epoch)
            reference.issue_many(tuple((policy.reference_for(phase, purpose), 'approval_delivery_'+purpose)
                for phase in ('configure', 'restore') for purpose in PURPOSES), requester_digest=scope.requester_digest,
                environment_ref=ENVIRONMENT, scope_ref=SCOPE_REF, expires_at=1120, now_epoch=1000)
            with TestClient(create_http_app(settings, v4_approval_delivery_local_candidate_action=ApprovalDeliveryLocalMcpAction(workflow)),
                    base_url='https://mcp.example.com') as mcp:
                result, _ = rpc_phase(mcp, headers, 'configure')
                assert (result['structuredContent']['outcome'] == 'succeeded') is (lost_ack != 'configure')
                if lost_ack == 'configure':
                    assert _call(mcp, headers, 'preview_v4_approval_delivery_local_restore_700', {})['isError']
                else:
                    assert (rpc_phase(mcp, headers, 'restore')[0]['structuredContent']['outcome'] == 'succeeded') is (lost_ack is None)
                count = len(requests)
                outcome = _call(mcp, headers, 'get_v4_approval_delivery_local_outcome_700', {})['structuredContent']
                assert outcome['workflow_outcome'] == ('verified_locally' if lost_ack is None else 'reconciliation_required')
                assert len(requests) == count and not outcome['native_backend_qualified']
                assert len(writes) == store.claim_count == material.claim_count == (1 if lost_ack == 'configure' else 2)
            assert backend._closed and backend._window._closed and not any(backend._window._cookie)
            assert owner._client is not None and owner._session_lock.locked() and peer.credentials == 0
            assert all(not any(buffer) for buffer in buffers + resolver.buffers + recovery.buffers)
            assert all(connection.sock is None for connection in connections)
    finally:
        if backend is not None: backend.close()
        server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
