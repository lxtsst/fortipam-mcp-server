"""Behavior checks for exact clone ownership, preservation and replay denial."""
from copy import deepcopy
from urllib.parse import parse_qs, unquote

import httpx
import pytest

from fortipam_mcp.launcher_clone_http_transport import (
    FortiPamLauncherCloneHttpTransport, LauncherCloneBinding,
    LauncherCloneTransportError, configuration_digest,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig

SOURCE = 'mcp-v4-launcher-test-b97'
DESTINATION = 'mcp-v4-launcher-clone-test-r2'


class Appliance:
    def __init__(self):
        self.rows = {SOURCE: {
            'name': SOURCE, 'q_origin_key': SOURCE, 'q_ref': 0, 'q_static': False,
            'type': 'rdp', 'launch-timeout': 30, 'preserved-setting': 'unchanged',
            'os_app': [{'exe': 'mstsc.exe', 'parameter': '/V:$HOST:$PORT /noConsentPrompt',
                'init-commands': [{'id': 1, 'q_origin_key': 1, 'cmd': 'cmdkey /generic:$HOST /user:$USER /pass:$PASSWORD'}],
                'clean-commands': [{'id': 1, 'q_origin_key': 1, 'cmd': 'cmdkey /del:$HOST'}]}]}}
        self.calls = []
        self.lose_response = False

    def projection(self):
        return [{'name': name, 'type': row['type'], 'q_ref': row['q_ref'], 'q_static': row['q_static']}
                for name, row in self.rows.items()]

    def handle(self, request):
        self.calls.append(request)
        name = unquote(request.url.path.rsplit('/', 1)[-1])
        query = parse_qs(request.url.query.decode())
        status, result = 200, None
        if request.method == 'POST':
            assert name == SOURCE and query == {'action': ['clone'], 'nkey': [DESTINATION], 'vdom': ['root']}
            assert request.content == b'' and DESTINATION not in self.rows
            self.rows[DESTINATION] = dict(deepcopy(self.rows[SOURCE]), name=DESTINATION, q_origin_key=DESTINATION)
            if self.lose_response:
                raise httpx.ReadTimeout('private diagnostic must not escape')
        elif request.method == 'DELETE':
            assert name == DESTINATION and request.content == b''
            del self.rows[name]
        elif name == 'launcher':
            result = self.projection()
        elif name in self.rows:
            result = [self.rows[name]]
        else:
            status = 404
        body = {'version': 'v7.0.0', 'build': 29, 'path': 'secret', 'name': 'launcher',
                'http_method': request.method, 'http_status': status, 'vdom': 'root',
                'status': 'success' if status == 200 else 'error', 'results': result}
        if name == 'launcher':
            body.update(matched_count=len(result), limit_reached=False)
        return httpx.Response(status, json=body)

    def binding(self):
        proposed = dict(deepcopy(self.rows[SOURCE]), name=DESTINATION, q_origin_key=DESTINATION)
        return LauncherCloneBinding(SOURCE, DESTINATION, configuration_digest(self.rows[SOURCE]),
            configuration_digest(proposed), configuration_digest({r['name']: configuration_digest(r) for r in self.projection()}))


def adapter(tmp_path, device, binding=None, **gates):
    tmp_path = tmp_path.resolve()
    tmp_path.chmod(0o700)
    config = SecretMetadataHttpTransportConfig(base_url='https://pam.example', bearer_token='synthetic-token', timeout_seconds=5, ca_file=None)
    return FortiPamLauncherCloneHttpTransport(config, binding or device.binding(), tmp_path,
        client_factory=lambda **kw: httpx.Client(transport=httpx.MockTransport(device.handle), **kw), **gates)


def test_clone_recovery_preserves_all_fields_and_consumes_both_directions(tmp_path):
    device = Appliance(); baseline = deepcopy(device.rows); binding = device.binding()
    transport = adapter(tmp_path, device, binding, clone_enabled=True, recovery_enabled=True)
    assert transport.inspect()['source_preserved']
    assert transport.execute()['clone_present']
    assert device.rows[DESTINATION]['preserved-setting'] == 'unchanged'
    assert transport.execute(recovery=True)['clone_present'] is False
    assert device.rows == baseline
    fresh = adapter(tmp_path, device, binding, clone_enabled=True, recovery_enabled=True)
    count = len(device.calls)
    for recovery in (False, True):
        with pytest.raises(LauncherCloneTransportError):fresh.execute(recovery=recovery)
    assert len(device.calls) == count
    assert [r.method for r in device.calls if r.method != 'GET'] == ['POST', 'DELETE']
    for p in tmp_path.iterdir():
        assert p.stat().st_mode & 0o777 == 0o600
        assert SOURCE not in p.read_text() and '$PASSWORD' not in p.read_text()


def test_default_gate_and_unowned_recovery_refuse_before_network(tmp_path):
    device = Appliance(); transport = adapter(tmp_path, device)
    with pytest.raises(LauncherCloneTransportError):transport.execute()
    transport = adapter(tmp_path, device, recovery_enabled=True)
    with pytest.raises(LauncherCloneTransportError):transport.execute(recovery=True)
    assert device.calls == []


def test_lost_post_response_is_non_replayable_and_not_cleanup_authority(tmp_path):
    device = Appliance(); binding = device.binding(); device.lose_response = True
    transport = adapter(tmp_path, device, binding, clone_enabled=True, recovery_enabled=True)
    with pytest.raises(LauncherCloneTransportError, match='unavailable') as failure:transport.execute()
    assert 'private diagnostic' not in str(failure.value)
    assert DESTINATION in device.rows and (tmp_path / 'clone.claim.json').exists()
    assert not (tmp_path / 'clone.verified.json').exists()
    count = len(device.calls)
    fresh = adapter(tmp_path, device, binding, clone_enabled=True, recovery_enabled=True)
    for recovery in (False, True):
        with pytest.raises(LauncherCloneTransportError):fresh.execute(recovery=recovery)
    assert len(device.calls) == count


def test_source_drift_and_retired_destination_refused(tmp_path):
    device = Appliance(); binding = device.binding()
    device.rows[SOURCE]['preserved-setting'] = 'drift'
    with pytest.raises(LauncherCloneTransportError):adapter(tmp_path, device, binding, clone_enabled=True).execute()
    assert all(r.method == 'GET' for r in device.calls)
    assert not (tmp_path / 'clone.claim.json').exists()
    with pytest.raises(LauncherCloneTransportError):
        LauncherCloneBinding(SOURCE, 'mcp-v4-launcher-clone-mini-r1', binding.source_digest, binding.clone_digest, binding.collection_digest)


def test_workflow_requester_expiry_and_durable_intent(tmp_path):
    from fortipam_mcp.launcher_clone_live_workflow import LauncherCloneLiveWorkflow, LauncherCloneWorkflowError
    device = Appliance(); binding = device.binding(); clock = [100]
    transport = adapter(tmp_path, device, binding, clone_enabled=True, recovery_enabled=True)
    flow = LauncherCloneLiveWorkflow(transport, clock=lambda: clock[0])
    preview = flow.preview(requester_digest='a' * 64)
    count = len(device.calls)
    with pytest.raises(LauncherCloneWorkflowError):flow.confirm(preview['preview_ref'], requester_digest='b' * 64)
    assert len(device.calls) == count
    clock[0] = 700
    with pytest.raises(LauncherCloneWorkflowError):flow.confirm(preview['preview_ref'], requester_digest='a' * 64)
    preview = flow.preview(requester_digest='a' * 64)
    auth = flow.confirm(preview['preview_ref'], requester_digest='a' * 64)
    count = len(device.calls)
    with pytest.raises(LauncherCloneWorkflowError):flow.execute(auth['authorization_ref'], requester_digest='b' * 64)
    assert len(device.calls) == count
    assert flow.execute(auth['authorization_ref'], requester_digest='a' * 64)['outcome'] == 'succeeded'
    fresh = LauncherCloneLiveWorkflow(adapter(tmp_path, device, binding, clone_enabled=True))
    count = len(device.calls)
    with pytest.raises(LauncherCloneWorkflowError):fresh.preview(requester_digest='a' * 64)
    assert len(device.calls) == count
    recovery = LauncherCloneLiveWorkflow(transport, recovery=True)
    preview = recovery.preview(requester_digest='a' * 64)
    auth = recovery.confirm(preview['preview_ref'], requester_digest='a' * 64)
    assert recovery.execute(auth['authorization_ref'], requester_digest='a' * 64)['outcome'] == 'succeeded'
    assert DESTINATION not in device.rows


def test_workflow_uncertain_dispatch_retains_intent_and_denies_replay(tmp_path):
    from fortipam_mcp.launcher_clone_live_workflow import LauncherCloneLiveWorkflow, LauncherCloneWorkflowError
    device = Appliance(); device.lose_response = True
    flow = LauncherCloneLiveWorkflow(adapter(tmp_path, device, clone_enabled=True))
    preview = flow.preview(requester_digest='a' * 64)
    auth = flow.confirm(preview['preview_ref'], requester_digest='a' * 64)
    assert flow.execute(auth['authorization_ref'], requester_digest='a' * 64)['outcome'] == 'reconciliation_required'
    assert (tmp_path / 'clone.intent.json').exists()
    count = len(device.calls)
    with pytest.raises(LauncherCloneWorkflowError):flow.execute(auth['authorization_ref'], requester_digest='a' * 64)
    assert len(device.calls) == count


def test_clone_tools_have_no_resource_or_direction_inputs_and_default_gates_are_closed(tmp_path):
    import asyncio
    from types import SimpleNamespace
    from fortipam_mcp.server import MCP_SERVER_CLASS
    from fortipam_mcp.launcher_clone_live_workflow import LauncherCloneLiveWorkflow
    from fortipam_mcp.launcher_clone_mcp_action import (
        PREFIX, LauncherCloneActions, LauncherCloneMcpAction,
        build_launcher_clone_candidate, register_launcher_clone_tools,
    )
    device = Appliance(); flow = LauncherCloneLiveWorkflow(adapter(tmp_path, device))
    action = LauncherCloneMcpAction(flow)
    with pytest.raises(RuntimeError):action.execute('opaque', None)
    with pytest.raises(RuntimeError):action.preview(None)
    assert device.calls == []
    assert build_launcher_clone_candidate({}) is None
    for key in ('EXECUTION_ENABLED', 'RECOVERY_EXECUTION_ENABLED'):
        with pytest.raises(ValueError):build_launcher_clone_candidate({PREFIX + key: 'true'})
    server = SimpleNamespace(mcp=MCP_SERVER_CLASS('launcher-clone'))
    register_launcher_clone_tools(server, LauncherCloneActions(action, action))
    tools = asyncio.run(server.mcp.list_tools())
    assert len(tools) == 6
    for tool in tools:
        expected = set() if tool.name.startswith('preview') else {'preview_ref'} if tool.name.startswith('confirm') else {'authorization_ref'}
        assert set(tool.input_schema.get('properties', {})) == expected


def test_intent_expiring_during_prewrite_read_cannot_dispatch(tmp_path, monkeypatch):
    from fortipam_mcp.launcher_clone_live_workflow import LauncherCloneLiveWorkflow, LauncherCloneWorkflowError
    device = Appliance(); clock = [100]
    transport = adapter(tmp_path, device, clone_enabled=True)
    flow = LauncherCloneLiveWorkflow(transport, clock=lambda: clock[0])
    preview = flow.preview(requester_digest='a' * 64)
    auth = flow.confirm(preview['preview_ref'], requester_digest='a' * 64)
    inspect = transport.inspect
    def slow_inspect(**kwargs):
        result = inspect(**kwargs)
        clock[0] = 700
        return result
    monkeypatch.setattr(transport, 'inspect', slow_inspect)
    with pytest.raises(LauncherCloneWorkflowError):flow.execute(auth['authorization_ref'], requester_digest='a' * 64)
    assert all(r.method == 'GET' for r in device.calls)
    assert not (tmp_path / 'clone.intent.json').exists()
