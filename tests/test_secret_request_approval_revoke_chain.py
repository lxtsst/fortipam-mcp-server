"""Real resolver/workflow/transport chain with synthetic device HTTP only."""
import httpx

from fortipam_mcp.secret_request_approval_revoke_resolver import OwnerOnlySecretRequestApprovalRevokeResolver
from fortipam_mcp.secret_request_approval_revoke_live_workflow import SecretRequestApprovalRevokeLiveWorkflow
from test_secret_request_approval_revoke_resolver import _setup
from test_secret_request_approval_revoke_http_transport import _Lab
from test_secret_request_approval_revoke_detail_contract import _NOW, _Clock


def test_bound_provenance_to_single_native_dispatch_and_restart(tmp_path, monkeypatch):
    args, _ = _setup(tmp_path)
    resolver = OwnerOnlySecretRequestApprovalRevokeResolver(**args)
    lab = _Lab(tmp_path)
    lab.claim = tmp_path / "withdrawal.claim"
    lab.request['results'][0].update({'tier-last-sent': 1, 'tier2-status': 'pending', 'tier3-status': 'pending'})
    original = lab.handler
    def handler(request):
        response = original(request)
        if request.method != 'DELETE':
            return response
        lab.request['results'][0].update({'final-status': 'pending', 'tier1-status': 'pending',
            'tier1': [], 'tier-last-sent': 0, 'start-time': '0000-00-00 00:00:00',
            'expiration-time': '0000-00-00 00:00:00'})
        return httpx.Response(200, json={'status': 'OK', 'http_status': 200,
            'http_method': 'DELETE', 'vdom': '', 'path': 'secret', 'name': 'request-approval',
            'msg': 'Successfully deleted approval entry'})
    lab.handler = handler
    monkeypatch.setattr('fortipam_mcp.secret_request_http_transport.datetime', _Clock)
    monkeypatch.setattr('fortipam_mcp.secret_request_approval_revoke_http_transport.time.time', lambda: _NOW.timestamp())
    key = tmp_path / 'workflow.key'
    key.write_bytes(b'w' * 32)
    key.chmod(0o600)
    kwargs = dict(database=tmp_path/'workflow.db', hmac_key_file=key, transport=lab.transport(),
        resolver=resolver, allowed_requester_digest='a'*64, allowed_transport_digest='b'*64,
        execution_enabled=True, clock=lambda: int(_NOW.timestamp()))
    actor = dict(requester_digest='a'*64, transport_digest='b'*64)
    workflow = SecretRequestApprovalRevokeLiveWorkflow(**kwargs)
    preview = workflow.preview(**actor)
    auth = workflow.authorize(preview['preview_ref'], **actor)
    result = workflow.execute(auth['authorization_ref'], **actor)
    assert result['outcome'] == 'succeeded'
    assert result['backend_launch_denial_requires_independent_evidence'] is True
    calls = list(lab.calls)
    restarted = SecretRequestApprovalRevokeLiveWorkflow(**kwargs)
    replay = restarted.execute(auth['authorization_ref'], **actor)
    assert replay['idempotent_replay'] and replay['outcome'] == 'succeeded'
    assert lab.calls == calls and len(lab.deletes) == 1
