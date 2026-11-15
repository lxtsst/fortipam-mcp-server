import json
from copy import deepcopy

import httpx
import pytest

from fortipam_mcp.job_request_deny_http_transport import (
    FortiPamJobRequestDenyHttpTransport, JobRequestDenyBinding, JobRequestDenyHttpTransportError, JobRequestDenyInspection,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_job_request_deny_contract import ROW, envelope


@pytest.mark.parametrize('case', ['denied', 'ambiguous', 'queue_absent', 'wrong_actor', 'logout_live', 'inspect', 'drift'])
def test_single_denial_reconciliation_and_prelogin_replay(tmp_path, monkeypatch, case):
    tmp_path.chmod(0o700)
    claim = tmp_path / 'claim.json'
    binding = JobRequestDenyBinding(19, 7, ROW['job-name'], ROW['user'], 'synthetic-reviewer')
    calls = []
    review_calls = []
    state_reads = 0
    detail_reads = 0

    def actor(raw, *, expected_name):
        if case == 'wrong_actor': raise ValueError('private upstream state')
        return {'name': expected_name}

    monkeypatch.setattr('fortipam_mcp.job_request_deny_http_transport._actor_context', actor)

    def handler(request):
        nonlocal state_reads, detail_reads
        calls.append((request.method, request.url.path))
        if request.url.path == '/remote/login':
            return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH">')
        if request.url.path == '/XX/YY/ZZ/AUTH':
            return httpx.Response(303, headers={'Location': '/', 'Set-Cookie': 'ccsrftoken="synthetic-csrf"; Path=/'})
        if request.url.path == '/api/v2/monitor/web-ui/state':
            state_reads += 1
            if state_reads > 1 and case != 'logout_live': return httpx.Response(401)
            return httpx.Response(200, json={'results': {'ccsrf_token_cookie_name': 'ccsrftoken'}})
        if request.url.path == '/api/v2/cmdb/secret/request':
            assert request.headers['X-Http-Method-Override'] == 'GET'
            return httpx.Response(200, json=envelope([] if case == 'queue_absent' else [deepcopy(ROW)], method="POST"))
        if request.url.path == '/api/v2/cmdb/secret/request/19':
            detail_reads += 1
            row = deepcopy(ROW)
            if detail_reads > 1: row.update({'final-status': 'denied', 'tier1-status': 'denied'})
            return httpx.Response(200, json=envelope(row))
        if request.url.path == '/api/v2/internal/request-review':
            assert claim.exists() and (claim.stat().st_mode & 0o777) == 0o600
            payload = json.loads(request.content)
            assert payload['approval-status'] == 'denied' and payload['request-id'] == 19
            assert payload['expiration-time'] == ROW['expiration-time']
            assert 'X-CSRFTOKEN' in request.headers
            review_calls.append(payload)
            if case == 'ambiguous': raise httpx.ReadTimeout('private transport failure')
            return httpx.Response(200)
        return httpx.Response(200)

    def factory(**kwargs):
        return httpx.Client(**kwargs, transport=httpx.MockTransport(handler))

    transport = FortiPamJobRequestDenyHttpTransport(
        SecretMetadataHttpTransportConfig('https://synthetic.invalid', 'unused-token', 1, None),
        binding, lambda: ('synthetic-reviewer', 'synthetic-password'), claim_path=claim, client_factory=factory,
    )
    if case in {'queue_absent', 'wrong_actor', 'logout_live', 'drift'}:
        with pytest.raises(JobRequestDenyHttpTransportError, match='^The fixed Job Request denial transport is unavailable.$'):
            transport.deny_and_readback(JobRequestDenyInspection('a'*64) if case=='drift' else None)
    elif case=='inspect':
        assert isinstance(transport.inspect(),JobRequestDenyInspection)
    else:
        result = transport.deny_and_readback()
        assert result.dispatch_consumed and result.denied_and_schedule_preserved and result.reviewer_logout_verified
        assert result.http_accepted == (case == 'denied')
    assert len(review_calls) == (0 if case in {'queue_absent', 'wrong_actor', 'inspect', 'drift'} else 1)
    assert ('GET', '/logout') in calls
    if claim.exists():
        count = len(calls)
        fresh = FortiPamJobRequestDenyHttpTransport(
            transport._config, binding, lambda: pytest.fail('credentials accessed during replay'),
            claim_path=claim, client_factory=lambda **kwargs: pytest.fail('network accessed during replay'))
        with pytest.raises(JobRequestDenyHttpTransportError): fresh.deny_and_readback()
        assert len(calls) == count
    else:
        assert case in {'queue_absent', 'wrong_actor', 'inspect', 'drift'}
    assert 'synthetic-reviewer' not in repr(binding)
    assert not claim.exists() or 'synthetic-password' not in claim.read_text()
