import json
from copy import deepcopy

import httpx
import pytest

from fortipam_mcp.job_request_approve_http_transport import (
    FortiPamJobRequestApproveHttpTransport, JobRequestApproveBinding, JobRequestApproveHttpTransportError, JobRequestApproveInspection,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_job_request_approve_contract import REQUEST as ROW, JOB, DETAIL, NOW, START, SCHEDULE, envelope


@pytest.mark.parametrize('case', ['approved', 'ambiguous', 'queue_absent', 'wrong_actor', 'logout_live', 'inspect', 'drift', 'time_elapsed', 'job_read_unavailable', 'delayed_readback', 'stale_readback'])
def test_single_approval_reconciliation_and_prelogin_replay(tmp_path, monkeypatch, caplog, case):
    tmp_path.chmod(0o700)
    claim = tmp_path / 'claim.json'
    binding = JobRequestApproveBinding(19, 7, ROW['job-name'], ROW['user'], 'synthetic-reviewer')
    calls = []
    review_calls = []
    state_reads = 0
    detail_reads = 0
    sleeps = []

    def actor(raw, *, expected_name):
        if case == 'wrong_actor': raise ValueError('private upstream state')
        return {'name': expected_name}

    monkeypatch.setattr('fortipam_mcp.job_request_approve_http_transport._actor_context', actor)

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
            ready = detail_reads > 1 and (case != 'delayed_readback' or detail_reads >= 6) and case != 'stale_readback'
            if ready: row.update({'final-status': 'approved', 'tier1-status': 'approved'})
            return httpx.Response(200, json=envelope(row))
        if request.url.path == '/api/v2/internal/request-review':
            assert claim.exists() and (claim.stat().st_mode & 0o777) == 0o600
            payload = json.loads(request.content)
            assert payload['approval-status'] == 'approved' and payload['request-id'] == 19
            assert payload['expiration-time'] == ROW['expiration-time']
            assert 'X-CSRFTOKEN' in request.headers
            review_calls.append(payload)
            if case == 'ambiguous': raise httpx.ReadTimeout('private transport failure')
            return httpx.Response(200)
        return httpx.Response(200)

    def factory(**kwargs):
        return httpx.Client(**kwargs, transport=httpx.MockTransport(handler))

    def job_reader():
        if case=='job_read_unavailable':raise RuntimeError('private upstream failure')
        return envelope([{**deepcopy(JOB),'approval-status':'approved' if review_calls else 'pending'}],name='job',method='POST')

    transport = FortiPamJobRequestApproveHttpTransport(
        SecretMetadataHttpTransportConfig('https://synthetic.invalid', 'unused-token', 1, None),
        binding, lambda: ('synthetic-reviewer', 'synthetic-password'), claim_path=claim, client_factory=factory, sleep=sleeps.append, clock=lambda:SCHEDULE-60 if case=="time_elapsed" else NOW, job_reader=job_reader,
        job_detail_reader=lambda:envelope(deepcopy(DETAIL),name="job",status="success"),
    )
    if case in {'queue_absent', 'wrong_actor', 'logout_live', 'drift', 'time_elapsed', 'job_read_unavailable'}:
        with pytest.raises(JobRequestApproveHttpTransportError, match='^The fixed Job Request approval transport is unavailable.$'):
            transport.approve_and_readback(JobRequestApproveInspection('a'*64) if case=='drift' else None)
    elif case=='inspect':
        assert isinstance(transport.inspect(),JobRequestApproveInspection)
    else:
        result = transport.approve_and_readback()
        assert result.dispatch_consumed and result.reviewer_logout_verified
        assert result.approved_and_scheduled_window_verified == (case != 'stale_readback')
        assert result.http_accepted == (case != 'ambiguous')
        if case == 'delayed_readback': assert sleeps == [0.25, 0.5, 1.0, 2.0]
        if case == 'stale_readback':
            assert sleeps == [0.25, 0.5, 1.0, 2.0, 4.0]
            assert 'approved_window_verified=False' in caplog.text
            assert 'http_accepted=True' in caplog.text
            assert 'reviewer_logout_verified=True' in caplog.text
        assert 'synthetic' not in caplog.text and 'private' not in caplog.text
    assert len(review_calls) == (0 if case in {'queue_absent', 'wrong_actor', 'inspect', 'drift', 'time_elapsed', 'job_read_unavailable'} else 1)
    assert ('GET', '/logout') in calls
    if claim.exists():
        count = len(calls)
        fresh = FortiPamJobRequestApproveHttpTransport(
            transport._config, binding, lambda: pytest.fail('credentials accessed during replay'),
            claim_path=claim, client_factory=lambda **kwargs: pytest.fail('network accessed during replay'),
            job_reader=lambda:pytest.fail('Job read during replay'))
        with pytest.raises(JobRequestApproveHttpTransportError): fresh.approve_and_readback()
        assert len(calls) == count
    else:
        assert case in {'queue_absent', 'wrong_actor', 'inspect', 'drift', 'time_elapsed', 'job_read_unavailable'}
    assert 'synthetic-reviewer' not in repr(binding)
    assert not claim.exists() or 'synthetic-password' not in claim.read_text()
