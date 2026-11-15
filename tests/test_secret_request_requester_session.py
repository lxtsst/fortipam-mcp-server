"""Fixed requester identity and cleanup tests; no credential or Request writes."""
import json

import httpx
import pytest

from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.secret_request_requester_session import (
    FixedSecretRequestRequesterSession, SecretRequestRequesterSessionError,
)

NAME = "mcp-v4-user-bp005-standard-20261002-1234abcd"


@pytest.mark.parametrize("case", ["valid", "wrong_relation", "logout_live"])
def test_bound_mcp_observation_uses_fresh_cookie_session_and_verified_logout(
    tmp_path, monkeypatch, case,
):
    from test_secret_request_create_http_transport import _principal
    from fortipam_mcp import secret_request_requester_session as module
    from fortipam_mcp.secret_request_http_transport import (
        OwnerOnlySecretRequestObservationBindingResolver,
    )
    from fortipam_mcp.secret_request_mcp_observation import (
        ProtectedSecretRequestMcpObservation,
        V4_SECRET_REQUEST_OBSERVATION_AUTHENTICATION_ENV,
        build_v4_secret_request_observation_transport,
    )
    from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
    from v4_planning.models import AuthenticatedRequester

    logins, logged_out, calls = [], set(), []

    def handler(req):
        calls.append((req.method, req.url.path))
        assert "authorization" not in req.headers
        if req.url.path == "/remote/login":
            return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH"></form>')
        if req.url.path == "/XX/YY/ZZ/AUTH":
            logins.append(True)
            return httpx.Response(303, headers={"location": "/landing",
                "set-cookie": f"session=synthetic-{len(logins)}; Path=/; Secure"})
        cookie = req.headers["cookie"].split(";", 1)[0]
        if req.url.path == "/landing":
            return httpx.Response(200, headers={"set-cookie": "csrf=synthetic-csrf; Path=/; Secure"})
        if req.url.path == "/logout":
            logged_out.add(cookie)
            return httpx.Response(200)
        if req.url.path == "/api/v2/monitor/web-ui/state":
            if cookie in logged_out and case != "logout_live":
                return httpx.Response(401)
            return httpx.Response(200, json={"http_method": "GET", "http_status": 200,
                "status": "success", "version": "v7.0.0", "build": 29,
                "path": "web-ui", "name": "state", "results": {"admin": {
                    "name": NAME, "login_name": NAME, "sponsored_group_name": "",
                    "guest_admin": False}, "ccsrf_token_cookie_name": "csrf"}})
        assert req.method == "GET" and req.url.path == "/api/v2/cmdb/secret/request/71"
        return httpx.Response(200, json={"http_method": "GET", "http_status": 200,
            "status": "success", "version": "v7.0.0", "build": 29, "vdom": "root",
            "path": "secret", "name": "request", "results": [{
                "secret-id": 84 if case == "wrong_relation" else 83,
                "request-type": "launcher", "final-status": "pending",
                "tier1-status": "pending"}]})

    config = SecretMetadataHttpTransportConfig("https://synthetic.invalid", "unused-token", 1, None)
    prototype = FixedSecretRequestRequesterSession(config, requester=NAME,
        credentials=lambda: (NAME, "synthetic-password"),
        client_factory=lambda **kw: httpx.Client(**kw, transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(module, "build_bp005_requester_session", lambda c, e: prototype)
    transport = build_v4_secret_request_observation_transport(config, {
        V4_SECRET_REQUEST_OBSERVATION_AUTHENTICATION_ENV: "bp005-requester-session"})
    principal = _principal()
    ref = "synthetic-observation-ref01"
    path = tmp_path / "binding.json"
    path.write_text(json.dumps({"contract": "fortipam-secret-request-observation-binding-v1",
        "version": "1.0.0", "request_ref": ref, "request_id": 71, "secret_id": 83,
        "requester_digest": principal.requester.digest, "environment_ref": "synthetic-environment-ref01",
        "scope_ref": "synthetic-scope-ref01", "request_type": "launcher"}))
    path.chmod(0o600)
    reader = ProtectedSecretRequestMcpObservation(transport,
        OwnerOnlySecretRequestObservationBindingResolver(path))
    other = V4PlanningPrincipal(AuthenticatedRequester("other-observer-ref01", "operator"), "b" * 64)
    with pytest.raises(RuntimeError):
        reader.observe(ref, other)
    assert not calls  # Caller rejection happens before any credential or network use.
    if case == "valid":
        first, second = reader.observe(ref, principal), reader.observe(ref, principal)
        assert first == second and first["lifecycle_state"] == "pending"
        assert first["raw_values_returned"] is False
        assert len(logins) == len(logged_out) == 2
    else:
        with pytest.raises(RuntimeError, match="observation is unavailable"):
            reader.observe(ref, principal)
        assert len(logins) == len(logged_out) == 1
    assert all(method != "POST" or path == "/XX/YY/ZZ/AUTH" for method, path in calls)


@pytest.mark.parametrize("mode", [None, "api-bearer", "unknown-mode"])
def test_observation_authentication_mode_preserves_bearer_default_and_fails_closed(mode):
    from fortipam_mcp.secret_request_http_transport import (
        FortiPamSecretRequestHttpTransport, SecretRequestHttpTransportError,
    )
    from fortipam_mcp.secret_request_mcp_observation import (
        V4_SECRET_REQUEST_OBSERVATION_AUTHENTICATION_ENV,
        build_v4_secret_request_observation_transport,
    )
    config = SecretMetadataHttpTransportConfig("https://synthetic.invalid", "synthetic-token", 1, None)
    environment = {} if mode is None else {V4_SECRET_REQUEST_OBSERVATION_AUTHENTICATION_ENV: mode}
    if mode == "unknown-mode":
        with pytest.raises(SecretRequestHttpTransportError):
            build_v4_secret_request_observation_transport(config, environment)
    else:
        assert type(build_v4_secret_request_observation_transport(config, environment)) is FortiPamSecretRequestHttpTransport


@pytest.mark.parametrize("case", ["valid", "wrong_actor", "external_redirect", "api_redirect",
                                 "missing_csrf", "logout_live", "provider_mismatch"])
def test_fixed_login_identity_and_retained_cookie_cleanup(case):
    calls = []
    logged_out = False
    provider_calls = []

    def handler(request):
        nonlocal logged_out
        calls.append((request.method, request.url.path))
        assert "authorization" not in request.headers
        if request.url.path == "/remote/login":
            return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH"></form>')
        if request.url.path == "/XX/YY/ZZ/AUTH":
            location = "https://untrusted.example/" if case == "external_redirect" else "/api/unexpected" if case == "api_redirect" else "/landing"
            return httpx.Response(303, headers={"location": location, "set-cookie": "session=private-cookie; Path=/; Secure"})
        if request.url.path == "/landing":
            return httpx.Response(200, headers={"set-cookie": "csrf=private-csrf; Path=/; Secure"})
        if request.url.path == "/logout":
            logged_out = True
            return httpx.Response(200, headers={"set-cookie": "session=; Max-Age=0; Path=/"})
        assert request.url.path == "/api/v2/monitor/web-ui/state"
        if logged_out:
            assert "session=private-cookie" in request.headers["cookie"]
            return httpx.Response(200 if case == "logout_live" else 401)
        name = "another-user" if case == "wrong_actor" else NAME
        results = {"admin": {"name": name, "login_name": name,
                             "sponsored_group_name": "", "guest_admin": False}}
        if case != "missing_csrf":
            results["ccsrf_token_cookie_name"] = "csrf"
        return httpx.Response(200, json={"http_method": "GET", "http_status": 200,
            "status": "success", "version": "v7.0.0", "build": 29,
            "path": "web-ui", "name": "state", "results": results})

    def credentials():
        provider_calls.append(True)
        return ("another-user" if case == "provider_mismatch" else NAME, "private-password")

    session = FixedSecretRequestRequesterSession(
        SecretMetadataHttpTransportConfig("https://synthetic.invalid", "unused-token", 1, None),
        requester=NAME, credentials=credentials,
        client_factory=lambda **kwargs: httpx.Client(**kwargs, transport=httpx.MockTransport(handler)),
    )
    if case in {"valid", "logout_live"}:
        session.inspect(NAME)
        assert session._authenticated
    else:
        with pytest.raises(SecretRequestRequesterSessionError, match="^The fixed Request requester session is unavailable.$"):
            session.inspect(NAME)
    assert session.finalize() is (case != "logout_live")
    count = len(calls)
    assert session.finalize() is (case != "logout_live")
    with pytest.raises(SecretRequestRequesterSessionError):
        session.inspect(NAME)
    assert len(calls) == count
    assert len(provider_calls) == 1
    assert session._csrf is None and not session._authenticated
    assert all(path != "/api/v2/cmdb/secret/request" for _, path in calls)
    assert ("POST", "/XX/YY/ZZ/AUTH") in calls if case != "provider_mismatch" else len(calls) == 1


@pytest.mark.parametrize('case', ['valid', 'replaced_directory', 'symlink', 'permissions'])
def test_provider_reuses_only_the_bound_owner_only_bp005_material(tmp_path, case):
    from fortipam_mcp.secret_request_requester_session import build_bp005_requester_session
    directory = tmp_path / 'provider'
    directory.mkdir(mode=0o700)
    session = build_bp005_requester_session(
        SecretMetadataHttpTransportConfig('https://synthetic.invalid', 'unused-token', 1, None),
        {'FORTIPAM_MCP_V4_LOCAL_USER_CREATE_ACTION_BP005_USERNAME': NAME,
         'FORTIPAM_MCP_V4_LOCAL_USER_CREATE_ACTION_BP005_MATERIAL_DIRECTORY': str(directory)})
    # Construction and closed-Gate startup do not load password material.
    if case == 'replaced_directory':
        directory.rename(tmp_path / 'retained-provider')
        directory.mkdir(mode=0o700)
    material = directory / 'initial-password'
    material.write_text('synthetic-password')
    material.chmod(0o600)
    if case == 'symlink':
        material.rename(directory / 'other')
        material.symlink_to(directory / 'other')
    if case == 'permissions':
        material.chmod(0o644)
    if case == 'valid':
        assert session._credentials() == (NAME, 'synthetic-password')
    else:
        with pytest.raises(SecretRequestRequesterSessionError, match='^The fixed Request requester session is unavailable.$'):
            session._credentials()


def test_wrong_bound_identity_rejects_before_credentials_or_network():
    def forbidden(*args, **kwargs):
        pytest.fail("preflight accessed a protected dependency")
    session = FixedSecretRequestRequesterSession(
        SecretMetadataHttpTransportConfig("https://synthetic.invalid", "unused-token", 1, None),
        requester=NAME, credentials=forbidden, client_factory=forbidden,
    )
    with pytest.raises(SecretRequestRequesterSessionError):
        session.inspect("another-user")
    assert session.finalize()


def test_request_reads_use_session_only_and_reject_outside_lifecycle():
    from test_secret_request_create_contract import _target_version_default
    calls = []

    def handler(request):
        calls.append(request)
        assert 'authorization' not in request.headers
        assert 'session=private-cookie' in request.headers['cookie']
        assert request.url.path == '/api/v2/cmdb/secret/request'
        if request.method == 'GET':
            assert request.url.params['action'] == 'default'
            return httpx.Response(200, json=_target_version_default('v7.0.0', 29))
        assert request.headers['x-http-method-override'] == 'GET'
        assert request.headers['x-csrftoken'] == 'private-csrf'
        assert json.loads(request.content)['json_filter'][0]['filters'][0]['pattern'] == 'creator'
        return httpx.Response(200, json={'results': [], 'status': 'OK', 'http_status': 200,
            'size': 0, 'filtered_count': 0, 'http_method': 'POST', 'vdom': 'root',
            'path': 'secret', 'name': 'request', 'serial': 'synthetic', 'version': 'v7.0.0', 'build': 29})

    session = FixedSecretRequestRequesterSession(
        SecretMetadataHttpTransportConfig('https://synthetic.invalid', 'unused-token', 1, None),
        requester=NAME, credentials=lambda: pytest.fail('unexpected credential access'))
    for read in (session.read_request_default, session.snapshot):
        with pytest.raises(SecretRequestRequesterSessionError):
            read()
    with httpx.Client(base_url='https://synthetic.invalid', transport=httpx.MockTransport(handler)) as client:
        client.cookies.set('session', 'private-cookie')
        session._client, session._authenticated, session._csrf = client, True, 'private-csrf'
        assert session.read_request_default().fortipam_build == 29
        assert session.snapshot().records == ()
        session._closed = True
        for read in (session.read_request_default, session.snapshot):
            with pytest.raises(SecretRequestRequesterSessionError):
                read()
    assert len(calls) == 2


@pytest.mark.parametrize("case", ["valid", "post_rejected", "post_timeout",
                                 "wrong_detail", "wrong_version", "logout_live"])
def test_composed_request_is_same_actor_claimed_once_and_finalized(tmp_path, case):
    from test_secret_request_create_contract import _target_version_default
    from test_secret_request_create_http_transport import _principal, _write_binding
    from fortipam_mcp.secret_request_create_contract import SecretRequestCreateInput
    from fortipam_mcp.secret_request_create_http_transport import (
        OwnerOnlySecretRequestCreateBindingResolver, OwnerOnlySecretRequestCreateDispatchClaim,
        SecretRequestCreateBinding,
    )

    principal = _principal()
    tmp_path.chmod(0o700)
    binding = SecretRequestCreateBinding('request-intent-reference01', NAME,
        principal.requester.digest, 'request-environment-ref01', 'request-scope-reference01', 4_000_000_000)
    request = SecretRequestCreateInput(requester=NAME, secret_id=83, request_type='launcher',
        start_after_approve='enable', start_time='', expiration_time='', duration=30,
        comments='synthetic', timezone='Asia/Shanghai')
    intent, claim = tmp_path / 'intent.json', tmp_path / 'claim.json'
    _write_binding(intent, binding, request)
    calls, created, logged_out = [], False, False

    class UnreadPostBody(httpx.SyncByteStream):
        def __iter__(self):
            pytest.fail('POST response body was consumed')

    def handler(req):
        nonlocal created, logged_out
        calls.append((req.method, req.url.path))
        assert 'authorization' not in req.headers
        if req.url.path == '/remote/login':
            return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH"></form>')
        if req.url.path == '/XX/YY/ZZ/AUTH':
            return httpx.Response(303, headers={'location': '/landing', 'set-cookie': 'session=private-cookie; Path=/; Secure'})
        assert 'session=private-cookie' in req.headers['cookie']
        if req.url.path == '/landing':
            return httpx.Response(200, headers={'set-cookie': 'csrf=private-csrf; Path=/; Secure'})
        if req.url.path == '/logout':
            logged_out = True
            # Durable success must wait for retained-cookie rejection.
            if claim.exists():
                assert 'terminal_outcome' not in json.loads(claim.read_text())
            return httpx.Response(200)
        if req.url.path == '/api/v2/monitor/web-ui/state':
            if logged_out:
                return httpx.Response(200 if case == 'logout_live' else 401)
            return httpx.Response(200, json={'http_method': 'GET', 'http_status': 200,
                'status': 'success', 'version': 'v7.0.0', 'build': 29, 'path': 'web-ui',
                'name': 'state', 'results': {'admin': {'name': NAME, 'login_name': NAME,
                    'sponsored_group_name': '', 'guest_admin': False}, 'ccsrf_token_cookie_name': 'csrf'}})
        if req.url.path == '/api/v2/cmdb/secret/request/71':
            return httpx.Response(200, json={'http_method': 'GET', 'http_status': 200,
                'status': 'success', 'version': 'v7.0.0', 'build': 29, 'vdom': 'root',
                'path': 'secret', 'name': 'request', 'results': [{'secret-id': 84 if case == 'wrong_detail' else 83,
                    'request-type': 'launcher', 'final-status': 'pending', 'tier1-status': 'pending'}]})
        assert req.url.path == '/api/v2/cmdb/secret/request'
        if req.method == 'GET':
            return httpx.Response(200, json=_target_version_default('v1.9.1', 1758)
                if case == 'wrong_version' else _target_version_default('v7.0.0', 29))
        assert req.headers['x-csrftoken'] == 'private-csrf'
        if 'x-http-method-override' in req.headers:
            records = [{'id': 69, 'secret-id': 83, 'request-type': 'launcher', 'creation-time': 1790000000}]
            if created:
                records.append({'id': 71, 'secret-id': 83, 'request-type': 'launcher', 'creation-time': 1790000001})
            return httpx.Response(200, json={'http_method': 'POST', 'http_status': 200,
                'status': 'OK', 'version': 'v7.0.0', 'build': 29, 'vdom': 'root', 'path': 'secret',
                'serial': 'synthetic', 'name': 'request', 'results': records,
                'size': len(records), 'filtered_count': len(records)})
        assert claim.exists() and json.loads(claim.read_text())['dispatch_attempted'] is True
        assert req.headers['content-length'] == str(len(req.content))
        assert 'transfer-encoding' not in req.headers
        assert json.loads(req.content)['user'] == NAME
        assert req.url.params['with_meta'] == 'true'
        created = True
        if case == 'post_timeout':
            raise httpx.ReadTimeout('private upstream detail')
        return httpx.Response(403 if case == 'post_rejected' else 200, stream=UnreadPostBody())

    config = SecretMetadataHttpTransportConfig('https://synthetic.invalid', 'unused-token', 1, None)
    session = FixedSecretRequestRequesterSession(config, requester=NAME,
        credentials=lambda: (NAME, 'private-password'),
        client_factory=lambda **kw: httpx.Client(**kw, transport=httpx.MockTransport(handler)))
    dependencies = dict(binding_resolver=OwnerOnlySecretRequestCreateBindingResolver(intent),
        dispatch_claim=OwnerOnlySecretRequestCreateDispatchClaim(claim, hmac_key=b'x' * 32),
        authorized_environment_ref=binding.environment_ref, authorized_scope_ref=binding.scope_ref)
    transport = session.compose_create_transport(**dependencies)
    result = transport.create(binding.intent_ref, principal=principal)
    assert result.outcome.value == ('bound' if case == 'valid' else 'reconciliation_required')
    assert (result.protected_record is not None) is (case == 'valid')
    assert session._closed and session._csrf is None
    count = len(calls)
    assert transport.create(binding.intent_ref, principal=principal) is result
    assert len(calls) == count
    if case == 'wrong_version':
        assert not claim.exists() and not created
    else:
        assert json.loads(claim.read_text())['terminal_outcome'] == result.outcome.value
        def forbidden(*args, **kwargs):
            pytest.fail('retained claim permitted login')
        restarted = FixedSecretRequestRequesterSession(config, requester=NAME,
            credentials=forbidden, client_factory=forbidden).compose_create_transport(**dependencies)
        assert restarted.create(binding.intent_ref, principal=principal).outcome.value == 'reconciliation_required'
    with pytest.raises(SecretRequestRequesterSessionError):
        session._dispatch_request_once(memoryview(b'{}'))
    assert len(calls) == count
