"""Real SDK protocol with synthetic identities; no deployed intake or device."""

import asyncio
import base64
from dataclasses import replace
import hashlib
import re
import time
from urllib.parse import parse_qs, urlsplit

import pytest
from mcp.server.auth.provider import ProviderTokenVerifier
from starlette.applications import Starlette
from starlette.testclient import TestClient

from fortipam_mcp import secret_bulk_import_intake as intake
from fortipam_mcp import secret_bulk_import_oauth as oauth
from fortipam_mcp.local_oauth import LocalOAuthConfigurationError, LocalOAuthProvider
from fortipam_mcp.secret_bulk_import_oauth import (
    OwnerFileIntakeOAuthCandidate, OwnerFileIntakeTokenVerifier,
)
from test_http_server import HttpServerSettings, _local_oauth_environment
from test_secret_bulk_import_dependencies import catalog
from test_secret_bulk_import_intake import Authority, prepared

PRIMARY = "https://mcp.example.com/fpamcp"
PRIVATE = "https://mcp.example.com/owner-file-intake"
SCOPE = intake._INTAKE_SCOPE
REDIRECT = "https://client.example/callback"
PKCE = "synthetic-pkce-verifier-with-more-than-forty-three-characters"


def fixture(tmp_path):
    settings = HttpServerSettings.from_environment(_local_oauth_environment(tmp_path)).local_oauth
    issuer = OwnerFileIntakeOAuthCandidate(settings, intake_resource=PRIVATE)
    app = Starlette(routes=issuer.authorization_routes())
    return issuer, TestClient(app, base_url="https://mcp.example.com")


def register(client, *, private=False, scope=None, grants=None):
    return client.post("/fpamcp/oauth/register", json={
        "client_name": "Synthetic owner intake" if private else "Synthetic planner",
        "redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none",
        "grant_types": grants or (["authorization_code"] if private else ["authorization_code", "refresh_token"]),
        "response_types": ["code"], "scope": scope or (SCOPE if private else "fortipam:read fortipam:plan"),
    })


def authorize(client, client_id, *, resource, scope, password="correct-horse-battery-staple"):
    response = client.get("/fpamcp/oauth/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT,
        "scope": scope, "state": "synthetic-state", "resource": resource,
        "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(PKCE.encode()).digest()).decode().rstrip("="),
        "code_challenge_method": "S256",
    }, follow_redirects=False)
    if response.status_code != 302:
        return response
    if urlsplit(response.headers["location"]).netloc == "client.example":
        return response
    page = client.get(response.headers["location"])
    request_id = re.search(r'name="request_id" value="([^"]+)"', page.text)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert request_id and csrf
    if resource == PRIVATE:
        assert "separate Owner authorization required" in page.text
    response = client.post("/fpamcp/oauth/login", data={
        "request_id": request_id.group(1), "csrf_token": csrf.group(1),
        "username": "operator", "password": password, "action": "allow",
    }, headers={"origin": "https://mcp.example.com"}, follow_redirects=False)
    if response.status_code != 302:
        return response
    return parse_qs(urlsplit(response.headers["location"]).query)["code"][0]


def exchange(client, client_id, code, resource, pkce=PKCE):
    return client.post("/fpamcp/oauth/token", data={
        "grant_type": "authorization_code", "client_id": client_id,
        "code": code, "code_verifier": pkce, "redirect_uri": REDIRECT, "resource": resource,
    })


def issue(client, *, private=False):
    registration = register(client, private=private)
    assert registration.status_code == 201
    client_id = registration.json()["client_id"]
    resource, scope = (PRIVATE, SCOPE) if private else (PRIMARY, "fortipam:read fortipam:plan")
    code = authorize(client, client_id, resource=resource, scope=scope)
    assert isinstance(code, str)
    response = exchange(client, client_id, code, resource)
    assert response.status_code == 200
    return client_id, response.json(), code


@pytest.mark.parametrize('private', [False, True])
def test_sdk_http_revocation_invalidates_exact_client_token_without_widening_mcp_resource(tmp_path, private):
    issuer, client = fixture(tmp_path)
    with client:
        client_id, issued, _ = issue(client, private=private)
        other_client, _, _ = issue(client, private=not private)
        verifier = OwnerFileIntakeTokenVerifier(issuer) if private else ProviderTokenVerifier(issuer)
        token = issued['access_token']
        assert asyncio.run(verifier.verify_token(token)) is not None
        response = client.post('/fpamcp/oauth/revoke', data={'client_id': other_client, 'client_secret': '', 'token': token})
        assert response.status_code == 200 and not response.content
        assert asyncio.run(verifier.verify_token(token)) is not None
        if private:
            assert asyncio.run(ProviderTokenVerifier(issuer).verify_token(token)) is None
        response = client.post('/fpamcp/oauth/revoke', data={'client_id': client_id, 'client_secret': '', 'token': token})
        assert response.status_code == 200 and not response.content
        assert asyncio.run(verifier.verify_token(token)) is None
        assert asyncio.run(ProviderTokenVerifier(issuer).verify_token(token)) is None
        assert oauth._REVOCATION_LOOKUP.get() is False


@pytest.mark.parametrize('fault', ['duplicate-token', 'unknown-field', 'hint', 'oversize'])
def test_revocation_frame_denies_before_cross_resource_lookup(tmp_path, monkeypatch, fault):
    issuer, client = fixture(tmp_path)
    content = {'duplicate-token': 'token=a&token=b&client_id=client',
        'unknown-field': 'token=a&client_id=client&resource=other',
        'hint': 'token=a&client_id=client&token_type_hint=other',
        'oversize': 'token=' + 'x' * 16384 + '&client_id=client'}[fault]
    monkeypatch.setattr(issuer, 'load_access_token', lambda *a: pytest.fail('Malformed revocation reached lookup'))
    with client:
        response = client.post('/fpamcp/oauth/revoke', content=content,
            headers={'Content-Type': 'application/x-www-form-urlencoded'})
    assert response.status_code == 400 and response.json()['error'] == 'invalid_request'
    assert oauth._REVOCATION_LOOKUP.get() is False


def test_paired_sdk_tokens_join_projection_but_do_not_replace_owner_authority(tmp_path, monkeypatch, capfd):
    binding, _, _ = prepared(tmp_path)
    issuer, client = fixture(tmp_path)
    planning, private = ProviderTokenVerifier(issuer), OwnerFileIntakeTokenVerifier(issuer)
    with client:
        planner_id, planner_token, _ = issue(client)
        private_id, private_token, code = issue(client, private=True)
        assert planner_id != private_id
        assert planner_token["expires_in"] == 3600
        assert private_token["expires_in"] == 900 and "refresh_token" not in private_token
        plan = asyncio.run(planning.verify_token(planner_token["access_token"]))
        own = asyncio.run(private.verify_token(private_token["access_token"]))
        assert plan and own and plan.subject == own.subject == "operator"
        assert plan.claims["iss"] == own.claims["iss"] == issuer.settings.issuer
        assert plan.resource == PRIMARY and own.resource == PRIVATE and own.scopes == [SCOPE]
        assert asyncio.run(planning.verify_token(private_token["access_token"])) is None
        assert asyncio.run(private.verify_token(planner_token["access_token"])) is None
        assert exchange(client, private_id, code, PRIVATE).status_code == 400

        now = int(time.time())
        binding = replace(binding, issuer=issuer.settings.issuer, subject="operator",
                          planning_resource=PRIMARY, intake_resource=PRIVATE,
                          planning_client=planner_id, intake_client=private_id,
                          issued_at=now - 1, expires_at=now + 60)
        options = dict(planning_token=planner_token["access_token"], intake_token=private_token["access_token"],
                       planning_verifier=planning, intake_verifier=private)
        source = intake.PinnedBulkImportFile
        monkeypatch.setattr(intake, "PinnedBulkImportFile", lambda *a, **k: pytest.fail("No Owner authority"))
        with pytest.raises(intake.BulkImportIntakeError):
            asyncio.run(intake.admit_prebound_owner_file(binding, **options))
        monkeypatch.setattr(intake, "PinnedBulkImportFile", source)
        transaction = asyncio.run(intake.admit_prebound_owner_file(binding, authority=Authority(binding), **options))
        assert repr(transaction.project_dependencies_once(catalog())) == "<ResolvedImportDependencies redacted>"
        transaction.close()
        asyncio.run(issuer.revoke_token(own))
        assert asyncio.run(private.verify_token(private_token["access_token"])) is None
        assert asyncio.run(planning.verify_token(planner_token["access_token"])) is not None
        asyncio.run(issuer.revoke_token(plan))
    assert capfd.readouterr() == ("", "")


@pytest.mark.parametrize("fault", ["main-resource", "main-scope", "unknown-resource", "extra-scope", "wrong-password"])
def test_private_authorization_denials_issue_no_tokens(tmp_path, fault):
    issuer, client = fixture(tmp_path)
    with client:
        registration = register(client, private=True)
        assert registration.status_code == 201
        options = dict(resource=PRIVATE, scope=SCOPE)
        if fault == "main-resource":
            options["resource"] = PRIMARY
        elif fault == "main-scope":
            options["scope"] = "fortipam:read fortipam:plan"
        elif fault == "unknown-resource":
            options["resource"] = PRIVATE + "/other"
        elif fault == "extra-scope":
            options["scope"] += " fortipam:read"
        else:
            options["password"] = "synthetic-wrong-password"
        response = authorize(client, registration.json()["client_id"], **options)
        assert not isinstance(response, str) and response.status_code == (401 if fault == "wrong-password" else 302)
        if fault != "wrong-password":
            assert "error" in parse_qs(urlsplit(response.headers["location"]).query)
        with issuer._connect() as connection:
            assert connection.execute("SELECT COUNT(*) FROM oauth_tokens").fetchone()[0] == 0


@pytest.mark.parametrize("fault", ["refresh", "mixed", "duplicate"])
def test_private_registration_rejects_mixed_or_refreshable_client(tmp_path, fault):
    issuer, client = fixture(tmp_path)
    with client:
        response = register(client, private=True,
                            scope=SCOPE if fault == "refresh" else SCOPE + (" fortipam:read" if fault == "mixed" else " " + SCOPE),
                            grants=["authorization_code", "refresh_token"] if fault == "refresh" else None)
        assert response.status_code == 400
        with issuer._connect() as connection:
            assert connection.execute("SELECT COUNT(*) FROM oauth_clients").fetchone()[0] == 0


@pytest.mark.parametrize("fault", ["resource", "pkce", "client"])
def test_private_code_exchange_denials_preserve_one_correct_exchange(tmp_path, fault):
    issuer, client = fixture(tmp_path)
    with client:
        registration = register(client, private=True)
        client_id = registration.json()["client_id"]
        code = authorize(client, client_id, resource=PRIVATE, scope=SCOPE)
        options = dict(resource=PRIVATE, pkce=PKCE)
        wrong_client = client_id
        if fault == "resource":
            options["resource"] = PRIMARY
        elif fault == "pkce":
            options["pkce"] = "different-synthetic-pkce-verifier-with-enough-characters"
        else:
            wrong_client = register(client).json()["client_id"]
        assert exchange(client, wrong_client, code, **options).status_code == 400
        assert exchange(client, client_id, code, PRIVATE).status_code == 200


def test_private_expiry_and_normal_refresh_keep_resources_separate(tmp_path, monkeypatch):
    issuer, client = fixture(tmp_path)
    private = OwnerFileIntakeTokenVerifier(issuer)
    with client:
        _, private_token, _ = issue(client, private=True)
        loaded = asyncio.run(private.verify_token(private_token["access_token"]))
        assert loaded
        monkeypatch.setattr("fortipam_mcp.secret_bulk_import_oauth.time.time", lambda: loaded.expires_at)
        assert asyncio.run(private.verify_token(private_token["access_token"])) is None
        monkeypatch.undo()
        planner_id, planner_token, _ = issue(client)
        denied = client.post("/fpamcp/oauth/token", data={
            "grant_type": "refresh_token", "client_id": planner_id,
            "refresh_token": planner_token["refresh_token"], "resource": PRIVATE,
        })
        assert denied.status_code == 400
        refreshed = client.post("/fpamcp/oauth/token", data={
            "grant_type": "refresh_token", "client_id": planner_id,
            "refresh_token": planner_token["refresh_token"], "resource": PRIMARY,
        })
        assert refreshed.status_code == 200
        assert asyncio.run(private.verify_token(refreshed.json()["access_token"])) is None


@pytest.mark.parametrize("resource", [PRIMARY, "http://mcp.example.com/intake", PRIVATE + "#fragment",
                                    "https://user@mcp.example.com/intake", PRIVATE + "/../other",
                                    "https://other.example.com/intake", PRIVATE + "/%2e", PRIVATE + "/"])
def test_invalid_private_resource_is_denied_before_storage(tmp_path, monkeypatch, resource):
    settings = HttpServerSettings.from_environment(_local_oauth_environment(tmp_path)).local_oauth
    monkeypatch.setattr(LocalOAuthProvider, "_initialize_database", lambda self: pytest.fail("Invalid resource reached storage"))
    with pytest.raises(LocalOAuthConfigurationError):
        OwnerFileIntakeOAuthCandidate(settings, intake_resource=resource)


def test_normal_issuer_stays_single_resource_without_candidate(tmp_path):
    settings = HttpServerSettings.from_environment(_local_oauth_environment(tmp_path)).local_oauth
    issuer = LocalOAuthProvider(settings)
    with TestClient(Starlette(routes=issuer.authorization_routes()), base_url="https://mcp.example.com") as client:
        assert register(client, private=True).status_code == 400
        registration = register(client)
        response = authorize(client, registration.json()["client_id"], resource=PRIVATE, scope="fortipam:read fortipam:plan")
        assert response.status_code == 302
        assert parse_qs(urlsplit(response.headers["location"]).query)["error"] == ["invalid_target"]


@pytest.mark.parametrize("fault", ["duplicate-resource", "missing-resource", "unknown-resource", "too-many-fields",
                                 "oversize", "wrong-length", "wrong-media", "duplicate-length"])
def test_private_token_frame_denials_do_not_consume_code(tmp_path, fault):
    from urllib.parse import urlencode

    issuer, client = fixture(tmp_path)
    with client:
        client_id = register(client, private=True).json()["client_id"]
        code = authorize(client, client_id, resource=PRIVATE, scope=SCOPE)
        fields = {"grant_type": "authorization_code", "client_id": client_id, "code": code,
                  "code_verifier": PKCE, "redirect_uri": REDIRECT, "resource": PRIVATE}
        if fault == "missing-resource":
            fields.pop("resource")
        elif fault == "unknown-resource":
            fields["resource"] += "/unknown"
        elif fault == "too-many-fields":
            fields.update({"extra" + str(index): "synthetic" for index in range(3)})
        body = urlencode(fields).encode()
        if fault == "duplicate-resource":
            body += b"&resource=" + PRIVATE.encode()
        elif fault == "oversize":
            body += b"&extra=" + b"x" * 16384
        headers = [("content-type", "application/x-www-form-urlencoded")]
        if fault == "wrong-length":
            headers.append(("content-length", "1"))
        elif fault == "wrong-media":
            headers = [("content-type", "application/json")]
        elif fault == "duplicate-length":
            headers.extend([("content-length", str(len(body))), ("content-length", str(len(body)))])
        assert client.post("/fpamcp/oauth/token", content=body, headers=headers).status_code == 400
        with issuer._connect() as connection:
            assert connection.execute("SELECT COUNT(*) FROM oauth_tokens").fetchone()[0] == 0
        assert exchange(client, client_id, code, PRIVATE).status_code == 200


def test_token_preflight_preserves_sdk_cors(tmp_path):
    _, client = fixture(tmp_path)
    with client:
        response = client.options("/fpamcp/oauth/token", headers={
            "origin": "https://client.example", "access-control-request-method": "POST",
        })
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == "*"


@pytest.mark.parametrize("outcome", ["success", "endpoint-error", "body-cancel"])
def test_token_context_and_mutable_body_clear_on_every_exit(tmp_path, monkeypatch, outcome):
    from starlette.responses import JSONResponse

    issuer, _ = fixture(tmp_path)
    buffers, observations = [], []

    def tracked(value=b""):
        result = bytearray(value)
        buffers.append(result)
        return result

    monkeypatch.setattr(oauth, "bytearray", tracked, raising=False)
    body = ("resource=" + PRIVATE).encode()
    scope = {"type": "http", "method": "POST", "path": "/fpamcp/oauth/token",
             "headers": [(b"content-length", str(len(body)).encode()),
                         (b"content-type", b"application/x-www-form-urlencoded")]}
    received = 0

    async def receive():
        nonlocal received
        received += 1
        if outcome == "body-cancel":
            if received == 1:
                return {"type": "http.request", "body": body[:10], "more_body": True}
            raise asyncio.CancelledError
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        pass

    async def endpoint(scope, receive, send):
        observations.append(oauth._REQUEST_RESOURCE.get())
        assert (await receive())["body"] == body
        if outcome == "endpoint-error":
            raise RuntimeError("Synthetic endpoint failure")
        await JSONResponse({"synthetic": True})(scope, receive, send)

    async def run():
        try:
            await issuer._bound_token_endpoint(endpoint)(scope, receive, send)
        finally:
            assert oauth._REQUEST_RESOURCE.get() is None

    if outcome == "success":
        asyncio.run(run())
    else:
        with pytest.raises(asyncio.CancelledError if outcome == "body-cancel" else RuntimeError):
            asyncio.run(run())
    assert buffers and all(not any(buffer) for buffer in buffers)
    assert observations == ([] if outcome == "body-cancel" else [PRIVATE])


def test_concurrent_token_requests_do_not_exchange_resource_contexts(tmp_path):
    issuer, _ = fixture(tmp_path)

    async def run():
        joined, count = asyncio.Event(), 0

        async def request(resource):
            body = ("resource=" + resource).encode()
            scope = {"type": "http", "method": "POST", "headers": [
                (b"content-length", str(len(body)).encode()),
                (b"content-type", b"application/x-www-form-urlencoded"),
            ]}

            async def receive():
                return {"type": "http.request", "body": body, "more_body": False}

            async def send(message):
                pass

            async def endpoint(scope, receive, send):
                nonlocal count
                count += 1
                if count == 2:
                    joined.set()
                await joined.wait()
                assert oauth._REQUEST_RESOURCE.get() == resource

            await issuer._bound_token_endpoint(endpoint)(scope, receive, send)
            assert oauth._REQUEST_RESOURCE.get() is None

        async with asyncio.timeout(1):
            await asyncio.gather(request(PRIMARY), request(PRIVATE))

    asyncio.run(run())
