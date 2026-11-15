from urllib.parse import parse_qs
import json
import threading

import httpx
import pytest

from fortipam_mcp.owner_session_metadata import OwnerSessionMetadataTransport
from fortipam_mcp.secret_metadata_http_transport import (
    FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig,
    SecretMetadataHttpTransportError, SYSTEM_STATUS_PATH, UTILITY_ID_PATH,
)


@pytest.mark.parametrize("failure", [None, "redirect", "firmware", "credentials", "logout"])
def test_owner_login_fixed_reads_and_revoke_on_every_exit(monkeypatch, failure):
    config = SecretMetadataHttpTransportConfig("https://pam.example.test", "api-token-not-for-owner", 5, None)
    witness = FortiPamSecretMetadataHttpTransport(config, bound_secret_name="witness")
    monkeypatch.setattr(witness, "read_product_version_and_build", lambda: ("7.0.0", 29))
    monkeypatch.setattr(witness, "_request", lambda *_: (200, {"serial": "synthetic"}))
    monkeypatch.setattr(witness, "verify_target_has_no_collector", lambda *_: True)
    calls = []
    active = False
    now = [1000.0]
    def respond(request):
        nonlocal active
        assert request.url.host == "pam.example.test"
        calls.append((request.method, request.url.path))
        assert "authorization" not in request.headers
        path = request.url.path
        if path == "/remote/login":
            return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH">')
        if path == "/XX/YY/ZZ/AUTH":
            assert request.method == "POST"
            form = parse_qs(request.content.decode())
            assert form["username"] == ["gui-owner"]
            active = True
            return httpx.Response(303, headers={"location": "https://other.example/" if failure == "redirect" else "/",
                "set-cookie": "testsession=synthetic; Secure; HttpOnly; Path=/"})
        if path == "/logout":
            active = failure == "logout"
            return httpx.Response(200)
        if path == "/":
            return httpx.Response(200)
        if not active:
            return httpx.Response(401, json={})
        assert "testsession=synthetic" in request.headers.get("cookie", "")
        if path == SYSTEM_STATUS_PATH:
            return httpx.Response(200, json={"version": "v7.0.0", "build": 30 if failure == "firmware" else 29, "serial": "synthetic"})
        if path.startswith(UTILITY_ID_PATH):
            if request.url.params["type"] == "folder":
                return httpx.Response(200, json={"results": {"id": 17}})
            return httpx.Response(404, json={})
        if path.endswith("/folder/17"):
            return httpx.Response(200, json={"results": {"id": 17, "inherit-permission": "disable",
                "group-permission": [], "user-permission": [{"id": 3, "user-name": ["gui-owner"],
                "folder-permission": "owner", "secret-permission": "owner", "allowed-launcher-type": "all"}]}})
        if "/template/" in path:
            return httpx.Response(200, json={"results": {"name": "Windows Machine"}})
        if "/target/" in path:
            return httpx.Response(200, json={"results": {"name": "target", "address": "192.0.2.10", "template": "Windows Machine", "winrm-https": "disable"}})
        raise AssertionError("Unexpected route")
    session = OwnerSessionMetadataTransport(config, owner_name="gui-owner",
        credentials=lambda: ("other" if failure == "credentials" else "gui-owner", "synthetic-password"),
        folder_path="Public/Collector", secret_name="collector", target_name="target", witness=witness,
        client_factory=lambda **kwargs: httpx.Client(**kwargs, transport=httpx.MockTransport(respond)),
        clock=lambda: now[0])
    def run():
        with session.authenticated():
            with pytest.raises(SecretMetadataHttpTransportError):
                with session.authenticated():
                    raise AssertionError("Nested authentication must not run")
            observed = session.inspect("Public/Collector", "collector", "Windows Machine")
            assert observed.folder_exists and observed.template_exists and not observed.secret_exists
            assert session.verify_winrm_collector_preflight("Public/Collector", "collector", "gui-owner",
                "Public/Witness", "witness", "target", "192.0.2.10")
            with pytest.raises(SecretMetadataHttpTransportError):
                session._request("POST", SYSTEM_STATUS_PATH, {})
            with pytest.raises(SecretMetadataHttpTransportError):
                session._request("DELETE", SYSTEM_STATUS_PATH, None)
            with pytest.raises(SecretMetadataHttpTransportError):
                session._request("GET", "/api/v2/cmdb/secret/folder/18", None)
            with pytest.raises(SecretMetadataHttpTransportError):
                session._request_projection_detail(17, winrm_collector=True)
            now[0] += 301
            with pytest.raises(SecretMetadataHttpTransportError):
                session.read_product_version_and_build()
    if failure:
        with pytest.raises(SecretMetadataHttpTransportError):
            run()
    else:
        run()
    assert session._client is None
    assert session.logout_verified is (failure not in {"credentials", "logout"})
    assert not any(path.startswith("https://other") for _, path in calls)
    assert all(method == "GET" or path == "/XX/YY/ZZ/AUTH" for method, path in calls)


@pytest.mark.parametrize("create,csrf", [(False, True), (True, False), (True, True)])
def test_fixed_owner_bridge_uses_cookie_csrf_and_never_replays(create, csrf):
    from fortipam_mcp.secret_metadata_http_transport import COLLECTION_PATH
    calls = []
    class Raw:
        def request(self, method, url, body=None, headers=None):
            calls.append((method, url, body, headers))
        def close(self):
            pass
    config = SecretMetadataHttpTransportConfig("https://pam.example.test", "must-not-be-sent", 5, None)
    owner = OwnerSessionMetadataTransport(config, owner_name="gui-owner", credentials=lambda: ("gui-owner", "test"),
        folder_path="Public/Collector", secret_name="collector", target_name="target",
        witness=FortiPamSecretMetadataHttpTransport(config), allow_secret_create=create,
        connection_factory=lambda *_args, **_kwargs: Raw(), clock=lambda: 100)
    owner._client = httpx.Client(base_url=config.base_url)
    owner._client.cookies.set("testsession", "synthetic", domain="pam.example.test", path="/")
    if csrf:
        owner._client.cookies.set("ccsrftoken", "synthetic-csrf", domain="pam.example.test", path="/")
    owner._expires_at = 200
    try:
        if not create:
            with pytest.raises(SecretMetadataHttpTransportError):
                owner.secret_create_connection("pam.example.test", 443)
        else:
            first = owner.secret_create_connection("pam.example.test", 443)
            second = owner.secret_create_connection("pam.example.test", 443)
            body = memoryview(bytearray(b'{"synthetic":true}'))
            try:
                if not csrf:
                    with pytest.raises(SecretMetadataHttpTransportError):
                        first.request("POST", COLLECTION_PATH, body, {"Authorization": "must-not-be-sent"})
                else:
                    first.request("POST", COLLECTION_PATH, body, {"Authorization": "must-not-be-sent"})
                    assert calls[0][2] is body
                    assert calls[0][3]["User-Agent"] == owner._client.headers["User-Agent"]
                    assert "Authorization" not in calls[0][3]
                    assert calls[0][3]["X-CSRFTOKEN"] == "synthetic-csrf"
                    with pytest.raises(SecretMetadataHttpTransportError):
                        second.request("POST", COLLECTION_PATH, body)
            finally:
                body.release()
        assert len(calls) == int(create and csrf)
    finally:
        owner._client.close()


def test_owner_collector_credential_repair_connection_is_csrf_bound_and_single_use():
    calls = []

    class Raw:
        def request(self, method, url, body=None, headers=None):
            calls.append((method, url, body, headers))

        def close(self):
            pass

    config = SecretMetadataHttpTransportConfig("https://pam.example.test", "must-not-be-sent", 5, None)
    owner = OwnerSessionMetadataTransport(
        config, owner_name="gui-owner", credentials=lambda: ("gui-owner", "test"),
        folder_path="Public/Collector", secret_name="collector", target_name="target",
        witness=FortiPamSecretMetadataHttpTransport(config), allow_collector_credential_repair=True,
        connection_factory=lambda *_args, **_kwargs: Raw(), clock=lambda: 100,
    )
    owner._client = httpx.Client(base_url=config.base_url)
    owner._client.cookies.set("testsession", "synthetic", domain="pam.example.test", path="/")
    owner._client.cookies.set("ccsrftoken", "synthetic-csrf", domain="pam.example.test", path="/")
    owner._expires_at = 200
    owner._secret_id = 27
    body = memoryview(bytearray(b'{"field":"synthetic"}'))
    try:
        connection = owner.collector_credential_repair_connection("pam.example.test", 443, secret_id=27)
        connection.request("PUT", "/api/v2/cmdb/secret/database/27", body, {"Authorization": "must-not-be-sent"})
        assert len(calls) == 1
        assert calls[0][3]["User-Agent"] == owner._client.headers["User-Agent"]
        assert calls[0][3]["X-CSRFTOKEN"] == "synthetic-csrf"
        assert "Authorization" not in calls[0][3]
        with pytest.raises(SecretMetadataHttpTransportError):
            owner.collector_credential_repair_connection("pam.example.test", 443, secret_id=27)
    finally:
        body.release()
        owner._client.close()


def test_owner_collector_credential_repair_connection_reserves_atomically():
    class Raw:
        def request(self, *_args, **_kwargs):
            raise AssertionError("Reservation test must not dispatch")

        def close(self):
            pass

    config = SecretMetadataHttpTransportConfig("https://pam.example.test", "must-not-be-sent", 5, None)
    owner = OwnerSessionMetadataTransport(
        config, owner_name="gui-owner", credentials=lambda: ("gui-owner", "test"),
        folder_path="Public/Collector", secret_name="collector", target_name="target",
        witness=FortiPamSecretMetadataHttpTransport(config), allow_collector_credential_repair=True,
        connection_factory=lambda *_args, **_kwargs: Raw(), clock=lambda: 100,
    )
    owner._client = httpx.Client(base_url=config.base_url)
    owner._client.cookies.set("testsession", "synthetic", domain="pam.example.test", path="/")
    owner._expires_at = 200
    owner._secret_id = 27
    barrier = threading.Barrier(2)
    results: list[bool] = []
    results_lock = threading.Lock()

    def reserve() -> None:
        barrier.wait(timeout=5)
        try:
            owner.collector_credential_repair_connection("pam.example.test", 443, secret_id=27)
            result = True
        except SecretMetadataHttpTransportError:
            result = False
        with results_lock:
            results.append(result)

    threads = [threading.Thread(target=reserve) for _ in range(2)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        assert all(not thread.is_alive() for thread in threads)
        assert results.count(True) == 1 and results.count(False) == 1
    finally:
        owner._client.close()


@pytest.mark.parametrize("profile", ["winrm_collector", "domain_account"])
def test_owner_detail_keeps_existing_predecode_material_redaction(profile):
    from test_secret_metadata_http_transport import _DetailConnection, _DetailResponse
    config = SecretMetadataHttpTransportConfig("https://pam.example.test", "must-not-be-sent", 5, None)
    calls = []
    owner = OwnerSessionMetadataTransport(config, owner_name="gui-owner", credentials=lambda: ("gui-owner", "test"),
        folder_path="Public/Collector", secret_name="collector", target_name="target",
        witness=FortiPamSecretMetadataHttpTransport(config), clock=lambda: 100,
        connection_factory=lambda *_args, **_kwargs: _DetailConnection(_DetailResponse({
            "results": [{"id": 27, "field": [{"value": "synthetic-secret"}]}]}), calls))
    owner._client = httpx.Client(base_url=config.base_url)
    owner._client.cookies.set("testsession", "synthetic", domain="pam.example.test", path="/")
    owner._expires_at = 200
    owner._secret_id = 27
    try:
        status, payload, redacted = owner._request_projection_detail(27, **{profile: True})
        assert status == 200 and redacted and payload["results"][0]["field"] is None
        assert "Authorization" not in calls[0]["headers"]
        with pytest.raises(SecretMetadataHttpTransportError):
            owner._request_projection_detail(28, **{profile: True})
        with pytest.raises(SecretMetadataHttpTransportError):
            owner._request_projection_detail(27, winrm_collector=True, domain_account=True)
        with pytest.raises(SecretMetadataHttpTransportError):
            owner._request_projection_detail(27)
        for path in ("/api/v2/cmdb/secret/database/28?format=id",
                     "/api/v2/cmdb/secret/database/27?format=field"):
            connection = owner._metadata_connection("pam.example.test", 443)
            try:
                with pytest.raises(SecretMetadataHttpTransportError):
                    connection.request("GET", path)
            finally:
                connection.close()
        assert len(calls) == 1
    finally:
        owner._client.close()


@pytest.mark.parametrize("defect", [None, "type_drift", "missing_type", "duplicate_field", "malformed"])
def test_owner_domain_template_preflight_projects_definitions_before_decoding(monkeypatch, defect):
    from fortipam_mcp import owner_session_metadata
    from fortipam_mcp.target_contract import DOMAIN_TEMPLATE, DOMAIN_TEMPLATE_FIELD_TYPES

    config = SecretMetadataHttpTransportConfig("https://pam.example.test", "not-an-owner-token", 5, None)
    target_path = "/api/v2/cmdb/secret/target/target"
    template_path = "/api/v2/cmdb/secret/template/Windows%20Domain%20Account"
    secret_path = "/api/v2/cmdb/secret/database/27"
    sentinel = "synthetic-unexpected-material"
    fields = [{"name": name, "type": kind, "value": sentinel,
               "password": sentinel, "unexpected": {"nested": sentinel}}
              for name, kind in DOMAIN_TEMPLATE_FIELD_TYPES]
    if defect == "type_drift":
        fields[-1]["type"] = "username"
    elif defect == "missing_type":
        del fields[-1]["type"]
    elif defect == "duplicate_field":
        fields[-1]["name"] = "Username"
    template = {
        "version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
        "status": "success", "path": "secret", "name": "template", "vdom": "root",
        "error": 0, "unexpected": {"value": sentinel},
        "results": [{"name": DOMAIN_TEMPLATE, "field": fields, "password": sentinel}],
    }
    template_bytes = json.dumps(template).encode()
    if defect == "malformed":
        template_bytes = template_bytes[:-1] + b",}"
    target = {"name": "target", "address": "192.0.2.10", "domain": "ad.example.test",
              "template": DOMAIN_TEMPLATE, "class": "Existing Domain Tag", "ldaps-port": 636,
              "user-naming-attribute": "sAMAccountName", "user-base": "", "access": "customized",
              "web-proxy-status": "disable", "field": [{"value": sentinel}],
              "user-permission": [{"permission": "owner", "user-name": [{"name": "gui-owner"}]}]}
    active = False
    clients = []
    reads = []

    def respond(request):
        nonlocal active
        assert "authorization" not in request.headers
        path = request.url.path
        if path == "/remote/login":
            return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH">')
        if path == "/XX/YY/ZZ/AUTH":
            active = True
            return httpx.Response(303, headers={"location": "/",
                "set-cookie": "testsession=synthetic; Secure; HttpOnly; Path=/"})
        if path == "/logout":
            active = False
            return httpx.Response(200)
        if path == "/":
            return httpx.Response(200)
        if not active:
            return httpx.Response(401, json={})
        reads.append(path)
        if path == SYSTEM_STATUS_PATH:
            return httpx.Response(200, json={"version": "v7.0.0", "build": 29})
        if path == target_path:
            return httpx.Response(200, json={**template, "name": "target", "results": [target],
                                            "unexpected": None})
        if path == "/api/v2/cmdb/secret/template/Windows Domain Account":
            return httpx.Response(200, content=template_bytes, headers={"content-type": "application/json"})
        if path == secret_path:
            return httpx.Response(200, json={"results": [{"id": 27, "field": [{"value": sentinel}]}]})
        raise AssertionError("Unexpected route")

    def client_factory(**kwargs):
        client = httpx.Client(**kwargs, transport=httpx.MockTransport(respond))
        clients.append(client)
        return client

    original_loads = json.loads
    def guarded_loads(content, *args, **kwargs):
        assert sentinel not in str(content)
        return original_loads(content, *args, **kwargs)
    monkeypatch.setattr(owner_session_metadata.json, "loads", guarded_loads)
    owner = OwnerSessionMetadataTransport(config, owner_name="gui-owner",
        credentials=lambda: ("gui-owner", "synthetic-password"), folder_path="Public/Domain",
        secret_name="domain-account", target_name="target", witness=FortiPamSecretMetadataHttpTransport(config),
        client_factory=client_factory)
    owner._allowed_paths |= {template_path, secret_path}
    with owner.authenticated():
        assert owner.verify_domain_account_preflight("target", "192.0.2.10", "ad.example.test", "gui-owner",
            expected_classification_tag="Existing Domain Tag") is (defect is None)
        if defect is None:
            _, projected = owner._request("GET", template_path, None)
            assert projected == {key: value for key, value in template.items() if key not in {"unexpected", "results"}} | {
                "results": [{"name": DOMAIN_TEMPLATE, "field": [{"name": name, "type": kind}
                    for name, kind in DOMAIN_TEMPLATE_FIELD_TYPES]}]}
        for path in (target_path, secret_path):
            _, projected = owner._request("GET", path, None)
            assert projected["results"][0]["field"] is None
    assert "/api/v2/cmdb/secret/template/Windows Domain Account" in reads
    assert owner.logout_verified and owner._client is None
    assert len(clients) == 1 and clients[0].is_closed
