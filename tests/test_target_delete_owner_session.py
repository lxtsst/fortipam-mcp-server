"""Fixed Owner login recovery refuses drift and never replays a DELETE."""
from urllib.parse import parse_qs

import httpx
import pytest

from fortipam_mcp.secret_metadata_http_transport import SYSTEM_STATUS_PATH
from fortipam_mcp.target_delete_http_transport import TargetDeleteHttpTransportError, _record_digest
from fortipam_mcp.target_delete_owner_session import FixedTargetDeleteOwnerSession
from fortipam_mcp.target_http_transport import TargetHttpTransportConfig

TARGET = "mcp-v4-target-owner-test"
OWNER = "synthetic-owner"
PATH = "/api/v2/cmdb/secret/target/" + TARGET


@pytest.mark.parametrize("failure", [None, "actor", "owner", "drift", "csrf", "ack", "logout"])
def test_fixed_owner_bodyless_delete_and_failure_cleanup(failure):
    record = {"name": TARGET, "q_origin_key": TARGET, "class": "Other",
              "user-permission": [{"user-name": [{"name": OWNER}], "permission": "owner"}]}
    calls = []
    active = False

    def envelope(method, **extra):
        return {"version": "v7.0.0", "build": 29, "status": "success", "http_status": 200,
                "http_method": method, "path": "secret", "name": "target", **extra}

    def respond(request):
        nonlocal active
        calls.append((request.method, request.url.path))
        assert request.url.host == "pam.example.test" and "authorization" not in request.headers
        path = request.url.path
        if path == "/remote/login":
            return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH">')
        if path == "/XX/YY/ZZ/AUTH":
            assert parse_qs(request.content.decode())["username"] == [OWNER]
            active = True
            return httpx.Response(303, headers={"location": "/", "set-cookie": (
                'session=synthetic; Secure; Path=/' if failure == "csrf"
                else 'ccsrftoken="synthetic-csrf"; Secure; Path=/')})
        if path == "/":
            return httpx.Response(200)
        if path == "/logout":
            active = failure == "logout"
            return httpx.Response(200)
        if not active:
            return httpx.Response(401, json={})
        if path == SYSTEM_STATUS_PATH:
            return httpx.Response(200, json={"version": "v7.0.0", "build": 29})
        if path == "/api/v2/monitor/web-ui/state":
            return httpx.Response(200, json={"version": "v7.0.0", "build": 29,
                "status": "success", "http_method": "GET", "path": "web-ui", "name": "state",
                "results": {"admin": {"name": "other" if failure == "actor" else OWNER,
                    "login_name": OWNER, "sponsored_group_name": "", "guest_admin": False}}})
        assert path == PATH
        if request.method == "GET":
            row = dict(record)
            if failure == "owner":
                row["user-permission"] = []
            if failure == "drift":
                row["description"] = "changed"
            return httpx.Response(200, json=envelope("GET", results=[row]))
        assert request.method == "DELETE" and request.content == b""
        assert request.headers["content-length"] == "0"
        assert request.headers["x-csrftoken"] == "synthetic-csrf"
        return httpx.Response(200, json=envelope("DELETE", status="unknown" if failure == "ack" else "success"))

    transport = FixedTargetDeleteOwnerSession(
        TargetHttpTransportConfig("https://pam.example.test", "synthetic-api-token", 5, None),
        owner_name=OWNER, credentials=lambda: (OWNER, "synthetic-password"), target_name=TARGET,
        accepted_digest=_record_digest(record),
        client_factory=lambda **kwargs: httpx.Client(**kwargs, transport=httpx.MockTransport(respond)),
    )
    if failure:
        with pytest.raises(TargetDeleteHttpTransportError):
            transport.dispatch()
    else:
        transport.inspect()
        assert not any(method == "DELETE" for method, _ in calls)
        status, payload = transport.dispatch()
        assert status == 200 and payload["status"] == "success"
    assert transport.logout_verified is (failure != "logout")
    assert sum(method == "DELETE" for method, _ in calls) == (1 if failure in {None, "ack", "logout"} else 0)
    before = list(calls)
    with pytest.raises(TargetDeleteHttpTransportError):
        transport.dispatch()
    with pytest.raises(TargetDeleteHttpTransportError):
        transport.inspect()
    assert calls == before
