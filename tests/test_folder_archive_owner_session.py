"""A fixed Owner must revalidate Folder state and never replay a DELETE."""
import copy
from urllib.parse import parse_qs

import httpx
import pytest

from fortipam_mcp.folder_archive_owner_session import FixedFolderArchiveOwnerSession, FolderArchiveOwnerSessionError
from fortipam_mcp.folder_http_transport import FolderTransportConfig, COLLECTION_PATH
from fortipam_mcp.secret_metadata_http_transport import SYSTEM_STATUS_PATH

OWNER = "synthetic-owner"
NAME = "mcp-v4-archive-owner-test"
PATH = COLLECTION_PATH + "/42"


@pytest.mark.parametrize("failure", (None, "actor", "owner", "drift", "csrf", "ack", "logout", "serial"))
def test_owner_archive_rechecks_before_one_bodyless_delete_and_verifies_logout(failure):
    record = {"id": 42, "name": NAME, "parent-folder": 7, "folder-type": "public",
              "inherit-policy": "enable", "inherit-permission": "disable", "inherit-folder-ztna": "enable",
              "secret-policy": "", "ztna-ems-tag": [], "ztna-tags-match-logic": "all",
              "user-permission": [{"id": 1, "user-name": [{"name": OWNER}],
                                   "folder-permission": "owner", "secret-permission": "owner"}],
              "group-permission": []}
    calls = []
    active = False
    present = True
    inject = None

    def envelope(method, **extra):
        return {"version": "v7.0.0", "build": 29, "status": "OK", "http_status": 200,
                "http_method": method, "path": "secret", "name": "folder", "serial": "FPA-SYNTHETIC", **extra}

    def respond(request):
        nonlocal active, present
        calls.append((request.method, request.url.path))
        assert request.url.host == "pam.example.test" and "authorization" not in request.headers
        path = request.url.path
        if path == "/remote/login":
            return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH">')
        if path == "/XX/YY/ZZ/AUTH":
            assert parse_qs(request.content.decode())["username"] == [OWNER]
            active = True
            return httpx.Response(303, headers={"location": "/", "set-cookie": (
                'session=synthetic; Secure; Path=/' if inject == "csrf"
                else 'ccsrftoken="synthetic-csrf"; Secure; Path=/')})
        if path == "/":
            return httpx.Response(200)
        if path == "/logout":
            active = inject == "logout"
            return httpx.Response(200)
        if not active:
            return httpx.Response(401, json={})
        if path == SYSTEM_STATUS_PATH:
            return httpx.Response(200, json={"version": "v7.0.0", "build": 29})
        if path == "/api/v2/monitor/web-ui/state":
            return httpx.Response(200, json={"version": "v7.0.0", "build": 29,
                "status": "success", "http_method": "GET", "path": "web-ui", "name": "state",
                "results": {"admin": {"name": "other" if inject == "actor" else OWNER,
                    "login_name": OWNER, "sponsored_group_name": "", "guest_admin": False}}})
        assert path in {COLLECTION_PATH, PATH}
        if request.method == "GET":
            row = copy.deepcopy(record)
            if inject == "owner":
                row["user-permission"][0]["user-name"] = ["different-owner"]
            if inject == "drift":
                row["inherit-policy"] = "disable"
            return httpx.Response(200, json=envelope("GET", results=[row] if present else [],
                matched_count=int(present), serial="OTHER" if inject == "serial" else "FPA-SYNTHETIC"))
        assert path == PATH and request.method == "DELETE" and request.content == b""
        assert request.headers["content-length"] == "0" and request.headers["x-csrftoken"] == "synthetic-csrf"
        present = False
        return httpx.Response(200, json=envelope("DELETE", status="unknown" if inject == "ack" else "success"))

    transport = FixedFolderArchiveOwnerSession(
        FolderTransportConfig("https://pam.example.test", "synthetic-api-token", 5, None, explicitly_enabled=True),
        owner_name=OWNER, folder_name=NAME, credentials=lambda: (OWNER, "synthetic-password"),
        client_factory=lambda **kwargs: httpx.Client(**kwargs, transport=httpx.MockTransport(respond)),
    )
    transport.read_collection()
    transport.inspect(OWNER)
    with pytest.raises(FolderArchiveOwnerSessionError):
        transport.inspect(OWNER)
    before = list(calls)
    with pytest.raises(FolderArchiveOwnerSessionError):
        transport.delete_empty_folder(43)
    assert calls == before
    inject = failure
    if failure:
        with pytest.raises(FolderArchiveOwnerSessionError):
            transport.delete_empty_folder(42)
    else:
        assert transport.delete_empty_folder(42)["status"] == "success"
    assert transport.logout_verified is (failure != "logout")
    assert sum(method == "DELETE" for method, _ in calls) == (1 if failure in {None, "ack", "logout"} else 0)
    before = list(calls)
    with pytest.raises(FolderArchiveOwnerSessionError):
        transport.delete_empty_folder(42)
    assert calls == before
    if failure is None:
        assert transport.read_collection()["results"] == []
        assert transport.logout_verified
