"""Private creation baseline reads do not establish ownership or perform writes."""
from copy import deepcopy
import json
from typing import Any, cast

import httpx
import pytest

from fortipam_mcp import isolated_folder_http_transport as module
from fortipam_mcp.secret_metadata_http_transport import SYSTEM_STATUS_PATH, SecretMetadataHttpTransportConfig


class Peer:
    def __init__(self, fault: str | None = None) -> None:
        self.fault = fault
        self.active = False
        self.calls: list[tuple[str, str]] = []
        self.serial = "SYNTHETIC29"
        self.folder: dict[str, Any] = {
            "id": 23, "name": "Collector", "folder-type": "public", "parent-folder": 17,
            "inherit-policy": "enable", "inherit-permission": "disable", "inherit-folder-ztna": "enable",
            "secret-policy": "", "ztna-ems-tag": [], "ztna-tags-match-logic": "and",
            "user-permission": [{"id": 1, "q_origin_key": 1, "user-name": [{"name": "test-owner"}],
                                 "folder-permission": "owner", "secret-permission": "owner",
                                 "allowed-launcher-type": "all"}], "group-permission": [],
        }

    def envelope(self, path: str, table: str, row: dict[str, Any]) -> dict[str, Any]:
        return {"version": "v7.0.0", "build": 29, "serial": self.serial, "http_status": 200,
                "http_method": "GET", "path": path, "name": table, "vdom": "root",
                "status": "OK", "results": row}

    def respond(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((request.method, path))
        assert "authorization" not in request.headers
        if path == "/remote/login":
            return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH">')
        if path == "/XX/YY/ZZ/AUTH":
            self.active = True
            return httpx.Response(303, headers={"location": "/", "set-cookie": "session=synthetic; Secure; Path=/"})
        assert request.method == "GET"
        if path == "/":
            return httpx.Response(200)
        if path == "/logout":
            self.active = self.fault == "logout"
            return httpx.Response(200)
        if not self.active:
            return httpx.Response(401, json={})
        if path == SYSTEM_STATUS_PATH:
            return httpx.Response(200, json={"version": "v7.0.0", "build": 29})
        if path == "/api/v2/monitor/web-ui/state":
            return httpx.Response(200, json={"version": "v7.0.0", "build": 29, "status": "success",
                "http_method": "GET", "path": "web-ui", "name": "state", "results": {"admin": {
                    "name": "other" if self.fault == "actor" else "test-owner", "login_name": "test-owner",
                    "sponsored_group_name": "", "guest_admin": False}}})
        if path == "/api/v2/utility/id/Public/BoundParent/Collector":
            return httpx.Response(403 if self.fault == "lookup" else 200, json={"results": {"id": 23}})
        if path == "/api/v2/cmdb/system/admin/test-owner":
            body = self.envelope("system", "admin", {"name": "test-owner", "accprofile": "super_admin",
                "status": "enable", "remote-auth": "disable", "wildcard": "disable"})
            if self.fault == "role": body["results"]["accprofile"] = "readonly"
            if self.fault == "role_unknown": body["results"]["unexpected"] = True
            if self.fault == "role_build": body["build"] = 30
            if self.fault == "action": body["action"] = None
        else:
            assert path == "/api/v2/cmdb/secret/folder/23"
            assert request.url.params["format"] == module._FOLDER_FIELDS
            body = self.envelope("secret", "folder", deepcopy(self.folder))
            if self.fault == "serial": body["serial"] = "OTHER"
            if self.fault in {"id", "parent"}: body["results"]["id" if self.fault == "id" else "parent-folder"] = 99
            if self.fault == "name": body["results"]["name"] = "Other"
            if self.fault == "missing": del body["results"]["user-permission"]
            if self.fault == "page": body["next_idx"] = 0
            if self.fault == "size": body["size"] = 2
            if self.fault == "mkey": body["mkey"] = 99
            if self.fault == "http": return httpx.Response(403, json=body)
        if self.fault == "secret_material": body["field"] = {"opaque": "SYNTHETIC_PROTECTED_MARKER"}
        if self.fault == "oversize": body["padding"] = "x" * module.MAX_RESPONSE_BYTES
        raw = json.dumps(body).encode()
        if self.fault == "role_duplicate" and path.endswith("test-owner"):
            raw = raw.replace(b'"accprofile": "super_admin"', b'"accprofile":"super_admin","accprofile":"super_admin"')
        if self.fault == "nested_duplicate" and path.endswith("/23"):
            raw = raw.replace(b'"folder-permission": "owner"', b'"folder-permission":"owner","folder-permission":"owner"')
        return httpx.Response(200, content=raw, headers={"content-type": "application/json"})


def transport(monkeypatch: pytest.MonkeyPatch, peer: Peer, *, bound: bool = True) -> module.IsolatedFolderHttpTransport:
    bindings: dict[str, Any] = {
        "child_name": "Collector", "owner_name": "test-owner",
        "owner_credentials": lambda: ("test-owner", "synthetic-password"),
        "owner_client_factory": lambda **kwargs: httpx.Client(**kwargs, transport=httpx.MockTransport(peer.respond)),
    } if bound else {}
    instance = module.IsolatedFolderHttpTransport(
        SecretMetadataHttpTransportConfig("https://fortipam.example.test", "synthetic-api-token", 5, None),
        parent_path="Public/BoundParent", **bindings,
    )
    monkeypatch.setattr(instance._metadata, "resolve_folder_id", lambda _: 17)
    monkeypatch.setattr(instance._metadata, "_request", lambda *args, **kwargs: pytest.fail("API fallback is forbidden"))
    return instance


def test_fixed_owner_baseline_snapshot_is_private_complete_and_independent(monkeypatch: pytest.MonkeyPatch) -> None:
    peer = Peer()
    instance = transport(monkeypatch, peer)
    original = deepcopy(peer.folder)
    snapshot = instance.read_created_folder_snapshot(23, name="Collector", parent_folder_id=17, owner_name="test-owner")
    assert snapshot.serial == peer.serial and snapshot.folder == original
    assert set(snapshot.folder) == set(module._FOLDER_FIELDS.split("|"))
    assert "test-owner" not in repr(snapshot)
    cast(dict[str, Any], snapshot.folder)["user-permission"][0]["allowed-launcher-type"] = "changed"
    assert peer.folder == original
    assert instance._owner_session is not None
    assert instance._owner_session.logout_verified and not peer.active
    assert all(method == "GET" or path == "/XX/YY/ZZ/AUTH" for method, path in peer.calls)


@pytest.mark.parametrize("fault", (
    "actor", "role", "role_unknown", "role_build", "action", "lookup", "serial", "id", "parent",
    "name", "missing", "page", "size", "mkey", "http", "role_duplicate", "nested_duplicate", "logout", "oversize",
))
def test_failed_snapshot_never_falls_back_or_returns_partial_baseline(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    peer = Peer(fault)
    instance = transport(monkeypatch, peer)
    with pytest.raises(ValueError, match="isolated Folder transport"):
        instance.read_created_folder_snapshot(23, name="Collector", parent_folder_id=17, owner_name="test-owner")
    assert instance._owner_session is not None
    assert instance._owner_session.logout_verified is (fault != "logout")
    assert all(method == "GET" or path == "/XX/YY/ZZ/AUTH" for method, path in peer.calls)


@pytest.mark.parametrize("fault", ("unbound", "id", "name", "owner", "parent"))
def test_snapshot_fixed_selectors_reject_before_owner_login(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    peer = Peer()
    instance = transport(monkeypatch, peer, bound=fault != "unbound")
    args: dict[str, Any] = {"name": "Collector", "parent_folder_id": 17, "owner_name": "test-owner"}
    if fault == "name": args["name"] = "Other"
    if fault == "owner": args["owner_name"] = "other"
    if fault == "parent": args["parent_folder_id"] = 99
    with pytest.raises(ValueError, match="isolated Folder transport"):
        instance.read_created_folder_snapshot(True if fault == "id" else 23, **args)
    assert peer.calls == []


@pytest.mark.parametrize("fault", ("secret_material", "nested_duplicate", "oversize"))
def test_snapshot_redacts_before_decode_and_zeroizes_success_or_refusal(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    peer = Peer(fault)
    instance = transport(monkeypatch, peer)
    loads = module.json.loads
    zeroize = module._zeroize_mutable
    cleared: list[bytearray] = []

    def checked_loads(content: Any, *args: Any, **kwargs: Any) -> Any:
        assert "SYNTHETIC_PROTECTED_MARKER" not in (content if isinstance(content, str) else bytes(content).decode())
        return loads(content, *args, **kwargs)

    def capture_zeroize(content: bytearray) -> None:
        cleared.append(content)
        zeroize(content)

    monkeypatch.setattr(module.json, "loads", checked_loads)
    monkeypatch.setattr(module, "_zeroize_mutable", capture_zeroize)
    if fault == "secret_material":
        assert instance.read_created_folder_snapshot(23, name="Collector", parent_folder_id=17,
                                                     owner_name="test-owner").folder == peer.folder
    else:
        with pytest.raises(ValueError, match="isolated Folder transport"):
            instance.read_created_folder_snapshot(23, name="Collector", parent_folder_id=17, owner_name="test-owner")
    assert len(cleared) >= 2 and all(not content for content in cleared)
    assert instance._owner_session is not None
    assert instance._owner_session.logout_verified


@pytest.mark.parametrize("fault", (None, "actor", "role", "role_unknown", "role_build", "action",
                                    "role_duplicate", "logout", "unbound"))
def test_pre_dispatch_device_serial_requires_fresh_owner_role_and_logout(monkeypatch: pytest.MonkeyPatch,
                                                                       fault: str | None) -> None:
    peer = Peer(fault)
    instance = transport(monkeypatch, peer, bound=fault != "unbound")
    if fault is None:
        assert instance.read_creation_device_serial() == peer.serial
        assert instance._owner_session is not None and instance._owner_session.logout_verified
    else:
        with pytest.raises(ValueError, match="isolated Folder transport"):
            instance.read_creation_device_serial()
    assert not any("secret/folder" in path or "utility/id" in path for _, path in peer.calls)
    assert all(method == "GET" or path == "/XX/YY/ZZ/AUTH" for method, path in peer.calls)
    if fault == "unbound": assert peer.calls == []
