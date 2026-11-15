import pytest
import httpx
from contextlib import nullcontext
from dataclasses import replace
from fortipam_mcp.folder_namespace_ssh_reader import FolderNamespaceObservation
from fortipam_mcp import isolated_folder_http_transport as module
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig


@pytest.mark.parametrize("enabled", [False, True])
def test_empty_inactive_policy_is_forwarded_only_for_explicit_create(monkeypatch, enabled):
    transport = namespace_transport(monkeypatch, lambda *args: FolderNamespaceObservation("name_absent", 25, 2, "a" * 64, True))
    calls = []
    monkeypatch.setattr(transport._folders, "create_isolated_child", lambda **kwargs: calls.append(kwargs) or {"mkey": 23}, raising=False)
    assert transport.create_isolated_child(name="Collector", parent_folder_id=17, owner_name="test-owner",
        empty_inactive_policy=enabled) == {"mkey": 23}
    expected = {"name": "Collector", "parent_folder_id": 17, "owner_name": "test-owner"}
    if enabled: expected["empty_inactive_policy"] = True
    assert calls == [expected]


@pytest.mark.parametrize("owner_reader", [False, True])
@pytest.mark.parametrize("policy", ["", "synthetic-inactive-policy"])
def test_empty_inactive_policy_readback_rejects_nonempty_only_in_opted_mode(monkeypatch, owner_reader, policy):
    transport = namespace_transport(monkeypatch, None)
    transport._metadata.child_id = 23
    row = {"name": "Collector", "parent-folder": 17, "inherit-policy": "enable",
        "inherit-folder-ztna": "enable", "inherit-permission": "disable", "secret-policy": policy,
        "group-permission": [], "user-permission": [{"id": 1, "user-name": [{"name": "test-owner"}],
            "folder-permission": "owner", "secret-permission": "owner"}]}
    monkeypatch.setattr(transport, "_detail", lambda *args: row)
    if not owner_reader: transport._owner_session = None
    args = dict(name="Collector", parent_folder_id=17, owner_name="test-owner")
    assert transport.verify_isolated_child(23, **args) is True
    assert transport.verify_isolated_child(23, **args, empty_inactive_policy=True) is (policy == "")


@pytest.mark.parametrize("flag", [None, 0, 1, "true", "false"])
@pytest.mark.parametrize("stage", ["create", "verify"])
def test_empty_inactive_policy_http_boundary_requires_bool_before_reads(monkeypatch, flag, stage):
    transport = namespace_transport(monkeypatch, None)
    monkeypatch.setattr(transport, "_parent_matches", lambda *args: pytest.fail("invalid mode must not read"))
    args = dict(name="Collector", parent_folder_id=17, owner_name="test-owner", empty_inactive_policy=flag)
    with pytest.raises(ValueError):
        if stage == "create": transport.create_isolated_child(**args)
        else: transport.verify_isolated_child(23, **args)


@pytest.mark.parametrize("payload", [None, {}, {"results": []}, {
    "version": "v7.0.0", "build": 29, "http_status": 404,
    "http_method": "GET", "path": "utility", "name": "id",
    "status": "Not Found", "error": 2,
    "cli_error": "Current user does not have read permission on requested secret/folder or the resource no longer exists",
}])
def test_unqualified_utility_404_cannot_authorize_isolated_folder_creation(monkeypatch, payload):
    transport = module.IsolatedFolderHttpTransport(SecretMetadataHttpTransportConfig(
        "https://fortipam.example.test", "test-token", 5, None), parent_path="Public/BoundParent")
    monkeypatch.setattr(transport._metadata, "resolve_folder_id", lambda path: 17)
    calls = []

    def request(method, path, body, *, query):
        calls.append((method, path, query))
        assert method == "GET" and body is None and query == "type=folder"
        return 404, payload

    monkeypatch.setattr(transport._metadata, "_request", request)
    with pytest.raises(ValueError, match="isolated Folder transport"):
        transport.find_child_ids("Collector", 17)
    assert calls == [("GET", "/api/v2/utility/id/Public/BoundParent/Collector", "type=folder")]


class Metadata:
    def __init__(self, config):
        self.resolved_parent = 17
        self.child_id = None
        self.owner_enabled = True
        self.child_parent = 17
        self.lookups = []
    def resolve_folder_id(self, path):
        assert path == "Public/BoundParent"
        return self.resolved_parent
    def _lookup_id(self, kind, path):
        self.lookups.append((kind, path))
        return self.child_id
    def _request(self, method, path, body, *, query):
        assert method == "GET" and body is None
        if path.startswith("/api/v2/utility/id/"):
            assert query == "type=folder"
            self.lookups.append(("folder", "Public/BoundParent/Collector"))
            return (404, {}) if self.child_id is None else (200, {"results": {"id": self.child_id}})
        if path.startswith("/api/v2/cmdb/system/admin/"):
            assert query == "format=name%7Cstatus%7Cremote-auth%7Cwildcard"
            row = {"name": "test-owner", "status": "enable" if self.owner_enabled else "disable", "remote-auth": "disable", "wildcard": "disable"}
        else:
            identifier = int(path.rsplit("/", 1)[1])
            row = dict.fromkeys(module._FOLDER_FIELDS.split("|"), "enable")
            row.update(id=identifier, name="Collector", **{"folder-type": "public", "parent-folder": self.child_parent, "user-permission": [], "group-permission": []})
        return 200, {"results": row}


class Folders:
    def __init__(self, config):
        self.owner_only = True
    def verify_owner_only_folder(self, folder_id, owner):
        return self.owner_only


def namespace_transport(monkeypatch, observer):
    monkeypatch.setattr(module, "FortiPamSecretMetadataHttpTransport", Metadata)
    monkeypatch.setattr(module, "FortiPamFolderHttpTransport", Folders)
    transport = module.IsolatedFolderHttpTransport(SecretMetadataHttpTransportConfig(
        "https://fortipam.example.test", "test-token", 5, None), parent_path="Public/BoundParent",
        child_name="Collector", owner_name="test-owner", owner_credentials=lambda: ("test-owner", "synthetic"),
        namespace_observer=observer)
    monkeypatch.setattr(transport, "_child_reader", lambda name: nullcontext(transport._metadata))
    return transport


def test_qualified_namespace_absence_is_fresh_and_precedes_any_utility_lookup(monkeypatch):
    events = []
    def observe(name, parent, owner):
        events.append(("namespace", name, parent, owner))
        return FolderNamespaceObservation("name_absent", 25, 2, "a" * 64, True)
    transport = namespace_transport(monkeypatch, observe)
    monkeypatch.setattr(transport._metadata, "resolve_folder_id", lambda path: events.append("parent-read") or 17)
    assert transport.find_child_ids("Collector", 17) == ()
    assert transport.find_child_ids("Collector", 17) == ()
    assert events == ["parent-read", ("namespace", "Collector", 17, "test-owner")] * 2
    assert transport._metadata.lookups == []


def test_present_namespace_requires_exact_successful_lookup_and_parent_detail(monkeypatch):
    transport = namespace_transport(monkeypatch, lambda *args: FolderNamespaceObservation(
        "name_present", 25, 2, "a" * 64, False))
    with pytest.raises(ValueError): transport.find_child_ids("Collector", 17)
    transport._metadata.child_id = 23
    assert transport.find_child_ids("Collector", 17) == (23,)
    transport._metadata.child_parent = 99
    with pytest.raises(ValueError): transport.find_child_ids("Collector", 17)


@pytest.mark.parametrize("observation", (
    None, {}, "absent",
    replace(FolderNamespaceObservation("name_absent", 25, 2, "a" * 64, True), status="name_present"),
    FolderNamespaceObservation("name_absent", 25, 2, "a" * 64, 1),
    FolderNamespaceObservation("name_absent", True, 2, "a" * 64, True),
    FolderNamespaceObservation("name_absent", 25, True, "a" * 64, True),
    FolderNamespaceObservation("name_absent", 1, 2, "a" * 64, True),
    FolderNamespaceObservation("name_absent", 25, 1, "a" * 64, True),
    FolderNamespaceObservation("name_absent", 25, 2, "bad digest", True),
))
def test_unqualified_namespace_observation_cannot_skip_lookup_or_authorize_post(monkeypatch, observation):
    transport = namespace_transport(monkeypatch, lambda *args: observation)
    with pytest.raises(ValueError): transport.find_child_ids("Collector", 17)
    with pytest.raises(ValueError): transport.create_isolated_child(name="Collector", parent_folder_id=17, owner_name="test-owner")
    assert transport._metadata.lookups == []


def test_namespace_final_dispatch_requalifies_before_expiry_and_never_posts_when_expired_or_present(monkeypatch):
    events = []
    present = False
    def observe(*args):
        events.append("namespace")
        return FolderNamespaceObservation("name_present" if present else "name_absent", 25, 2, "a" * 64, not present)
    transport = namespace_transport(monkeypatch, observe)
    monkeypatch.setattr(transport._metadata, "resolve_folder_id", lambda path: events.append("parent-read") or 17)
    monkeypatch.setattr(transport._folders, "create_isolated_child", lambda **kwargs: events.append("post") or {"mkey": 23}, raising=False)
    def expire():
        events.append("expiry-check")
        raise ValueError("expired authorization")
    with pytest.raises(ValueError, match="expired authorization"):
        transport.create_isolated_child(name="Collector", parent_folder_id=17, owner_name="test-owner", before_dispatch=expire)
    assert events == ["parent-read", "namespace", "expiry-check"]
    present = True
    events.clear()
    with pytest.raises(ValueError):
        transport.create_isolated_child(name="Collector", parent_folder_id=17, owner_name="test-owner", before_dispatch=expire)
    assert events == ["parent-read", "namespace"]


def test_namespace_observer_requires_explicit_owner_binding(monkeypatch):
    with pytest.raises(ValueError):
        module.IsolatedFolderHttpTransport(SecretMetadataHttpTransportConfig(
            "https://fortipam.example.test", "test-token", 5, None), parent_path="Public/BoundParent",
            namespace_observer=lambda *args: None)


def test_final_dispatch_guard_runs_after_parent_read_and_prevents_post(monkeypatch):
    monkeypatch.setattr(module, "FortiPamSecretMetadataHttpTransport", Metadata)
    monkeypatch.setattr(module, "FortiPamFolderHttpTransport", Folders)
    transport = module.IsolatedFolderHttpTransport(SecretMetadataHttpTransportConfig(
        "https://fortipam.example.test", "test-token", 5, None), parent_path="Public/BoundParent")
    events = []

    def resolve(path):
        events.append("parent-read")
        return 17

    def create(**kwargs):
        events.append("post")
        return {"http_status": 200, "mkey": 23}

    def expired():
        events.append("expiry-check")
        raise ValueError("expired authorization")

    monkeypatch.setattr(transport._metadata, "resolve_folder_id", resolve)
    monkeypatch.setattr(transport._folders, "create_isolated_child", create, raising=False)
    with pytest.raises(ValueError, match="expired authorization"):
        transport.create_isolated_child(name="Collector", parent_folder_id=17,
            owner_name="test-owner", before_dispatch=expired)
    assert events == ["parent-read", "expiry-check"]

    events.clear()
    result = transport.create_isolated_child(name="Collector", parent_folder_id=17,
        owner_name="test-owner", before_dispatch=lambda: events.append("expiry-check"))
    assert result["mkey"] == 23
    assert events == ["parent-read", "expiry-check", "post"]


def test_private_parent_path_and_exact_lookup_prevent_collection_absence_inference(monkeypatch):
    monkeypatch.setattr(module, "FortiPamSecretMetadataHttpTransport", Metadata)
    monkeypatch.setattr(module, "FortiPamFolderHttpTransport", Folders)
    transport = module.IsolatedFolderHttpTransport(SecretMetadataHttpTransportConfig(
        "https://fortipam.example.test", "test-token", 5, None), parent_path="Public/BoundParent")
    assert len(transport.read_parent_digest(17)) == 64
    assert transport.owner_is_available("test-owner")
    transport._metadata.owner_enabled = False
    assert not transport.owner_is_available("test-owner")
    with pytest.raises(ValueError, match="isolated Folder transport"):
        transport.find_child_ids("Collector", 17)
    assert transport._metadata.lookups == [("folder", "Public/BoundParent/Collector")]
    transport._metadata.child_id = 23
    assert transport.find_child_ids("Collector", 17) == (23,)
    assert transport.verify_isolated_child(23, name="Collector", parent_folder_id=17, owner_name="test-owner")
    transport._folders.owner_only = False
    assert not transport.verify_isolated_child(23, name="Collector", parent_folder_id=17, owner_name="test-owner")
    transport._metadata.child_parent = 99
    with pytest.raises(ValueError):
        transport.find_child_ids("Collector", 17)
    transport._metadata.resolved_parent = 99
    with pytest.raises(ValueError):
        transport.read_parent_digest(17)


@pytest.mark.parametrize("failure", (None, "actor", "logout", "lookup", "parent", "acl", "envelope"))
def test_owner_readback_observes_api_hidden_child_without_fallback_or_write(monkeypatch, failure):
    from fortipam_mcp.secret_metadata_http_transport import SYSTEM_STATUS_PATH

    monkeypatch.setattr(module, "FortiPamSecretMetadataHttpTransport", Metadata)
    monkeypatch.setattr(module, "FortiPamFolderHttpTransport", Folders)
    active = False
    present = False
    calls = []
    row = {"id": 23, "name": "Collector", "folder-type": "public", "parent-folder": 17,
           "inherit-policy": "enable", "inherit-permission": "disable", "inherit-folder-ztna": "enable",
           "secret-policy": "", "ztna-ems-tag": [], "ztna-tags-match-logic": "all",
           "user-permission": [{"id": 1, "user-name": [{"name": "test-owner"}],
                                "folder-permission": "owner", "secret-permission": "owner"}],
           "group-permission": []}

    def respond(request):
        nonlocal active
        path = request.url.path
        calls.append((request.method, path))
        assert "authorization" not in request.headers
        if path == "/remote/login":
            return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH">')
        if path == "/XX/YY/ZZ/AUTH":
            active = True
            return httpx.Response(303, headers={"location": "/", "set-cookie": "session=synthetic; Secure; Path=/"})
        assert request.method == "GET"
        if path == "/":
            return httpx.Response(200)
        if path == "/logout":
            active = present and failure == "logout"
            return httpx.Response(200)
        if not active:
            return httpx.Response(401, json={})
        if path == SYSTEM_STATUS_PATH:
            return httpx.Response(200, json={"version": "v7.0.0", "build": 29})
        if path == "/api/v2/monitor/web-ui/state":
            return httpx.Response(200, json={"version": "v7.0.0", "build": 29,
                "status": "success", "http_method": "GET", "path": "web-ui", "name": "state",
                "results": {"admin": {"name": "other" if present and failure == "actor" else "test-owner",
                    "login_name": "test-owner", "sponsored_group_name": "", "guest_admin": False}}})
        if path == "/api/v2/utility/id/Public/BoundParent/Collector":
            assert request.url.params["type"] == "folder"
            return httpx.Response(403 if present and failure == "lookup" else 200 if present else 404,
                                  json={"results": {"id": 23}} if present else {})
        assert path == "/api/v2/cmdb/secret/folder/23"
        return httpx.Response(200, json={"results": row, "version": "v7.0.0", "build": 29,
            "http_status": 200, "http_method": "GET", "path": "secret", "name": "folder",
            "status": "error" if failure == "envelope" else "OK"})

    transport = module.IsolatedFolderHttpTransport(
        SecretMetadataHttpTransportConfig("https://fortipam.example.test", "test-token", 5, None),
        parent_path="Public/BoundParent", child_name="Collector", owner_name="test-owner",
        owner_credentials=lambda: ("test-owner", "synthetic-password"),
        owner_client_factory=lambda **kwargs: httpx.Client(**kwargs, transport=httpx.MockTransport(respond)),
    )
    with pytest.raises(ValueError, match="isolated Folder transport"):
        transport.find_child_ids("Collector", 17)
    assert transport._owner_session.logout_verified
    present = True
    if failure == "parent":
        row["parent-folder"] = 99
    if failure == "acl":
        row["inherit-permission"] = "enable"
    if failure in {"actor", "logout", "lookup", "parent", "envelope"}:
        with pytest.raises(ValueError, match="isolated Folder transport"):
            transport.find_child_ids("Collector", 17)
    else:
        assert transport.find_child_ids("Collector", 17) == (23,)
        assert transport.verify_isolated_child(23, name="Collector", parent_folder_id=17,
                                               owner_name="test-owner") is (failure != "acl")
    assert transport._metadata.child_id is None and transport._metadata.lookups == []
    assert transport._owner_session.logout_verified is (failure != "logout")
    before = list(calls)
    with pytest.raises(ValueError):
        transport.find_child_ids("Other", 17)
    with pytest.raises(ValueError):
        transport.verify_isolated_child(23, name="Collector", parent_folder_id=17, owner_name="other")
    with pytest.raises(ValueError):
        transport.create_isolated_child(name="Other", parent_folder_id=17, owner_name="test-owner")
    assert calls == before
