import httpx
import pytest
from v4_planning import canonical_digest

from fortipam_mcp import folder_namespace_candidate as module
from fortipam_mcp.folder_namespace_ssh_reader import FolderNamespaceObservation
from fortipam_mcp.isolated_folder_http_transport import _FOLDER_FIELDS
from fortipam_mcp.isolated_folder_m4_adapter import IsolatedFolderBinding
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig, SYSTEM_STATUS_PATH


OWNER = "synthetic-owner"
NAME = "mcp-v4-domain-owner-synthetic"


def envelope(path="secret", name="folder", **changes):
    value = {"version": "v7.0.0", "build": 29, "serial": "SYNTHETIC_SERIAL",
             "http_status": 200, "http_method": "GET", "path": path, "name": name, "status": "OK"}
    value.update(changes)
    return value


def folder(identifier, name, parent):
    value = dict.fromkeys(_FOLDER_FIELDS.split("|"), "enable")
    value.update(id=identifier, name=name, **{"folder-type": "public", "parent-folder": parent,
        "inherit-permission": "disable", "secret-policy": [], "ztna-ems-tag": [],
        "ztna-tags-match-logic": "all", "group-permission": [],
        "user-permission": [{"id": 1, "user-name": [{"name": OWNER}],
                             "folder-permission": "owner", "secret-permission": "owner"}]})
    return value


class NativePeer:
    def __init__(self):
        self.parent = folder(17, "BoundParent", 0)
        self.rows = [self.parent, folder(18, "KnownChild", 17)]
        self.collection = envelope(results=self.rows, matched_count=2, limit_reached=False)
        self.role = envelope("system", "admin", results={"name": OWNER, "accprofile": "super_admin",
            "status": "enable", "remote-auth": "disable", "wildcard": "disable"})
        self.events = []
        self.provider_calls = 0
        self.readers = []
        self.actor_fault = None
        self.logout_fault = None
        self.collection_reads = 0
        self.active = False
        self.login_count = 0

    def credentials(self):
        self.provider_calls += 1
        return OWNER, "synthetic-password-" + str(self.provider_calls)

    def client(self, **kwargs):
        return httpx.Client(**kwargs, transport=httpx.MockTransport(self.respond))

    def respond(self, request):
        path = request.url.path
        self.events.append((request.method, path))
        assert "authorization" not in request.headers
        if path == "/remote/login":
            return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH">')
        if path == "/XX/YY/ZZ/AUTH":
            assert f"synthetic-password-{self.provider_calls}" in request.content.decode()
            self.active = True
            self.login_count += 1
            return httpx.Response(303, headers={"location": "/", "set-cookie": "session=synthetic; Secure; Path=/"})
        assert request.method == "GET"
        if path == "/logout":
            phase = "collection" if self.login_count % 2 else "role"
            self.active = self.logout_fault == phase
            return httpx.Response(200)
        if not self.active:
            return httpx.Response(401, json={})
        if path == "/":
            return httpx.Response(200)
        if path == SYSTEM_STATUS_PATH:
            return httpx.Response(200, json={"version": "v7.0.0", "build": 29})
        if path == "/api/v2/monitor/web-ui/state":
            phase = "collection" if self.login_count % 2 else "role"
            return httpx.Response(200, json={"version": "v7.0.0", "build": 29,
                "status": "success", "http_method": "GET", "path": "web-ui", "name": "state",
                "results": {"admin": {"name": "other" if self.actor_fault == phase else OWNER,
                    "login_name": OWNER, "sponsored_group_name": "", "guest_admin": False}}})
        if path == "/api/v2/cmdb/secret/folder":
            assert request.url.params["format"] == _FOLDER_FIELDS
            assert request.url.params["count"] == "512"
            self.collection_reads += 1
            return httpx.Response(200, json=self.collection)
        assert path == "/api/v2/cmdb/system/admin/" + OWNER
        assert request.url.params["format"] == module._ROLE_FIELDS
        return httpx.Response(200, json=self.role)

    def reader(self, config, **kwargs):
        self.readers.append((config, kwargs))
        assert not self.active
        return self

    def read_namespace(self):
        return FolderNamespaceObservation("name_absent", 25, 2, "a" * 64, True)


@pytest.fixture
def setup(tmp_path, monkeypatch):
    peer = NativePeer()
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("synthetic pinned peer\n"); known_hosts.chmod(0o600)
    config = SecretMetadataHttpTransportConfig("https://fortipam.example.test", "synthetic-token", 5, None)
    binding = IsolatedFolderBinding(NAME, 17, OWNER, canonical_digest(peer.parent))
    monkeypatch.setattr(module, "FortiPamFolderNamespaceSshReader", peer.reader)
    args = dict(binding=binding, parent_path="Public/BoundParent", credentials=peer.credentials,
                ssh_host="synthetic.invalid", ssh_port=22, ssh_known_hosts_file=known_hosts,
                witness_folder_id=18, client_factory=peer.client)
    return peer, config, binding, args


def test_factory_is_lazy_requalifies_each_call_and_uses_exactly_one_credential_snapshot(setup):
    peer, config, binding, args = setup
    observe = module.build_folder_namespace_observer(config, **args)
    assert peer.provider_calls == 0 and peer.events == []
    for expected in (1, 2):
        result = observe(binding.name, binding.parent_folder_id, binding.owner_name)
        assert result.global_name_absent and result.folder_count == 25
        assert peer.provider_calls == expected
        ssh, private = peer.readers[-1]
        assert ssh.username == OWNER and ssh.password == "synthetic-password-" + str(expected)
        assert private == {"candidate_name": NAME, "positive_witness_names": ("BoundParent", "KnownChild"),
                           "expected_device_serial": "SYNTHETIC_SERIAL"}
        assert OWNER not in repr(result) and "SYNTHETIC_SERIAL" not in repr(result)
    assert sum(path == "/logout" for method, path in peer.events) == 4


def test_positive_public_child_witness_can_belong_to_a_different_parent(setup):
    peer, config, binding, args = setup
    peer.rows[1]["parent-folder"] = 99
    observe = module.build_folder_namespace_observer(config, **args)
    assert observe(NAME, 17, OWNER).global_name_absent


@pytest.mark.parametrize("fault", (
    "parent_drift", "parent_name", "parent_personal", "missing_witness", "witness_parent", "witness_personal",
    "duplicate_id", "sentinel", "matched_count", "limit_reached", "collection_build", "collection_serial",
    "role_serial", "role_build", "role_envelope", "role_profile", "role_profile_shape", "role_disabled",
    "role_remote", "role_wildcard", "role_owner", "actor_collection", "actor_role", "logout_role",
))
def test_factory_rejects_drift_visibility_role_and_identity_without_ssh_or_fallback(setup, fault):
    peer, config, binding, args = setup
    if fault == "parent_drift": peer.parent["secret-policy"] = "changed"
    elif fault == "parent_name": peer.parent["name"] = "WrongParent"
    elif fault == "parent_personal": peer.parent["folder-type"] = "personal"
    elif fault == "missing_witness": peer.rows[1]["id"] = 19
    elif fault == "witness_parent": peer.rows[1]["parent-folder"] = 0
    elif fault == "witness_personal": peer.rows[1]["folder-type"] = "personal"
    elif fault == "duplicate_id": peer.rows[1]["id"] = 17
    elif fault == "sentinel": peer.rows[1]["name"] = module._SENTINEL
    elif fault == "matched_count": peer.collection["matched_count"] = 3
    elif fault == "limit_reached": peer.collection["limit_reached"] = True
    elif fault == "collection_build": peer.collection["build"] = 30
    elif fault == "collection_serial": peer.collection["serial"] = "invalid serial"
    elif fault == "role_serial": peer.role["serial"] = "OTHER_SERIAL"
    elif fault == "role_build": peer.role["build"] = 30
    elif fault == "role_envelope": peer.role["http_status"] = 403
    elif fault == "role_profile": peer.role["results"]["accprofile"] = "read_only"
    elif fault == "role_profile_shape": peer.role["results"]["accprofile"] = [{"name": "super_admin"}]
    elif fault == "role_disabled": peer.role["results"]["status"] = "disable"
    elif fault == "role_remote": peer.role["results"]["remote-auth"] = "enable"
    elif fault == "role_wildcard": peer.role["results"]["wildcard"] = "enable"
    elif fault == "role_owner": peer.role["results"]["name"] = "other"
    elif fault == "actor_collection": peer.actor_fault = "collection"
    elif fault == "actor_role": peer.actor_fault = "role"
    elif fault == "logout_role": peer.logout_fault = "role"
    observe = module.build_folder_namespace_observer(config, **args)
    with pytest.raises(ValueError, match="private Folder namespace candidate"):
        observe(binding.name, binding.parent_folder_id, binding.owner_name)
    assert peer.provider_calls == 1 and peer.readers == []
    assert any(path == "/logout" for method, path in peer.events)


@pytest.mark.parametrize("changes", ({"ssh_host": "bad host"}, {"ssh_port": 0}, {"ssh_port": True},
                                    {"witness_folder_id": 17}, {"witness_folder_id": True},
                                    {"parent_path": "Public/../BoundParent"}))
def test_invalid_source_configuration_rejects_without_credentials_or_network(setup, changes):
    peer, config, binding, args = setup
    args.update(changes)
    with pytest.raises(ValueError): module.build_folder_namespace_observer(config, **args)
    assert peer.provider_calls == 0 and peer.events == []


def test_wrong_binding_or_snapshot_actor_never_opens_owner_or_ssh(setup):
    peer, config, binding, args = setup
    observe = module.build_folder_namespace_observer(config, **args)
    with pytest.raises(ValueError): observe("Other", 17, OWNER)
    with pytest.raises(ValueError): observe(NAME, 99, OWNER)
    with pytest.raises(ValueError): observe(NAME, 17, "other")
    assert peer.provider_calls == 0
    args["credentials"] = lambda: ("other", "synthetic-password")
    observe = module.build_folder_namespace_observer(config, **args)
    with pytest.raises(ValueError): observe(NAME, 17, OWNER)
    assert peer.events == [] and peer.readers == []
