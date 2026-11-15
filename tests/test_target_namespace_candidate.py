import httpx
import pytest

from fortipam_mcp import target_namespace_candidate as module
from fortipam_mcp.target_contract import WebTargetCreateInput
from fortipam_mcp.target_http_transport import TargetHttpTransportConfig
from fortipam_mcp.target_namespace_ssh_reader import TargetNamespaceObservation, _candidate_digest
from fortipam_mcp.secret_metadata_http_transport import SYSTEM_STATUS_PATH


OWNER = "synthetic-owner"
NAME = "mcp-v4-target-web-20261007-r123"
WITNESSES = ("Synthetic Target A", "Synthetic Target B")


def envelope(path="secret", name="target", **changes):
    value = {"version": "v7.0.0", "build": 29, "serial": "SYNTHETIC_SERIAL", "http_status": 200,
             "http_method": "GET", "status": "success", "path": path, "name": name}
    value.update(changes)
    return value


class NativePeer:
    def __init__(self):
        self.collection = envelope(results=[{"name": name} for name in WITNESSES], size=2, matched_count=2)
        self.role = envelope("system", "admin", results={"name": OWNER, "accprofile": "super_admin",
            "status": "enable", "remote-auth": "disable", "wildcard": "disable"})
        self.events = []
        self.provider_calls = 0
        self.readers = []
        self.active = False
        self.actor = OWNER
        self.logout_fault = False
        self.closed = 0
        self.observation_fault = None

    def credentials(self):
        self.provider_calls += 1
        return OWNER, "synthetic-password-" + str(self.provider_calls)

    def client(self, **kwargs):
        peer = self
        class TrackedClient(httpx.Client):
            def close(self):
                super().close()
                peer.closed += 1
        return TrackedClient(**kwargs, transport=httpx.MockTransport(self.respond))

    def respond(self, request):
        path = request.url.path
        self.events.append((request.method, path))
        assert "authorization" not in request.headers
        if path == "/remote/login":
            return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH">')
        if path == "/XX/YY/ZZ/AUTH":
            assert "synthetic-password-" + str(self.provider_calls) in request.content.decode()
            self.active = True
            return httpx.Response(303, headers={"location": "/", "set-cookie": "session=synthetic; Secure; Path=/"})
        assert request.method == "GET"
        if path == "/logout":
            self.active = self.logout_fault
            return httpx.Response(200)
        if not self.active: return httpx.Response(401, json={})
        if path == "/": return httpx.Response(200)
        if path == SYSTEM_STATUS_PATH: return httpx.Response(200, json={"version": "v7.0.0", "build": 29})
        if path == "/api/v2/monitor/web-ui/state":
            return httpx.Response(200, json={"version": "v7.0.0", "build": 29, "status": "success",
                "http_method": "GET", "path": "web-ui", "name": "state", "results": {"admin": {
                    "name": self.actor, "login_name": OWNER, "sponsored_group_name": "", "guest_admin": False}}})
        if path == "/api/v2/cmdb/secret/target":
            assert dict(request.url.params) == {"format": "name"}
            return httpx.Response(200, json=self.collection)
        assert path == "/api/v2/cmdb/system/admin/" + OWNER
        assert request.url.params["format"] == module._ROLE_FIELDS
        return httpx.Response(200, json=self.role)

    def reader(self, config, **kwargs):
        assert not self.active and self.closed == self.provider_calls
        self.readers.append((config, kwargs))
        return self

    def read_namespace(self):
        names = self.readers[-1][1]["expected_api_names"]
        absent = NAME not in names
        return TargetNamespaceObservation("name_absent" if absent else "name_present", len(names), 2,
            "a" * 64, absent, _candidate_digest(NAME if self.observation_fault is None else
                                               "mcp-v4-target-web-20261007-r124"))


@pytest.fixture
def setup(tmp_path, monkeypatch):
    peer = NativePeer()
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("synthetic pinned peer\n"); known_hosts.chmod(0o600)
    config = TargetHttpTransportConfig("https://fortipam.example.test", "synthetic-token", 5, None, OWNER)
    binding = WebTargetCreateInput(NAME, "https://fixture.example.test/unserved")
    monkeypatch.setattr(module, "FortiPamTargetNamespaceSshReader", peer.reader)
    args = dict(binding=binding, credentials=peer.credentials, ssh_host="synthetic.invalid", ssh_port=22,
                ssh_known_hosts_file=known_hosts, positive_witness_names=WITNESSES, client_factory=peer.client)
    return peer, config, args


def test_factory_is_lazy_fresh_each_time_and_reads_no_url_or_body(setup):
    peer, config, args = setup
    observe = module.build_target_namespace_observer(config, **args)
    assert peer.events == [] and peer.provider_calls == 0
    for number in (1, 2):
        result = observe(NAME)
        assert result.global_name_absent and result.target_count == 2 and result.matches_candidate(NAME)
        assert peer.provider_calls == peer.closed == number and not peer.active
        ssh, private = peer.readers[-1]
        assert ssh.username == OWNER and ssh.password == "synthetic-password-" + str(number)
        assert private == {"candidate_name": NAME, "positive_witness_names": WITNESSES,
                           "expected_device_serial": "SYNTHETIC_SERIAL", "expected_api_names": WITNESSES}
    assert sum(path == "/logout" for method, path in peer.events) == 2


def test_candidate_present_is_categorical_and_never_deduplicated(setup):
    peer, config, args = setup
    peer.collection.update(results=[{"name": name} for name in (*WITNESSES, NAME)], size=3, matched_count=3)
    result = module.build_target_namespace_observer(config, **args)(NAME)
    assert result.status == "name_present" and not result.global_name_absent and result.target_count == 3


@pytest.mark.parametrize("fault", (
    "duplicate", "witness", "size", "size_bool", "matched", "limit", "next_idx", "next_index", "total",
    "too_many", "row", "name", "build", "serial", "role_profile", "role_owner", "role_disabled",
    "role_remote", "role_wildcard", "actor", "logout",
))
def test_unqualified_source_never_reaches_ssh_and_closes_owner(setup, fault):
    peer, config, args = setup
    if fault == "duplicate": peer.collection["results"][1]["name"] = WITNESSES[0]
    elif fault == "witness": peer.collection["results"][1]["name"] = "Other"
    elif fault == "size": peer.collection["size"] = 1
    elif fault == "size_bool": peer.collection["size"] = True
    elif fault == "matched": peer.collection["matched_count"] = 3
    elif fault == "limit": peer.collection["limit_reached"] = True
    elif fault in {"next_idx", "next_index"}: peer.collection[fault] = 2
    elif fault == "total": peer.collection["total"] = 3
    elif fault == "too_many": peer.collection.update(results=[{"name": f"Target{n}"} for n in range(129)],
                                                     size=129, matched_count=129)
    elif fault == "row": peer.collection["results"][1] = "unexpected"
    elif fault == "name": peer.collection["results"][1]["name"] = "bad\u200bname"
    elif fault == "build": peer.collection["build"] = 30
    elif fault == "serial": peer.collection["serial"] = "OTHER_SERIAL"
    elif fault == "role_profile": peer.role["results"]["accprofile"] = "read_only"
    elif fault == "role_owner": peer.role["results"]["name"] = "other"
    elif fault == "role_disabled": peer.role["results"]["status"] = "disable"
    elif fault == "role_remote": peer.role["results"]["remote-auth"] = "enable"
    elif fault == "role_wildcard": peer.role["results"]["wildcard"] = "enable"
    elif fault == "actor": peer.actor = "other"
    elif fault == "logout": peer.logout_fault = True
    with pytest.raises(ValueError) as error: module.build_target_namespace_observer(config, **args)(NAME)
    assert str(error.value) == module._UNAVAILABLE
    assert peer.readers == [] and peer.closed == 1
    assert any(path == "/logout" for method, path in peer.events)


def test_private_candidate_mismatch_is_rejected_even_for_summary_shaped_reader(setup):
    peer, config, args = setup
    peer.observation_fault = "binding"
    with pytest.raises(ValueError): module.build_target_namespace_observer(config, **args)(NAME)
    assert peer.closed == 1 and not peer.active


def test_wrong_selector_or_credential_actor_stops_before_login(setup):
    peer, config, args = setup
    observe = module.build_target_namespace_observer(config, **args)
    with pytest.raises(ValueError): observe("mcp-v4-target-web-20261007-r124")
    assert peer.provider_calls == 0
    args["credentials"] = lambda: ("other", "synthetic-password")
    with pytest.raises(ValueError): module.build_target_namespace_observer(config, **args)(NAME)
    assert peer.events == [] and peer.closed == 0


@pytest.mark.parametrize("changes", ({"ssh_port": True}, {"ssh_host": "bad host"},
                                    {"positive_witness_names": (WITNESSES[0],)},
                                    {"positive_witness_names": (WITNESSES[0], WITNESSES[0])}))
def test_invalid_local_binding_is_lazy_and_closed(setup, changes):
    peer, config, args = setup
    args.update(changes)
    with pytest.raises(ValueError): module.build_target_namespace_observer(config, **args)
    assert peer.events == [] and peer.provider_calls == 0
