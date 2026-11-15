"""Fixed source sequence, transport closure and source/custody denial tests."""
import copy
from dataclasses import replace
import json
import logging
import pickle
import ssl

import httpx
import pytest

from fortipam_mcp import service_account_state_reader as r
from fortipam_mcp.service_account_state_projection import _UPDATER_METADATA
from v4_planning.material_provider import MaterialAccessDenied
from test_service_account_state_projection import KEY, SENTINEL, SERIAL, binding, response, rows


class Body(httpx.SyncByteStream):
    def __init__(self, value, eof):
        self.value, self.eof, self.closed = value, eof, False

    def __iter__(self):
        half = len(self.value) // 2
        yield self.value[:half]
        yield self.value[half:]
        self.eof()

    def close(self):
        self.closed = True


def actor():
    return dict(version="v7.0.0", build=29, path="web-ui", name="state", http_method="GET",
        http_status=200, status="success", vdom="root", serial=SERIAL, results={
            "admin": {"name": "synthetic-api", "login_name": "synthetic-api",
                "sponsored_group_name": "", "guest_admin": False, "global_admin": True,
                "profile": {"name": "super_admin"}}, "vdom_mode": "",
            "maintenance_mode": {"mode": "disable"}})


class Harness:
    def __init__(self, fault=None):
        self.now = 10.0
        self.fault = fault
        self.requests, self.streams, self.clients, self.options = [], [], [], []
        secret, target, updater = rows()
        updater.update({name: {"opaque": SENTINEL} for name in _UPDATER_METADATA - {"q_origin_key"}})
        self.values = [json.dumps(actor()).encode(), bytes(response("database", secret)),
            bytes(response("target", target)), bytes(response("dependency-updater", updater)),
            bytes(response("dependency-updater", updater)), bytes(response("target", target)),
            bytes(response("database", secret)), json.dumps(actor()).encode()]

    def handle(self, request):
        index = len(self.requests)
        self.requests.append(request)
        logging.getLogger("httpx").info("PRIVATE_HTTP_SENTINEL")
        data = self.values[index]
        if self.fault == "oversize" and index == 1: data = b"x" * (r.m._MAX_BYTES + 1)
        if self.fault == "malformed" and index == 1: data = b"{"
        if self.fault == "late_headers": self.now += 31
        def eof():
            if self.fault == "late_eof": self.now += 31
            elif self.fault == "rollback": self.now -= 1
            elif self.fault == "nan": self.now = float("nan")
        stream = Body(data, eof); self.streams.append(stream)
        return httpx.Response(302 if self.fault == "redirect" else 403 if self.fault == "status" else 200,
            headers={"content-type": "text/html" if self.fault == "type" else "application/json",
                "content-encoding": "gzip" if self.fault == "encoding" else "identity",
                "location": "https://other.invalid/PRIVATE_REDIRECT"}, stream=stream)

    def factory(self, **kwargs):
        self.options.append(kwargs)
        if self.fault == "factory": raise RuntimeError("PRIVATE_FACTORY_SENTINEL")
        harness = self
        class Client(httpx.Client):
            def __enter__(self):
                if harness.fault == "enter": raise RuntimeError("PRIVATE_ENTER_SENTINEL")
                return super().__enter__()
            def __exit__(self, *args):
                result = super().__exit__(*args)
                if harness.fault == "late_close": harness.now += 31
                return result
        client = Client(transport=httpx.MockTransport(self.handle), **kwargs)
        self.clients.append(client)
        return client

    def reader(self, **changes):
        config = r.SecretMetadataHttpTransportConfig("https://synthetic.invalid", "synthetic-token", 10, None)
        return r.ServiceAccountStateReader(replace(config, **changes), binding=binding(),
            actor_name="synthetic-api", actor_profile="super_admin", witness_key=KEY,
            client_factory=self.factory, clock=lambda: self.now)


def tracked(reader, monkeypatch):
    owned = []
    original = reader._get
    def capture(*args):
        raw = original(*args); owned.append(raw)
        # Erase material fields before any caller/whole-response framing.
        if args[1] == reader._routes[0]:
            assert b'"Password"' not in raw
        return raw
    monkeypatch.setattr(reader, "_get", capture)
    return owned


def test_exact_eight_get_sequence_private_framing_closure_and_current_seal(monkeypatch, caplog):
    h = Harness(); reader = h.reader(); owned = tracked(reader, monkeypatch)
    loads = json.loads
    def selected(value, *args, **kwargs):
        if isinstance(value, (bytes, bytearray)): assert SENTINEL.encode() not in value
        return loads(value, *args, **kwargs)
    monkeypatch.setattr(json, "loads", selected)
    caplog.set_level(logging.DEBUG)
    observation = reader.read_once(); reader.check_current(observation)
    assert observation.observed_at == 10 and observation.expires_at == 40
    assert len(h.requests) == 8 and all(request.method == "GET" and request.content == b"" for request in h.requests)
    expected = [r._ACTOR, *reader._routes, *reversed(reader._routes), r._ACTOR]
    assert [str(request.url).removeprefix("https://synthetic.invalid") for request in h.requests] == expected
    assert all(request.headers["authorization"] == "Bearer synthetic-token" for request in h.requests)
    assert all(request.headers["accept-encoding"] == "identity" for request in h.requests)
    assert all("no-store" in request.headers["cache-control"] for request in h.requests)
    assert all(not raw for raw in owned) and all(stream.closed for stream in h.streams)
    assert all(client.is_closed for client in h.clients)
    assert h.options[0]["trust_env"] is False and h.options[0]["follow_redirects"] is False
    tls = h.options[0]["verify"]
    assert tls.check_hostname and tls.verify_mode == ssl.CERT_REQUIRED
    assert tls.minimum_version == ssl.TLSVersion.TLSv1_2
    assert "PRIVATE_" not in caplog.text and "synthetic" not in caplog.text
    assert observation.projection.summary()["permission_qualified"] is False
    for value in (reader, observation):
        assert "synthetic" not in repr(value)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(MaterialAccessDenied): operation(value)
    reader.close()
    assert not reader._key
    with pytest.raises(r.ServiceAccountStateReadError): reader.check_current(observation)


@pytest.mark.parametrize("fault", ["redirect", "status", "type", "encoding", "oversize", "malformed",
    "late_headers", "late_eof", "late_close", "rollback", "nan", "factory", "enter"])
def test_transport_failure_clears_closes_and_forbids_retry(fault, monkeypatch):
    h = Harness(fault); reader = h.reader(); owned = tracked(reader, monkeypatch)
    with pytest.raises(r.ServiceAccountStateReadError) as error: reader.read_once()
    assert str(error.value) == r._ERROR and error.value.__suppress_context__
    assert all(not raw for raw in owned) and not reader._key
    assert all(stream.closed for stream in h.streams) and all(client.is_closed for client in h.clients)
    count = len(h.requests)
    with pytest.raises(r.ServiceAccountStateReadError): reader.read_once()
    assert len(h.requests) == count


@pytest.mark.parametrize("index", range(8))
def test_each_response_requires_same_device(index):
    h = Harness(); h.values[index] = h.values[index].replace(SERIAL.encode(), b"OTHER")
    with pytest.raises(r.ServiceAccountStateReadError): h.reader().read_once()


@pytest.mark.parametrize("index", [0, 7])
@pytest.mark.parametrize("fault", ["name", "login", "sponsor", "guest", "global", "role", "vdom",
    "maintenance", "schema-errors", "action", "no-serial"])
def test_actor_brackets_refuse_wrong_context_or_error(index, fault):
    h = Harness(); value = actor(); state = value["results"]; admin = state["admin"]
    if fault == "name": admin["name"] = "other"
    elif fault == "login": admin["login_name"] = "other"
    elif fault == "sponsor": admin["sponsored_group_name"] = "group"
    elif fault == "guest": admin["guest_admin"] = True
    elif fault == "global": admin["global_admin"] = False
    elif fault == "role": admin["profile"]["name"] = "other"
    elif fault == "vdom": state["vdom_mode"] = "split"
    elif fault == "maintenance": state["maintenance_mode"]["mode"] = "enable"
    elif fault == "schema-errors": value["schema_errors"] = []
    elif fault == "action": value["action"] = ""
    elif fault == "no-serial": del value["serial"]
    h.values[index] = json.dumps(value).encode()
    with pytest.raises(r.ServiceAccountStateReadError): h.reader().read_once()
    assert len(h.requests) == (1 if index == 0 else 8)


@pytest.mark.parametrize("fault", ["selection", "config", "key", "tls", "clock", "factory", "route"])
def test_constructor_input_drift_refuses_before_network(fault):
    h = Harness(); reader = h.reader()
    if fault == "selection": object.__setattr__(reader._binding, "dependency_id", 3)
    elif fault == "config": object.__setattr__(reader._config, "bearer_token", "other-token")
    elif fault == "key": reader._key[0] ^= 1
    elif fault == "tls": reader._tls.check_hostname = False
    elif fault == "clock": reader._clock = lambda: 10.0
    elif fault == "factory": reader._factory = h.factory
    elif fault == "route": reader._routes = (r._ACTOR,) * 3
    with pytest.raises(r.ServiceAccountStateReadError): reader.read_once()
    assert not h.requests and not reader._key


@pytest.mark.parametrize("fault", ["expiry", "foreign", "tamper", "nested-tamper", "retry", "rollback"])
def test_observation_expiry_ownership_and_seal_cannot_be_reused(fault):
    h = Harness(); reader = h.reader(); observed = reader.read_once()
    if fault == "expiry": h.now = observed.expires_at
    elif fault == "foreign": observed = replace(observed)
    elif fault == "tamper": object.__setattr__(observed, "expires_at", 999999.0)
    elif fault == "nested-tamper": object.__setattr__(observed.projection, "relation_digest", "b" * 64)
    elif fault == "retry":
        with pytest.raises(r.ServiceAccountStateReadError): reader.read_once()
    elif fault == "rollback": h.now -= 1
    with pytest.raises(r.ServiceAccountStateReadError): reader.check_current(observed)
    assert not reader._key and reader._current is None and len(h.requests) == 8


def test_ca_snapshot_is_used_and_later_change_invalidates_source(tmp_path, monkeypatch):
    path = tmp_path / "ca.pem"; path.write_text("SYNTHETIC_CA_A")
    original = ssl.create_default_context; captured = []
    def context(*, cadata=None):
        captured.append(cadata)
        return original()
    monkeypatch.setattr(r.ssl, "create_default_context", context)
    h = Harness(); reader = h.reader(ca_file=str(path))
    observed = reader.read_once()
    path.write_text("SYNTHETIC_CA_B")
    with pytest.raises(r.ServiceAccountStateReadError): reader.check_current(observed)
    assert captured == ["SYNTHETIC_CA_A"] and len(h.requests) == 8


@pytest.mark.parametrize("name", ["..", ".", "a/b", "a\\b", "a?b", "a#b", "a%2fb"])
def test_dynamic_selector_cannot_change_fixed_route(name):
    h = Harness()
    with pytest.raises(r.ServiceAccountStateReadError):
        r.ServiceAccountStateReader(r.SecretMetadataHttpTransportConfig("https://synthetic.invalid", "token", 10, None),
            binding=replace(binding(), target_name=name), actor_name="synthetic-api",
            actor_profile="super_admin", witness_key=KEY, client_factory=h.factory)
    assert not h.requests
