"""Existing-Target source boundaries with synthetic HTTP and no device IO."""
import copy
from dataclasses import replace
import hashlib
import json
import logging
import pickle
import ssl

import httpx
import pytest

from fortipam_mcp import windows_service_credential_target_sources as r
from test_target_preservation_contract import row as configuration_row, SERIAL, DIGEST, NAME
from test_windows_service_credential_contract import binding
from test_windows_privileged_secret_contract import binding as privileged_binding
from v4_planning.material_provider import MaterialAccessDenied

ACTOR = "synthetic-api-actor"
ADDRESS = "192.0.2.1"


def envelope(results, *, runtime=False, actor=False):
    return dict(version="v7.0.0", build=29, path="web-ui" if actor else "secret",
        name="state" if actor else "target", http_method="POST" if runtime else "GET",
        status="OK" if runtime else "success", http_status=200, serial=SERIAL,
        vdom="root", results=results)


def payloads():
    actor = envelope(dict(admin=dict(name=ACTOR, login_name=ACTOR, sponsored_group_name="",
        guest_admin=False, global_admin=True, profile=dict(name="synthetic-role", other="fixed")),
        vdom_mode="", maintenance_mode=dict(mode="disable")), actor=True)
    state = configuration_row();state["domain"] = ""
    configuration = envelope([state]);configuration["mkey"] = NAME
    runtime = envelope([dict(name=NAME, address=ADDRESS, domain="", url="",
        template=state["template"], permissions=dict(user="owner"), is_service_addr=False,
        priv_acct=0, opaque_extra=dict(unselected="PRIVATE_RUNTIME_SENTINEL"))], runtime=True)
    runtime.update(size=1, filtered_count=1, next_idx=0, limit_reached=False)
    return [copy.deepcopy(value) for value in (actor, configuration, runtime, runtime, configuration, actor)]


class Body(httpx.SyncByteStream):
    def __init__(self, data, harness, index):
        self.data, self.harness, self.index, self.closed = data, harness, index, False
    def __iter__(self):
        yield self.data
        if self.index == 2:
            if self.harness.fault == "stream": raise OSError("PRIVATE_STREAM_SENTINEL")
            if self.harness.fault == "interrupt": raise KeyboardInterrupt()
            if self.harness.fault == "late-eof": self.harness.now = 40.0
            if self.harness.fault == "clock-rollback": self.harness.now = 9.0
    def close(self):
        self.closed = True
        if self.index == 2 and self.harness.fault == "response-close":
            raise OSError("PRIVATE_CLOSE_SENTINEL")


class Harness:
    def __init__(self, fault=None):
        self.now, self.fault = 10.0, fault
        self.values, self.requests, self.streams, self.clients, self.options = payloads(), [], [], [], []
    def handle(self, request):
        index = len(self.requests); self.requests.append(request)
        logging.getLogger("httpcore.http11").debug("PRIVATE_HEADER_SENTINEL")
        data = json.dumps(self.values[index]).encode()
        headers = {"content-type": "application/json", "set-cookie": "synthetic=private"}
        status = 200
        if index == 2:
            if self.fault == "oversize": data = b"x" * (r._MAX_BYTES + 1)
            if self.fault == "truncated": data = data[:-1]
            if self.fault == "trailing": data += b"{}"
            if self.fault == "whitespace": data = b" \n" + data + b"\t "
            if self.fault == "status": status = 403
            if self.fault == "redirect": status = 302;headers["location"] = "https://other.invalid/private"
            if self.fault == "type": headers["content-type"] = "text/html"
            if self.fault == "encoding": headers["content-encoding"] = "gzip"
            if self.fault == "length": headers["content-length"] = str(len(data) + 1)
            if self.fault == "zero-length": headers["content-length"] = "0"
            if self.fault == "te-and-length": headers.update({"content-length": str(len(data)), "transfer-encoding": "chunked"})
            if self.fault == "late-headers": self.now = 40.0
        stream = Body(data, self, index);self.streams.append(stream)
        return httpx.Response(status, headers=headers, stream=stream)
    def factory(self, **options):
        self.options.append(options)
        if self.fault == "factory": raise OSError("PRIVATE_FACTORY_SENTINEL")
        h = self
        class Client(httpx.Client):
            def __exit__(self, *args):
                super().__exit__(*args)
                if h.fault == "client-close": raise OSError("PRIVATE_CLIENT_SENTINEL")
                if h.fault == "late-client-close": h.now = 40.0
        client = Client(transport=httpx.MockTransport(self.handle), **options)
        self.clients.append(client);return client
    def reader(self, **changes):
        raw = bytearray(json.dumps(payloads()[0]).encode())
        try:
            expected_actor = r._actor_context(raw, expected_name=ACTOR)
        finally:
            r._zeroize_mutable(raw)
        options = dict(target_name=NAME, target_address=ADDRESS, expected_actor_context_digest=expected_actor,
            serial_digest=DIGEST, clock=lambda: self.now, client_factory=self.factory)
        options.update(changes)
        return r.WindowsServiceCredentialTargetSources(
            r.SecretMetadataHttpTransportConfig("https://synthetic.invalid", "synthetic-token", 8, None), **options)


def test_fixed_six_read_bracket_binds_service_profile_without_material_or_authority(monkeypatch, caplog):
    h = Harness();reader = h.reader();owned = [];original = reader._receive
    def track(*args):
        value = original(*args);owned.append(value);return value
    monkeypatch.setattr(reader, "_receive", track)
    caplog.set_level(logging.DEBUG)
    observation = reader.read_once();reader.check_current(observation)
    profile = replace(binding(), target_name=NAME, target_address=ADDRESS, serial_digest=DIGEST,
        target_reference_context_digest=observation.target_reference_context_digest)
    reader.check_profile(observation, profile)
    assert [q.method for q in h.requests] == ["GET", "GET", "POST", "POST", "GET", "GET"]
    assert [q.url.path for q in h.requests] == [r._ACTOR, r._TARGET + "/" + NAME,
        r._TARGET, r._TARGET, r._TARGET + "/" + NAME, r._ACTOR]
    for request in h.requests:
        assert request.headers["authorization"] == "Bearer synthetic-token"
        assert request.headers["accept-encoding"] == "identity" and "cookie" not in request.headers
    for request in h.requests[2:4]:
        assert request.headers["x-http-method-override"] == "GET"
        assert json.loads(request.content) == {"json_filter": [{"logic": "or", "filters": [{
            "key": "name", "type": "string", "operator": "exact", "negate": False, "pattern": NAME}]}]}
    assert observation.runtime_field_count == 9 and observation.observed_at == 10 and observation.expires_at == 40
    assert all(not raw for raw in owned) and all(s.closed for s in h.streams) and all(c.is_closed for c in h.clients)
    assert not h.options[0]["trust_env"] and not h.options[0]["follow_redirects"]
    assert h.options[0]["verify"].verify_mode == ssl.CERT_REQUIRED and h.options[0]["verify"].check_hostname
    assert "PRIVATE_" not in caplog.text and "synthetic" not in caplog.text
    assert not hasattr(reader, "execute") and not hasattr(observation, "association_context_digest")
    for value in (reader, observation):
        assert ACTOR not in repr(value) and NAME not in repr(value)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(MaterialAccessDenied): operation(value)
    reader.close()
    with pytest.raises(r.WindowsServiceCredentialTargetSourceError): reader.check_current(observation)


@pytest.mark.parametrize("index", range(6))
def test_each_response_is_bound_to_native_device_and_version(index):
    h = Harness();h.values[index]["serial"] = "OTHER"
    with pytest.raises(r.WindowsServiceCredentialTargetSourceError): h.reader().read_once()
    assert len(h.requests) <= index + 1 and all(s.closed for s in h.streams)


@pytest.mark.parametrize("fault", ["factory", "oversize", "truncated", "trailing", "status", "redirect", "type",
    "encoding", "length", "zero-length", "te-and-length", "late-headers", "stream", "late-eof",
    "clock-rollback", "response-close", "client-close", "late-client-close"])
def test_failed_window_is_consumed_closed_and_never_replayed(fault, monkeypatch):
    h = Harness(fault);reader = h.reader();owned = [];original = reader._receive
    def track(*args):
        value = original(*args);owned.append(value);return value
    monkeypatch.setattr(reader, "_receive", track)
    with pytest.raises(r.WindowsServiceCredentialTargetSourceError) as error: reader.read_once()
    assert str(error.value) == r._ERROR and error.value.__suppress_context__
    count = len(h.requests)
    with pytest.raises(r.WindowsServiceCredentialTargetSourceError): reader.read_once()
    assert len(h.requests) == count and all(not raw for raw in owned)
    assert all(s.closed for s in h.streams) and all(c.is_closed for c in h.clients)


@pytest.mark.parametrize("fault", ["config-drift", "runtime-extra-drift", "runtime-fields-drift", "actor-profile-drift",
    "privilege-bool", "service-address", "permission", "wrong-name", "wrong-template", "multiple", "empty",
    "paging", "matched-count", "schema-errors", "status-success"])
def test_wrong_representation_identity_reference_or_scope_refuses(fault):
    h = Harness()
    if fault == "config-drift": h.values[4]["results"][0]["description"] = "changed"
    if fault == "runtime-extra-drift": h.values[3]["results"][0]["opaque_extra"] = {"other": "changed"}
    if fault == "runtime-fields-drift": h.values[3]["results"][0]["new_field"] = "changed"
    if fault == "actor-profile-drift": h.values[5]["results"]["admin"]["profile"]["other"] = "changed"
    if fault == "privilege-bool": h.values[2]["results"][0]["priv_acct"] = False
    if fault == "service-address": h.values[2]["results"][0]["is_service_addr"] = True
    if fault == "permission": h.values[2]["results"][0]["permissions"]["user"] = "none"
    if fault == "wrong-name": h.values[2]["results"][0]["name"] = "other"
    if fault == "wrong-template": h.values[2]["results"][0]["template"] = "other"
    if fault == "multiple": h.values[2]["results"] *= 2
    if fault == "empty": h.values[2]["results"] = []
    if fault == "paging": h.values[2]["has_more"] = False
    if fault == "matched-count": h.values[2]["matched_count"] = 2
    if fault == "schema-errors": h.values[2]["schema_errors"] = []
    if fault == "status-success": h.values[2]["status"] = "success"
    with pytest.raises(r.WindowsServiceCredentialTargetSourceError): h.reader().read_once()
    assert len(h.requests) <= 6 and all(c.is_closed for c in h.clients)


@pytest.mark.parametrize("fault", ["identity", "consistent-other-identity", "global", "guest", "sponsor", "vdom", "maintenance"])
def test_actor_context_is_not_substituted_by_owner_or_role_metadata(fault):
    h = Harness();state = h.values[0]["results"];admin = state["admin"]
    if fault == "identity": admin["name"] = "other"
    if fault == "consistent-other-identity": admin.update(name="other", login_name="other")
    if fault == "global": admin["global_admin"] = False
    if fault == "guest": admin["guest_admin"] = True
    if fault == "sponsor": admin["sponsored_group_name"] = "other"
    if fault == "vdom": state["vdom_mode"] = "split-vdom"
    if fault == "maintenance": state["maintenance_mode"]["mode"] = "enable"
    with pytest.raises(r.WindowsServiceCredentialTargetSourceError): h.reader().read_once()
    assert len(h.requests) == 1


@pytest.mark.parametrize("fault", ["copy", "tamper", "expiry", "clock", "factory", "config", "tls", "profile", "privileged"])
def test_source_lifetime_and_exact_profile_binding_are_not_digest_attestations(fault):
    h = Harness();reader = h.reader();observed = reader.read_once()
    profile = replace(binding(), target_name=NAME, target_address=ADDRESS, serial_digest=DIGEST,
        target_reference_context_digest=observed.target_reference_context_digest)
    if fault == "copy": observed = replace(observed)
    if fault == "tamper": object.__setattr__(observed, "runtime_digest", "f" * 64)
    if fault == "expiry": h.now = 40.0
    if fault == "clock": reader._clock = lambda: 10.0
    if fault == "factory": reader._factory = h.factory
    if fault == "config": object.__setattr__(reader._config, "bearer_token", "other")
    if fault == "tls": reader._tls.check_hostname = False
    if fault == "profile": profile = replace(profile, target_reference_context_digest="f" * 64)
    if fault == "privileged": profile = privileged_binding()
    with pytest.raises(r.WindowsServiceCredentialTargetSourceError): reader.check_profile(observed, profile)
    assert len(h.requests) == 6


def test_whitespace_framing_is_valid_but_no_second_read_window_is_available():
    h = Harness("whitespace");reader = h.reader();observed = reader.read_once();reader.check_current(observed)
    with pytest.raises(r.WindowsServiceCredentialTargetSourceError): reader.read_once()
    assert len(h.requests) == 6


def test_unselected_target_values_are_fingerprinted_without_scalar_decoding(monkeypatch):
    original = r.m._scalar
    def selected(raw, span):
        assert b"SENTINEL" not in raw[slice(*span)]
        return original(raw, span)
    monkeypatch.setattr(r.m, "_scalar", selected)
    h = Harness();reader = h.reader();reader.check_current(reader.read_once())


def test_interrupt_closes_and_consumes_the_partial_window():
    h = Harness("interrupt");reader = h.reader()
    with pytest.raises(KeyboardInterrupt): reader.read_once()
    assert all(s.closed for s in h.streams) and all(c.is_closed for c in h.clients)
    with pytest.raises(r.WindowsServiceCredentialTargetSourceError): reader.read_once()
    assert len(h.requests) == 3


def test_changed_ca_file_revokes_observation_before_another_request(tmp_path, monkeypatch):
    ca = tmp_path / "ca.pem";ca.write_text("SYNTHETIC_CA_A")
    original = ssl.create_default_context;loaded = []
    def context(*, cadata=None):
        loaded.append(cadata)
        return original()
    monkeypatch.setattr(r.ssl, "create_default_context", context)
    h = Harness();raw = bytearray(json.dumps(payloads()[0]).encode())
    try:
        identity = r._actor_context(raw, expected_name=ACTOR)
    finally:
        r._zeroize_mutable(raw)
    reader = r.WindowsServiceCredentialTargetSources(
        r.SecretMetadataHttpTransportConfig("https://synthetic.invalid", "synthetic-token", 8, str(ca)),
        target_name=NAME, target_address=ADDRESS, serial_digest=DIGEST,
        expected_actor_context_digest=identity, clock=lambda: h.now, client_factory=h.factory)
    observed = reader.read_once();ca.write_text("SYNTHETIC_CA_B")
    with pytest.raises(r.WindowsServiceCredentialTargetSourceError): reader.check_current(observed)
    assert loaded == ["SYNTHETIC_CA_A"] and len(h.requests) == 6


@pytest.mark.parametrize("changes", [dict(target_name="MCPV4WinTarget20261025R1"),
    dict(target_name="../other"), dict(target_address="127.0.0.1"), dict(serial_digest="invalid")])
def test_unqualified_selectors_refuse_before_http(changes):
    h = Harness()
    with pytest.raises(r.WindowsServiceCredentialTargetSourceError): h.reader(**changes)
    assert not h.requests and not h.clients
