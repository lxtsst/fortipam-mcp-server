"""Synthetic Owner window and fixed HTTP peer; no real configuration read."""
from copy import copy, deepcopy
import hashlib
import json
import pickle
from types import SimpleNamespace

import pytest

from fortipam_mcp import approval_delivery_source as module
from fortipam_mcp.owner_session_metadata import OwnerSessionMetadataTransport
from fortipam_mcp.secret_metadata_http_transport import (
    FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig,
)
from test_approval_delivery_contract import state
from test_approval_delivery_material_contract import BINDINGS, SYNTHETIC
from test_approval_delivery_material_projection import frame
from test_approval_delivery_projection import SERIAL, CANARY
from v4_planning.material_provider import MaterialAccessDenied

COOKIE = "SYNTHETIC_APPROVAL_COOKIE_MUST_NOT_BE_HASHED"
ACTOR = "synthetic-owner"


class Peer:
    def __init__(self, protocol="imaps"):
        self.payload = frame(protocol)
        self.time, self.cookie = 10.0, COOKIE
        self.calls, self.resources, self.buffers = [], [], []
        self.fault = None
        self.credentials = 0
        self.hook = lambda phase: None

    def clock(self):
        return self.time

    def login(self):
        self.credentials += 1
        raise AssertionError("The source must not resolve credentials or log in.")

    def client(self):
        peer = self
        class Client:
            def build_request(self, method, url):
                assert method == "GET" and url == "https://pam.example.test" + module.CURRENT_PATH
                return SimpleNamespace(headers={"cookie": peer.cookie})
        return Client()

    def factory(self, host, port, **options):
        peer = self
        assert host == "pam.example.test" and port == 443
        assert options["context"].check_hostname and 0 < options["timeout"] <= 5
        class Socket:
            def settimeout(self, timeout):
                assert 0 < timeout <= 5
        class Connection:
            def __init__(self):
                self.sock, self.closed = Socket(), False
                peer.resources.append(self)
            def set_debuglevel(self, value):
                assert value == 0
            def connect(self):
                peer.hook("connect")
            def request(self, method, path, *, headers):
                assert method == "GET" and path == module.CURRENT_PATH
                assert headers["Cookie"] == peer.cookie and "Authorization" not in headers
                assert headers["Accept-Encoding"] == "identity"
                peer.calls.append((method, path))
            def getresponse(self):
                result = Response()
                if peer.fault == "detached":
                    self.sock = None
                return result
            def close(self):
                self.closed = True
                peer.hook("connection-close")
        class Response:
            def __init__(self):
                self.raw = json.dumps(peer.payload, separators=(",", ":")).encode()
                self.offset, self.closed = 0, False
                self.status = 302 if peer.fault == "redirect" else 200
                peer.resources.append(self)
            def getheader(self, name, default=None):
                return {"content-type": "text/html" if peer.fault == "html" else "application/json",
                    "content-encoding": "gzip" if peer.fault == "gzip" else "identity",
                    "content-length": ("2097153" if peer.fault == "oversize" else
                        str(len(self.raw) + (1 if peer.fault == "truncated" else 0))),
                    "transfer-encoding": "chunked" if peer.fault == "ambiguous-length" else None}.get(name.lower(), default)
            def isclosed(self):
                return self.offset >= len(self.raw)
            def readinto(self, view):
                if not peer.buffers or peer.buffers[-1] is not view.obj:
                    peer.buffers.append(view.obj)
                count = min(len(view), len(self.raw) - self.offset, 173)
                view[:count] = self.raw[self.offset:self.offset + count]
                self.offset += count
                peer.hook("read")
                if peer.fault == "invalid-count":
                    return True
                return count
            def close(self):
                self.closed = True
                peer.hook("response-close")
        return Connection()


@pytest.fixture
def candidate():
    owners, sources = [], []
    def make(protocol="imaps", guard=True):
        peer = Peer(protocol)
        config = SecretMetadataHttpTransportConfig("https://pam.example.test", "synthetic-unused-bearer", 5, None)
        owner = OwnerSessionMetadataTransport(config, owner_name=ACTOR, credentials=peer.login,
            folder_path="synthetic", secret_name="synthetic", target_name="synthetic",
            witness=FortiPamSecretMetadataHttpTransport(config), connection_factory=peer.factory, clock=peer.clock)
        owner._client, owner._expires_at = peer.client(), 70.0
        owner._session_lock.acquire()
        owners.append(owner)
        source = module.ApprovalDeliverySource(owner, expected_actor=ACTOR, expected_serial=SERIAL,
            material_binding_digests=BINDINGS, source_guard=(lambda: True) if guard else None)
        sources.append(source)
        assert not peer.calls and peer.credentials == 0
        return peer, source, owner
    yield make
    for source in sources:
        source.close()
    for owner in owners:
        owner._client = None
        if owner._session_lock.locked():
            owner._session_lock.release()


@pytest.mark.parametrize("protocol", ["imaps", "ms-graph"])
@pytest.mark.parametrize("enabled", [True, False])
def test_one_fixed_get_feeds_private_compilation_without_login_write_or_material_output(candidate, protocol, enabled):
    peer, source, owner = candidate(protocol)
    summary = source.read()
    retained = list(source._projection._buffers.values())
    draft = source._prepare_request(state(protocol), enabled=enabled)
    body = source._compile_once(draft)
    try:
        payload = json.loads(body)["approval-email-setting"]
        assert all(payload[role].encode() == value for role, value in SYNTHETIC.items())
        assert payload["server"] == ("example.test" if enabled else "")
        assert all(not any(buffer) for buffer in [*retained, *peer.buffers, source._cookie])
        assert peer.calls == [("GET", module.CURRENT_PATH)] and peer.credentials == 0
        assert all(resource.closed for resource in peer.resources)
        assert owner._client is not None and owner._session_lock.locked()
        assert summary["fixed_get_completed"] is True
        assert summary["execution_authorized"] is False and summary["whole_setting_baseline_verified"] is False
        assert source.summary()["closed"] is True
        assert all(canary not in repr(summary) for canary in [COOKIE, SERIAL, CANARY, ACTOR, "example.test"])
        with pytest.raises(ValueError):
            source._compile_once(draft)
        with pytest.raises(ValueError):
            source.read()
        assert len(peer.calls) == 1
    finally:
        body[:] = b"\0" * len(body)


def test_protected_values_and_unselected_config_never_enter_decode_or_digest(candidate, monkeypatch):
    peer, source, _ = candidate()
    decode, digest = json.loads, hashlib.sha256
    def check(value):
        raw = value.encode() if isinstance(value, str) else value
        assert COOKIE.encode() not in raw and CANARY.encode() not in raw
        assert not any(secret in raw for secret in SYNTHETIC.values())
    def safe_decode(value, *args, **kwargs):
        check(value)
        return decode(value, *args, **kwargs)
    def safe_digest(value=b"", *args, **kwargs):
        check(value)
        return digest(value, *args, **kwargs)
    monkeypatch.setattr(json, "loads", safe_decode)
    monkeypatch.setattr(hashlib, "sha256", safe_digest)
    source.read()
    draft = source._prepare_request(state(), enabled=False)
    body = source._compile_once(draft)
    body[:] = b"\0" * len(body)
    assert len(peer.calls) == 1


def test_guard_is_unbound_by_default_and_denies_before_io(candidate):
    peer, source, _ = candidate(guard=False)
    with pytest.raises(ValueError, match="^The private approval-delivery source is unavailable.$"):
        source.read()
    assert not peer.calls and not peer.resources and source.summary()["closed"]
    assert not any(source._cookie)


@pytest.mark.parametrize("fault", ["redirect", "html", "gzip", "oversize", "truncated", "ambiguous-length", "invalid-count"])
def test_bad_http_response_fails_closed_without_retry_or_material_retention(candidate, fault):
    peer, source, _ = candidate()
    peer.fault = fault
    with pytest.raises(ValueError) as error:
        source.read()
    assert COOKIE not in str(error.value) and CANARY not in str(error.value)
    assert len(peer.calls) == 1 and all(resource.closed for resource in peer.resources)
    assert all(not any(buffer) for buffer in [*peer.buffers, source._cookie])
    with pytest.raises(ValueError):
        source.read()
    assert len(peer.calls) == 1


@pytest.mark.parametrize("mutation", ["cookie", "client", "config", "actor", "expiry", "lock", "timeout", "backwards", "tls"])
def test_window_change_after_read_denies_compilation_and_clears_retained_slots(candidate, mutation):
    peer, source, owner = candidate()
    source.read()
    draft = source._prepare_request(state(), enabled=False)
    retained = list(source._projection._buffers.values())
    if mutation == "cookie": peer.cookie = "SYNTHETIC_REPLACED_COOKIE"
    elif mutation == "client": owner._client = peer.client()
    elif mutation == "config": owner._config = SecretMetadataHttpTransportConfig("https://other.example.test", "synthetic", 5, None)
    elif mutation == "actor": owner._owner_name = "synthetic-other-owner"
    elif mutation == "expiry": owner._expires_at += 1
    elif mutation == "lock": owner._session_lock.release()
    elif mutation == "timeout": peer.time += 5
    elif mutation == "backwards": peer.time -= 1
    else: source._tls.check_hostname = False
    with pytest.raises(ValueError):
        source._compile_once(draft)
    assert all(not any(buffer) for buffer in [*retained, source._cookie])
    assert len(peer.calls) == 1


@pytest.mark.parametrize("mutation", ["close", "guard", "cookie", "expiry"])
def test_guard_callback_revocation_is_rechecked_before_any_connection(candidate, mutation):
    peer, source, owner = candidate()
    def guard():
        if mutation == "close": source.close()
        elif mutation == "guard": source._guard = lambda: True
        elif mutation == "cookie": peer.cookie = "SYNTHETIC_REPLACED_COOKIE"
        else: peer.time = owner._expires_at
        return True
    source._guard = source._guard_pin = guard
    with pytest.raises(ValueError):
        source.read()
    assert not peer.calls and not peer.resources and not any(source._cookie)


@pytest.mark.parametrize("phase", ["read", "response-close", "connection-close"])
@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_read_and_cleanup_failure_erases_all_owners_before_result(candidate, phase, error_type):
    peer, source, _ = candidate()
    def hook(at):
        if at == phase:
            raise error_type("SYNTHETIC_PRIVATE_FAILURE")
    peer.hook = hook
    expected = ValueError if issubclass(error_type, Exception) else error_type
    with pytest.raises(expected) as error:
        source.read()
    if expected is ValueError:
        assert "SYNTHETIC_PRIVATE_FAILURE" not in str(error.value)
    assert all(resource.closed for resource in peer.resources)
    assert all(not any(buffer) for buffer in [*peer.buffers, source._cookie])
    assert source._projection is None


def test_final_read_cleanup_failure_does_not_publish_or_retain_projection(candidate, monkeypatch):
    peer, source, _ = candidate()
    original = module._erase_transfer_storage
    project_original = module.project_material_approval_delivery
    consumed = []
    # Projection erases and clears the raw allocation, so identify its owner
    # rather than relying on the consumed buffer's length.
    def project(raw, **kwargs):
        observed = project_original(raw, **kwargs)
        consumed.append(raw)
        return observed
    monkeypatch.setattr(module, "project_material_approval_delivery", project)
    def fail_after_projection(buffer):
        original(buffer)
        if consumed and buffer is consumed[0]:
            raise KeyboardInterrupt
    monkeypatch.setattr(module, "_erase_transfer_storage", fail_after_projection)
    with pytest.raises(KeyboardInterrupt):
        source.read()
    assert source._projection._closed and all(not any(value) for value in source._projection._buffers.values())
    assert not any(source._cookie) and all(not any(value) for value in peer.buffers)
    monkeypatch.setattr(module, "_erase_transfer_storage", original)


def test_window_revoked_after_encoding_erases_pending_body_before_handoff(candidate, monkeypatch):
    peer, source, _ = candidate()
    source.read()
    draft = source._prepare_request(state(), enabled=False)
    projector = type(source._projection)
    original, pending = projector._compile_once, []
    def compile_once(observed, selected):
        body = original(observed, selected)
        pending.append(body)
        peer.cookie = "SYNTHETIC_REVOKED_AFTER_ENCODING"
        return body
    monkeypatch.setattr(projector, "_compile_once", compile_once)
    with pytest.raises(ValueError):
        source._compile_once(draft)
    assert pending and not any(pending[0]) and not any(source._cookie)
    assert source._projection._closed and len(peer.calls) == 1


def test_draft_identity_and_opaque_source_boundary(candidate):
    _, source, _ = candidate()
    source.read()
    source._prepare_request(state(), enabled=False)
    other = source._projection._prepare_request(state(), enabled=False)
    with pytest.raises(ValueError):
        source._compile_once(other)
    assert source._projection._closed
    for operation in (copy, deepcopy, pickle.dumps):
        with pytest.raises(MaterialAccessDenied):
            operation(source)
