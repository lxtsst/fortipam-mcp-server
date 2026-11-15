"""Synthetic IO and live allocation checks for cancellation before handoff."""
import os
from types import SimpleNamespace
from threading import RLock

import pytest

from fortipam_mcp import bp005_standard_user_preflight as bp005
from fortipam_mcp import fortitoken_user_source as token_source
from fortipam_mcp import glass_break_source as glass
from fortipam_mcp import ldap_server_http_transport as ldap
from fortipam_mcp import scim_client_native_source as scim
from fortipam_mcp import system_email_native_source as email
from fortipam_mcp import local_user_reset_api_actor as api_actor
from fortipam_mcp import local_user_reset_owner_session as owner_session
from fortipam_mcp import secret_request_approval_revoke_resolver as resolver
from test_mutable_receive_prefix import embedded
from fortipam_mcp import radius_pair_fixture_material_worker as paired
from fortipam_mcp import radius_fixture_material_worker as primary

PAYLOAD = b'{"synthetic_material":"SYNTHETIC_PRIVATE_RECEIVE_VALUE"}'


class Response:
    def __init__(self, failure=None, stage=None, payload=PAYLOAD):
        self.status = 200
        self.offset = 0
        self.buffers = []
        self.closed = False
        self.failure, self.stage = failure, stage
        self.payload = payload

    def getheader(self, name, default=None):
        return {"content-type": "application/json", "content-encoding": "identity",
                "content-length": str(len(self.payload))}.get(name.lower(), default)

    def isclosed(self):
        return self.offset == len(self.payload)

    def readinto(self, view):
        if not self.buffers or self.buffers[-1] is not view.obj:
            self.buffers.append(view.obj)
        count = min(len(view), len(self.payload) - self.offset)
        view[:count] = self.payload[self.offset:self.offset + count]
        self.offset += count
        if self.stage == "read" and count:
            raise self.failure()
        return count

    def close(self):
        self.closed = True
        if self.stage == "close": raise self.failure()


class Connection:
    def __init__(self, response):
        self.response = response
        self.sock = SimpleNamespace(settimeout=lambda value: None)
        self.closed = False
        self.calls = []

    def request(self, *args, **kwargs): self.calls.append((args, kwargs))
    def getresponse(self): return self.response
    def close(self): self.closed = True


def _reader(kind, response):
    connection = Connection(response)
    owner = SimpleNamespace(_remaining=lambda deadline: 1)
    if kind == "token":
        return token_source, lambda: token_source.FortitokenUserSource._receive(owner, connection, 10, 1024)
    if kind == "glass":
        return glass, lambda: glass.GlassBreakSource._receive(owner, connection, connection.sock, 10, 1024)
    if kind == "scim":
        return scim, lambda: scim.ScimNativeSource._receive(owner, connection, 10, 1024)
    config = SimpleNamespace(base_url="https://synthetic.example.test", bearer_token="synthetic-only", timeout_seconds=5, ca_file=None)
    owner = SimpleNamespace(_factory=lambda *args, **kwargs: connection, _host="synthetic.example.test", _port=443,
        _config=config, _context=SimpleNamespace(check_hostname=True, verify_mode=2), _closed=False)
    if kind == "email":
        return email, lambda: email.SystemEmailNativeSource._fetch(owner, email._PATH)
    if kind == "bp005-query":
        table, body = bp005._QUERIES[0]
        return bp005, lambda: bp005.FortiPamBp005StandardUserPreflightReader._read_name_query(owner, table, body)
    if kind == "bp005-get":
        return bp005, lambda: bp005.FortiPamBp005StandardUserPreflightReader._read(owner, bp005._ACTOR)
    if kind == "ldap":
        return ldap, lambda: ldap.FortiPamLdapServerHttpTransport._exchange(owner, "GET", "/fixed-synthetic", limit=1024)
    raise AssertionError


@pytest.mark.parametrize("kind", ["token", "glass", "scim", "email", "bp005-query", "bp005-get", "ldap"])
def test_receivers_transfer_data_only_after_original_read_allocation_is_erased(kind):
    response = Response(); _, invoke = _reader(kind, response)
    result = invoke()
    if isinstance(result, tuple): result = result[1]
    try:
        assert result == PAYLOAD
        assert response.buffers and all(result is not old and not any(old) for old in response.buffers)
    finally:
        result[:] = b"\0" * len(result)


@pytest.mark.parametrize("kind", ["token", "glass", "scim", "email", "bp005-query", "bp005-get", "ldap"])
@pytest.mark.parametrize("failure", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("stage", ["read", "close"])
def test_read_or_final_close_cancellation_erases_original_and_pending_exact_result(kind, failure, stage, monkeypatch):
    response = Response(failure, stage); module, invoke = _reader(kind, response)
    original = module._take_mutable_prefix; results = []
    def capture(storage, length):
        result = original(storage, length); results.append(result); return result
    monkeypatch.setattr(module, "_take_mutable_prefix", capture)
    with pytest.raises(failure): invoke()
    assert response.buffers and all(not any(value) for value in response.buffers + results)
    if stage == "close": assert results


def test_preflight_ordinary_close_failure_keeps_its_existing_success_behavior():
    response = Response(ValueError, "close"); _, invoke = _reader("bp005-get", response)
    result = invoke()
    try: assert result == PAYLOAD
    finally: result[:] = b"\0" * len(result)


@pytest.mark.parametrize("module,kind", [(api_actor, "api"), (owner_session, "owner")])
@pytest.mark.parametrize("failure", [KeyboardInterrupt, SystemExit])
def test_cancelled_response_handoff_erases_the_new_pending_owner(module, kind, failure):
    raw_response = Response(failure, "close", b'{"results":{"valid":true}}')
    raw_connection = Connection(raw_response)
    owner = SimpleNamespace(_lock=RLock(), _active=lambda generation: True,
        _policy_accepted=False, _observations={"policy_conform": {}})
    factory = module._ApiResetConnection if kind == "api" else module._ResetConnection
    connection = factory(owner, raw_connection, "policy_conform", 1, lambda: None)
    connection._sent = True
    with pytest.raises(failure): connection.getresponse()
    assert connection._response is not None and not any(connection._response._content)
    assert raw_response.buffers and all(not any(value) for value in raw_response.buffers)


@pytest.mark.parametrize("module,kind", [(api_actor, "api"), (owner_session, "owner")])
def test_successful_response_handoff_keeps_only_the_new_owner_live_until_caller_close(module, kind):
    payload = b'{"results":{"valid":true}}'; raw_response = Response(payload=payload)
    owner = SimpleNamespace(_lock=RLock(), _active=lambda generation: True,
        _policy_accepted=False, _observations={"policy_conform": {}})
    factory = module._ApiResetConnection if kind == "api" else module._ResetConnection
    connection = factory(owner, Connection(raw_response), "policy_conform", 1, lambda: None)
    connection._sent = True
    result = connection.getresponse()
    try:
        assert result._content == payload and all(not any(value) for value in raw_response.buffers)
        assert all(result._content is not old for old in raw_response.buffers)
    finally: result.close()
    assert not any(result._content)


@pytest.mark.parametrize("module", [primary, paired, resolver, embedded])
@pytest.mark.parametrize("failure", [KeyboardInterrupt, SystemExit])
def test_file_descriptor_close_cancellation_erases_unpublished_prefix(module, failure, tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    path = tmp_path / "synthetic-material"
    path.write_bytes(PAYLOAD); path.chmod(0o600)
    directory = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    original_close = os.close; original_take = module._take_mutable_prefix; results = []
    failed = False
    def capture(storage, length):
        result = original_take(storage, length); results.append(result); return result
    def close(descriptor):
        nonlocal failed
        original_close(descriptor)
        if results and descriptor != directory and not failed:
            failed = True
            raise failure()
    try:
        with monkeypatch.context() as patch:
            patch.setattr(module, "_take_mutable_prefix", capture)
            patch.setattr(module.os, "close", close)
            with pytest.raises(failure):
                if module is embedded: module.read_fixed(path, os.getuid(), 1024)
                elif module is resolver: module._read(path, 1024)
                else: module._read(directory, path.name, os.getuid(), 1024)
        assert failed and results and all(not any(result) for result in results)
    finally:
        original_close(directory)
