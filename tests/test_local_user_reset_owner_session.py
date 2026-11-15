"""Synthetic-only acceptance of the private BP002 session boundary."""
from __future__ import annotations

from dataclasses import replace
import json
import ssl
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from fortipam_mcp.local_user_reset_http_transport import (
    FortiPamLocalUserResetHttpTransport, LocalUserResetBaseline, LocalUserResetBinding,
    LocalUserResetHttpOutcome, LocalUserResetHttpTransportError, LocalUserResetMaterialLease,
    _CHANGE_PATH, _POLICY_PATH,
)
from fortipam_mcp.local_user_reset_owner_session import LocalUserResetOwnerSessionTransport
from fortipam_mcp.secret_metadata_http_transport import SYSTEM_STATUS_PATH, SecretMetadataHttpTransportConfig


def _binding() -> LocalUserResetBinding:
    return LocalUserResetBinding(LocalUserResetBaseline(
        username="mcp-v4-user-reset-synthetic", status="disable", is_local=True,
        access_profile="Guest", sponsor_group="", schedule="", guest_auth="enable",
        nonmaterial_state_digest="a" * 64, fixture_creation_digest="c" * 64,
        reported_reference_count=0, usage_entry_count=0,
        product_version="7.0.0", product_build=29,
    ))


class _RawResponse:
    def __init__(self, content: bytes, *, encoding: str = "identity") -> None:
        self.status = 200
        self.content, self.offset, self.encoding = content, 0, encoding
        self.closed = False

    def getheader(self, name: str, default: str = "") -> str:
        return {"content-type": "application/json", "content-encoding": self.encoding}.get(name, default)

    def readinto(self, buffer: memoryview) -> int:
        count = min(len(buffer), len(self.content) - self.offset)
        buffer[:count] = self.content[self.offset:self.offset + count]
        self.offset += count
        return count

    def close(self) -> None:
        self.closed = True


class _Harness:
    def __init__(self, *, failure: str = "", enabled: bool = True) -> None:
        self.failure, self.active = failure, False
        self.now = 100.0
        self.calls: list[tuple[str, str]] = []
        self.writes: list[tuple[str, str, bytes, dict[str, str]]] = []
        self.raws: list[Any] = []
        self.binding = _binding()
        self.config = SecretMetadataHttpTransportConfig("https://pam.example.test:9443", "never-send", 5, None)
        self.owner = LocalUserResetOwnerSessionTransport(
            self.config, owner_name="synthetic-owner", credentials=self.credentials,
            binding=self.binding, enabled=enabled, client_factory=self.client,
            connection_factory=self.connection, clock=lambda: self.now,
        )

    def credentials(self) -> tuple[str, str]:
        return ("wrong-owner" if self.failure == "credentials" else "synthetic-owner", "synthetic-only")

    def client(self, **kwargs: Any) -> httpx.Client:
        assert kwargs["follow_redirects"] is False and kwargs["trust_env"] is False
        assert kwargs["verify"].verify_mode == ssl.CERT_REQUIRED
        assert kwargs["verify"].check_hostname is True
        return httpx.Client(**kwargs, transport=httpx.MockTransport(self.respond))

    def respond(self, request: httpx.Request) -> httpx.Response:
        assert request.url.host == "pam.example.test" and request.url.port == 9443
        assert "authorization" not in request.headers
        path = request.url.path
        self.calls.append((request.method, path))
        if path == "/remote/login":
            page = '<form action="/XX/YY/ZZ/AUTH" method="post">'
            if self.failure == "form":
                page = '<a action="/XX/YY/ZZ/AUTH">'
            if self.failure == "oversize_login":
                page += " " * 65536
            return httpx.Response(200, text=page)
        if path == "/XX/YY/ZZ/AUTH":
            assert parse_qs(request.content.decode())["username"] == ["synthetic-owner"]
            self.active = self.failure not in {"login_redirect", "query_redirect", "route"}
            location = {"host": "https://other.example/", "port": "https://pam.example.test:9444/",
                "scheme": "http://pam.example.test:9443/", "userinfo": "https://other@pam.example.test:9443/",
                "route": "/api/v2/monitor/system/status", "api_root": "/api",
                "logout_route": "/logout", "encoded_route": "/ui/%2e%2e/home",
                "fragment_route": "/ui/home#unsafe", "landing_failed": "/ui/home",
                "login_redirect": "/remote/login?reason=synthetic",
                "query_redirect": "/?reason=synthetic",
                "nonroot_success": "/ui/home?context=synthetic"}.get(self.failure, "/")
            cookies = ["session=synthetic; Secure; HttpOnly; Path=/"]
            if self.failure != "csrf":
                cookies.append("ccsrftoken=synthetic-csrf; Secure; Path=/")
            return httpx.Response(303, headers=[("location", location), *[("set-cookie", c) for c in cookies]])
        if path == "/logout":
            self.active = self.failure == "logout"
            return httpx.Response(200)
        if path == "/":
            return httpx.Response(200)
        if path == "/ui/home":
            return httpx.Response(500 if self.failure == "landing_failed" else 200)
        if path == SYSTEM_STATUS_PATH:
            if not self.active:
                return httpx.Response(403, json={})
            return httpx.Response(200, json={"version": "v7.0.0", "build": 30 if self.failure == "firmware" else 29})
        raise AssertionError("Unexpected route")

    def connection(self, host: str, port: int, **kwargs: Any) -> Any:
        assert (host, port) == ("pam.example.test", 9443)
        assert kwargs["context"].verify_mode == ssl.CERT_REQUIRED and kwargs["context"].check_hostname
        harness = self

        class Raw:
            closed = False
            path = ""

            def request(self, method: str, path: str, *, body: memoryview, headers: dict[str, str]) -> None:
                self.path = path
                harness.writes.append((method, path, bytes(body), dict(headers)))

            def getresponse(self) -> _RawResponse:
                payload = b'{"results":{"valid":true}}' if self.path == _POLICY_PATH else b'{"results":{"changed":true}}'
                if harness.failure == "policy":
                    payload = b'{"results":{"valid":false,"reused":true}}'
                if harness.failure == "echo":
                    payload = b'{"results":{"valid":true},"password":"synthetic"}'
                if harness.failure == "oversize_response":
                    payload += b" " * 16384
                return _RawResponse(payload, encoding="gzip" if harness.failure == "encoding" else "identity")

            def close(self) -> None:
                self.closed = True

        raw = Raw()
        self.raws.append(raw)
        return raw


def _body(binding: LocalUserResetBinding, operation: str, **override: object) -> bytearray:
    values: dict[str, object] = {"mkey": binding.expected.username, "old_password": ""}
    if operation == "policy_conform":
        values.update(apply_to="guest-admin", password="synthetic-new")
    else:
        values["new_password"] = "synthetic-new"
    values.update(override)
    return bytearray(json.dumps(values, separators=(",", ":")).encode())


def _headers(body: bytearray) -> dict[str, str]:
    return {"Accept": "application/json", "Content-Type": "application/json",
        "Content-Length": str(len(body)), "Connection": "close"}


def _policy(harness: _Harness) -> Any:
    connection = harness.owner.local_user_reset_connection("pam.example.test", 9443,
        binding=harness.binding, operation="policy_conform")
    body = _body(harness.binding, "policy_conform")
    with memoryview(body) as view:
        connection.request("POST", _POLICY_PATH, view, _headers(body))
    response = connection.getresponse()
    response.close()
    connection.close()
    return connection


def test_fixed_two_posts_with_cookie_csrf_and_backend_only_result() -> None:
    harness = _Harness()
    buffers = (bytearray(b"synthetic-old"), bytearray(b"synthetic-new"))

    class Inspector:
        def read_nonmaterial_baseline(self) -> LocalUserResetBaseline:
            return harness.binding.expected

    transport = FortiPamLocalUserResetHttpTransport(harness.config, binding=harness.binding,
        inspector=Inspector(), owner_session=harness.owner, enabled=True,
        material_lease_provider=lambda: LocalUserResetMaterialLease(
            lambda: (memoryview(buffers[0]), memoryview(buffers[1]))))
    with harness.owner.authenticated():
        result = transport.reset()
        assert result.outcome == LocalUserResetHttpOutcome.BACKEND_CHANGED_METADATA_PRESERVED
        assert result.backend_changed and result.metadata_preserved and not result.login_verified
        assert transport.reset().outcome == LocalUserResetHttpOutcome.GATE_CLOSED
    assert harness.owner.logout_verified and harness.owner._client is None
    assert [row[1] for row in harness.writes] == [_POLICY_PATH, _CHANGE_PATH]
    for _, _, _, headers in harness.writes:
        assert "Authorization" not in headers and headers["X-CSRFTOKEN"] == "synthetic-csrf"
        assert "session=synthetic" in headers["Cookie"] and headers["User-Agent"]
    assert not any(buffers[0]) and not any(buffers[1])
    assert all(raw.closed for raw in harness.raws)


@pytest.mark.parametrize("failure", ["form", "credentials", "host", "port", "scheme", "userinfo", "route", "api_root", "logout_route", "encoded_route", "fragment_route", "login_redirect", "query_redirect", "firmware", "logout", "oversize_login"])
def test_login_fails_closed_and_clears_session(failure: str) -> None:
    harness = _Harness(failure=failure)
    with pytest.raises(LocalUserResetHttpTransportError, match="^The private Local User reset Owner session is unavailable\\.$"):
        with harness.owner.authenticated():
            pass
    assert harness.owner._client is None and not harness.writes
    assert not any(harness.owner._key)
    if failure not in {"form", "credentials", "oversize_login"}:
        assert ("GET", "/logout") in harness.calls
    if failure in {"login_redirect", "query_redirect"}:
        assert (("GET", "/") in harness.calls) is (failure == "query_redirect")
        assert harness.calls.count(("GET", SYSTEM_STATUS_PATH)) == 2
    if failure in {"route", "api_root", "logout_route", "encoded_route", "fragment_route"}:
        assert ("GET", "/ui/home") not in harness.calls


def test_closed_gate_allows_login_but_no_write_and_nested_login_rejected() -> None:
    harness = _Harness(enabled=False)
    with harness.owner.authenticated():
        with pytest.raises(LocalUserResetHttpTransportError):
            with harness.owner.authenticated():
                pass
        for operation in ("policy_conform", "change_password"):
            with pytest.raises(LocalUserResetHttpTransportError):
                harness.owner.local_user_reset_connection("pam.example.test", 9443,
                    binding=harness.binding, operation=operation)  # type: ignore[arg-type]
    assert harness.owner.logout_verified and not harness.writes


def test_same_origin_nonroot_redirect_requires_fixed_authenticated_status() -> None:
    harness = _Harness(failure="nonroot_success", enabled=False)
    with harness.owner.authenticated():
        assert ("GET", "/") not in harness.calls
        assert ("GET", SYSTEM_STATUS_PATH) in harness.calls
        assert harness.calls.count(("GET", "/ui/home")) == 1
    assert harness.owner.logout_verified and not harness.writes


def test_landing_response_does_not_override_fixed_authenticated_status() -> None:
    harness = _Harness(failure="landing_failed", enabled=False)
    with harness.owner.authenticated():
        assert ("GET", "/ui/home") in harness.calls
        assert harness.calls.count(("GET", SYSTEM_STATUS_PATH)) == 1
    assert harness.owner.logout_verified and harness.owner._client is None
    assert not harness.writes


@pytest.mark.parametrize("failure", ["host", "port", "binding", "order", "expiry"])
def test_exact_connection_scope(failure: str) -> None:
    harness = _Harness()
    with harness.owner.authenticated():
        if failure == "expiry":
            harness.now += 301
        with pytest.raises(LocalUserResetHttpTransportError):
            harness.owner.local_user_reset_connection(
                "other.example" if failure == "host" else "pam.example.test",
                443 if failure == "port" else 9443,
                binding=replace(harness.binding) if failure == "binding" else harness.binding,
                operation="change_password" if failure == "order" else "policy_conform")
    assert not harness.writes


@pytest.mark.parametrize("failure", ["method", "path", "authorization", "cookie", "mkey", "apply_to", "extra", "missing", "duplicate", "password_type", "invalid_escape"])
def test_request_shape_cannot_be_used_as_a_relay(failure: str) -> None:
    harness = _Harness()
    with harness.owner.authenticated():
        connection = harness.owner.local_user_reset_connection("pam.example.test", 9443,
            binding=harness.binding, operation="policy_conform")
        body = _body(harness.binding, "policy_conform")
        if failure in {"mkey", "apply_to", "extra"}:
            body = _body(harness.binding, "policy_conform", **{failure: "other"})
        elif failure == "missing":
            body = bytearray(b'{"mkey":"mcp-v4-user-reset-synthetic"}')
        elif failure == "duplicate":
            body[-1:] = b',"mkey":"duplicate"}'
        elif failure == "password_type":
            body = _body(harness.binding, "policy_conform", password=True)
        elif failure == "invalid_escape":
            body = bytearray(body.replace(b"synthetic-new", b"bad\\q"))
        headers = _headers(body)
        if failure in {"authorization", "cookie"}:
            headers[failure] = "must-not-relay"
        with memoryview(body) as view, pytest.raises(LocalUserResetHttpTransportError):
            connection.request("GET" if failure == "method" else "POST",
                _CHANGE_PATH if failure == "path" else _POLICY_PATH, view, headers)
    assert not harness.writes


@pytest.mark.parametrize("failure", ["policy", "echo", "oversize_response", "encoding", "csrf"])
def test_policy_must_be_acknowledged_before_change(failure: str) -> None:
    harness = _Harness(failure=failure)
    with harness.owner.authenticated():
        if failure == "policy":
            _policy(harness)
        else:
            with pytest.raises(LocalUserResetHttpTransportError):
                _policy(harness)
        with pytest.raises(LocalUserResetHttpTransportError):
            harness.owner.local_user_reset_connection("pam.example.test", 9443,
                binding=harness.binding, operation="change_password")
    assert all(row[1] != _CHANGE_PATH for row in harness.writes)


def test_changed_material_rejected_and_each_operation_reserved_once() -> None:
    harness = _Harness()
    with harness.owner.authenticated():
        _policy(harness)
        with pytest.raises(LocalUserResetHttpTransportError):
            _policy(harness)
        connection = harness.owner.local_user_reset_connection("pam.example.test", 9443,
            binding=harness.binding, operation="change_password")
        body = _body(harness.binding, "change_password", new_password="different-synthetic")
        with memoryview(body) as view, pytest.raises(LocalUserResetHttpTransportError):
            connection.request("POST", _CHANGE_PATH, view, _headers(body))
        with pytest.raises(LocalUserResetHttpTransportError):
            harness.owner.local_user_reset_connection("pam.example.test", 9443,
                binding=harness.binding, operation="change_password")
    assert len(harness.writes) == 1


def test_connection_from_old_generation_cannot_dispatch_after_relogin() -> None:
    harness = _Harness()
    with harness.owner.authenticated():
        connection = harness.owner.local_user_reset_connection("pam.example.test", 9443,
            binding=harness.binding, operation="policy_conform")
    with harness.owner.authenticated():
        body = _body(harness.binding, "policy_conform")
        with memoryview(body) as view, pytest.raises(LocalUserResetHttpTransportError):
            connection.request("POST", _POLICY_PATH, view, _headers(body))
        with pytest.raises(LocalUserResetHttpTransportError):
            harness.owner.local_user_reset_connection("pam.example.test", 9443,
                binding=harness.binding, operation="policy_conform")
    assert not harness.writes and harness.owner.logout_verified


def test_owner_cannot_be_bound_reset_target() -> None:
    harness = _Harness()
    with pytest.raises(LocalUserResetHttpTransportError):
        LocalUserResetOwnerSessionTransport(harness.config,
            owner_name=harness.binding.expected.username.upper(), credentials=harness.credentials,
            binding=harness.binding)


def test_explicit_zero_port_is_rejected() -> None:
    harness = _Harness()
    config = SecretMetadataHttpTransportConfig("https://pam.example.test:0", "unused", 5, None)
    with pytest.raises(LocalUserResetHttpTransportError):
        LocalUserResetOwnerSessionTransport(config, owner_name="synthetic-owner",
            credentials=harness.credentials, binding=harness.binding)


@pytest.mark.parametrize("failure", ["cookies", "close"])
def test_cleanup_exception_is_fixed_and_cannot_keep_session_lock(failure: str) -> None:
    harness = _Harness()

    def factory(**kwargs: Any) -> httpx.Client:
        client = harness.client(**kwargs)
        original_close = client.close

        def raise_cleanup(domain: str | None = None, path: str | None = None) -> None:
            del domain, path
            if failure == "close":
                original_close()
            raise RuntimeError("synthetic-private-detail-must-not-escape")

        if failure == "cookies":
            client.cookies.clear = raise_cleanup  # type: ignore[method-assign]
        else:
            client.close = raise_cleanup  # type: ignore[method-assign]
        return client

    harness.owner._client_factory = factory
    with pytest.raises(LocalUserResetHttpTransportError) as caught:
        with harness.owner.authenticated():
            pass
    assert "synthetic-private" not in str(caught.value)
    assert caught.value.__suppress_context__
    assert harness.owner._client is None and not harness.owner._session_lock.locked()
    harness.owner._client_factory = harness.client
    with harness.owner.authenticated():
        pass
    assert harness.owner.logout_verified


def test_dispatch_uses_validated_snapshot_even_if_caller_buffer_changes() -> None:
    harness = _Harness()
    with harness.owner.authenticated():
        connection = harness.owner.local_user_reset_connection("pam.example.test", 9443,
            binding=harness.binding, operation="policy_conform")
        original = _body(harness.binding, "policy_conform")
        expected = bytes(original)
        raw = harness.raws[-1]
        send = raw.request
        snapshot_owner: list[bytearray] = []

        def tamper(method: str, path: str, *, body: memoryview, headers: dict[str, str]) -> None:
            assert body.readonly and isinstance(body.obj, bytearray)
            snapshot_owner.append(body.obj)
            original[:] = b"x" * len(original)
            send(method, path, body=body, headers=headers)

        raw.request = tamper
        with memoryview(original) as view:
            connection.request("POST", _POLICY_PATH, view, _headers(original))
        assert harness.writes[0][2] == expected
        assert not any(snapshot_owner[0])
