"""Synthetic HTTP framing and physical-channel guards; never live credentials."""
from io import BytesIO
import hashlib
import http.client
import json
import socket
import ssl

import pytest

from fortipam_mcp.ems_tag_contract import DisabledLinuxProcessTag
from fortipam_mcp.ems_tag_http_transport import (
    EmsTagHttpConfig, EmsTagHttpError, NativeEmsTagHttpTransport,
)
from fortipam_mcp.ems_tag_sources import CATALOG_PATH, METADATA_PATH
from test_ems_tag_contract import envelope
from test_ems_tag_sources import Channel


class Tls:
    check_hostname = True
    verify_mode = ssl.CERT_REQUIRED
    minimum_version = ssl.TLSVersion.TLSv1_2

    def load_verify_locations(self, *, cafile):
        self.cafile = cafile

    def wrap_socket(self, channel, *, server_hostname):
        self.server_hostname = server_hostname
        return channel


class HttpSocket:
    def __init__(self, raw): self.raw = raw
    def makefile(self, mode): return BytesIO(self.raw)


def reply(payload=None, *, status=200, content_type="application/json", extra=b"", body=None):
    body = json.dumps(payload).encode() if body is None else body
    raw = (f"HTTP/1.1 {status} Unit\r\nContent-Type: {content_type}\r\nContent-Length: {len(body)}\r\n".encode()
           + extra + b"\r\n" + body)
    response = http.client.HTTPResponse(HttpSocket(raw))
    response.begin()
    return response


def make(tmp_path, monkeypatch):
    ca = tmp_path / "ca.pem"
    ca.write_bytes(b"synthetic-ca-only")
    tls = Tls()
    monkeypatch.setattr("fortipam_mcp.ems_tag_http_transport.ssl.create_default_context", lambda: tls)
    config = EmsTagHttpConfig("ems.example.test", "192.0.2.19", "192.0.2.2", 5, ca,
        hashlib.sha256(ca.read_bytes()).hexdigest(), hashlib.sha256(b"synthetic-peer").hexdigest())
    transport = NativeEmsTagHttpTransport(config, owner_credentials=lambda: ("synthetic_owner", "synthetic-only"))
    channel, connections = Channel(), []
    fault = [None]

    class Connection:
        def __init__(self): self.closed = False
        def request(self, method, path, *, body, headers):
            self.method, self.path, self.body = method, path, body
            self.csrf_present = any(name.casefold() == "x-csrftoken" for name in headers)
        def getresponse(self):
            if self.path == "/":
                return reply(content_type="text/html", body=b"<html></html>",
                    extra=b"Set-Cookie: csrftoken=synthetic; Path=/; Secure\r\n")
            if self.path == "/api/v1/auth/signin":
                return reply(envelope(None), extra=("Set-Cookie: sessionid=" + getattr(channel,"session_value","synthetic") + "; Path=/; Secure; HttpOnly\r\n").encode())
            if self.path == "/api/v1/auth/signout":
                return reply(getattr(channel, "logout_payload", {"result": {"retval": 1, "message": "Signed out"}}))
            if self.path == "/api/v1/session/check": return reply(status=401, body=b"")
            if self.path == CATALOG_PATH and fault[0] is not None:
                return fault[0]()
            return reply(channel.get(self.path))
        def close(self): self.closed = True

    def connect():
        transport._pins()
        connection = Connection();connections.append(connection)
        return connection

    monkeypatch.setattr(transport, "_connect", connect)
    return transport, channel, connections, fault, config, tls


def test_complete_fixed_source_uses_own_credentials_and_ordinary_logout_only_once(tmp_path, monkeypatch):
    transport, channel, connections, _, _, _ = make(tmp_path, monkeypatch)
    transport.authenticate()
    source = transport.make_sources(DisabledLinuxProcessTag("a" * 32), source_key=b"s" * 32)
    current = source.observe();source.check_current(current)
    assert current.full_scope.catalog.count == 1
    assert len(channel.calls) == 7
    closure = transport.close()
    assert closure.own_logout_verified and closure.next_session_check_401
    assert closure.failure_stage is None and closure.logout_http_status == 200
    assert closure.connections_closed and closure.cookie_jar_cleared and closure.owned_mutable_buffers_cleared
    assert all(connection.closed and (connection.body is None or not connection.body) for connection in connections)
    assert all(connection.csrf_present for connection in connections[1:])
    count = len(connections)
    assert transport.close() is closure and len(connections) == count
    assert "synthetic_owner" not in repr(transport) + repr(source) + repr(current)
    with pytest.raises(EmsTagHttpError): transport.authenticate()
    source.close()


@pytest.mark.parametrize("path", ["/api/v1/tags/zero_trust/8/get", "/api/v1/tags/zero_trust/07/get",
    "/api/v1/tags/zero_trust/7/get?extra=true", "/api/v1/tags/zero_trust/create",
    "/api/v1/tags/zero_trust/delete", "/api/v1/endpoints/index", CATALOG_PATH + "&filter=anything"])
def test_unknown_or_caller_modified_routes_never_open_a_connection(tmp_path, monkeypatch, path):
    transport, _, connections, _, _, _ = make(tmp_path, monkeypatch)
    transport.authenticate();count = len(connections)
    with pytest.raises(EmsTagHttpError): transport.get_json(path)
    assert len(connections) == count
    closure = transport.close()
    assert closure.own_logout_verified and closure.next_session_check_401


@pytest.mark.parametrize("fault", ["short", "oversize", "duplicate_length", "duplicate_json", "nonfinite",
    "compressed", "chunked_length", "incomplete_chunk", "foreign_cookie", "content_type", "trailing_json"])
def test_catalog_framing_failure_closes_reads_but_allows_own_logout(tmp_path, monkeypatch, fault):
    transport, _, connections, selected, _, _ = make(tmp_path, monkeypatch)
    payload = envelope({"tags": [], "total": 0})
    def broken():
        if fault == "short": return framed(b"Content-Length: 20\r\n", b"{}")
        if fault == "oversize": return framed(b"Content-Length: 262145\r\n", b"{}")
        if fault == "duplicate_length": return reply(payload, extra=b"Content-Length: 2\r\n")
        if fault == "duplicate_json": return reply(body=b'{"data":{},"result":{"retval":1,"retval":0,"message":null}}')
        if fault == "nonfinite": return reply(body=b'{"data":NaN,"result":{"retval":1,"message":null}}')
        if fault == "compressed": return reply(payload, extra=b"Content-Encoding: gzip\r\n")
        if fault == "chunked_length": return reply(payload, extra=b"Transfer-Encoding: chunked\r\n")
        if fault == "incomplete_chunk": return framed(b"Transfer-Encoding: chunked\r\n", b"4\r\n{}")
        if fault == "foreign_cookie": return reply(payload, extra=b"Set-Cookie: csrftoken=foreign; Domain=.example.test; Path=/; Secure\r\n")
        if fault == "content_type": return reply(payload, content_type="text/plain")
        return reply(body=json.dumps(payload).encode() + b"{}")
    selected[0] = broken
    transport.authenticate()
    with pytest.raises(EmsTagHttpError): transport.get_json(CATALOG_PATH)
    count = len(connections)
    with pytest.raises(EmsTagHttpError): transport.get_json(CATALOG_PATH)
    assert len(connections) == count
    assert transport.close().own_logout_verified


def framed(headers, body):
    raw = b"HTTP/1.1 200 Unit\r\nContent-Type: application/json\r\n" + headers + b"\r\n" + body
    result = http.client.HTTPResponse(HttpSocket(raw));result.begin();return result


@pytest.mark.parametrize("fault", ["ca_rotation", "unverified_tls", "dns_drift", "peer_mismatch"])
def test_real_connector_rejects_changed_tls_dns_or_peer_before_credentials(tmp_path, monkeypatch, fault):
    transport, _, _, _, config, tls = make(tmp_path, monkeypatch)
    monkeypatch.delattr(transport, "_connect")
    calls = []
    class PhysicalSocket:
        def settimeout(self, value): calls.append(("timeout", value))
        def setsockopt(self, *args): calls.append(("interface", args))
        def bind(self, value): calls.append(("bind", value))
        def connect(self, value): calls.append(("connect", value))
        def getpeercert(self, *, binary_form): return b"different-peer" if fault == "peer_mismatch" else b"synthetic-peer"
        def close(self): calls.append(("close",))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: [(None, None, None, None,
        ("192.0.2.20" if fault == "dns_drift" else config.address, 443))])
    monkeypatch.setattr(socket, "socket", lambda *args: PhysicalSocket())
    if fault == "ca_rotation": config.ca_file.write_bytes(b"rotated")
    elif fault == "unverified_tls": tls.check_hostname = False
    with pytest.raises(EmsTagHttpError): transport.authenticate()
    assert transport._counts.get("/api/v1/auth/signin", 0) == 0
    if fault != "peer_mismatch": assert not calls
    else:
        assert ("interface", (socket.IPPROTO_IP, 25, 5)) in calls
        assert ("bind", (config.local_address, 0)) in calls and ("connect", (config.address, 443)) in calls
        assert any(call[0] == "close" for call in calls)
    transport.close()


def test_mutation_method_is_not_a_read_channel_capability(tmp_path, monkeypatch):
    transport, _, connections, _, _, _ = make(tmp_path, monkeypatch)
    transport.authenticate();count = len(connections)
    body = bytearray(b"{}")
    with pytest.raises(EmsTagHttpError): transport._request("POST", "/api/v1/tags/zero_trust/create", body)
    assert not body and len(connections) == count
    assert transport.close().own_logout_verified


@pytest.mark.parametrize("payload", [envelope(None), {"result": {"retval": True, "message": "x"}},
    {"result": {"retval": 1}}, {"result": {"retval": 1, "message": None}},
    {"result": {"retval": 0, "message": "Denied"}}])
def test_only_native_result_only_logout_envelope_is_accepted_and_failure_is_retained(tmp_path, monkeypatch, payload):
    transport, channel, connections, _, _, _ = make(tmp_path, monkeypatch)
    channel.logout_payload = payload
    transport.authenticate()
    closure = transport.close()
    assert not closure.own_logout_verified and not closure.next_session_check_401
    assert closure.failure_stage == "logout_envelope" and closure.logout_http_status == 200
    assert transport._counts.get("/api/v1/session/check", 0) == 0
    count = len(connections)
    assert transport.close() is closure and len(connections) == count


@pytest.mark.parametrize('timeout',[True,0,-1,float('nan'),float('inf'),10.01,'10',None])
def test_new_fixed_reader_timeout_bound_rejects_before_dns_or_connection(tmp_path,monkeypatch,timeout):
    transport,_,connections,_,_,_=make(tmp_path,monkeypatch); monkeypatch.delattr(transport,'_connect')
    monkeypatch.setattr(socket,'getaddrinfo',lambda *_:pytest.fail('Invalid timeout must precede DNS.'))
    with pytest.raises(ValueError): transport._connect(timeout_seconds=timeout)
    assert connections==[]


def test_real_session_binding_uses_cookie_not_python_instance_or_caller_label(tmp_path, monkeypatch):
    first, _, _, _, _, _ = make(tmp_path, monkeypatch)
    first.authenticate();one = first.session_binding_digest(b"s" * 32)
    same, _, _, _, _, _ = make(tmp_path, monkeypatch)
    same.authenticate()
    assert same.session_binding_digest(b"s" * 32) == one
    different, channel, _, _, _, _ = make(tmp_path, monkeypatch)
    channel.session_value = "different-synthetic-session"
    different.authenticate()
    assert different.session_binding_digest(b"s" * 32) != one
    assert first.session_binding_digest(b"s" * 32) == one
    for transport in (first, same, different):
        assert transport.close().next_session_check_401
        with pytest.raises(EmsTagHttpError): transport.session_binding_digest(b"s" * 32)


def test_session_binding_requires_actual_nonempty_session_cookie(tmp_path, monkeypatch):
    transport, _, _, _, _, _ = make(tmp_path, monkeypatch)
    transport.authenticate()
    for cookie in list(transport._jar):
        if cookie.name == "sessionid": transport._jar.clear(cookie.domain,cookie.path,cookie.name)
    with pytest.raises(EmsTagHttpError): transport.session_binding_digest(b"s" * 32)
    transport.close()
