"""Synthetic-only checks for the fixed BP002 policy projection and transport."""

from __future__ import annotations

from dataclasses import replace
import json
from typing import Any

import pytest

import fortipam_mcp.local_user_reset_policy_reader as policy_module
from fortipam_mcp.local_user_reset_policy_reader import (
    FortiPamLocalUserResetPolicyReader, LocalUserResetPolicyReadError,
    LocalUserResetPolicySnapshot, _PATH, _project,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig


def _body(*, fields: dict[str, object] | None = None,
          envelope: dict[str, object] | None = None) -> bytes:
    row: dict[str, object] = {
        "minimum-length": 8, "min-change-characters": 0,
        "min-upper-case-letter": 0, "min-lower-case-letter": 0,
        "min-number": 0, "min-non-alphanumeric": 0,
        "status": "disable", "reuse-password": "enable",
        "expire-status": "disable", "unparsed-extra": "opaque-sentinel",
    }
    row.update(fields or {})
    value: dict[str, object] = {
        "http_method": "GET", "http_status": 200, "status": "success",
        "version": "v7.0.0", "build": 29, "path": "system",
        "name": "password-policy", "results": row,
    }
    value.update(envelope or {})
    return json.dumps(value, separators=(",", ":")).encode()


def test_projection_decodes_only_fixed_policy_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    original = policy_module._value

    def selected_only(content: bytearray, span: tuple[int, int]) -> object:
        assert b"opaque-sentinel" not in content[slice(*span)]
        return original(content, span)

    monkeypatch.setattr(policy_module, "_value", selected_only)
    snapshot = _project(bytearray(_body()))
    assert snapshot.minimum_length == 8 and snapshot.status == "disable"
    assert len(snapshot.digest) == 64
    assert replace(snapshot, minimum_length=9).digest != snapshot.digest


@pytest.mark.parametrize("field,value", [
    ("minimum-length", True), ("minimum-length", 0),
    ("min-number", "1"), ("status", "unknown"),
])
def test_invalid_policy_scalar_rejects(field: str, value: object) -> None:
    with pytest.raises((ValueError, LocalUserResetPolicyReadError)):
        _project(bytearray(_body(fields={field: value})))


@pytest.mark.parametrize("change", [
    {"build": 30}, {"path": "secret"}, {"http_method": "POST"},
    {"status": "failure"},
])
def test_wrong_envelope_rejects(change: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        _project(bytearray(_body(envelope=change)))


class Response:
    def __init__(self, body: bytes, *, status: int = 200,
                 encoding: str = "identity") -> None:
        self.body, self.status, self.encoding = body, status, encoding
        self.offset = 0
        self.closed = False

    def getheader(self, name: str, default: str = "") -> str:
        if name == "content-type":
            return "application/json"
        if name == "content-encoding":
            return self.encoding
        return default

    def readinto(self, view: memoryview) -> int:
        part = self.body[self.offset:self.offset + len(view)]
        view[:len(part)] = part
        self.offset += len(part)
        return len(part)

    def close(self) -> None:
        self.closed = True


class Connection:
    def __init__(self, response: Response) -> None:
        self.response = response
        self.closed = False
        self.requested = False

    def request(self, method: str, target: str, *, headers: dict[str, str]) -> None:
        assert method == "GET" and target == _PATH
        assert headers["Authorization"] == "Bearer synthetic-token"
        assert headers["Accept-Encoding"] == "identity"
        self.requested = True

    def getresponse(self) -> Response:
        assert self.requested
        return self.response

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize("status,encoding,valid", [
    (200, "identity", True), (401, "identity", False),
    (200, "gzip", False),
])
def test_fixed_transport_closes_every_resource(
    status: int, encoding: str, valid: bool,
) -> None:
    response = Response(_body(), status=status, encoding=encoding)
    connection = Connection(response)

    def factory(host: str, port: int, **kwargs: Any) -> Connection:
        assert host == "pam.example.test" and port == 9443
        assert kwargs["context"].check_hostname
        return connection

    reader = FortiPamLocalUserResetPolicyReader(
        SecretMetadataHttpTransportConfig(
            "https://pam.example.test:9443", "synthetic-token", 5, None,
        ),
        connection_factory=factory,
    )
    if valid:
        assert reader.read_policy_snapshot().minimum_length == 8
    else:
        with pytest.raises(LocalUserResetPolicyReadError):
            reader.read_policy_snapshot()
    assert response.closed and connection.closed
