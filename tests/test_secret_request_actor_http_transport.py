"""Exercise the exact FortiPAM API actor check used before Request dispatch."""

from __future__ import annotations

import json

import pytest

from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.secret_request_actor_http_transport import (
    FortiPamSecretRequestActorHttpTransport,
    SecretRequestActorHttpTransportError,
)


class _Response:
    status = 200

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.offset = 0
        self.closed = False

    def getheader(self, name: str, default: str = "") -> str:
        return "application/json" if name == "content-type" else default

    def readinto(self, view: memoryview) -> int:
        count = min(len(view), len(self.body) - self.offset)
        view[:count] = self.body[self.offset:self.offset + count]
        self.offset += count
        return count

    def close(self) -> None:
        self.closed = True


class _Connection:
    def __init__(self, response: _Response) -> None:
        self.response = response
        self.requests: list[tuple[str, str]] = []
        self.closed = False

    def request(self, method: str, path: str, *, headers: dict[str, str]) -> None:
        assert headers["Accept"] == "application/json"
        self.requests.append((method, path))

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        self.closed = True


def _actor_body(name: str, *, build: int = 29) -> bytes:
    return json.dumps({
        "http_method": "GET",
        "path": "web-ui",
        "name": "state",
        "status": "success",
        "version": "v7.0.0",
        "build": build,
        "results": {"admin": {"name": name, "login_name": name}},
    }, separators=(",", ":")).encode()


@pytest.mark.parametrize("name,build,accepted", [
    ("synthetic-requester", 29, True),
    ("synthetic-api-actor", 29, False),
    ("synthetic-requester", 30, False),
])
def test_actor_must_match_requester_on_supported_build(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    build: int,
    accepted: bool,
) -> None:
    response = _Response(_actor_body(name, build=build))
    connection = _Connection(response)
    monkeypatch.setattr(
        "fortipam_mcp.secret_request_actor_http_transport._ssl_context",
        lambda _config: object(),
    )
    reader = FortiPamSecretRequestActorHttpTransport(
        SecretMetadataHttpTransportConfig(
            "https://fpa.example", "synthetic-token", 5, None,
        ),
        connection_factory=lambda *_args, **_kwargs: connection,
    )

    if accepted:
        reader.inspect("synthetic-requester")
    else:
        with pytest.raises(SecretRequestActorHttpTransportError):
            reader.inspect("synthetic-requester")

    assert connection.requests == [("GET", "/api/v2/monitor/web-ui/state")]
    assert response.closed and connection.closed
