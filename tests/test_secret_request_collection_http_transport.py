from __future__ import annotations

import json

import pytest

from fortipam_mcp import secret_request_collection_http_transport as collection_module
from fortipam_mcp.secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig,
)
from fortipam_mcp.secret_request_collection_http_transport import (
    FortiPamSecretRequestCollectionHttpTransport,
    SecretRequestCollectionRecord,
    SecretRequestCreatorSnapshot,
    bind_new_secret_request,
)


class _Response:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.status = 200
        self.offset = 0

    def getheader(self, name: str, default: str = "") -> str:
        return "application/json" if name == "content-type" else default

    def readinto(self, view: memoryview) -> int:
        chunk = self.payload[self.offset : self.offset + len(view)]
        view[: len(chunk)] = chunk
        self.offset += len(chunk)
        return len(chunk)

    def close(self) -> None:
        return None


class _Connection:
    def __init__(self, response: _Response) -> None:
        self.response = response
        self.requests: list[tuple[str, str, bytes, dict[str, str]]] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes,
        headers: dict[str, str],
    ) -> None:
        self.requests.append((method, path, body, headers))

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        return None


@pytest.mark.parametrize(
    ("version", "build"),
    (("v1.9.1", 1758), ("v7.0.0", 29)),
)
def test_creator_collection_uses_exact_read_override_and_skips_private_values(
    monkeypatch: pytest.MonkeyPatch,
    version: str,
    build: int,
) -> None:
    payload = json.dumps(
        {
            "results": [
                {
                    "id": 71,
                    "secret-id": 83,
                    "request-type": "launcher",
                    "creation-time": "2026-09-06 12:34:56",
                    "user": "must-not-enter-decoder",
                    "comments": "must-not-enter-decoder",
                    "field": [{"value": "must-not-enter-decoder"}],
                }
            ],
            "status": "OK",
            "http_status": 200,
            "size": 1,
            "filtered_count": 1,
            "http_method": "POST",
            "vdom": "root",
            "path": "secret",
            "name": "request",
            "serial": "synthetic-target",
            "version": version,
            "build": build,
        }
    ).encode()
    decoded: list[bytes] = []
    original_loads = collection_module.json.loads

    def recording_loads(value):
        data = bytes(value) if not isinstance(value, str) else value.encode()
        decoded.append(data)
        return original_loads(value)

    monkeypatch.setattr(collection_module.json, "loads", recording_loads)
    monkeypatch.setattr(collection_module, "_ssl_context", lambda _config: object())
    connection = _Connection(_Response(payload))
    transport = FortiPamSecretRequestCollectionHttpTransport(
        SecretMetadataHttpTransportConfig(
            "https://fpa.example",
            "synthetic-token",
            5,
            None,
        ),
        connection_factory=lambda *_args, **_kwargs: connection,
    )

    snapshot = transport.snapshot()

    assert snapshot.records == (
        SecretRequestCollectionRecord(71, 83, "launcher", "2026-09-06 12:34:56"),
    )
    assert snapshot.raw_values_returned is False
    assert snapshot.fortipam_version == version.removeprefix("v")
    assert snapshot.fortipam_build == build
    method, path, body, headers = connection.requests[0]
    assert method == "POST"
    assert path == "/api/v2/cmdb/secret/request?with_meta=true&vdom=root"
    assert json.loads(body) == {
        "json_filter": [
            {
                "logic": "and",
                "filters": [
                    {
                        "key": "query-type",
                        "type": "string",
                        "operator": "exact",
                        "pattern": "creator",
                    }
                ],
            }
        ]
    }
    assert headers["X-HTTP-Method-Override"] == "GET"
    assert all(b"must-not-enter-decoder" not in value for value in decoded)
    assert all(value != b"83" for value in decoded)


def test_bind_new_request_requires_one_unchanged_same_creator_delta() -> None:
    existing = SecretRequestCollectionRecord(
        70, 82, "launcher", "2026-09-06 12:30:00"
    )
    created = SecretRequestCollectionRecord(
        71, 83, "launcher", "2026-09-06 12:34:56"
    )
    before = SecretRequestCreatorSnapshot((existing,))
    after = SecretRequestCreatorSnapshot((existing, created))

    assert bind_new_secret_request(
        before,
        after,
        expected_secret_id=83,
        expected_request_type="launcher",
    ) == created

    ambiguous = SecretRequestCreatorSnapshot(
        (
            existing,
            created,
            SecretRequestCollectionRecord(
                72, 83, "launcher", "2026-09-06 12:34:57"
            ),
        )
    )
    with pytest.raises(collection_module.SecretRequestCollectionHttpTransportError):
        bind_new_secret_request(
            before,
            ambiguous,
            expected_secret_id=83,
            expected_request_type="launcher",
        )


def test_build_29_creator_record_accepts_epoch_seconds_creation_time() -> None:
    payload = {
        "results": [{"id": 71, "secret-id": 83, "request-type": "launcher",
                     "creation-time": 1_790_000_000}],
        "status": "OK", "http_status": 200, "size": 1, "filtered_count": 1,
        "http_method": "POST", "vdom": "root", "path": "secret",
        "name": "request", "serial": "synthetic-target", "version": "v7.0.0",
        "build": 29,
    }

    snapshot = collection_module._parse_snapshot(bytearray(json.dumps(payload).encode()))

    assert snapshot.records == (SecretRequestCollectionRecord(71, 83, "launcher", 1_790_000_000),)
    payload["size"] = 3  # 7.0 reports the unfiltered total here.
    snapshot = collection_module._parse_snapshot(bytearray(json.dumps(payload).encode()))
    assert snapshot.records == (SecretRequestCollectionRecord(71, 83, "launcher", 1_790_000_000),)
    payload["version"] = "v1.9.1"
    payload["build"] = 1758
    with pytest.raises(collection_module.SecretRequestCollectionHttpTransportError):
        collection_module._parse_snapshot(bytearray(json.dumps(payload).encode()))
