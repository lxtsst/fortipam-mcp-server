from __future__ import annotations

import json

import pytest

import fortipam_mcp.classification_tag_http_transport as transport_module
from fortipam_mcp.classification_tag_http_transport import (
    ClassificationTagTransportError,
    FortiPamClassificationTagHttpTransport,
)
from fortipam_mcp.folder_http_transport import FolderTransportConfig


class _Response:
    def __init__(self, status_code: int, payload: object) -> None:
        self.status_code = status_code
        self.content = json.dumps(payload).encode("utf-8")
        self.headers = {"content-type": "application/json"}


class _Client:
    def __init__(self, responses: list[_Response], calls: list[dict[str, object]]) -> None:
        self._responses = responses
        self._calls = calls

    def __enter__(self) -> "_Client":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def request(self, method: str, url: str, **kwargs: object) -> _Response:
        self._calls.append({"method": method, "url": url, **kwargs})
        return self._responses.pop(0)


def _config() -> FolderTransportConfig:
    return FolderTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
        explicitly_enabled=True,
    )


def test_inspect_maps_only_json_404_to_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamClassificationTagHttpTransport(
        _config(), client_factory=lambda **_: _Client([_Response(404, {})], calls)
    )

    result = transport.inspect("mcp-classification-tag-01")

    assert result.exists is False
    assert calls == [
        {
            "method": "GET",
            "url": "https://fpa.example.test/api/v2/cmdb/secret/classification-tag/mcp-classification-tag-01",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": None,
        }
    ]


def test_create_posts_only_name_and_description_then_reads_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    name = "mcp-classification-tag-01"
    description = "Lab ownership marker"
    responses = [
        _Response(200, {"http_status": 200}),
        _Response(200, {"results": [{"name": name, "description": description}]}),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamClassificationTagHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )

    result = transport.create_and_readback(name, description)

    assert result.verified is True
    assert calls == [
        {
            "method": "POST",
            "url": "https://fpa.example.test/api/v2/cmdb/secret/classification-tag",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": {"name": name, "description": description},
        },
        {
            "method": "GET",
            "url": "https://fpa.example.test/api/v2/cmdb/secret/classification-tag/mcp-classification-tag-01",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": None,
        },
    ]


def test_create_rejects_failed_post_or_unverifiable_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    rejected = FortiPamClassificationTagHttpTransport(
        _config(), client_factory=lambda **_: _Client([_Response(400, {})], [])
    )
    with pytest.raises(ClassificationTagTransportError):
        rejected.create_and_readback("mcp-classification-tag-01", "Lab marker")

    partial = FortiPamClassificationTagHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [
                _Response(200, {"http_status": 200}),
                _Response(200, {"results": [{"name": "mcp-classification-tag-01"}]}),
            ],
            [],
        ),
    )
    assert partial.create_and_readback(
        "mcp-classification-tag-01", "Lab marker"
    ).verified is False
