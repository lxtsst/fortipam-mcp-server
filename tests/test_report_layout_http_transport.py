from __future__ import annotations

from copy import deepcopy
import json

import pytest

import fortipam_mcp.report_layout_http_transport as transport_module
from fortipam_mcp.character_set_http_transport import CharacterSetHttpTransportConfig
from fortipam_mcp.report_layout_http_transport import (
    FortiPamReportLayoutHttpTransport,
    REPORT_LAYOUT_DELETE_NAME,
    ReportLayoutHttpTransportError,
)


NAME = "MCPV4ReportB163Test"


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


def _config() -> CharacterSetHttpTransportConfig:
    return CharacterSetHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _layout(name: str = "default") -> dict[str, object]:
    return {
        "body-item": [
            {
                "id": index,
                "parameters": [],
                "q_origin_key": index,
                "top-n": 10,
                "type": "chart",
            }
            for index in range(36)
        ],
        "cutoff-option": "run-time",
        "cutoff-time": "00:00",
        "day": "sunday",
        "description": "",
        "email-recipients": "",
        "email-send": "disable",
        "format": "pdf",
        "max-pdf-report": 31,
        "name": name,
        "options": "include-table-of-content view-chart-as-heading",
        "page": {
            "column-break-before": "",
            "footer": {
                "footer-item": [
                    {
                        "content": "",
                        "description": "",
                        "id": index,
                        "img-src": "",
                        "q_origin_key": index,
                        "style": "",
                        "type": "text",
                    }
                    for index in range(2)
                ],
                "style": "",
            },
            "header": {
                "header-item": [
                    {
                        "content": "",
                        "description": "",
                        "id": 1,
                        "img-src": "",
                        "q_origin_key": 1,
                        "style": "",
                        "type": "text",
                    }
                ],
                "style": "",
            },
            "options": "",
            "page-break-before": "",
            "paper": "a4",
        },
        "q_origin_key": "default",
        "schedule-type": "daily",
        "style-theme": "default-report",
        "subtitle": "",
        "time": "00:00",
        "title": "Default Report",
    }


def test_inspect_requires_eligible_default_then_maps_only_404_to_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [_Response(200, {"results": [_layout()]}), _Response(404, {})]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamReportLayoutHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, calls),
    )

    result = transport.inspect(NAME)

    assert result.exists is False
    assert result.default_eligible is True
    assert len(result.default_digest) == 64
    assert [call["method"] for call in calls] == ["GET", "GET"]
    assert calls[0]["url"] == "https://fpa.example.test/api/v2/cmdb/report/layout/default"
    assert calls[1]["url"].endswith(f"/api/v2/cmdb/report/layout/{NAME}")


def test_create_clones_only_sanitized_default_then_reads_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    default = _layout()
    expected_digest = transport_module._template_digest(  # noqa: SLF001
        transport_module._sanitize_layout(default, expected_name="default")  # noqa: SLF001
    )
    target = _layout(NAME)
    responses = [
        _Response(200, {"results": [default]}),
        _Response(200, {"http_status": 200}),
        _Response(200, {"results": [target]}),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamReportLayoutHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, calls),
    )

    result = transport.create_and_readback(NAME, expected_digest)

    assert result.verified is True
    assert [call["method"] for call in calls] == ["GET", "POST", "GET"]
    body = calls[1]["json"]
    assert isinstance(body, dict)
    assert body["name"] == NAME
    assert "q_origin_key" not in body
    assert body["email-send"] == "disable"
    assert body["email-recipients"] == ""
    assert all(
        "q_origin_key" not in item and item["parameters"] == []
        for item in body["body-item"]
    )
    assert all(
        "q_origin_key" not in item
        for item in body["page"]["footer"]["footer-item"]
    )


def test_schema_drift_filters_or_default_digest_change_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    filtered = _layout()
    assert isinstance(filtered["body-item"], list)
    filtered["body-item"][0]["parameters"] = [{"name": "private-filter"}]
    transport = FortiPamReportLayoutHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [_Response(200, {"results": [filtered]})], []
        ),
    )
    with pytest.raises(ReportLayoutHttpTransportError):
        transport.inspect(NAME)

    default = _layout()
    changed = deepcopy(default)
    changed["title"] = "Changed"
    expected_digest = transport_module._template_digest(  # noqa: SLF001
        transport_module._sanitize_layout(default, expected_name="default")  # noqa: SLF001
    )
    transport = FortiPamReportLayoutHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [_Response(200, {"results": [changed]})], []
        ),
    )
    with pytest.raises(ReportLayoutHttpTransportError):
        transport.create_and_readback(NAME, expected_digest)


def test_name_and_unexpected_schema_are_rejected_before_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamReportLayoutHttpTransport(
        _config(), client_factory=lambda **_: _Client([], [])
    )
    with pytest.raises(ReportLayoutHttpTransportError):
        transport.inspect("report-with-hyphen")

    unexpected = _layout()
    unexpected["unknown"] = "value"
    transport = FortiPamReportLayoutHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [_Response(200, {"results": [unexpected]})], []
        ),
    )
    with pytest.raises(ReportLayoutHttpTransportError):
        transport.inspect(NAME)


def test_delete_requires_exact_accepted_clone_then_proves_404_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    default = _layout()
    target = _layout(REPORT_LAYOUT_DELETE_NAME)
    responses = [
        _Response(200, {"results": [default]}),
        _Response(200, {"results": [target]}),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamReportLayoutHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, calls),
    )

    inspection = transport.inspect_delete_target()

    assert inspection.exists is True
    assert inspection.eligible_fixed_clone is True
    assert len(inspection.target_digest) == 64
    calls.clear()
    responses.extend(
        [
            _Response(200, {"results": [default]}),
            _Response(200, {"results": [target]}),
            _Response(200, {"http_status": 200}),
            _Response(404, {}),
        ]
    )

    readback = transport.delete_and_readback(inspection.target_digest)

    assert readback.verified is True
    assert [call["method"] for call in calls] == ["GET", "GET", "DELETE", "GET"]
    assert calls[2]["url"].endswith(f"/report/layout/{REPORT_LAYOUT_DELETE_NAME}")
    assert calls[2]["json"] is None


def test_delete_rejects_changed_clone_or_digest_before_delete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    changed = _layout(REPORT_LAYOUT_DELETE_NAME)
    changed["title"] = "Changed"
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, {"results": [_layout()]}),
        _Response(200, {"results": [changed]}),
    ]
    transport = FortiPamReportLayoutHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, calls),
    )

    inspection = transport.inspect_delete_target()

    assert inspection.eligible_fixed_clone is False
    assert [call["method"] for call in calls] == ["GET", "GET"]
    with pytest.raises(ReportLayoutHttpTransportError):
        transport.delete_and_readback("not-a-digest")
    assert [call["method"] for call in calls] == ["GET", "GET"]
