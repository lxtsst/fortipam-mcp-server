"""Behavior checks for the fixed disabled Job transport."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from fortipam_mcp.job_definition_http_transport import (
    FortiPamDisabledJobHttpTransport,
    JobDefinitionHttpTransportError,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig


SOURCE = "mcp-v4-bp008-job-20260930-r3"
TARGET = "mcp-v4-bp008-job-20260930-r6"


def _source() -> dict[str, object]:
    return {
        "name": SOURCE, "user": "admin", "secret": 999,
        "associated-secret": 0, "status": "disable", "type": "ssh-script",
        "schedule": "one-shot", "script-type": "custom-script",
        "script-name": "", "script": "echo BP008_JOB_OK",
        "approval-status": "approved", "ssh-procedure": [],
        "web-api-procedure": [], "new-line-mode": "crlf",
        "scheduled-time": "2026-10-01 07:05:00",
        "job-sch-start-date": "2026-10-01 07:05:00",
        "job-sch-frequency": "day", "job-sch-interval": 1,
        "job-sch-month-day": "", "job-sch-month-type": "specific",
        "job-sch-week-day": "", "web-proxy-port": 8080,
        "web-proxy-server": "",
    }


def _transport() -> FortiPamDisabledJobHttpTransport:
    return FortiPamDisabledJobHttpTransport(
        SecretMetadataHttpTransportConfig(
            "https://fpa.example.test", "synthetic-token", 10, None,
        ),
        target_name=TARGET, target_requester="adminapi", expected_secret_id=999,
    )


def test_one_post_and_get_override_readback(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = _transport()
    source = _source()
    posted = 0

    def request(
        method: str, path: str, body: object, *,
        query: str | None = None, override: str | None = None,
    ) -> tuple[int, object]:
        nonlocal posted
        if method == "GET":
            assert path.endswith(SOURCE) and query == "vdom=root"
            return 200, {"status": "success", "version": "v7.0.0",
                         "build": 29, "results": source}
        assert path == "/api/v2/cmdb/secret/job"
        if override == "GET":
            assert body == {"json_filter": []}
            assert query == "with_meta=true&vdom=root"
            rows = [source]
            if posted:
                rows.append({**source, "name": TARGET, "user": "adminapi"})
            return 200, {"status": "OK", "version": "v7.0.0",
                         "build": 29, "results": rows}
        assert override is None
        assert query is None
        assert isinstance(body, dict)
        assert body["name"] == TARGET
        assert body["user"] == "adminapi"
        assert body["status"] == "disable"
        assert body["$originalName"] == ""
        posted += 1
        return 200, {"status": "success"}

    monkeypatch.setattr(transport, "_request", request)
    inspection = transport.inspect()
    assert not inspection.target_exists
    assert transport.post_disabled_once(inspection)
    assert transport.readback(expected=inspection).definition_verified
    assert posted == 1
    assert "adminapi" not in repr(inspection)


def test_complete_created_fields_reject_missing_schedule_and_unrelated_field_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = _transport()
    source = _source()
    target = {**source, "name": TARGET, "user": "adminapi"}
    created = False

    def request(method: str, path: str, body: object, **kwargs: object) -> tuple[int, object]:
        if method == "GET":
            return 200, {"status": "success", "version": "v7.0.0", "build": 29, "results": source}
        return 200, {"status": "OK", "version": "v7.0.0", "build": 29, "results": [source, target] if created else [source]}

    monkeypatch.setattr(transport, "_request", request)
    expected = transport.inspect()
    assert not expected.target_exists
    created = True
    assert transport.readback(expected=expected).definition_verified
    for field in ("job-sch-interval", "web-proxy-port", "new-line-mode"):
        before = target.pop(field)
        with pytest.raises(JobDefinitionHttpTransportError): transport.readback(expected=expected)
        target[field] = "drift"
        with pytest.raises(JobDefinitionHttpTransportError): transport.readback(expected=expected)
        target[field] = before
    source["web-proxy-port"] = 8081
    target["web-proxy-port"] = 8081
    with pytest.raises(JobDefinitionHttpTransportError): transport.readback(expected=expected)


def test_summary_source_missing_or_formatted_fields_blocks_inspection_before_post(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = _transport()
    source = _source()
    summary = deepcopy(source)
    writes = []

    def request(method: str, path: str, body: object, **kwargs: object) -> tuple[int, object]:
        if method == "GET":
            return 200, {"status": "success", "version": "v7.0.0", "build": 29, "results": source}
        if kwargs.get("override") == "GET":
            return 200, {"status": "OK", "version": "v7.0.0", "build": 29, "results": [summary]}
        writes.append(method)
        raise AssertionError("A partial view must never permit POST")

    monkeypatch.setattr(transport, "_request", request)
    for fault in ("missing", "formatted"):
        summary.clear(); summary.update(deepcopy(source))
        if fault == "missing": summary.pop("web-proxy-port")
        else: summary["scheduled-time"] = 0
        with pytest.raises(JobDefinitionHttpTransportError): transport.inspect()
    assert writes == []


def test_source_drift_blocks_post(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = _transport()
    source = _source()
    posted = 0

    def request(
        method: str, path: str, body: object, *,
        query: str | None = None, override: str | None = None,
    ) -> tuple[int, object]:
        nonlocal posted
        if method == "GET":
            return 200, {"status": "success", "version": "v7.0.0",
                         "build": 29, "results": source}
        if override == "GET":
            return 200, {"status": "OK", "version": "v7.0.0",
                         "build": 29, "results": [source]}
        posted += 1
        return 200, {"status": "success"}

    monkeypatch.setattr(transport, "_request", request)
    inspection = transport.inspect()
    changed = deepcopy(source)
    changed["scheduled-time"] = "2026-10-01 08:05:00"
    source.clear()
    source.update(changed)
    with pytest.raises(JobDefinitionHttpTransportError, match="unavailable"):
        transport.post_disabled_once(inspection)
    assert posted == 0


def test_existing_target_blocks_post(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = _transport()
    source = _source()

    def request(
        method: str, path: str, body: object, *,
        query: str | None = None, override: str | None = None,
    ) -> tuple[int, object]:
        if method == "GET":
            return 200, {"status": "success", "version": "v7.0.0",
                         "build": 29, "results": source}
        if override == "GET":
            return 200, {"status": "OK", "version": "v7.0.0",
                         "build": 29, "results": [source, {**source, "name": TARGET}]}
        raise AssertionError("POST must not be sent")

    monkeypatch.setattr(transport, "_request", request)
    inspection = transport.inspect()
    assert inspection.target_exists
    with pytest.raises(JobDefinitionHttpTransportError, match="unavailable"):
        transport.post_disabled_once(inspection)


def test_activation_inspect_and_single_put(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = _transport()
    source = _source()
    target = {
        **source, "name": TARGET, "user": "adminapi",
        "execution-time-start": 0, "execution-time-end": 0, "result-txt": "",
    }
    writes: list[dict[str, object]] = []

    def request(
        method: str, path: str, body: object, *,
        query: str | None = None, override: str | None = None,
    ) -> tuple[int, object]:
        if method == "GET":
            return 200, {"status": "success", "version": "v7.0.0",
                         "build": 29, "results": source}
        if override == "GET":
            return 200, {"status": "OK", "version": "v7.0.0",
                         "build": 29, "results": [target]}
        assert method == "PUT" and path.endswith(TARGET)
        assert query == "with_meta=true&vdom=root"
        assert isinstance(body, dict)
        writes.append(body)
        target["status"] = "enable"
        return 200, {"status": "success"}

    monkeypatch.setattr(transport, "_request", request)
    now = datetime(2026, 9, 30, 3, 0, tzinfo=timezone.utc)
    inspected = transport.inspect_activation(
        scheduled_at=now + timedelta(minutes=5), now=now,
    )
    assert "adminapi" not in repr(inspected)
    assert transport.put_activation_once(inspected, now=now)
    assert writes[0]["status"] == "enable"
    with pytest.raises(JobDefinitionHttpTransportError, match="unavailable"):
        transport.put_activation_once(inspected, now=now)
    assert len(writes) == 1


def test_activation_drift_blocks_put(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = _transport()
    source = _source()
    target = {
        **source, "name": TARGET, "user": "adminapi",
        "execution-time-start": 0, "execution-time-end": 0, "result-txt": "",
    }
    writes = 0

    def request(
        method: str, path: str, body: object, *,
        query: str | None = None, override: str | None = None,
    ) -> tuple[int, object]:
        nonlocal writes
        if method == "GET":
            return 200, {"status": "success", "version": "v7.0.0",
                         "build": 29, "results": source}
        if override == "GET":
            return 200, {"status": "OK", "version": "v7.0.0",
                         "build": 29, "results": [target]}
        writes += 1
        return 200, {"status": "success"}

    monkeypatch.setattr(transport, "_request", request)
    now = datetime(2026, 9, 30, 3, 0, tzinfo=timezone.utc)
    inspected = transport.inspect_activation(
        scheduled_at=now + timedelta(minutes=5), now=now,
    )
    target["script"] = "id"
    with pytest.raises(JobDefinitionHttpTransportError, match="unavailable"):
        transport.put_activation_once(inspected, now=now)
    assert writes == 0
