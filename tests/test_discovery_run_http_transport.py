"""Focused one-shot Unix Discovery scan dispatch checks."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import httpx
import pytest

from fortipam_mcp.discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from fortipam_mcp.discovery_entry_create_http_transport import (
    FortiPamDiscoveryEntryCreateHttpTransport,
)
from fortipam_mcp.discovery_entry_projection import DiscoveryEntryReadback
from fortipam_mcp.discovery_run_http_transport import (
    DiscoveryRunHttpTransportError,
    FortiPamDiscoveryRunHttpTransport,
    _account_reply, _account_reply_shape, _reply_shape_record,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.discovery_run_mcp_action import UnixDiscoveryRunLiveWorkflow


@pytest.mark.parametrize("raw,complete,category,kind", [
    (b'{"ongoing_requests":0,"failed_requests":0}', True, "object", "integer"),
    (b'{"ongoing_requests":"0","failed_requests":"0"}', True, "object", "decimal_text"),
    (b'{"ongoing_requests":true,"failed_requests":true}', True, "object", "boolean"),
    (b'{"ongoing_requests":null,"failed_requests":null}', True, "object", "null"),
    (b'{"ongoing_requests":[],"failed_requests":[]}', True, "object", "array"),
    (b'{"ongoing_requests":{},"failed_requests":{}}', True, "object", "object"),
    (b'{"ongoing_requests":0.0,"failed_requests":0.0}', True, "object", "floating"),
    (b'{"ongoing_requests":" 0","failed_requests":" 0"}', True, "object", "other_text"),
    (b'{"status":"idle"}', True, "object", "missing"),
    (b'{"ongoing_requests":0,"ongoing_requests":1}', True, "invalid_json", "unobserved"),
    (b'{"ongoing_requests":NaN}', True, "invalid_json", "unobserved"),
    (b'[]', True, "non_object", "unobserved"),
    (b'{', True, "invalid_json", "unobserved"),
    (b'', True, "empty", "unobserved"),
    (b'{"ongoing_requests":0,"failed_requests":0}', False, "incomplete", "unobserved"),
])
def test_original_reply_shape_keeps_only_fixed_wire_metadata(raw, complete, category, kind):
    shape = _account_reply_shape(bytearray(raw), 200, "application/json", complete=complete, truncated=False)
    assert shape.response_complete is complete and shape.json_category == category
    assert shape.ongoing_kind == shape.failed_kind == kind
    assert _reply_shape_record(asdict(shape)) == shape


def test_shape_never_retains_unselected_material_or_accepts_incomplete_json():
    raw = bytearray(b'{"ongoing_requests":0,"failed_requests":0,"password":"synthetic-private-material"}')
    shape = _account_reply_shape(raw, 200, "application/json", complete=True, truncated=False)
    assert "synthetic-private-material" not in json.dumps(asdict(shape)) and "password" not in json.dumps(asdict(shape))
    assert set(asdict(shape)) == {"contract", "http_status", "json_content", "response_complete", "truncated", "json_category", "ongoing_kind", "failed_kind",
        "results_kind", "results_ongoing_kind", "results_failed_kind", "status_category", "error_category", "root_empty"}
    with pytest.raises(DiscoveryRunHttpTransportError): _account_reply(raw, 200, "application/json", complete=False)
    with pytest.raises(DiscoveryRunHttpTransportError): _reply_shape_record({**asdict(shape), "extra": "forbidden"})
    assert _account_reply_shape(raw, 200, "text/plain", complete=True, truncated=False).json_category == "not_json"


def test_nested_counters_and_fixed_status_categories_are_evidence_only():
    raw = bytearray(b'{"results":{"ongoing_requests":"0","failed_requests":0,"password":"synthetic-private"},"status":"success","error":0}')
    shape = _account_reply_shape(raw, 200, "application/json", complete=True, truncated=False)
    assert shape.ongoing_kind == shape.failed_kind == "missing" and not shape.root_empty
    assert shape.results_kind == "object" and shape.results_ongoing_kind == "decimal_text" and shape.results_failed_kind == "integer"
    assert shape.status_category == "success" and shape.error_category == "zero"
    assert "synthetic-private" not in json.dumps(asdict(shape))
    with pytest.raises(DiscoveryRunHttpTransportError): _account_reply(raw, 200, "application/json")


def _state(*, scanned: bool) -> DiscoveryEntryReadback:
    return DiscoveryEntryReadback(
        True, False, True, True, True, True, True, True, not scanned,
    )


def test_exact_source_scan_posts_once_without_import(monkeypatch) -> None:
    source = DisabledUnixDiscoveryCreateInput(
        "bp014-discovery-unix-disabled-20260930-r7", 17,
    )
    seen: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ongoing_requests": 0, "failed_requests": 0})

    original_client = httpx.Client
    monkeypatch.setattr(
        "fortipam_mcp.discovery_run_http_transport.httpx.Client",
        lambda **kwargs: original_client(**kwargs, transport=httpx.MockTransport(respond)),
    )
    monkeypatch.setattr(
        "fortipam_mcp.discovery_run_http_transport._ssl_context", lambda _: True,
    )
    states = iter((_state(scanned=False), _state(scanned=True)))
    monkeypatch.setattr(
        "fortipam_mcp.discovery_run_http_transport.inspect_discovery_entry_detail",
        lambda *args, **kwargs: next(states),
    )
    config = SecretMetadataHttpTransportConfig("https://example.test", "test-token", 5, None)
    transport = FortiPamDiscoveryRunHttpTransport(config)

    result = transport.run_once(source)

    assert result.dispatch == "accepted"
    assert result.source_scanned is True
    assert result.auto_onboarding_disabled is True
    assert result.import_dispatched is False
    assert result.account_ack is not None and result.account_ack.zero_requests
    assert len(seen) == 1
    assert seen[0].url.path == "/api/v2/internal/secret-discovery"
    assert json.loads(seen[0].content) == {
        "discovery-name": source.source_name, "type": "discovery",
    }
    with pytest.raises(DiscoveryRunHttpTransportError):
        transport.run_once(source)
    assert len(seen) == 1


def test_failed_post_is_ambiguous_and_never_replayed(monkeypatch) -> None:
    source = DisabledUnixDiscoveryCreateInput(
        "bp014-discovery-unix-disabled-20260930-r7", 17,
    )
    calls = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(403, json={"status": "error"})

    original_client = httpx.Client
    monkeypatch.setattr(
        "fortipam_mcp.discovery_run_http_transport.httpx.Client",
        lambda **kwargs: original_client(**kwargs, transport=httpx.MockTransport(respond)),
    )
    monkeypatch.setattr(
        "fortipam_mcp.discovery_run_http_transport._ssl_context", lambda _: True,
    )
    monkeypatch.setattr(
        "fortipam_mcp.discovery_run_http_transport.inspect_discovery_entry_detail",
        lambda *args, **kwargs: _state(scanned=False),
    )
    config = SecretMetadataHttpTransportConfig("https://example.test", "test-token", 5, None)
    transport = FortiPamDiscoveryRunHttpTransport(config)

    result = transport.run_once(source)

    assert result.dispatch == "ambiguous"
    assert result.http_status == 403
    assert result.source_scanned is False
    assert result.account_ack is None
    with pytest.raises(DiscoveryRunHttpTransportError):
        transport.run_once(source)
    assert calls == 1


@pytest.mark.parametrize("payload,counts", [
    ({"ongoing_requests": 0, "failed_requests": 0}, (0, 0)),
    ({"ongoing_requests": 3, "failed_requests": 0}, (3, 0)),
    ({"ongoing_requests": 0, "failed_requests": 2}, (0, 2)),
    ({"ongoing_requests": 0, "failed_requests": 0, "status": "error"}, None),
    ({"ongoing_requests": 0, "failed_requests": 0, "error": -1}, None),
    ({"ongoing_requests": "0", "failed_requests": "0"}, (0, 0)),
    ({"ongoing_requests": "3", "failed_requests": 0}, (3, 0)),
    ({"ongoing_requests": 0, "failed_requests": "2"}, (0, 2)),
    ({"ongoing_requests": "9007199254740991", "failed_requests": 0}, (9007199254740991, 0)),
    ({"ongoing_requests": "9007199254740992", "failed_requests": 0}, None),
    ({"ongoing_requests": "00", "failed_requests": 0}, None),
    ({"ongoing_requests": " 0", "failed_requests": 0}, None),
    ({"ongoing_requests": "0.0", "failed_requests": 0}, None),
    ({"ongoing_requests": "1e0", "failed_requests": 0}, None),
    ({"ongoing_requests": "-1", "failed_requests": 0}, None),
    ({"ongoing_requests": "", "failed_requests": 0}, None),
    ({"ongoing_requests": "\u0660", "failed_requests": 0}, None),
    ({"ongoing_requests": None, "failed_requests": 0}, None),
    ({"ongoing_requests": [], "failed_requests": 0}, None),
    ({"failed_requests": 0}, None),
    ({"status": "idle", "completed": 1, "total": 1}, None),
    ({"ongoing_requests": True, "failed_requests": 0}, None),
    ({"ongoing_requests": 0.0, "failed_requests": 0}, None),
    ({"ongoing_requests": -1, "failed_requests": 0}, None),
])
def test_original_account_counts_survive_without_borrowing_target_progress(monkeypatch, payload, counts):
    source = DisabledUnixDiscoveryCreateInput("bp014-discovery-unix-disabled-20261024-r900", 17)
    original = httpx.Client
    def reply(request): return httpx.Response(200, json=payload)
    monkeypatch.setattr("fortipam_mcp.discovery_run_http_transport.httpx.Client",
        lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(reply)))
    monkeypatch.setattr("fortipam_mcp.discovery_run_http_transport._ssl_context", lambda _: True)
    state = iter((_state(scanned=False), _state(scanned=True)))
    monkeypatch.setattr("fortipam_mcp.discovery_run_http_transport.inspect_discovery_entry_detail", lambda *args, **kwargs: next(state))
    transport = FortiPamDiscoveryRunHttpTransport(SecretMetadataHttpTransportConfig("https://example.test", "synthetic-token", 5, None))
    result = transport.run_once(source)
    if counts is None:
        assert result.account_ack is None and result.dispatch == "ambiguous"
    else:
        assert (result.account_ack.ongoing_requests, result.account_ack.failed_requests) == counts
        assert result.dispatch == ("accepted" if counts[1] == 0 else "ambiguous")
    assert result.source_scanned is (counts == (0, 0))
    assert result.auto_onboarding_disabled and not result.import_dispatched


@pytest.mark.parametrize("reply", [
    '{"ongoing_requests":1,"failed_requests":0}',
    '{"ongoing_requests":1,"ongoing_requests":0,"failed_requests":0}',
    '{"ongoing_requests":NaN,"failed_requests":0}',
])
def test_pending_or_ambiguous_ack_cannot_be_verified_from_a_timestamp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reply: str,
) -> None:
    source = DisabledUnixDiscoveryCreateInput(
        "bp014-discovery-unix-disabled-20260930-r700", 17,
    )
    config = SecretMetadataHttpTransportConfig("https://example.test", "test-token", 5, None)
    posts: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        posts.append(request)
        return httpx.Response(
            200, headers={"content-type": "application/json"}, content=reply.encode(),
        )

    original = httpx.Client
    monkeypatch.setattr(
        "fortipam_mcp.discovery_run_http_transport.httpx.Client",
        lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(respond)),
    )
    monkeypatch.setattr("fortipam_mcp.discovery_run_http_transport._ssl_context", lambda _: True)
    monkeypatch.setattr(
        "fortipam_mcp.discovery_run_http_transport.inspect_discovery_entry_detail",
        lambda *args, **kwargs: _state(scanned=bool(posts)),
    )
    monkeypatch.setattr(
        FortiPamDiscoveryEntryCreateHttpTransport,
        "inspect_credential_reference", lambda *args: "a" * 64,
    )
    transport = FortiPamDiscoveryRunHttpTransport(config)
    workflow = UnixDiscoveryRunLiveWorkflow(
        transport, FortiPamDiscoveryEntryCreateHttpTransport(config),
        source, tmp_path / "consumed.json", clock=lambda: 100,
    )
    preview = workflow.preview(requester_digest="b" * 64)
    authorized = workflow.confirm(preview["preview_ref"], requester_digest="b" * 64)
    result = workflow.execute(authorized["authorization_ref"], requester_digest="b" * 64)
    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown" and result["one_shot_claim_consumed"]
    assert result["import_dispatched"] is False and len(posts) == 1
    with pytest.raises(RuntimeError):
        workflow.execute(authorized["authorization_ref"], requester_digest="b" * 64)
    fresh = UnixDiscoveryRunLiveWorkflow(
        FortiPamDiscoveryRunHttpTransport(config),
        FortiPamDiscoveryEntryCreateHttpTransport(config), source,
        tmp_path / "consumed.json", clock=lambda: 100,
    )
    with pytest.raises(RuntimeError):
        fresh.preview(requester_digest="b" * 64)
    assert len(posts) == 1
