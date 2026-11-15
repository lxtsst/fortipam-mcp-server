"""Aggregate Discovery review must not expose account or credential values."""

from __future__ import annotations

import json
import logging
import asyncio
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from fortipam_mcp import discovery_review_http_transport as transport
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from fortipam_mcp.discovery_review_http_transport import (
    DiscoveryReviewHttpTransportError,
    project_unix_discovery_review,
    project_unix_discovery_selection,
)
from fortipam_mcp.discovery_review_mcp_action import (
    SELECTION_BINDING_CONTRACT, _load_review_binding,
    build_unix_discovery_review,
    register_unix_discovery_review_tool,
)


def _response() -> dict[str, object]:
    return {
        "status": "success", "http_method": "GET", "http_status": 200,
        "path": "secret", "name": "discovery", "vdom": "root",
        "version": "v7.0.0", "build": 29,
        "results": [{
            "name": "bp014-discovery-unix-disabled-20260930-r6",
            "source-type": "Unix-like", "discovery-type": "account-discovery",
            "discovery-method": "existing-secret", "discovery-secret": 17,
            "last-discovery-time": "2026-09-30 02:36:00",
            "schedule-status": "disable", "auto-onboarding": "disable",
            "discovery-results": [
                {"name": "private-unmanaged", "managed-status": 0,
                 "last-scanned-time": "2026-09-30 02:36:00", "q_origin_key": "fixture"},
                {"name": "private-managed", "managed-status": 30,
                 "last-scanned-time": "2026-09-30 02:36:00", "q_origin_key": "fixture"},
            ],
        }],
    }


def test_review_returns_only_counts_for_exact_scanned_source() -> None:
    request = DisabledUnixDiscoveryCreateInput(
        "bp014-discovery-unix-disabled-20260930-r6", 17,
    )
    summary = project_unix_discovery_review(_response(), request)

    assert summary["total_accounts"] == 2
    assert summary["managed_accounts"] == 1
    assert summary["unmanaged_accounts"] == 1
    assert summary["onboarding_review"] == "needed"
    assert summary["import_executed"] is False
    assert "private-" not in str(summary)
    assert "discovery-secret" not in summary


def test_review_rejects_reference_drift_and_unrequested_source_fields() -> None:
    request = DisabledUnixDiscoveryCreateInput(
        "bp014-discovery-unix-disabled-20260930-r6", 17,
    )
    response = _response()
    response["results"][0]["discovery-secret"] = 18
    with pytest.raises(DiscoveryReviewHttpTransportError):
        project_unix_discovery_review(response, request)

    response = _response()
    response["results"][0]["credential-value"] = "private-credential"
    with pytest.raises(DiscoveryReviewHttpTransportError):
        project_unix_discovery_review(response, request)


def test_review_tool_is_default_off() -> None:
    assert build_unix_discovery_review({}) is None
    with pytest.raises(ValueError):
        build_unix_discovery_review({
            "FORTIPAM_MCP_V4_DISCOVERY_REVIEW_700_ENABLED": "true",
        })


def test_selection_only_classifies_one_exact_unmanaged_fixture() -> None:
    response = _response()
    row = response["results"][0]
    row["name"] = "bp014-discovery-unix-disabled-20260930-r9"
    row["discovery-results"] = [
        {"name": "fpam-bp014-discovery-r1", "managed-status": 0,
         "last-scanned-time": "2026-09-30 02:36:00", "q_origin_key": "fixture"},
        {"name": "root", "managed-status": 0,
         "last-scanned-time": "2026-09-30 02:36:00", "q_origin_key": "system"},
    ]
    request = DisabledUnixDiscoveryCreateInput(
        "bp014-discovery-unix-disabled-20260930-r9", 17,
    )

    decision = project_unix_discovery_selection(
        response, request, "fpam-bp014-discovery-r1",
    )

    assert decision["onboarding_decision"] == "prepare_existing_onboarding"
    assert decision["selected_account_unmanaged"] is True
    assert decision["selected_account_name_returned"] is False
    assert decision["import_executed"] is False
    assert "fpam-bp014" not in str(decision)
    with pytest.raises(DiscoveryReviewHttpTransportError):
        project_unix_discovery_selection(response, request, "root")
    row["discovery-results"][0]["managed-status"] = 30
    after = project_unix_discovery_selection(
        response, request, "fpam-bp014-discovery-r1",
    )
    assert after["onboarding_decision"] == "already_managed"
    assert after["selected_account_unmanaged"] is False
    assert after["selected_account_name_returned"] is False


def test_selection_binding_is_owner_only_and_fixture_specific(tmp_path: Path) -> None:
    binding = tmp_path / "binding.json"
    value = {
        "contract": SELECTION_BINDING_CONTRACT,
        "source_name": "bp014-discovery-unix-disabled-20260930-r9",
        "discovery_secret_id": 17,
        "selected_account": "fpam-bp014-discovery-r1",
    }
    binding.write_text(json.dumps(value))
    binding.chmod(0o600)

    request, selected = _load_review_binding(binding)

    assert request.discovery_secret_id == 17
    assert selected == "fpam-bp014-discovery-r1"
    value["selected_account"] = "root"
    binding.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        _load_review_binding(binding)
    binding.chmod(0o644)
    with pytest.raises(ValueError):
        _load_review_binding(binding)


@pytest.mark.parametrize("field,value", [("limit_reached", True), ("limit_reached", 0),
    ("next_idx", 1), ("next_idx", False), ("size", 0), ("size", 2), ("size", True),
    ("matched_count", 2), ("error", -1), ("error", False), ("schema_errors", []),
    ("action", ""), ("filtered_count", 0), ("build", 29.0)])
def test_partial_ambiguous_or_error_envelope_cannot_produce_onboarding_decision(field, value):
    response = _response(); response[field] = value
    row = response["results"][0]; row["discovery-results"][0]["name"] = "fpam-bp014-discovery-r1"
    request = DisabledUnixDiscoveryCreateInput(row["name"], 17)
    for action in (lambda: project_unix_discovery_review(response, request),
                   lambda: project_unix_discovery_selection(response, request, "fpam-bp014-discovery-r1")):
        with pytest.raises(DiscoveryReviewHttpTransportError): action()


@pytest.mark.parametrize("fault", ["empty", "duplicate", "unknown-field", "missing-field", "empty-name",
    "control-name", "name-type", "bool-status", "negative-status", "large-status", "origin-type",
    "time-type", "source-time", "noncanonical-time", "bool-reference"])
def test_snapshot_rows_and_source_identity_must_be_complete_and_unambiguous(fault):
    response = _response(); row = response["results"][0]; account = row["discovery-results"][0]
    if fault == "empty": row["discovery-results"] = []
    elif fault == "duplicate": row["discovery-results"].append(dict(account))
    elif fault == "unknown-field": account["unknown"] = "PRIVATE_SENTINEL"
    elif fault == "missing-field": del account["last-scanned-time"]
    elif fault == "empty-name": account["name"] = ""
    elif fault == "control-name": account["name"] = "private\nname"
    elif fault == "name-type": account["name"] = 7
    elif fault == "bool-status": account["managed-status"] = True
    elif fault == "negative-status": account["managed-status"] = -1
    elif fault == "large-status": account["managed-status"] = 2_147_483_648
    elif fault == "origin-type": account["q_origin_key"] = False
    elif fault == "time-type": account["last-scanned-time"] = 7
    elif fault == "source-time": row["last-discovery-time"] = "2026-02-30 02:36:00"
    elif fault == "noncanonical-time": row["last-discovery-time"] = "2026-9-30 02:36:00"
    elif fault == "bool-reference": row["discovery-secret"] = True
    with pytest.raises(DiscoveryReviewHttpTransportError) as error:
        project_unix_discovery_review(response, DisabledUnixDiscoveryCreateInput(row["name"], 17))
    assert "PRIVATE_" not in str(error.value)


def test_complete_detail_metadata_and_maximum_managed_secret_reference():
    response = _response()
    response.update(limit_reached=False, size=1, matched_count=1, next_idx=0, error=None)
    row = response["results"][0]; row["discovery-results"][1]["managed-status"] = 2_147_483_647
    summary = project_unix_discovery_review(response, DisabledUnixDiscoveryCreateInput(row["name"], 17))
    assert summary["managed_accounts"] == summary["unmanaged_accounts"] == 1


class _Body(httpx.SyncByteStream):
    def __init__(self, raw, eof): self.raw, self.eof, self.closed = raw, eof, False
    def __iter__(self):
        yield self.raw[:20]
        yield self.raw[20:]
        self.eof()
    def close(self): self.closed = True


class _Harness:
    def __init__(self, fault=None):
        self.fault, self.now = fault, 10.0
        self.clients, self.streams, self.requests, self.options = [], [], [], []
        self.response = _response()
    def handle(self, request):
        self.requests.append(request)
        logging.getLogger("httpx").info("PRIVATE_HTTP_SENTINEL")
        raw = json.dumps(self.response).encode()
        if self.fault == "duplicate-key": raw = raw.replace(b'"managed-status": 0', b'"managed-status":30,"managed-status":0')
        elif self.fault == "nonfinite": raw = raw.replace(b'"managed-status": 0', b'"managed-status":NaN')
        elif self.fault == "malformed": raw = b'{"PRIVATE_SENTINEL":'
        elif self.fault == "oversize": raw = b"x" * (transport._MAX_BYTES + 1)
        if self.fault == "late-headers": self.now += 31
        def eof():
            if self.fault == "late-eof": self.now += 31
            elif self.fault == "rollback": self.now -= 1
            elif self.fault == "infinite-clock": self.now = float("inf")
        stream = _Body(raw, eof); self.streams.append(stream)
        return httpx.Response(302 if self.fault == "redirect" else 403 if self.fault == "status" else 200,
            headers={"content-type": "text/json-unqualified" if self.fault == "type" else "application/json",
                "content-encoding": "gzip" if self.fault == "encoding" else "identity",
                "location": "https://other.invalid/PRIVATE_SENTINEL"}, stream=stream)
    def factory(self, **kwargs):
        self.options.append(kwargs)
        if self.fault == "factory": raise RuntimeError("PRIVATE_FACTORY_SENTINEL")
        harness = self
        class _Client(httpx.Client):
            def __enter__(self):
                if harness.fault == "enter": raise RuntimeError("PRIVATE_ENTER_SENTINEL")
                return super().__enter__()
            def __exit__(self, *args):
                result = super().__exit__(*args)
                if harness.fault == "late-close": harness.now += 31
                return result
        client = _Client(transport=httpx.MockTransport(self.handle), **kwargs)
        self.clients.append(client); return client
    def review(self):
        config = SecretMetadataHttpTransportConfig("https://synthetic.invalid", "synthetic-token", 10, None)
        reader = transport.FortiPamDiscoveryReviewHttpTransport(config,
            clock=lambda: self.now, client_factory=self.factory)
        return reader.review(DisabledUnixDiscoveryCreateInput(self.response["results"][0]["name"], 17))


def test_http_transport_is_fixed_bounded_private_and_clears_owned_body(monkeypatch, caplog):
    h = _Harness(); erased = []; original = transport._zeroize_mutable
    def wipe(raw): original(raw); erased.append(raw)
    monkeypatch.setattr(transport, "_zeroize_mutable", wipe)
    caplog.set_level(logging.DEBUG)
    assert h.review()["total_accounts"] == 2
    assert len(h.requests) == 1 and h.requests[0].method == "GET" and h.requests[0].content == b""
    assert h.requests[0].headers["authorization"] == "Bearer synthetic-token"
    assert h.requests[0].headers["accept-encoding"] == "identity"
    assert h.requests[0].url.path.startswith("/api/v2/cmdb/secret/discovery/")
    assert not h.options[0]["follow_redirects"] and not h.options[0]["trust_env"]
    assert all(client.is_closed for client in h.clients) and all(stream.closed for stream in h.streams)
    assert erased and all(not raw for raw in erased)
    assert "PRIVATE_" not in caplog.text and "discovery-unix" not in caplog.text


@pytest.mark.parametrize("fault", ["duplicate-key", "nonfinite", "malformed", "oversize", "late-headers",
    "late-eof", "rollback", "infinite-clock", "redirect", "status", "type", "encoding", "factory", "enter", "late-close"])
def test_unqualified_transfer_or_json_cannot_produce_a_summary(fault, monkeypatch):
    h = _Harness(fault); erased = []; original = transport._zeroize_mutable
    def wipe(raw): original(raw); erased.append(raw)
    monkeypatch.setattr(transport, "_zeroize_mutable", wipe)
    with pytest.raises(DiscoveryReviewHttpTransportError) as error: h.review()
    assert str(error.value) == transport._UNAVAILABLE and error.value.__suppress_context__
    assert len(h.requests) <= 1
    assert all(client.is_closed for client in h.clients) and all(stream.closed for stream in h.streams)
    assert erased and all(not raw for raw in erased)


@pytest.mark.parametrize("selected", [None, "synthetic-account"])
def test_late_http_registration_keeps_closed_schemas_and_rejects_arguments_before_handler(selected):
    from fortipam_mcp.server import MCP_SERVER_CLASS, MCP_TOOL_ERROR, _harden_mcp_input_validation
    mcp = MCP_SERVER_CLASS("synthetic-discovery-http")
    @mcp.tool()
    def baseline() -> dict[str, bool]: return {"baseline": True}
    _harden_mcp_input_validation(mcp)
    calls = []
    def read(principal): calls.append(principal); return {"status": "synthetic"}
    host = SimpleNamespace(mcp=mcp, _v4_planning_principal=lambda: "synthetic-principal")
    register_unix_discovery_review_tool(host, SimpleNamespace(_selected_account=selected, review=read, select=read))
    tools = [tool for tool in asyncio.run(mcp.list_tools()) if tool.name != "baseline"]
    assert len(tools) == (1 if selected is None else 2)
    for tool in tools:
        assert tool.input_schema["additionalProperties"] is False and tool.input_schema["properties"] == {}
        with pytest.raises(MCP_TOOL_ERROR) as error:
            asyncio.run(mcp.call_tool(tool.name, {"account": "PRIVATE_SENTINEL"}))
        assert "PRIVATE_SENTINEL" not in str(error.value)
        assert calls == []
    asyncio.run(mcp.call_tool(tools[0].name, {}))
    assert calls == ["synthetic-principal"]
