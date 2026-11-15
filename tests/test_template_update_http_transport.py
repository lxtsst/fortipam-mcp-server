"""Exact native REST dispatch, full-state preservation and durable replay denial."""

from copy import deepcopy
import json
import os
from pathlib import Path

import httpx
import pytest

from fortipam_mcp.template_reconciliation_http_transport import TemplateReconciliationHttpTransportConfig
from fortipam_mcp.template_ssh_transport import (
    TemplateArchivePreflightReadback, TemplateUpdateBaselineReadback, TemplateUpdateReadback,
)
from fortipam_mcp.template_update_http_transport import (
    FortiPamTemplateUpdateHttpTransport, TemplateUpdateHttpBinding, TemplateUpdateHttpTransportError,
    _native_baseline, _native_body, load_template_update_http_binding,
    template_update_api_configuration_digest,
)


NAME = "mcp-v4-template-update-disposable"
CLI_DIGEST = "a" * 64


class Inspection:
    def update_baseline_readback(self, name):
        assert name == NAME
        return TemplateUpdateBaselineReadback(*([True] * 8), CLI_DIGEST)

    def archive_preflight_readback(self, name):
        assert name == NAME
        return TemplateArchivePreflightReadback(*([True] * 10))

    def updated_web_vnc_readback(self, name):
        assert name == NAME
        return TemplateUpdateReadback(*([True] * 8), CLI_DIGEST)


def harness(tmp_path, *, row=None, fail_put=False, drift_after=False, restore_default_port=False):
    tmp_path.chmod(0o700)
    calls = []
    source_port, destination_port = (5901, 5900) if restore_default_port else (5900, 5901)
    native = _native_baseline(NAME, source_port)
    actual = deepcopy(native if row is None else row)
    binding = TemplateUpdateHttpBinding(NAME, template_update_api_configuration_digest(native), CLI_DIGEST)
    claim = tmp_path / "dispatch.json"

    def respond(request):
        calls.append(request)
        assert request.url.path == f"/api/v2/cmdb/secret/template/{NAME}"
        assert dict(request.url.params) == {"vdom": "root"}
        if request.method == "PUT":
            assert claim.exists() and claim.stat().st_mode & 0o777 == 0o600
            if fail_put:
                raise httpx.ReadTimeout("private response unavailable")
            assert json.loads(request.content) == _native_body(NAME, destination_port)
            actual["launcher"][0]["port"] = destination_port
            if drift_after:
                actual["description"] = "changed externally"
        return httpx.Response(200, json={
            "http_status": 200, "http_method": request.method, "status": "success",
            "path": "secret", "name": "template", "version": "v7.0.0", "build": 29,
            "results": [actual] if request.method == "GET" else {},
        })

    def factory(**kwargs):
        assert kwargs["follow_redirects"] is False and kwargs["trust_env"] is False
        return httpx.Client(transport=httpx.MockTransport(respond), **kwargs)

    config = TemplateReconciliationHttpTransportConfig("https://fortipam.example", "test-token", 15, None)
    transport = FortiPamTemplateUpdateHttpTransport(config, binding, Inspection(), claim,
                                                  client_factory=factory, restore_default_port=restore_default_port)
    return transport, calls, claim, config, binding, factory


def test_fixed_native_put_preserves_state_and_denies_restart_before_network(tmp_path):
    transport, calls, claim, config, binding, factory = harness(tmp_path)
    assert transport.update_web_vnc_port_and_readback(NAME).verified
    assert [request.method for request in calls] == ["GET", "PUT", "GET"]
    proof = json.loads(claim.read_text())
    assert proof["state"] == "execution_reserved" and NAME not in claim.read_text()
    fresh = FortiPamTemplateUpdateHttpTransport(config, binding, Inspection(), claim, client_factory=factory)
    with pytest.raises(TemplateUpdateHttpTransportError):
        fresh.update_baseline_readback(NAME)
    assert len(calls) == 3


def test_protected_old_or_unbound_template_refused_without_network(tmp_path):
    transport, calls, *_ = harness(tmp_path)
    with pytest.raises(TemplateUpdateHttpTransportError):
        transport.update_web_vnc_port_and_readback("mcp-v4-template-b53")
    assert calls == []
    with pytest.raises(TemplateUpdateHttpTransportError):
        TemplateUpdateHttpBinding("mcp-v4-template-b53", "a" * 64, "b" * 64)


@pytest.mark.parametrize("drift", ["description", "field", "extra_launcher"])
def test_non_port_baseline_drift_has_no_claim_or_put(tmp_path, drift):
    row = _native_baseline(NAME, 5900)
    if drift == "description":
        row["description"] = "changed"
    elif drift == "field":
        row["field"][0]["need-edit"] = "enable"
    else:
        row["launcher"].append(deepcopy(row["launcher"][0]))
    transport, calls, claim, *_ = harness(tmp_path, row=row)
    with pytest.raises(TemplateUpdateHttpTransportError):
        transport.update_web_vnc_port_and_readback(NAME)
    assert [request.method for request in calls] == ["GET"] and not claim.exists()


def test_uncertain_put_retains_claim_and_cannot_repeat(tmp_path):
    transport, calls, claim, *_ = harness(tmp_path, fail_put=True)
    with pytest.raises(TemplateUpdateHttpTransportError, match="unavailable"):
        transport.update_web_vnc_port_and_readback(NAME)
    assert claim.exists() and [request.method for request in calls] == ["GET", "PUT"]
    with pytest.raises(TemplateUpdateHttpTransportError):
        transport.update_web_vnc_port_and_readback(NAME)
    assert len(calls) == 2


def test_post_write_non_port_drift_requires_reconciliation(tmp_path):
    transport, calls, claim, *_ = harness(tmp_path, drift_after=True)
    with pytest.raises(TemplateUpdateHttpTransportError):
        transport.update_web_vnc_port_and_readback(NAME)
    assert claim.exists() and [request.method for request in calls] == ["GET", "PUT", "GET"]


def test_binding_owner_mode_and_symlink_are_checked(tmp_path):
    path = tmp_path / "binding.json"
    path.write_text(json.dumps({
        "contract": "fortipam_v4_template_update_rest_binding_v1", "template_name": NAME,
        "api_configuration_digest": "a" * 64, "cli_configuration_digest": CLI_DIGEST,
    }))
    path.chmod(0o600)
    assert load_template_update_http_binding(path).template_name == NAME
    path.chmod(0o644)
    with pytest.raises(TemplateUpdateHttpTransportError):
        load_template_update_http_binding(path)
    path.chmod(0o600)
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(TemplateUpdateHttpTransportError):
        load_template_update_http_binding(link)


def test_failed_claim_sync_prevents_put_and_preserves_claim(tmp_path, monkeypatch):
    transport, calls, claim, *_ = harness(tmp_path)
    monkeypatch.setattr(os, "fsync", lambda _: (_ for _ in ()).throw(OSError("sync failed")))
    with pytest.raises(TemplateUpdateHttpTransportError):
        transport.update_web_vnc_port_and_readback(NAME)
    assert claim.exists() and [request.method for request in calls] == ["GET"]


def test_restore_uses_fresh_intent_exact_reverse_delta_and_restart_denial(tmp_path):
    from fortipam_mcp.template_update_live_workflow import (
        TemplateWebVncPortUpdateLiveWorkflow, TemplateUpdateLiveWorkflowError,
    )
    from scripts.v4_template_update_mcp_oauth_acceptance import _validate_preview, _validate_execution

    transport, calls, claim, config, binding, factory = harness(tmp_path, restore_default_port=True)
    intent = tmp_path / "intent.json"
    workflow = TemplateWebVncPortUpdateLiveWorkflow(
        transport, claim_path=intent, write_transport="rest_api", restore_default_port=True,
    )
    requester = "b" * 64
    preview = workflow.preview(template_name=NAME, requester_digest=requester)
    _validate_preview(preview, NAME, False, write_transport="rest_api", restore_default_port=True)
    confirmation = workflow.confirm(preview["preview_ref"], requester_digest=requester)
    result = workflow.execute(confirmation["authorization_ref"], requester_digest=requester)
    _validate_execution(result, False, write_transport="rest_api", restore_default_port=True)
    assert sum(r.method == "PUT" for r in calls) == 1
    assert json.loads(intent.read_text())["direction"] == "restore_default_port"
    assert json.loads(claim.read_text())["direction"] == "restore_default_port"
    observed = len(calls)
    fresh = TemplateWebVncPortUpdateLiveWorkflow(
        transport, claim_path=intent, write_transport="rest_api", restore_default_port=True,
    )
    with pytest.raises(TemplateUpdateLiveWorkflowError):
        fresh.preview(template_name=NAME, requester_digest=requester)
    restarted = FortiPamTemplateUpdateHttpTransport(
        config, binding, Inspection(), claim, client_factory=factory, restore_default_port=True,
    )
    with pytest.raises(TemplateUpdateHttpTransportError):
        restarted.update_web_vnc_port_and_readback(NAME)
    assert len(calls) == observed


@pytest.mark.parametrize("failure", ["wrong_port", "metadata_drift", "uncertain_put", "post_drift"])
def test_restore_failure_never_replays_or_hides_drift(tmp_path, failure):
    row = _native_baseline(NAME, 5900 if failure == "wrong_port" else 5901)
    if failure == "metadata_drift":
        row["field"][0]["need-edit"] = "enable"
    transport, calls, claim, *_ = harness(
        tmp_path, row=row, restore_default_port=True,
        fail_put=failure == "uncertain_put", drift_after=failure == "post_drift",
    )
    with pytest.raises(TemplateUpdateHttpTransportError):
        transport.update_web_vnc_port_and_readback(NAME)
    if failure in {"wrong_port", "metadata_drift"}:
        assert not claim.exists() and not any(r.method == "PUT" for r in calls)
    else:
        assert claim.exists() and sum(r.method == "PUT" for r in calls) == 1
        observed = len(calls)
        with pytest.raises(TemplateUpdateHttpTransportError):
            transport.update_web_vnc_port_and_readback(NAME)
        assert len(calls) == observed
