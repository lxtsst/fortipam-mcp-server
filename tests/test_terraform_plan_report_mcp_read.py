"""Caller-bound signed reports, private descriptors and actual OAuth/MCP reads."""
from __future__ import annotations

import asyncio
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest
from starlette.testclient import TestClient

from fortipam_mcp import http_server, server
from fortipam_mcp import terraform_plan_report_mcp_read as module
from fortipam_mcp.local_oauth import LocalOAuthProvider
from fortipam_mcp.terraform_plan_receipt import TerraformPlanProducerPins, _canonical, _DOMAIN
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_http_server import (
    _authorize_and_login, _register_public_client, _request_headers,
    _v4_controlled_environment,
)
from test_terraform_plan_configuration import plan
from test_terraform_plan_projection import MARKER
from test_v4_m3 import _requester


def source(tmp_path: Path, principal: V4PlanningPrincipal):
    directory = tmp_path / "report-input"
    directory.mkdir(mode=0o700)
    artifact, receipt, public = (directory / name for name in ("plan.private", "receipt.private", "public.private"))
    raw = json.dumps(plan()).encode()
    artifact.write_bytes(raw)
    key = Ed25519PrivateKey.generate()
    public_bytes = key.public_key().public_bytes_raw()
    public.write_bytes(public_bytes)
    pins = TerraformPlanProducerPins(*("a" * 64 for _ in range(5)))
    now = int(time.time())
    binding = dict(contract="fortipam-terraform-plan-report-binding/v1", artifact_path=str(artifact),
        receipt_path=str(receipt), public_key_path=str(public), public_key_sha256=hashlib.sha256(public_bytes).hexdigest(),
        pins={name: getattr(pins, name) for name in pins.__dataclass_fields__}, run_nonce="d" * 64,
        requester_digest=principal.requester.digest, transport_digest=principal.transport_namespace_digest,
        issued_at=now - 1, expires_at=now + 300)
    payload = dict(contract="fortipam-synthetic-terraform-plan-receipt/v1", purpose="synthetic-plan-review-only",
        profile_digest=pins.digest(), **{name: binding[name] for name in
            ("run_nonce", "requester_digest", "transport_digest", "issued_at", "expires_at")},
        completed_at=now, artifact_sha256=hashlib.sha256(raw).hexdigest(), artifact_bytes=len(raw),
        commands=["version", "init", "plan", "show"], exit_codes=[0, 0, 0, 0], endpoint_connection_attempts=0,
        device_material_loaded=False, device_contacted=False, apply_invoked=False)
    wire = _canonical(payload)
    receipt.write_bytes(b'{"payload":' + wire + b',"signature":"' + key.sign(_DOMAIN + hashlib.sha256(wire).digest()).hex().encode() + b'"}')
    descriptor = directory / "binding.private"
    descriptor.write_bytes(_canonical(binding))
    for path in (artifact, receipt, public, descriptor):
        path.chmod(0o600)
    env = {module.FEATURE_ENV: "true", module.BINDING_ENV: str(descriptor)}
    return env, descriptor, binding


@pytest.mark.parametrize("value,expected", [(None, False), ("false", False), ("true", True), ("TRUE", None), ("yes", None)])
def test_feature_requires_exact_opt_in(value, expected):
    env = {} if value is None else {module.FEATURE_ENV: value}
    if expected is None:
        with pytest.raises(module.TerraformPlanReportError):
            module.load_terraform_plan_report_feature(env)
    else:
        assert module.load_terraform_plan_report_feature(env) is expected


def test_another_human_or_client_cannot_consume_or_disclose_report(tmp_path, monkeypatch):
    principal = V4PlanningPrincipal(_requester(), "c" * 64)
    env, descriptor, _ = source(tmp_path, principal)
    report = module.build_terraform_plan_report(env)
    monkeypatch.setattr(json, "loads", lambda *_a, **_k: pytest.fail("Artifact scalar decoding is forbidden."))
    foreign_human = replace(principal.requester, subject_ref="different-human-ref")
    for denied in (None, V4PlanningPrincipal(foreign_human, "c" * 64), V4PlanningPrincipal(principal.requester, "e" * 64)):
        with pytest.raises(module.TerraformPlanReportError) as caught:
            report.summarize(denied)
        assert str(caught.value) == module._ERROR
        assert report._reader._attempted is False
    result = report.summarize(principal)
    assert result["runtime_caller_authenticated"] is True
    assert result["authenticated_requester_matches_receipt_binding"] is True
    assert result["authenticated_transport_matches_receipt_binding"] is True
    assert result["review_complete"] is result["apply_authorized"] is result["source_provenance_verified"] is False
    assert result["configuration_resource_entries"] == 1
    assert MARKER not in str(result) and str(tmp_path) not in str(result)
    assert principal.requester.digest not in str(result) and principal.transport_namespace_digest not in str(result)
    assert "redacted" in repr(report)
    with pytest.raises(module.TerraformPlanReportError):
        report.summarize(principal)
    report.close()
    assert descriptor.exists()


@pytest.mark.parametrize("fault", ["extra", "missing", "duplicate", "relative", "bad-pin", "expired", "world-readable", "symlink"])
def test_untrusted_startup_descriptor_fails_without_sensitive_error(tmp_path, fault, monkeypatch):
    principal = V4PlanningPrincipal(_requester(), "c" * 64)
    env, descriptor, binding = source(tmp_path, principal)
    if fault == "extra": binding["private_key"] = MARKER
    elif fault == "missing": del binding["pins"]
    elif fault == "relative": binding["artifact_path"] = "../" + MARKER
    elif fault == "bad-pin": binding["pins"]["provider_lock_sha256"] = MARKER
    elif fault == "expired": binding["issued_at"], binding["expires_at"] = 1, 2
    descriptor.write_bytes(_canonical(binding))
    if fault == "duplicate":
        descriptor.write_bytes(descriptor.read_bytes().replace(b'"contract":', b'"contract":"duplicate","contract":'))
    elif fault == "world-readable": descriptor.chmod(0o644)
    elif fault == "symlink":
        link = descriptor.with_name("link.private"); link.symlink_to(descriptor)
        env[module.BINDING_ENV] = str(link)
    buffers = []
    original = module._read_owned
    def read(path):
        raw, identity = original(path); buffers.append(raw); return raw, identity
    monkeypatch.setattr(module, "_read_owned", read)
    with pytest.raises(module.TerraformPlanReportError) as caught:
        module.build_terraform_plan_report(env)
    assert str(caught.value) == module._ERROR
    assert all(not any(raw) for raw in buffers)


def test_closed_report_and_bad_artifact_are_consumed(tmp_path):
    principal = V4PlanningPrincipal(_requester(), "c" * 64)
    env, _, binding = source(tmp_path, principal)
    report = module.build_terraform_plan_report(env)
    Path(binding["artifact_path"]).write_bytes(b"changed")
    with pytest.raises(module.TerraformPlanReportError): report.summarize(principal)
    assert report._reader._attempted is True
    report.close()
    with pytest.raises(module.TerraformPlanReportError): report.summarize(principal)


def token(client, scope):
    client_id = _register_public_client(client, scope)
    code, verifier = _authorize_and_login(client, client_id, scope)
    response = client.post("/fpamcp/oauth/token", data=dict(grant_type="authorization_code", client_id=client_id,
        code=code, code_verifier=verifier, redirect_uri="https://client.example/callback", resource="https://mcp.example.com/fpamcp"))
    assert response.status_code == 200
    return response.json()["access_token"]


def rpc(client, bearer, method, params=None):
    headers = _request_headers(bearer); headers["host"] = "mcp.example.com"
    response = client.post("/fpamcp", headers=headers, json=dict(jsonrpc="2.0", id="report", method=method, params=params or {}))
    assert response.status_code == 200
    return response.json()["result"]


def test_actual_oauth_mcp_binds_human_client_scopes_and_rejects_extra_inputs(tmp_path):
    env = _v4_controlled_environment(tmp_path)
    settings = http_server.HttpServerSettings.from_environment(env)
    base_app = http_server.create_http_app(settings, v4_folder_action=object())
    scope = "fortipam:read fortipam:plan fortipam:operate"
    with TestClient(base_app, base_url="https://mcp.example.com") as client:
        accepted = token(client, scope)
        other_client = token(client, scope)
        plan_only = token(client, "fortipam:read fortipam:plan")
        tools = rpc(client, accepted, "tools/list")["tools"]
        assert module.TOOL not in {entry["name"] for entry in tools}
    verified = asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(accepted))
    principal = module.terraform_plan_report_principal(verified, settings.v4_planning_authorization)
    source_env, _, _ = source(tmp_path, principal)
    env.update(source_env)
    report = module.build_terraform_plan_report(env)
    settings = http_server.HttpServerSettings.from_environment(env)
    app = http_server.create_http_app(settings, v4_folder_action=object(), v4_terraform_plan_report=report)
    with TestClient(app, base_url="https://mcp.example.com") as client:
        tools = rpc(client, accepted, "tools/list")["tools"]
        schema = next(entry for entry in tools if entry["name"] == module.TOOL)
        assert schema["inputSchema"] == {"additionalProperties": False, "properties": {}, "title": "summarize_v4_synthetic_terraform_planArguments", "type": "object"}
        assert schema["annotations"]["readOnlyHint"] is True and schema["annotations"]["idempotentHint"] is False
        for bearer, arguments in ((other_client, {}), (plan_only, {}), (accepted, {"path": MARKER})):
            result = rpc(client, bearer, "tools/call", {"name": module.TOOL, "arguments": arguments})
            assert result["isError"] is True
            assert MARKER not in str(result) and str(tmp_path) not in str(result)
            assert report._reader._attempted is False
        result = rpc(client, accepted, "tools/call", {"name": module.TOOL, "arguments": {}})
        assert result["isError"] is False
        summary = result["structuredContent"]
        assert summary["runtime_caller_authenticated"] is summary["private_binding_matches"] is True
        assert summary["apply_authorized"] is summary["review_complete"] is summary["source_provenance_verified"] is False
        assert rpc(client, accepted, "tools/call", {"name": module.TOOL, "arguments": {}})["isError"] is True
        matrix = rpc(client, accepted, "tools/call", {"name": "get_capability_matrix", "arguments": {}})["structuredContent"]
        capability = next(entry for entry in matrix["tools"] if entry["tool_name"] == module.TOOL)
        assert capability["contacts_fortipam"] is capability["device_write"] is False
    report.close()


@pytest.mark.parametrize("profile,enabled,host", [("readonly", True, None), ("v4-plan-only", True, None), ("v4-controlled", True, None), ("v4-controlled", False, object())])
def test_report_cannot_be_bound_outside_its_exact_profile(profile, enabled, host):
    with pytest.raises(RuntimeError, match="Terraform report"):
        server.FortiPamMcpServer(runtime_profile=profile, v4_http_oauth=True,
            v4_terraform_plan_report_enabled=enabled, v4_terraform_plan_report=host)
