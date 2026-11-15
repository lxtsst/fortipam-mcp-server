"""Canonical client against authenticated in-process MCP, never a device listener."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest
from starlette.testclient import TestClient

from scripts import v4_secret_dlp_association_mcp_oauth_acceptance as acceptance
from fortipam_mcp.http_server import create_http_app
from test_secret_dlp_association_mcp_action import _candidate, _settings, _login, _rpc, _call
from test_secret_dlp_association_live_workflow import IDENTITY, SENSOR
from test_http_server import _initialize_payload


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    action, transport = _candidate()
    app = create_http_app(_settings(tmp_path / "oauth"), v4_secret_dlp_association_candidate_action=action)
    with TestClient(app, base_url="https://mcp.example.com") as client:
        h = SimpleNamespace(client=client, transport=transport, state=state, calls=[], revocations=0,
            client_id=None, transform=None, omitted_tool=None, common_transform=None)

        async def common(*args: Any, **kwargs: Any) -> dict[str, object]:
            assert kwargs["ca_file"] == tmp_path / "ca.pem"
            assert kwargs["lab_connect_host"] == "127.0.0.1" and kwargs["lab_connect_port"] == 28443
            assert kwargs["allow_loopback_tunnel"] is True
            assert kwargs["required_tools"] in (acceptance.ASSOCIATION_TOOLS, acceptance.RESTORE_TOOLS)
            headers, h.client_id, token = _login(client, client_id=h.client_id)
            metadata = client.get("/.well-known/oauth-authorization-server/fpamcp/oauth")
            assert metadata.status_code == 200 and metadata.json()["issuer"] == "https://mcp.example.com/fpamcp/oauth"
            initialized = client.post("/fpamcp", headers=headers, json=_initialize_payload())
            assert initialized.status_code == 200 and initialized.json()["result"]["serverInfo"]

            class Session:
                async def list_tools(self) -> SimpleNamespace:
                    listing = _rpc(client, headers, "tools/list", {})
                    return SimpleNamespace(tools=[SimpleNamespace(name=tool["name"]) for tool in listing["tools"]
                                                 if tool["name"] != h.omitted_tool])
                async def call_tool(self, name: str, arguments: dict[str, object]) -> SimpleNamespace:
                    h.calls.append((name, arguments))
                    response = _call(client, headers, name, arguments)
                    value = response.get("structuredContent")
                    if h.transform and isinstance(value, dict):
                        h.transform(name, value)
                    return SimpleNamespace(is_error=response["isError"], structured_content=value)

            try:
                await kwargs["tool_session_callback"](Session())
            finally:
                revoked = client.post("/fpamcp/oauth/revoke", data={"client_id": h.client_id,
                                                                       "client_secret": "", "token": token})
                assert revoked.status_code == 200
                rejected = client.post("/fpamcp", headers=headers, json=_initialize_payload())
                assert rejected.status_code == 401
                h.revocations += 1
            result: dict[str, object] = {"oauth_metadata_verified": True, "mcp_initialized": True,
                                        "token_revoked": True, "credential_values_returned": False}
            if h.common_transform:
                h.common_transform(result)
            return result

        monkeypatch.setattr(acceptance.oauth, "run_address_mcp_oauth_surface_acceptance", common)
        yield h


def _run(h: Any, tmp_path: Path, operation: str = "associate", *, execute: bool = False,
         discover: bool = False) -> dict[str, object]:
    inputs: dict[str, Any] = {"operation": operation, "ca_file": tmp_path / "ca.pem",
                             "lab_connect_host": "127.0.0.1", "lab_connect_port": 28443,
                             "allow_loopback_tunnel": True}
    if not discover:
        inputs["execute_preview_state_file" if execute else "preview_state_file"] = h.state / f"{operation}.json"
    return asyncio.run(acceptance.run_secret_dlp_association_mcp_oauth_acceptance(
        "https://mcp.example.com/fpamcp", tmp_path / "login.env", tmp_path / "client.json", **inputs))


def _associate(h: Any, tmp_path: Path) -> None:
    _run(h, tmp_path)
    _run(h, tmp_path, execute=True)


def test_real_mcp_client_association_and_separate_restore(harness: Any, tmp_path: Path) -> None:
    for operation in ("associate", "restore"):
        preview = _run(harness, tmp_path, operation)
        path = harness.state / f"{operation}.json"
        stored = json.loads(path.read_text())
        assert set(stored) == {"contract", "operation", "preview_ref"}
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert preview["preview_verified"] is True and preview["device_write_executed"] is False
        result = _run(harness, tmp_path, operation, execute=True)
        assert result["execution_verified"] is result["token_revoked"] is True
        assert result["file_audit_effect"] == "unproven"
        assert not path.exists()
        claim = path.with_name(path.name + ".dispatch.json")
        assert stat.S_IMODE(claim.stat().st_mode) == 0o600
        assert json.loads(claim.read_text())["retry_allowed"] is False
        public = json.dumps(result) + json.dumps(stored) + claim.read_text()
        assert all(value not in public for value in (IDENTITY.name, IDENTITY.target, SENSOR, "authorization_ref", "access_token"))
    assert harness.transport.associations == harness.transport.restorations == 1
    assert harness.revocations == 4
    assert [name for name, _ in harness.calls] == [
        "preview_v4_secret_dlp_association_700", "confirm_v4_secret_dlp_association_700",
        "execute_confirmed_v4_secret_dlp_association_700", "preview_v4_secret_dlp_association_restore_700",
        "confirm_v4_secret_dlp_association_restore_700", "execute_confirmed_v4_secret_dlp_association_restore_700"]


@pytest.mark.parametrize("operation", ["associate", "restore"])
def test_discovery_never_invokes_device_tools(harness: Any, tmp_path: Path, operation: str) -> None:
    result = _run(harness, tmp_path, operation, discover=True)
    assert not harness.calls and not list(harness.state.iterdir())
    assert result["device_tool_invoked"] is result["device_write_executed"] is False
    assert harness.revocations == 1


@pytest.mark.parametrize("operation", ["associate", "restore"])
def test_missing_exact_tool_rejects_before_device_tools(harness: Any, tmp_path: Path, operation: acceptance.Operation) -> None:
    harness.omitted_tool = acceptance._tool_name(operation, "execute_confirmed")
    with pytest.raises(acceptance.SecretDlpAssociationMcpOAuthAcceptanceError, match="surface"):
        _run(harness, tmp_path, operation)
    assert not harness.calls and harness.revocations == 1


@pytest.mark.parametrize("section,field,value", [
    ("Current State", "sensor_native_profile", "unproven"),
    ("Current State", "opaque_fields", "unsupported"),
    ("Current State", "secret_id", 17),
    ("Proposed Changes", "operation", "restore"),
    ("Proposed Changes", "other_secret_fields", "replace"),
    ("Expected State", "metadata_and_opaque_fields", "changed"),
    ("Expected State", "file_audit_effect", "verified"),
])
def test_source_cpe_expansion_or_unsafe_evidence_is_rejected(
    harness: Any, tmp_path: Path, section: str, field: str, value: object,
) -> None:
    harness.transform = lambda name, result: result[section].update({field: value})
    with pytest.raises(acceptance.SecretDlpAssociationMcpOAuthAcceptanceError):
        _run(harness, tmp_path)
    assert not list(harness.state.iterdir()) and harness.transport.associations == 0
    assert harness.revocations == 1


@pytest.mark.parametrize("phase,field,value", [
    ("confirm", "preview_ref", "secret-dlp-associate-preview-other"),
    ("confirm", "authorization_ref", "secret-dlp-restore-authorized-other"),
    ("confirm", "device_write_executed", 0),
    ("execute_confirmed", "verification", "unknown"),
    ("execute_confirmed", "idempotent_replay", True),
    ("execute_confirmed", "raw_api_response_returned", True),
    ("execute_confirmed", "credential_values_returned", 0),
    ("execute_confirmed", "device_write_may_have_occurred", False),
    ("execute_confirmed", "operation", "restore"),
    ("execute_confirmed", "field", "synthetic-material-sentinel"),
])
def test_closed_confirmation_and_readback_failures_preserve_one_attempt_claim(
    harness: Any, tmp_path: Path, phase: str, field: str, value: object,
) -> None:
    _run(harness, tmp_path)
    def transform(name: str, result: dict[str, Any]) -> None:
        if name.startswith(phase):
            result[field] = value
    harness.transform = transform
    with pytest.raises(acceptance.SecretDlpAssociationMcpOAuthAcceptanceError) as error:
        _run(harness, tmp_path, execute=True)
    assert "sentinel" not in str(error.value)
    calls = len(harness.calls)
    with pytest.raises(acceptance.SecretDlpAssociationMcpOAuthAcceptanceError):
        _run(harness, tmp_path, execute=True)
    assert len(harness.calls) == calls
    assert harness.revocations == 3
    assert harness.transport.associations == (0 if phase == "confirm" else 1)


def test_genuine_ambiguous_readback_is_not_retryable(harness: Any, tmp_path: Path) -> None:
    _run(harness, tmp_path)
    harness.transport.failure = "ambiguous"
    with pytest.raises(acceptance.SecretDlpAssociationMcpOAuthAcceptanceError):
        _run(harness, tmp_path, execute=True)
    with pytest.raises(acceptance.SecretDlpAssociationMcpOAuthAcceptanceError):
        _run(harness, tmp_path, execute=True)
    assert harness.transport.associations == 1
    with pytest.raises(acceptance.SecretDlpAssociationMcpOAuthAcceptanceError):
        _run(harness, tmp_path, "restore")
    assert harness.transport.restorations == 0


@pytest.mark.parametrize("defect", ["mode", "symlink", "foreign_ref", "restore_op", "private_selector"])
def test_state_only_accepts_owned_0600_exact_ref_contract(harness: Any, tmp_path: Path, defect: str) -> None:
    _run(harness, tmp_path)
    path = harness.state / "associate.json"
    if defect == "mode":
        path.chmod(0o644)
    elif defect == "symlink":
        target = path.with_name("real.json")
        path.rename(target)
        path.symlink_to(target)
    else:
        state = json.loads(path.read_text())
        if defect == "foreign_ref":
            state["preview_ref"] = "secret-dlp-restore-preview-other"
        elif defect == "restore_op":
            state["operation"] = "restore"
        else:
            state["secret_id"] = 17
        path.write_text(json.dumps(state))
    with pytest.raises(acceptance.SecretDlpAssociationMcpOAuthAcceptanceError, match="state"):
        _run(harness, tmp_path, execute=True)
    assert len(harness.calls) == 1 and harness.revocations == 1 and harness.transport.associations == 0


@pytest.mark.parametrize("field", ["oauth_metadata_verified", "mcp_initialized", "token_revoked"])
def test_transport_proof_requires_independent_flags(harness: Any, tmp_path: Path, field: str) -> None:
    harness.common_transform = lambda result: result.update({field: False})
    with pytest.raises(acceptance.SecretDlpAssociationMcpOAuthAcceptanceError, match="transport acceptance"):
        _run(harness, tmp_path, discover=True)


def test_cli_can_run_from_outside_repository(tmp_path: Path) -> None:
    result = subprocess.run([sys.executable, str(Path(acceptance.__file__).resolve()), "--help"],
        cwd=tmp_path, env={"PATH": os.environ["PATH"], "PYTHONNOUSERSITE": "1"},
        capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert "--operation {associate,restore}" in result.stdout
    assert "--preview-sensor-name" not in result.stdout
