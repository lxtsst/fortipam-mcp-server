"""Synthetic acceptance boundary tests; never contacts OAuth or a device."""
import asyncio
from contextlib import asynccontextmanager
import copy
import json
from types import SimpleNamespace
import time

import pytest

from scripts import v4_secret_request_approval_revoke_mcp_oauth_acceptance as acceptance


def payloads():
    preview = {
        "contract": acceptance.CONTRACT,
        "preview_ref": f"secret-request-approval-revoke-{acceptance.OPERATION}-preview-" + "a" * 32,
        "expires_at": time.time() + 100,
        "Current State": {"exact_active_original_grant_verified": True, "original_reviewer_verified": True, "credential_values_returned": False},
        "Proposed Changes": {"operation": acceptance.OPERATION, "own_grant_withdrawal_only": True, "request_and_parent_metadata_preserved": True},
        "Expected State": {"request_pending": True, "request_and_parent_metadata_preserved": True, "backend_launch_denial_requires_independent_evidence": True},
        "device_write_executed": False,
    }
    authorization = {"contract": acceptance.CONTRACT, "preview_ref": preview["preview_ref"],
        "authorization_ref": f"secret-request-approval-revoke-{acceptance.OPERATION}-authorized-" + "b" * 32,
        "expires_at": preview["expires_at"], "confirmation": "recorded", "execution": "authorized_once", "device_write_executed": False}
    result = {"contract": acceptance.CONTRACT, "operation": acceptance.OPERATION, "outcome": "succeeded", "verification": "verified",
        "idempotent_replay": False, "device_write_may_have_occurred": True, "credential_values_returned": False,
        "raw_api_response_returned": False, "backend_launch_denial_requires_independent_evidence": True}
    return {acceptance.PREVIEW_TOOL: preview, acceptance.AUTHORIZE_TOOL: authorization, acceptance.EXECUTE_TOOL: result}


@pytest.mark.parametrize("failure", [None, "preview", "authorization", "execute", "result", "cleanup", "cleanup_exception"])
def test_one_shot_cleanup_and_minimized_failure(monkeypatch, tmp_path, failure):
    tmp_path.chmod(0o700)
    marker = tmp_path / "dispatch.json"
    values = payloads()
    calls, cleanup = [], []
    if failure == "preview":
        values[acceptance.PREVIEW_TOOL]["raw_secret"] = "private-source-value"
    if failure == "authorization":
        values[acceptance.AUTHORIZE_TOOL]["preview_ref"] += "wrong"
    if failure == "result":
        values[acceptance.EXECUTE_TOOL]["outcome"] = "reconciliation_required"

    class Session:
        async def initialize(self):
            pass

        async def list_tools(self):
            return SimpleNamespace(tools=[SimpleNamespace(name=name) for name in acceptance.TOOLS])

        async def call_tool(self, name, arguments):
            calls.append((name, arguments))
            if name == acceptance.PREVIEW_TOOL:
                assert arguments == {}
            if name == acceptance.EXECUTE_TOOL:
                assert marker.exists()
                assert json.loads(marker.read_text())["retry_allowed"] is False
                if failure == "execute":
                    raise RuntimeError("private-source-value")
            return SimpleNamespace(is_error=False, structured_content=values[name])

    @asynccontextmanager
    async def session(*args):
        yield Session()

    async def token(*args, **kwargs):
        assert kwargs["include_operation_scope"] is True
        return "private-token", False, True, "private-client"

    async def revoke(*args):
        cleanup.append(True)
        if failure == "cleanup_exception":
            raise RuntimeError("private-source-value")
        return failure != "cleanup"

    monkeypatch.setattr(acceptance.oauth, "_mcp_session", session)
    monkeypatch.setattr(acceptance.oauth, "_oauth_token", token)
    monkeypatch.setattr(acceptance.oauth, "_revoke_and_prove_401", revoke)
    monkeypatch.setattr(acceptance.oauth, "load_prefixed_environment_file", lambda *a, **k: None)
    monkeypatch.setattr(acceptance.oauth, "_required_login_value", lambda name: "private-login")

    def run():
        return asyncio.run(acceptance.run_secret_request_approval_revoke_mcp_oauth_acceptance(
            "https://synthetic.example.test/mcp", tmp_path / "login.env", tmp_path / "client.json", marker))

    if failure:
        with pytest.raises(acceptance.SecretRequestApprovalRevokeMcpOAuthAcceptanceError) as caught:
            run()
        assert "private-" not in str(caught.value)
    else:
        result = run()
        assert result["backend_launch_denial_verified"] is False
        assert result["revoked_access_rejected"] is True
        assert "private-" not in json.dumps(result)
    assert cleanup == [True]
    assert sum(name == acceptance.EXECUTE_TOOL for name, _ in calls) == (0 if failure in {"preview", "authorization"} else 1)
    if marker.exists():
        assert marker.stat().st_mode & 0o777 == 0o600
        before = list(calls)
        with pytest.raises(acceptance.SecretRequestApprovalRevokeMcpOAuthAcceptanceError):
            run()
        assert calls == before


@pytest.mark.parametrize("mutation", ["expired", "nan", "boolean", "extended", "raw", "extra", "wrong_ref"])
def test_preview_rejects_invalid_exact_contract(mutation):
    preview = copy.deepcopy(payloads()[acceptance.PREVIEW_TOOL])
    if mutation == "expired":
        preview["expires_at"] = time.time() - 1
    elif mutation == "nan":
        preview["expires_at"] = float("nan")
    elif mutation == "extended":
        preview["expires_at"] = time.time() + 200
    elif mutation == "boolean":
        preview["Current State"]["original_reviewer_verified"] = 1
    elif mutation == "raw":
        preview["Current State"]["raw"] = "sensitive"
    elif mutation == "extra":
        preview["extra"] = True
    else:
        preview["preview_ref"] = "unbound-ref"
    with pytest.raises(acceptance.SecretRequestApprovalRevokeMcpOAuthAcceptanceError):
        acceptance._validate_preview(preview)


def test_dispatch_is_durable_before_use_and_refuses_alias(monkeypatch, tmp_path):
    tmp_path.chmod(0o700)
    calls = []
    real_fsync = acceptance.os.fsync

    def fsync(fd):
        calls.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(acceptance.os, "fsync", fsync)
    marker = tmp_path / "marker.json"
    acceptance._reserve_dispatch(marker)
    assert len(calls) == 2
    with pytest.raises(acceptance.SecretRequestApprovalRevokeMcpOAuthAcceptanceError):
        acceptance._reserve_dispatch(marker)
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(acceptance.SecretRequestApprovalRevokeMcpOAuthAcceptanceError):
        acceptance._new_dispatch_path(alias / "fresh.json")


def test_candidate_contract_matches_production():
    from fortipam_mcp.secret_request_approval_revoke_live_workflow import CONTRACT
    from fortipam_mcp.secret_request_approval_revoke_mcp_action import register_secret_request_approval_revoke_tools
    import inspect

    assert acceptance.CONTRACT == CONTRACT
    registered = inspect.getsource(register_secret_request_approval_revoke_tools)
    assert all(name in registered for name in acceptance.TOOLS)


@pytest.mark.parametrize("field,value", [
    ("idempotent_replay", True), ("verification", "unknown"),
    ("operation", "other-operation"), ("credential_values_returned", True),
    ("raw_api_response_returned", True),
    ("backend_launch_denial_requires_independent_evidence", False),
])
def test_execution_rejects_unproven_or_disclosing_results(field, value):
    result = payloads()[acceptance.EXECUTE_TOOL]
    result[field] = value
    with pytest.raises(acceptance.SecretRequestApprovalRevokeMcpOAuthAcceptanceError):
        acceptance._validate_execution(result)


def test_partial_marker_failure_retains_non_replayable_record(monkeypatch, tmp_path):
    tmp_path.chmod(0o700)
    marker = tmp_path / "partial.json"

    def failed_fsync(fd):
        raise OSError("synthetic-durability-failure")

    monkeypatch.setattr(acceptance.os, "fsync", failed_fsync)
    with pytest.raises(OSError):
        acceptance._reserve_dispatch(marker)
    assert marker.exists()
    with pytest.raises(acceptance.SecretRequestApprovalRevokeMcpOAuthAcceptanceError):
        acceptance._new_dispatch_path(marker)
