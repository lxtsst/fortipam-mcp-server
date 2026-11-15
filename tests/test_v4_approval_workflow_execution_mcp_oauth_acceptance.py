from __future__ import annotations

import asyncio
import ipaddress
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scripts import v4_approval_workflow_execution_mcp_oauth_acceptance as acceptance


def _private_lab_host() -> str:
    return str(ipaddress.IPv4Address(0x0A000001))


def test_request_create_cli_forwards_mcp_read_timeout_to_surface_client(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    intent = tmp_path / "intent-ref.json"
    intent.write_text(json.dumps({"intent_ref": "fresh-request-intent-ref01"}), encoding="ascii")
    intent.chmod(0o600)
    forwarded: list[int] = []

    class SurfaceReached(RuntimeError):
        pass

    async def surface(*args: Any, **kwargs: Any) -> dict[str, object]:
        forwarded.append(kwargs["mcp_read_timeout_seconds"])
        assert kwargs["required_tools"] == acceptance.REQUEST_CREATE_TOOLS
        # Stop before OAuth, network, callback or either dispatch record.
        raise SurfaceReached

    monkeypatch.setattr(acceptance.oauth, "run_address_mcp_oauth_surface_acceptance", surface)
    monkeypatch.setattr(sys, "argv", [
        "bp008-acceptance", "--url", "https://synthetic.example.test/mcp",
        "--login-file", str(tmp_path / "login.env"),
        "--client-state-file", str(tmp_path / "client.json"),
        "--dispatch-state-file", str(tmp_path / "dispatch.json"),
        "--request-intent-ref-file", str(intent), "--mcp-read-timeout-seconds", "120",
    ])
    with pytest.raises(SurfaceReached):
        acceptance.main()
    assert forwarded == [120]
    assert not (tmp_path / "dispatch.json").exists()


@pytest.mark.parametrize("include_request", [False, True])
def test_bp008_external_execution_is_one_shot_and_value_minimized(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    include_request: bool,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    binding_file = state / "execution-binding.json"
    binding_file.write_text(
        json.dumps(
            {
                "plan_ref": "approval-plan-reference01",
                "scheme_draft_ref": "approval-draft-reference1",
            }
        ),
        encoding="utf-8",
    )
    binding_file.chmod(0o600)
    intent_ref_file = state / "request-intent-ref.json"
    intent_ref_file.write_text(
        json.dumps({"intent_ref": "request-intent-reference01"}),
        encoding="utf-8",
    )
    intent_ref_file.chmod(0o600)
    dispatch_file = state / "dispatch.json"
    calls: list[tuple[str, dict[str, object]]] = []

    class FakeSession:
        async def call_tool(
            self,
            name: str,
            arguments: dict[str, object],
        ) -> SimpleNamespace:
            calls.append((name, arguments))
            if name == acceptance.V4_APPROVAL_AND_OBSERVE_EXECUTION_TOOL:
                assert dispatch_file.exists()
            payloads: dict[str, dict[str, object]] = {
                "get_server_info": {
                    "runtime_profile": "v4-controlled",
                    "v4_host_services_bound": True,
                    "v4_approval_and_observe_execution_bound": True,
                    "v4_approval_and_observe_execution_tool_count": 1,
                    "v4_secret_request_create_bound": include_request,
                    "v4_secret_request_create_tool_count": (
                        1 if include_request else 0
                    ),
                },
                "get_v4_plan_status": {
                    "host_services_bound": True,
                    "projection_mode": "source_backed",
                    "confirmation_transport_bound": True,
                    "scheme_draft_issuance_protocol_bound": True,
                    "reference_authorization_protocol_bound": True,
                    "approval_receipt_authenticator_protocol_bound": True,
                    "approver_authorization_protocol_bound": True,
                },
                acceptance.V4_APPROVAL_AND_OBSERVE_EXECUTION_TOOL: {
                    "authorization_scope": "source_bound_approval_workflow",
                    "completed_line_refs": ["approval-line-reference01"],
                    "outcome": "succeeded",
                    "policy_mode": "independent_approval",
                    "post_write_status": "expected_state_matches",
                    "pre_write_status": "match",
                    "reconciliation_required": False,
                    "stopped_line_ref": None,
                },
                acceptance.V4_SECRET_REQUEST_CREATE_TOOL: {
                    "contract": "fortipam-v4-secret-request-create-result-v1",
                    "outcome": "bound",
                    "raw_values_returned": False,
                    "reconciliation_required": False,
                    "request_bound": True,
                    "request_identifiers_returned": False,
                    "request_intent_returned": False,
                },
            }
            return SimpleNamespace(is_error=False, structured_content=payloads[name])

    async def fake_common(*args: Any, **kwargs: Any) -> dict[str, object]:
        assert kwargs["required_tools"] == (
            acceptance.TOOLS
            if not include_request
            else acceptance.TOOLS
            | {acceptance.V4_SECRET_REQUEST_CREATE_TOOL}
        )
        callback = kwargs["tool_session_callback"]
        await callback(FakeSession())
        return {
            "oauth_metadata_verified": True,
            "mcp_initialized": True,
            "token_revoked": True,
            "credential_values_returned": False,
        }

    monkeypatch.setattr(
        acceptance.oauth,
        "run_address_mcp_oauth_surface_acceptance",
        fake_common,
    )
    result = asyncio.run(
        acceptance.run_approval_workflow_execution_mcp_oauth_acceptance(
            "https://fpamcp.example.test/fpamcp-v4",
            state / "login.env",
            state / "client.json",
            binding_file,
            dispatch_file,
            request_intent_ref_file=(intent_ref_file if include_request else None),
        )
    )

    expected_calls = [
        ("get_server_info", {}),
        ("get_v4_plan_status", {}),
        (
            acceptance.V4_APPROVAL_AND_OBSERVE_EXECUTION_TOOL,
            {
                "plan_ref": "approval-plan-reference01",
                "scheme_draft_ref": "approval-draft-reference1",
            },
        ),
    ]
    if include_request:
        expected_calls.append(
            (
                acceptance.V4_SECRET_REQUEST_CREATE_TOOL,
                {"intent_ref": "request-intent-reference01"},
            )
        )
    assert calls == expected_calls
    assert result["dispatch_attempted_once"] is True
    assert result["completed_action_count"] == 1
    assert result["post_write_expected_state_verified"] is True
    assert result["approval_receipt_returned"] is False
    assert result["request_create_attempted"] is include_request
    assert result["request_bound"] is include_request
    assert result["request_identifiers_returned"] is False
    assert "approval-plan-reference01" not in repr(result)
    assert "approval-draft-reference1" not in repr(result)
    assert "approval-line-reference01" not in repr(result)
    dispatch = json.loads(dispatch_file.read_text(encoding="ascii"))
    assert dispatch == {
        "contract": acceptance._DISPATCH_CONTRACT,
        "dispatch_attempted": True,
        "retry_allowed": False,
    }

    with pytest.raises(
        acceptance.ApprovalWorkflowExecutionMcpOAuthAcceptanceError,
        match="dispatch state file is unavailable",
    ):
        asyncio.run(
            acceptance.run_approval_workflow_execution_mcp_oauth_acceptance(
                "https://fpamcp.example.test/fpamcp-v4",
                state / "login.env",
                state / "client.json",
                binding_file,
                dispatch_file,
                request_intent_ref_file=(
                    intent_ref_file if include_request else None
                ),
            )
        )


def test_request_only_acceptance_skips_the_already_satisfied_approval_write(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    intent_ref_file = state / "request-intent-ref.json"
    intent_ref_file.write_text(
        json.dumps({"intent_ref": "request-intent-reference01"}),
        encoding="utf-8",
    )
    intent_ref_file.chmod(0o600)
    dispatch_file = state / "dispatch.json"
    calls: list[tuple[str, dict[str, object]]] = []

    class FakeSession:
        async def call_tool(
            self,
            name: str,
            arguments: dict[str, object],
        ) -> SimpleNamespace:
            calls.append((name, arguments))
            if name == acceptance.V4_SECRET_REQUEST_CREATE_TOOL:
                assert dispatch_file.exists()
            payloads: dict[str, dict[str, object]] = {
                "get_server_info": {
                    "runtime_profile": "v4-controlled",
                    "v4_host_services_bound": True,
                    "v4_secret_request_create_bound": True,
                    "v4_secret_request_create_tool_count": 1,
                },
                "get_v4_plan_status": {
                    "host_services_bound": True,
                    "projection_mode": "source_backed",
                    "confirmation_transport_bound": True,
                    "scheme_draft_issuance_protocol_bound": True,
                    "reference_authorization_protocol_bound": True,
                },
                acceptance.V4_SECRET_REQUEST_CREATE_TOOL: {
                    "contract": "fortipam-v4-secret-request-create-result-v1",
                    "outcome": "bound",
                    "raw_values_returned": False,
                    "reconciliation_required": False,
                    "request_bound": True,
                    "request_identifiers_returned": False,
                    "request_intent_returned": False,
                },
            }
            return SimpleNamespace(is_error=False, structured_content=payloads[name])

    async def fake_common(*args: Any, **kwargs: Any) -> dict[str, object]:
        assert kwargs["required_tools"] == acceptance.REQUEST_CREATE_TOOLS
        assert kwargs["allow_insecure_private_ip_lab"] is True
        assert kwargs["lab_connect_host"] == _private_lab_host()
        assert kwargs["lab_connect_port"] == 18443
        assert kwargs["allow_loopback_tunnel"] is True
        await kwargs["tool_session_callback"](FakeSession())
        return {
            "oauth_metadata_verified": True,
            "mcp_initialized": True,
            "token_revoked": True,
            "credential_values_returned": False,
        }

    monkeypatch.setattr(
        acceptance.oauth,
        "run_address_mcp_oauth_surface_acceptance",
        fake_common,
    )
    result = asyncio.run(
        acceptance.run_approval_workflow_execution_mcp_oauth_acceptance(
            "https://fpamcp.example.test/fpamcp-v4",
            state / "login.env",
            state / "client.json",
            None,
            dispatch_file,
            request_intent_ref_file=intent_ref_file,
            allow_insecure_private_ip_lab=True,
            lab_connect_host=_private_lab_host(),
            lab_connect_port=18443,
            allow_loopback_tunnel=True,
        )
    )

    assert calls == [
        ("get_server_info", {}),
        ("get_v4_plan_status", {}),
        (
            acceptance.V4_SECRET_REQUEST_CREATE_TOOL,
            {"intent_ref": "request-intent-reference01"},
        ),
    ]
    assert result["approval_policy_action_attempted"] is False
    assert result["independent_approval_binding_verified"] is False
    assert result["completed_action_count"] == 0
    assert result["post_write_expected_state_verified"] is False
    assert result["request_create_attempted"] is True
    assert result["request_bound"] is True
    assert result["device_write_executed"] is True
    assert "request-intent-reference01" not in repr(result)


def test_request_or_execution_input_is_required(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    with pytest.raises(
        acceptance.ApprovalWorkflowExecutionMcpOAuthAcceptanceError,
        match="execution or Request intent is required",
    ):
        asyncio.run(
            acceptance.run_approval_workflow_execution_mcp_oauth_acceptance(
                "https://fpamcp.example.test/fpamcp-v4",
                state / "login.env",
                state / "client.json",
                None,
                state / "dispatch.json",
            )
        )
