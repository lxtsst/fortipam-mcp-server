from __future__ import annotations

import asyncio
import json
from pathlib import Path
import stat
from types import SimpleNamespace
from typing import Any

import pytest

from scripts import v4_approval_workflow_mcp_oauth_acceptance as acceptance


def _preview() -> dict[str, object]:
    return {
        "state": "awaiting_confirmation",
        "confirmation_state": "awaiting_human_reauthentication",
        "summary_ref": "summary-ref-opaque",
        "revision": 1,
        "confirmation_url": "https://fpamcp.example.test/confirm/opaque",
        "scheme_id": "ApprovalAndObserveScheme",
        "blueprint_ref": "FPA-BP-008",
        "object_changes": [
            {
                "object_class": "ApprovalProfileBinding",
                "object_ref": "profile-object-ref-opaque",
            },
            {
                "object_class": "SecretApprovalBinding",
                "object_ref": "secret-object-ref-opaque",
            },
        ],
    }


def _plan() -> dict[str, object]:
    return {
        "dispatchable": False,
        "adapter_registry_bound": False,
        "executor_runtime_packaged": False,
        "executor_mcp_exposed": False,
        "planner_mcp_exposed": True,
        "plan_ref": "prepared-plan-ref-opaque",
    }


def _write_owner_only_ref(path: Path) -> None:
    path.write_text(
        json.dumps({"scheme_draft_ref": "scheme-draft-ref-opaque"}),
        encoding="utf-8",
    )
    path.chmod(0o600)


def _write_owner_only_request_ref(path: Path) -> None:
    path.write_text(
        json.dumps({"request_ref": "request-observation-ref-opaque"}),
        encoding="utf-8",
    )
    path.chmod(0o600)


def test_bp008_preview_and_plan_reject_widening() -> None:
    acceptance._validate_bp008_preview(_preview())
    acceptance._validate_bp008_plan(_plan())

    widened = _preview()
    widened["object_changes"] = [
        *widened["object_changes"],  # type: ignore[misc]
        {"object_class": "ApprovalRequest", "object_ref": "request-ref"},
    ]
    with pytest.raises(
        acceptance.ApprovalWorkflowMcpOAuthAcceptanceError,
        match="intent preview is invalid",
    ):
        acceptance._validate_bp008_preview(widened)

    dispatchable = {**_plan(), "dispatchable": True}
    with pytest.raises(
        acceptance.ApprovalWorkflowMcpOAuthAcceptanceError,
        match="safely non-executable",
    ):
        acceptance._validate_bp008_plan(dispatchable)


def test_acceptance_prepares_one_bp008_plan_without_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state_directory = tmp_path / "state"
    state_directory.mkdir(mode=0o700)
    state_directory.chmod(0o700)
    draft_file = state_directory / "draft.json"
    _write_owner_only_ref(draft_file)
    request_ref_file = state_directory / "request.json"
    _write_owner_only_request_ref(request_ref_file)
    execution_binding_file = state_directory / "execution-binding.json"
    calls: list[tuple[str, dict[str, object]]] = []

    class FakeSession:
        async def call_tool(
            self,
            name: str,
            arguments: dict[str, object],
        ) -> SimpleNamespace:
            calls.append((name, arguments))
            payloads: dict[str, dict[str, object]] = {
                "get_v4_plan_status": {
                    "runtime_profile": "v4-plan-only",
                    "host_services_bound": True,
                    "confirmation_transport_bound": True,
                    "projection_mode": "source_backed",
                    "scheme_draft_issuance_protocol_bound": True,
                    "reference_authorization_protocol_bound": True,
                },
                "preview_v4_administrative_intent": _preview(),
                "confirm_v4_administrative_intent": {
                    "confirmation_ref": "confirmation-ref-opaque"
                },
                "prepare_v4_non_executable_plan": _plan(),
                "observe_v4_bound_secret_request": {
                    "contract": "fortipam-v4-secret-request-observation-v1",
                    "request_exists": True,
                    "request_type": "launcher",
                    "lifecycle_state": "pending",
                    "approval_progress": "tier1",
                    "action_status": "needed",
                    "raw_values_returned": False,
                },
            }
            return SimpleNamespace(is_error=False, structured_content=payloads[name])

    async def fake_common(*args: Any, **kwargs: Any) -> dict[str, object]:
        assert kwargs["required_tools"] == acceptance.TOOLS | {
            acceptance.REQUEST_OBSERVATION_TOOL
        }
        assert kwargs["requested_scope"] == acceptance.oauth.PLAN_ONLY_SCOPE
        callback = kwargs["tool_session_callback"]
        await callback(FakeSession())
        return {
            "oauth_metadata_verified": True,
            "mcp_initialized": True,
            "token_revoked": True,
            "credential_values_returned": False,
        }

    async def fake_affirm(*args: object, **kwargs: object) -> None:
        return None

    monkeypatch.setenv(acceptance.LOGIN_USERNAME, "operator")
    monkeypatch.setenv(acceptance.LOGIN_PASSWORD, "not-used-by-test")
    monkeypatch.setattr(
        acceptance.oauth,
        "run_address_mcp_oauth_surface_acceptance",
        fake_common,
    )
    monkeypatch.setattr(acceptance, "_affirm_browser_confirmation", fake_affirm)

    result = asyncio.run(
        acceptance.run_approval_workflow_mcp_oauth_acceptance(
            "https://fpamcp.example.test/fpamcp-v4",
            tmp_path / "login.env",
            tmp_path / "client.json",
            draft_file,
            request_ref_file=request_ref_file,
            execution_binding_output_file=execution_binding_file,
        )
    )

    assert calls == [
        ("get_v4_plan_status", {}),
        (
            "preview_v4_administrative_intent",
            {"scheme_draft_ref": "scheme-draft-ref-opaque"},
        ),
        (
            "confirm_v4_administrative_intent",
            {"summary_ref": "summary-ref-opaque", "summary_revision": 1},
        ),
        (
            "prepare_v4_non_executable_plan",
            {
                "summary_ref": "summary-ref-opaque",
                "confirmation_ref": "confirmation-ref-opaque",
            },
        ),
        (
            "observe_v4_bound_secret_request",
            {"request_ref": "request-observation-ref-opaque"},
        ),
    ]
    assert result["non_executable_plan_prepared"] is True
    assert result["execution_binding_staged"] is True
    assert result["device_write_executed"] is False
    assert result["request_created"] is False
    assert result["request_observation_verified"] is True
    assert result["token_revoked"] is True
    assert stat.S_IMODE(execution_binding_file.stat().st_mode) == 0o600
    assert json.loads(execution_binding_file.read_text(encoding="ascii")) == {
        "plan_ref": "prepared-plan-ref-opaque",
        "scheme_draft_ref": "scheme-draft-ref-opaque",
    }


def test_request_observation_rejects_identifier_or_raw_field_widening() -> None:
    observation = {
        "contract": "fortipam-v4-secret-request-observation-v1",
        "request_exists": True,
        "request_type": "launcher",
        "lifecycle_state": "pending",
        "approval_progress": "tier1",
        "action_status": "needed",
        "raw_values_returned": False,
    }
    acceptance._validate_request_observation(observation)
    acceptance._validate_request_observation(
        {
            **observation,
            "lifecycle_state": "approved_availability_unknown",
            "approval_progress": "complete",
            "action_status": "unknown",
        }
    )

    with pytest.raises(
        acceptance.ApprovalWorkflowMcpOAuthAcceptanceError,
        match="request observation is invalid",
    ):
        acceptance._validate_request_observation(
            {**observation, "request_id": 71}
        )
