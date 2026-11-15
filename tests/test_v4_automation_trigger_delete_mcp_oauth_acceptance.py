from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import v4_automation_trigger_delete_mcp_oauth_acceptance as acceptance


def _preview() -> dict[str, object]:
    return {
        "contract": acceptance.WORKFLOW,
        "preview_ref": acceptance.PREVIEW_PREFIX + "unit-test",
        "Current State": {
            "accepted_unbound_automation_trigger_exists": True,
            "exact_fixed_projection_observed": True,
            "complete_api_record_digest_matches": True,
            "fixed_action_dependency_matches": True,
            "trigger_reference_count": 0,
            "read_transports": ["rest_api", "ssh_cli"],
        },
        "Proposed Changes": {
            "operation": "delete_exact_unreferenced_automation_trigger_via_api",
            "trigger_count_affected": 1,
            "irreversible_after_execution": True,
            "action_object_changes": False,
            "automation_test_or_execution": False,
            "email_or_external_side_effect": False,
        },
        "Expected State": {
            "accepted_automation_trigger_absent": True,
            "fixed_action_dependency_preserved": True,
            "automation_test_or_execution": False,
            "email_or_external_side_effect": False,
            "readback_transports": ["rest_api", "ssh_cli"],
        },
        "device_write_executed": False,
    }


def _confirmation() -> dict[str, object]:
    return {
        "contract": acceptance.WORKFLOW,
        "authorization_ref": acceptance.AUTHORIZATION_PREFIX + "unit-test",
        "confirmation": "recorded",
        "execution": "authorized_once",
        "device_write_executed": False,
    }


def _execution() -> dict[str, object]:
    return {
        "contract": acceptance.EXECUTION,
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "compensation": "separate_automation_trigger_create_action_required",
        "irreversible_after_execution": True,
        "trigger_or_action_fields_returned": False,
        "action_object_changes": False,
        "automation_test_or_execution": False,
        "email_or_external_side_effect": False,
        "raw_api_or_cli_response_returned": False,
    }


class _Session:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def list_tools(self) -> SimpleNamespace:
        names = set(acceptance.TOOLS)
        names.update(
            f"synthetic-{index}"
            for index in range(acceptance.EXPECTED_TOOL_COUNT - len(names))
        )
        return SimpleNamespace(tools=[SimpleNamespace(name=name) for name in names])

    async def call_tool(self, name: str, arguments: dict[str, object]) -> SimpleNamespace:
        del arguments
        if name == "get_capability_matrix":
            return SimpleNamespace(
                structured_content={"tool_count": acceptance.EXPECTED_SELECTED_CAPABILITY_COUNT},
                is_error=False,
            )
        self.calls.append(name)
        payload = {
            "preview_v4_automation_trigger_delete": _preview(),
            "confirm_v4_automation_trigger_delete": _confirmation(),
            "execute_confirmed_v4_automation_trigger_delete": _execution(),
        }[name]
        return SimpleNamespace(structured_content=payload, is_error=False)


def _patch(monkeypatch: pytest.MonkeyPatch, session: _Session) -> None:
    async def run(*args: object, **kwargs: object) -> dict[str, object]:
        del args
        await kwargs["tool_session_callback"](session)  # type: ignore[operator]
        return {
            "oauth_metadata_verified": True,
            "mcp_initialized": True,
            "token_revoked": True,
            "credential_values_returned": False,
        }

    monkeypatch.setattr(acceptance.oauth, "run_address_mcp_oauth_surface_acceptance", run)


def test_surface_preview_and_execution(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    session = _Session()
    _patch(monkeypatch, session)
    surface = asyncio.run(
        acceptance.run_automation_trigger_delete_mcp_oauth_acceptance(
            "https://mcp.example.test/fpamcp-v4", tmp_path / "login", tmp_path / "client"
        )
    )
    assert surface["tool_count"] == 280
    assert surface["selected_capability_count"] == 281
    assert surface["device_tool_invoked"] is False

    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    state = state_dir / "preview.json"
    session = _Session()
    _patch(monkeypatch, session)
    preview = asyncio.run(
        acceptance.run_automation_trigger_delete_mcp_oauth_acceptance(
            "https://mcp.example.test/fpamcp-v4",
            tmp_path / "login",
            tmp_path / "client",
            preview_state_file=state,
        )
    )
    assert preview["automation_trigger_delete_preview_verified"] is True
    assert json.loads(state.read_text())["preview_ref"].startswith(acceptance.PREVIEW_PREFIX)

    session = _Session()
    _patch(monkeypatch, session)
    executed = asyncio.run(
        acceptance.run_automation_trigger_delete_mcp_oauth_acceptance(
            "https://mcp.example.test/fpamcp-v4",
            tmp_path / "login",
            tmp_path / "client",
            execute_preview_state_file=state,
        )
    )
    assert executed["automation_trigger_delete_execution_verified"] is True
    assert executed["device_write_executed"] is True
    assert not state.exists()


def test_validators_reject_leak_and_unverified_execution() -> None:
    leaked = _preview()
    assert isinstance(leaked["Current State"], dict)
    leaked["Current State"]["trigger_name"] = "mcp-v4-automation-trigger-b40"  # type: ignore[index]
    with pytest.raises(acceptance.AutomationTriggerDeleteMcpOAuthAcceptanceError):
        acceptance._validate_preview(leaked, False)
    failed = _execution()
    failed["verification"] = "unknown"
    with pytest.raises(acceptance.AutomationTriggerDeleteMcpOAuthAcceptanceError):
        acceptance._validate_execution(failed, False)
