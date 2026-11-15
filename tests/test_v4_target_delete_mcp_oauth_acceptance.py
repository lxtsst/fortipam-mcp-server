from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import v4_target_delete_mcp_oauth_acceptance as acceptance


def _preview() -> dict[str, object]:
    return {
        "contract": acceptance.WORKFLOW,
        "preview_ref": acceptance.PREVIEW_PREFIX + "unit-test",
        "Current State": {
            "accepted_target_exists": True,
            "complete_api_record_digest_matches": True,
            "target_class_is_other": True,
            "accepted_classification_tag_absent": True,
            "target_reference_count": 0,
            "selectors_returned": False,
            "read_transports": ["rest_api", "ssh_cli"],
        },
        "Proposed Changes": {
            "operation": "delete_exact_unreferenced_target_via_api",
            "target_count_affected": 1,
            "irreversible_after_execution": True,
            "classification_tag_secret_or_session_change": False,
        },
        "Expected State": {
            "target_absent": True,
            "accepted_classification_tag_absent": True,
            "target_reference_count": 0,
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


@pytest.mark.parametrize("verified", [True, False])
def test_owner_session_preview_requires_exact_actor_and_relation(verified: bool) -> None:
    preview = _preview()
    current = preview["Current State"]
    assert isinstance(current, dict)
    current.update({"delete_authentication": "owner_session", "exact_owner_actor_and_relation_verified": verified})
    if verified:
        acceptance._validate_preview(preview, False)
    else:
        with pytest.raises(acceptance.TargetDeleteMcpOAuthAcceptanceError):
            acceptance._validate_preview(preview, False)


def _execution() -> dict[str, object]:
    return {
        "contract": acceptance.EXECUTION,
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "compensation": "separate_target_create_action_required",
        "target_name_or_configuration_returned": False,
        "classification_tag_name_returned": False,
        "raw_api_or_cli_response_returned": False,
    }


class _Session:
    def __init__(self, *, preview: dict[str, object] | None = None) -> None:
        self.preview = preview or _preview()
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def list_tools(self) -> SimpleNamespace:
        names = set(acceptance.TOOLS)
        names.update(
            f"synthetic-{index}"
            for index in range(acceptance.EXPECTED_TOOL_COUNT - len(names))
        )
        return SimpleNamespace(tools=[SimpleNamespace(name=name) for name in names])

    async def call_tool(self, name: str, arguments: dict[str, object]) -> SimpleNamespace:
        self.calls.append((name, arguments))
        payload = {
            "preview_v4_ssh_target_delete": self.preview,
            "confirm_v4_ssh_target_delete": _confirmation(),
            "execute_confirmed_v4_ssh_target_delete": _execution(),
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

    monkeypatch.setattr(
        acceptance.oauth,
        "run_address_mcp_oauth_surface_acceptance",
        run,
    )


def test_surface_preview_and_execution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _patch(monkeypatch, _Session())
    surface = asyncio.run(
        acceptance.run_target_delete_mcp_oauth_acceptance(
            "https://mcp.example.test/fpamcp-v4",
            tmp_path / "login",
            tmp_path / "client",
        )
    )
    assert surface["tool_count"] == 298
    assert surface["device_tool_invoked"] is False

    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    state = state_dir / "preview.json"
    _patch(monkeypatch, _Session())
    preview = asyncio.run(
        acceptance.run_target_delete_mcp_oauth_acceptance(
            "https://mcp.example.test/fpamcp-v4",
            tmp_path / "login",
            tmp_path / "client",
            preview_state_file=state,
        )
    )
    assert preview["target_delete_preview_verified"] is True
    assert json.loads(state.read_text())["preview_ref"].startswith(
        acceptance.PREVIEW_PREFIX
    )

    _patch(monkeypatch, _Session())
    executed = asyncio.run(
        acceptance.run_target_delete_mcp_oauth_acceptance(
            "https://mcp.example.test/fpamcp-v4",
            tmp_path / "login",
            tmp_path / "client",
            execute_preview_state_file=state,
        )
    )
    assert executed["target_delete_execution_verified"] is True
    assert executed["device_write_executed"] is True
    assert not state.exists()


def test_validators_reject_identifier_leak_and_unverified_execution() -> None:
    leaked = _preview()
    assert isinstance(leaked["Current State"], dict)
    leaked["Current State"]["target"] = "mcp-v4-target-b29"  # type: ignore[index]
    with pytest.raises(acceptance.TargetDeleteMcpOAuthAcceptanceError):
        acceptance._validate_preview(leaked, False)
    failed = _execution()
    failed["verification"] = "unknown"
    with pytest.raises(acceptance.TargetDeleteMcpOAuthAcceptanceError):
        acceptance._validate_execution(failed, False)


def test_fixed_wrapper_rejects_combined_preview_and_execute(tmp_path: Path) -> None:
    with pytest.raises(acceptance.TargetDeleteMcpOAuthAcceptanceError):
        asyncio.run(
            acceptance.run_target_delete_mcp_oauth_acceptance(
                "https://mcp.example.test/fpamcp-v4",
                tmp_path / "login",
                tmp_path / "client",
                preview_state_file=tmp_path / "a",
                execute_preview_state_file=tmp_path / "b",
            )
        )


def test_authorized_once_chain_uses_the_validated_preview_without_temp_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    session = _Session()
    _patch(monkeypatch, session)

    result = asyncio.run(
        acceptance.run_target_delete_mcp_oauth_acceptance(
            "https://mcp.example.test/fpamcp-v4",
            tmp_path / "login",
            tmp_path / "client",
            execute_authorized_once=True,
        )
    )

    assert [name for name, _arguments in session.calls] == [
        "preview_v4_ssh_target_delete",
        "confirm_v4_ssh_target_delete",
        "execute_confirmed_v4_ssh_target_delete",
    ]
    assert session.calls[1][1] == {
        "preview_ref": acceptance.PREVIEW_PREFIX + "unit-test"
    }
    assert session.calls[2][1] == {
        "authorization_ref": acceptance.AUTHORIZATION_PREFIX + "unit-test"
    }
    assert result["target_delete_preview_verified"] is True
    assert result["target_delete_execution_verified"] is True
    assert result["authorized_once_chain_completed"] is True
    assert result["device_write_executed"] is True
    assert list(tmp_path.glob("*.json")) == []


def test_authorized_once_chain_stops_before_confirmation_on_preview_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    preview = _preview()
    assert isinstance(preview["Current State"], dict)
    preview["Current State"]["target_reference_count"] = 1  # type: ignore[index]
    session = _Session(preview=preview)
    _patch(monkeypatch, session)

    with pytest.raises(acceptance.TargetDeleteMcpOAuthAcceptanceError):
        asyncio.run(
            acceptance.run_target_delete_mcp_oauth_acceptance(
                "https://mcp.example.test/fpamcp-v4",
                tmp_path / "login",
                tmp_path / "client",
                execute_authorized_once=True,
            )
        )

    assert [name for name, _arguments in session.calls] == [
        "preview_v4_ssh_target_delete"
    ]


def test_authorized_once_mode_rejects_preview_state_inputs(tmp_path: Path) -> None:
    for state_input in (
        {"preview_state_file": tmp_path / "preview.json"},
        {"execute_preview_state_file": tmp_path / "execute.json"},
    ):
        with pytest.raises(acceptance.TargetDeleteMcpOAuthAcceptanceError):
            asyncio.run(
                acceptance.run_target_delete_mcp_oauth_acceptance(
                    "https://mcp.example.test/fpamcp-v4",
                    tmp_path / "login",
                    tmp_path / "client",
                    execute_authorized_once=True,
                    **state_input,
                )
            )
