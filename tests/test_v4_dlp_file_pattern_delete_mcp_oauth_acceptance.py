from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import v4_dlp_file_pattern_delete_mcp_oauth_acceptance as acceptance


def _preview() -> dict[str, object]:
    return {
        "contract": acceptance.WORKFLOW,
        "preview_ref": acceptance.PREFIX + "unit-test",
        "expires_at": 700,
        "Current State": {
            "accepted_dlp_file_pattern_exists": True,
            "exact_fixed_single_pdf_pattern_observed": True,
            "complete_api_record_digest_matches": True,
            "sensor_reference_count_rest": 0,
            "sensor_reference_count_ssh": 0,
            "fixed_regexp_sensor_present": True,
            "read_transports": ["rest_api", "ssh_cli"],
        },
        "Proposed Changes": {
            "operation": "delete_exact_unreferenced_dlp_file_pattern_via_api",
            "dlp_file_pattern_count_affected": 1,
            "irreversible_after_execution": True,
            "dlp_sensor_changes": False,
            "secret_or_policy_association_changes": False,
            "license_or_session_changes": False,
        },
        "Expected State": {
            "accepted_dlp_file_pattern_absent": True,
            "fixed_regexp_sensor_preserved": True,
            "dlp_sensor_changes": False,
            "secret_or_policy_association_changes": False,
            "license_or_session_changes": False,
            "readback_transports": ["rest_api", "ssh_cli"],
        },
        "device_write_executed": False,
    }


def _confirmation() -> dict[str, object]:
    return {
        "contract": acceptance.WORKFLOW,
        "preview_ref": acceptance.PREFIX + "unit-test",
        "authorization_ref": "dlp-file-pattern-delete-authorized-unit-test",
        "confirmation": "recorded",
        "execution": "authorized_once",
        "expires_at": 700,
        "device_write_executed": False,
    }


def _execution() -> dict[str, object]:
    return {
        "contract": acceptance.EXECUTION,
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "compensation": "separate_dlp_file_pattern_create_action_required",
        "irreversible_after_execution": True,
        "dlp_file_pattern_id_or_name_returned": False,
        "profile_content_returned": False,
        "dlp_sensor_changes": False,
        "secret_or_policy_association_changes": False,
        "license_or_session_changes": False,
        "raw_api_or_cli_response_returned": False,
    }


class _Session:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def list_tools(self) -> SimpleNamespace:
        names = set(acceptance.TOOLS)
        names.update(
            f"synthetic-tool-{index}"
            for index in range(acceptance.EXPECTED_TOOL_COUNT - len(names))
        )
        return SimpleNamespace(
            tools=[SimpleNamespace(name=name) for name in names]
        )

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, object],
    ) -> SimpleNamespace:
        if name == "get_capability_matrix":
            return SimpleNamespace(
                structured_content={
                    "tool_count": acceptance.EXPECTED_SELECTED_CAPABILITY_COUNT
                },
                is_error=False,
            )
        self.calls.append((name, arguments))
        payload = {
            "preview_v4_dlp_file_pattern_delete": _preview(),
            "confirm_v4_dlp_file_pattern_delete": _confirmation(),
            "execute_confirmed_v4_dlp_file_pattern_delete": _execution(),
        }[name]
        return SimpleNamespace(structured_content=payload, is_error=False)


def _common() -> dict[str, object]:
    return {
        "oauth_metadata_verified": True,
        "mcp_initialized": True,
        "token_revoked": True,
        "credential_values_returned": False,
    }


def _patch_oauth(
    monkeypatch: pytest.MonkeyPatch,
    session: _Session,
) -> None:
    async def run(*args: object, **kwargs: object) -> dict[str, object]:
        callback = kwargs["tool_session_callback"]
        await callback(session)  # type: ignore[operator]
        return _common()

    monkeypatch.setattr(
        acceptance.oauth,
        "run_address_mcp_oauth_surface_acceptance",
        run,
    )


def test_surface_mode_discovers_tools_without_invoking_device_tool(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    session = _Session()
    _patch_oauth(monkeypatch, session)

    result = asyncio.run(
        acceptance.run_dlp_file_pattern_delete_mcp_oauth_acceptance(
            "https://mcp.example.test/fpamcp-v4",
            tmp_path / "login.env",
            tmp_path / "client.json",
        )
    )

    assert result["dlp_file_pattern_delete_tool_surface_complete"] is True
    assert result["tool_count"] == acceptance.EXPECTED_TOOL_COUNT
    assert (
        result["selected_capability_count"]
        == acceptance.EXPECTED_SELECTED_CAPABILITY_COUNT
    )
    assert result["device_tool_invoked"] is False
    assert result["device_write_executed"] is False
    assert result["token_revoked"] is True
    assert session.calls == []


def test_preview_and_execution_use_owner_only_state_and_exact_tools(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    state_file = state_dir / "preview.json"
    session = _Session()
    _patch_oauth(monkeypatch, session)

    preview_result = asyncio.run(
        acceptance.run_dlp_file_pattern_delete_mcp_oauth_acceptance(
            "https://mcp.example.test/fpamcp-v4",
            tmp_path / "login.env",
            tmp_path / "client.json",
            preview_state_file=state_file,
        )
    )
    assert preview_result["dlp_file_pattern_delete_preview_verified"] is True
    assert state_file.stat().st_mode & 0o077 == 0
    assert json.loads(state_file.read_text())["preview_ref"].startswith(
        acceptance.PREFIX
    )

    session = _Session()
    _patch_oauth(monkeypatch, session)
    execute_result = asyncio.run(
        acceptance.run_dlp_file_pattern_delete_mcp_oauth_acceptance(
            "https://mcp.example.test/fpamcp-v4",
            tmp_path / "login.env",
            tmp_path / "client.json",
            execute_preview_state_file=state_file,
        )
    )
    assert execute_result["dlp_file_pattern_delete_execution_verified"] is True
    assert execute_result["device_write_executed"] is True
    assert not state_file.exists()
    assert [name for name, _ in session.calls] == [
        "confirm_v4_dlp_file_pattern_delete",
        "execute_confirmed_v4_dlp_file_pattern_delete",
    ]


def test_validators_reject_identifier_leak_and_unverified_execution() -> None:
    leaked = _preview()
    assert isinstance(leaked["Current State"], dict)
    leaked["Current State"]["pattern_id"] = 1000  # type: ignore[index]
    with pytest.raises(acceptance.DlpFilePatternDeleteMcpOAuthAcceptanceError):
        acceptance._validate_preview(leaked, False)

    failed = _execution()
    failed["verification"] = "unknown"
    with pytest.raises(acceptance.DlpFilePatternDeleteMcpOAuthAcceptanceError):
        acceptance._validate_execution(failed, False)
