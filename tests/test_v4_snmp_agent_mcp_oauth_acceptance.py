from __future__ import annotations

import asyncio
import stat
from types import SimpleNamespace

import pytest

from scripts.v4_snmp_agent_mcp_oauth_acceptance import (
    SnmpAgentMcpOAuthAcceptanceError,
    _read,
    _validate_preview,
    _write,
    run_snmp_agent_mcp_oauth_acceptance,
)


def test_preview_reference_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    _write(path, "snmp-agent-preview-opaque")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read(path) == "snmp-agent-preview-opaque"
    with pytest.raises(SnmpAgentMcpOAuthAcceptanceError):
        _write(path, "snmp-agent-preview-other")


def test_preview_requires_disabled_baseline_and_fixed_enable_only() -> None:
    unchanged = {
        "snmp_community_configuration_changed": False,
        "snmpv3_user_configuration_changed": False,
        "notification_host_configuration_changed": False,
        "interface_administrative_access_changed": False,
    }
    projection = {
        "contract": "fortipam_v4_snmp_agent_enable_workflow_v1",
        "preview_ref": "snmp-agent-preview-opaque", "device_write_executed": False,
        "Current State": {"snmp_agent_status": "disable", "write_transport": "strict_api_preflight_ssh_cli_fallback", **unchanged},
        "Proposed Changes": {"operation": "enable_preconfigured_snmp_agent_via_cli_fallback", "configuration_profile": "enable-preconfigured-system-snmp-agent-v1", "snmp_agent_status": "enable", **unchanged, "snmp_query_or_trap_sent": False, "rest_write_attempted": False},
        "Expected State": {"snmp_agent_status": "enable", **unchanged, "snmp_query_or_trap_effect_verified": False, "readback_transport": "strict_api_and_ssh_cli"},
    }
    _validate_preview(projection, False)
    projection["Proposed Changes"]["snmp_query_or_trap_sent"] = True
    with pytest.raises(SnmpAgentMcpOAuthAcceptanceError):
        _validate_preview(projection, False)


def test_rollback_preview_requires_enabled_baseline_and_fixed_disable_only() -> None:
    unchanged = {
        "snmp_community_configuration_changed": False,
        "snmpv3_user_configuration_changed": False,
        "notification_host_configuration_changed": False,
        "interface_administrative_access_changed": False,
    }
    projection = {
        "contract": "fortipam_v4_snmp_agent_rollback_workflow_v1",
        "preview_ref": "snmp-agent-rollback-preview-opaque",
        "device_write_executed": False,
        "Current State": {
            "snmp_agent_status": "enable",
            "write_transport": "strict_api_preflight_ssh_cli_fallback",
            **unchanged,
        },
        "Proposed Changes": {
            "operation": "restore_preconfigured_snmp_agent_disabled_state_via_cli_fallback",
            "configuration_profile": "disable-preconfigured-system-snmp-agent-v1",
            "snmp_agent_status": "disable",
            **unchanged,
            "snmp_query_or_trap_sent": False,
            "rest_write_attempted": False,
        },
        "Expected State": {
            "pre_action_state_restored": True,
            "snmp_agent_status": "disable",
            **unchanged,
            "snmp_query_or_trap_effect_verified": False,
            "readback_transport": "strict_api_and_ssh_cli",
        },
    }
    _validate_preview(projection, False, rollback=True)
    projection["Current State"]["snmp_agent_status"] = "disable"
    with pytest.raises(SnmpAgentMcpOAuthAcceptanceError):
        _validate_preview(projection, False, rollback=True)


def test_rollback_preview_reference_is_direction_bound(tmp_path) -> None:
    directory = tmp_path / "rollback-state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    prefix = "snmp-agent-rollback-preview-"
    _write(path, f"{prefix}opaque", prefix=prefix)
    assert _read(path, prefix=prefix) == f"{prefix}opaque"
    with pytest.raises(SnmpAgentMcpOAuthAcceptanceError):
        _read(path)


def test_private_ip_lab_exception_is_passed_to_common_oauth_helper(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    observed: dict[str, object] = {}

    async def fake_common(*args, **kwargs):
        observed.update(kwargs)
        return {
            "oauth_metadata_verified": True,
            "mcp_initialized": True,
            "token_revoked": True,
            "credential_values_returned": False,
        }

    monkeypatch.setattr(
        "scripts.v4_snmp_agent_mcp_oauth_acceptance.oauth.run_address_mcp_oauth_surface_acceptance",
        fake_common,
    )
    result = asyncio.run(
        run_snmp_agent_mcp_oauth_acceptance(
            "http://192.0.2.10/fpamcp-v4-b98",
            tmp_path / "login.env",
            tmp_path / "client.json",
            allow_insecure_private_ip_lab=True,
        )
    )
    assert observed["allow_insecure_private_ip_lab"] is True
    assert result["device_write_executed"] is False


def test_rollback_execution_selects_only_fixed_rollback_tools(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    directory = tmp_path / "rollback-execution"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    state = directory / "preview.json"
    prefix = "snmp-agent-rollback-preview-"
    _write(state, f"{prefix}opaque", prefix=prefix)

    calls: list[tuple[str, dict[str, object]]] = []
    required = {
        "preview_v4_snmp_agent_enable",
        "confirm_v4_snmp_agent_enable",
        "execute_confirmed_v4_snmp_agent_enable",
        "preview_v4_snmp_agent_rollback",
        "confirm_v4_snmp_agent_rollback",
        "execute_confirmed_v4_snmp_agent_rollback",
    }
    names = required | {f"other_tool_{index}" for index in range(292)}

    class FakeSession:
        async def list_tools(self):
            return SimpleNamespace(
                tools=[SimpleNamespace(name=name) for name in sorted(names)]
            )

        async def call_tool(self, name: str, arguments: dict[str, object]):
            calls.append((name, arguments))
            if name == "confirm_v4_snmp_agent_rollback":
                return SimpleNamespace(
                    is_error=False,
                    structured_content={
                        "contract": "fortipam_v4_snmp_agent_rollback_workflow_v1",
                        "authorization_ref": "snmp-agent-rollback-authorized-opaque",
                        "confirmation": "recorded",
                        "execution": "authorized_once",
                        "device_write_executed": False,
                    },
                )
            if name == "execute_confirmed_v4_snmp_agent_rollback":
                return SimpleNamespace(
                    is_error=False,
                    structured_content={
                        "contract": "fortipam_v4_snmp_agent_rollback_execution_v1",
                        "outcome": "succeeded",
                        "verification": "verified",
                        "idempotent_replay": False,
                        "pre_action_state_restored": True,
                        "snmp_agent_status": "disable",
                        "snmp_community_configuration_changed": False,
                        "snmpv3_user_configuration_changed": False,
                        "notification_host_configuration_changed": False,
                        "interface_administrative_access_changed": False,
                        "snmp_query_or_trap_effect_verified": False,
                        "raw_cli_returned": False,
                    },
                )
            raise AssertionError(name)

    async def fake_common(*args, **kwargs):
        await kwargs["tool_session_callback"](FakeSession())
        return {
            "oauth_metadata_verified": True,
            "mcp_initialized": True,
            "token_revoked": True,
            "credential_values_returned": False,
        }

    monkeypatch.setattr(
        "scripts.v4_snmp_agent_mcp_oauth_acceptance.oauth.run_address_mcp_oauth_surface_acceptance",
        fake_common,
    )
    result = asyncio.run(
        run_snmp_agent_mcp_oauth_acceptance(
            "https://fpamcp.example.test/fpamcp-v4",
            tmp_path / "login.env",
            tmp_path / "client.json",
            execute_preview_state_file=state,
            rollback=True,
        )
    )

    assert calls == [
        (
            "confirm_v4_snmp_agent_rollback",
            {"preview_ref": "snmp-agent-rollback-preview-opaque"},
        ),
        (
            "execute_confirmed_v4_snmp_agent_rollback",
            {"authorization_ref": "snmp-agent-rollback-authorized-opaque"},
        ),
    ]
    assert not state.exists()
    assert result["snmp_agent_direction"] == "rollback"
    assert result["exact_tool_count_verified"] is True
    assert result["device_write_executed"] is True
