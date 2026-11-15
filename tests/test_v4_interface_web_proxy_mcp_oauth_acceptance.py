from __future__ import annotations

import asyncio
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.v4_interface_web_proxy_mcp_oauth_acceptance import (
    InterfaceWebProxyMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
    run_interface_web_proxy_mcp_oauth_acceptance,
)


def test_private_ip_lab_flag_is_forwarded(monkeypatch) -> None:
    import scripts.v4_interface_web_proxy_mcp_oauth_acceptance as subject

    observed: dict[str, object] = {}

    async def stub(*_args, **kwargs):
        observed.update(kwargs)
        callback = kwargs["tool_session_callback"]

        class Tools:
            tools = [
                type("Tool", (), {"name": name})()
                for name in subject.TOOLS
                    | {f"other_tool_{index}" for index in range(292)}
            ]

        class Session:
            async def list_tools(self):
                return Tools()

        await callback(Session())
        return {
            "oauth_metadata_verified": True,
            "mcp_initialized": True,
            "token_revoked": True,
            "credential_values_returned": False,
        }

    monkeypatch.setattr(subject.oauth, "run_address_mcp_oauth_surface_acceptance", stub)
    result = asyncio.run(
        subject.run_interface_web_proxy_mcp_oauth_acceptance(
            "http://192.0.2.10/mcp",
            Path("login"),
            Path("state"),
            allow_insecure_private_ip_lab=True,
        )
    )

    assert observed["allow_insecure_private_ip_lab"] is True
    assert result["interface_web_proxy_tool_surface_complete"] is True


def _preview() -> dict[str, object]:
    return {
        "contract": "fortipam_v4_interface_explicit_web_proxy_enable_workflow_v1",
        "preview_ref": "interface-web-proxy-preview-opaque",
        "device_write_executed": False,
        "Current State": {
            "selected_interface_explicit_web_proxy": "disable",
            "enabled_explicit_web_proxy_interface_count": 0,
            "interface_reference_returned": False,
            "proxy_port_changed": False,
            "proxy_ca_changed": False,
            "write_transport": "ssh_cli_fallback",
        },
        "Proposed Changes": {
            "operation": "enable_explicit_web_proxy_on_one_existing_interface_via_cli_fallback",
            "configuration_profile": "enable-one-existing-interface-explicit-web-proxy-v1",
            "selected_interface_explicit_web_proxy": "enable",
            "other_interfaces_changed": False,
            "proxy_port_changed": False,
            "proxy_ca_changed": False,
            "vip_or_route_changed": False,
            "secret_or_target_changed": False,
            "rest_write_attempted": False,
        },
        "Expected State": {
            "selected_interface_explicit_web_proxy": "enable",
            "enabled_explicit_web_proxy_interface_count": 1,
            "other_interfaces_changed": False,
            "proxy_port_changed": False,
            "proxy_ca_changed": False,
            "vip_or_route_changed": False,
            "web_proxy_reachability_verified": False,
            "readback_transport": "ssh_cli",
        },
    }


def _execution() -> dict[str, object]:
    return {
        "contract": "fortipam_v4_interface_explicit_web_proxy_enable_execution_v1",
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "compensation": "separate_interface_explicit_web_proxy_disable_action_required",
        "selected_interface_explicit_web_proxy": "enable",
        "enabled_explicit_web_proxy_interface_count": 1,
        "proxy_port_changed": False,
        "proxy_ca_changed": False,
        "vip_or_route_changed": False,
        "secret_or_target_changed": False,
        "web_proxy_reachability_verified": False,
        "raw_cli_returned": False,
    }


def _rollback_preview() -> dict[str, object]:
    return {
        "contract": "fortipam_v4_interface_explicit_web_proxy_rollback_workflow_v1",
        "preview_ref": "interface-web-proxy-rollback-preview-opaque",
        "device_write_executed": False,
        "Current State": {
            "selected_interface_explicit_web_proxy": "enable",
            "enabled_explicit_web_proxy_interface_count": 1,
            "interface_reference_returned": False,
            "proxy_port_changed": False,
            "proxy_ca_changed": False,
            "write_transport": "ssh_cli_fallback",
        },
        "Proposed Changes": {
            "operation": "restore_interface_explicit_web_proxy_pre_action_state_via_cli_fallback",
            "configuration_profile": "disable-one-existing-interface-explicit-web-proxy-v1",
            "selected_interface_explicit_web_proxy": "disable",
            "other_interfaces_changed": False,
            "proxy_port_changed": False,
            "proxy_ca_changed": False,
            "vip_or_route_changed": False,
            "secret_or_target_changed": False,
            "rest_write_attempted": False,
        },
        "Expected State": {
            "pre_action_state_restored": True,
            "selected_interface_explicit_web_proxy": "disable",
            "enabled_explicit_web_proxy_interface_count": 0,
            "other_interfaces_changed": False,
            "proxy_port_changed": False,
            "proxy_ca_changed": False,
            "vip_or_route_changed": False,
            "web_proxy_reachability_verified": False,
            "readback_transport": "ssh_cli",
        },
    }


def _rollback_execution() -> dict[str, object]:
    return {
        "contract": "fortipam_v4_interface_explicit_web_proxy_rollback_execution_v1",
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "pre_action_state_restored": True,
        "selected_interface_explicit_web_proxy": "disable",
        "enabled_explicit_web_proxy_interface_count": 0,
        "proxy_port_changed": False,
        "proxy_ca_changed": False,
        "vip_or_route_changed": False,
        "secret_or_target_changed": False,
        "web_proxy_reachability_verified": False,
        "raw_cli_returned": False,
    }


def test_preview_state_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"

    _write_preview_state(path, "interface-web-proxy-preview-opaque")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "interface-web-proxy-preview-opaque"
    with pytest.raises(InterfaceWebProxyMcpOAuthAcceptanceError):
        _write_preview_state(path, "invalid")


def test_preview_requires_one_disabled_interface_and_no_reachability_claim() -> None:
    projection = _preview()
    _validate_preview(projection, False)
    projection["Expected State"]["web_proxy_reachability_verified"] = True  # type: ignore[index]
    with pytest.raises(InterfaceWebProxyMcpOAuthAcceptanceError):
        _validate_preview(projection, False)


def test_execution_requires_categorical_single_enable_without_side_effect_claim() -> None:
    result = _execution()
    _validate_execution(result, False)
    result["proxy_port_changed"] = True
    with pytest.raises(InterfaceWebProxyMcpOAuthAcceptanceError):
        _validate_execution(result, False)


def test_rollback_preview_requires_one_enabled_interface_and_fixed_disable_only() -> None:
    projection = _rollback_preview()
    _validate_preview(projection, False, rollback=True)
    projection["Current State"]["selected_interface_explicit_web_proxy"] = "disable"  # type: ignore[index]
    with pytest.raises(InterfaceWebProxyMcpOAuthAcceptanceError):
        _validate_preview(projection, False, rollback=True)


def test_rollback_preview_reference_is_direction_bound(tmp_path) -> None:
    directory = tmp_path / "rollback-state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    prefix = "interface-web-proxy-rollback-preview-"
    _write_preview_state(path, f"{prefix}opaque", prefix=prefix)
    assert _read_preview_ref(path, prefix=prefix) == f"{prefix}opaque"
    with pytest.raises(InterfaceWebProxyMcpOAuthAcceptanceError):
        _read_preview_ref(path)


def test_rollback_execution_selects_only_fixed_rollback_tools(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    directory = tmp_path / "rollback-execution"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    state = directory / "preview.json"
    prefix = "interface-web-proxy-rollback-preview-"
    _write_preview_state(state, f"{prefix}opaque", prefix=prefix)

    calls: list[tuple[str, dict[str, object]]] = []
    required = {
        "preview_v4_interface_explicit_web_proxy_enable",
        "confirm_v4_interface_explicit_web_proxy_enable",
        "execute_confirmed_v4_interface_explicit_web_proxy_enable",
        "preview_v4_interface_explicit_web_proxy_rollback",
        "confirm_v4_interface_explicit_web_proxy_rollback",
        "execute_confirmed_v4_interface_explicit_web_proxy_rollback",
    }
    names = required | {f"other_tool_{index}" for index in range(292)}

    class FakeSession:
        async def list_tools(self):
            return SimpleNamespace(
                tools=[SimpleNamespace(name=name) for name in sorted(names)]
            )

        async def call_tool(self, name: str, arguments: dict[str, object]):
            calls.append((name, arguments))
            if name == "confirm_v4_interface_explicit_web_proxy_rollback":
                return SimpleNamespace(
                    is_error=False,
                    structured_content={
                        "contract": "fortipam_v4_interface_explicit_web_proxy_rollback_workflow_v1",
                        "authorization_ref": "interface-web-proxy-rollback-authorized-opaque",
                        "confirmation": "recorded",
                        "execution": "authorized_once",
                        "device_write_executed": False,
                    },
                )
            if name == "execute_confirmed_v4_interface_explicit_web_proxy_rollback":
                return SimpleNamespace(
                    is_error=False,
                    structured_content=_rollback_execution(),
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
        "scripts.v4_interface_web_proxy_mcp_oauth_acceptance.oauth.run_address_mcp_oauth_surface_acceptance",
        fake_common,
    )
    result = asyncio.run(
        run_interface_web_proxy_mcp_oauth_acceptance(
            "https://fpamcp.example.test/fpamcp-v4",
            tmp_path / "login.env",
            tmp_path / "client.json",
            execute_preview_state_file=state,
            rollback=True,
            expected_tool_count=298,
        )
    )

    assert calls == [
        (
            "confirm_v4_interface_explicit_web_proxy_rollback",
            {"preview_ref": "interface-web-proxy-rollback-preview-opaque"},
        ),
        (
            "execute_confirmed_v4_interface_explicit_web_proxy_rollback",
            {"authorization_ref": "interface-web-proxy-rollback-authorized-opaque"},
        ),
    ]
    assert not state.exists()
    assert result["interface_web_proxy_direction"] == "rollback"
    assert result["exact_tool_count_verified"] is True
    assert result["device_write_executed"] is True


@pytest.mark.parametrize("missing_required, expected_count", [(False, None), (True, None), (False, 298)])
def test_tool_surface_growth_does_not_hide_missing_interface_tools(
    monkeypatch, missing_required, expected_count,
) -> None:
    import scripts.v4_interface_web_proxy_mcp_oauth_acceptance as subject

    names = subject.TOOLS | {f"unrelated_{i}" for i in range(300)}
    if missing_required:
        names = names - {subject.ROLLBACK_TOOLS[2]}

    class Session:
        async def list_tools(self):
            return SimpleNamespace(tools=[SimpleNamespace(name=n) for n in names])

        async def call_tool(self, *args):
            pytest.fail("Surface qualification must not call a device tool")

    async def common(*args, **kwargs):
        assert kwargs["lab_connect_host"] == "127.0.0.1"
        assert kwargs["lab_connect_port"] == 8000
        assert kwargs["allow_loopback_tunnel"] is True
        await kwargs["tool_session_callback"](Session())
        return dict(oauth_metadata_verified=True, mcp_initialized=True,
                    token_revoked=True, credential_values_returned=False)

    monkeypatch.setattr(subject.oauth, "run_address_mcp_oauth_surface_acceptance", common)
    def run():
        return asyncio.run(subject.run_interface_web_proxy_mcp_oauth_acceptance(
            "https://example.test/mcp", Path("login"), Path("client"),
            expected_tool_count=expected_count, lab_connect_host="127.0.0.1",
            lab_connect_port=8000, allow_loopback_tunnel=True,
        ))
    if missing_required or expected_count is not None:
        with pytest.raises(InterfaceWebProxyMcpOAuthAcceptanceError):
            run()
    else:
        result = run()
        assert result["interface_web_proxy_tool_surface_complete"] is True
        assert result["exact_tool_count_verified"] is False
        assert result["device_tool_invoked"] is False
