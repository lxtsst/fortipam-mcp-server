from __future__ import annotations

import pytest

from fortipam_mcp.mcp_smoke import (
    EXPECTED_PROMPTS,
    EXPECTED_RESOURCES,
    EXPECTED_TOOLS,
    LAB_ADMIN_TOOLS,
    LAB_EXPECTED_TOOLS,
    assert_expected_native_content,
    assert_expected_tools,
)


def test_expected_tool_set_is_accepted() -> None:
    assert_expected_tools(set(EXPECTED_TOOLS))
    assert len(EXPECTED_TOOLS) == 28


def test_lab_tool_set_is_accepted_only_with_explicit_contract() -> None:
    assert_expected_tools(set(LAB_EXPECTED_TOOLS), LAB_EXPECTED_TOOLS)
    assert len(LAB_EXPECTED_TOOLS) == 34
    assert set(EXPECTED_TOOLS).isdisjoint(LAB_ADMIN_TOOLS)


def test_expected_native_content_is_accepted() -> None:
    assert_expected_native_content(set(EXPECTED_RESOURCES), set(EXPECTED_PROMPTS))


def test_native_content_drift_fails_smoke_contract() -> None:
    with pytest.raises(RuntimeError):
        assert_expected_native_content(
            set(EXPECTED_RESOURCES) | {"fortipam://v2.1/unexpected"},
            set(EXPECTED_PROMPTS),
        )
    with pytest.raises(RuntimeError):
        assert_expected_native_content(
            set(EXPECTED_RESOURCES),
            set(EXPECTED_PROMPTS) - {"fortipam_ha_diagnostics_triage"},
        )


def test_missing_live_tool_fails_smoke_contract() -> None:
    with pytest.raises(RuntimeError):
        assert_expected_tools(set(EXPECTED_TOOLS) - {"get_approval_profile_summary"})


def test_unexpected_tool_fails_smoke_contract() -> None:
    with pytest.raises(RuntimeError):
        assert_expected_tools(set(EXPECTED_TOOLS) | {"unexpected_tool"})


def test_expected_tool_contract_contains_nine_fixed_reads_and_aggregate() -> None:
    assert {
        "get_overall_health_summary",
        "get_system_status_summary",
        "get_system_global_summary",
        "get_approval_profile_summary",
        "get_fortianalyzer_delivery_posture_summary",
        "get_license_support_posture_summary",
        "get_ha_configuration_posture_summary",
        "get_recording_storage_health_summary",
        "get_password_changer_configuration_posture_summary",
        "get_ems_connection_posture_summary",
    }.issubset(EXPECTED_TOOLS)


def test_expected_tool_contract_contains_operational_knowledge_tools() -> None:
    assert {
        "get_scenario_catalog_status",
        "search_operational_scenarios",
        "get_operational_scenario",
    }.issubset(EXPECTED_TOOLS)


def test_expected_tool_contract_contains_lab_only_admin_workflow() -> None:
    assert {
        "preview_v31_lab_public_folder",
        "preview_v31_lab_target",
        "preview_v31_lab_secret_metadata",
        "preview_v31_lab_local_user",
        "preview_v31_lab_folder_access_assignment",
        "execute_confirmed_v31_lab_operation",
    } == set(LAB_ADMIN_TOOLS)


def test_stdio_smoke_child_can_import_from_explicit_install_path(tmp_path, monkeypatch):
    import subprocess
    import sys
    from fortipam_mcp import mcp_smoke

    install_root = tmp_path / "installed"
    install_root.mkdir()
    (install_root / "isolated_smoke_marker.py").write_text("VALUE = 'installed-package'\n")
    monkeypatch.setenv("PYTHONPATH", str(install_root))
    monkeypatch.setenv("UNRELATED_PRIVATE_SETTING", "not-forwarded")
    monkeypatch.chdir(tmp_path)

    class ChildVerified(Exception):
        pass

    def inspect_child(parameters, *, errlog):
        assert "UNRELATED_PRIVATE_SETTING" not in parameters.env
        child = subprocess.run(
            [parameters.command, *parameters.args], env=parameters.env,
            capture_output=True, text=True, check=True,
        )
        assert child.stdout.strip() == "installed-package"
        raise ChildVerified

    monkeypatch.setattr(mcp_smoke, "stdio_client", inspect_child)
    with pytest.raises(ChildVerified):
        mcp_smoke.run_smoke([
            sys.executable, "-c",
            "from isolated_smoke_marker import VALUE; print(VALUE)",
        ])
