from __future__ import annotations

from fortipam_mcp.apl_update_plan import (
    V4_APL_UPDATE_PLAN_CONTRACT,
    apl_update_plan_requirements,
)


def test_apl_update_plan_is_version_bounded_and_non_executable() -> None:
    result = apl_update_plan_requirements()
    assert result["contract"] == V4_APL_UPDATE_PLAN_CONTRACT
    assert result["action_family"] == "apl.update"
    assert result["source_version"] == "1.9.0"
    assert result["target_version"] == "1.9.1"
    assert result["target_version_validation_required"] is True
    for key in (
        "configuration_ready",
        "execution_authorized",
        "fortipam_contacted",
        "identity_system_contacted",
        "provisioning_effect_applied",
        "authentication_effect_applied",
        "local_state_written",
        "raw_source_content_returned",
    ):
        assert result[key] is False


def test_apl_update_plan_result_returns_fresh_mutable_collections() -> None:
    first = apl_update_plan_requirements()
    second = apl_update_plan_requirements()
    first["documented_requirements"].clear()  # type: ignore[union-attr]
    assert second["documented_requirements"]
