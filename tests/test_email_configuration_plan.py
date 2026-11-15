from __future__ import annotations

import pytest

from fortipam_mcp.email_configuration_plan import (
    V4_EMAIL_ALERT_BUILD_CONTRACT,
    V4_EMAIL_ALERT_PLAN_CONTRACT,
    V4_SYSTEM_EMAIL_BUILD_CONTRACT,
    V4_SYSTEM_EMAIL_PLAN_CONTRACT,
    build_email_alert_plan,
    build_system_email_plan,
    email_alert_plan_requirements,
    system_email_plan_requirements,
)


def test_system_email_plan_is_value_free_and_non_executable() -> None:
    result = system_email_plan_requirements()

    assert result["contract"] == V4_SYSTEM_EMAIL_PLAN_CONTRACT
    assert result["action_family"] == "system-email.configure"
    assert result["target_version"] == "1.9.1"
    assert result["planning_status"] == "requirements_only"
    assert result["configuration_ready"] is False
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False
    assert result["mail_service_contacted"] is False
    assert result["local_state_written"] is False
    assert result["protected_material_accepted"] is False
    assert result["raw_source_content_returned"] is False
    assert set(result["blocked_operations"]) == {
        "device_state_read",
        "mail_endpoint_or_port_input",
        "username_or_password_input_or_output",
        "sender_reply_to_or_domain_input",
        "certificate_input_or_output",
        "smtp_or_imap_connection",
        "test_email_delivery",
        "configuration_write",
        "execution_authorization",
    }


def test_email_alert_plan_is_value_free_and_non_executable() -> None:
    result = email_alert_plan_requirements()

    assert result["contract"] == V4_EMAIL_ALERT_PLAN_CONTRACT
    assert result["action_family"] == "email-alert.configure"
    assert result["target_version"] == "1.9.1"
    assert result["planning_status"] == "requirements_only"
    assert result["configuration_ready"] is False
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False
    assert result["mail_service_contacted"] is False
    assert result["local_state_written"] is False
    assert result["protected_material_accepted"] is False
    assert result["raw_source_content_returned"] is False
    assert set(result["blocked_operations"]) == {
        "device_state_read",
        "sender_or_recipient_input",
        "alert_category_or_threshold_input",
        "mail_service_configuration",
        "email_notification_enablement",
        "test_or_live_email_delivery",
        "configuration_write",
        "execution_authorization",
    }


def test_email_plan_results_return_fresh_mutable_collections() -> None:
    first_system = system_email_plan_requirements()
    second_system = system_email_plan_requirements()
    first_alert = email_alert_plan_requirements()
    second_alert = email_alert_plan_requirements()

    first_system["documented_requirements"].clear()  # type: ignore[union-attr]
    first_alert["project_acceptance_requirements"].clear()  # type: ignore[union-attr]

    assert second_system["documented_requirements"]
    assert second_alert["project_acceptance_requirements"]


def _build_system(**overrides: bool) -> dict[str, object]:
    evidence = {
        "mail_scopes_separated": True,
        "nonproduction_service_approved": True,
        "network_dependencies_verified": True,
        "tls_trust_verified": True,
        "credential_custody_ready": True,
        "sender_relay_policy_verified": True,
        "delivery_test_separately_gated": True,
        "redacted_readback_defined": True,
        "failure_rollback_approved": True,
    }
    evidence.update(overrides)
    return build_system_email_plan(**evidence)


def _build_alert(**overrides: bool) -> dict[str, object]:
    evidence = {
        "categories_thresholds_approved": True,
        "nonproduction_recipients_approved": True,
        "content_identity_exposure_reviewed": True,
        "mail_dependency_verified": True,
        "rate_loop_controls_verified": True,
        "notification_delivery_separately_gated": True,
        "redacted_readback_defined": True,
        "failure_rollback_approved": True,
    }
    evidence.update(overrides)
    return build_email_alert_plan(**evidence)


def test_system_email_builder_is_categorical_and_non_executing() -> None:
    result = _build_system(tls_trust_verified=False)
    assert result["contract"] == V4_SYSTEM_EMAIL_BUILD_CONTRACT
    assert result["missing_requirements"] == ["tls_trust_verified"]
    assert result["plan_ready"] is False
    assert result["mail_service_state_observed"] is False
    assert result["configuration_execution_ready"] is False
    assert result["execution_authorized"] is False


def test_email_alert_builder_is_categorical_and_non_executing() -> None:
    result = _build_alert(rate_loop_controls_verified=False)
    assert result["contract"] == V4_EMAIL_ALERT_BUILD_CONTRACT
    assert result["missing_requirements"] == ["rate_loop_controls_verified"]
    assert result["plan_ready"] is False
    assert result["mail_service_contacted"] is False
    assert result["configuration_execution_ready"] is False
    assert result["execution_authorized"] is False


def test_email_builders_complete_plans_still_have_no_execution_authority() -> None:
    for result in (_build_system(), _build_alert()):
        assert result["planning_status"] == "ready_for_operator_review"
        assert result["plan_ready"] is True
        assert result["configuration_execution_ready"] is False
        assert result["execution_authorized"] is False


@pytest.mark.parametrize("builder", [_build_system, _build_alert])
def test_email_builders_reject_non_boolean_evidence(builder: object) -> None:
    callable_builder = builder  # keep the parametrized callable explicit for mypy
    with pytest.raises(ValueError, match="must be boolean"):
        callable_builder(redacted_readback_defined=1)  # type: ignore[operator,call-arg]
    V4_SYSTEM_EMAIL_BUILD_CONTRACT,
    build_email_alert_plan,
    build_system_email_plan,
