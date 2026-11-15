from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

import pytest

from fortipam_mcp.antivirus_profile_mcp_action import (
    V4_ANTIVIRUS_PROFILE_DELETE_EXECUTION_ENV,
    V4AntivirusProfileActionConfigurationError,
    load_v4_antivirus_profile_delete_execution_feature,
)
from fortipam_mcp.character_set_mcp_action import (
    ProtectedCharacterSetMcpAction,
    V4_CHARACTER_SET_EXECUTION_ENV,
    V4CharacterSetActionConfigurationError,
    V4CharacterSetActionRuntimeError,
    load_v4_character_set_execution_feature,
)
from fortipam_mcp.password_policy_mcp_action import (
    ProtectedPasswordPolicyMcpAction,
    V4_PASSWORD_POLICY_EXECUTION_ENV,
    V4PasswordPolicyActionConfigurationError,
    V4PasswordPolicyActionRuntimeError,
    load_v4_password_policy_execution_feature,
)
from fortipam_mcp.recording_policy_mcp_action import (
    ProtectedRecordingPolicyMcpAction,
    V4_RECORDING_POLICY_EXECUTION_ENV,
    V4RecordingPolicyActionConfigurationError,
    V4RecordingPolicyActionRuntimeError,
    load_v4_recording_policy_execution_feature,
)
from fortipam_mcp.rdp_event_filter_mcp_action import (
    V4_RDP_EVENT_FILTER_DELETE_EXECUTION_ENV,
    V4RdpEventFilterActionConfigurationError,
    load_v4_rdp_event_filter_delete_execution_feature,
)
from fortipam_mcp.ssh_filter_mcp_action import (
    V4_SSH_FILTER_DELETE_EXECUTION_ENV,
    V4SshFilterActionConfigurationError,
    load_v4_ssh_filter_delete_execution_feature,
)
from fortipam_mcp.secret_metadata_mcp_action import (
    ProtectedSecretMetadataMcpAction,
    V4_SECRET_METADATA_EXECUTION_ENV,
    V4SecretMetadataActionConfigurationError,
    V4SecretMetadataActionRuntimeError,
    load_v4_secret_metadata_execution_feature,
)
from fortipam_mcp.secret_policy_mcp_action import (
    ProtectedSecretPolicyMcpAction,
    V4_SECRET_POLICY_EXECUTION_ENV,
    V4_SECRET_POLICY_UPDATE_EXECUTION_ENV,
    V4SecretPolicyActionConfigurationError,
    V4SecretPolicyActionRuntimeError,
    load_v4_secret_policy_execution_feature,
    load_v4_secret_policy_update_execution_feature,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from fortipam_mcp.windows_app_filter_mcp_action import (
    ProtectedWindowsAppFilterMcpAction,
    V4_WINDOWS_APP_FILTER_DELETE_EXECUTION_ENV,
    V4_WINDOWS_APP_FILTER_EXECUTION_ENV,
    V4WindowsAppFilterActionConfigurationError,
    V4WindowsAppFilterActionRuntimeError,
    load_v4_windows_app_filter_execution_feature,
    load_v4_windows_app_filter_delete_execution_feature,
)
from test_v4_m3 import _requester


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        return {"preview_ref": "remaining-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        return {"authorization_ref": "remaining-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        return {"outcome": "succeeded"}


Loader = Callable[[Mapping[str, str] | None], bool]


@pytest.mark.parametrize(
    ("loader", "variable", "configuration_error"),
    (
        (
            load_v4_antivirus_profile_delete_execution_feature,
            V4_ANTIVIRUS_PROFILE_DELETE_EXECUTION_ENV,
            V4AntivirusProfileActionConfigurationError,
        ),
        (
            load_v4_rdp_event_filter_delete_execution_feature,
            V4_RDP_EVENT_FILTER_DELETE_EXECUTION_ENV,
            V4RdpEventFilterActionConfigurationError,
        ),
        (
            load_v4_ssh_filter_delete_execution_feature,
            V4_SSH_FILTER_DELETE_EXECUTION_ENV,
            V4SshFilterActionConfigurationError,
        ),
        (load_v4_character_set_execution_feature, V4_CHARACTER_SET_EXECUTION_ENV, V4CharacterSetActionConfigurationError),
        (load_v4_password_policy_execution_feature, V4_PASSWORD_POLICY_EXECUTION_ENV, V4PasswordPolicyActionConfigurationError),
        (load_v4_recording_policy_execution_feature, V4_RECORDING_POLICY_EXECUTION_ENV, V4RecordingPolicyActionConfigurationError),
        (load_v4_secret_metadata_execution_feature, V4_SECRET_METADATA_EXECUTION_ENV, V4SecretMetadataActionConfigurationError),
        (load_v4_secret_policy_execution_feature, V4_SECRET_POLICY_EXECUTION_ENV, V4SecretPolicyActionConfigurationError),
        (load_v4_secret_policy_update_execution_feature, V4_SECRET_POLICY_UPDATE_EXECUTION_ENV, V4SecretPolicyActionConfigurationError),
        (load_v4_windows_app_filter_execution_feature, V4_WINDOWS_APP_FILTER_EXECUTION_ENV, V4WindowsAppFilterActionConfigurationError),
        (load_v4_windows_app_filter_delete_execution_feature, V4_WINDOWS_APP_FILTER_DELETE_EXECUTION_ENV, V4WindowsAppFilterActionConfigurationError),
    ),
)
def test_remaining_execution_gates_default_false_and_parse_exactly(
    loader: Loader,
    variable: str,
    configuration_error: type[ValueError],
) -> None:
    assert loader({}) is False
    assert loader({variable: "false"}) is False
    assert loader({variable: "true"}) is True
    with pytest.raises(configuration_error, match="exactly true or false"):
        loader({variable: "TRUE"})


@pytest.mark.parametrize(
    ("action", "preview_args", "runtime_error"),
    (
        (ProtectedCharacterSetMcpAction(_Workflow(), execution_enabled=False), ("mcp-v4-charset-01",), V4CharacterSetActionRuntimeError),
        (ProtectedPasswordPolicyMcpAction(_Workflow(), execution_enabled=False), ("mcp-v4-password-policy-01",), V4PasswordPolicyActionRuntimeError),
        (ProtectedRecordingPolicyMcpAction(_Workflow(), execution_enabled=False), ("mcp-v4-recording-policy-01",), V4RecordingPolicyActionRuntimeError),
        (ProtectedSecretMetadataMcpAction(_Workflow(), execution_enabled=False), ("Public/mcp-v4-folder-01", "mcp-v4-secret-01", "Unix Account (SSH Password)"), V4SecretMetadataActionRuntimeError),
        (ProtectedWindowsAppFilterMcpAction(_Workflow(), execution_enabled=False), ("mcp-v4-windows-filter-01",), V4WindowsAppFilterActionRuntimeError),
    ),
)
def test_remaining_execution_gates_deny_after_confirmation_without_dispatch(
    action: Any,
    preview_args: tuple[object, ...],
    runtime_error: type[RuntimeError],
) -> None:
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    preview = action.preview(*preview_args, principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    with pytest.raises(runtime_error):
        action.execute(str(confirmation["authorization_ref"]), principal)
    assert action._workflow.calls == ["preview", "confirm"]


def test_secret_policy_create_and_update_gates_are_independent() -> None:
    create_workflow = _Workflow()
    update_workflow = _Workflow()
    action = ProtectedSecretPolicyMcpAction(
        create_workflow,
        update_workflow=update_workflow,
        execution_enabled=False,
        update_execution_enabled=False,
    )
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("mcp-v4-secret-policy-01", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    with pytest.raises(V4SecretPolicyActionRuntimeError):
        action.execute(str(confirmation["authorization_ref"]), principal)

    update_preview = action.preview_update("mcp-v4-secret-policy-01", principal)
    update_confirmation = action.confirm_update(
        str(update_preview["preview_ref"]),
        principal,
    )
    with pytest.raises(V4SecretPolicyActionRuntimeError):
        action.execute_update(str(update_confirmation["authorization_ref"]), principal)

    assert create_workflow.calls == ["preview", "confirm"]
    assert update_workflow.calls == ["preview", "confirm"]
