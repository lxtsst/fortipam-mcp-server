"""MCP boundary for one controlled FortiPAM Address Group CLI fallback."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_acl_mcp_action import folder_acl_action_principal_from_access_token


V4_ADDRESS_GROUP_ACTION_FEATURE_ENV = "FORTIPAM_MCP_V4_ADDRESS_GROUP_ACTION_ENABLED"
V4_ADDRESS_GROUP_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_ADDRESS_GROUP_EXECUTION_ENABLED"
)
V4_ADDRESS_GROUP_DELETE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_ADDRESS_GROUP_DELETE_EXECUTION_ENABLED"
)
V4_ADDRESS_GROUP_PREVIEW_TOOL = "preview_v4_address_group_create"
V4_ADDRESS_GROUP_CONFIRM_TOOL = "confirm_v4_address_group_create"
V4_ADDRESS_GROUP_ACTION_TOOL = "execute_confirmed_v4_address_group_create"
V4_ADDRESS_GROUP_DELETE_PREVIEW_TOOL = "preview_v4_address_group_delete"
V4_ADDRESS_GROUP_DELETE_CONFIRM_TOOL = "confirm_v4_address_group_delete"
V4_ADDRESS_GROUP_DELETE_ACTION_TOOL = "execute_confirmed_v4_address_group_delete"
V4_ADDRESS_GROUP_ACTION_UNAVAILABLE = "FortiPAM V4 Address Group action is unavailable."


class V4AddressGroupActionConfigurationError(ValueError):
    """Raised when the Address Group action host is incomplete or unsafe."""


class V4AddressGroupActionRuntimeError(RuntimeError):
    """Stable non-disclosing Address Group action failure."""


def load_v4_address_group_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Address Group opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ADDRESS_GROUP_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4AddressGroupActionConfigurationError(
        f"{V4_ADDRESS_GROUP_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_address_group_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ADDRESS_GROUP_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4AddressGroupActionConfigurationError(
        f"{V4_ADDRESS_GROUP_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_address_group_delete_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent destructive final-dispatch gate, default denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ADDRESS_GROUP_DELETE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4AddressGroupActionConfigurationError(
        f"{V4_ADDRESS_GROUP_DELETE_EXECUTION_ENV} must be exactly true or false."
    )


def address_group_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning/operation scope as other C2 writes."""

    try:
        return folder_acl_action_principal_from_access_token(
            access_token,
            planning_settings,
        )
    except Exception as exc:
        raise V4AddressGroupActionRuntimeError(
            V4_ADDRESS_GROUP_ACTION_UNAVAILABLE
        ) from exc


class ProtectedAddressGroupMcpAction:
    """Expose only C/P/E, confirmation, and one CLI fallback execution."""

    def __init__(
        self,
        workflow: Any,
        *,
        execution_enabled: bool = True,
        delete_workflow: Any | None = None,
        delete_execution_enabled: bool = False,
    ) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled
        self._delete_workflow = delete_workflow
        self._delete_execution_enabled = delete_execution_enabled

    def preview(
        self,
        group_name: str,
        member_name: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    group_name=group_name,
                    member_name=member_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4AddressGroupActionRuntimeError(
                V4_ADDRESS_GROUP_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4AddressGroupActionRuntimeError(
                V4_ADDRESS_GROUP_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4AddressGroupActionRuntimeError(
                V4_ADDRESS_GROUP_ACTION_UNAVAILABLE
            )
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.execute(
                    authorization_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4AddressGroupActionRuntimeError(
                V4_ADDRESS_GROUP_ACTION_UNAVAILABLE
            ) from exc

    def preview_delete(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._require_delete_workflow().preview(
                    requester_digest=requester_digest
                ),
            )
        except Exception as exc:
            raise V4AddressGroupActionRuntimeError(
                V4_ADDRESS_GROUP_ACTION_UNAVAILABLE
            ) from exc

    def confirm_delete(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._require_delete_workflow().confirm(
                    preview_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4AddressGroupActionRuntimeError(
                V4_ADDRESS_GROUP_ACTION_UNAVAILABLE
            ) from exc

    def execute_delete(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._delete_execution_enabled:
            raise V4AddressGroupActionRuntimeError(
                V4_ADDRESS_GROUP_ACTION_UNAVAILABLE
            )
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._require_delete_workflow().execute(
                    authorization_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4AddressGroupActionRuntimeError(
                V4_ADDRESS_GROUP_ACTION_UNAVAILABLE
            ) from exc

    def _require_delete_workflow(self) -> Any:
        if self._delete_workflow is None:
            raise V4AddressGroupActionRuntimeError(
                V4_ADDRESS_GROUP_ACTION_UNAVAILABLE
            )
        return self._delete_workflow


def build_v4_address_group_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedAddressGroupMcpAction:
    """Construct the fixed CLI fallback with a separate read-only member check."""

    env = os.environ if environment is None else environment
    try:
        from .address_group_delete_http_transport import (
            FortiPamAddressGroupDeleteHttpTransport,
        )
        from .address_group_delete_live_workflow import (
            AddressGroupDeleteLiveWorkflow,
        )
        from .address_group_live_workflow import AddressGroupCreateLiveWorkflow
        from .address_group_ssh_transport import (
            FortiPamAddressGroupSshTransport,
            load_address_group_ssh_transport_config,
        )
        from .address_http_transport import (
            FortiPamAddressHttpTransport,
            load_address_http_transport_config,
        )

        group_transport = FortiPamAddressGroupSshTransport(
            load_address_group_ssh_transport_config(env)
        )
        address_config = load_address_http_transport_config(env)
        member_transport = FortiPamAddressHttpTransport(address_config)
        workflow = AddressGroupCreateLiveWorkflow(
            group_transport,
            member_transport,
        )
        delete_workflow = AddressGroupDeleteLiveWorkflow(
            FortiPamAddressGroupDeleteHttpTransport(
                address_config,
                group_transport,
                member_transport,
            )
        )
    except Exception as exc:
        raise V4AddressGroupActionConfigurationError(
            V4_ADDRESS_GROUP_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedAddressGroupMcpAction(
        workflow,
        execution_enabled=load_v4_address_group_execution_feature(env),
        delete_workflow=delete_workflow,
        delete_execution_enabled=(
            load_v4_address_group_delete_execution_feature(env)
        ),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4AddressGroupActionRuntimeError(
            V4_ADDRESS_GROUP_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedAddressGroupMcpAction",
    "V4_ADDRESS_GROUP_ACTION_FEATURE_ENV",
    "V4_ADDRESS_GROUP_ACTION_TOOL",
    "V4_ADDRESS_GROUP_ACTION_UNAVAILABLE",
    "V4_ADDRESS_GROUP_CONFIRM_TOOL",
    "V4_ADDRESS_GROUP_DELETE_ACTION_TOOL",
    "V4_ADDRESS_GROUP_DELETE_CONFIRM_TOOL",
    "V4_ADDRESS_GROUP_DELETE_EXECUTION_ENV",
    "V4_ADDRESS_GROUP_DELETE_PREVIEW_TOOL",
    "V4_ADDRESS_GROUP_EXECUTION_ENV",
    "V4_ADDRESS_GROUP_PREVIEW_TOOL",
    "V4AddressGroupActionConfigurationError",
    "V4AddressGroupActionRuntimeError",
    "address_group_action_principal_from_access_token",
    "build_v4_address_group_action",
    "load_v4_address_group_action_feature",
    "load_v4_address_group_delete_execution_feature",
    "load_v4_address_group_execution_feature",
]
