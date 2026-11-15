"""MCP boundary for one controlled FortiPAM IPv4 address create action."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_acl_mcp_action import folder_acl_action_principal_from_access_token


V4_ADDRESS_ACTION_FEATURE_ENV = "FORTIPAM_MCP_V4_ADDRESS_ACTION_ENABLED"
V4_ADDRESS_EXECUTION_ENV = "FORTIPAM_MCP_V4_ADDRESS_EXECUTION_ENABLED"
V4_ADDRESS_DELETE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_ADDRESS_DELETE_EXECUTION_ENABLED"
)
V4_ADDRESS_PREVIEW_TOOL = "preview_v4_ipv4_address_create"
V4_ADDRESS_CONFIRM_TOOL = "confirm_v4_ipv4_address_create"
V4_ADDRESS_ACTION_TOOL = "execute_confirmed_v4_ipv4_address_create"
V4_ADDRESS_DELETE_PREVIEW_TOOL = "preview_v4_ipv4_address_delete"
V4_ADDRESS_DELETE_CONFIRM_TOOL = "confirm_v4_ipv4_address_delete"
V4_ADDRESS_DELETE_ACTION_TOOL = "execute_confirmed_v4_ipv4_address_delete"
V4_ADDRESS_ACTION_UNAVAILABLE = "FortiPAM V4 Address action is unavailable."


class V4AddressActionConfigurationError(ValueError):
    """Raised when the Address action host is incomplete or unsafe."""


class V4AddressActionRuntimeError(RuntimeError):
    """Stable non-disclosing Address action failure."""


def load_v4_address_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Address opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ADDRESS_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4AddressActionConfigurationError(
        f"{V4_ADDRESS_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_address_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ADDRESS_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4AddressActionConfigurationError(
        f"{V4_ADDRESS_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_address_delete_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Address recovery dispatch gate."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ADDRESS_DELETE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4AddressActionConfigurationError(
        f"{V4_ADDRESS_DELETE_EXECUTION_ENV} must be exactly true or false."
    )


def address_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning/operation scope as Folder ACL actions."""

    try:
        return folder_acl_action_principal_from_access_token(
            access_token,
            planning_settings,
        )
    except Exception as exc:
        raise V4AddressActionRuntimeError(V4_ADDRESS_ACTION_UNAVAILABLE) from exc


class ProtectedAddressMcpAction:
    """Expose only C/P/E, confirmation, and execution for one IPv4 address."""

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

    def preview(self, name: str, cidr: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    name=name,
                    cidr=cidr,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4AddressActionRuntimeError(V4_ADDRESS_ACTION_UNAVAILABLE) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4AddressActionRuntimeError(V4_ADDRESS_ACTION_UNAVAILABLE) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4AddressActionRuntimeError(V4_ADDRESS_ACTION_UNAVAILABLE)
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
            raise V4AddressActionRuntimeError(V4_ADDRESS_ACTION_UNAVAILABLE) from exc

    def preview_delete(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        if self._delete_workflow is None:
            raise V4AddressActionRuntimeError(V4_ADDRESS_ACTION_UNAVAILABLE)
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.preview(requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4AddressActionRuntimeError(V4_ADDRESS_ACTION_UNAVAILABLE) from exc

    def confirm_delete(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        if self._delete_workflow is None:
            raise V4AddressActionRuntimeError(V4_ADDRESS_ACTION_UNAVAILABLE)
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.confirm(
                    preview_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4AddressActionRuntimeError(V4_ADDRESS_ACTION_UNAVAILABLE) from exc

    def execute_delete(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._delete_execution_enabled or self._delete_workflow is None:
            raise V4AddressActionRuntimeError(V4_ADDRESS_ACTION_UNAVAILABLE)
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.execute(
                    authorization_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4AddressActionRuntimeError(V4_ADDRESS_ACTION_UNAVAILABLE) from exc


def build_v4_address_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedAddressMcpAction:
    """Construct the dedicated IPv4 Address API action host."""

    env = os.environ if environment is None else environment
    try:
        from .address_delete_http_transport import FortiPamAddressDeleteHttpTransport
        from .address_delete_live_workflow import AddressDeleteLiveWorkflow
        from .address_group_ssh_transport import (
            FortiPamAddressGroupSshTransport,
            load_address_group_ssh_transport_config,
        )
        from .address_http_transport import (
            FortiPamAddressHttpTransport,
            load_address_http_transport_config,
        )
        from .address_live_workflow import AddressCreateLiveWorkflow

        config = load_address_http_transport_config(env)
        workflow = AddressCreateLiveWorkflow(FortiPamAddressHttpTransport(config))
        delete_workflow = AddressDeleteLiveWorkflow(
            FortiPamAddressDeleteHttpTransport(
                config,
                FortiPamAddressGroupSshTransport(
                    load_address_group_ssh_transport_config(env)
                ),
            )
        )
    except Exception as exc:
        raise V4AddressActionConfigurationError(
            V4_ADDRESS_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedAddressMcpAction(
        workflow,
        execution_enabled=load_v4_address_execution_feature(env),
        delete_workflow=delete_workflow,
        delete_execution_enabled=load_v4_address_delete_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4AddressActionRuntimeError(V4_ADDRESS_ACTION_UNAVAILABLE) from exc


__all__ = [
    "ProtectedAddressMcpAction",
    "V4_ADDRESS_ACTION_FEATURE_ENV",
    "V4_ADDRESS_ACTION_TOOL",
    "V4_ADDRESS_ACTION_UNAVAILABLE",
    "V4_ADDRESS_CONFIRM_TOOL",
    "V4_ADDRESS_DELETE_ACTION_TOOL",
    "V4_ADDRESS_DELETE_CONFIRM_TOOL",
    "V4_ADDRESS_DELETE_EXECUTION_ENV",
    "V4_ADDRESS_DELETE_PREVIEW_TOOL",
    "V4_ADDRESS_EXECUTION_ENV",
    "V4_ADDRESS_PREVIEW_TOOL",
    "V4AddressActionConfigurationError",
    "V4AddressActionRuntimeError",
    "address_action_principal_from_access_token",
    "build_v4_address_action",
    "load_v4_address_action_feature",
    "load_v4_address_delete_execution_feature",
    "load_v4_address_execution_feature",
]
