"""Default-off OAuth/MCP candidate for one privately bound subscription cycle."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from .secret_event_subscription_contract import (
    Operation, SecretEventSubscriptionBinding, validate_subscription_email_binding,
)
from .secret_event_subscription_http_transport import (
    FortiPamSecretEventSubscriptionHttpTransport, _private_bytes,
)
from .secret_event_subscription_live_workflow import SecretEventSubscriptionLiveWorkflow
from .secret_event_subscription_requester_session import SecretEventSubscriptionRequesterClient
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config
from .v4_plan_runtime import V4PlanningPrincipal

PREFIX = "FORTIPAM_MCP_V4_SECRET_EVENT_SUBSCRIPTION_700_"
BINDING_CONTRACT = "fortipam_v4_secret_event_subscription_700_private_binding_v1"
RECIPIENT_CONTRACT = "fortipam_v4_secret_event_subscription_700_private_recipient_v1"
_UNAVAILABLE = "FortiPAM V4 Secret event subscription action is unavailable."


class SecretEventSubscriptionMcpAction:
    def __init__(self, workflow: SecretEventSubscriptionLiveWorkflow, *, execution_enabled: bool) -> None:
        self._workflow, self._execution_enabled = workflow, execution_enabled

    def preview(self, principal: Any) -> dict[str, object]:
        try:
            return self._workflow.preview(requester_digest=_requester(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        try:
            return self._workflow.confirm(preview_ref, requester_digest=_requester(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if self._execution_enabled is not True:
            raise RuntimeError(_UNAVAILABLE)
        try:
            return self._workflow.execute(authorization_ref, requester_digest=_requester(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None


@dataclass(frozen=True, slots=True, repr=False)
class SecretEventSubscriptionMcpCandidate:
    subscribe: SecretEventSubscriptionMcpAction
    restore: SecretEventSubscriptionMcpAction

    def __post_init__(self) -> None:
        if (type(self.subscribe) is not SecretEventSubscriptionMcpAction
                or type(self.restore) is not SecretEventSubscriptionMcpAction
                or self.subscribe._workflow._operation != "subscribe"
                or self.restore._workflow._operation != "restore"
                or self.subscribe._workflow._transport._binding != self.restore._workflow._transport._binding
                or self.restore._workflow._transport._subscribe_claim != self.subscribe._workflow._transport._claim
                or self.restore._workflow._transport._binding_digest != self.subscribe._workflow._transport._binding_digest
                or self.subscribe._workflow._transport._key != self.restore._workflow._transport._key):
            raise ValueError(_UNAVAILABLE)


def build_secret_event_subscription_candidate(
    environment: Mapping[str, str],
) -> SecretEventSubscriptionMcpCandidate | None:
    enabled = environment.get(PREFIX + "ENABLED", "false")
    gate = environment.get(PREFIX + "EXECUTION_ENABLED", "false")
    if enabled not in {"true", "false"} or gate not in {"true", "false"}:
        raise ValueError(_UNAVAILABLE)
    if enabled == "false":
        if gate == "true":
            raise ValueError(_UNAVAILABLE)
        return None
    try:
        profile = environment.get(PREFIX + "AUTHENTICATION_PROFILE", "bearer")
        if profile not in {"bearer", "bp005-requester-session"}:
            raise ValueError
        binding = _load_binding(_path(environment, "BINDING_FILE"))
        email_profile = environment.get(PREFIX + "EMAIL_PROFILE", "unset")
        if email_profile not in {"unset", "bound-lab-recipient"}:
            raise ValueError
        if email_profile == "bound-lab-recipient":
            if profile != "bp005-requester-session":
                raise ValueError
            expected_email = _load_recipient(_path(environment, "RECIPIENT_BINDING_FILE"), binding)
        else:
            if PREFIX + "RECIPIENT_BINDING_FILE" in environment:
                raise ValueError
            expected_email = ""
        config = load_secret_metadata_http_transport_config(environment)
        key = _path(environment, "AUTHORIZATION_HMAC_KEY_FILE")
        subscribe_claim = _path(environment, "SUBSCRIBE_CLAIM_FILE")
        restore_claim = _path(environment, "RESTORE_CLAIM_FILE")
        requester_client = (SecretEventSubscriptionRequesterClient(
            config, owner_name=binding.owner_name, environment=environment,
        ) if profile == "bp005-requester-session" else None)

        def direction(operation: Operation) -> SecretEventSubscriptionMcpAction:
            options: dict[str, Any] = {}
            if requester_client is not None:
                options["client_factory"] = requester_client
            transport = FortiPamSecretEventSubscriptionHttpTransport(config, binding, operation=operation,
                claim_path=subscribe_claim if operation == "subscribe" else restore_claim,
                subscribe_claim_path=subscribe_claim if operation == "restore" else None,
                hmac_key_file=key, execution_enabled=lambda: gate == "true",
                expected_email=expected_email, **options)
            workflow = SecretEventSubscriptionLiveWorkflow(_path(environment, "AUTHORIZATION_DB"),
                key, transport, binding, operation=operation)
            return SecretEventSubscriptionMcpAction(workflow, execution_enabled=gate == "true")

        return SecretEventSubscriptionMcpCandidate(direction("subscribe"), direction("restore"))
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def _path(environment: Mapping[str, str], name: str) -> Path:
    value = Path(environment[PREFIX + name])
    if not value.is_absolute():
        raise ValueError(_UNAVAILABLE)
    return value


def _load_binding(path: Path) -> SecretEventSubscriptionBinding:
    value = json.loads(_private_bytes(path, limit=4096))
    fields = {"contract", "secret_id", "folder_id", "secret_name", "target_name", "owner_name"}
    if not isinstance(value, dict) or set(value) != fields or value["contract"] != BINDING_CONTRACT:
        raise ValueError(_UNAVAILABLE)
    return SecretEventSubscriptionBinding(**{k: value[k] for k in fields - {"contract"}})


def _requester(principal: Any) -> str:
    if not isinstance(principal, V4PlanningPrincipal):
        raise RuntimeError(_UNAVAILABLE)
    return principal.requester.digest


def _load_recipient(path: Path, binding: SecretEventSubscriptionBinding) -> str:
    def unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        if len({key for key, _ in pairs}) != len(pairs):
            raise ValueError(_UNAVAILABLE)
        return dict(pairs)

    value = json.loads(_private_bytes(path, limit=4096), object_pairs_hook=unique_fields)
    if (type(value) is not dict
            or set(value) != {"contract", "secret_id", "owner_name", "recipient"}
            or value["contract"] != RECIPIENT_CONTRACT
            or type(value["secret_id"]) is not int or value["secret_id"] != binding.secret_id
            or value["owner_name"] != binding.owner_name):
        raise ValueError(_UNAVAILABLE)
    recipient = value["recipient"]
    if not isinstance(recipient, str):
        raise ValueError(_UNAVAILABLE)
    validate_subscription_email_binding(recipient)
    if not recipient:
        raise ValueError(_UNAVAILABLE)
    return recipient


def register_secret_event_subscription_candidate_tools(
    server: Any, candidate: SecretEventSubscriptionMcpCandidate,
) -> None:
    from .server import (
        LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, READ_ONLY_TOOL_ANNOTATIONS,
    )

    def register(operation: Operation, action: SecretEventSubscriptionMcpAction) -> None:
        @server.mcp.tool(name=f"preview_v4_secret_event_subscription_{operation}_700",
            description=f"Preview one fixed build-29 Web/cfg-chg subscription {operation}; no device write.",
            annotations=READ_ONLY_TOOL_ANNOTATIONS)
        async def preview() -> dict[str, object]:
            return await asyncio.to_thread(action.preview, server._v4_planning_principal())

        @server.mcp.tool(name=f"confirm_v4_secret_event_subscription_{operation}_700",
            description=f"Record caller-bound intent for the unchanged fixed subscription {operation}; no device write.",
            annotations=LOCAL_STATE_TOOL_ANNOTATIONS)
        async def confirm(preview_ref: str) -> dict[str, object]:
            return await asyncio.to_thread(action.confirm, preview_ref, server._v4_secret_metadata_action_principal())

        @server.mcp.tool(name=f"execute_confirmed_v4_secret_event_subscription_{operation}_700",
            description=f"Execute the authorized fixed subscription {operation} once; return categorical readback.",
            annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)
        async def execute(authorization_ref: str) -> dict[str, object]:
            return await asyncio.to_thread(action.execute, authorization_ref, server._v4_secret_metadata_action_principal())

    register("subscribe", candidate.subscribe)
    register("restore", candidate.restore)
