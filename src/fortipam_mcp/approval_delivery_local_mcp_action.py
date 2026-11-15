"""Opt-in controlled OAuth tools for one host-bound Approval Email workflow.

Only opaque preview/authorization references enter tools. Product semantics,
source/custody and independent native recovery remain unqualified.
"""
from __future__ import annotations

import asyncio
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object

from .approval_delivery_http_backend import ApprovalDeliveryHttpBackend
from .approval_delivery_local_workflow import ApprovalDeliveryLocalWorkflow, Phase
from .approval_delivery_preview_action import _finish_private_work
from .runtime_profile import RuntimeProfile
from .v4_plan_runtime import V4PlanningPrincipal

_ERROR = "The private approval-delivery action is unavailable."


class _QueryWork:
    def _revoke(self) -> None:
        # Outcome queries own metadata work, with no execution revocation right.
        pass


class ApprovalDeliveryLocalMcpAction(_OpaqueC3Object):
    def __init__(self, workflow: ApprovalDeliveryLocalWorkflow) -> None:
        if type(workflow) is not ApprovalDeliveryLocalWorkflow: raise ValueError(_ERROR)
        self._workflow = self._workflow_pin = workflow
        self._backend_pin = workflow._backend
        self._identity_pin = (workflow._scope.requester_digest, workflow._transport)
        self._cancelled = False

    def _check_principal(self, principal: V4PlanningPrincipal) -> None:
        # Reject foreign callers before they acquire disposal/revocation rights.
        if (type(principal) is not V4PlanningPrincipal or self._workflow is not self._workflow_pin
                or self._workflow._backend is not self._backend_pin
                or (self._workflow._scope.requester_digest, self._workflow._transport) != self._identity_pin
                or (principal.requester.digest, principal.transport_namespace_digest) != self._identity_pin):
            raise RuntimeError(_ERROR)

    def _call_owned(self, operation: str, phase: Phase | None, reference: str | None,
            principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            self._check_principal(principal)
            if self._cancelled and operation != "outcome": raise ValueError
            identity = dict(requester_digest=principal.requester.digest, transport_digest=principal.transport_namespace_digest)
            if operation == "outcome": return self._workflow.outcome(**identity)
            if phase not in ("configure", "restore"): raise ValueError
            if operation == "preview": return self._workflow.preview(phase, **identity)
            if type(reference) is not str: raise ValueError
            if operation == "authorize": return self._workflow.authorize(phase, reference, **identity)
            if operation == "execute": return self._workflow.execute(phase, reference, **identity)
            raise ValueError
        except Exception:
            raise RuntimeError(_ERROR) from None

    async def call(self, operation: str, principal: V4PlanningPrincipal, *, phase: Phase | None = None,
            reference: str | None = None) -> dict[str, object]:
        self._check_principal(principal)
        if operation == "outcome":
            return await _finish_private_work(lambda: self._call_owned(operation, phase, reference, principal), _QueryWork())
        try:
            return await _finish_private_work(lambda: self._call_owned(operation, phase, reference, principal), self)
        except asyncio.CancelledError as error:
            # The original worker has drained. Cleanup also drains under repeat
            # cancellation, including a cancel racing with worker completion.
            try: await _finish_private_work(self._dispose_private, self)
            finally: raise error

    def _revoke(self) -> None:
        self._cancelled = True
        self._workflow_pin._enabled.update(configure=False, restore=False)
        if type(self._backend_pin) is ApprovalDeliveryHttpBackend:
            self._backend_pin._closed = self._backend_pin._window._closed = True

    def _dispose_private(self) -> None:
        if type(self._backend_pin) is ApprovalDeliveryHttpBackend: self._backend_pin.close()

    def close(self) -> None:
        self._revoke()
        try: self._workflow_pin.close()
        finally: self._dispose_private()


def register_approval_delivery_local_candidate_tools(server: Any, action: ApprovalDeliveryLocalMcpAction) -> None:
    from .server import LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, READ_ONLY_TOOL_ANNOTATIONS
    if (type(action) is not ApprovalDeliveryLocalMcpAction
            or getattr(server, "_runtime_profile", None) is not RuntimeProfile.V4_CONTROLLED): raise ValueError(_ERROR)

    def register(phase: Phase) -> None:
        async def preview() -> dict[str, object]:
            return await action.call("preview", server._v4_planning_principal(), phase=phase)
        async def authorize(preview_ref: str) -> dict[str, object]:
            return await action.call("authorize", server._v4_secret_metadata_action_principal(), phase=phase, reference=preview_ref)
        async def execute(authorization_ref: str) -> dict[str, object]:
            return await action.call("execute", server._v4_secret_metadata_action_principal(), phase=phase, reference=authorization_ref)
        server.mcp.tool(name=f"preview_v4_approval_delivery_local_{phase}_700",
            description="Preview one host-bound Approval Email candidate; native delivery semantics remain unqualified.",
            annotations=READ_ONLY_TOOL_ANNOTATIONS)(preview)
        server.mcp.tool(name=f"authorize_v4_approval_delivery_local_{phase}_700",
            description="Check independent protected lab grants for one fixed Approval Email phase.",
            annotations=LOCAL_STATE_TOOL_ANNOTATIONS)(authorize)
        server.mcp.tool(name=f"execute_v4_approval_delivery_local_{phase}_700",
            description="Execute one protected local Approval Email phase; native polling and approval effects remain unqualified.",
            annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)(execute)
    register("configure"); register("restore")

    async def outcome() -> dict[str, object]:
        return await action.call("outcome", server._v4_planning_principal())
    server.mcp.tool(name="get_v4_approval_delivery_local_outcome_700",
        description="Read the original owned Approval Email outcome without reloading material or redispatching.",
        annotations=READ_ONLY_TOOL_ANNOTATIONS)(outcome)


def wrap_approval_delivery_local_shutdown(app: Any, action: ApprovalDeliveryLocalMcpAction) -> Any:
    async def wrapped(scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "lifespan":
            await app(scope, receive, send)
            return
        async def receive_and_close() -> Any:
            message = await receive()
            if message["type"] == "lifespan.shutdown": await _finish_private_work(action.close, action)
            return message
        try: await app(scope, receive_and_close, send)
        finally: await _finish_private_work(action.close, action)
    return wrapped
