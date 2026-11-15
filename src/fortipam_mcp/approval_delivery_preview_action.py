"""Opt-in no-input MCP preview of one host-bound Approval Email proposal.

No credentials, mailbox, endpoint, material or proposal enters MCP arguments.
One borrowed source is consumed for a private read and C/P/E only; no body,
authorization, operation, write, native qualification or recovery is produced.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from contextvars import copy_context
from typing import Any, Protocol, TypeVar

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .approval_delivery_contract import _checked_nonmaterial
from .approval_delivery_material_contract import _ROLES, prepare_material_approval_delivery
from .approval_delivery_source import ApprovalDeliverySource, CONTRACT as SOURCE_CONTRACT
from .approval_delivery_transition import prepare_approval_delivery_transition
from .runtime_profile import RuntimeProfile
from .v4_plan_runtime import V4PlanningPrincipal

CONTRACT = "fortipam-build29-approval-email-readonly-mcp-preview-local/v1"
_ERROR = "The private approval-delivery preview is unavailable."
TOOL_NAME = "preview_v4_approval_delivery_local_700"
_T = TypeVar("_T")


class ApprovalDeliveryPreviewAction(_OpaqueC3Object):
    """One host proposal/window, bound to the original OAuth requester/client."""

    def __init__(self, source: ApprovalDeliverySource, proposed: Mapping[str, Any], *, enabled: bool,
            requester_digest: str, transport_digest: str) -> None:
        try:
            if (type(source) is not ApprovalDeliverySource or source._closed
                    or source._attempted or source._projection is not None):
                raise ValueError
            for digest in (requester_digest, transport_digest):
                require_digest(digest, "approval-delivery preview principal")
            values = _checked_nonmaterial(proposed)
            self._draft_pin = prepare_material_approval_delivery(values, enabled=enabled,
                material_binding_digests=source._bindings)
            self._proposal = self._proposal_pin = tuple(values.items())
            self._identity = self._identity_pin = (requester_digest, transport_digest)
            self._source = self._source_pin = source
        except Exception:
            raise ValueError(_ERROR) from None

    def preview(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        self._check_principal(principal)
        return self._preview_owned(principal)

    def _check_principal(self, principal: V4PlanningPrincipal) -> None:
        # No source side effects: unrelated callers must not acquire either
        # disposal ownership or the right to revoke an in-flight source.
        if (type(principal) is not V4PlanningPrincipal or self._identity != self._identity_pin
                or (principal.requester.digest, principal.transport_namespace_digest) != self._identity_pin):
            raise RuntimeError(_ERROR)

    def _preview_owned(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        """Run only after identity validation has transferred disposal ownership."""
        try:
            try:
                with self._source_pin._lock:
                    # Binding can change while an authorized callback queues.
                    # Recheck inside the owned cleanup scope in that case.
                    self._check_principal(principal)
                    if (self._source is not self._source_pin or self._proposal != self._proposal_pin
                            or self._source_pin._bindings != dict(zip(_ROLES, self._draft_pin._binding_digests, strict=True))):
                        raise ValueError
                    self._source_pin.read()
                    with prepare_approval_delivery_transition(self._source_pin, dict(self._proposal_pin),
                            enabled=self._draft_pin.enabled) as transition:
                        if transition._draft != self._draft_pin:
                            raise ValueError
                        public = transition.preview()
                        public.update(preview_contract=CONTRACT, read_source_contract=SOURCE_CONTRACT,
                            fixed_get_completed=True, private_request_body_compiled=False,
                            authorization_or_operation_created=False, configuration_written=False)
            finally:
                # Includes cancellation before acquiring the source lock and
                # app-owned disposal before any public result is handed off.
                self.close()
            return public
        except Exception:
            raise RuntimeError(_ERROR) from None

    def close(self) -> None:
        self._source_pin.close()

    def _revoke(self) -> None:
        # Nonblocking latch for the event-loop thread. The existing source
        # checks this flag around IO; its owning worker performs disposal.
        self._source_pin._closed = True


class _PrivateWorkOwner(Protocol):
    def _revoke(self) -> None: ...


async def _finish_private_work(callback: Callable[[], _T], action: _PrivateWorkOwner) -> _T:
    """Drain owned work before propagating cancellation, including repeats.

    Entry requires a validated preview principal or app-owned shutdown. Shield
    the executor Future itself, not a cancellable to_thread Task. A queued
    callback still runs under the revocation latch and disposes its source.
    Context propagation matches to_thread. Always retrieve the worker outcome,
    including cleanup errors, before returning or raising the caller's cancel.
    """
    context = copy_context()
    worker = asyncio.get_running_loop().run_in_executor(None, context.run, callback)
    cancelled: asyncio.CancelledError | None = None
    while not worker.done():
        try:
            await asyncio.shield(worker)
        except asyncio.CancelledError as error:
            if cancelled is None:
                cancelled = error
            action._revoke()
        except BaseException:
            # The completed worker's error is retrieved below. Its resource
            # cleanup belongs to the synchronous callback's existing finally.
            break
    try:
        result = worker.result()
    except BaseException:
        if cancelled is not None:
            raise cancelled from None
        raise
    if cancelled is not None:
        raise cancelled from None
    return result


def register_approval_delivery_preview_tool(server: Any, action: ApprovalDeliveryPreviewAction) -> None:
    from .server import READ_ONLY_TOOL_ANNOTATIONS
    if (type(action) is not ApprovalDeliveryPreviewAction
            or getattr(server, "_runtime_profile", None) is not RuntimeProfile.V4_CONTROLLED):
        raise ValueError(_ERROR)

    async def preview() -> dict[str, object]:
        principal = server._v4_planning_principal()
        action._check_principal(principal)
        return await _finish_private_work(lambda: action._preview_owned(principal), action)

    server.mcp.tool(name=TOOL_NAME,
        description="Preview one host-bound Approval Email proposal without input, write or recovery authority; native semantics remain unqualified.",
        annotations=READ_ONLY_TOOL_ANNOTATIONS)(preview)


def wrap_approval_delivery_preview_shutdown(app: Any, action: ApprovalDeliveryPreviewAction) -> Any:
    """Dispose an unused borrowed Cookie copy when the MCP app stops."""
    async def wrapped(scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "lifespan":
            await app(scope, receive, send)
            return
        async def receive_and_close() -> Any:
            message = await receive()
            if message["type"] == "lifespan.shutdown":
                await _finish_private_work(action.close, action)
            return message
        try:
            await app(scope, receive_and_close, send)
        finally:
            await _finish_private_work(action.close, action)
    return wrapped
