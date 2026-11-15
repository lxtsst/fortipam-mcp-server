"""Reference-only ordinary OAuth/MCP entry for the fixed Owner JWT package."""
from __future__ import annotations

import asyncio
from collections.abc import Callable
import threading
from typing import Any

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from .jwt_manual_key_contract import _require_digest
from .jwt_manual_key_owner_workflow import JwtManualKeyOwnerPreview, JwtManualKeyOwnerWorkflow
from .v4_plan_runtime import V4PlanningPrincipal

CONTRACT = "fortipam-build29-jwt-owner-mcp-v1"
_ERROR = "FortiPAM Owner JWT operation is unavailable."


class JwtManualKeyOwnerMcpAction(_OpaqueC3Object):
    """Authenticate the configured human/client before resolving any material."""

    def __init__(self, factory: Callable[[], JwtManualKeyOwnerWorkflow], *, phase: str,
            requester_digest: str, transport_digest: str, execution_enabled: bool = False) -> None:
        if not callable(factory) or phase not in {"create", "remove"} or type(execution_enabled) is not bool:
            raise ValueError(_ERROR)
        _require_digest(requester_digest); _require_digest(transport_digest)
        self._factory, self._phase = factory, phase
        self._requester, self._transport, self._enabled = requester_digest, transport_digest, execution_enabled
        self._workflow: JwtManualKeyOwnerWorkflow | None = None
        self._preview: JwtManualKeyOwnerPreview | None = None
        self._issued: tuple[M4ExecutionPlan, M4ExecutionAuthorization] | None = None
        self._closed = False
        self._lock = threading.Lock()

    def _identity(self, principal: V4PlanningPrincipal) -> dict[str, str]:
        if (type(principal) is not V4PlanningPrincipal or principal.requester.digest != self._requester
                or principal.transport_namespace_digest != self._transport or self._closed):
            raise RuntimeError(_ERROR)
        return {"requester_digest": self._requester, "transport_digest": self._transport}

    def preview(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        with self._lock:
            identity = self._identity(principal)
            try:
                if self._workflow is None:
                    workflow = self._factory()
                    if type(workflow) is not JwtManualKeyOwnerWorkflow or workflow._phase != self._phase:
                        raise ValueError
                    self._workflow = workflow
                self._preview = self._workflow.preview(**identity)
                p = self._preview
                result: dict[str, object] = {"contract": CONTRACT, "phase": self._phase,
                    "policy_mode": "lab_auto", "preview_ref": p.preview_ref, "expires_at": p.expires_at,
                    "Current State": {"owner_context_verified": True,
                        "original_creation_qualified": self._phase == "remove", "current_digest": p.current_digest},
                    "Proposed Changes": {"operation": "create_one_manual_public_key" if self._phase == "create" else "remove_original_owned_key",
                        "maximum_native_mutations": 1, "user_or_role_changes": False},
                    "Expected State": {"digest": p.expected_digest,
                        "full_owned_state_or_absence_required": True, "jwt_login_qualified": False},
                    "recovery": "original_ack_and_terminal_ledger_only_no_retry_or_adoption",
                    "device_write_executed": False}
                result["summary_digest"] = canonical_digest(result)
                return result
            except Exception:
                self._close()
                raise RuntimeError(_ERROR) from None

    def authorize(self, preview_ref: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        with self._lock:
            identity = self._identity(principal)
            try:
                if (not self._enabled or self._workflow is None or self._preview is None
                        or type(preview_ref) is not str or preview_ref != self._preview.preview_ref):
                    raise ValueError
                self._issued = self._workflow.issue(self._preview, **identity)
                return {"contract": CONTRACT, "phase": self._phase, "policy_mode": "lab_auto",
                    "authorization_ref": self._issued[1].authorization_ref,
                    "expires_at": self._issued[1].expires_at}
            except Exception:
                self._close()
                raise RuntimeError(_ERROR) from None

    def execute(self, authorization_ref: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        with self._lock:
            self._identity(principal)
            try:
                if (not self._enabled or self._workflow is None or self._issued is None
                        or type(authorization_ref) is not str or authorization_ref != self._issued[1].authorization_ref):
                    raise ValueError
                result = self._workflow.execute(*self._issued)
                return {"contract": CONTRACT, "phase": self._phase, "outcome": result.outcome,
                    "verification": result.verification, "idempotent_replay": result.idempotent_replay}
            except Exception:
                raise RuntimeError(_ERROR) from None
            finally:
                self._close()

    def _close(self) -> None:
        self._enabled = False; self._closed = True
        if self._workflow is not None:
            self._workflow.close()
            self._workflow._source.close()

    def close(self) -> None:
        with self._lock:
            self._close()


def register_jwt_manual_key_owner_tools(server: Any, action: JwtManualKeyOwnerMcpAction) -> None:
    from .server import READ_ONLY_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS
    if type(action) is not JwtManualKeyOwnerMcpAction:
        raise ValueError(_ERROR)

    async def preview_v4_jwt_manual_key_owner_700() -> dict[str, object]:
        return await asyncio.to_thread(action.preview, server._v4_secret_metadata_action_principal())

    async def authorize_v4_jwt_manual_key_owner_700(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.authorize, preview_ref, server._v4_secret_metadata_action_principal())

    async def execute_v4_jwt_manual_key_owner_700(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.execute, authorization_ref, server._v4_secret_metadata_action_principal())

    server.mcp.tool(annotations=READ_ONLY_TOOL_ANNOTATIONS,
        description="Preview the configured manual JWT public-key create or original-owned removal; no key inputs or device write.")(preview_v4_jwt_manual_key_owner_700)
    server.mcp.tool(annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
        description="Bind the exact current JWT preview to the configured standing lab policy; no device write.")(authorize_v4_jwt_manual_key_owner_700)
    server.mcp.tool(annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        description="Dispatch one fixed Owner JWT operation through its original M4, verify full state, and close the candidate Gates.")(execute_v4_jwt_manual_key_owner_700)
    for operation in ("preview", "authorize", "execute"):
        tool = server.mcp._tool_manager.get_tool(operation + "_v4_jwt_manual_key_owner_700")
        if tool is None:
            raise ValueError(_ERROR)
        model = tool.fn_metadata.arg_model
        model.model_config["extra"] = "forbid"
        model.model_rebuild(force=True)
        tool.parameters = model.model_json_schema()
        if tool.parameters.get("additionalProperties") is not False:
            raise ValueError(_ERROR)


def wrap_jwt_manual_key_owner_shutdown(app: Any, action: JwtManualKeyOwnerMcpAction) -> Any:
    async def bounded(scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "lifespan":
            await app(scope, receive, send)
            return
        try:
            await app(scope, receive, send)
        finally:
            await asyncio.to_thread(action.close)
    return bounded
