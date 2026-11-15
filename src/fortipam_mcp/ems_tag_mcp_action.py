"""Private, default-closed OAuth/MCP composition for one original EMS phase.

Trusted startup fixes create or independent recovery and supplies protected
inputs. The request supplies only an opaque reference. This candidate does not
qualify native FortiPAM Tag admission or enable the normal runtime.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
import hashlib
from pathlib import Path
from threading import RLock
import time
from typing import Any, Literal

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from v4_planning import M4ExecutionKernel, M4ExecutionPlan, M4ExecutionResult
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_ref

from .ems_tag_authority import EmsTagCreateAuthority, EmsTagIssued, EmsTagPreview
from .ems_tag_account_tag_source import EmsOriginalAccountTagSession
from .ems_tag_create_m4_adapter import NativeEmsTagCreateM4Adapter
from .ems_tag_custody import EmsTagOriginalActorBinding, EmsTagOriginalCustody
from .ems_tag_http_transport import NativeEmsTagHttpTransport
from .ems_tag_original_binding import retain_original_binding
from .ems_tag_recovery_authority import EmsTagRecoveryAuthority
from .ems_tag_recovery_custody import EmsTagRecoveryCustody
from .ems_tag_recovery_m4_adapter import NativeEmsTagRecoveryM4Adapter
from .ldap_server_runtime import _private_directory
from .m4_execution_store import PersistentM4ExecutionStateStore
from .v4_plan_runtime import V4PlanningPrincipal

_ERROR = "The private EMS Tag action is unavailable."
Phase = Literal["create", "recover"]


def _identity(principal: V4PlanningPrincipal) -> dict[str, str]:
    if type(principal) is not V4PlanningPrincipal:
        raise ValueError
    principal.__post_init__()
    return dict(requester_digest=principal.requester.digest,
                transport_digest=principal.transport_namespace_digest)


class EmsTagPreparedContext(_OpaqueC3Object):
    """Unissued protected components built only after authenticated preparation."""
    def __init__(self, *, authority: EmsTagCreateAuthority | EmsTagRecoveryAuthority,
            store: PersistentM4ExecutionStateStore, custody_directory: Path,
            witness_key_file: Path, original_binding_file: Path | None = None,
            owned_account_session: EmsOriginalAccountTagSession | None = None) -> None:
        try:
            if (type(authority) not in (EmsTagCreateAuthority, EmsTagRecoveryAuthority)
                    or type(store) is not PersistentM4ExecutionStateStore or store._read_only
                    or not store.monotonic_checkpoint_protocol_bound or store.claim_count != 0
                    or authority._issued is not None or authority._preview is not None):
                raise ValueError
            _private_directory(custody_directory)
            if any(custody_directory.iterdir()):
                raise ValueError
            if isinstance(authority, EmsTagCreateAuthority):
                sources = authority._sources
                transport = getattr(authority._sources._get, "__self__", None)
                if (type(transport) is not NativeEmsTagHttpTransport
                        or getattr(authority._sources._get, "__func__", None) is not NativeEmsTagHttpTransport.get_json):
                    raise ValueError
                if original_binding_file is None:
                    raise ValueError
                _private_directory(original_binding_file.parent)
                if original_binding_file.exists() or original_binding_file.is_symlink():
                    raise ValueError
                self.phase: Phase = "create"
            else:
                sources = authority._scope._sources
                transport = authority._scope._transport
                if original_binding_file is not None:
                    raise ValueError
                self.phase = "recover"
            if sources._original_account is not owned_account_session:
                raise ValueError
            if owned_account_session is not None:
                if type(owned_account_session) is not EmsOriginalAccountTagSession:
                    raise ValueError
                owned_account_session.check_source(sources)
                owned_account_session.require_phase(self.phase, authority._binding["requester_digest"])
                if owned_account_session._transport is not transport:
                    raise ValueError
            self.authority, self.store = authority, store
            self.directory, self.witness = custody_directory, witness_key_file
            self.original_binding_file = original_binding_file
            self.transport: NativeEmsTagHttpTransport = transport
            self._account_session = owned_account_session
            self._close_attempted, self._close_verified = False, False
            self._close_lock = RLock()
        except Exception:
            raise ValueError(_ERROR) from None

    def close(self) -> bool:
        """An explicit Account context owns its Account and Owner channels."""
        with self._close_lock:
            if self._close_attempted:
                return self._close_verified
            self._close_attempted = True
            authority = self.authority
            sources = authority._sources if isinstance(authority, EmsTagCreateAuthority) else authority._scope._sources
            account = self._account_session
            closed = False
            try:
                if account is not None:
                    closed = account.close().next_session_check_401 is True
                else:
                    closed = self.transport.close().next_session_check_401 is True
            except Exception:
                closed = False
            finally:
                if account is not None:
                    try:
                        closure = account._owner_transport.close()
                        closed = closed and all((closure.own_logout_verified, closure.next_session_check_401,
                            closure.cookie_jar_cleared, closure.owned_mutable_buffers_cleared, closure.connections_closed))
                    except Exception:
                        closed = False
                    finally:
                        account._owner_tags.close()
                        account._enrollment._sources.close()
                        account._enrollment.close()
                authority.close()
                if authority._fpa_admission is not None:
                    authority._fpa_admission.source.close()
                if isinstance(authority, EmsTagRecoveryAuthority):
                    authority._scope.close()
                sources.close()
            self._close_verified = closed
            return closed


class _RequestAdapter:
    """Keep SDK requester checks inside each M4 phase, including before send."""
    def __init__(self, adapter: NativeEmsTagCreateM4Adapter | NativeEmsTagRecoveryM4Adapter,
                 guard: Callable[[], None]) -> None:
        self._adapter, self._guard = adapter, guard

    def read_current(self, plan: M4ExecutionPlan) -> str:
        self._guard()
        return self._adapter.read_current(plan)

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        self._guard()
        self._adapter.dispatch(plan)

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        self._guard()
        return self._adapter.read_postcondition(plan)


class EmsTagMcpAction(_OpaqueC3Object):
    def __init__(self, *, phase: Phase,
            prepare: Callable[[V4PlanningPrincipal], EmsTagPreparedContext],
            execution_enabled: bool = False) -> None:
        if phase not in ("create", "recover") or not callable(prepare) or type(execution_enabled) is not bool:
            raise ValueError(_ERROR)
        self._phase, self._prepare, self._enabled = phase, prepare, execution_enabled
        self._context: EmsTagPreparedContext | None = None
        self._caller: dict[str, str] | None = None
        self._preview: EmsTagPreview | None = None
        self._issued: EmsTagIssued | None = None
        self._result: M4ExecutionResult | None = None
        self._session_closed = False
        self._prepared = self._started = self._closed = False
        self._lock = RLock()

    def _require(self, principal: V4PlanningPrincipal) -> dict[str, str]:
        identity = _identity(principal)
        if self._closed or self._caller is not None and identity != self._caller:
            raise ValueError
        return identity

    def call(self, operation: str, principal: V4PlanningPrincipal, reference: str | None = None,
             *, current_principal: Callable[[], V4PlanningPrincipal]) -> dict[str, object]:
        try:
            with self._lock:
                identity = self._require(principal)
                if reference is not None:
                    require_ref(reference, "ems_phase_reference")
                def guard() -> None:
                    if self._require(current_principal()) != identity:
                        raise ValueError
                guard()
                if operation == "preview" and reference is None:
                    if self._issued is not None or self._started:
                        raise ValueError
                    if self._context is None:
                        if self._prepared:
                            raise ValueError
                        self._prepared, self._caller = True, identity
                        prepared = self._prepare(principal)
                        if type(prepared) is not EmsTagPreparedContext:
                            raise ValueError
                        self._context = prepared
                    context = self._context
                    authority = context.authority
                    if (context.phase != self._phase or authority._binding["requester_digest"] != identity["requester_digest"]
                            or authority._binding["transport_digest"] != identity["transport_digest"]):
                        raise ValueError
                    guard()
                    if authority._fpa_admission is not None:
                        authority._fpa_admission.check(refresh=True)
                    if isinstance(authority, EmsTagCreateAuthority):
                        observed = authority._sources.observe()
                        preview = authority.preview(observed, **identity)
                        count = observed.full_scope.catalog.count
                    else:
                        observed_recovery = authority._scope.observe_owned()
                        preview = authority.preview(observed_recovery, **identity)
                        count = observed_recovery.full_scope.catalog.count
                    guard()
                    self._preview = preview
                    return {"preview_ref": preview.preview_ref, "phase": self._phase,
                        "Current State": {"tag_count": count, "complete_tag_api_scope": True},
                        "Proposed Changes": {"operation": "create_disabled_tag" if self._phase == "create" else "remove_original_owned_tag",
                            "tag_count_delta": 1 if self._phase == "create" else -1},
                        "Expected State": {"prior_tag_states_preserved": True,
                            "candidate_disabled_and_unassigned": self._phase == "create",
                            "candidate_absent": self._phase == "recover", "fortipam_tag_admission":
                                "fresh_zero_reference_scope" if authority._fpa_admission is not None else "unassessed"},
                        "device_write_executed": False}
                if self._context is None or self._preview is None:
                    raise ValueError
                context, preview = self._context, self._preview
                authority = context.authority
                if operation == "authorize" and type(reference) is str:
                    if (not self._enabled or self._issued is not None or reference != preview.preview_ref
                            or authority._fpa_admission is None):
                        raise ValueError
                    if isinstance(authority, EmsTagCreateAuthority):
                        current = authority._sources._current
                        if current is None:
                            raise ValueError
                        self._issued = authority.issue(preview, current, **identity)
                    else:
                        current_recovery = authority._scope._current
                        if current_recovery is None:
                            raise ValueError
                        self._issued = authority.issue(preview, current_recovery, **identity)
                    guard()
                    return {"authorization_ref": self._issued.authorization.authorization_ref,
                            "phase": self._phase, "device_write_executed": False}
                issued = self._issued
                if (operation != "execute" or type(reference) is not str or issued is None
                        or reference != issued.authorization.authorization_ref or not self._enabled):
                    raise ValueError
                if self._result is not None:
                    return self._public_result(replay=True)
                if self._started:
                    raise ValueError
                self._started = True
                adapter: NativeEmsTagCreateM4Adapter | NativeEmsTagRecoveryM4Adapter
                try:
                    if isinstance(authority, EmsTagCreateAuthority):
                        source = authority._sources
                        transport = context.transport
                        custody = EmsTagOriginalCustody(context.directory, context.witness, source._draft,
                            preview.baseline_digest, issued.plan, issued.authorization, context.store,
                            source_context_digest=source.source_context_digest, actor_binding=EmsTagOriginalActorBinding(
                                transport.session_binding_digest(source._key), identity["transport_digest"],
                                hashlib.sha256(authority._key).hexdigest()))
                        if context.original_binding_file is None:
                            raise ValueError
                        if authority._fpa_admission is None:
                            raise ValueError
                        retain_original_binding(context.original_binding_file, custody,
                            fpa_binding=authority._fpa_admission.binding)
                        adapter = NativeEmsTagCreateM4Adapter(transport=transport, sources=source,
                            authority=authority, issued=issued, store=context.store, custody=custody,
                            execution_enabled=True, check_request=guard)
                    else:
                        scope = authority._scope
                        recovery_custody = EmsTagRecoveryCustody(context.directory, context.witness, scope._original,
                            scope._context, EmsTagOriginalActorBinding(scope._session, scope._caller_transport,
                                hashlib.sha256(authority._key).hexdigest()), issued.plan, issued.authorization, context.store)
                        adapter = NativeEmsTagRecoveryM4Adapter(scope=scope, authority=authority, issued=issued,
                            store=context.store, custody=recovery_custody, execution_enabled=True, check_request=guard)
                    try:
                        self._result = M4ExecutionKernel(_RequestAdapter(adapter, guard), authority, context.store).execute(
                            issued.plan, issued.authorization)
                    finally:
                        adapter.close()
                finally:
                    self._session_closed = context.close()
                return self._public_result(replay=False)
        except Exception:
            raise RuntimeError(_ERROR) from None

    def _public_result(self, *, replay: bool) -> dict[str, object]:
        if self._result is None:
            raise ValueError
        assessed = self._context is not None and self._context.authority._fpa_admission is not None
        return {"phase": self._phase, "outcome": self._result.outcome,
                "verification": self._result.verification, "idempotent_replay": replay,
                "session_closed": self._session_closed, "fortipam_tag_admission":
                    "verified" if assessed and self._result.verification == "verified" else "unverified"}

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed, self._enabled = True, False
            if self._context is not None and not self._started:
                self._session_closed = self._context.close()


def register_ems_tag_candidate_tools(server: Any, action: EmsTagMcpAction) -> None:
    from .server import LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, READ_ONLY_TOOL_ANNOTATIONS
    if type(action) is not EmsTagMcpAction:
        raise ValueError(_ERROR)

    def principal(*, operate: bool) -> V4PlanningPrincipal:
        token = get_access_token()
        if not isinstance(token, AccessToken) or type(token.expires_at) is not int or token.expires_at <= int(time.time()):
            raise RuntimeError(_ERROR)
        value = server._v4_secret_metadata_action_principal() if operate else server._v4_planning_principal()
        if type(value) is not V4PlanningPrincipal:
            raise RuntimeError(_ERROR)
        return value

    async def preview() -> dict[str, object]:
        return await asyncio.to_thread(action.call, "preview", principal(operate=False),
                                       current_principal=lambda: principal(operate=False))

    async def authorize(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.call, "authorize", principal(operate=True), preview_ref,
                                       current_principal=lambda: principal(operate=True))

    async def execute(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.call, "execute", principal(operate=True), authorization_ref,
                                       current_principal=lambda: principal(operate=True))

    suffix = f"ems_original_tag_{action._phase}_748"
    server.mcp.tool(name=f"preview_v4_{suffix}", annotations=READ_ONLY_TOOL_ANNOTATIONS,
        description="Preview the fixed original EMS Tag phase from authenticated protected inputs.")(preview)
    server.mcp.tool(name=f"authorize_v4_{suffix}", annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
        description="Issue the independent fixed EMS phase intent under the authenticated lab operator.")(authorize)
    server.mcp.tool(name=f"execute_v4_{suffix}", annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        description="Execute one original EMS phase with durable M4, custody and complete Tag API readback.")(execute)
    for operation in ("preview", "authorize", "execute"):
        tool = server.mcp._tool_manager.get_tool(f"{operation}_v4_{suffix}")
        if tool is None:
            raise ValueError(_ERROR)
        model = tool.fn_metadata.arg_model
        model.model_config["extra"] = "forbid"
        model.model_rebuild(force=True)
        schema = model.model_json_schema()
        if schema.get("additionalProperties") is not False:
            raise ValueError(_ERROR)
        tool.parameters = schema
