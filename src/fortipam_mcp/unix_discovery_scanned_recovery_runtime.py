"""Default-closed private lab issuer for one original scanned Source recovery.

Use the exact original-run lab scope, not global activity assertions. Existing
unscanned Tools/builders retain their contract; this candidate has separate DI.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
from threading import RLock
import time
from typing import Any, TYPE_CHECKING, cast

if TYPE_CHECKING:
    from mcp.server import MCPServer
    from .server import FortiPamMcpServer

from v4_planning import M4AuthorizationDenied, M4ExecutionAuthorization, M4ExecutionKernel, M4ExecutionPlan, M4ExecutionResult, canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .discovery_review_http_transport import _nonfinite, _unique_pairs
from .discovery_scanned_source_recovery import (
    ACTION_ID, ACTION_VERSION, ADAPTER_REF, ScannedSourceRecoveryM4Adapter, ScannedSourceRecoveryReader,
    scanned_recovery_parameters_digest, scanned_recovery_state_digest, scanned_recovery_summary,
)
from .ldap_server_runtime import _key, _private_directory, _read
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable
from .unix_discovery_account_run_runtime import _execution_binding
from .v4_plan_runtime import V4PlanningPrincipal

CONTRACT = "fortipam-build29-unix-scanned-recovery-runtime-v1"
POLICY = "fortipam-mcp-lab-auto-original-unix-scanned-recovery"
_CONTEXT = "source-recovery-execution-context.json"
_DOMAIN = b"unix-scanned-recovery-lab-auto/v1\x00"
_ERROR = "The private scanned Source recovery composition is unavailable."


def _mac(key: bytearray, body: object) -> str:
    return hmac.new(key, _DOMAIN + json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(), hashlib.sha256).hexdigest()


def _open_prepared_recovery(directory: Path, authority_key_file: Path, witness_key_file: Path,
        reader: ScannedSourceRecoveryReader, store: PersistentM4ExecutionStateStore, *, clock: Callable[[], int] | None = None,
        before_dispatch: Callable[[], None] | None = None) -> ScannedSourceRecoveryM4Adapter:
    """Validate the original signed context for a bound runtime or reader."""
    key, raw = bytearray(), bytearray()
    try:
        if type(reader) is not ScannedSourceRecoveryReader: raise ValueError
        key = bytearray(_key(authority_key_file))
        if len(key) != 32: raise ValueError
        raw = _read(directory / _CONTEXT, 16_384)
        body = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_nonfinite)
        fields = {"contract", "policy", "stage", "scope_digest", "parameters_digest", "execution_binding_digest", "plan", "authorization"}
        if type(body) is not dict or set(body) != fields | {"signature"}: raise ValueError
        signature = body.pop("signature")
        if (type(signature) is not str or not hmac.compare_digest(signature, _mac(key, body))
                or body["contract"] != CONTRACT or body["policy"] != POLICY or body["stage"] != "prepared_only"
                or body["parameters_digest"] != scanned_recovery_parameters_digest(reader._run)
                or body["execution_binding_digest"] != _execution_binding(key, directory, authority_key_file, witness_key_file, store, reader._config)):
            raise ValueError
        require_digest(body["scope_digest"], "scanned_recovery_scope")
        return ScannedSourceRecoveryM4Adapter(reader, M4ExecutionPlan(**body["plan"]), M4ExecutionAuthorization(**body["authorization"]),
            store, directory, witness_key_file, clock=clock, before_dispatch=before_dispatch)
    except Exception:
        raise M4AuthorizationDenied(_ERROR) from None
    finally:
        _zeroize_mutable(key); _zeroize_mutable(raw)


def open_original_scanned_source_recovery(directory: Path, authority_key_file: Path, witness_key_file: Path,
        reader: ScannedSourceRecoveryReader, store: PersistentM4ExecutionStateStore, *, clock: Callable[[], int] | None = None) -> ScannedSourceRecoveryM4Adapter:
    """Read original evidence after expiry with an enforced read-only store."""
    if type(store) is not PersistentM4ExecutionStateStore or not store._read_only: raise M4AuthorizationDenied(_ERROR)
    return _open_prepared_recovery(directory, authority_key_file, witness_key_file, reader, store, clock=clock)


class UnixScannedSourceRecoveryRuntime(_OpaqueC3Object):
    """Scoped standing lab authority; durable preparation precedes reservation."""

    def __init__(self, reader: ScannedSourceRecoveryReader, store: PersistentM4ExecutionStateStore, directory: Path, *,
            authority_key_file: Path, witness_key_file: Path, environment_ref: str, scope_ref: str, audience_ref: str,
            requester_digest: str, transport_digest: str, execution_enabled: bool = False, clock: Callable[[], int] | None = None) -> None:
        self._key = bytearray()
        try:
            if (type(reader) is not ScannedSourceRecoveryReader or type(store) is not PersistentM4ExecutionStateStore
                    or not store.monotonic_checkpoint_protocol_bound or store._read_only or type(execution_enabled) is not bool
                    or clock is not None and not callable(clock)): raise ValueError
            reader._validate(); run = reader._run
            if directory != run._directory.with_name(run._directory.name + "-recovery") or requester_digest != run._plan.requester_digest: raise ValueError
            for value in (environment_ref, scope_ref, audience_ref): require_ref(value, "scanned_recovery_scope")
            for value in (requester_digest, transport_digest): require_digest(value, "scanned_recovery_identity")
            _private_directory(directory)
            protected = {run._key_file, run._store._path, run._store._key_path, run._creation._key_file,
                run._creation._store._path, run._creation._store._key_path,
                *(run._directory / name for name in ("account-run-execution-context.json", "account-run-send.claim.json", "account-run-ack.json", "account-run-state.json")),
                *(run._creation._directory / name for name in ("source-execution-context.json", "source-send.claim.json", "source-create-ack.json", "source-created-state.json"))}
            object_claim = run._creation._directory / "source-scanned-recovery.claim.json"
            paths = (authority_key_file, witness_key_file, store._path, store._key_path, object_claim,
                *(directory / name for name in (_CONTEXT, "recovery-send.claim.json", "recovery-delete-ack.json")))
            if len(set(paths)) != len(paths) or any(path in protected for path in paths): raise ValueError
            self._key = bytearray(_key(authority_key_file)); witness = bytearray(_key(witness_key_file))
            try:
                keys: tuple[bytes | bytearray, ...] = (self._key, witness, store._key, run._key, run._store._key, run._creation._key, run._creation._store._key)
                if any(len(key) != 32 for key in keys) or any(hmac.compare_digest(left, right)
                        for index, left in enumerate(keys) for right in keys[index + 1:]): raise ValueError
            finally: _zeroize_mutable(witness)
            if store.claim_count or object_claim.exists() or any((directory / name).exists() for name in (_CONTEXT, "recovery-send.claim.json", "recovery-delete-ack.json")): raise ValueError
            self._reader, self._store, self._directory = reader, store, directory
            self._authority_file, self._witness_file = authority_key_file, witness_key_file
            self._scope = dict(environment_ref=environment_ref, scope_ref=scope_ref, audience_ref=audience_ref,
                requester_digest=requester_digest, transport_digest=transport_digest, policy=POLICY)
            info = directory.stat(); self._directory_identity = (info.st_dev, info.st_ino)
            self._clock = clock if clock is not None else lambda: int(time.time())
            self._last = -1; self._enabled, self._closed, self._failed = execution_enabled, False, False
            self._preview: tuple[str, int, int] | None = None
            self._issued: tuple[M4ExecutionPlan, M4ExecutionAuthorization] | None = None
            self._context_body: dict[str, object] | None = None
            self._adapter: ScannedSourceRecoveryM4Adapter | None = None
            self._lock = RLock(); self._pins = self._context()
        except Exception:
            _zeroize_mutable(self._key); raise M4AuthorizationDenied(_ERROR) from None

    def _context(self) -> str:
        self._reader._validate(); _private_directory(self._directory)
        info = self._directory.stat()
        if ((info.st_dev, info.st_ino) != self._directory_identity
                or not hmac.compare_digest(_key(self._authority_file), self._key)
                or not hmac.compare_digest(_key(self._store._key_path), self._store._key)): raise ValueError
        return _mac(self._key, dict(scope=self._scope, parameters=scanned_recovery_parameters_digest(self._reader._run),
            execution_binding=_execution_binding(self._key, self._directory, self._authority_file, self._witness_file, self._store, self._reader._config),
            reader_identity=id(self._reader), guard_identity=id(self._reader._guard), guard_context=self._reader._guard._source,
            store_identity=id(self._store), checkpoint_identity=id(self._store._monotonic_checkpoint), clock_identity=id(self._clock)))

    def _now(self) -> int:
        try:
            now = self._clock()
            if self._closed or self._failed or type(now) is not int or now < 0 or now < self._last or self._context() != self._pins: raise ValueError
            self._last = now; return now
        except Exception:
            self._failed = True; raise ValueError from None

    def _identity(self, principal: V4PlanningPrincipal) -> None:
        if (type(principal) is not V4PlanningPrincipal or principal.requester.digest != self._scope["requester_digest"]
                or principal.transport_namespace_digest != self._scope["transport_digest"]): raise ValueError
        principal.__post_init__()

    def preview(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(principal); self._now()
                if self._issued is not None or (self._directory / _CONTEXT).exists(): raise ValueError
                result = self._reader.preview(); now = self._now()
                ref = "scanned-source-recovery-preview-" + _mac(self._key, dict(nonce=secrets.token_hex(32), pins=self._pins, created_at=now))
                self._preview = ref, now, now + 60
                return {**result, "contract": CONTRACT, "preview_ref": ref, "expires_at": now + 60, "policy_mode": "lab_auto"}
        except Exception: raise M4AuthorizationDenied(_ERROR) from None

    def _derive(self) -> tuple[M4ExecutionPlan, M4ExecutionAuthorization]:
        if self._preview is None: raise ValueError
        ref, created, expiry = self._preview
        context = dict(scope=self._scope, preview=ref, created_at=created, expires_at=expiry, pins=self._pins)
        def signed(purpose: str) -> str: return _mac(self._key, dict(purpose=purpose, context=context))
        values: dict[str, Any] = dict(plan_ref="scanned-source-recover-plan-" + signed("plan"), revision=1,
            action_id=ACTION_ID, action_version=ACTION_VERSION, adapter_ref=ADAPTER_REF, target_ref="discovery-entry",
            requester_digest=self._scope["requester_digest"], parameters_digest=scanned_recovery_parameters_digest(self._reader._run),
            summary_digest=canonical_digest(scanned_recovery_summary()), confirmation_digest=signed("standing-intent"), approval_digest=signed("lab-policy"),
            expected_current_digest=scanned_recovery_state_digest(self._reader._run, exists=True),
            expected_state_digest=scanned_recovery_state_digest(self._reader._run, exists=False), idempotency_digest=signed("idempotency"),
            expires_at=expiry, compensation_ref=None)
        plan = M4ExecutionPlan(**values, plan_digest=canonical_digest(values))
        auth: dict[str, Any] = dict(authorization_ref="scanned-source-recover-auth-" + signed("authorization"), plan_ref=plan.plan_ref,
            plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
            confirmation_ref="scanned-source-recover-intent-" + signed("intent-ref"), confirmation_digest=plan.confirmation_digest,
            approval_ref="scanned-source-recover-policy-" + signed("policy-ref"), approval_digest=plan.approval_digest,
            approver_digest=signed("policy-authority"), issued_at=created, expires_at=expiry, one_time=True, execution_authorized=True)
        return plan, M4ExecutionAuthorization(**auth, authorization_digest=canonical_digest(auth))

    def issue(self, preview_ref: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        preparing = False
        try:
            with self._lock:
                self._identity(principal)
                if (not self._enabled or self._issued is not None or self._preview is None or preview_ref != self._preview[0]
                        or not self._preview[1] <= self._now() < self._preview[2]): raise ValueError
                self._reader.preview(); plan, auth = self._derive()
                if self._now() >= auth.expires_at or self._store.claim_count: raise ValueError
                body: dict[str, object] = dict(contract=CONTRACT, policy=POLICY, stage="prepared_only", scope_digest=canonical_digest(self._scope),
                    parameters_digest=plan.parameters_digest, execution_binding_digest=_execution_binding(self._key, self._directory,
                        self._authority_file, self._witness_file, self._store, self._reader._config), plan=asdict(plan), authorization=asdict(auth))
                preparing = True
                parent = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    info = os.fstat(parent)
                    if (info.st_dev, info.st_ino) != self._directory_identity: raise ValueError
                    fd = os.open(_CONTEXT, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=parent)
                    with os.fdopen(fd, "w") as stream:
                        json.dump({**body, "signature": _mac(self._key, body)}, stream, sort_keys=True, separators=(",", ":"))
                        stream.flush(); os.fsync(stream.fileno())
                    os.fsync(parent)
                finally: os.close(parent)
                self._context_body = body; self._check_record(); self._issued = plan, auth
                return {"contract": CONTRACT, "authorization_ref": auth.authorization_ref, "expires_at": auth.expires_at,
                    "policy_mode": "lab_auto", "device_write_executed": False}
        except Exception:
            if preparing: self._failed = True
            raise M4AuthorizationDenied(_ERROR) from None

    def _check_record(self) -> None:
        raw = _read(self._directory / _CONTEXT, 16_384)
        try:
            expected = {**self._context_body, "signature": _mac(self._key, self._context_body)} if self._context_body is not None else None
            if expected is None or json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_nonfinite) != expected: raise ValueError
        finally: _zeroize_mutable(raw)

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            with self._lock:
                now = self._now(); issued = self._issued
                if (not self._enabled or issued is None or type(now_epoch) is not int
                        or not issued[1].issued_at <= now_epoch <= now < issued[1].expires_at
                        or plan is not issued[0] or authorization is not issued[1] or issued != self._derive()): raise ValueError
                self._check_record()
        except Exception: raise M4AuthorizationDenied(_ERROR) from None

    def _before_dispatch(self) -> None:
        if self._issued is None: raise M4AuthorizationDenied(_ERROR)
        self.verify(*self._issued, now_epoch=self._now())

    def execute(self, authorization_ref: str, principal: V4PlanningPrincipal) -> M4ExecutionResult:
        if not self._lock.acquire(blocking=False): raise M4AuthorizationDenied(_ERROR)
        try:
            self._identity(principal); issued = self._issued
            if issued is None or authorization_ref != issued[1].authorization_ref: raise ValueError
            self.verify(*issued, now_epoch=self._now())
            adapter = _open_prepared_recovery(self._directory, self._authority_file, self._witness_file,
                self._reader, self._store, clock=self._clock, before_dispatch=self._before_dispatch)
            self._adapter = adapter
            return M4ExecutionKernel(adapter, self, self._store, clock=self._clock).execute(*issued)
        except M4AuthorizationDenied: raise
        except Exception: raise M4AuthorizationDenied(_ERROR) from None
        finally:
            if self._adapter is not None: self._adapter.close()
            self._lock.release()

    def close(self) -> None:
        with self._lock:
            self._enabled, self._closed = False, True
            if self._adapter is not None: self._adapter.close()
            _zeroize_mutable(self._key)


class UnixScannedSourceRecoveryMcpAction:
    """Explicit candidate DI; no default or environment activation."""

    def __init__(self, runtime: UnixScannedSourceRecoveryRuntime, *, execution_enabled: bool = False) -> None:
        if type(runtime) is not UnixScannedSourceRecoveryRuntime or type(execution_enabled) is not bool: raise M4AuthorizationDenied(_ERROR)
        self._runtime, self._execution_enabled = runtime, execution_enabled

    def preview(self, principal: Any) -> dict[str, object]:
        return self._runtime.preview(principal)

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        return self._runtime.issue(preview_ref, principal)

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled: raise M4AuthorizationDenied(_ERROR)
        return self._runtime.execute(authorization_ref, principal).as_dict()


def register_unix_scanned_source_recovery_tools(server: FortiPamMcpServer, action: UnixScannedSourceRecoveryMcpAction) -> None:
    from .server import LAB_ADMIN_DESTRUCTIVE_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, READ_ONLY_TOOL_ANNOTATIONS
    mcp = cast("MCPServer", server.mcp)

    @mcp.tool(description="Preview recovery of one owned Source after its single verified original Run in the exclusive disposable lab.",
        annotations=READ_ONLY_TOOL_ANNOTATIONS)
    async def preview_v4_unix_scanned_source_recovery_700() -> dict[str, object]:
        import asyncio
        return await asyncio.to_thread(action.preview, server._v4_planning_principal())

    @mcp.tool(description="Bind one scoped standing-lab recovery intent for the authenticated requester.", annotations=LOCAL_STATE_TOOL_ANNOTATIONS)
    async def confirm_v4_unix_scanned_source_recovery_700(preview_ref: str) -> dict[str, object]:
        import asyncio
        return await asyncio.to_thread(action.confirm, preview_ref, server._v4_password_policy_action_principal())

    @mcp.tool(description="Delete only the owned scanned Source once, then verify absence and preserved references.", annotations=LAB_ADMIN_DESTRUCTIVE_TOOL_ANNOTATIONS)
    async def execute_confirmed_v4_unix_scanned_source_recovery_700(authorization_ref: str) -> dict[str, object]:
        import asyncio
        return await asyncio.to_thread(action.execute, authorization_ref, server._v4_password_policy_action_principal())

    # Candidate registration follows the server's initial schema hardening.
    try:
        for name in ("preview_v4_unix_scanned_source_recovery_700", "confirm_v4_unix_scanned_source_recovery_700",
                "execute_confirmed_v4_unix_scanned_source_recovery_700"):
            tool = mcp._tool_manager.get_tool(name)
            if tool is None: raise ValueError
            model = tool.fn_metadata.arg_model
            model.model_config["extra"] = "forbid"
            model.model_rebuild(force=True)
            schema = model.model_json_schema()
            if schema.get("additionalProperties") is not False: raise ValueError
            tool.parameters = schema
    except Exception: raise M4AuthorizationDenied(_ERROR) from None
