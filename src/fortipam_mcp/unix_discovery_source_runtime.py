"""Private standing-lab M4 composition for one disabled, unscanned Unix Source.

Reuse the accepted Unix C/P/E and durable object claim. This opt-in composition
adds original response custody, not Scan, import, credential or recovery rights.
Trusted startup supplies identity/scope and separate owner-only keys; no Tool or
environment registration is supplied here.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
import hashlib
import hmac
import json
import os
from pathlib import Path
from threading import RLock
import time
from typing import Any

from v4_planning import M4AuthorizationDenied, M4ExecutionAuthorization, M4ExecutionKernel, M4ExecutionPlan, M4ExecutionResult, canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .discovery_entry_create_http_transport import FortiPamDiscoveryEntryCreateHttpTransport
from .discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from .discovery_entry_live_workflow import UnixDiscoveryCreateLiveWorkflow
from .discovery_entry_mcp_action import UnixDiscoveryMcpAction
from .discovery_entry_m4_adapter import ACTION_ID, ACTION_VERSION, DiscoveryEntryBinding, DiscoveryEntryM4Adapter
from .discovery_entry_m4_runtime import DiscoveryEntryExecutionBinding
from .discovery_review_http_transport import _nonfinite, _unique_pairs
from .discovery_source_create_custody import DiscoverySourceCreateCustody
from .ldap_server_runtime import _key, _private_directory, _read
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _zeroize_mutable
from .service_account_state_reader import _ca
from .v4_plan_runtime import V4PlanningPrincipal

CONTRACT = "fortipam-build29-unix-source-original-runtime-v1"
POLICY = "fortipam-mcp-lab-auto-unix-source-original-create"
_DOMAIN = b"unix-source-original-lab-auto/v1\x00"
_CONTEXT_FILE = "source-execution-context.json"
_ERROR = "The private Unix Source execution composition is unavailable."


def _mac(key: bytearray, body: object) -> str:
    return hmac.new(key, _DOMAIN + json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(), hashlib.sha256).hexdigest()


def open_original_unix_source_custody(directory: Path, authority_key_file: Path, witness_key_file: Path,
        binding: DiscoveryEntryBinding, store: PersistentM4ExecutionStateStore,
        config: SecretMetadataHttpTransportConfig, *, clock: Callable[[], int] | None = None) -> DiscoverySourceCreateCustody:
    """Read original prepared context after expiry; issue no execution authority."""
    key, raw = bytearray(), bytearray()
    try:
        key = bytearray(_key(authority_key_file))
        if len(key) != 32:
            raise ValueError
        raw = _read(directory / _CONTEXT_FILE, 16_384)
        body = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_nonfinite)
        fields = {"contract", "policy", "stage", "scope_digest", "source_parameters_digest", "serial_digest", "reference_digest", "plan", "authorization"}
        if type(body) is not dict or set(body) != fields | {"signature"}:
            raise ValueError
        signature = body.pop("signature")
        if (type(signature) is not str or not hmac.compare_digest(signature, _mac(key, body))
                or body["contract"] != CONTRACT or body["policy"] != POLICY or body["stage"] != "prepared_only"
                or body["source_parameters_digest"] != binding.parameters_digest):
            raise ValueError
        for field in ("scope_digest", "serial_digest", "reference_digest"):
            require_digest(body[field], "source_context")
        return DiscoverySourceCreateCustody(directory, witness_key_file, binding,
            M4ExecutionPlan(**body["plan"]), M4ExecutionAuthorization(**body["authorization"]), store, config,
            serial_digest=body["serial_digest"], reference_digest=body["reference_digest"], clock=clock)
    except Exception:
        raise M4AuthorizationDenied(_ERROR) from None
    finally:
        _zeroize_mutable(key); _zeroize_mutable(raw)


class UnixDiscoverySourceRuntime(_OpaqueC3Object):
    """Server-held scoped lab policy; original ownership remains kernel-bound."""

    def __init__(self, workflow: UnixDiscoveryCreateLiveWorkflow, store: PersistentM4ExecutionStateStore,
            directory: Path, *, authority_key_file: Path, witness_key_file: Path,
            source_binding: DiscoveryEntryBinding,
            environment_ref: str, scope_ref: str, audience_ref: str,
            requester_digest: str, transport_digest: str, serial_digest: str,
            execution_enabled: bool = False, clock: Callable[[], int] | None = None) -> None:
        self._key = bytearray()
        try:
            if (type(workflow) is not UnixDiscoveryCreateLiveWorkflow or type(store) is not PersistentM4ExecutionStateStore
                    or not store.monotonic_checkpoint_protocol_bound or type(execution_enabled) is not bool
                    or clock is not None and not callable(clock)
                    or type(source_binding) is not DiscoveryEntryBinding
                    or type(source_binding.request) is not DisabledUnixDiscoveryCreateInput
                    or source_binding.request != workflow._request
                    or type(workflow._transport) is not FortiPamDiscoveryEntryCreateHttpTransport
                    or workflow._transport._original_custody is not None):
                raise ValueError
            for value in (environment_ref, scope_ref, audience_ref): require_ref(value, "unix_source_scope")
            for value in (requester_digest, transport_digest, serial_digest): require_digest(value, "unix_source_identity")
            _private_directory(directory); _private_directory(workflow._claim.parent)
            files = (authority_key_file, witness_key_file, store._key_path, store._path, workflow._claim,
                *(directory / name for name in (_CONTEXT_FILE, "source-send.claim.json", "source-create-ack.json",
                    "source-ack-unqualified.json", "source-created-state.json")))
            if len(set(files)) != len(files):
                raise ValueError
            self._key = bytearray(_key(authority_key_file))
            witness = bytearray(_key(witness_key_file))
            try:
                if (len(self._key) != 32 or len(witness) != 32 or any(hmac.compare_digest(left, right)
                        for left, right in ((self._key, witness), (self._key, store._key), (witness, store._key)))):
                    raise ValueError
            finally:
                _zeroize_mutable(witness)
            self._workflow, self._store, self._directory = workflow, store, directory
            self._authority_file, self._witness_file = authority_key_file, witness_key_file
            self._config = workflow._transport._config
            self._claim = workflow._claim
            # Trusted startup retains this original binding independently. A
            # process restart must not generate a replacement nonce.
            self._source = source_binding
            self._scope = dict(environment_ref=environment_ref, scope_ref=scope_ref, audience_ref=audience_ref,
                requester_digest=requester_digest, transport_digest=transport_digest, policy=POLICY)
            self._serial = serial_digest
            info = directory.stat()
            self._directory_identity = (info.st_dev, info.st_ino)
            self._clock = clock if clock is not None else lambda: int(time.time())
            self._last = -1
            self._closed = self._failed = False
            self._enabled = execution_enabled
            self._preview: tuple[str, str, int, int] | None = None
            self._issued: DiscoveryEntryExecutionBinding | None = None
            self._context_body: dict[str, object] | None = None
            self._custody: DiscoverySourceCreateCustody | None = None
            self._lock = RLock()
            self._pins = self._context()
        except Exception:
            _zeroize_mutable(self._key)
            raise M4AuthorizationDenied(_ERROR) from None

    def _context(self) -> str:
        w = self._workflow
        self._config.__post_init__(); self._source.__post_init__()
        _private_directory(self._directory); _private_directory(self._claim.parent)
        info = self._directory.stat()
        if (w._request != self._source.request or w._claim != self._claim or w._transport._config is not self._config
                or w._transport._original_custody is not None or (info.st_dev, info.st_ino) != self._directory_identity
                or not hmac.compare_digest(_key(self._authority_file), self._key)):
            raise ValueError
        ca = _ca(self._config)
        return _mac(self._key, dict(scope=self._scope, config=asdict(self._config),
            ca_sha256=None if ca is None else hashlib.sha256(ca).hexdigest(), serial=self._serial,
            parameters=self._source.parameters_digest, claim=str(self._claim),
            witness_sha256=hashlib.sha256(_key(self._witness_file)).hexdigest(),
            workflow_identity=id(w), transport_identity=id(w._transport), store_identity=id(self._store),
            workflow_clock_identity=id(w._clock), clock_identity=id(self._clock)))

    def _now(self) -> int:
        try:
            now = self._clock()
            if self._closed or self._failed or type(now) is not int or now < self._last or now < 0 or self._context() != self._pins:
                raise ValueError
            self._last = now
            return now
        except Exception:
            self._failed = True
            raise ValueError from None

    def _identity(self, principal: V4PlanningPrincipal) -> None:
        if (type(principal) is not V4PlanningPrincipal or principal.requester.digest != self._scope["requester_digest"]
                or principal.transport_namespace_digest != self._scope["transport_digest"]):
            raise ValueError
        principal.__post_init__()

    def preview(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(principal); self._now()
                if self._issued is not None or (self._directory / _CONTEXT_FILE).exists(): raise ValueError
                result = self._workflow.preview(requester_digest=principal.requester.digest)
                ref = str(result["preview_ref"])
                record = self._workflow._get_preview(ref, principal.requester.digest)
                now = self._now()
                expiry = min(record.expires_at, now + 60)
                self._preview = (ref, record.reference_digest, now, expiry)
                return {**result, "contract": CONTRACT, "expires_at": expiry, "policy_mode": "lab_auto",
                    "scan_import_or_recovery_authorized": False}
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _derive(self, legacy_authorization_ref: str) -> DiscoveryEntryExecutionBinding:
        if self._preview is None: raise ValueError
        ref, dependency, created, expiry = self._preview
        context = dict(scope=self._scope, source=self._source.parameters_digest, preview_ref=ref,
            legacy_authorization_ref=legacy_authorization_ref, reference=dependency, serial=self._serial,
            created_at=created, expires_at=expiry, runtime_pins=self._pins)
        def signed(purpose: str) -> str: return _mac(self._key, dict(purpose=purpose, context=context))
        values: dict[str, Any] = dict(plan_ref="unix-source-plan-" + signed("plan"), revision=1,
            action_id=ACTION_ID, action_version=ACTION_VERSION, adapter_ref=self._source.adapter_ref,
            target_ref="discovery-entry", requester_digest=self._scope["requester_digest"],
            summary_digest=signed("summary"), confirmation_digest=signed("standing-intent"), approval_digest=signed("lab-policy"),
            parameters_digest=self._source.parameters_digest, expected_current_digest=self._source.state_digest(exists=False),
            expected_state_digest=self._source.state_digest(exists=True), idempotency_digest=signed("idempotency"),
            expires_at=expiry, compensation_ref=None)
        plan = M4ExecutionPlan(**values, plan_digest=canonical_digest(values))
        auth: dict[str, Any] = dict(authorization_ref="unix-source-auth-" + signed("authorization"),
            plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
            confirmation_ref="unix-source-intent-" + signed("intent-ref"), confirmation_digest=plan.confirmation_digest,
            approval_ref="unix-source-policy-" + signed("policy-ref"), approval_digest=plan.approval_digest,
            approver_digest=signed("policy-authority"), issued_at=created, expires_at=expiry,
            one_time=True, execution_authorized=True)
        return DiscoveryEntryExecutionBinding(plan, M4ExecutionAuthorization(**auth, authorization_digest=canonical_digest(auth)), self._source)

    def issue(self, preview_ref: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(principal)
                if (not self._enabled or self._issued is not None or self._preview is None
                        or preview_ref != self._preview[0] or not self._preview[2] <= self._now() < self._preview[3]):
                    raise ValueError
                result = self._workflow.confirm(preview_ref, requester_digest=principal.requester.digest)
                self._legacy_authorization = str(result["authorization_ref"])
                issued = self._derive(self._legacy_authorization)
                if self._now() >= issued.authorization.expires_at: raise ValueError
                body: dict[str, object] = dict(contract=CONTRACT, policy=POLICY, stage="prepared_only",
                    scope_digest=canonical_digest(self._scope), source_parameters_digest=self._source.parameters_digest,
                    serial_digest=self._serial, reference_digest=self._preview[1],
                    plan=asdict(issued.plan), authorization=asdict(issued.authorization))
                descriptor = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    info = os.fstat(descriptor)
                    if (info.st_dev, info.st_ino) != self._directory_identity: raise ValueError
                    fd = os.open(_CONTEXT_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
                    with os.fdopen(fd, "w") as stream:
                        json.dump({**body, "signature": _mac(self._key, body)}, stream, sort_keys=True, separators=(",", ":"))
                        stream.flush(); os.fsync(stream.fileno())
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                self._context_body, self._issued = body, issued
                return {"contract": CONTRACT, "authorization_ref": issued.authorization.authorization_ref,
                    "expires_at": issued.authorization.expires_at, "policy_mode": "lab_auto", "device_write_executed": False}
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            with self._lock:
                now = self._now()
                issued = self._issued
                if (not self._enabled or issued is None or self._preview is None or type(now_epoch) is not int
                        or not issued.authorization.issued_at <= now_epoch <= now < issued.authorization.expires_at
                        or plan is not issued.plan or authorization is not issued.authorization
                        or issued != self._derive(self._legacy_authorization)):
                    raise ValueError
                raw = _read(self._directory / _CONTEXT_FILE, 16_384)
                try:
                    expected = {**self._context_body, "signature": _mac(self._key, self._context_body)} if self._context_body is not None else None
                    if json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_nonfinite) != expected: raise ValueError
                finally:
                    _zeroize_mutable(raw)
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _before_dispatch(self) -> None:
        issued, preview = self._issued, self._preview
        if issued is None or preview is None: raise M4AuthorizationDenied(_ERROR)
        self.verify(issued.plan, issued.authorization, now_epoch=self._now())
        record = self._workflow._get_preview(preview[0], issued.plan.requester_digest)
        if (record.authorization_ref != self._legacy_authorization or record.reference_digest != preview[1]
                or self._workflow._inspect_absent_and_references() != preview[1]):
            raise M4AuthorizationDenied(_ERROR)
        self.verify(issued.plan, issued.authorization, now_epoch=self._now())
        self._workflow._reserve_claim(preview[1])
        del self._workflow._authorized[self._legacy_authorization]

    def execute(self, authorization_ref: str, principal: V4PlanningPrincipal) -> M4ExecutionResult:
        if not self._lock.acquire(blocking=False): raise M4AuthorizationDenied(_ERROR)
        try:
            self._identity(principal)
            issued = self._issued
            if issued is None or authorization_ref != issued.authorization.authorization_ref: raise ValueError
            self.verify(issued.plan, issued.authorization, now_epoch=self._now())
            custody = open_original_unix_source_custody(self._directory, self._authority_file, self._witness_file,
                self._source, self._store, self._config, clock=self._clock)
            self._custody = custody
            transport = FortiPamDiscoveryEntryCreateHttpTransport(self._config, original_custody=custody)
            try:
                if self._preview is None or transport.inspect_credential_reference(self._source.request) != self._preview[1]:
                    raise ValueError
            except Exception:
                self._failed = True
                raise M4AuthorizationDenied(_ERROR) from None
            adapter = DiscoveryEntryM4Adapter(issued.plan, self._source, transport, before_dispatch=self._before_dispatch)
            return M4ExecutionKernel(adapter, self, self._store, clock=self._clock).execute(issued.plan, issued.authorization)
        except M4AuthorizationDenied:
            raise
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None
        finally:
            if self._custody is not None: self._custody.close()
            self._lock.release()

    def close(self) -> None:
        with self._lock:
            self._enabled = False
            self._closed = True
            if self._preview is not None:
                with self._workflow._lock:
                    if self._issued is not None:
                        self._workflow._authorized.pop(self._legacy_authorization, None)
                    self._workflow._previews.pop(self._preview[0], None)
            self._preview = self._issued = None
            if self._custody is not None: self._custody.close()
            _zeroize_mutable(self._key)


class UnixDiscoverySourceMcpAction(UnixDiscoveryMcpAction):
    """Explicit DI into the existing three Unix Tools; ordinary builder unchanged."""

    def __init__(self, runtime: UnixDiscoverySourceRuntime, *, execution_enabled: bool = False) -> None:
        if type(runtime) is not UnixDiscoverySourceRuntime or type(execution_enabled) is not bool:
            raise M4AuthorizationDenied(_ERROR)
        super().__init__(runtime._workflow, execution_enabled=execution_enabled)
        self._runtime = runtime

    def preview(self, principal: Any) -> dict[str, object]:
        return self._runtime.preview(principal)

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        return self._runtime.issue(preview_ref, principal)

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise M4AuthorizationDenied(_ERROR)
        return self._runtime.execute(authorization_ref, principal).as_dict()
