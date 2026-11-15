"""Private scoped lab issuer for original account reply/content custody.

Explicit private DI into existing Run Tools; no environment activation or recovery rights.
The fixture digest does not qualify live scope, latest activity or native use.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict
import hashlib
import hmac
import json
import os
from pathlib import Path
from threading import RLock
import time
from typing import Any, cast

from v4_planning import M4AuthorizationDenied, M4ExecutionAuthorization, M4ExecutionKernel, M4ExecutionPlan, M4ExecutionResult, canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .discovery_account_run_custody import (
    ACTION_ID, ACTION_VERSION, ADAPTER_REF, AccountDiscoveryRunCustody, AccountDiscoveryRunM4Adapter,
    account_run_parameters_digest, account_run_state_digest,
)
from .discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from .discovery_entry_create_http_transport import FortiPamDiscoveryEntryCreateHttpTransport
from .discovery_review_http_transport import _nonfinite, _unique_pairs
from .discovery_run_http_transport import FortiPamDiscoveryRunHttpTransport
from .discovery_run_mcp_action import UnixDiscoveryRunLiveWorkflow, UnixDiscoveryRunMcpAction
from .discovery_source_create_custody import DiscoverySourceCreateCustody
from .ldap_server_runtime import _key, _private_directory, _read
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _zeroize_mutable
from .service_account_state_reader import _ca
from .v4_plan_runtime import V4PlanningPrincipal
from .unix_discovery_onboarding_guard import ORIGINAL_RUN_RELATION_CONTRACT, ORIGINAL_RUN_STABLE_RELATION_CONTRACT, UnixDiscoveryOnboardingGuard

CONTRACT = "fortipam-build29-unix-account-run-original-runtime-v1"
POLICY = "fortipam-mcp-lab-auto-unix-account-run-original"
_DOMAIN = b"unix-account-run-original-lab-auto/v1\x00"
_CONTEXT = "account-run-execution-context.json"
_OBJECT_CLAIM = "source-account-run.claim.json"
_RECORDS = (_CONTEXT, "account-run-send.claim.json", "account-run-ack.json", "account-run-state.json")
_ERROR = "The private original Unix account Run composition is unavailable."


def _mac(key: bytearray, body: object) -> str:
    return hmac.new(key, _DOMAIN + json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(), hashlib.sha256).hexdigest()


def _directory(creation: DiscoverySourceCreateCustody) -> Path:
    if type(creation) is not DiscoverySourceCreateCustody: raise ValueError
    return creation._directory.with_name(creation._directory.name + "-account-run")


def _execution_binding(key: bytearray, directory: Path, authority_key_file: Path, witness_key_file: Path,
        store: PersistentM4ExecutionStateStore, config: SecretMetadataHttpTransportConfig) -> str:
    if type(store) is not PersistentM4ExecutionStateStore or not store.monotonic_checkpoint_protocol_bound: raise ValueError
    info = directory.stat(); ca = _ca(config)
    return _mac(key, dict(directory=str(directory), directory_identity=[info.st_dev, info.st_ino],
        authority_key_file=str(authority_key_file), witness_key_file=str(witness_key_file),
        witness_sha256=hashlib.sha256(_key(witness_key_file)).hexdigest(),
        store_path=str(store._path), store_key_path=str(store._key_path), store_key_sha256=hashlib.sha256(_key(store._key_path)).hexdigest(),
        checkpoint_store_ref=store._checkpoint_store_ref, config=asdict(config),
        checkpoint_authority_ref=store._monotonic_checkpoint.authority_ref if store._monotonic_checkpoint is not None else None,
        ca_sha256=None if ca is None else hashlib.sha256(ca).hexdigest()))


def open_original_unix_account_run_custody(directory: Path, authority_key_file: Path, witness_key_file: Path,
        creation: DiscoverySourceCreateCustody, store: PersistentM4ExecutionStateStore,
        config: SecretMetadataHttpTransportConfig, *, selected_account: str, fixture_birth_digest: str,
        clock: Callable[[], int] | None = None) -> AccountDiscoveryRunCustody:
    """Read original prepared context after expiry without issuing or resuming."""
    key, raw = bytearray(), bytearray()
    try:
        if directory != _directory(creation): raise ValueError
        _private_directory(directory)
        key = bytearray(_key(authority_key_file))
        if len(key) != 32: raise ValueError
        raw = _read(directory / _CONTEXT, 16_384)
        body = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_nonfinite)
        fields = {"contract", "policy", "stage", "scope_digest", "source_custody_digest", "parameters_digest", "execution_binding_digest", "plan", "authorization"}
        relation_fields = {"relation_guard_contract", "relation_digest", "relation_context_digest"}
        if type(body) is not dict or set(body) not in (fields | {"signature"}, fields | relation_fields | {"signature"}): raise ValueError
        if "relation_guard_contract" in body:
            if body["relation_guard_contract"] not in (ORIGINAL_RUN_RELATION_CONTRACT, ORIGINAL_RUN_STABLE_RELATION_CONTRACT): raise ValueError
            for field in ("relation_digest", "relation_context_digest"): require_digest(body[field], "original_run_relation")
        signature = body.pop("signature")
        if (type(signature) is not str or not hmac.compare_digest(signature, _mac(key, body))
                or body["contract"] != CONTRACT or body["policy"] != POLICY or body["stage"] != "prepared_only"
                or body["parameters_digest"] != account_run_parameters_digest(creation, selected_account, fixture_birth_digest)
                or body["source_custody_digest"] != creation.inspect_original_state().custody_digest
                or body["execution_binding_digest"] != _execution_binding(key, directory, authority_key_file, witness_key_file, store, config)):
            raise ValueError
        require_digest(body["scope_digest"], "account_run_scope")
        return AccountDiscoveryRunCustody(directory, witness_key_file, creation,
            M4ExecutionPlan(**body["plan"]), M4ExecutionAuthorization(**body["authorization"]), store, config,
            selected_account=selected_account, fixture_birth_digest=fixture_birth_digest, clock=clock,
            reference_digest=body["relation_digest"] if body.get("relation_guard_contract") == ORIGINAL_RUN_STABLE_RELATION_CONTRACT else None)
    except Exception:
        raise M4AuthorizationDenied(_ERROR) from None
    finally:
        _zeroize_mutable(key); _zeroize_mutable(raw)


class UnixDiscoveryAccountRunRuntime(_OpaqueC3Object):
    """Default-closed original Run authority with a fixed Source object claim."""

    def __init__(self, workflow: UnixDiscoveryRunLiveWorkflow, creation: DiscoverySourceCreateCustody,
            store: PersistentM4ExecutionStateStore, directory: Path, *, authority_key_file: Path, witness_key_file: Path,
            selected_account: str, fixture_birth_digest: str, environment_ref: str, scope_ref: str, audience_ref: str,
            requester_digest: str, transport_digest: str, execution_enabled: bool = False,
            clock: Callable[[], int] | None = None, relation_guard: UnixDiscoveryOnboardingGuard | None = None) -> None:
        self._key = bytearray()
        try:
            if (type(workflow) is not UnixDiscoveryRunLiveWorkflow or type(creation) is not DiscoverySourceCreateCustody
                    or type(store) is not PersistentM4ExecutionStateStore or not store.monotonic_checkpoint_protocol_bound
                    or store._read_only or type(execution_enabled) is not bool or clock is not None and not callable(clock)
                    or type(workflow._request) is not DisabledUnixDiscoveryCreateInput
                    or workflow._request != creation._binding.request or directory != _directory(creation)
                    or workflow._claim != creation._directory / _OBJECT_CLAIM
                    or type(workflow._transport) is not FortiPamDiscoveryRunHttpTransport
                    or type(workflow._reference) is not FortiPamDiscoveryEntryCreateHttpTransport
                    or workflow._transport._original_custody is not None
                    or workflow._transport._config != creation._config or workflow._reference._config != creation._config
                    or requester_digest != creation._plan.requester_digest):
                raise ValueError
            if relation_guard is not None:
                if (type(relation_guard) is not UnixDiscoveryOnboardingGuard or relation_guard._original_source_path is None
                        or relation_guard._request != workflow._request or relation_guard._account != selected_account): raise ValueError
                relation_guard.check_transport(creation._config)
            for value in (environment_ref, scope_ref, audience_ref): require_ref(value, "account_run_scope")
            for value in (requester_digest, transport_digest): require_digest(value, "account_run_identity")
            parameters = account_run_parameters_digest(creation, selected_account, fixture_birth_digest)
            _private_directory(directory); _private_directory(creation._directory)
            files = (authority_key_file, witness_key_file, store._path, store._key_path, workflow._claim,
                *(directory / name for name in _RECORDS))
            protected = (creation._key_file, creation._store._path, creation._store._key_path,
                *(creation._directory / name for name in ("source-execution-context.json", "source-send.claim.json",
                    "source-create-ack.json", "source-ack-unqualified.json", "source-created-state.json")))
            if len(set(files)) != len(files) or any(path in protected for path in files): raise ValueError
            self._key = bytearray(_key(authority_key_file))
            witness = bytearray(_key(witness_key_file))
            try:
                keys: tuple[bytes | bytearray, ...] = (self._key, witness, store._key, creation._key, creation._store._key)
                if any(len(key) != 32 for key in keys) or any(hmac.compare_digest(left, right)
                        for index, left in enumerate(keys) for right in keys[index + 1:]): raise ValueError
            finally:
                _zeroize_mutable(witness)
            if store.claim_count or any((directory / name).exists() for name in _RECORDS): raise ValueError
            workflow._require_unconsumed()
            self._workflow, self._creation, self._store, self._directory = workflow, creation, store, directory
            self._authority_file, self._witness_file = authority_key_file, witness_key_file
            self._config, self._claim = creation._config, workflow._claim
            self._selected, self._fixture, self._parameters = selected_account, fixture_birth_digest, parameters
            self._guard = relation_guard
            self._scope = dict(environment_ref=environment_ref, scope_ref=scope_ref, audience_ref=audience_ref,
                requester_digest=requester_digest, transport_digest=transport_digest, policy=POLICY)
            info = directory.stat(); self._directory_identity = (info.st_dev, info.st_ino)
            self._clock = clock if clock is not None else lambda: int(time.time())
            self._last = -1
            self._enabled, self._closed, self._failed = execution_enabled, False, False
            self._preview: tuple[str, str, int, int, str, str | None] | None = None
            self._issued: tuple[M4ExecutionPlan, M4ExecutionAuthorization] | None = None
            self._context_body: dict[str, object] | None = None
            self._custody: AccountDiscoveryRunCustody | None = None
            self._lock = RLock()
            self._pins = self._context()
        except Exception:
            _zeroize_mutable(self._key)
            raise M4AuthorizationDenied(_ERROR) from None

    def _context(self) -> str:
        w = self._workflow
        if self._guard is not None: self._guard.check_transport(self._config)
        self._config.__post_init__()
        _private_directory(self._directory); _private_directory(self._creation._directory)
        info = self._directory.stat()
        if (w._request != self._creation._binding.request or w._claim != self._claim
                or self._claim != self._creation._directory / _OBJECT_CLAIM
                or w._transport._config != self._config or w._reference._config != self._config
                or w._transport._original_custody is not None or self._directory != _directory(self._creation)
                or (info.st_dev, info.st_ino) != self._directory_identity
                or not hmac.compare_digest(_key(self._authority_file), self._key)
                or not hmac.compare_digest(_key(self._store._key_path), self._store._key)):
            raise ValueError
        pins: dict[str, object] = dict(scope=self._scope,
            execution_binding=_execution_binding(self._key, self._directory, self._authority_file, self._witness_file, self._store, self._config),
            parameters=account_run_parameters_digest(self._creation, self._selected, self._fixture),
            claim=str(self._claim),
            workflow_identity=id(w), transport_identity=id(w._transport), reference_identity=id(w._reference),
            store_identity=id(self._store), creation_identity=id(self._creation),
            checkpoint_identity=id(self._store._monotonic_checkpoint),
            workflow_clock_identity=id(w._clock), clock_identity=id(self._clock))
        if self._guard is not None: pins.update(relation_guard_identity=id(self._guard), relation_context=self._guard._source)
        return _mac(self._key, pins)

    def _now(self) -> int:
        try:
            now = self._clock()
            if self._closed or self._failed or type(now) is not int or now < self._last or now < 0 or self._context() != self._pins: raise ValueError
            self._last = now
            return now
        except Exception:
            self._failed = True
            raise ValueError from None

    def _identity(self, principal: V4PlanningPrincipal) -> None:
        if (type(principal) is not V4PlanningPrincipal or principal.requester.digest != self._scope["requester_digest"]
                or principal.transport_namespace_digest != self._scope["transport_digest"]): raise ValueError
        principal.__post_init__()

    def _full_source(self) -> None:
        payload = self._workflow._transport._read_full_source(self._workflow._request)
        pin = self._creation.bind_scan_preservation(cast(Mapping[str, object], payload), self._selected, fixture_birth_digest=self._fixture)
        pin.close()

    def _observe_relation(self, *, scanned: bool = False) -> str | None:
        if self._guard is None: return None
        if scanned and self._custody is None: raise ValueError
        key = bytearray(_key(self._witness_file))
        try:
            observed = self._guard.observe_original_run(self._creation, selected_account=self._selected,
                fixture_birth_digest=self._fixture, original_run=self._custody if scanned else None, reference_witness_key=key)
            if observed.native_fixture_or_activity_qualified is not False or observed.stable_reference_digest is None: raise ValueError
            return observed.stable_reference_digest
        finally:
            _zeroize_mutable(key)

    def preview(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(principal); self._now()
                if self._issued is not None or (self._directory / _CONTEXT).exists(): raise ValueError
                result = self._workflow.preview(requester_digest=principal.requester.digest)
                self._full_source()
                relation = self._observe_relation()
                ref = str(result["preview_ref"])
                record = self._workflow._get_preview(ref, principal.requester.digest)
                now = self._now(); expiry = min(record.expires_at, now + 60)
                current = {"original_disabled_unscanned_source": True, "full_original_source_preserved": True,
                    "bound_unix_secret_and_target_visible": True}
                expected = {"original_zero_reply_and_preserved_scan_content": True, "current_activity_latest_or_recovery_qualified": False}
                if self._guard is not None:
                    current["complete_reference_bracket_verified"] = True
                    expected["complete_reference_bracket_preserved"] = True
                summary = {"Current State": current, "Proposed Changes": result["Proposed Changes"], "Expected State": expected}
                self._preview = (ref, record.reference_digest, now, expiry, canonical_digest(summary), relation)
                return {"contract": CONTRACT, "preview_ref": ref, "expires_at": expiry, "policy_mode": "lab_auto",
                    **summary, "device_write_executed": False, "native_scope_qualified": False}
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _derive(self, legacy_ref: str) -> tuple[M4ExecutionPlan, M4ExecutionAuthorization]:
        if self._preview is None: raise ValueError
        ref, dependency, created, expiry, summary, relation = self._preview
        context = dict(scope=self._scope, parameters=self._parameters, preview_ref=ref, legacy_authorization_ref=legacy_ref,
            reference=dependency, created_at=created, expires_at=expiry, runtime_pins=self._pins)
        if relation is not None: context.update(relation_guard_contract=ORIGINAL_RUN_STABLE_RELATION_CONTRACT, relation_digest=relation)
        def signed(purpose: str) -> str: return _mac(self._key, dict(purpose=purpose, context=context))
        values: dict[str, Any] = dict(plan_ref="unix-account-run-plan-" + signed("plan"), revision=1,
            action_id=ACTION_ID, action_version=ACTION_VERSION, adapter_ref=ADAPTER_REF, target_ref="discovery-entry",
            requester_digest=self._scope["requester_digest"], summary_digest=summary,
            confirmation_digest=signed("standing-intent"), approval_digest=signed("lab-policy"),
            parameters_digest=self._parameters,
            expected_current_digest=account_run_state_digest(self._creation, self._selected, self._fixture, scanned=False),
            expected_state_digest=account_run_state_digest(self._creation, self._selected, self._fixture, scanned=True),
            idempotency_digest=signed("idempotency"), expires_at=expiry, compensation_ref=None)
        plan = M4ExecutionPlan(**values, plan_digest=canonical_digest(values))
        auth: dict[str, Any] = dict(authorization_ref="unix-account-run-auth-" + signed("authorization"), plan_ref=plan.plan_ref,
            plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
            confirmation_ref="unix-account-run-intent-" + signed("intent-ref"), confirmation_digest=plan.confirmation_digest,
            approval_ref="unix-account-run-policy-" + signed("policy-ref"), approval_digest=plan.approval_digest,
            approver_digest=signed("policy-authority"), issued_at=created, expires_at=expiry,
            one_time=True, execution_authorized=True)
        return plan, M4ExecutionAuthorization(**auth, authorization_digest=canonical_digest(auth))

    def issue(self, preview_ref: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(principal)
                if (not self._enabled or self._issued is not None or self._preview is None or preview_ref != self._preview[0]
                        or not self._preview[2] <= self._now() < self._preview[3]): raise ValueError
                result = self._workflow.confirm(preview_ref, requester_digest=principal.requester.digest)
                self._legacy_authorization = str(result["authorization_ref"])
                self._full_source()
                if self._observe_relation() != self._preview[5]: raise ValueError
                plan, auth = self._derive(self._legacy_authorization)
                if self._now() >= auth.expires_at or self._store.claim_count: raise ValueError
                body: dict[str, object] = dict(contract=CONTRACT, policy=POLICY, stage="prepared_only",
                    scope_digest=canonical_digest(self._scope), source_custody_digest=self._creation.inspect_original_state().custody_digest,
                    parameters_digest=self._parameters, execution_binding_digest=_execution_binding(self._key, self._directory,
                        self._authority_file, self._witness_file, self._store, self._config), plan=asdict(plan), authorization=asdict(auth))
                if self._guard is not None:
                    body.update(relation_guard_contract=ORIGINAL_RUN_STABLE_RELATION_CONTRACT,
                        relation_digest=self._preview[5], relation_context_digest=self._guard._source)
                descriptor = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    info = os.fstat(descriptor)
                    if (info.st_dev, info.st_ino) != self._directory_identity: raise ValueError
                    fd = os.open(_CONTEXT, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
                    with os.fdopen(fd, "w") as stream:
                        json.dump({**body, "signature": _mac(self._key, body)}, stream, sort_keys=True, separators=(",", ":"))
                        stream.flush(); os.fsync(stream.fileno())
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                self._context_body = body
                self._check_record()
                self._issued = plan, auth
                return {"contract": CONTRACT, "authorization_ref": auth.authorization_ref, "expires_at": auth.expires_at,
                    "policy_mode": "lab_auto", "device_write_executed": False, "native_scope_qualified": False}
        except Exception:
            if hasattr(self, "_legacy_authorization"): self._failed = True
            raise M4AuthorizationDenied(_ERROR) from None

    def _check_record(self) -> None:
        raw = _read(self._directory / _CONTEXT, 16_384)
        try:
            expected = {**self._context_body, "signature": _mac(self._key, self._context_body)} if self._context_body is not None else None
            if expected is None or json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_nonfinite) != expected: raise ValueError
        finally:
            _zeroize_mutable(raw)

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            with self._lock:
                now = self._now(); issued = self._issued
                if (not self._enabled or issued is None or self._preview is None or type(now_epoch) is not int
                        or not issued[1].issued_at <= now_epoch <= now < issued[1].expires_at
                        or plan is not issued[0] or authorization is not issued[1]
                        or issued != self._derive(self._legacy_authorization)): raise ValueError
                self._check_record()
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _before_dispatch(self) -> None:
        issued, preview = self._issued, self._preview
        if issued is None or preview is None or self._custody is None: raise M4AuthorizationDenied(_ERROR)
        self._custody._writing_now()
        self.verify(*issued, now_epoch=self._now())
        record = self._workflow._get_preview(preview[0], issued[0].requester_digest)
        if (record.authorization_ref != self._legacy_authorization or record.reference_digest != preview[1]
                or self._workflow._inspect() != preview[1]): raise M4AuthorizationDenied(_ERROR)
        self._full_source()
        if self._observe_relation() != preview[5]: raise M4AuthorizationDenied(_ERROR)
        self.verify(*issued, now_epoch=self._now())
        self._workflow._reserve_claim(preview[1])
        del self._workflow._authorized[self._legacy_authorization]

    def _after_readback(self) -> None:
        if self._guard is None: return
        if self._issued is None or self._preview is None: raise M4AuthorizationDenied(_ERROR)
        self.verify(*self._issued, now_epoch=self._now())
        if self._observe_relation(scanned=True) != self._preview[5]: raise M4AuthorizationDenied(_ERROR)
        self.verify(*self._issued, now_epoch=self._now())

    def execute(self, authorization_ref: str, principal: V4PlanningPrincipal) -> M4ExecutionResult:
        if not self._lock.acquire(blocking=False): raise M4AuthorizationDenied(_ERROR)
        try:
            self._identity(principal)
            issued = self._issued
            if issued is None or authorization_ref != issued[1].authorization_ref: raise ValueError
            self.verify(*issued, now_epoch=self._now())
            custody = open_original_unix_account_run_custody(self._directory, self._authority_file, self._witness_file,
                self._creation, self._store, self._config, selected_account=self._selected, fixture_birth_digest=self._fixture, clock=self._clock)
            self._custody = custody
            transport = FortiPamDiscoveryRunHttpTransport(self._config, original_custody=custody)
            adapter = AccountDiscoveryRunM4Adapter(custody, transport, before_dispatch=self._before_dispatch, after_readback=self._after_readback)
            return M4ExecutionKernel(adapter, self, self._store, clock=self._clock).execute(*issued)
        except M4AuthorizationDenied:
            raise
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None
        finally:
            if self._custody is not None: self._custody.close()
            self._lock.release()

    def close(self) -> None:
        with self._lock:
            self._enabled, self._closed = False, True
            if hasattr(self, "_legacy_authorization"):
                with self._workflow._lock: self._workflow._authorized.pop(self._legacy_authorization, None)
            if self._custody is not None: self._custody.close()
            _zeroize_mutable(self._key)


class UnixDiscoveryOriginalRunMcpAction(UnixDiscoveryRunMcpAction):
    """Explicit DI into existing Run Tools with original M4/custody authority."""

    def __init__(self, runtime: UnixDiscoveryAccountRunRuntime, *, execution_enabled: bool = False) -> None:
        if type(runtime) is not UnixDiscoveryAccountRunRuntime or type(execution_enabled) is not bool: raise M4AuthorizationDenied(_ERROR)
        super().__init__(runtime._workflow, execution_enabled=execution_enabled)
        self._runtime = runtime

    def preview(self, principal: Any) -> dict[str, object]:
        return self._runtime.preview(principal)

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        return self._runtime.issue(preview_ref, principal)

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled: raise M4AuthorizationDenied(_ERROR)
        return self._runtime.execute(authorization_ref, principal).as_dict()
