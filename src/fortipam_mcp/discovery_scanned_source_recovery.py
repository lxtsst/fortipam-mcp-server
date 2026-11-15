"""Private recovery of one disposable Source after its single original Run.

The scoped lab assumes one operator for this owned Source. Positive original
Run counts/M4 plus fresh complete state are required; this does not assert
global activity, latest-run/timezone qualification or production readiness.
No issuer, environment builder, Tool or automatic compensation is supplied.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
from threading import RLock
import time
from typing import cast
from urllib.parse import quote

import httpx
from v4_planning import M4AdapterAmbiguous, M4AdapterDenied, M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.execution_kernel import M4Claim, _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .discovery_account_run_custody import AccountDiscoveryRunCustody
from .discovery_review_http_transport import _nonfinite, _unique_pairs
from .ldap_server_runtime import _key, _private_directory, _read
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _ssl_context, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs
from .unix_discovery_onboarding_guard import UnixDiscoveryOnboardingGuard

ACTION_ID = "discovery-owned-scanned-recover"
ACTION_VERSION = "1.0.0"
ADAPTER_REF = "fortipam-700-build29-unix-scanned-source-recovery-candidate"
CONTRACT = "fortipam-build29-owned-scanned-source-recovery-v1"
_SCOPE = "single-original-run-exclusive-disposable-lab"
_DOMAIN = b"owned-scanned-source-recovery/v1\x00"
_ERROR = "Owned scanned Source recovery is unavailable."
_SEND, _ACK, _OBJECT = "recovery-send.claim.json", "recovery-delete-ack.json", "source-scanned-recovery.claim.json"


class ScannedSourceRecoveryError(ValueError):
    """Fixed refusal without selectors, native state or authentication data."""


def _binding(run: AccountDiscoveryRunCustody) -> dict[str, object]:
    try:
        if type(run) is not AccountDiscoveryRunCustody: raise ValueError
        source = run._creation.inspect_original_state(); original = run.inspect_original_state()
        baseline = run.inspect_reference_baseline()
        if (not source.acknowledgement_qualified or source.original_outcome != "succeeded" or source.original_verification != "verified"
                or original.original_outcome != "succeeded" or original.original_verification != "verified"
                or not original.native_reply_valid or original.ongoing_requests != 0 or original.failed_requests != 0
                or not original.original_configuration_preserved or baseline is None
                or not run._store._read_only or not run._creation._store._read_only
                or run._store.claim_count != 1 or run._creation._store.claim_count != 1): raise ValueError
        return dict(contract=CONTRACT, lab_scope=_SCOPE, source_custody=source.custody_digest,
            run_custody=original.custody_digest, run_context=original.context_digest, reference_baseline=baseline,
            source_parameters=run._creation._binding.parameters_digest, requester=run._plan.requester_digest,
            device=run._creation._serial, general_activity_or_timezone_qualified=False)
    except Exception: raise ScannedSourceRecoveryError(_ERROR) from None


def scanned_recovery_parameters_digest(run: AccountDiscoveryRunCustody) -> str:
    return canonical_digest(_binding(run))


def scanned_recovery_state_digest(run: AccountDiscoveryRunCustody, *, exists: bool) -> str:
    if type(exists) is not bool: raise ScannedSourceRecoveryError(_ERROR)
    return _state_digest(_binding(run), exists=exists)


def _state_digest(binding: dict[str, object], *, exists: bool) -> str:
    return canonical_digest({**binding, "source_exists": exists, "reference_baseline_preserved": True})


def scanned_recovery_summary() -> dict[str, object]:
    """Intended C/P/E only; the reader must establish its current state."""
    return {"Current State": {"original_single_run_verified": True, "original_reply_counts_zero": True,
        "complete_source_and_reference_baseline_match": True, "exclusive_lab_operator_required": True},
        "Proposed Changes": {"delete_owned_source_and_its_results": True, "scan_or_import": False},
        "Expected State": {"owned_source_absent": True, "reference_baseline_preserved": True,
            "general_activity_or_timezone_qualified": False}}


class ScannedSourceRecoveryReader(_OpaqueC3Object):
    """Six fixed GETs, including exact Source presence/absence brackets."""

    def __init__(self, run: AccountDiscoveryRunCustody, guard: UnixDiscoveryOnboardingGuard) -> None:
        try:
            self._binding = _binding(run)
            if (type(guard) is not UnixDiscoveryOnboardingGuard or guard._original_source_path is None
                    or guard._request != run._creation._binding.request or guard._account != run._selected): raise ValueError
            guard.check_transport(run._config)
            self._run, self._guard, self._config = run, guard, run._config
            self._request = run._creation._binding.request
            self._path = "/api/v2/cmdb/secret/discovery/" + quote(self._request.source_name, safe="") + "?vdom=root"
            self._pins = guard._source
            self._closed = False
        except Exception: raise ScannedSourceRecoveryError(_ERROR) from None

    def _validate(self) -> None:
        expected = self._run._creation._binding.request
        if (self._closed or _binding(self._run) != self._binding or self._guard._source != self._pins or self._request != expected
                or self._path != "/api/v2/cmdb/secret/discovery/" + quote(expected.source_name, safe="") + "?vdom=root"):
            raise ValueError
        self._guard.check_transport(self._config)

    def _http(self, method: str, maximum: int) -> tuple[int, bytearray, str]:
        if method != "GET" or maximum != 262_144: raise ValueError
        raw = bytearray()
        try:
            with _private_http_logs(), httpx.Client(base_url=self._config.base_url, verify=_ssl_context(self._config), timeout=self._config.timeout_seconds,
                    follow_redirects=False, trust_env=False) as client:
                with client.stream(method, self._path, headers={"Accept": "application/json", "Accept-Encoding": "identity",
                        "Authorization": "Bearer " + self._config.bearer_token, "Cache-Control": "no-cache, no-store"}) as response:
                    content_type = response.headers.get("content-type", "")
                    if "json" not in content_type.lower() or response.headers.get("content-encoding", "identity").lower() not in {"", "identity"}: raise ValueError
                    for chunk in response.iter_bytes():
                        if len(raw) + len(chunk) > maximum: raise ValueError
                        raw.extend(chunk)
                    result, raw = raw, bytearray()
                    return response.status_code, result, content_type
        finally: _zeroize_mutable(raw)

    def _source(self) -> tuple[bool, str]:
        raw = bytearray()
        try:
            status, raw, _ = self._http("GET", 262_144)
            body = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_nonfinite)
            if type(body) is not dict or status not in {200, 404}: raise ValueError
            for name, expected in dict(version="v7.0.0", build=29, path="secret", name="discovery", vdom="root",
                    http_method="GET", http_status=status, status="success" if status == 200 else "error").items():
                if type(body.get(name)) is not type(expected) or body.get(name) != expected: raise ValueError
            serial = body.get("serial")
            if type(serial) is not str or hashlib.sha256(serial.encode()).hexdigest() != self._run._creation._serial: raise ValueError
            if body.get("limit_reached", False) is not False: raise ValueError
            if "mkey" in body and body["mkey"] != self._request.source_name: raise ValueError
            if status == 404:
                if body.get("results") is not None and body["results"] != []: raise ValueError
                return False, canonical_digest({"source_absent": True})
            row = self._run._row(self._request, body)
            digest = hashlib.sha256(json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
            self._run.inspect_scanned_state(self._request, body)
            return True, digest
        finally: _zeroize_mutable(raw)

    def read(self) -> str:
        try:
            self._validate(); first = self._source()
            key = bytearray(_key(self._run._key_file))
            try: reference = self._guard.observe_original_run_references(self._run, reference_witness_key=key)
            finally: _zeroize_mutable(key)
            last = self._source(); self._validate()
            if first != last or reference != self._binding["reference_baseline"]:
                return canonical_digest({**self._binding, "observed_reference": reference, "source_brackets": [first, last]})
            return _state_digest(self._binding, exists=first[0])
        except Exception: raise ScannedSourceRecoveryError(_ERROR) from None

    def preview(self) -> dict[str, object]:
        if self.read() != scanned_recovery_state_digest(self._run, exists=True): raise ScannedSourceRecoveryError(_ERROR)
        return {"contract": CONTRACT, **scanned_recovery_summary(), "device_write_executed": False}

    def close(self) -> None:
        self._closed = True


@dataclass(frozen=True, slots=True, repr=False)
class OriginalScannedRecoveryObservation(_OpaqueC3Object):
    acknowledgement_qualified: bool
    original_outcome: str
    original_verification: str
    general_activity_or_timezone_qualified: bool = False


class ScannedSourceRecoveryM4Adapter(_OpaqueC3Object):
    """One fixed original DELETE and immutable receipt; authority is external."""

    def __init__(self, reader: ScannedSourceRecoveryReader, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
            store: PersistentM4ExecutionStateStore, directory: Path, witness_key_file: Path, *, clock: Callable[[], int] | None = None,
            before_dispatch: Callable[[], None] | None = None) -> None:
        self._key = bytearray()
        try:
            if (type(reader) is not ScannedSourceRecoveryReader or type(plan) is not M4ExecutionPlan
                    or type(authorization) is not M4ExecutionAuthorization or type(store) is not PersistentM4ExecutionStateStore
                    or not store.monotonic_checkpoint_protocol_bound or clock is not None and not callable(clock)
                    or before_dispatch is not None and not callable(before_dispatch)):
                raise ValueError
            reader._validate(); run = reader._run
            if directory != run._directory.with_name(run._directory.name + "-recovery"): raise ValueError
            _private_directory(directory)
            protected = {run._key_file, run._store._path, run._store._key_path, run._creation._key_file,
                run._creation._store._path, run._creation._store._key_path, *(run._directory / name for name in
                    ("account-run-execution-context.json", "account-run-send.claim.json", "account-run-ack.json", "account-run-state.json")),
                *(run._creation._directory / name for name in ("source-execution-context.json", "source-send.claim.json",
                    "source-create-ack.json", "source-ack-unqualified.json", "source-created-state.json"))}
            paths = (witness_key_file, store._path, store._key_path, directory / _SEND, directory / _ACK,
                run._creation._directory / _OBJECT)
            if len(set(paths)) != len(paths) or any(path in protected for path in paths): raise ValueError
            self._key = bytearray(_key(witness_key_file))
            keys: tuple[bytes | bytearray, ...] = (self._key, store._key, run._key, run._store._key, run._creation._key, run._creation._store._key)
            if any(len(key) != 32 for key in keys) or any(hmac.compare_digest(left, right)
                    for index, left in enumerate(keys) for right in keys[index + 1:]): raise ValueError
            self._reader, self._plan, self._authorization, self._store = reader, plan, authorization, store
            self._directory, self._key_file = directory, witness_key_file
            self._object_claim = run._creation._directory / _OBJECT
            info = directory.stat(); self._directory_identity = (info.st_dev, info.st_ino)
            self._clock = clock if clock is not None else lambda: int(time.time())
            self._before_dispatch = before_dispatch
            self._last = -1; self._sent = self._delete_started = self._ack_consumed = self._closed = False
            self._lock = RLock()
            self._context = canonical_digest(dict(binding=reader._binding, plan=plan.plan_digest, authorization=authorization.authorization_digest))
            self._validate(plan)
        except Exception:
            _zeroize_mutable(self._key); raise ScannedSourceRecoveryError(_ERROR) from None

    def _validate(self, plan: M4ExecutionPlan, *, original_only: bool = False) -> None:
        p, a, r = self._plan, self._authorization, self._reader
        p.__post_init__(); a.__post_init__()
        if original_only:
            if _binding(r._run) != r._binding: raise ValueError
        else: r._validate()
        info = self._directory.stat(); _private_directory(self._directory)
        if (self._closed or plan != p or p.action_id != ACTION_ID or p.action_version != ACTION_VERSION or p.adapter_ref != ADAPTER_REF
                or p.target_ref != "discovery-entry" or p.requester_digest != r._run._plan.requester_digest
                or p.parameters_digest != canonical_digest(r._binding)
                or p.summary_digest != canonical_digest(scanned_recovery_summary())
                or p.expected_current_digest != _state_digest(r._binding, exists=True)
                or p.expected_state_digest != _state_digest(r._binding, exists=False) or p.compensation_ref is not None
                or a.plan_ref != p.plan_ref or a.plan_digest != p.plan_digest or a.requester_digest != p.requester_digest
                or a.confirmation_digest != p.confirmation_digest or a.approval_digest != p.approval_digest
                or a.expires_at > p.expires_at or not 0 < a.expires_at - a.issued_at <= 60
                or not a.one_time or not a.execution_authorized or (info.st_dev, info.st_ino) != self._directory_identity
                or not hmac.compare_digest(_key(self._key_file), self._key)):
            raise ValueError

    def _claim(self) -> M4Claim:
        p, a = self._plan, self._authorization
        return self._store.inspect_claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest, idempotency_digest=p.idempotency_digest,
            authorization_digest=a.authorization_digest, context_digest=canonical_digest(dict(plan_digest=p.plan_digest, authorization_digest=a.authorization_digest, revision=p.revision)))

    def _writing_now(self) -> int:
        self._validate(self._plan); _require_m4_dispatch_ownership(self._plan, self._authorization, self._store)
        if self._claim().result is not None: raise ValueError
        now = self._clock()
        if type(now) is not int or now < self._last or not self._authorization.issued_at <= now < self._authorization.expires_at: raise ValueError
        self._last = now; return now

    def _signature(self, name: str, body: object) -> str:
        return hmac.new(self._key, _DOMAIN + name.encode() + b"\x00" + json.dumps(body, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()

    def _write(self, directory: Path, name: str, body: dict[str, object]) -> None:
        self._writing_now(); _private_directory(directory)
        parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(parent)
            expected = self._directory_identity if directory == self._directory else self._reader._run._creation._directory_identity
            if (info.st_dev, info.st_ino) != expected: raise ValueError
            fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            with os.fdopen(fd, "w") as stream:
                json.dump({**body, "signature": self._signature(name, body)}, stream, sort_keys=True, separators=(",", ":"))
                stream.flush(); os.fsync(stream.fileno())
            os.fsync(parent)
        finally: os.close(parent)

    def _record(self, path: Path, fields: set[str]) -> dict[str, object]:
        self._validate(self._plan, original_only=True); raw = _read(path, 4096)
        try:
            body = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_nonfinite)
            if type(body) is not dict or set(body) != fields | {"signature"}: raise ValueError
            signature = body.pop("signature")
            if type(signature) is not str or not hmac.compare_digest(signature, self._signature(path.name, body)) or body["context_digest"] != self._context: raise ValueError
            for name, value in body.items():
                if name.endswith("_at"):
                    if type(value) is not int or not self._authorization.issued_at <= value < self._authorization.expires_at: raise ValueError
                elif name == "acknowledgement_qualified":
                    if type(value) is not bool: raise ValueError
                else: require_digest(value, "owned_scanned_source_recovery")
            return cast(dict[str, object], body)
        finally: _zeroize_mutable(raw)

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try: self._validate(plan); return self._reader.read()
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        raw = bytearray(); status = None; content_type = ""; truncated = False; complete = False
        try:
            with self._lock:
                self._writing_now()
                if self._sent or self.read_current(plan) != plan.expected_current_digest: raise ValueError
                if self._before_dispatch is not None: self._before_dispatch()
                now = self._writing_now()
                obj = dict(context_digest=self._context, claimed_at=now)
                self._write(self._object_claim.parent, _OBJECT, obj)
                send = dict(context_digest=self._context, object_claim_digest=canonical_digest(obj), claimed_at=now)
                self._write(self._directory, _SEND, send); self._sent = True
                try: status, raw, content_type, truncated, complete = self._delete_http()
                except Exception: pass
                self._writing_now(); qualified = False
                try:
                    body = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_nonfinite)
                    if status != 200 or type(body) is not dict or truncated or not complete: raise ValueError
                    for name, expected in dict(version="v7.0.0", build=29, path="secret", name="discovery", vdom="root",
                            http_method="DELETE", http_status=200).items():
                        if type(body.get(name)) is not type(expected) or body.get(name) != expected: raise ValueError
                    if body.get("status") not in {"success", "OK"} or type(body.get("serial")) is not str: raise ValueError
                    if hashlib.sha256(body["serial"].encode()).hexdigest() != self._reader._run._creation._serial: raise ValueError
                    if "error" in body and (type(body["error"]) is not int or body["error"] != 0): raise ValueError
                    if "mkey" in body and body["mkey"] != self._reader._request.source_name: raise ValueError
                    qualified = True
                except Exception: pass
                self._ack_consumed = True
                self._write(self._directory, _ACK, dict(context_digest=self._context, send_digest=canonical_digest(send),
                    raw_ack_digest=hmac.new(self._key, _DOMAIN + b"reply\x00" + raw, hashlib.sha256).hexdigest(),
                    native_category_digest=canonical_digest(dict(http_status=status, json="json" in content_type.lower(), truncated=truncated, complete=complete)),
                    acknowledgement_qualified=qualified, acknowledged_at=self._writing_now()))
                if not qualified: raise ValueError
        except Exception: raise M4AdapterAmbiguous(_ERROR) from None
        finally: _zeroize_mutable(raw)

    def _delete_http(self) -> tuple[int | None, bytearray, str, bool, bool]:
        self._writing_now()
        if not self._sent or self._delete_started or self._ack_consumed: raise ValueError
        self._record(self._directory / _SEND, {"context_digest", "object_claim_digest", "claimed_at"})
        if self._before_dispatch is not None: self._before_dispatch()
        self._delete_started = True
        config = self._reader._config; raw = bytearray(); status = None; content_type = ""; truncated = complete = False
        try:
            with _private_http_logs(), httpx.Client(base_url=config.base_url, verify=_ssl_context(config), timeout=config.timeout_seconds,
                    follow_redirects=False, trust_env=False) as client:
                with client.stream("DELETE", self._reader._path, headers={"Accept": "application/json", "Accept-Encoding": "identity",
                        "Authorization": "Bearer " + config.bearer_token, "Cache-Control": "no-cache, no-store"}) as response:
                    status = response.status_code; content_type = response.headers.get("content-type", "")
                    if "json" not in content_type.lower() or response.headers.get("content-encoding", "identity").lower() not in {"", "identity"}: raise ValueError
                    for chunk in response.iter_bytes():
                        if len(raw) + len(chunk) > 16_384:
                            raw.extend(chunk[:16_384 - len(raw)]); truncated = True; break
                        raw.extend(chunk)
                    complete = not truncated
        except (httpx.HTTPError, OSError, ValueError): pass
        return status, raw, content_type, truncated, complete

    def inspect_original_result(self) -> OriginalScannedRecoveryObservation:
        try:
            self._validate(self._plan, original_only=True); claim = self._claim()
            obj = self._record(self._object_claim, {"context_digest", "claimed_at"})
            send = self._record(self._directory / _SEND, {"context_digest", "object_claim_digest", "claimed_at"})
            ack = self._record(self._directory / _ACK, {"context_digest", "send_digest", "raw_ack_digest", "native_category_digest", "acknowledgement_qualified", "acknowledged_at"})
            if (send["object_claim_digest"] != canonical_digest(obj) or ack["send_digest"] != canonical_digest(send)
                    or not cast(int, obj["claimed_at"]) == cast(int, send["claimed_at"]) <= cast(int, ack["acknowledged_at"])): raise ValueError
            return OriginalScannedRecoveryObservation(cast(bool, ack["acknowledgement_qualified"]),
                str(claim.result.outcome) if claim.result is not None else "in_progress",
                str(claim.result.verification) if claim.result is not None else "unknown")
        except Exception: raise ScannedSourceRecoveryError(_ERROR) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            self._validate(plan)
            if not self._sent or not self.inspect_original_result().acknowledgement_qualified: raise ValueError
            digest = self._reader.read()
            if digest != plan.expected_state_digest: raise ValueError
            return digest
        except Exception: raise M4AdapterAmbiguous(_ERROR) from None

    def close(self) -> None:
        self._closed = True; _zeroize_mutable(self._key)
