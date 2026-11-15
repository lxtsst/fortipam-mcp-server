"""Prospective original-M4 account Run evidence; no Tool or recovery.

The native fixture digest is private producer input, not fixture qualification.
Original reply/content custody never establishes current activity or latest Run.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from threading import RLock
import time
from typing import cast

from v4_planning import M4AdapterAmbiguous, M4AdapterDenied, M4AdapterFailure, M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.execution_kernel import M4Claim, _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from .discovery_run_http_transport import AccountDiscoveryAck, AccountDiscoveryReplyShape, DiscoveryRunResult, FortiPamDiscoveryRunHttpTransport, _account_reply, _account_reply_shape, _reply_shape_record
from .discovery_source_create_custody import DiscoverySourceCreateCustody
from .discovery_source_scan_preservation import OwnedUnixDiscoveryScanPreservation
from .ldap_server_runtime import _key, _private_directory, _read
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _zeroize_mutable
from .service_account_state_reader import _ca
from .m4_execution_store import PersistentM4ExecutionStateStore
from .discovery_review_http_transport import _unique_pairs, _nonfinite

ACTION_ID = "discovery-account-run"
ACTION_VERSION = "1.0.0"
ADAPTER_REF = "fortipam-700-build29-unix-account-run-original-candidate"
_CONTRACT = "fortipam-build29-original-account-run-custody-v1"
_ERROR = "Original account Discovery Run custody is unavailable."
_DOMAIN = b"fortipam-original-account-run/v1\x00"
_SEND, _ACK, _STATE = "account-run-send.claim.json", "account-run-ack.json", "account-run-state.json"
_SEND_FIELDS = frozenset({"context_digest", "source_before_sha256", "claimed_at"})
_ACK_FIELDS = frozenset({"context_digest", "send_digest", "raw_ack_digest", "native_category_digest", "native_reply_valid", "ongoing_requests", "failed_requests", "acknowledged_at"})
_STATE_FIELDS = frozenset({"context_digest", "ack_digest", "row_digest", "run_result_digest", "original_configuration_preserved", "observed_at"})


class AccountRunCustodyError(ValueError):
    """Fixed refusal without selectors, native state or authentication data."""


def _binding(creation: DiscoverySourceCreateCustody, selected_account: str, fixture_birth_digest: str) -> dict[str, object]:
    if type(creation) is not DiscoverySourceCreateCustody or type(selected_account) is not str or re.fullmatch(r"fpam-bp014-discovery-r[0-9]{9}", selected_account) is None:
        raise AccountRunCustodyError(_ERROR)
    require_digest(fixture_birth_digest, "run_fixture")
    original = creation.inspect_original_state()
    if not original.acknowledgement_qualified or original.original_outcome != "succeeded" or original.original_verification != "verified":
        raise AccountRunCustodyError(_ERROR)
    return dict(contract=_CONTRACT, original_source_custody=original.custody_digest,
        source_parameters=creation._binding.parameters_digest, source_before_sha256=original.legacy_row_sha256,
        selected_account=selected_account, fixture_birth_digest=fixture_birth_digest,
        requester_digest=creation._plan.requester_digest, device_digest=creation._serial)


def account_run_parameters_digest(creation: DiscoverySourceCreateCustody, selected_account: str, fixture_birth_digest: str) -> str:
    return canonical_digest(_binding(creation, selected_account, fixture_birth_digest))


def account_run_state_digest(creation: DiscoverySourceCreateCustody, selected_account: str, fixture_birth_digest: str, *, scanned: bool) -> str:
    if type(scanned) is not bool: raise AccountRunCustodyError(_ERROR)
    return _state_digest(_binding(creation, selected_account, fixture_birth_digest), scanned=scanned)


def _state_digest(binding: dict[str, object], *, scanned: bool) -> str:
    return canonical_digest({**binding,
        "state": "original_zero_reply_and_preserved_scan_content" if scanned else "original_disabled_unscanned_source",
        "current_activity_or_recovery_qualified": False})


@dataclass(frozen=True, slots=True, repr=False)
class OriginalAccountRunObservation(_OpaqueC3Object):
    context_digest: str
    custody_digest: str
    native_reply_valid: bool
    ongoing_requests: int | None
    failed_requests: int | None
    original_configuration_preserved: bool
    original_outcome: str
    original_verification: str
    current_activity_or_recovery_qualified: bool = False
    reply_shape: AccountDiscoveryReplyShape | None = None


class AccountDiscoveryRunCustody(_OpaqueC3Object):
    """Exclusive records only in the original owned Run M4 dispatch."""

    def __init__(self, directory: Path, witness_key_file: Path, creation: DiscoverySourceCreateCustody,
            plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, store: PersistentM4ExecutionStateStore,
            config: SecretMetadataHttpTransportConfig, *, selected_account: str, fixture_birth_digest: str,
            clock: Callable[[], int] | None = None, reference_digest: str | None = None) -> None:
        self._key = bytearray()
        try:
            if (type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization
                    or type(store) is not PersistentM4ExecutionStateStore or not store.monotonic_checkpoint_protocol_bound
                    or type(config) is not SecretMetadataHttpTransportConfig or clock is not None and not callable(clock)):
                raise ValueError
            self._creation, self._binding = creation, _binding(creation, selected_account, fixture_birth_digest)
            if config != creation._config: raise ValueError
            self._directory, self._key_file = Path(directory), Path(witness_key_file)
            _private_directory(self._directory)
            if self._directory == creation._directory: raise ValueError
            info = self._directory.stat(); self._directory_identity = (info.st_dev, info.st_ino)
            files = (self._key_file, store._path, store._key_path, *(self._directory / name for name in (_SEND, _ACK, _STATE)))
            if len(set(files)) != len(files) or self._key_file in (creation._key_file, creation._store._path, creation._store._key_path): raise ValueError
            protected_parent = (creation._key_file, creation._store._path, creation._store._key_path,
                *(creation._directory / name for name in ("source-send.claim.json", "source-create-ack.json", "source-ack-unqualified.json", "source-created-state.json")))
            if any(path in protected_parent for path in (self._key_file, *(self._directory / name for name in (_SEND, _ACK, _STATE)))): raise ValueError
            self._key = bytearray(_key(self._key_file))
            if len(self._key) != 32 or any(hmac.compare_digest(self._key, key) for key in (store._key, creation._key, creation._store._key)):
                raise ValueError
            self._plan, self._authorization, self._store, self._config = plan, authorization, store, config
            if reference_digest is not None: require_digest(reference_digest, "original_run_reference")
            self._reference_digest = reference_digest
            self._selected, self._fixture = selected_account, fixture_birth_digest
            self._clock = clock if clock is not None else lambda: int(time.time())
            self._last = -1
            self._send_started = self._ack_consumed = self._state_consumed = self._closed = False
            self._pin: OwnedUnixDiscoveryScanPreservation | None = None
            self._lock = RLock()
            self._context = self._context_digest()
            self._validate()
        except Exception:
            _zeroize_mutable(self._key)
            raise AccountRunCustodyError(_ERROR) from None

    def _context_digest(self) -> str:
        ca = _ca(self._config)
        context: dict[str, object] = dict(binding=self._binding, plan=self._plan.plan_digest, authorization=self._authorization.authorization_digest,
            transport=hmac.new(self._key, json.dumps(asdict(self._config), sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest(),
            ca_sha256=None if ca is None else hashlib.sha256(ca).hexdigest())
        if self._reference_digest is not None: context["original_reference_digest"] = self._reference_digest
        return canonical_digest(context)

    def inspect_reference_baseline(self) -> str | None:
        """Read original evidence only; no fresh relation or recovery qualification."""
        try:
            self._validate()
            return self._reference_digest
        except Exception:
            raise AccountRunCustodyError(_ERROR) from None

    def _validate(self) -> None:
        p, a, c = self._plan, self._authorization, self._creation
        p.__post_init__(); a.__post_init__()
        binding = _binding(c, self._selected, self._fixture)
        if (self._closed or binding != self._binding
                or p.action_id != ACTION_ID or p.action_version != ACTION_VERSION or p.adapter_ref != ADAPTER_REF
                or p.target_ref != "discovery-entry" or p.requester_digest != c._plan.requester_digest
                or p.parameters_digest != canonical_digest(binding)
                or p.expected_current_digest != _state_digest(binding, scanned=False)
                or p.expected_state_digest != _state_digest(binding, scanned=True)
                or p.compensation_ref is not None or a.plan_ref != p.plan_ref or a.plan_digest != p.plan_digest
                or a.requester_digest != p.requester_digest or a.confirmation_digest != p.confirmation_digest
                or a.approval_digest != p.approval_digest or a.expires_at > p.expires_at
                or self._config != c._config or self._context_digest() != self._context):
            raise ValueError
        _private_directory(self._directory)
        info = self._directory.stat()
        if (info.st_dev, info.st_ino) != self._directory_identity or not hmac.compare_digest(_key(self._key_file), self._key): raise ValueError

    def matches_transport(self, config: SecretMetadataHttpTransportConfig) -> bool:
        try: self._validate(); return config == self._config
        except Exception: return False

    def _claim(self) -> M4Claim:
        self._validate(); p, a = self._plan, self._authorization
        return self._store.inspect_claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest, idempotency_digest=p.idempotency_digest,
            authorization_digest=a.authorization_digest, context_digest=canonical_digest(dict(plan_digest=p.plan_digest, authorization_digest=a.authorization_digest, revision=p.revision)))

    def _writing_now(self) -> int:
        self._validate(); _require_m4_dispatch_ownership(self._plan, self._authorization, self._store)
        if self._claim().result is not None: raise ValueError
        now = self._clock()
        if type(now) is not int or now < self._last or not self._authorization.issued_at <= now < self._authorization.expires_at: raise ValueError
        self._last = now; return now

    def _signature(self, name: str, body: object) -> str:
        return hmac.new(self._key, _DOMAIN + name.encode() + b"\x00" + json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(), hashlib.sha256).hexdigest()

    def _write(self, name: str, body: dict[str, object]) -> None:
        self._validate(); descriptor = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if ((info.st_dev, info.st_ino) != self._directory_identity or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700): raise ValueError
            fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
            with os.fdopen(fd, "w") as stream:
                json.dump({**body, "signature": self._signature(name, body)}, stream, sort_keys=True, separators=(",", ":")); stream.flush(); os.fsync(stream.fileno())
            os.fsync(descriptor)
        finally: os.close(descriptor)

    def _record(self, name: str, fields: frozenset[str]) -> dict[str, object]:
        self._validate(); raw = _read(self._directory / name, 4096)
        try:
            self._validate(); body = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_nonfinite)
            allowed = (fields | {"signature"}, fields | {"signature", "reply_shape"}) if name == _ACK else (fields | {"signature"},)
            if type(body) is not dict or frozenset(body) not in allowed: raise ValueError
            signature = body.pop("signature")
            if type(signature) is not str or not hmac.compare_digest(signature, self._signature(name, body)) or body["context_digest"] != self._context: raise ValueError
            for field, value in body.items():
                if field.endswith("_at"):
                    if type(value) is not int or not self._authorization.issued_at <= value < self._authorization.expires_at: raise ValueError
                elif field in {"native_reply_valid", "original_configuration_preserved"}:
                    if type(value) is not bool: raise ValueError
                elif field in {"ongoing_requests", "failed_requests"}:
                    if value is not None and (type(value) is not int or value < 0): raise ValueError
                elif field == "reply_shape": _reply_shape_record(value)
                else: require_digest(value, "account_run_record")
            if name == _ACK and (body["native_reply_valid"] is not (body["ongoing_requests"] is not None and body["failed_requests"] is not None)): raise ValueError
            if name == _ACK and "reply_shape" in body:
                shape = _reply_shape_record(body["reply_shape"])
                if body["native_reply_valid"] and (shape.http_status != 200 or not shape.json_content
                        or not shape.response_complete or shape.truncated or shape.json_category != "object"
                        or shape.status_category == "error" or shape.error_category == "nonzero"
                        or shape.ongoing_kind not in {"integer", "decimal_text"} or shape.failed_kind not in {"integer", "decimal_text"}): raise ValueError
            return cast(dict[str, object], body)
        finally: _zeroize_mutable(raw)

    def _row(self, request: DisabledUnixDiscoveryCreateInput, payload: object) -> dict[str, object]:
        if request != self._creation._binding.request or type(payload) is not dict: raise ValueError
        self._creation.check_read_device(payload, table="discovery")
        rows = payload.get("results")
        if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict or rows[0].get("name") != request.source_name: raise ValueError
        return cast(dict[str, object], rows[0])

    def begin_original_send(self, request: DisabledUnixDiscoveryCreateInput, config: SecretMetadataHttpTransportConfig, payload: object) -> None:
        try:
            with self._lock:
                now = self._writing_now()
                row = self._row(request, payload)
                digest = hashlib.sha256(json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
                if self._send_started or config != self._config or digest != self._binding["source_before_sha256"]: raise ValueError
                self._pin = self._creation.bind_scan_preservation(cast(Mapping[str, object], payload), self._selected, fixture_birth_digest=self._fixture)
                self._writing_now(); self._write(_SEND, dict(context_digest=self._context, source_before_sha256=digest, claimed_at=now)); self._send_started = True
        except Exception:
            self.close(); raise AccountRunCustodyError(_ERROR) from None

    def inspect_unscanned_state(self, request: DisabledUnixDiscoveryCreateInput, payload: object) -> str:
        """Pure current-state comparison; cannot produce an original record."""
        try:
            with self._lock:
                self._validate(); row = self._row(request, payload)
                digest = hashlib.sha256(json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
                if digest != self._binding["source_before_sha256"]:
                    return canonical_digest({**self._binding, "observed_source_sha256": digest, "state": "source_drift"})
                return self._plan.expected_current_digest
        except Exception: raise AccountRunCustodyError(_ERROR) from None

    def capture_original_ack(self, raw: bytearray, *, http_status: int | None, content_type: str, complete: bool, truncated: bool = False) -> None:
        try:
            with self._lock:
                now = self._writing_now()
                if not self._send_started or self._ack_consumed or type(raw) is not bytearray or len(raw) > 16_384 or type(truncated) is not bool or type(complete) is not bool: raise ValueError
                self._ack_consumed = True; send = self._record(_SEND, _SEND_FIELDS)
                shape = _account_reply_shape(raw, http_status, content_type, complete=complete, truncated=truncated)
                try: ack = _account_reply(raw, http_status, content_type, truncated=truncated, complete=complete)
                except Exception: ack = None
                self._writing_now(); self._write(_ACK, dict(context_digest=self._context, send_digest=canonical_digest(send),
                    raw_ack_digest=hmac.new(self._key, _DOMAIN + b"reply\x00" + raw, hashlib.sha256).hexdigest(),
                    native_category_digest=canonical_digest(dict(http_status=http_status, json="json" in content_type.lower(), truncated=truncated)),
                    reply_shape=asdict(shape), native_reply_valid=ack is not None, ongoing_requests=None if ack is None else ack.ongoing_requests,
                    failed_requests=None if ack is None else ack.failed_requests, acknowledged_at=now))
        except Exception:
            self.close(); raise AccountRunCustodyError(_ERROR) from None
        finally:
            if type(raw) is bytearray: _zeroize_mutable(raw)

    def capture_original_state(self, request: DisabledUnixDiscoveryCreateInput, payload: object, result: DiscoveryRunResult) -> None:
        try:
            with self._lock:
                now = self._writing_now()
                if not self._send_started or not self._ack_consumed or self._state_consumed or type(result) is not DiscoveryRunResult: raise ValueError
                self._state_consumed = True; row = self._row(request, payload); ack = self._record(_ACK, _ACK_FIELDS)
                if result.account_ack is not None:
                    if type(result.account_ack) is not AccountDiscoveryAck: raise ValueError
                    result.account_ack.__post_init__()
                if ((result.account_ack is None) is not (ack["native_reply_valid"] is False)
                        or result.account_ack is not None and (result.account_ack.ongoing_requests != ack["ongoing_requests"] or result.account_ack.failed_requests != ack["failed_requests"])): raise ValueError
                preserved = False
                if self._pin is None: raise ValueError
                try:
                    self._pin.accept_completed_scan(cast(Mapping[str, object], payload), result,
                        actor_digest=self._creation._plan.requester_digest, device_digest=self._creation._serial, fixture_birth_digest=self._fixture)
                    preserved = True
                except RuntimeError: pass
                encoded = json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
                if len(encoded) > 262_144: raise ValueError
                self._writing_now(); self._write(_STATE, dict(context_digest=self._context, ack_digest=canonical_digest(ack),
                    row_digest=hmac.new(self._key, _DOMAIN + b"row\x00" + encoded, hashlib.sha256).hexdigest(),
                    run_result_digest=canonical_digest(asdict(result)), original_configuration_preserved=preserved, observed_at=now))
        except Exception:
            self.close(); raise AccountRunCustodyError(_ERROR) from None

    def inspect_original_state(self) -> OriginalAccountRunObservation:
        try:
            with self._lock:
                claim = self._claim(); send = self._record(_SEND, _SEND_FIELDS); ack = self._record(_ACK, _ACK_FIELDS); state = self._record(_STATE, _STATE_FIELDS)
                if (send["source_before_sha256"] != self._binding["source_before_sha256"] or ack["send_digest"] != canonical_digest(send)
                        or state["ack_digest"] != canonical_digest(ack) or not cast(int, send["claimed_at"]) <= cast(int, ack["acknowledged_at"]) <= cast(int, state["observed_at"])): raise ValueError
                return OriginalAccountRunObservation(self._context, canonical_digest(state), cast(bool, ack["native_reply_valid"]),
                    cast(int | None, ack["ongoing_requests"]), cast(int | None, ack["failed_requests"]), cast(bool, state["original_configuration_preserved"]),
                    str(claim.result.outcome) if claim.result is not None else "in_progress", str(claim.result.verification) if claim.result is not None else "unknown",
                    reply_shape=None if "reply_shape" not in ack else _reply_shape_record(ack["reply_shape"]))
        except Exception: raise AccountRunCustodyError(_ERROR) from None

    def inspect_scanned_state(self, request: DisabledUnixDiscoveryCreateInput, payload: object) -> str:
        """Compare a fresh complete row to original positive Run content only."""
        try:
            with self._lock:
                original = self.inspect_original_state(); row = self._row(request, payload)
                if (not original.native_reply_valid or original.ongoing_requests != 0 or original.failed_requests != 0
                        or not original.original_configuration_preserved): raise ValueError
                state = self._record(_STATE, _STATE_FIELDS)
                encoded = json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
                if len(encoded) > 262_144 or not hmac.compare_digest(cast(str, state["row_digest"]),
                        hmac.new(self._key, _DOMAIN + b"row\x00" + encoded, hashlib.sha256).hexdigest()): raise ValueError
                return self._plan.expected_state_digest
        except Exception: raise AccountRunCustodyError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            if self._pin is not None: self._pin.close()
            _zeroize_mutable(self._key)


class AccountDiscoveryRunM4Adapter:
    """One unregistered original Run candidate; no recovery dispatch."""

    def __init__(self, custody: AccountDiscoveryRunCustody, transport: FortiPamDiscoveryRunHttpTransport,
            *, before_dispatch: Callable[[], None] | None = None, after_readback: Callable[[], None] | None = None) -> None:
        if (type(custody) is not AccountDiscoveryRunCustody or type(transport) is not FortiPamDiscoveryRunHttpTransport
                or transport._original_custody is not custody or not custody.matches_transport(transport._config)
                or before_dispatch is not None and not callable(before_dispatch)
                or after_readback is not None and not callable(after_readback)):
            raise M4AdapterDenied(_ERROR)
        self._custody, self._transport, self._dispatched = custody, transport, False
        self._before_dispatch = before_dispatch
        self._after_readback = after_readback

    def _validate(self, plan: M4ExecutionPlan) -> None:
        try:
            self._custody._validate()
            if plan != self._custody._plan or self._transport._original_custody is not self._custody: raise ValueError
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def _request(self) -> DisabledUnixDiscoveryCreateInput:
        request = self._custody._creation._binding.request
        if type(request) is not DisabledUnixDiscoveryCreateInput: raise M4AdapterDenied(_ERROR)
        return request

    def read_current(self, plan: M4ExecutionPlan) -> str:
        self._validate(plan); request = self._request()
        try: return self._custody.inspect_unscanned_state(request, self._transport._read_full_source(request))
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        self._validate(plan)
        if self._dispatched: raise M4AdapterDenied(_ERROR)
        try: self._custody._writing_now()
        except Exception: raise M4AdapterDenied(_ERROR) from None
        self._dispatched = True
        try:
            if self.read_current(plan) != plan.expected_current_digest: raise M4AdapterDenied(_ERROR)
            if self._before_dispatch is not None: self._before_dispatch()
            self._transport.run_once(self._request())
        except Exception: raise M4AdapterAmbiguous(_ERROR) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        self._validate(plan)
        if not self._dispatched: raise M4AdapterFailure(_ERROR)
        request = self._request()
        try:
            digest = self._custody.inspect_scanned_state(request, self._transport._read_full_source(request))
            if self._after_readback is not None: self._after_readback()
            return digest
        except Exception: raise M4AdapterAmbiguous(_ERROR) from None
