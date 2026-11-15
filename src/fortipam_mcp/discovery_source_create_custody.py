"""Prospective original-M4 Unix Source custody; no HTTP, issuer or recovery.

Signed observations preserve the actual original send, bounded ACK metadata and
full immediate row pin. An unqualified ACK remains unqualified, even when the
existing create adapter independently verifies that the Source now exists.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
from threading import RLock
import time
from typing import TYPE_CHECKING, cast

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.execution_kernel import M4Claim, _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from .discovery_entry_m4_adapter import ACTION_ID, ACTION_VERSION, UNIX_ADAPTER_REF, DiscoveryEntryBinding
from .discovery_entry_projection import project_discovery_entry_detail
from .ldap_server_runtime import _key, _private_directory, _read
from .local_user_reset_projection import _object_spans
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _json_value_end, _skip_json_space, _zeroize_mutable

if TYPE_CHECKING:
    from .discovery_source_scan_preservation import OwnedUnixDiscoveryScanPreservation


_ERROR = "Original Unix Discovery Source custody is unavailable."
_DOMAIN = b"unix-discovery-source-original-custody/v1\x00"
_SEND, _ACK, _REJECTED, _STATE = "source-send.claim.json", "source-create-ack.json", "source-ack-unqualified.json", "source-created-state.json"
_ACK_FIELDS = frozenset({"version", "build", "http_method", "http_status", "status", "path", "name", "vdom", "serial", "mkey", "error", "revision"})
_ACK_REQUIRED = _ACK_FIELDS - {"error", "revision"}
_DETAIL = frozenset({"name", "source-type", "discovery-type", "schedule-status", "auto-onboarding", "discovery-method", "discovery-secret", "last-discovery-time", "q_origin_key"})
_ACK_RECORD = frozenset({"context_digest", "send_digest", "acknowledgement_digest", "native_category_digest", "acknowledged_at"})


class DiscoverySourceCustodyError(ValueError):
    """Fixed refusal without selectors, native records or authentication data."""


@dataclass(frozen=True, slots=True, repr=False)
class OriginalDiscoverySourceObservation(_OpaqueC3Object):
    context_digest: str
    custody_digest: str
    row_digest: str
    legacy_row_sha256: str
    acknowledgement_qualified: bool
    original_outcome: str
    original_verification: str


class DiscoverySourceCreateCustody(_OpaqueC3Object):
    """Write only inside the original owned M4 dispatch; inspect after expiry."""

    def __init__(self, directory: Path, witness_key_file: Path, binding: DiscoveryEntryBinding,
                 plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
                 store: PersistentM4ExecutionStateStore, config: SecretMetadataHttpTransportConfig,
                 *, serial_digest: str, reference_digest: str,
                 clock: Callable[[], int] | None = None) -> None:
        self._key = bytearray()
        try:
            if (type(binding) is not DiscoveryEntryBinding or type(binding.request) is not DisabledUnixDiscoveryCreateInput
                    or type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization
                    or type(store) is not PersistentM4ExecutionStateStore or not store.monotonic_checkpoint_protocol_bound
                    or type(config) is not SecretMetadataHttpTransportConfig or clock is not None and not callable(clock)):
                raise ValueError
            require_digest(serial_digest, "source_serial")
            require_digest(reference_digest, "source_reference")
            self._directory, self._key_file = Path(directory), Path(witness_key_file)
            _private_directory(self._directory)
            info = self._directory.stat()
            self._directory_identity = (info.st_dev, info.st_ino)
            files = (self._key_file, store._path, store._key_path, *(self._directory / n for n in (_SEND, _ACK, _REJECTED, _STATE)))
            if len(set(files)) != len(files):
                raise ValueError
            self._key = bytearray(_key(self._key_file))
            if hmac.compare_digest(self._key, store._key):
                raise ValueError
            self._binding, self._plan, self._authorization, self._store, self._config = binding, plan, authorization, store, config
            self._serial, self._reference = serial_digest, reference_digest
            self._context = self._context_digest()
            self._clock = clock if clock is not None else lambda: int(time.time())
            self._last_now = -1
            self._send_started = self._ack_consumed = self._state_consumed = self._closed = False
            self._ack_qualified: bool | None = None
            self._lock = RLock()
            self._validate()
        except Exception:
            _zeroize_mutable(self._key)
            raise DiscoverySourceCustodyError(_ERROR) from None

    def _context_digest(self) -> str:
        return canonical_digest({"plan": self._plan.plan_digest,
            "authorization": self._authorization.authorization_digest,
            "parameters": self._binding.parameters_digest, "serial": self._serial, "reference": self._reference,
            "transport": hmac.new(self._key, json.dumps(asdict(self._config), sort_keys=True,
                separators=(",", ":")).encode(), hashlib.sha256).hexdigest()})

    def _validate(self) -> None:
        p, a, b = self._plan, self._authorization, self._binding
        p.__post_init__(); a.__post_init__(); b.__post_init__()
        if (p.action_id != ACTION_ID or p.action_version != ACTION_VERSION or p.adapter_ref != UNIX_ADAPTER_REF
                or p.target_ref != "discovery-entry" or p.parameters_digest != b.parameters_digest
                or p.expected_current_digest != b.state_digest(exists=False) or p.expected_state_digest != b.state_digest(exists=True)
                or p.compensation_ref is not None or a.plan_ref != p.plan_ref or a.plan_digest != p.plan_digest
                or a.requester_digest != p.requester_digest or a.confirmation_digest != p.confirmation_digest
                or a.approval_digest != p.approval_digest or a.expires_at > p.expires_at
                or self._context != self._context_digest()):
            raise ValueError
        _private_directory(self._directory)
        info = self._directory.stat()
        if (info.st_dev, info.st_ino) != self._directory_identity or not hmac.compare_digest(_key(self._key_file), self._key):
            raise ValueError

    def matches_transport(self, config: SecretMetadataHttpTransportConfig) -> bool:
        try:
            self._validate()
            return type(config) is SecretMetadataHttpTransportConfig and config == self._config
        except Exception:
            return False

    def check_read_device(self, payload: object, *, table: str) -> None:
        """Check fixed reference/read origin before any original Source POST."""
        try:
            self._validate()
            if type(payload) is not dict or table not in {"database", "target", "discovery"}:
                raise ValueError
            expected = dict(version="v7.0.0", build=29, path="secret", name=table,
                http_method="GET", http_status=200, vdom="root")
            for key, value in expected.items():
                if type(payload.get(key)) is not type(value) or payload.get(key) != value: raise ValueError
            serial = payload.get("serial")
            if (type(serial) is not str or not 1 <= len(serial) <= 128
                    or hashlib.sha256(serial.encode()).hexdigest() != self._serial
                    or payload.get("status") not in {"success", "OK"} or payload.get("limit_reached", False) is not False):
                raise ValueError
            if "error" in payload and (type(payload["error"]) is not int or payload["error"] != 0):
                raise ValueError
        except Exception:
            raise DiscoverySourceCustodyError(_ERROR) from None

    def _original_claim(self) -> M4Claim:
        self._validate()
        p, a = self._plan, self._authorization
        return self._store.inspect_claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest,
            idempotency_digest=p.idempotency_digest, authorization_digest=a.authorization_digest,
            context_digest=canonical_digest({"plan_digest": p.plan_digest,
                "authorization_digest": a.authorization_digest, "revision": p.revision}))

    def _writing_now(self) -> int:
        if self._closed:
            raise ValueError
        self._validate()
        _require_m4_dispatch_ownership(self._plan, self._authorization, self._store)
        if self._original_claim().result is not None:
            raise ValueError
        now = self._clock()
        if type(now) is not int or now < self._last_now or not self._authorization.issued_at <= now < self._authorization.expires_at:
            raise ValueError
        self._last_now = now
        return now

    def _signature(self, phase: str, body: dict[str, object]) -> str:
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return hmac.new(self._key, _DOMAIN + phase.encode() + b"\x00" + raw, hashlib.sha256).hexdigest()

    def _write(self, name: str, body: dict[str, object]) -> None:
        self._validate()
        directory = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if ((info.st_dev, info.st_ino) != self._directory_identity or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError
            fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, "w") as stream:
                json.dump({**body, "signature": self._signature(name, body)}, stream, sort_keys=True, separators=(",", ":"))
                stream.flush(); os.fsync(stream.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)

    def _record(self, name: str, fields: frozenset[str]) -> dict[str, object]:
        from . import secret_bulk_import_metadata as metadata
        self._validate()
        raw = _read(self._directory / name, 4096)
        try:
            self._validate()
            left = _skip_json_space(raw, 0); right = _json_value_end(raw, left)
            if _skip_json_space(raw, right) != len(raw):
                raise ValueError
            metadata._validate_json(raw, left, right, depth=0, budget=[1000])
            spans = _object_spans(raw, left, right)
            if set(spans) != fields | {"signature"}:
                raise ValueError
            body = {key: metadata._scalar(raw, value) for key, value in spans.items()}
            signature = body.pop("signature")
            for key, value in body.items():
                if key.endswith("_at"):
                    if type(value) is not int or not self._authorization.issued_at <= value < self._authorization.expires_at:
                        raise ValueError
                else:
                    if type(value) is not str:
                        raise ValueError
                    require_digest(value, "source_custody_record")
            if body["context_digest"] != self._context or type(signature) is not str or not hmac.compare_digest(signature, self._signature(name, body)):
                raise ValueError
            return body
        finally:
            _zeroize_mutable(raw)

    def begin_original_send(self, request: DisabledUnixDiscoveryCreateInput,
                            config: SecretMetadataHttpTransportConfig, reference_digest: str) -> None:
        try:
            with self._lock:
                now = self._writing_now()
                if self._send_started or request != self._binding.request or config != self._config or reference_digest != self._reference:
                    raise ValueError
                self._write(_SEND, {"context_digest": self._context, "reference_digest": reference_digest,
                    "expected_absence_digest": self._plan.expected_current_digest, "claimed_at": now})
                self._send_started = True
        except Exception:
            self._closed = True
            raise DiscoverySourceCustodyError(_ERROR) from None

    def _consume_ack(self, raw: bytearray, http_status: int | None, content_type: str) -> str:
        from . import secret_bulk_import_metadata as metadata
        if (type(raw) is not bytearray or not 0 < len(raw) <= 16_384 or type(http_status) is not int
                or http_status != 200 or "json" not in content_type.lower()):
            raise ValueError
        left = _skip_json_space(raw, 0); right = _json_value_end(raw, left)
        if _skip_json_space(raw, right) != len(raw):
            raise ValueError
        metadata._validate_json(raw, left, right, depth=0, budget=[5000])
        spans = metadata._object_spans(raw, left, right, _ACK_FIELDS)
        if not _ACK_REQUIRED <= spans.keys():
            raise ValueError
        expected = dict(version="v7.0.0", build=29, http_method="POST", http_status=200,
            path="secret", name="discovery", vdom="root", mkey=self._binding.request.source_name)
        for key, value in expected.items():
            actual = metadata._scalar(raw, spans[key])
            if type(actual) is not type(value) or actual != value:
                raise ValueError
        status = metadata._scalar(raw, spans["status"])
        if type(status) is not str or status not in {"success", "OK"}:
            raise ValueError
        if "error" in spans:
            error = metadata._scalar(raw, spans["error"])
            if type(error) is not int or error != 0:
                raise ValueError
        serial = metadata._scalar(raw, spans["serial"])
        if type(serial) is not str or not 1 <= len(serial) <= 128 or hashlib.sha256(serial.encode()).hexdigest() != self._serial:
            raise ValueError
        return hmac.new(self._key, _DOMAIN + b"ack\x00" + raw, hashlib.sha256).hexdigest()

    def capture_original_ack(self, raw: bytearray, *, http_status: int | None, content_type: str) -> bool:
        """Record qualified/rejected original metadata; never upgrade by post-read."""
        try:
            with self._lock:
                now = self._writing_now()
                if (type(raw) is not bytearray or len(raw) > 16_384 or type(content_type) is not str
                        or not self._send_started or self._ack_consumed):
                    raise ValueError
                self._ack_consumed = True
                send = self._record(_SEND, frozenset({"context_digest", "reference_digest", "expected_absence_digest", "claimed_at"}))
                try:
                    digest = self._consume_ack(raw, http_status, content_type)
                    qualified = True
                except Exception:
                    digest = hmac.new(self._key, _DOMAIN + b"unqualified-ack\x00" + raw, hashlib.sha256).hexdigest()
                    qualified = False
                self._writing_now()
                self._write(_ACK if qualified else _REJECTED, {"context_digest": self._context,
                    "send_digest": canonical_digest(send), "acknowledgement_digest": digest,
                    "native_category_digest": canonical_digest({"http_status": http_status
                        if type(http_status) is int and 100 <= http_status <= 599 else None,
                        "json": "json" in content_type.lower()}), "acknowledged_at": now})
                self._ack_qualified = qualified
                return qualified
        except Exception:
            self._closed = True
            raise DiscoverySourceCustodyError(_ERROR) from None
        finally:
            if type(raw) is bytearray:
                _zeroize_mutable(raw)

    def capture_original_state(self, request: DisabledUnixDiscoveryCreateInput, payload: object) -> None:
        """Seal the immediate original row even if its ACK was unqualified."""
        try:
            with self._lock:
                now = self._writing_now()
                if (not self._send_started or self._ack_qualified is None or self._state_consumed
                        or request != self._binding.request or type(payload) is not dict):
                    raise ValueError
                self._state_consumed = True
                rows = payload.get("results")
                if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict:
                    raise ValueError
                row = rows[0]
                projected = {**payload, "results": [{k: v for k, v in row.items() if k in _DETAIL}]}
                result = project_discovery_entry_detail(projected, expected_name=request.source_name,
                    expected_secret_id=request.discovery_secret_id, expected_source_type="Unix-like")
                serial = payload.get("serial")
                if (not result.create_readback_verified or type(serial) is not str
                        or hashlib.sha256(serial.encode()).hexdigest() != self._serial):
                    raise ValueError
                encoded = json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
                if len(encoded) > 262_144:
                    raise ValueError
                ack_name = _ACK if self._ack_qualified else _REJECTED
                ack = self._record(ack_name, _ACK_RECORD)
                self._writing_now()
                self._write(_STATE, {"context_digest": self._context, "ack_digest": canonical_digest(ack),
                    "row_digest": hmac.new(self._key, _DOMAIN + b"row\x00" + encoded, hashlib.sha256).hexdigest(),
                    "legacy_row_sha256": hashlib.sha256(encoded).hexdigest(),
                    "row_shape_digest": canonical_digest(sorted(row)), "verified_at": now})
        except Exception:
            self._closed = True
            raise DiscoverySourceCustodyError(_ERROR) from None

    def inspect_original_state(self) -> OriginalDiscoverySourceObservation:
        """Read immutable original custody; return the original terminal status."""
        try:
            with self._lock:
                claim = self._original_claim()
                send = self._record(_SEND, frozenset({"context_digest", "reference_digest", "expected_absence_digest", "claimed_at"}))
                qualified = (self._directory / _ACK).exists()
                if qualified == (self._directory / _REJECTED).exists():
                    raise ValueError
                ack = self._record(_ACK if qualified else _REJECTED, _ACK_RECORD)
                state = self._record(_STATE, frozenset({"context_digest", "ack_digest", "row_digest", "legacy_row_sha256", "row_shape_digest", "verified_at"}))
                if (ack["send_digest"] != canonical_digest(send) or state["ack_digest"] != canonical_digest(ack)
                        or send["reference_digest"] != self._reference or send["expected_absence_digest"] != self._plan.expected_current_digest
                        or not cast(int, send["claimed_at"]) <= cast(int, ack["acknowledged_at"]) <= cast(int, state["verified_at"])):
                    raise ValueError
                return OriginalDiscoverySourceObservation(self._context, canonical_digest(state), cast(str, state["row_digest"]),
                    cast(str, state["legacy_row_sha256"]), qualified,
                    str(claim.result.outcome) if claim.result is not None else "in_progress",
                    str(claim.result.verification) if claim.result is not None else "unknown")
        except Exception:
            raise DiscoverySourceCustodyError(_ERROR) from None

    def bind_scan_preservation(self, original_source: Mapping[str, object], selected_account: str,
                               *, fixture_birth_digest: str) -> OwnedUnixDiscoveryScanPreservation:
        """Join original positive custody to content preservation, never Scan rights.

        The native fixture digest is private producer input. This does not
        qualify its current existence, latest-run scope, or recovery authority.
        """
        from .discovery_entry_create_http_transport import DiscoveryEntryCreateResult
        from .discovery_source_scan_preservation import OwnedUnixDiscoveryScanPreservation
        try:
            with self._lock:
                original = self.inspect_original_state()
                request = self._binding.request
                if (not original.acknowledgement_qualified or original.original_outcome != "succeeded"
                        or original.original_verification != "verified" or type(request) is not DisabledUnixDiscoveryCreateInput):
                    raise ValueError
                rows = original_source.get("results")
                if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict:
                    raise ValueError
                row = rows[0]
                encoded = json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
                if len(encoded) > 262_144 or hashlib.sha256(encoded).hexdigest() != original.legacy_row_sha256:
                    raise ValueError
                projected = {**original_source, "results": [{k: v for k, v in row.items() if k in _DETAIL}]}
                readback = project_discovery_entry_detail(projected, expected_name=request.source_name,
                    expected_secret_id=request.discovery_secret_id, expected_source_type="Unix-like")
                return OwnedUnixDiscoveryScanPreservation(request, selected_account,
                    actor_digest=self._plan.requester_digest, device_digest=self._serial,
                    fixture_birth_digest=fixture_birth_digest,
                    creation=DiscoveryEntryCreateResult(True, "http_200", 200, readback),
                    original_source=original_source, key=self._key)
        except Exception:
            raise DiscoverySourceCustodyError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            _zeroize_mutable(self._key)
