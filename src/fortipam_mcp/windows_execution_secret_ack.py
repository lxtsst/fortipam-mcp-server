"""Private original-dispatch Windows execution Secret ACK and metadata custody.

No HTTP client, authority issuer, Tool or recovery writer is provided. Reusing
the CMDB byte grammar does not import Web profile authority. Original missing
ACK, partial records and terminal UNKNOWN never permit creation replay.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
from threading import RLock
from typing import cast
import uuid

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import MaterialLeaseRequest, MaterialProviderClass, MaterialPurpose, _OpaqueC3Object
from v4_planning.material_runtime import material_lease_request_digest
from v4_planning.models import require_digest

from . import secret_bulk_import_metadata as parser
from .ldap_server_runtime import _key, _private_directory, _read
from .local_user_reset_projection import _object_spans
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _json_value_end, _skip_json_space, _zeroize_mutable,
)
from .web_secret_create_ack import _consume_database_create_ack_metadata
from .windows_execution_secret_contract import (
    CONTRACT, REQUEST_UUID, WindowsExecutionSecretBinding, WindowsExecutionSecretDefaults,
    WindowsExecutionSecretMetadata, _proposed_metadata, consume_windows_execution_secret_metadata,
)
from .windows_execution_secret_material import (
    ADAPTER_REF, TARGET_REF, _OriginalDispatch, windows_execution_secret_parameters_digest,
)

_ERROR = "The private original Windows execution Secret acknowledgement is unavailable."
_DOMAIN = b"windows-execution-secret-create-custody/v1\x00"
_MATERIAL_KEY_DOMAIN = b"windows-execution-secret-material-witness/v1\x00"
_USERNAME_DOMAIN = b"windows-execution-secret-username-token/v1\x00"
_SEND, _ACK, _METADATA = "create.send.json", "create.ack.json", "create.metadata.json"
_SEND_FIELDS = frozenset({"context_digest", "body_digest", "username_digest", "password_digest", "sent_at"})
_ACK_FIELDS = frozenset({"context_digest", "send_digest", "native_secret_id", "ack_digest", "acknowledged_at"})
_METADATA_FIELDS = frozenset({"context_digest", "ack_record_digest", "native_secret_id", "native_uuid",
                            "state_digest", "observed_at"})


class WindowsExecutionSecretAckError(RuntimeError):
    """A categorical refusal without raw values, selectors or source content."""


@dataclass(frozen=True, slots=True, repr=False)
class WindowsExecutionSecretOriginalCreation(_OpaqueC3Object):
    """Private observation only; no ownership promotion or deletion authority."""

    native_secret_id: int
    native_uuid: str | None
    state_digest: str | None
    custody_digest: str
    original_outcome: str
    original_verification: str


class WindowsExecutionSecretAckCustody(_OpaqueC3Object):
    def __init__(self, directory: Path, witness_key_file: Path, *,
            config: SecretMetadataHttpTransportConfig, profile: WindowsExecutionSecretBinding,
            defaults: WindowsExecutionSecretDefaults, plan: M4ExecutionPlan,
            authorization: M4ExecutionAuthorization, request: MaterialLeaseRequest,
            execution_store: PersistentM4ExecutionStateStore, material_store: PersistentMaterialUseStateStore,
            clock: Callable[[], int]) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or type(profile) is not WindowsExecutionSecretBinding
                    or type(defaults) is not WindowsExecutionSecretDefaults or type(plan) is not M4ExecutionPlan
                    or type(authorization) is not M4ExecutionAuthorization or type(request) is not MaterialLeaseRequest
                    or type(execution_store) is not PersistentM4ExecutionStateStore
                    or type(material_store) is not PersistentMaterialUseStateStore or not callable(clock)
                    or not execution_store.monotonic_checkpoint_protocol_bound
                    or not material_store.monotonic_checkpoint_protocol_bound):
                raise ValueError
            self._directory, self._key_file = Path(directory), Path(witness_key_file)
            _private_directory(self._directory)
            info = self._directory.stat()
            self._directory_identity = info.st_dev, info.st_ino
            self._key = _key(self._key_file)
            if (len({self._key_file, execution_store._path, execution_store._key_path,
                     material_store._path, material_store._key_path}) != 5
                    or hmac.compare_digest(self._key, execution_store._key)
                    or material_store.uses_key_material(self._key)
                    or material_store.uses_key_material(execution_store._key)):
                raise ValueError
            self._config, self._profile, self._defaults = config, profile, defaults
            self._plan, self._authorization, self._request = plan, authorization, request
            self._execution_store, self._material_store = execution_store, material_store
            self._guard = _OriginalDispatch(plan, authorization, execution_store, material_store, request, clock)
            self._source = self._source_digest()
            self._context = self._context_digest()
            self._begin_consumed = self._send_started = self._ack_consumed = self._metadata_consumed = self._closed = False
            self._lock = RLock()
            self._validate()
        except Exception:
            raise WindowsExecutionSecretAckError(_ERROR) from None

    def _source_digest(self) -> str:
        self._config.__post_init__()
        ca = None
        if self._config.ca_file is not None:
            with Path(self._config.ca_file).open("rb") as stream:
                data = stream.read(1048577)
            if not 0 < len(data) <= 1048576:
                raise ValueError
            ca = hashlib.sha256(data).hexdigest()
        return canonical_digest({"origin": self._config.base_url,
            "bearer": hashlib.sha256(self._config.bearer_token.encode()).hexdigest(), "ca": ca,
            "serial": self._profile.serial_digest})

    def _context_digest(self) -> str:
        return canonical_digest({"contract": CONTRACT, "parameters": self._plan.parameters_digest,
            "plan": self._plan.plan_digest, "authorization": self._authorization.authorization_digest,
            "request": material_lease_request_digest(self._request), "source": self._source_digest(),
            "directory": str(self._directory), "directory_device": self._directory_identity[0],
            "directory_inode": self._directory_identity[1], "key_file": str(self._key_file),
            "key_digest": hashlib.sha256(self._key).hexdigest(),
            "execution_store": str(self._execution_store._path), "material_store": str(self._material_store._path),
            "execution_key": hashlib.sha256(self._execution_store._key).hexdigest(),
            "material_key": hashlib.sha256(self._material_store._key).hexdigest()})

    def _validate(self) -> None:
        p, a, r = self._plan, self._authorization, self._request
        p.__post_init__(); a.__post_init__(); r.__post_init__()
        if (p.action_id != "secret-create-from-reference" or p.action_version != "1.0.0"
                or p.adapter_ref != ADAPTER_REF or p.target_ref != TARGET_REF or p.compensation_ref is not None
                or p.parameters_digest != windows_execution_secret_parameters_digest(self._profile, self._defaults,
                    create_uuid=REQUEST_UUID)
                or r.action_id != p.action_id or r.action_version != p.action_version
                or r.provider_class is not MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE
                or r.purpose is not MaterialPurpose.INITIAL_ONBOARDING or r.expires_at - r.requested_at > 60
                or r.plan_digest != p.plan_digest or r.authorization_digest != a.authorization_digest
                or a.plan_ref != p.plan_ref or a.plan_digest != p.plan_digest
                or a.requester_digest != p.requester_digest or a.confirmation_digest != p.confirmation_digest
                or a.approval_digest != p.approval_digest or r.requested_at < a.issued_at
                or r.expires_at > min(a.expires_at, p.expires_at)
                or self._source_digest() != self._source or self._context_digest() != self._context
                or not hmac.compare_digest(_key(self._key_file), self._key)):
            raise ValueError
        _private_directory(self._directory)
        info = self._directory.stat()
        if (info.st_dev, info.st_ino) != self._directory_identity:
            raise ValueError

    def _writing_now(self) -> int:
        if self._closed:
            raise ValueError
        self._validate()
        self._guard.require(claimed=True, acquired=True)
        return self._guard.last_now

    def _signature(self, name: str, record: dict[str, object]) -> str:
        raw = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return hmac.new(self._key, _DOMAIN + name.encode() + b"\x00" + raw, hashlib.sha256).hexdigest()

    def _write(self, name: str, record: dict[str, object]) -> None:
        self._validate()
        directory = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if (info.st_dev, info.st_ino) != self._directory_identity:
                raise ValueError
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(descriptor, "w") as stream:
                info = os.fstat(stream.fileno())
                if (info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode)
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                    raise ValueError
                json.dump({**record, "signature": self._signature(name, record)}, stream,
                    sort_keys=True, separators=(",", ":"), allow_nan=False)
                stream.flush(); os.fsync(stream.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)

    def _record(self, name: str, fields: frozenset[str]) -> dict[str, object]:
        self._validate()
        raw = _read(self._directory / name, 4096)
        try:
            left = _skip_json_space(raw, 0); right = _json_value_end(raw, left)
            if _skip_json_space(raw, right) != len(raw):
                raise ValueError
            parser._validate_json(raw, left, right, depth=0, budget=[10000])
            spans = _object_spans(raw, left, right)
            if set(spans) != fields | {"signature"}:
                raise ValueError
            record = {key: parser._scalar(raw, span) for key, span in spans.items()}
            signature = record.pop("signature")
            for key, value in record.items():
                if key.endswith("_at"):
                    if type(value) is not int or not self._request.requested_at <= value < self._request.expires_at:
                        raise ValueError
                elif key == "native_secret_id":
                    parser._integer(value)
                elif key == "native_uuid":
                    if type(value) is not str or str(uuid.UUID(value)) != value or value == REQUEST_UUID:
                        raise ValueError
                else:
                    if type(value) is not str:
                        raise ValueError
                    require_digest(value, "windows_ack_record")
            if (record["context_digest"] != self._context or type(signature) is not str
                    or not hmac.compare_digest(signature, self._signature(name, record))):
                raise ValueError
            self._validate()
            return record
        finally:
            _zeroize_mutable(raw)

    def _material_key(self) -> bytes:
        self._validate()
        return hmac.new(self._key, _MATERIAL_KEY_DOMAIN + self._context.encode("ascii"), hashlib.sha256).digest()

    def _body_witnesses(self, body: memoryview) -> dict[str, str]:
        from .secret_instruction_build29_api_preservation import _MATERIAL_DOMAIN
        if (type(body) is not memoryview or not body.readonly or not body.c_contiguous
                or body.format != "B" or type(body.obj) is not bytearray
                or len(body) != len(body.obj) or not 0 < len(body) <= 32768):
            raise ValueError
        raw = body.obj
        left = _skip_json_space(raw, 0); right = _json_value_end(raw, left)
        if _skip_json_space(raw, right) != len(raw):
            raise ValueError
        parser._validate_json(raw, left, right, depth=0, budget=[50000])
        fields = _object_spans(raw, left, right)
        wanted = _proposed_metadata(self._profile, REQUEST_UUID)
        if set(fields) != set(wanted) | {"field"}:
            raise ValueError
        for key, expected in wanted.items():
            value = parser._scalar(raw, fields[key])
            if type(value) is not type(expected) or value != expected:
                raise ValueError
        rows = parser._array(raw, fields["field"], 2)
        if len(rows) != 2:
            raise ValueError
        witnesses = {}
        material_key = self._material_key()
        for row, name in zip(rows, ("Password", "Username"), strict=True):
            entry = _object_spans(raw, *row)
            if (set(entry) != {"id", "name", "value"} or parser._scalar(raw, entry["name"]) != name
                    or type(parser._scalar(raw, entry["id"])) is not int
                    or parser._scalar(raw, entry["id"]) != 0
                    or raw[entry["value"][0]] != 34 or entry["value"][1] - entry["value"][0] <= 2):
                raise ValueError
            token = hmac.new(material_key, _MATERIAL_DOMAIN if name == "Password" else _USERNAME_DOMAIN, hashlib.sha256)
            with memoryview(raw)[slice(*entry["value"])] as value:
                token.update(value)
            witnesses[name.lower() + "_digest"] = token.hexdigest()
        witness = hmac.new(self._key, _DOMAIN + b"request-body\x00", hashlib.sha256)
        witness.update(body)
        return {"body_digest": witness.hexdigest(), **witnesses}

    def begin_original_send(self, body: memoryview) -> None:
        try:
            with self._lock:
                now = self._writing_now()
                if self._begin_consumed:
                    raise ValueError
                self._begin_consumed = True
                # An orphan later record can never turn a missing send marker into a new send.
                if any(os.path.lexists(self._directory / name) for name in (_SEND, _ACK, _METADATA)):
                    raise ValueError
                witnesses = self._body_witnesses(body)
                self._writing_now()
                self._write(_SEND, {"context_digest": self._context, **witnesses, "sent_at": now})
                self._send_started = True
        except Exception:
            self._closed = True
            raise WindowsExecutionSecretAckError(_ERROR) from None

    def capture_original_ack(self, raw: bytearray, *, http_status: int, content_type: str) -> None:
        try:
            with self._lock:
                now = self._writing_now()
                if (not self._send_started or self._ack_consumed or type(http_status) is not int or http_status != 200
                        or type(content_type) is not str or content_type.split(";", 1)[0].strip().lower() != "application/json"):
                    raise ValueError
                self._ack_consumed = True
                sent = self._record(_SEND, _SEND_FIELDS)
                native_id, status = _consume_database_create_ack_metadata(raw,
                    serial_digest=self._profile.serial_digest, accepted_statuses=frozenset({"success"}))
                self._writing_now()
                ack_digest = hmac.new(self._key, _DOMAIN + b"native-ack\x00" +
                    canonical_digest({"context": self._context, "send": canonical_digest(sent),
                        "native_id": native_id, "status": status}).encode(), hashlib.sha256).hexdigest()
                self._write(_ACK, {"context_digest": self._context, "send_digest": canonical_digest(sent),
                    "native_secret_id": native_id, "ack_digest": ack_digest, "acknowledged_at": now})
        except Exception:
            self._closed = True
            raise WindowsExecutionSecretAckError(_ERROR) from None
        finally:
            if type(raw) is bytearray:
                _zeroize_mutable(raw)

    def capture_original_metadata(self, raw: bytearray) -> WindowsExecutionSecretMetadata:
        try:
            with self._lock:
                now = self._writing_now()
                if not self._send_started or not self._ack_consumed or self._metadata_consumed:
                    raise ValueError
                self._metadata_consumed = True
                ack = self._record(_ACK, _ACK_FIELDS)
                observed = consume_windows_execution_secret_metadata(raw, self._profile,
                    expected_secret_id=cast(int, ack["native_secret_id"]), create_uuid=REQUEST_UUID)
                self._writing_now()
                self._write(_METADATA, {"context_digest": self._context, "ack_record_digest": canonical_digest(ack),
                    "native_secret_id": observed.native_secret_id, "native_uuid": observed.native_uuid,
                    "state_digest": observed.state_digest, "observed_at": now})
                return observed
        except Exception:
            self._closed = True
            raise WindowsExecutionSecretAckError(_ERROR) from None
        finally:
            if type(raw) is bytearray:
                _zeroize_mutable(raw)

    def inspect_original_creation(self) -> WindowsExecutionSecretOriginalCreation:
        """Observe sealed records and the original M4 status, including after expiry."""
        try:
            with self._lock:
                self._validate()
                p, a = self._plan, self._authorization
                claim = self._execution_store.inspect_claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest,
                    idempotency_digest=p.idempotency_digest, authorization_digest=a.authorization_digest,
                    context_digest=canonical_digest({"plan_digest": p.plan_digest,
                        "authorization_digest": a.authorization_digest, "revision": p.revision}))
                sent, ack = self._record(_SEND, _SEND_FIELDS), self._record(_ACK, _ACK_FIELDS)
                if ack["send_digest"] != canonical_digest(sent) or cast(int, ack["acknowledged_at"]) < cast(int, sent["sent_at"]):
                    raise ValueError
                meta = self._record(_METADATA, _METADATA_FIELDS) if os.path.lexists(self._directory / _METADATA) else None
                if meta is None and claim.result is not None and str(claim.result.outcome) == "succeeded":
                    raise ValueError
                if meta is not None and (meta["ack_record_digest"] != canonical_digest(ack)
                        or meta["native_secret_id"] != ack["native_secret_id"]
                        or cast(int, meta["observed_at"]) < cast(int, ack["acknowledged_at"])):
                    raise ValueError
                return WindowsExecutionSecretOriginalCreation(cast(int, ack["native_secret_id"]),
                    cast(str, meta["native_uuid"]) if meta else None, cast(str, meta["state_digest"]) if meta else None,
                    canonical_digest({"send": sent, "ack": ack, "metadata": meta}),
                    str(claim.result.outcome) if claim.result is not None else "in_progress",
                    str(claim.result.verification) if claim.result is not None else "unknown")
        except Exception:
            raise WindowsExecutionSecretAckError(_ERROR) from None
